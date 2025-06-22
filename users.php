<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

define('CONFIG_ACCESS', true);
require_once 'config/app_config.php';

$pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$userId = $_SESSION['user_id'];
$username = $_SESSION['username'] ?? 'User';

// Session-Check
if (isset($_SESSION['user_id'])) {
    try {
        $stmt = $pdo->prepare("SELECT is_active FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $userActive = $stmt->fetchColumn();
        
        if (!$userActive) {
            session_destroy();
            header('Location: login.php?error=' . urlencode('Your account has been deactivated. Please contact an administrator.'));
            exit;
        }
    } catch (Exception $e) {
        session_destroy();
        header('Location: login.php?error=' . urlencode('Session validation failed.'));
        exit;
    }
}

// Check permissions
$stmt = $pdo->prepare("SELECT role FROM user_roles WHERE user_id = ?");
$stmt->execute([$userId]);
$userRoles = $stmt->fetchAll(PDO::FETCH_COLUMN);

$permissions = [];
foreach ($userRoles as $role) {
    switch ($role) {
        case 'admin':
            $permissions = ['view_vouchers', 'scan_vouchers', 'create_vouchers', 'manage_vouchers', 'delete_vouchers', 'manage_categories', 'delete_categories', 'manage_users', 'delete_users', 'configure_system', 'pretix_sync', 'export_data', 'change_passwords'];
            break;
        case 'user_manager':
            $permissions = array_merge($permissions, ['view_vouchers', 'manage_users', 'change_passwords', 'export_data']);
            break;
    }
}
$permissions = array_unique($permissions);

function hasPermission($perm, $perms) {
    return in_array($perm, $perms);
}

$canManage = hasPermission('manage_users', $permissions);

if (!$canManage) {
    header('Location: dashboard.php');
    exit;
}

// Pretix Integration Functions
function getPretixSettings($pdo) {
    try {
        $stmt = $pdo->prepare("SELECT is_enabled, settings FROM system_integrations WHERE integration = 'pretix'");
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($result && $result['is_enabled']) {
            $settings = json_decode($result['settings'], true);
            if ($settings && !empty($settings['api_url']) && !empty($settings['api_token'])) {
                return $settings;
            }
        }
    } catch (Exception $e) {
        error_log("Pretix settings error: " . $e->getMessage());
    }
    return null;
}

function createPretixVoucher($pretixSettings, $voucherData) {
    if (!$pretixSettings) return null;
    
    try {
        $url = rtrim($pretixSettings['api_url'], '/') . '/api/v1/organizers/' . 
               $pretixSettings['organizer'] . '/events/' . $pretixSettings['event'] . '/vouchers/';
        
        $postData = [
            'code' => $voucherData['voucher_code'],
            'max_usages' => 1,
            'valid_until' => null,
            'block_quota' => false,
            'allow_ignore_quota' => false,
            'price_mode' => 'set',
            'value' => $voucherData['actual_value'],
            'tag' => 'user_voucher',
            'comment' => 'Auto-created for user reactivation'
        ];
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($postData),
            CURLOPT_HTTPHEADER => [
                'Authorization: Token ' . $pretixSettings['api_token'],
                'Content-Type: application/json'
            ],
            CURLOPT_TIMEOUT => 30
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 201) {
            $responseData = json_decode($response, true);
            return $responseData['id'] ?? null;
        }
        
        return null;
        
    } catch (Exception $e) {
        error_log("Pretix voucher creation error: " . $e->getMessage());
        return null;
    }
}

function deletePretixVoucher($pretixSettings, $voucherId) {
    if (!$pretixSettings || !$voucherId) return false;
    
    try {
        $url = rtrim($pretixSettings['api_url'], '/') . '/api/v1/organizers/' . 
               $pretixSettings['organizer'] . '/events/' . $pretixSettings['event'] . 
               '/vouchers/' . $voucherId . '/';
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => [
                'Authorization: Token ' . $pretixSettings['api_token'],
                'Content-Type: application/json'
            ],
            CURLOPT_TIMEOUT => 30
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        // 204 = successful deletion, 404 = already deleted
        return in_array($httpCode, [204, 404]);
        
    } catch (Exception $e) {
        error_log("Pretix voucher deletion error: " . $e->getMessage());
        return false;
    }
}

function syncVoucherDeletionToPretix($pdo, $voucherIds) {
    $pretixSettings = getPretixSettings($pdo);
    if (!$pretixSettings) return ['success' => 0, 'failed' => 0, 'errors' => []];
    
    $success = 0;
    $failed = 0;
    $errors = [];
    
    // Get Pretix voucher IDs for the vouchers to be deleted
    $placeholders = str_repeat('?,', count($voucherIds) - 1) . '?';
    $stmt = $pdo->prepare("SELECT id, voucher_code, pretix_voucher_id FROM vouchers WHERE id IN ($placeholders) AND pretix_voucher_id IS NOT NULL");
    $stmt->execute($voucherIds);
    $vouchersToSync = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    foreach ($vouchersToSync as $voucher) {
        if (deletePretixVoucher($pretixSettings, $voucher['pretix_voucher_id'])) {
            $success++;
        } else {
            $failed++;
            $errors[] = "Failed to delete voucher {$voucher['voucher_code']} from Pretix";
        }
    }
    
    return ['success' => $success, 'failed' => $failed, 'errors' => $errors];
}

function syncVoucherCreationToPretix($pdo, $voucherIds) {
    $pretixSettings = getPretixSettings($pdo);
    if (!$pretixSettings) return ['success' => 0, 'failed' => 0, 'errors' => []];
    
    $success = 0;
    $failed = 0;
    $errors = [];
    
    // Get vouchers that need to be synced to Pretix
    $placeholders = str_repeat('?,', count($voucherIds) - 1) . '?';
    $stmt = $pdo->prepare("SELECT id, voucher_code, actual_value FROM vouchers WHERE id IN ($placeholders) AND pretix_voucher_id IS NULL");
    $stmt->execute($voucherIds);
    $vouchersToSync = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    foreach ($vouchersToSync as $voucher) {
        $pretixVoucherId = createPretixVoucher($pretixSettings, $voucher);
        
        if ($pretixVoucherId) {
            // Update local voucher with Pretix ID
            $updateStmt = $pdo->prepare("UPDATE vouchers SET pretix_voucher_id = ?, pretix_published = 1 WHERE id = ?");
            $updateStmt->execute([$pretixVoucherId, $voucher['id']]);
            $success++;
        } else {
            $failed++;
            $errors[] = "Failed to create voucher {$voucher['voucher_code']} in Pretix";
        }
    }
    
    return ['success' => $success, 'failed' => $failed, 'errors' => $errors];
}

// AJAX Handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    try {
        switch ($_POST['action']) {
            case 'search_users':
                $search = $_POST['search'] ?? '';
                $stmt = $pdo->prepare("SELECT u.*, GROUP_CONCAT(ur.role) as roles FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id WHERE u.username LIKE ? OR u.email LIKE ? GROUP BY u.id LIMIT 20");
                $stmt->execute(["%$search%", "%$search%"]);
                echo json_encode(['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
                exit;
                
            case 'create_user':
                // Check if username already exists
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
                $stmt->execute([$_POST['username']]);
                if ($stmt->fetchColumn() > 0) {
                    echo json_encode(['success' => false, 'message' => 'Username already taken']);
                    exit;
                }
                
                // Check if email already exists
                if (!empty($_POST['email'])) {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
                    $stmt->execute([$_POST['email']]);
                    if ($stmt->fetchColumn() > 0) {
                        echo json_encode(['success' => false, 'message' => 'Email already taken']);
                        exit;
                    }
                }
                
                $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash, first_name, last_name, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, NOW())");
                $result = $stmt->execute([
                    $_POST['username'],
                    $_POST['email'] ?: null,
                    password_hash($_POST['password'], PASSWORD_DEFAULT),
                    $_POST['first_name'] ?? '',
                    $_POST['last_name'] ?? ''
                ]);
                
                if ($result) {
                    $newUserId = $pdo->lastInsertId();
                    
                    // Automatically assign "user" role
                    $stmt = $pdo->prepare("INSERT INTO user_roles (user_id, role) VALUES (?, 'user')");
                    $stmt->execute([$newUserId]);
                    
                    // Additional role if selected
                    if (!empty($_POST['role']) && $_POST['role'] !== 'user') {
                        $stmt = $pdo->prepare("INSERT INTO user_roles (user_id, role) VALUES (?, ?)");
                        $stmt->execute([$newUserId, $_POST['role']]);
                    }
                    
                    echo json_encode(['success' => true, 'message' => 'User successfully created (automatically registered as "User")']);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Error creating user']);
                }
                exit;
                
            case 'update_user':
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ? AND id != ?");
                $stmt->execute([$_POST['username'], $_POST['user_id']]);
                if ($stmt->fetchColumn() > 0) {
                    echo json_encode(['success' => false, 'message' => 'Username already taken']);
                    exit;
                }
                
                if (!empty($_POST['email'])) {
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?");
                    $stmt->execute([$_POST['email'], $_POST['user_id']]);
                    if ($stmt->fetchColumn() > 0) {
                        echo json_encode(['success' => false, 'message' => 'Email already taken']);
                        exit;
                    }
                }
                
                $stmt = $pdo->prepare("UPDATE users SET username = ?, email = ?, first_name = ?, last_name = ?, updated_at = NOW() WHERE id = ?");
                $result = $stmt->execute([
                    $_POST['username'],
                    $_POST['email'] ?: null,
                    $_POST['first_name'] ?? '',
                    $_POST['last_name'] ?? '',
                    $_POST['user_id']
                ]);
                echo json_encode(['success' => $result, 'message' => $result ? 'User updated' : 'Error updating user']);
                exit;
                
            case 'toggle_user_status':
                $pdo->beginTransaction();
                try {
                    // Check current status
                    $stmt = $pdo->prepare("SELECT is_active FROM users WHERE id = ?");
                    $stmt->execute([$_POST['user_id']]);
                    $currentStatus = $stmt->fetchColumn();
                    
                    if ($currentStatus) {
                        // DEACTIVATING USER - Delete vouchers and sync to Pretix
                        $stmt = $pdo->prepare("SELECT id FROM vouchers WHERE user_id = ?");
                        $stmt->execute([$_POST['user_id']]);
                        $voucherIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
                        
                        if (!empty($voucherIds)) {
                            // Sync deletion to Pretix
                            $pretixResult = syncVoucherDeletionToPretix($pdo, $voucherIds);
                            
                            // Delete vouchers from local database
                            $stmt = $pdo->prepare("DELETE FROM vouchers WHERE user_id = ?");
                            $stmt->execute([$_POST['user_id']]);
                            $deletedCount = $stmt->rowCount();
                            
                            // Toggle user status
                            $stmt = $pdo->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?");
                            $stmt->execute([$_POST['user_id']]);
                            
                            $pdo->commit();
                            
                            $message = "User deactivated and $deletedCount vouchers deleted";
                            if ($pretixResult['success'] > 0) {
                                $message .= " (Pretix: {$pretixResult['success']} synced";
                                if ($pretixResult['failed'] > 0) {
                                    $message .= ", {$pretixResult['failed']} failed";
                                }
                                $message .= ")";
                            }
                            
                            echo json_encode(['success' => true, 'message' => $message]);
                        } else {
                            // No vouchers, just toggle status
                            $stmt = $pdo->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?");
                            $stmt->execute([$_POST['user_id']]);
                            $pdo->commit();
                            echo json_encode(['success' => true, 'message' => 'User deactivated']);
                        }
                    } else {
                        // ACTIVATING USER - Restore vouchers and sync to Pretix
                        $stmt = $pdo->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?");
                        $stmt->execute([$_POST['user_id']]);
                        
                        // Check if user had vouchers before (stored in a backup table or recreate basic vouchers)
                        // For now, we'll just activate without recreating vouchers
                        // You could implement a voucher backup system here if needed
                        
                        $pdo->commit();
                        echo json_encode(['success' => true, 'message' => 'User activated (Note: Previous vouchers were not restored)']);
                    }
                } catch (Exception $e) {
                    $pdo->rollback();
                    echo json_encode(['success' => false, 'message' => 'Error changing status: ' . $e->getMessage()]);
                }
                exit;
                
            case 'delete_user':
                if ($_POST['user_id'] == $userId) {
                    echo json_encode(['success' => false, 'message' => 'You cannot delete yourself']);
                    exit;
                }
                
                $pdo->beginTransaction();
                try {
                    // Get all voucher IDs for this user before deletion
                    $stmt = $pdo->prepare("SELECT id FROM vouchers WHERE user_id = ?");
                    $stmt->execute([$_POST['user_id']]);
                    $voucherIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
                    
                    // Sync voucher deletion to Pretix if there are vouchers
                    $pretixResult = ['success' => 0, 'failed' => 0];
                    if (!empty($voucherIds)) {
                        $pretixResult = syncVoucherDeletionToPretix($pdo, $voucherIds);
                    }
                    
                    // Delete user data
                    $pdo->prepare("DELETE FROM user_roles WHERE user_id = ?")->execute([$_POST['user_id']]);
                    $stmt = $pdo->prepare("DELETE FROM vouchers WHERE user_id = ?");
                    $stmt->execute([$_POST['user_id']]);
                    $deletedVouchers = $stmt->rowCount();
                    $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$_POST['user_id']]);
                    
                    $pdo->commit();
                    
                    $message = "User and $deletedVouchers vouchers deleted";
                    if ($pretixResult['success'] > 0) {
                        $message .= " (Pretix: {$pretixResult['success']} synced";
                        if ($pretixResult['failed'] > 0) {
                            $message .= ", {$pretixResult['failed']} failed";
                        }
                        $message .= ")";
                    }
                    
                    echo json_encode(['success' => true, 'message' => $message]);
                } catch (Exception $e) {
                    $pdo->rollback();
                    echo json_encode(['success' => false, 'message' => 'Error deleting: ' . $e->getMessage()]);
                }
                exit;
                
            case 'change_user_password':
                if (strlen($_POST['password']) < 6) {
                    echo json_encode(['success' => false, 'message' => 'Password must be at least 6 characters long']);
                    exit;
                }
                
                $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
                $result = $stmt->execute([password_hash($_POST['password'], PASSWORD_DEFAULT), $_POST['user_id']]);
                echo json_encode(['success' => $result, 'message' => $result ? 'Password successfully changed' : 'Error changing password']);
                exit;
                
            case 'update_user_roles':
                if ($_POST['user_id'] == $userId) {
                    $newRoles = explode(',', $_POST['roles']);
                    if (!in_array('admin', $newRoles) && in_array('admin', $userRoles)) {
                        echo json_encode(['success' => false, 'message' => 'You cannot remove your own admin role']);
                        exit;
                    }
                }
                
                $pdo->beginTransaction();
                try {
                    $pdo->prepare("DELETE FROM user_roles WHERE user_id = ?")->execute([$_POST['user_id']]);
                    $roles = explode(',', $_POST['roles']);
                    foreach ($roles as $role) {
                        if (trim($role)) {
                            $pdo->prepare("INSERT INTO user_roles (user_id, role) VALUES (?, ?)")->execute([$_POST['user_id'], trim($role)]);
                        }
                    }
                    $pdo->commit();
                    echo json_encode(['success' => true, 'message' => 'Roles successfully updated']);
                } catch (Exception $e) {
                    $pdo->rollback();
                    echo json_encode(['success' => false, 'message' => 'Error updating roles']);
                }
                exit;
                
            case 'delete_user_vouchers':
                $pdo->beginTransaction();
                try {
                    // Get all voucher IDs for this user
                    $stmt = $pdo->prepare("SELECT id FROM vouchers WHERE user_id = ?");
                    $stmt->execute([$_POST['user_id']]);
                    $voucherIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
                    
                    if (empty($voucherIds)) {
                        echo json_encode(['success' => true, 'message' => '0 vouchers deleted']);
                        exit;
                    }
                    
                    // Sync deletion to Pretix
                    $pretixResult = syncVoucherDeletionToPretix($pdo, $voucherIds);
                    
                    // Delete vouchers from local database
                    $stmt = $pdo->prepare("DELETE FROM vouchers WHERE user_id = ?");
                    $stmt->execute([$_POST['user_id']]);
                    $deletedCount = $stmt->rowCount();
                    
                    $pdo->commit();
                    
                    $message = "$deletedCount vouchers deleted";
                    if ($pretixResult['success'] > 0) {
                        $message .= " (Pretix: {$pretixResult['success']} synced";
                        if ($pretixResult['failed'] > 0) {
                            $message .= ", {$pretixResult['failed']} failed";
                        }
                        $message .= ")";
                    }
                    
                    echo json_encode(['success' => true, 'message' => $message]);
                } catch (Exception $e) {
                    $pdo->rollback();
                    echo json_encode(['success' => false, 'message' => 'Error deleting vouchers: ' . $e->getMessage()]);
                }
                exit;

            case 'restore_user_vouchers':
                $pdo->beginTransaction();
                try {
                    // Get existing vouchers for this user that are not synced to Pretix
                    $stmt = $pdo->prepare("SELECT id FROM vouchers WHERE user_id = ? AND pretix_voucher_id IS NULL");
                    $stmt->execute([$_POST['user_id']]);
                    $voucherIds = $stmt->fetchAll(PDO::FETCH_COLUMN);
                    
                    if (empty($voucherIds)) {
                        echo json_encode(['success' => true, 'message' => 'No vouchers to restore']);
                        exit;
                    }
                    
                    // Sync creation to Pretix
                    $pretixResult = syncVoucherCreationToPretix($pdo, $voucherIds);
                    
                    $pdo->commit();
                    
                    $message = "Voucher restoration attempted";
                    if ($pretixResult['success'] > 0) {
                        $message = "{$pretixResult['success']} vouchers restored to Pretix";
                        if ($pretixResult['failed'] > 0) {
                            $message .= " ({$pretixResult['failed']} failed)";
                        }
                    } else if ($pretixResult['failed'] > 0) {
                        $message = "Failed to restore {$pretixResult['failed']} vouchers to Pretix";
                    }
                    
                    echo json_encode(['success' => true, 'message' => $message]);
                } catch (Exception $e) {
                    $pdo->rollback();
                    echo json_encode(['success' => false, 'message' => 'Error restoring vouchers: ' . $e->getMessage()]);
                }
                exit;
                
            default:
                echo json_encode(['success' => false, 'message' => 'Unknown action']);
                exit;
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management - <?php echo getAppName(); ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .logo-container {
            max-height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .logo-container img {
            max-height: 50px;
            max-width: 200px;
            width: auto;
            height: auto;
            object-fit: contain;
        }
        @media (max-width: 640px) {
            .logo-container {
                max-height: 40px;
            }
            .logo-container img {
                max-height: 40px;
                max-width: 150px;
            }
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Navigation -->
    <nav class="bg-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex items-center">
                    <a href="dashboard.php" class="flex items-center">
                        <?php if (getLogoUrl()): ?>
                            <div class="logo-container mr-4">
                                <img src="<?php echo htmlspecialchars(getLogoUrl()); ?>" alt="<?php echo htmlspecialchars(getCompanyName()); ?>" 
                                     class="logo-img">
                            </div>
                        <?php else: ?>
                            <div class="flex items-center">
                                <span class="text-2xl mr-2">🎫</span>
                                <span class="text-xl sm:text-2xl font-bold text-gray-900">
                                    <?php echo htmlspecialchars(getAppName()); ?>
                                </span>
                            </div>
                        <?php endif; ?>
                    </a>
                    <span class="hidden md:inline ml-4 text-base lg:text-lg text-gray-600">/ User Management</span>
                </div>
                
                <div class="md:hidden flex items-center">
                    <button onclick="toggleMobileMenu()" class="text-gray-600 hover:text-gray-900 focus:outline-none focus:text-gray-900 p-2">
                        <svg id="menuIcon" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
                        </svg>
                        <svg id="closeIcon" class="h-6 w-6 hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
                
                <div class="hidden md:flex items-center space-x-4">
                    <a href="dashboard.php" class="text-gray-600 hover:text-gray-900 text-sm transition">← Dashboard</a>
                    <a href="profile.php" class="bg-purple-600 hover:bg-purple-700 text-white px-3 py-2 rounded-lg text-sm transition">
                        👤 Profile
                    </a>
                    <div class="text-sm text-gray-600">
                        <strong class="hidden lg:inline"><?php echo htmlspecialchars($username); ?></strong>
                        <strong class="lg:hidden"><?php echo htmlspecialchars(substr($username, 0, 10)); ?></strong>
                        <div class="text-xs text-purple-600 hidden lg:block"><?php echo implode(', ', $userRoles); ?></div>
                    </div>
                    <a href="logout.php" class="bg-red-500 hover:bg-red-600 text-white px-3 py-2 rounded-lg text-sm transition">
                        <span class="hidden sm:inline">Logout</span>
                        <span class="sm:hidden">🚪</span>
                    </a>
                </div>
            </div>
            
            <div id="mobileMenu" class="md:hidden hidden border-t border-gray-200 bg-white">
                <div class="px-2 pt-2 pb-3 space-y-1">
                    <div class="px-3 py-2 text-sm text-gray-600 border-b border-gray-200">
                        <div class="font-medium"><?php echo htmlspecialchars($username); ?></div>
                        <div class="text-xs text-purple-600"><?php echo implode(', ', $userRoles); ?></div>
                    </div>
                    
                    <a href="dashboard.php" class="block px-3 py-2 text-base font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-50 rounded-md transition">
                        🏠 Dashboard
                    </a>
                    
                    <a href="profile.php" class="block px-3 py-2 text-base font-medium text-purple-700 hover:text-purple-900 hover:bg-purple-50 rounded-md transition">
                        👤 Profile
                    </a>
                    
                    <a href="logout.php" class="block px-3 py-2 text-base font-medium text-red-600 hover:text-red-900 hover:bg-red-50 rounded-md transition">
                        🚪 Logout
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <h1 class="text-xl sm:text-2xl font-bold text-gray-800">👥 User Management</h1>
                <button onclick="showCreateModal()" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition">
                    + Create User
                </button>
            </div>
        </div>

        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex flex-col sm:flex-row gap-2 mb-4">
                <input type="text" id="searchInput" placeholder="Search users..." 
                       class="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 text-sm">
                <button onclick="searchUsers()" class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition text-sm">
                    🔍 Search
                </button>
            </div>
            <div id="userList">
                <div class="text-center py-8 text-gray-500">
                    <div class="text-4xl mb-2">👥</div>
                    <p>Search for users to manage them</p>
                    <p class="text-sm mt-1">Enter at least 2 characters</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Create User Modal -->
    <div id="createModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-xl max-w-md w-full p-6">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-xl font-bold text-gray-800">👥 Create User</h3>
                <button onclick="closeCreateModal()" class="text-gray-500 hover:text-gray-700 text-2xl">×</button>
            </div>
            
            <form onsubmit="createUser(event)" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Username *</label>
                    <input type="text" name="username" required 
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
                    <input type="email" name="email" 
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                </div>
                
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">First Name</label>
                        <input type="text" name="first_name" 
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
                        <input type="text" name="last_name" 
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                    </div>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Password *</label>
                    <input type="password" name="password" required minlength="6" 
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                    <p class="text-xs text-gray-500 mt-1">At least 6 characters</p>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Additional Role</label>
                    <select name="role" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                        <option value="">No additional role</option>
                        <option value="admin">Administrator (Full access)</option>
                        <option value="user_manager">User Manager (User management)</option>
                        <option value="voucher_manager">Voucher Manager (Vouchers + Categories)</option>
                        <option value="scanner">Scanner (Scan only)</option>
                    </select>
                    <p class="text-xs text-gray-500 mt-1">All users automatically get the "User" role</p>
                </div>
                
                <div class="flex gap-2 pt-4">
                    <button type="submit" class="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg transition">
                        👥 Create
                    </button>
                    <button type="button" onclick="closeCreateModal()" class="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- User Management Modal -->
    <div id="userModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto" id="modalContent"></div>
    </div>

    <!-- Toast Container -->
    <div id="toastContainer" class="fixed bottom-4 right-4 z-50 space-y-2"></div>

    <script>
        async function searchUsers() {
            const search = document.getElementById('searchInput').value.trim();
            if (search.length < 2) {
                showToast('Enter at least 2 characters', 'warning');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('action', 'search_users');
                formData.append('search', search);
                
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                if (result.success) {
                    displayUsers(result.data);
                } else {
                    showToast(result.message, 'error');
                }
            } catch (error) {
                showToast('Error searching users', 'error');
            }
        }

        function displayUsers(users) {
            const container = document.getElementById('userList');
            
            if (users.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-8 text-gray-500">
                        <div class="text-4xl mb-2">🔍</div>
                        <p>No users found</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = users.map(user => `
                <div class="flex flex-col sm:flex-row sm:items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 rounded-lg mb-2 transition">
                    <div class="flex-1 mb-3 sm:mb-0">
                        <div class="flex items-center gap-3 mb-1">
                            <div class="font-medium text-lg ${user.is_active ? '' : 'line-through text-gray-400'}">${user.username}</div>
                            ${user.is_active ? 
                                '<span class="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs">Active</span>' :
                                '<span class="bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs">Deactivated</span>'
                            }
                        </div>
                        <div class="text-sm text-gray-600 space-y-1">
                            <div><strong>Email:</strong> ${user.email || 'No email'}</div>
                            <div><strong>Name:</strong> ${user.first_name || ''} ${user.last_name || ''}</div>
                            <div><strong>Roles:</strong> ${user.roles || 'No roles'}</div>
                            <div><strong>Created:</strong> ${new Date(user.created_at).toLocaleDateString('en-US')}</div>
                        </div>
                    </div>
                    <div class="flex flex-col gap-2">
                        <button onclick="manageUser(${user.id}, '${user.username}', '${user.email || ''}', '${user.first_name || ''}', '${user.last_name || ''}', ${user.is_active}, '${user.roles || ''}')" 
                                class="bg-purple-600 hover:bg-purple-700 text-white px-3 py-1 rounded text-sm transition">
                            ⚙️ Manage
                        </button>
                    </div>
                </div>
            `).join('');
        }

        function manageUser(userId, username, email, firstName, lastName, isActive, roles) {
            const content = document.getElementById('modalContent');
            content.innerHTML = `
                <div class="p-6">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-xl font-bold text-gray-800">Manage user: ${username}</h3>
                        <button onclick="closeUserModal()" class="text-gray-500 hover:text-gray-700 text-2xl">×</button>
                    </div>
                    
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                        <button onclick="editUser(${userId}, '${username}', '${email}', '${firstName}', '${lastName}')" 
                                class="bg-purple-600 hover:bg-purple-700 text-white py-3 px-4 rounded-lg transition">
                            ✏️ Edit
                        </button>
                        <button onclick="editUserRoles(${userId}, '${username}', '${roles}')" 
                                class="bg-indigo-600 hover:bg-indigo-700 text-white py-3 px-4 rounded-lg transition">
                            👤 Manage Roles
                        </button>
                        <button onclick="changeUserPassword(${userId}, '${username}')" 
                                class="bg-orange-600 hover:bg-orange-700 text-white py-3 px-4 rounded-lg transition">
                            🔑 Change Password
                        </button>
                        <button onclick="toggleUserStatus(${userId}, ${isActive})" 
                                class="bg-yellow-600 hover:bg-yellow-700 text-white py-3 px-4 rounded-lg transition">
                            ${isActive ? '⏸️ Deactivate' : '▶️ Activate'}
                        </button>
                        <button onclick="deleteUserVouchers(${userId}, '${username}')" 
                                class="bg-gray-600 hover:bg-gray-700 text-white py-3 px-4 rounded-lg transition">
                            🗑️ Delete Vouchers
                        </button>
                        <button onclick="restoreUserVouchers(${userId}, '${username}')" 
                                class="bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg transition">
                            🔄 Restore to Pretix
                    </div>
                    
                    <div class="bg-purple-50 border border-purple-200 rounded-lg p-4 mb-4">
                        <h4 class="font-medium text-purple-800 mb-2 flex items-center">
                            <span class="mr-2">🔄</span> Pretix Synchronization
                        </h4>
                        <p class="text-sm text-purple-700">
                            • When deactivating users, vouchers are deleted from both local DB and Pretix<br>
                            • When activating users, use "Restore to Pretix" to sync existing vouchers<br>
                            • "Delete Vouchers" removes vouchers from both systems
                        </p>
                    </div>
                    
                    <div class="border-t pt-4">
                        <button onclick="deleteUser(${userId}, '${username}')" 
                                class="w-full bg-red-600 hover:bg-red-700 text-white py-3 px-4 rounded-lg transition">
                            ❌ Delete User Completely
                        </button>
                    </div>
                </div>
            `;
            document.getElementById('userModal').classList.remove('hidden');
        }

        function editUser(userId, username, email, firstName, lastName) {
            const content = document.getElementById('modalContent');
            content.innerHTML = `
                <div class="p-6">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-xl font-bold text-gray-800">Edit User</h3>
                        <button onclick="closeUserModal()" class="text-gray-500 hover:text-gray-700 text-2xl">×</button>
                    </div>
                    
                    <form onsubmit="updateUser(event, ${userId})" class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Username</label>
                            <input type="text" name="username" value="${username}" required 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
                            <input type="email" name="email" value="${email}" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                        </div>
                        
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">First Name</label>
                                <input type="text" name="first_name" value="${firstName}" 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
                                <input type="text" name="last_name" value="${lastName}" 
                                       class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500">
                            </div>
                        </div>
                        
                        <div class="flex gap-3 pt-4">
                            <button type="submit" class="flex-1 bg-purple-600 hover:bg-purple-700 text-white py-2 rounded-lg transition">
                                💾 Save
                            </button>
                            <button type="button" onclick="closeUserModal()" class="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition">
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            `;
        }

        function editUserRoles(userId, username, currentRoles) {
            const roles = currentRoles ? currentRoles.split(',').filter(r => r.trim()) : [];
            
            const content = document.getElementById('modalContent');
            content.innerHTML = `
                <div class="p-6">
                    <div class="flex justify-between items-center mb-6">
                        <h3 class="text-xl font-bold text-gray-800">Roles for ${username}</h3>
                        <button onclick="closeUserModal()" class="text-gray-500 hover:text-gray-700 text-2xl">×</button>
                    </div>
                    
                    <form onsubmit="updateUserRoles(event, ${userId})" class="space-y-4">
                        <div class="space-y-3">
                            <label class="flex items-center p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
                                <input type="checkbox" name="admin" ${roles.includes('admin') ? 'checked' : ''} class="mr-3 rounded">
                                <div>
                                    <div class="font-medium">Administrator</div>
                                    <div class="text-sm text-gray-500">Full access to all functions</div>
                                </div>
                            </label>
                            
                            <label class="flex items-center p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
                                <input type="checkbox" name="user_manager" ${roles.includes('user_manager') ? 'checked' : ''} class="mr-3 rounded">
                                <div>
                                    <div class="font-medium">User Manager</div>
                                    <div class="text-sm text-gray-500">User management and password changes</div>
                                </div>
                            </label>
                            
                            <label class="flex items-center p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
                                <input type="checkbox" name="voucher_manager" ${roles.includes('voucher_manager') ? 'checked' : ''} class="mr-3 rounded">
                                <div>
                                    <div class="font-medium">Voucher Manager</div>
                                    <div class="text-sm text-gray-500">Manage vouchers and categories</div>
                                </div>
                            </label>
                            
                            <label class="flex items-center p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
                                <input type="checkbox" name="scanner" ${roles.includes('scanner') ? 'checked' : ''} class="mr-3 rounded">
                                <div>
                                    <div class="font-medium">Scanner</div>
                                    <div class="text-sm text-gray-500">Scan and redeem vouchers</div>
                                </div>
                            </label>
                            
                            <label class="flex items-center p-3 border rounded-lg hover:bg-gray-50 cursor-pointer">
                                <input type="checkbox" name="user" ${roles.includes('user') ? 'checked' : ''} class="mr-3 rounded">
                                <div>
                                    <div class="font-medium">User</div>
                                    <div class="text-sm text-gray-500">View own vouchers only</div>
                                </div>
                            </label>
                        </div>
                        
                        <div class="bg-purple-50 border border-purple-200 rounded-lg p-3">
                            <p class="text-sm text-purple-800">
                                <strong>Note:</strong> The "User" role is recommended for all users so they can see their own vouchers.
                            </p>
                        </div>
                        
                        <div class="flex gap-3 pt-4">
                            <button type="submit" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2 rounded-lg transition">
                                💾 Save Roles
                            </button>
                            <button type="button" onclick="closeUserModal()" class="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition">
                                Cancel
                            </button>
                        </div>
                    </form>
                </div>
            `;
        }

        // API Functions
        async function createUser(event) {
            event.preventDefault();
            const formData = new FormData(event.target);
            formData.append('action', 'create_user');
            
            try {
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
                if (result.success) {
                    closeCreateModal();
                    event.target.reset();
                    document.getElementById('searchInput').value = formData.get('username');
                    searchUsers();
                }
            } catch (error) {
                showToast('Error creating user', 'error');
            }
        }

        async function updateUser(event, userId) {
            event.preventDefault();
            const formData = new FormData(event.target);
            formData.append('action', 'update_user');
            formData.append('user_id', userId);
            
            try {
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
                if (result.success) {
                    closeUserModal();
                    searchUsers();
                }
            } catch (error) {
                showToast('Error updating user', 'error');
            }
        }

        async function updateUserRoles(event, userId) {
            event.preventDefault();
            const formData = new FormData(event.target);
            
            const roles = [];
            if (formData.get('admin')) roles.push('admin');
            if (formData.get('user_manager')) roles.push('user_manager');
            if (formData.get('voucher_manager')) roles.push('voucher_manager');
            if (formData.get('scanner')) roles.push('scanner');
            if (formData.get('user')) roles.push('user');
            
            try {
                const apiFormData = new FormData();
                apiFormData.append('action', 'update_user_roles');
                apiFormData.append('user_id', userId);
                apiFormData.append('roles', roles.join(','));
                
                const response = await fetch('users.php', { method: 'POST', body: apiFormData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
                if (result.success) {
                    closeUserModal();
                    searchUsers();
                }
            } catch (error) {
                showToast('Error updating roles', 'error');
            }
        }

        async function changeUserPassword(userId, username) {
            const password = prompt(`Enter new password for ${username}:`);
            if (!password) return;
            
            if (password.length < 6) {
                showToast('Password must be at least 6 characters long', 'error');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('action', 'change_user_password');
                formData.append('user_id', userId);
                formData.append('password', password);
                
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
                if (result.success) closeUserModal();
            } catch (error) {
                showToast('Error changing password', 'error');
            }
        }

        async function toggleUserStatus(userId, currentStatus) {
            const action = currentStatus ? 'deactivate' : 'activate';
            let confirmMessage = `Really ${action} user?`;
            
            if (currentStatus) {
                confirmMessage += '\n\n⚠️ Warning: All user vouchers will be deleted and removed from Pretix!';
            } else {
                confirmMessage += '\n\n💡 Tip: After activation, use "Restore to Pretix" to sync existing vouchers.';
            }
            
            if (!confirm(confirmMessage)) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'toggle_user_status');
                formData.append('user_id', userId);
                
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
                if (result.success) {
                    closeUserModal();
                    searchUsers();
                }
            } catch (error) {
                showToast('Error changing status', 'error');
            }
        }

        async function deleteUser(userId, username) {
            if (!confirm(`Really delete user "${username}"?\n\n⚠️ All associated vouchers will also be deleted and removed from Pretix!\nThis action cannot be undone.`)) return;
            
            const confirmation = prompt(`To confirm, enter "${username}":`);
            if (confirmation !== username) {
                showToast('Confirmation failed', 'error');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('action', 'delete_user');
                formData.append('user_id', userId);
                
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
                if (result.success) {
                    closeUserModal();
                    searchUsers();
                }
            } catch (error) {
                showToast('Error deleting user', 'error');
            }
        }

        async function deleteUserVouchers(userId, username) {
            if (!confirm(`Delete all vouchers from "${username}"?\n\n⚠️ Vouchers will also be removed from Pretix!\nThis action cannot be undone.`)) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'delete_user_vouchers');
                formData.append('user_id', userId);
                
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
            } catch (error) {
                showToast('Error deleting vouchers', 'error');
            }
        }

        async function restoreUserVouchers(userId, username) {
            if (!confirm(`Restore vouchers for "${username}" to Pretix?\n\nThis will sync existing local vouchers to Pretix.`)) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'restore_user_vouchers');
                formData.append('user_id', userId);
                
                const response = await fetch('users.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                showToast(result.message, result.success ? 'success' : 'error');
            } catch (error) {
                showToast('Error restoring vouchers', 'error');
            }
        }

        function createVoucherForUser(userId, username) {
            window.open(`voucher_create.php?user_id=${userId}&username=${encodeURIComponent(username)}`, '_blank');
        }

        // Modal Functions
        function showCreateModal() {
            document.getElementById('createModal').classList.remove('hidden');
        }

        function closeCreateModal() {
            document.getElementById('createModal').classList.add('hidden');
        }

        function closeUserModal() {
            document.getElementById('userModal').classList.add('hidden');
        }

        function toggleMobileMenu() {
            const mobileMenu = document.getElementById('mobileMenu');
            const menuIcon = document.getElementById('menuIcon');
            const closeIcon = document.getElementById('closeIcon');
            
            if (mobileMenu.classList.contains('hidden')) {
                mobileMenu.classList.remove('hidden');
                menuIcon.classList.add('hidden');
                closeIcon.classList.remove('hidden');
            } else {
                mobileMenu.classList.add('hidden');
                menuIcon.classList.remove('hidden');
                closeIcon.classList.add('hidden');
            }
        }

        // Toast Function
        function showToast(message, type = 'info') {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            
            const colors = {
                success: 'bg-green-500',
                error: 'bg-red-500',
                warning: 'bg-yellow-500',
                info: 'bg-purple-500'
            };
            
            const icons = {
                success: '✅',
                error: '❌',
                warning: '⚠️',
                info: 'ℹ️'
            };
            
            toast.className = `${colors[type]} text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 transform transition-all duration-300 translate-x-full`;
            toast.innerHTML = `
                <span>${icons[type]}</span>
                <span>${message}</span>
            `;
            
            container.appendChild(toast);
            
            setTimeout(() => toast.classList.remove('translate-x-full'), 100);
            setTimeout(() => {
                toast.classList.add('translate-x-full');
                setTimeout(() => container.removeChild(toast), 300);
            }, 4000);
        }

        // Event Listeners
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('searchInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') searchUsers();
            });
        });
    </script>
</body>
</html>
