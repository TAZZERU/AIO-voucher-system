<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

define('CONFIG_ACCESS', true);
require_once 'config/app_config.php';

$pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
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
        case 'voucher_manager':
            $permissions = array_merge($permissions, ['view_vouchers', 'scan_vouchers', 'create_vouchers', 'manage_vouchers', 'delete_vouchers', 'manage_categories', 'export_data']);
            break;
        case 'scanner':
            $permissions = array_merge($permissions, ['scan_vouchers']);
            break;
        case 'user':
            $permissions = array_merge($permissions, ['view_own_vouchers']);
            break;
    }
}
$permissions = array_unique($permissions);

function hasPermission($perm, $perms) {
    return in_array($perm, $perms);
}

$canViewAll = hasPermission('view_vouchers', $permissions);
$canCreate = hasPermission('create_vouchers', $permissions);
$canDelete = hasPermission('delete_vouchers', $permissions);
$canScan = hasPermission('scan_vouchers', $permissions);
$canViewOwn = hasPermission('view_own_vouchers', $permissions);
$canManage = hasPermission('manage_vouchers', $permissions);

// Scanner-Only Check
$isScannerOnly = $canScan && !$canViewAll && !$canViewOwn;

if (!$canViewAll && !$canViewOwn && !$isScannerOnly) {
    header('Location: dashboard.php');
    exit;
}

// Pretix functions
function removePretixVoucher($voucherCode, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // Find Vouchers in Pretix
        $stmt = $pdo->prepare("SELECT pretix_voucher_id FROM vouchers WHERE voucher_code = ?");
        $stmt->execute([$voucherCode]);
        $pretixId = $stmt->fetchColumn();
        
        if (!$pretixId) return false;
        
        // Delete from Pretix
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $settings['api_url'] . '/api/v1/organizers/' . $settings['organizer'] . '/events/' . $settings['event'] . '/vouchers/' . $pretixId . '/');
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Token ' . $settings['api_token']
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 204) {
            // Update local database
            $stmt = $pdo->prepare("UPDATE vouchers SET pretix_voucher_id = NULL, pretix_published = 0 WHERE voucher_code = ?");
            $stmt->execute([$voucherCode]);
            return true;
        }
        
        return false;
    } catch (Exception $e) {
        error_log('Pretix remove error: ' . $e->getMessage());
        return false;
    }
}

function markPretixVoucherAsRedeemed($voucherCode, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // Find Vouchers in Pretix
        $stmt = $pdo->prepare("SELECT pretix_voucher_id FROM vouchers WHERE voucher_code = ?");
        $stmt->execute([$voucherCode]);
        $pretixId = $stmt->fetchColumn();
        
        if (!$pretixId) return false;
        
        // Markiere as redeemed in Pretix 
        $data = [
            'redeemed' => 1  
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $settings['api_url'] . '/api/v1/organizers/' . $settings['organizer'] . '/events/' . $settings['event'] . '/vouchers/' . $pretixId . '/');
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Token ' . $settings['api_token'],
            'Content-Type: application/json'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return $httpCode === 200;
    } catch (Exception $e) {
        error_log('Pretix mark redeemed error: ' . $e->getMessage());
        return false;
    }
}

function pushToPretix($voucherCode, $type, $price, $actualValue, $isPermanent, $expiresAt, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // Get Details 
        $stmt = $pdo->prepare("SELECT name, icon FROM voucher_types WHERE type_key = ?");
        $stmt->execute([$type]);
        $categoryInfo = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $categoryName = $categoryInfo['name'] ?? $type;
        $categoryIcon = $categoryInfo['icon'] ?? '🎫';
        
        $comment = $categoryIcon . ' ' . $categoryName;
        if ($actualValue != $price) {
            $comment .= ' (Value: €' . number_format($actualValue, 2) . ', Price: €' . number_format($price, 2) . ')';
        }
        if ($isPermanent) {
            $comment .= ' - PERMANENT VOUCHER';
        }
        $comment .= ' - Auto-created from Voucher System';
        
        $data = [
            'code' => $voucherCode,
            'max_usages' => 1,
            'valid_until' => $isPermanent ? null : $expiresAt,
            'price_mode' => 'set',
            'value' => $price,
            'tag' => $type,
            'comment' => $comment
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $settings['api_url'] . '/api/v1/organizers/' . $settings['organizer'] . '/events/' . $settings['event'] . '/vouchers/');
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Token ' . $settings['api_token'],
            'Content-Type: application/json'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 201) {
            $responseData = json_decode($response, true);
            $stmt = $pdo->prepare("UPDATE vouchers SET pretix_voucher_id = ?, pretix_published = 1 WHERE voucher_code = ?");
            $stmt->execute([$responseData['id'], $voucherCode]);
            return true;
        }
        
        return false;
    } catch (Exception $e) {
        error_log('Pretix push error: ' . $e->getMessage());
        return false;
    }
}

// AJAX Handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    switch ($_POST['action']) {
        case 'load_vouchers':
            $search = $_POST['search'] ?? '';
            $searchUser = $_POST['search_user'] ?? '';
            
            if ($canViewAll) {
                $query = "SELECT v.*, u.username, u.is_active as user_active, vt.is_active as category_active, vt.name as category_name 
                         FROM vouchers v 
                         LEFT JOIN users u ON v.user_id = u.id 
                         LEFT JOIN voucher_types vt ON v.type = vt.type_key 
                         WHERE 1=1";
                $params = [];
                
                if ($search) {
                    $query .= " AND v.voucher_code LIKE ?";
                    $params[] = "%$search%";
                }
                if ($searchUser) {
                    $query .= " AND u.username LIKE ?";
                    $params[] = "%$searchUser%";
                }
                
                $query .= " ORDER BY v.created_at DESC LIMIT 50";
                
                $stmt = $pdo->prepare($query);
                $stmt->execute($params);
            } elseif ($canViewOwn) {
                $query = "SELECT v.*, u.username, u.is_active as user_active, vt.is_active as category_active, vt.name as category_name 
                         FROM vouchers v 
                         LEFT JOIN users u ON v.user_id = u.id 
                         LEFT JOIN voucher_types vt ON v.type = vt.type_key 
                         WHERE v.user_id = ?";
                $params = [$userId];
                
                if ($search) {
                    $query .= " AND v.voucher_code LIKE ?";
                    $params[] = "%$search%";
                }
                
                $query .= " ORDER BY v.created_at DESC";
                
                $stmt = $pdo->prepare($query);
                $stmt->execute($params);
            } elseif ($isScannerOnly) {
                // Für Scanner: Mit Suche oder die letzten 5
                $query = "SELECT v.*, u.username, u.is_active as user_active, vt.is_active as category_active, vt.name as category_name 
                         FROM vouchers v 
                         LEFT JOIN users u ON v.user_id = u.id 
                         LEFT JOIN voucher_types vt ON v.type = vt.type_key 
                         WHERE 1=1";
                $params = [];
                
                if ($search) {
                    $query .= " AND v.voucher_code LIKE ?";
                    $params[] = "%$search%";
                }
                if ($searchUser) {
                    $query .= " AND u.username LIKE ?";
                    $params[] = "%$searchUser%";
                }
                
                $query .= " ORDER BY v.created_at DESC";
                
                // Limit 
                if (empty($search) && empty($searchUser)) {
                    $query .= " LIMIT 5";
                } else {
                    $query .= " LIMIT 20"; 
                }
                
                $stmt = $pdo->prepare($query);
                $stmt->execute($params);
            } else {
                echo json_encode(['success' => false, 'message' => 'No permission to view vouchers']);
                exit;
            }
            
            echo json_encode(['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            exit;
            
        case 'redeem_voucher':
            if (!$canScan) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            // Check if code is provided
            $stmt = $pdo->prepare("
                SELECT v.*, vt.is_active as category_active 
                FROM vouchers v 
                LEFT JOIN voucher_types vt ON v.type = vt.type_key 
                WHERE v.voucher_code = ? AND v.is_redeemed = 0 AND v.is_active = 1
            ");
            $stmt->execute([$_POST['code']]);
            $voucher = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$voucher) {
                echo json_encode(['success' => false, 'message' => 'Voucher not found or already redeemed or deactivated']);
                exit;
            }
            
            if (!$voucher['category_active']) {
                echo json_encode(['success' => false, 'message' => 'Voucher category is deactivated']);
                exit;
            }
            
            // Check if user is active
            if (!$voucher['is_permanent'] && $voucher['expires_at'] && strtotime($voucher['expires_at']) < time()) {
                echo json_encode(['success' => false, 'message' => 'Voucher has expired on ' . date('m/d/Y', strtotime($voucher['expires_at']))]);
                exit;
            }
            
            $stmt = $pdo->prepare("UPDATE vouchers SET is_redeemed = 1, redeemed_at = NOW(), redeemed_by = ? WHERE voucher_code = ?");
            $result = $stmt->execute([$userId, $_POST['code']]);
            
            if ($result && $stmt->rowCount() > 0) {
                // Pretix Sync 
                markPretixVoucherAsRedeemed($_POST['code'], $pdo);
                
                echo json_encode(['success' => true, 'message' => 'Voucher successfully redeemed']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Error redeeming voucher']);
            }
            exit;
            
        case 'toggle_voucher_status':
            if (!$canManage) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            // Check if voucher ID is provided
            $stmt = $pdo->prepare("
                SELECT v.*, vt.is_active as category_active 
                FROM vouchers v 
                LEFT JOIN voucher_types vt ON v.type = vt.type_key 
                WHERE v.id = ?
            ");
            $stmt->execute([$_POST['voucher_id']]);
            $voucher = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$voucher) {
                echo json_encode(['success' => false, 'message' => 'Voucher not found']);
                exit;
            }
            
            // If voucher is already redeemed, it cannot be activated
            if (!$voucher['is_active'] && !$voucher['category_active']) {
                echo json_encode(['success' => false, 'message' => 'Cannot activate voucher: Category is deactivated']);
                exit;
            }
            
            $newStatus = !$voucher['is_active'];
            
            $stmt = $pdo->prepare("UPDATE vouchers SET is_active = ? WHERE id = ?");
            $result = $stmt->execute([$newStatus, $_POST['voucher_id']]);
            
            if ($result) {
                // Pretix Sync
                if ($newStatus && $voucher['category_active'] && !$voucher['is_redeemed']) {
                    // Voucher active
                    pushToPretix($voucher['voucher_code'], $voucher['type'], $voucher['price'], $voucher['actual_value'], $voucher['is_permanent'], $voucher['expires_at'], $pdo);
                } else {
                    // Voucher not active or deactivated
                    removePretixVoucher($voucher['voucher_code'], $pdo);
                }
                
                echo json_encode(['success' => true, 'message' => 'Voucher status changed']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Error']);
            }
            exit;
            
        case 'delete_voucher':
            if (!$canDelete) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            // First check if voucher ID is provided
            $stmt = $pdo->prepare("SELECT voucher_code FROM vouchers WHERE id = ?");
            $stmt->execute([$_POST['voucher_id']]);
            $voucherCode = $stmt->fetchColumn();
            
            if ($voucherCode) {
                removePretixVoucher($voucherCode, $pdo);
            }
            
            $stmt = $pdo->prepare("DELETE FROM vouchers WHERE id = ?");
            $result = $stmt->execute([$_POST['voucher_id']]);
            echo json_encode(['success' => $result, 'message' => $result ? 'Voucher permanently deleted' : 'Error']);
            exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vouchers - <?php echo getAppName(); ?></title>
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
                                <img src="<?php echo htmlspecialchars(getLogoUrl()); ?>" 
                                     alt="<?php echo htmlspecialchars(getCompanyName()); ?>" 
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
                    <span class="hidden md:inline ml-4 text-base lg:text-lg text-gray-600">/ Vouchers</span>
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
                    <a href="profile.php" class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg text-sm transition">
                        👤 Profile
                    </a>
                    <div class="text-sm text-gray-600">
                        <strong class="hidden lg:inline"><?php echo htmlspecialchars($username); ?></strong>
                        <strong class="lg:hidden"><?php echo htmlspecialchars(substr($username, 0, 10)); ?></strong>
                        <div class="text-xs text-blue-600 hidden lg:block"><?php echo implode(', ', $userRoles); ?></div>
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
                        <div class="text-xs text-blue-600"><?php echo implode(', ', $userRoles); ?></div>
                    </div>
                    
                    <a href="dashboard.php" class="block px-3 py-2 text-base font-medium text-gray-700 hover:text-gray-900 hover:bg-gray-50 rounded-md transition">
                        🏠 Dashboard
                    </a>
                    
                    <a href="profile.php" class="block px-3 py-2 text-base font-medium text-blue-700 hover:text-blue-900 hover:bg-blue-50 rounded-md transition">
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
        
        <!-- Header -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex flex-col space-y-4 sm:flex-row sm:items-center sm:justify-between sm:space-y-0 gap-4">
                <h1 class="text-xl sm:text-2xl font-bold text-gray-800">
                    <?php 
                    if ($canViewAll) {
                        echo 'All Vouchers';
                    } elseif ($canViewOwn) {
                        echo 'My Vouchers';
                    } elseif ($isScannerOnly) {
                        echo 'Voucher Search';
                    }
                    ?>
                </h1>
                
                <div class="flex flex-col sm:flex-row gap-2">
                    <?php if ($canViewAll || $isScannerOnly): ?>
                        <div class="flex flex-col sm:flex-row gap-2">
                            <input type="text" id="voucherSearch" placeholder="Search voucher code..." 
                                   class="flex-1 sm:w-48 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500">
                            <input type="text" id="userSearch" placeholder="Search by user..." 
                                   class="flex-1 sm:w-48 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500">
                            <button onclick="searchVouchers()" 
                                    class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg text-sm transition">
                                🔍 Search
                            </button>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($canCreate): ?>
                        <a href="voucher_create.php" class="bg-green-600 hover:bg-green-700 text-white px-3 py-2 rounded-lg text-sm text-center transition">
                            <span class="hidden sm:inline">+ Create Voucher</span>
                            <span class="sm:hidden">+ Voucher</span>
                        </a>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Scanner -->
        <?php if ($canScan): ?>
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <h2 class="text-lg font-bold text-gray-800 mb-4">📱 Redeem Voucher</h2>
            <div class="flex flex-col sm:flex-row gap-2">
                <input type="text" id="scanCode" placeholder="Code: XXXX-XXXX-XXXX" 
                       class="flex-1 px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm">
                <button onclick="redeemVoucher()" 
                        class="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    Redeem
                </button>
            </div>
        </div>
        <?php endif; ?>

        <!-- Voucher List -->
        <div class="bg-white rounded-xl shadow-lg">
            <div class="p-4 sm:p-6 border-b">
                <h2 class="text-lg font-bold text-gray-800">Voucher List</h2>
                <?php if ($isScannerOnly): ?>
                    <p class="text-sm text-gray-600 mt-1">Use search to find specific vouchers or view the 5 most recent ones</p>
                <?php endif; ?>
            </div>
            
            <div class="p-4 sm:p-6">
                <div id="voucherList">
                    <div class="text-center py-12 text-gray-500">
                        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                        <p>Loading vouchers...</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- QR Modal -->
    <div id="qrModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-xl max-w-md w-full p-6 text-center">
            <h3 class="text-xl font-bold text-gray-800 mb-4">QR Code</h3>
            <div id="qrCode"></div>
            <button onclick="closeQR()" class="mt-4 bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg">
                Close
            </button>
        </div>
    </div>

    <script>
        // Load vouchers
        async function loadVouchers(search = '') {
            const userSearch = document.getElementById('userSearch') ? document.getElementById('userSearch').value.trim() : '';
            try {
                const formData = new FormData();
                formData.append('action', 'load_vouchers');
                formData.append('search', search);
                formData.append('search_user', userSearch);
                
                const response = await fetch('vouchers.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    displayVouchers(result.data);
                } else {
                    showError('Error loading vouchers: ' + (result.message || 'Unknown error'));
                }
            } catch (error) {
                showError('Error loading vouchers: Network error');
            }
        }
        
        function displayVouchers(vouchers) {
            const container = document.getElementById('voucherList');
            const canViewAll = <?php echo $canViewAll ? 'true' : 'false'; ?>;
            const canManage = <?php echo $canManage ? 'true' : 'false'; ?>;
            const canDelete = <?php echo $canDelete ? 'true' : 'false'; ?>;
            const canScan = <?php echo $canScan ? 'true' : 'false'; ?>;
            const isScannerOnly = <?php echo $isScannerOnly ? 'true' : 'false'; ?>;
            
            if (vouchers.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-12 text-gray-500">
                        <div class="text-6xl mb-4">📭</div>
                        <p class="text-lg">No vouchers found</p>
                        ${isScannerOnly ? '<p class="text-sm text-gray-400 mt-2">Try searching for specific vouchers or users</p>' : ''}
                    </div>
                `;
                return;
            }
            
            container.innerHTML = vouchers.map(voucher => {
                const now = new Date();
                const expiresAt = voucher.expires_at ? new Date(voucher.expires_at) : null;
                const isExpired = !voucher.is_permanent && expiresAt && expiresAt < now;
                
                return `
                <div class="flex flex-col sm:flex-row sm:items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 rounded-lg mb-4 transition">
                    <div class="flex-1">
                        <div class="flex items-center gap-3 mb-2">
                            <span class="font-mono font-bold text-lg text-blue-600">${voucher.voucher_code}</span>
                            ${voucher.is_permanent ? 
                                '<span class="bg-purple-100 text-purple-800 px-2 py-1 rounded-full text-xs">♾️ Permanent</span>' : ''
                            }
                            ${isExpired ? 
                                '<span class="bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs">⏰ Expired</span>' :
                                voucher.is_redeemed ? 
                                '<span class="bg-gray-100 text-gray-600 px-2 py-1 rounded-full text-xs">✓ Redeemed</span>' :
                                voucher.is_active == 0 ?
                                '<span class="bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs">🚫 Deactivated</span>' :
                                voucher.category_active == 0 ?
                                '<span class="bg-purple-100 text-purple-800 px-2 py-1 rounded-full text-xs">🚫 Category Deactivated</span>' :
                                '<span class="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs">✨ Available</span>'
                            }
                            ${voucher.user_active == 0 ? 
                                '<span class="bg-orange-100 text-orange-800 px-2 py-1 rounded-full text-xs">🚫 User Deactivated</span>' : ''
                            }
                        </div>
                        <div class="text-sm text-gray-600">
                            <span><strong>Type:</strong> ${voucher.type}</span> • 
                            <span><strong>Value:</strong> €${parseFloat(voucher.actual_value || voucher.price).toFixed(2)}</span>
                            ${voucher.actual_value != voucher.price ? ` • <strong>Price:</strong> €${parseFloat(voucher.price).toFixed(2)}` : ''}
                            ${voucher.username ? ` • <strong>User:</strong> ${voucher.username}` : ''}
                            ${voucher.category_name ? ` • <strong>Category:</strong> ${voucher.category_name}` : ''}
                        </div>
                        <div class="text-xs text-gray-500 mt-1">
                            Created: ${new Date(voucher.created_at).toLocaleDateString('en-US')}
                            ${voucher.expires_at && !voucher.is_permanent ? ` • Expires: ${new Date(voucher.expires_at).toLocaleDateString('en-US')}` : ''}
                            ${voucher.redeemed_at ? ` • Redeemed: ${new Date(voucher.redeemed_at).toLocaleDateString('en-US')}` : ''}
                        </div>
                    </div>
                    
                    <div class="flex items-center gap-2 mt-3 sm:mt-0">
                        ${(!voucher.is_redeemed && !isExpired && voucher.user_active == 1 && voucher.is_active == 1 && voucher.category_active == 1) || canViewAll ? `
                            <button onclick="showQR('${voucher.voucher_code}')" 
                                    class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                                QR
                            </button>
                        ` : ''}
                        
                        ${!voucher.is_redeemed && !isExpired && voucher.user_active == 1 && voucher.is_active == 1 && voucher.category_active == 1 && canScan ? `
                            <button onclick="quickRedeem('${voucher.voucher_code}')" 
                                    class="bg-orange-600 hover:bg-orange-700 text-white px-3 py-1 rounded text-sm">
                                Redeem
                            </button>
                        ` : ''}
                        
                        ${canManage && !isScannerOnly ? `
                            <button onclick="toggleVoucherStatus(${voucher.id}, ${voucher.is_active}, ${voucher.category_active})" 
                                    class="${voucher.is_active == 1 ? 'bg-yellow-600 hover:bg-yellow-700' : 'bg-green-600 hover:bg-green-700'} text-white px-3 py-1 rounded text-sm ${voucher.category_active == 0 && voucher.is_active == 0 ? 'opacity-50 cursor-not-allowed' : ''}"
                                    ${voucher.category_active == 0 && voucher.is_active == 0 ? 'disabled title="Cannot activate: Category is deactivated"' : ''}>
                                ${voucher.is_active == 1 ? '⏸️' : '▶️'}
                            </button>
                        ` : ''}
                        
                        ${canDelete && !isScannerOnly ? `
                            <button onclick="deleteVoucher(${voucher.id})" 
                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm">
                                🗑️
                            </button>
                        ` : ''}
                    </div>
                </div>
                `;
            }).join('');
        }
        
        function searchVouchers() {
            const search = document.getElementById('voucherSearch').value;
            loadVouchers(search);
        }
        
        async function redeemVoucher() {
            const code = document.getElementById('scanCode').value.trim();
            if (!code) {
                alert('Please enter voucher code');
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('action', 'redeem_voucher');
                formData.append('code', code);
                
                const response = await fetch('vouchers.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    document.getElementById('scanCode').value = '';
                    loadVouchers();
                }
            } catch (error) {
                alert('Error redeeming voucher');
            }
        }
        
        async function quickRedeem(code) {
            if (!confirm(`Redeem voucher ${code}?`)) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'redeem_voucher');
                formData.append('code', code);
                
                const response = await fetch('vouchers.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    loadVouchers();
                }
            } catch (error) {
                alert('Error redeeming voucher');
            }
        }
        
        async function toggleVoucherStatus(id, currentStatus, categoryActive) {
            // If the voucher is already redeemed or expired, do not allow status change
            if (!currentStatus && !categoryActive) {
                alert('Cannot activate voucher: Category is deactivated');
                return;
            }
            
            const action = currentStatus ? 'deactivate' : 'activate';
            if (!confirm(`Really ${action} voucher?`)) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'toggle_voucher_status');
                formData.append('voucher_id', id);
                
                const response = await fetch('vouchers.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    loadVouchers();
                }
            } catch (error) {
                alert('Error changing voucher status');
            }
        }
        
        async function deleteVoucher(id) {
            if (!confirm('Really permanently delete voucher? This cannot be undone!')) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'delete_voucher');
                formData.append('voucher_id', id);
                
                const response = await fetch('vouchers.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    loadVouchers();
                }
            } catch (error) {
                alert('Error deleting voucher');
            }
        }
        
        function showQR(code) {
            document.getElementById('qrCode').innerHTML = `
                <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(code)}" 
                     alt="QR Code" class="mx-auto border rounded-lg mb-4">
                <div class="font-mono text-lg font-bold">${code}</div>
            `;
            document.getElementById('qrModal').classList.remove('hidden');
        }
        
        function closeQR() {
            document.getElementById('qrModal').classList.add('hidden');
        }
        
        function showError(message) {
            document.getElementById('voucherList').innerHTML = `
                <div class="text-center py-12 text-red-500">
                    <div class="text-6xl mb-4">⚠️</div>
                    <p>${message}</p>
                </div>
            `;
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

        // Event Listeners
        document.addEventListener('DOMContentLoaded', function() {
            loadVouchers();
            
            // Enter key for search
            document.getElementById('voucherSearch')?.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') searchVouchers();
            });
            
            document.getElementById('userSearch')?.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') searchVouchers();
            });
            
            // Enter key for scanner
            document.getElementById('scanCode')?.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') redeemVoucher();
            });
            
            // Code formatting
            document.getElementById('scanCode')?.addEventListener('input', function(e) {
                let value = e.target.value.replace(/[^A-Z0-9]/g, '').toUpperCase();
                if (value.length > 12) value = value.substring(0, 12);
                
                if (value.length > 8) {
                    value = value.substring(0, 4) + '-' + value.substring(4, 8) + '-' + value.substring(8);
                } else if (value.length > 4) {
                    value = value.substring(0, 4) + '-' + value.substring(4);
                }
                
                e.target.value = value;
            });
        });
    </script>
</body>
</html>
