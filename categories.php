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
    }
}
$permissions = array_unique($permissions);

function hasPermission($perm, $perms) {
    return in_array($perm, $perms);
}

$canManage = hasPermission('manage_categories', $permissions);
$canDelete = hasPermission('delete_categories', $permissions);

if (!$canManage) {
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
        
        // find Pretix ID for voucher
        $stmt = $pdo->prepare("SELECT pretix_voucher_id FROM vouchers WHERE voucher_code = ?");
        $stmt->execute([$voucherCode]);
        $pretixId = $stmt->fetchColumn();
        
        if (!$pretixId) return false;
        
        // Delete voucher from Pretix
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
            return true;
        }
        
        return false;
    } catch (Exception $e) {
        error_log('Pretix remove error: ' . $e->getMessage());
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
        
        // find default price and value for type
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
        case 'load_categories':
            $stmt = $pdo->query("SELECT vt.*, COUNT(v.id) as voucher_count FROM voucher_types vt LEFT JOIN vouchers v ON vt.type_key = v.type GROUP BY vt.id ORDER BY vt.created_at DESC");
            echo json_encode(['success' => true, 'data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            exit;
            
        case 'create_category':
            if (!$canManage) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            $typeKey = strtolower(trim($_POST['type_key']));
            $name = trim($_POST['name']);
            $icon = trim($_POST['icon']) ?: '🎫';
            $price = floatval($_POST['default_price']);
            $value = floatval($_POST['default_value']);
            $isPermanent = isset($_POST['is_permanent_type']) ? 1 : 0;
            
            if (empty($typeKey) || empty($name)) {
                echo json_encode(['success' => false, 'message' => 'Type key and name are required']);
                exit;
            }
            
            // Check if type_key already exists
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM voucher_types WHERE type_key = ?");
            $stmt->execute([$typeKey]);
            if ($stmt->fetchColumn() > 0) {
                echo json_encode(['success' => false, 'message' => 'Type key already exists']);
                exit;
            }
            
            $stmt = $pdo->prepare("INSERT INTO voucher_types (type_key, name, icon, default_price, default_value, is_permanent_type, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, NOW())");
            $result = $stmt->execute([$typeKey, $name, $icon, $price, $value, $isPermanent]);
            echo json_encode(['success' => $result, 'message' => $result ? 'Category created' : 'Error']);
            exit;
            
        case 'update_category':
            if (!$canManage) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            $isPermanent = isset($_POST['is_permanent_type']) ? 1 : 0;
            
            $stmt = $pdo->prepare("UPDATE voucher_types SET name = ?, icon = ?, default_price = ?, default_value = ?, is_permanent_type = ? WHERE id = ?");
            $result = $stmt->execute([$_POST['name'], $_POST['icon'], $_POST['default_price'], $_POST['default_value'], $isPermanent, $_POST['category_id']]);
            echo json_encode(['success' => $result, 'message' => $result ? 'Category updated' : 'Error']);
            exit;
            
        case 'toggle_category':
            if (!$canManage) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            $categoryId = $_POST['category_id'];
            
            // Get current status
            $stmt = $pdo->prepare("SELECT is_active, type_key FROM voucher_types WHERE id = ?");
            $stmt->execute([$categoryId]);
            $category = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$category) {
                echo json_encode(['success' => false, 'message' => 'Category not found']);
                exit;
            }
            
            $newStatus = !$category['is_active'];
            
            $stmt = $pdo->prepare("UPDATE voucher_types SET is_active = ? WHERE id = ?");
            $result = $stmt->execute([$newStatus, $categoryId]);
            
            if ($result) {
                // Pretix Sync
                if ($newStatus) {
                    // Category activated - push all active vouchers to Pretix
                    $stmt = $pdo->prepare("SELECT voucher_code, type, price, actual_value, is_permanent, expires_at FROM vouchers WHERE type = ? AND is_active = 1 AND is_redeemed = 0");
                    $stmt->execute([$category['type_key']]);
                    $vouchers = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    foreach ($vouchers as $voucher) {
                        pushToPretix($voucher['voucher_code'], $voucher['type'], $voucher['price'], $voucher['actual_value'], $voucher['is_permanent'], $voucher['expires_at'], $pdo);
                    }
                } else {
                    // category deactivated - remove all vouchers from Pretix
                    $stmt = $pdo->prepare("SELECT voucher_code FROM vouchers WHERE type = ?");
                    $stmt->execute([$category['type_key']]);
                    $vouchers = $stmt->fetchAll(PDO::FETCH_COLUMN);
                    
                    foreach ($vouchers as $voucherCode) {
                        removePretixVoucher($voucherCode, $pdo);
                    }
                }
                
                echo json_encode(['success' => true, 'message' => 'Category status changed']);
            } else {
                echo json_encode(['success' => false, 'message' => 'Error updating category']);
            }
            exit;
            
        case 'delete_category':
            if (!$canDelete) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            // Check if category has vouchers
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM vouchers WHERE type = (SELECT type_key FROM voucher_types WHERE id = ?)");
            $stmt->execute([$_POST['category_id']]);
            $voucherCount = $stmt->fetchColumn();
            
            if ($voucherCount > 0) {
                echo json_encode(['success' => false, 'message' => "Cannot delete category: $voucherCount vouchers exist"]);
                exit;
            }
            
            $stmt = $pdo->prepare("DELETE FROM voucher_types WHERE id = ?");
            $result = $stmt->execute([$_POST['category_id']]);
            echo json_encode(['success' => $result, 'message' => $result ? 'Category deleted' : 'Error']);
            exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Categories - <?php echo getAppName(); ?></title>
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
                    <span class="hidden md:inline ml-4 text-base lg:text-lg text-gray-600">/ Categories</span>
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

    <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Header -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex flex-col sm:flex-row justify-between items-center gap-4">
                <h1 class="text-xl sm:text-2xl font-bold text-gray-800">🏷️ Voucher Categories</h1>
                <button onclick="showCreateModal()" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm transition">
                    + Create Category
                </button>
            </div>
        </div>

        <!-- Categories List -->
        <div class="bg-white rounded-xl shadow-lg">
            <div class="p-4 sm:p-6 border-b">
                <h2 class="text-lg font-bold text-gray-800">Category List</h2>
                <p class="text-sm text-gray-600 mt-1">Categories control Pretix sync - deactivated categories remove all vouchers from Pretix</p>
            </div>
            
            <div class="p-4 sm:p-6">
                <div id="categoryList">
                    <div class="text-center py-12 text-gray-500">
                        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
                        <p>Loading categories...</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Create Modal -->
    <div id="createModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-xl max-w-md w-full p-6">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-xl font-bold text-gray-800">🏷️ Create Category</h3>
                <button onclick="closeCreateModal()" class="text-gray-500 hover:text-gray-700 text-2xl">×</button>
            </div>
            
            <form onsubmit="createCategory(event)" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Type Key *</label>
                    <input type="text" name="type_key" required 
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                           placeholder="e.g., food, drink">
                    <p class="text-xs text-gray-500 mt-1">Lowercase, no spaces - used as tag in Pretix</p>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                    <input type="text" name="name" required 
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                           placeholder="e.g., Food Voucher">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Icon</label>
                    <input type="text" name="icon" 
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                           placeholder="🎫" maxlength="2">
                    <p class="text-xs text-gray-500 mt-1">Emoji shown in Pretix comment</p>
                </div>
                
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Default Price (€)</label>
                        <input type="number" name="default_price" step="0.01" min="0" value="10.00"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <p class="text-xs text-gray-500 mt-1">What customer pays</p>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Default Value (€)</label>
                        <input type="number" name="default_value" step="0.01" min="0" value="10.00"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <p class="text-xs text-gray-500 mt-1">Actual voucher worth</p>
                    </div>
                </div>
                
                <div class="flex items-center">
                    <input type="checkbox" name="is_permanent_type" id="create_permanent" 
                           class="rounded border-gray-300 text-blue-600 focus:ring-blue-500">
                    <label for="create_permanent" class="ml-2 text-sm font-medium text-gray-700">
                        ♾️ Permanent Voucher Type (never expires)
                    </label>
                </div>
                
                <div class="flex gap-2 pt-4">
                    <button type="submit" class="flex-1 bg-green-600 hover:bg-green-700 text-white py-2 rounded-lg transition">
                        🏷️ Create
                    </button>
                    <button type="button" onclick="closeCreateModal()" class="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Modal -->
    <div id="editModal" class="hidden fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center p-4">
        <div class="bg-white rounded-xl max-w-md w-full p-6">
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-xl font-bold text-gray-800">✏️ Edit Category</h3>
                <button onclick="closeEditModal()" class="text-gray-500 hover:text-gray-700 text-2xl">×</button>
            </div>
            
            <form onsubmit="updateCategory(event)" class="space-y-4">
                <input type="hidden" name="category_id" id="editCategoryId">
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Name *</label>
                    <input type="text" name="name" id="editName" required 
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Icon</label>
                    <input type="text" name="icon" id="editIcon"
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                           maxlength="2">
                </div>
                
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Default Price (€)</label>
                        <input type="number" name="default_price" id="editPrice" step="0.01" min="0"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <p class="text-xs text-gray-500 mt-1">What customer pays</p>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Default Value (€)</label>
                        <input type="number" name="default_value" id="editValue" step="0.01" min="0"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        <p class="text-xs text-gray-500 mt-1">Actual voucher worth</p>
                    </div>
                </div>
                
                <div class="flex items-center">
                    <input type="checkbox" name="is_permanent_type" id="edit_permanent" 
                           class="rounded border-gray-300 text-blue-600 focus:ring-blue-500">
                    <label for="edit_permanent" class="ml-2 text-sm font-medium text-gray-700">
                        ♾️ Permanent Voucher Type (never expires)
                    </label>
                </div>
                
                <div class="flex gap-2 pt-4">
                    <button type="submit" class="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-2 rounded-lg transition">
                        💾 Update
                    </button>
                    <button type="button" onclick="closeEditModal()" class="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-2 rounded-lg transition">
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Load categories
        async function loadCategories() {
            try {
                const formData = new FormData();
                formData.append('action', 'load_categories');
                
                const response = await fetch('categories.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    displayCategories(result.data);
                } else {
                    showError('Error loading categories');
                }
            } catch (error) {
                showError('Error loading categories');
            }
        }
        
        function displayCategories(categories) {
            const container = document.getElementById('categoryList');
            const canDelete = <?php echo $canDelete ? 'true' : 'false'; ?>;
            
            if (categories.length === 0) {
                container.innerHTML = `
                    <div class="text-center py-12 text-gray-500">
                        <div class="text-6xl mb-4">🏷️</div>
                        <p class="text-lg">No categories found</p>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = categories.map(category => `
                <div class="flex flex-col sm:flex-row sm:items-center justify-between p-4 bg-gray-50 hover:bg-gray-100 rounded-lg mb-4 transition">
                    <div class="flex-1">
                        <div class="flex items-center gap-3 mb-2">
                            <span class="text-2xl">${category.icon}</span>
                            <span class="font-bold text-lg text-gray-800">${category.name}</span>
                            ${category.is_permanent_type == 1 ? 
                                '<span class="bg-purple-100 text-purple-800 px-2 py-1 rounded-full text-xs">♾️ Permanent</span>' : ''
                            }
                            ${category.is_active == 1 ? 
                                '<span class="bg-green-100 text-green-800 px-2 py-1 rounded-full text-xs">✨ Active</span>' :
                                '<span class="bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs">🚫 Deactivated</span>'
                            }
                        </div>
                        <div class="text-sm text-gray-600">
                            <span><strong>Key:</strong> ${category.type_key}</span> • 
                            <span><strong>Price:</strong> €${parseFloat(category.default_price).toFixed(2)}</span> • 
                            <span><strong>Value:</strong> €${parseFloat(category.default_value).toFixed(2)}</span> • 
                            <span><strong>Vouchers:</strong> ${category.voucher_count}</span>
                        </div>
                        <div class="text-xs text-gray-500 mt-1">
                            Created: ${new Date(category.created_at).toLocaleDateString('en-US')}
                        </div>
                    </div>
                    
                    <div class="flex items-center gap-2 mt-3 sm:mt-0">
                        <button onclick="editCategory(${category.id}, '${category.name}', '${category.icon}', ${category.default_price}, ${category.default_value}, ${category.is_permanent_type})" 
                                class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded text-sm">
                            ✏️ Edit
                        </button>
                        
                        <button onclick="toggleCategory(${category.id}, ${category.is_active})" 
                                class="${category.is_active == 1 ? 'bg-yellow-600 hover:bg-yellow-700' : 'bg-green-600 hover:bg-green-700'} text-white px-3 py-1 rounded text-sm">
                            ${category.is_active == 1 ? '⏸️' : '▶️'}
                        </button>
                        
                        ${canDelete ? `
                            <button onclick="deleteCategory(${category.id}, ${category.voucher_count})" 
                                    class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm">
                                🗑️
                            </button>
                        ` : ''}
                    </div>
                </div>
            `).join('');
        }
        
        function showCreateModal() {
            document.getElementById('createModal').classList.remove('hidden');
        }
        
        function closeCreateModal() {
            document.getElementById('createModal').classList.add('hidden');
            document.querySelector('#createModal form').reset();
        }
        
        function editCategory(id, name, icon, price, value, isPermanent) {
            document.getElementById('editCategoryId').value = id;
            document.getElementById('editName').value = name;
            document.getElementById('editIcon').value = icon;
            document.getElementById('editPrice').value = price;
            document.getElementById('editValue').value = value;
            document.getElementById('edit_permanent').checked = isPermanent == 1;
            document.getElementById('editModal').classList.remove('hidden');
        }
        
        function closeEditModal() {
            document.getElementById('editModal').classList.add('hidden');
        }
        
        async function createCategory(event) {
            event.preventDefault();
            const formData = new FormData(event.target);
            formData.append('action', 'create_category');
            
            try {
                const response = await fetch('categories.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    closeCreateModal();
                    loadCategories();
                }
            } catch (error) {
                alert('Error creating category');
            }
        }
        
        async function updateCategory(event) {
            event.preventDefault();
            const formData = new FormData(event.target);
            formData.append('action', 'update_category');
            
            try {
                const response = await fetch('categories.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    closeEditModal();
                    loadCategories();
                }
            } catch (error) {
                alert('Error updating category');
            }
        }
        
        async function toggleCategory(id, currentStatus) {
            const action = currentStatus ? 'deactivate' : 'activate';
            if (!confirm(`Really ${action} category? This will ${currentStatus ? 'remove all vouchers from' : 'add all active vouchers to'} Pretix.`)) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'toggle_category');
                formData.append('category_id', id);
                
                const response = await fetch('categories.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    loadCategories();
                }
            } catch (error) {
                alert('Error changing category status');
            }
        }
        
        async function deleteCategory(id, voucherCount) {
            if (voucherCount > 0) {
                alert(`Cannot delete category: ${voucherCount} vouchers exist`);
                return;
            }
            
            if (!confirm('Really delete category? This cannot be undone!')) return;
            
            try {
                const formData = new FormData();
                formData.append('action', 'delete_category');
                formData.append('category_id', id);
                
                const response = await fetch('categories.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                alert(result.message);
                
                if (result.success) {
                    loadCategories();
                }
            } catch (error) {
                alert('Error deleting category');
            }
        }
        
        function showError(message) {
            document.getElementById('categoryList').innerHTML = `
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
            loadCategories();
        });
        
        // Close modals on escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeCreateModal();
                closeEditModal();
            }
        });
        
        // Type key formatting
        document.querySelector('#createModal input[name="type_key"]').addEventListener('input', function(e) {
            e.target.value = e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '');
        });
        
        // Auto-sync price and value fields if they're the same
        document.querySelector('#createModal input[name="default_price"]').addEventListener('input', function(e) {
            const valueField = document.querySelector('#createModal input[name="default_value"]');
            if (valueField.value === '' || valueField.value === this.defaultValue) {
                valueField.value = e.target.value;
            }
        });
        
        document.querySelector('#editModal input[name="default_price"]').addEventListener('input', function(e) {
            const valueField = document.querySelector('#editModal input[name="default_value"]');
            if (valueField.value === this.value) {
                valueField.value = e.target.value;
            }
        });
    </script>
</body>
</html>
