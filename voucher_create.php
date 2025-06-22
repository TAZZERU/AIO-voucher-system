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

$canCreate = hasPermission('create_vouchers', $permissions);
$canDelete = hasPermission('delete_vouchers', $permissions);

if (!$canCreate) {
    header('Location: dashboard.php');
    exit;
}

$message = '';
$message_type = '';

// Pretix Push Function - ERWEITERT
function pushToPretix($voucherCode, $type, $price, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // Get category info
        $stmt = $pdo->prepare("SELECT name, icon FROM voucher_types WHERE type_key = ?");
        $stmt->execute([$type]);
        $categoryInfo = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $categoryName = $categoryInfo['name'] ?? $type;
        $categoryIcon = $categoryInfo['icon'] ?? '🎫';
        
        $data = [
            'code' => $voucherCode,
            'max_usages' => 1,
            'valid_until' => null,
            'price_mode' => 'set',
            'value' => $price,
            'tag' => $type, // Category-Key as Tag
            'comment' => $categoryIcon . ' ' . $categoryName . ' - Auto-created from Voucher System'
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

// Pretix Remove Function
function removePretixVoucher($voucherCode, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // Find Pretix ID
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
        
        return $httpCode === 204;
    } catch (Exception $e) {
        error_log('Pretix remove error: ' . $e->getMessage());
        return false;
    }
}

// AJAX Handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    switch ($_POST['action']) {
        case 'search_users':
            $search = trim($_POST['search'] ?? '');
            
            if (strlen($search) >= 2) {
                $stmt = $pdo->prepare("SELECT id, username, email, CONCAT(first_name, ' ', last_name) as full_name FROM users WHERE is_active = 1 AND (username LIKE ? OR email LIKE ? OR first_name LIKE ? OR last_name LIKE ?) ORDER BY username LIMIT 10");
                $searchTerm = "%$search%";
                $stmt->execute([$searchTerm, $searchTerm, $searchTerm, $searchTerm]);
                $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                echo json_encode(['success' => true, 'users' => $users]);
            } else {
                echo json_encode(['success' => true, 'users' => []]);
            }
            exit;
            
        case 'delete_voucher':
            if (!$canDelete) {
                echo json_encode(['success' => false, 'message' => 'No permission']);
                exit;
            }
            
            $voucherCode = $_POST['voucher_code'] ?? '';
            
            if (empty($voucherCode)) {
                echo json_encode(['success' => false, 'message' => 'Voucher code missing']);
                exit;
            }
            
            try {
                // remove from Pretix first
                removePretixVoucher($voucherCode, $pdo);
                
                // delete from database
                $stmt = $pdo->prepare("DELETE FROM vouchers WHERE voucher_code = ?");
                $result = $stmt->execute([$voucherCode]);
                
                if ($result && $stmt->rowCount() > 0) {
                    echo json_encode(['success' => true, 'message' => 'Voucher deleted successfully']);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Voucher not found']);
                }
            } catch (Exception $e) {
                echo json_encode(['success' => false, 'message' => 'Error deleting voucher']);
            }
            exit;
    }
}

// Load voucher types
$voucherTypes = $pdo->query("SELECT * FROM voucher_types WHERE is_active = 1 ORDER BY name")->fetchAll(PDO::FETCH_ASSOC);

// Create voucher
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action'])) {
    $userIdTarget = $_POST['user_id'];
    $type = $_POST['type'];
    $price = $_POST['price'];
    $quantity = intval($_POST['quantity'] ?? 1);
    
    // price-validation
    if (empty($userIdTarget) || empty($type) || $price === '' || !is_numeric($price) || $price < 0) {
        $message = 'Please fill in all required fields. Price must be 0 or higher.';
        $message_type = 'error';
    } elseif ($quantity < 1 || $quantity > 100) {
        $message = 'Quantity must be between 1 and 100';
        $message_type = 'error';
    } else {
        // Check if user exists and is active
        $stmt = $pdo->prepare("SELECT username, is_active FROM users WHERE id = ?");
        $stmt->execute([$userIdTarget]);
        $targetUser = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$targetUser) {
            $message = 'Selected user not found';
            $message_type = 'error';
        } elseif (!$targetUser['is_active']) {
            $message = 'Selected user is deactivated';
            $message_type = 'error';
        } else {
            // Check if voucher type exists and is active
            $stmt = $pdo->prepare("SELECT is_active FROM voucher_types WHERE type_key = ?");
            $stmt->execute([$type]);
            $categoryActive = $stmt->fetchColumn();
            
            try {
                $pdo->beginTransaction();
                $created = 0;
                $codes = [];
                
                for ($i = 0; $i < $quantity; $i++) {
                    // Generate unique code
                    do {
                        $code = strtoupper(substr(str_shuffle('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 4) . '-' . 
                                          substr(str_shuffle('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 4) . '-' . 
                                          substr(str_shuffle('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 4));
                        
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM vouchers WHERE voucher_code = ?");
                        $stmt->execute([$code]);
                        $exists = $stmt->fetchColumn() > 0;
                    } while ($exists);
                    
                    $stmt = $pdo->prepare("INSERT INTO vouchers (voucher_code, user_id, type, price, is_active, created_at) VALUES (?, ?, ?, ?, 1, NOW())");
                    if ($stmt->execute([$code, $userIdTarget, $type, $price])) {
                        $created++;
                        $codes[] = $code;
                        
                        // Pretix Push only if category is active
                        if ($categoryActive) {
                            pushToPretix($code, $type, $price, $pdo);
                        }
                    }
                }
                
                $pdo->commit();
                
                if ($created > 0) {
                    $message = "$created vouchers successfully created for " . $targetUser['username'] . "!";
                    $message_type = 'success';
                    $_SESSION['created_codes'] = $codes;
                } else {
                    $message = 'Error creating vouchers';
                    $message_type = 'error';
                }
                
            } catch (Exception $e) {
                $pdo->rollback();
                $message = 'Error: ' . $e->getMessage();
                $message_type = 'error';
            }
        }
    }
}

$createdCodes = $_SESSION['created_codes'] ?? [];
unset($_SESSION['created_codes']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Voucher - <?php echo getAppName(); ?></title>
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
            <h1 class="text-xl sm:text-2xl font-bold text-gray-800">🎫 Create Voucher</h1>
        </div>

        <!-- Messages -->
        <?php if ($message): ?>
            <div class="mb-6 p-4 rounded-lg <?php echo $message_type === 'success' ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <!-- Created Codes Display -->
        <?php if (!empty($createdCodes)): ?>
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
                <h2 class="text-lg font-bold text-gray-800 mb-4">✅ Created Vouchers</h2>
                <div class="space-y-3">
                    <?php foreach ($createdCodes as $code): ?>
                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg border">
                            <div class="font-mono font-bold text-blue-600 text-lg"><?php echo $code; ?></div>
                            <?php if ($canDelete): ?>
                                <button onclick="deleteVoucher('<?php echo $code; ?>')" 
                                        class="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm transition">
                                    🗑️ Delete
                                </button>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- Create Form -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
            <form method="POST" class="space-y-6">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">User *</label>
                    <div class="relative">
                        <input type="text" id="userSearch" placeholder="Search for user..." 
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                               autocomplete="off">
                        <input type="hidden" name="user_id" id="selectedUserId" required>
                        
                        <!-- Search Results -->
                        <div id="userResults" class="hidden absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg max-h-60 overflow-y-auto">
                            <!-- Results will be populated here -->
                        </div>
                    </div>
                    <p class="text-xs text-gray-500 mt-1">Type at least 2 characters to search</p>
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Voucher Type *</label>
                    <select name="type" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500" onchange="updatePrice()">
                        <option value="">Select type...</option>
                        <?php foreach ($voucherTypes as $vtype): ?>
                            <option value="<?php echo $vtype['type_key']; ?>" 
                                    data-price="<?php echo $vtype['default_price']; ?>"
                                    <?php echo ($_POST['type'] ?? '') == $vtype['type_key'] ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($vtype['icon'] . ' ' . $vtype['name']); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <p class="text-xs text-gray-500 mt-1">Category will be shown in Pretix with icon and name</p>
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Price (€) *</label>
                    <input type="number" name="price" step="0.01" min="0" required 
                           value="<?php echo htmlspecialchars($_POST['price'] ?? '10.00'); ?>"
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <p class="text-xs text-gray-500 mt-1">You can enter 0 for free vouchers (e.g. free drinks)</p>
                </div>

                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">Quantity</label>
                    <input type="number" name="quantity" min="1" max="100" 
                           value="<?php echo htmlspecialchars($_POST['quantity'] ?? '1'); ?>"
                           class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <p class="text-xs text-gray-500 mt-1">Maximum 100 vouchers at once</p>
                </div>

                <div class="flex gap-4">
                    <button type="submit" class="flex-1 bg-green-600 hover:bg-green-700 text-white py-3 px-4 rounded-lg font-medium transition">
                        🎫 Create Voucher(s)
                    </button>
                    <a href="vouchers.php" class="flex-1 bg-gray-600 hover:bg-gray-700 text-white py-3 px-4 rounded-lg font-medium text-center transition">
                        Cancel
                    </a>
                </div>
            </form>
        </div>
    </div>

    <script>
        let searchTimeout;
        let selectedUser = null;

        document.getElementById('userSearch').addEventListener('input', function(e) {
            const search = e.target.value.trim();
            
            clearTimeout(searchTimeout);
            
            if (search.length >= 2) {
                searchTimeout = setTimeout(() => {
                    searchUsers(search);
                }, 300);
            } else {
                hideResults();
                clearSelection();
            }
        });

        async function searchUsers(search) {
            try {
                const formData = new FormData();
                formData.append('action', 'search_users');
                formData.append('search', search);
                
                const response = await fetch('voucher_create.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    displayResults(result.users);
                }
            } catch (error) {
                console.error('Search error:', error);
            }
        }

        function displayResults(users) {
            const resultsDiv = document.getElementById('userResults');
            
            if (users.length === 0) {
                resultsDiv.innerHTML = '<div class="p-3 text-gray-500 text-sm">No users found</div>';
            } else {
                resultsDiv.innerHTML = users.map(user => `
                    <div class="p-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-b-0" 
                         onclick="selectUser(${user.id}, '${user.username}', '${user.email || ''}', '${user.full_name || ''}')">
                        <div class="font-medium text-gray-900">${user.username}</div>
                        ${user.email ? `<div class="text-sm text-gray-500">${user.email}</div>` : ''}
                        ${user.full_name && user.full_name.trim() !== ' ' ? `<div class="text-sm text-gray-600">${user.full_name}</div>` : ''}
                    </div>
                `).join('');
            }
            
            resultsDiv.classList.remove('hidden');
        }

        function selectUser(id, username, email, fullName) {
            selectedUser = {id, username, email, fullName};
            
            let displayText = username;
            if (fullName && fullName.trim() !== ' ') {
                displayText += ` (${fullName})`;
            } else if (email) {
                displayText += ` (${email})`;
            }
            
            document.getElementById('userSearch').value = displayText;
            document.getElementById('selectedUserId').value = id;
            hideResults();
        }

        function clearSelection() {
            selectedUser = null;
            document.getElementById('selectedUserId').value = '';
        }

        function hideResults() {
            document.getElementById('userResults').classList.add('hidden');
        }

        // Hide results when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('#userSearch') && !e.target.closest('#userResults')) {
                hideResults();
            }
        });

        async function deleteVoucher(voucherCode) {
            if (!confirm(`Really delete voucher ${voucherCode}? This will also remove it from Pretix.`)) {
                return;
            }
            
            try {
                const formData = new FormData();
                formData.append('action', 'delete_voucher');
                formData.append('voucher_code', voucherCode);
                
                const response = await fetch('voucher_create.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Remove the voucher element from the page
                    const voucherElements = document.querySelectorAll('.font-mono');
                    voucherElements.forEach(element => {
                        if (element.textContent === voucherCode) {
                            element.closest('.flex').remove();
                        }
                    });
                    
                    // Show success message
                    showTempMessage('Voucher deleted successfully', 'success');
                } else {
                    alert('Error: ' + result.message);
                }
            } catch (error) {
                alert('Error deleting voucher');
            }
        }

        function showTempMessage(message, type) {
            const messageDiv = document.createElement('div');
            messageDiv.className = `fixed top-4 right-4 p-4 rounded-lg z-50 ${type === 'success' ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'}`;
            messageDiv.textContent = message;
            
            document.body.appendChild(messageDiv);
            
            setTimeout(() => {
                messageDiv.remove();
            }, 3000);
        }

        function updatePrice() {
            const typeSelect = document.querySelector('select[name="type"]');
            const priceInput = document.querySelector('input[name="price"]');
            const selectedOption = typeSelect.options[typeSelect.selectedIndex];
            
            if (selectedOption && selectedOption.dataset.price) {
                priceInput.value = selectedOption.dataset.price;
            }
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
    </script>
</body>
</html>
