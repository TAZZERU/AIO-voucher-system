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

// Session-Check for deactivated accounts
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

// Load user data
$stmt = $pdo->prepare("SELECT u.*, GROUP_CONCAT(ur.role) as roles FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id WHERE u.id = ? GROUP BY u.id");
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    session_destroy();
    header('Location: login.php');
    exit;
}

$userRoles = explode(',', $user['roles'] ?? '');

$message = '';
$message_type = '';

// Update profile
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $email = trim($_POST['email']) ?: null;
    $firstName = trim($_POST['first_name']) ?: null;
    $lastName = trim($_POST['last_name']) ?: null;
    
    // Check if email exists (excluding current user)
    if ($email) {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?");
        $stmt->execute([$email, $userId]);
        if ($stmt->fetchColumn() > 0) {
            $message = 'Email already exists';
            $message_type = 'error';
        }
    }
    
    if (!$message) {
        try {
            $stmt = $pdo->prepare("UPDATE users SET email = ?, first_name = ?, last_name = ?, updated_at = NOW() WHERE id = ?");
            $result = $stmt->execute([$email, $firstName, $lastName, $userId]);
            
            if ($result) {
                $message = 'Profile updated successfully!';
                $message_type = 'success';
                
                // Reload user data
                $stmt = $pdo->prepare("SELECT u.*, GROUP_CONCAT(ur.role) as roles FROM users u LEFT JOIN user_roles ur ON u.id = ur.user_id WHERE u.id = ? GROUP BY u.id");
                $stmt->execute([$userId]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
            } else {
                $message = 'Error updating profile';
                $message_type = 'error';
            }
        } catch (Exception $e) {
            $message = 'Database error: ' . $e->getMessage();
            $message_type = 'error';
        }
    }
}

// Change password
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['change_password'])) {
    $currentPassword = $_POST['current_password'];
    $newPassword = $_POST['new_password'];
    $confirmPassword = $_POST['confirm_password'];
    
    if (empty($currentPassword) || empty($newPassword) || empty($confirmPassword)) {
        $message = 'Please fill in all password fields';
        $message_type = 'error';
    } elseif (strlen($newPassword) < 6) {
        $message = 'New password must be at least 6 characters';
        $message_type = 'error';
    } elseif ($newPassword !== $confirmPassword) {
        $message = 'New passwords do not match';
        $message_type = 'error';
    } elseif (!password_verify($currentPassword, $user['password_hash'])) {
        $message = 'Current password is incorrect';
        $message_type = 'error';
    } else {
        try {
            $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, updated_at = NOW() WHERE id = ?");
            $result = $stmt->execute([password_hash($newPassword, PASSWORD_DEFAULT), $userId]);
            
            if ($result) {
                $message = 'Password changed successfully!';
                $message_type = 'success';
            } else {
                $message = 'Error changing password';
                $message_type = 'error';
            }
        } catch (Exception $e) {
            $message = 'Database error: ' . $e->getMessage();
            $message_type = 'error';
        }
    }
}

// Load user statistics
$stats = ['total' => 0, 'active' => 0, 'redeemed' => 0, 'total_value' => 0];
try {
    $stmt = $pdo->prepare("SELECT COUNT(*) as total, SUM(CASE WHEN is_redeemed = 0 THEN 1 ELSE 0 END) as active, SUM(CASE WHEN is_redeemed = 1 THEN 1 ELSE 0 END) as redeemed, SUM(price) as total_value FROM vouchers WHERE user_id = ?");
    $stmt->execute([$userId]);
    $stats = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    // Keep default stats
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - <?php echo getAppName(); ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Navigation -->
    <nav class="bg-white shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex items-center">
                    <a href="dashboard.php" class="flex items-center text-xl sm:text-2xl font-bold text-gray-900">
                        <span class="text-2xl mr-2">🎫</span>
                        <span class="hidden sm:inline"><?php echo getAppName(); ?></span>
                        <span class="sm:hidden">Voucher</span>
                    </a>
                    <span class="hidden md:inline ml-4 text-base lg:text-lg text-gray-600">/ Profile</span>
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
                    
                    <a href="logout.php" class="block px-3 py-2 text-base font-medium text-red-600 hover:text-red-900 hover:bg-red-50 rounded-md transition">
                        🚪 Logout
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Header -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex items-center">
                <div class="bg-blue-100 p-3 rounded-full mr-4">
                    <span class="text-2xl">👤</span>
                </div>
                <div>
                    <h1 class="text-xl sm:text-2xl font-bold text-gray-800"><?php echo htmlspecialchars($user['username']); ?></h1>
                    <p class="text-gray-600"><?php echo implode(', ', array_filter($userRoles)); ?></p>
                </div>
            </div>
        </div>

        <!-- Messages -->
        <?php if ($message): ?>
            <div class="mb-6 p-4 rounded-lg <?php echo $message_type === 'success' ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <!-- Statistics -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6 mb-8">
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-xs sm:text-sm font-medium text-gray-500 uppercase">My Vouchers</p>
                        <p class="text-xl sm:text-3xl font-bold text-blue-600"><?php echo $stats['total'] ?? 0; ?></p>
                    </div>
                    <div class="bg-blue-100 p-2 sm:p-3 rounded-full">🎫</div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-xs sm:text-sm font-medium text-gray-500 uppercase">Active</p>
                        <p class="text-xl sm:text-3xl font-bold text-green-600"><?php echo $stats['active'] ?? 0; ?></p>
                    </div>
                    <div class="bg-green-100 p-2 sm:p-3 rounded-full">✨</div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-xs sm:text-sm font-medium text-gray-500 uppercase">Redeemed</p>
                        <p class="text-xl sm:text-3xl font-bold text-gray-600"><?php echo $stats['redeemed'] ?? 0; ?></p>
                    </div>
                    <div class="bg-gray-100 p-2 sm:p-3 rounded-full">✓</div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-xs sm:text-sm font-medium text-gray-500 uppercase">Total Value</p>
                        <p class="text-lg sm:text-3xl font-bold text-purple-600">€<?php echo number_format($stats['total_value'] ?? 0, 0); ?></p>
                    </div>
                    <div class="bg-purple-100 p-2 sm:p-3 rounded-full">💰</div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            <!-- Profile Information -->
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <h2 class="text-lg font-bold text-gray-800 mb-4">👤 Profile Information</h2>
                
                <form method="POST" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Username</label>
                        <input type="text" value="<?php echo htmlspecialchars($user['username']); ?>" readonly 
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg bg-gray-100">
                        <p class="text-xs text-gray-500 mt-1">Username cannot be changed</p>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
                        <input type="email" name="email" value="<?php echo htmlspecialchars($user['email'] ?? ''); ?>"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">First Name</label>
                            <input type="text" name="first_name" value="<?php echo htmlspecialchars($user['first_name'] ?? ''); ?>"
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Last Name</label>
                            <input type="text" name="last_name" value="<?php echo htmlspecialchars($user['last_name'] ?? ''); ?>"
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        </div>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Roles</label>
                        <div class="flex flex-wrap gap-2">
                            <?php foreach (array_filter($userRoles) as $role): ?>
                                <span class="bg-blue-100 text-blue-800 px-2 py-1 rounded-full text-xs">
                                    <?php echo htmlspecialchars($role); ?>
                                </span>
                            <?php endforeach; ?>
                        </div>
                        <p class="text-xs text-gray-500 mt-1">Roles are managed by administrators</p>
                    </div>
                    
                    <button type="submit" name="update_profile" value="1" 
                            class="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg transition">
                        💾 Update Profile
                    </button>
                </form>
            </div>

            <!-- Change Password -->
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <h2 class="text-lg font-bold text-gray-800 mb-4">🔑 Change Password</h2>
                
                <form method="POST" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Current Password *</label>
                        <input type="password" name="current_password" required 
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">New Password * (min. 6 characters)</label>
                        <input type="password" name="new_password" required minlength="6"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Confirm New Password *</label>
                        <input type="password" name="confirm_password" required minlength="6"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <button type="submit" name="change_password" value="1" 
                            class="w-full bg-orange-600 hover:bg-orange-700 text-white py-2 px-4 rounded-lg transition">
                        🔑 Change Password
                    </button>
                </form>
            </div>
        </div>

        <!-- Account Information -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mt-8">
            <h2 class="text-lg font-bold text-gray-800 mb-4">ℹ️ Account Information</h2>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                    <strong>Account Created:</strong> <?php echo date('F j, Y', strtotime($user['created_at'])); ?>
                </div>
                <div>
                    <strong>Last Updated:</strong> <?php echo $user['updated_at'] ? date('F j, Y', strtotime($user['updated_at'])) : 'Never'; ?>
                </div>
                <div>
                    <strong>Last Login:</strong> <?php echo $user['last_login'] ? date('F j, Y H:i', strtotime($user['last_login'])) : 'Never'; ?>
                </div>
                <div>
                    <strong>Account Status:</strong> 
                    <span class="<?php echo $user['is_active'] ? 'text-green-600' : 'text-red-600'; ?>">
                        <?php echo $user['is_active'] ? 'Active' : 'Deactivated'; ?>
                    </span>
                </div>
            </div>
        </div>
    </div>

    <script>
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

        // Password confirmation validation
        document.addEventListener('DOMContentLoaded', function() {
            const newPassword = document.querySelector('input[name="new_password"]');
            const confirmPassword = document.querySelector('input[name="confirm_password"]');
            
            function validatePasswords() {
                if (newPassword.value !== confirmPassword.value) {
                    confirmPassword.setCustomValidity('Passwords do not match');
                } else {
                    confirmPassword.setCustomValidity('');
                }
            }
            
            newPassword.addEventListener('input', validatePasswords);
            confirmPassword.addEventListener('input', validatePasswords);
        });
    </script>
</body>
</html>
