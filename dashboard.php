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

// Load user roles
$stmt = $pdo->prepare("SELECT role FROM user_roles WHERE user_id = ?");
$stmt->execute([$userId]);
$userRoles = $stmt->fetchAll(PDO::FETCH_COLUMN);

// Permissions
$permissions = [];
foreach ($userRoles as $role) {
    switch ($role) {
        case 'admin':
            $permissions = ['view_vouchers', 'scan_vouchers', 'create_vouchers', 'manage_vouchers', 'delete_vouchers', 'manage_categories', 'delete_categories', 'manage_users', 'delete_users', 'configure_system', 'pretix_sync', 'export_data', 'change_passwords'];
            break;
        case 'user_manager':
            $permissions = array_merge($permissions, ['view_vouchers', 'manage_users', 'change_passwords', 'export_data']);
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - <?php echo getAppName(); ?></title>
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
                    <a href="profile.php" class="bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg text-sm transition">
                        👤 Profile
                    </a>
                    <div class="text-sm text-gray-600">
                        Welcome, <strong class="hidden lg:inline"><?php echo htmlspecialchars($username); ?></strong>
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

    <!-- Main Content -->
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Welcome Header -->
        <div class="bg-white rounded-xl shadow-lg p-6 mb-8">
            <div class="flex items-center">
                <div class="bg-blue-100 p-3 rounded-full mr-4">
                    <span class="text-2xl">👋</span>
                </div>
                <div>
                    <h1 class="text-2xl sm:text-3xl font-bold text-gray-800">
                        Welcome back, <?php echo htmlspecialchars($username); ?>!
                    </h1>
                    <p class="text-gray-600 mt-1">
                        You have <?php echo implode(', ', $userRoles); ?> access to the voucher system
                    </p>
                </div>
            </div>
        </div>

        <!-- Navigation Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
            
            <!-- Vouchers -->
            <?php if (hasPermission('view_vouchers', $permissions) || hasPermission('view_own_vouchers', $permissions)): ?>
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 hover:shadow-xl transition">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg sm:text-xl font-bold text-gray-800">🎫 Vouchers</h3>
                    <div class="bg-blue-100 p-2 rounded-full">
                        <svg class="w-4 h-4 sm:w-6 sm:h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 5v2m0 4v2m0 4v2M5 5a2 2 0 00-2 2v3a1 1 0 001 1h1a1 1 0 001-1V7a2 2 0 00-2-2H5zM5 14a2 2 0 00-2 2v3a1 1 0 001 1h1a1 1 0 001-1v-3a2 2 0 00-2-2H5z"></path>
                        </svg>
                    </div>
                </div>
                <p class="text-sm sm:text-base text-gray-600 mb-4">Manage, view and redeem vouchers</p>
                <a href="vouchers.php" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg inline-block text-center text-sm sm:text-base transition">
                    Manage Vouchers
                </a>
            </div>
            <?php endif; ?>

            <!-- Scanner -->
            <?php if (hasPermission('scan_vouchers', $permissions)): ?>
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 hover:shadow-xl transition">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg sm:text-xl font-bold text-gray-800">📱 Scanner</h3>
                    <div class="bg-green-100 p-2 rounded-full">
                        <svg class="w-4 h-4 sm:w-6 sm:h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h4"></path>
                        </svg>
                    </div>
                </div>
                <p class="text-sm sm:text-base text-gray-600 mb-4">Scan QR codes and redeem vouchers</p>
                <a href="scanner.php" class="w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded-lg inline-block text-center text-sm sm:text-base transition">
                    Open Scanner
                </a>
            </div>
            <?php endif; ?>

            <!-- Users -->
            <?php if (hasPermission('manage_users', $permissions)): ?>
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 hover:shadow-xl transition">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg sm:text-xl font-bold text-gray-800">👥 Users</h3>
                    <div class="bg-purple-100 p-2 rounded-full">
                        <svg class="w-4 h-4 sm:w-6 sm:h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z"></path>
                        </svg>
                    </div>
                </div>
                <p class="text-sm sm:text-base text-gray-600 mb-4">Manage users and assign roles</p>
                <a href="users.php" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg inline-block text-center text-sm sm:text-base transition">
                    Manage Users
                </a>
            </div>
            <?php endif; ?>

            <!-- Categories -->
            <?php if (hasPermission('manage_categories', $permissions)): ?>
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 hover:shadow-xl transition">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg sm:text-xl font-bold text-gray-800">🏷️ Categories</h3>
                    <div class="bg-yellow-100 p-2 rounded-full">
                        <svg class="w-4 h-4 sm:w-6 sm:h-6 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"></path>
                        </svg>
                    </div>
                </div>
                <p class="text-sm sm:text-base text-gray-600 mb-4">Manage voucher categories</p>
                <a href="categories.php" class="w-full bg-yellow-600 hover:bg-yellow-700 text-white py-2 px-4 rounded-lg inline-block text-center text-sm sm:text-base transition">
                    Manage Categories
                </a>
            </div>
            <?php endif; ?>

            <!-- System -->
            <?php if (hasPermission('configure_system', $permissions)): ?>
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 hover:shadow-xl transition">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg sm:text-xl font-bold text-gray-800">⚙️ System</h3>
                    <div class="bg-gray-100 p-2 rounded-full">
                        <svg class="w-4 h-4 sm:w-6 sm:h-6 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                        </svg>
                    </div>
                </div>
                <p class="text-sm sm:text-base text-gray-600 mb-4">OIDC, Pretix and system settings</p>
                <a href="settings.php" class="w-full bg-gray-600 hover:bg-gray-700 text-white py-2 px-4 rounded-lg inline-block text-center text-sm sm:text-base transition">
                    Settings
                </a>
            </div>
            <?php endif; ?>

            <!-- Export -->
            <?php if (hasPermission('export_data', $permissions)): ?>
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 hover:shadow-xl transition">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg sm:text-xl font-bold text-gray-800">📊 Export</h3>
                    <div class="bg-indigo-100 p-2 rounded-full">
                        <svg class="w-4 h-4 sm:w-6 sm:h-6 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                        </svg>
                    </div>
                </div>
                <p class="text-sm sm:text-base text-gray-600 mb-4">Export data and create reports</p>
                <a href="export.php" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2 px-4 rounded-lg inline-block text-center text-sm sm:text-base transition">
                    Export & Reports
                </a>
            </div>
            <?php endif; ?>
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

        document.addEventListener('click', function(event) {
            const mobileMenu = document.getElementById('mobileMenu');
            const menuButton = event.target.closest('button[onclick="toggleMobileMenu()"]');
            
            if (!menuButton && !mobileMenu.contains(event.target)) {
                mobileMenu.classList.add('hidden');
                document.getElementById('menuIcon').classList.remove('hidden');
                document.getElementById('closeIcon').classList.add('hidden');
            }
        });

        window.addEventListener('resize', function() {
            if (window.innerWidth >= 768) {
                document.getElementById('mobileMenu').classList.add('hidden');
                document.getElementById('menuIcon').classList.remove('hidden');
                document.getElementById('closeIcon').classList.add('hidden');
            }
        });
    </script>
</body>
</html>

