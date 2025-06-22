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

// Session-Check für deaktivierte User
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
        case 'voucher_manager':
            $permissions = array_merge($permissions, ['view_vouchers', 'scan_vouchers', 'create_vouchers', 'manage_vouchers', 'delete_vouchers', 'manage_categories', 'export_data']);
            break;
    }
}
$permissions = array_unique($permissions);

function hasPermission($perm, $perms) {
    return in_array($perm, $perms);
}

$canExport = hasPermission('export_data', $permissions);

if (!$canExport) {
    header('Location: dashboard.php');
    exit;
}

// Export handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['export'])) {
    $exportType = $_POST['export_type'];
    $format = $_POST['format'];
    $dateFrom = $_POST['date_from'] ?: null;
    $dateTo = $_POST['date_to'] ?: null;
    
    $filename = '';
    $data = [];
    
    switch ($exportType) {
        case 'vouchers':
            $filename = 'vouchers_' . date('Y-m-d_H-i-s');
            
            $query = "SELECT v.voucher_code, v.type, v.price, v.is_active, v.is_redeemed, v.created_at, v.redeemed_at, 
                             u.username, vt.name as type_name, vt.icon as type_icon,
                             r.username as redeemed_by_user
                      FROM vouchers v 
                      LEFT JOIN users u ON v.user_id = u.id 
                      LEFT JOIN voucher_types vt ON v.type = vt.type_key
                      LEFT JOIN users r ON v.redeemed_by = r.id
                      WHERE 1=1";
            $params = [];
            
            if ($dateFrom) {
                $query .= " AND v.created_at >= ?";
                $params[] = $dateFrom . ' 00:00:00';
            }
            if ($dateTo) {
                $query .= " AND v.created_at <= ?";
                $params[] = $dateTo . ' 23:59:59';
            }
            
            $query .= " ORDER BY v.created_at DESC";
            
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            break;
            
        case 'users':
            $filename = 'users_' . date('Y-m-d_H-i-s');
            
            $query = "SELECT u.username, u.email, u.first_name, u.last_name, u.is_active, u.created_at, u.last_login,
                             GROUP_CONCAT(ur.role) as roles
                      FROM users u 
                      LEFT JOIN user_roles ur ON u.id = ur.user_id 
                      WHERE 1=1";
            $params = [];
            
            if ($dateFrom) {
                $query .= " AND u.created_at >= ?";
                $params[] = $dateFrom . ' 00:00:00';
            }
            if ($dateTo) {
                $query .= " AND u.created_at <= ?";
                $params[] = $dateTo . ' 23:59:59';
            }
            
            $query .= " GROUP BY u.id ORDER BY u.created_at DESC";
            
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            break;
            
        case 'categories':
            $filename = 'categories_' . date('Y-m-d_H-i-s');
            
            $query = "SELECT vt.type_key, vt.name, vt.icon, vt.default_price, vt.is_active, vt.created_at,
                             COUNT(v.id) as voucher_count,
                             SUM(CASE WHEN v.is_redeemed = 0 THEN 1 ELSE 0 END) as active_vouchers,
                             SUM(CASE WHEN v.is_redeemed = 1 THEN 1 ELSE 0 END) as redeemed_vouchers
                      FROM voucher_types vt 
                      LEFT JOIN vouchers v ON vt.type_key = v.type 
                      GROUP BY vt.id ORDER BY vt.created_at DESC";
            
            $stmt = $pdo->query($query);
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            break;
            
        case 'statistics':
            $filename = 'statistics_' . date('Y-m-d_H-i-s');
            
            // Overall stats
            $stmt = $pdo->query("SELECT 
                COUNT(*) as total_vouchers,
                SUM(CASE WHEN is_redeemed = 0 THEN 1 ELSE 0 END) as active_vouchers,
                SUM(CASE WHEN is_redeemed = 1 THEN 1 ELSE 0 END) as redeemed_vouchers,
                SUM(price) as total_value,
                SUM(CASE WHEN is_redeemed = 1 THEN price ELSE 0 END) as redeemed_value
                FROM vouchers");
            $overallStats = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Stats by type
            $stmt = $pdo->query("SELECT 
                v.type,
                vt.name as type_name,
                COUNT(*) as total,
                SUM(CASE WHEN v.is_redeemed = 0 THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN v.is_redeemed = 1 THEN 1 ELSE 0 END) as redeemed,
                SUM(v.price) as total_value
                FROM vouchers v 
                LEFT JOIN voucher_types vt ON v.type = vt.type_key
                GROUP BY v.type ORDER BY total DESC");
            $typeStats = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $data = [
                'overall' => $overallStats,
                'by_type' => $typeStats,
                'generated_at' => date('Y-m-d H:i:s')
            ];
            break;
    }
    
    if ($format === 'csv') {
        header('Content-Type: text/csv');
        header('Content-Disposition: attachment; filename="' . $filename . '.csv"');
        
        $output = fopen('php://output', 'w');
        
        if ($exportType === 'statistics') {
            // Special handling for statistics
            fputcsv($output, ['Statistics Report - Generated at: ' . $data['generated_at']]);
            fputcsv($output, []);
            fputcsv($output, ['Overall Statistics']);
            foreach ($data['overall'] as $key => $value) {
                fputcsv($output, [ucfirst(str_replace('_', ' ', $key)), $value]);
            }
            fputcsv($output, []);
            fputcsv($output, ['Statistics by Type']);
            if (!empty($data['by_type'])) {
                fputcsv($output, array_keys($data['by_type'][0]));
                foreach ($data['by_type'] as $row) {
                    fputcsv($output, $row);
                }
            }
        } else {
            if (!empty($data)) {
                fputcsv($output, array_keys($data[0]));
                foreach ($data as $row) {
                    fputcsv($output, $row);
                }
            }
        }
        
        fclose($output);
        exit;
    } elseif ($format === 'json') {
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $filename . '.json"');
        
        echo json_encode($data, JSON_PRETTY_PRINT);
        exit;
    }
}

// Load statistics for dashboard
$stats = [];
try {
    $stmt = $pdo->query("SELECT COUNT(*) as total_vouchers, SUM(CASE WHEN is_redeemed = 0 THEN 1 ELSE 0 END) as active_vouchers, SUM(CASE WHEN is_redeemed = 1 THEN 1 ELSE 0 END) as redeemed_vouchers, SUM(price) as total_value FROM vouchers");
    $stats = $stmt->fetch(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    $stats = ['total_vouchers' => 0, 'active_vouchers' => 0, 'redeemed_vouchers' => 0, 'total_value' => 0];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Export & Reports - <?php echo getAppName(); ?></title>
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
                    <span class="hidden md:inline ml-4 text-base lg:text-lg text-gray-600">/ Export</span>
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
            <h1 class="text-xl sm:text-2xl font-bold text-gray-800">📊 Export & Reports</h1>
            <p class="text-gray-600 mt-2">Export data and generate reports</p>
        </div>

        <!-- Statistics Overview -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6 mb-8">
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-xs sm:text-sm font-medium text-gray-500 uppercase">Total Vouchers</p>
                        <p class="text-xl sm:text-3xl font-bold text-blue-600"><?php echo $stats['total_vouchers'] ?? 0; ?></p>
                    </div>
                    <div class="bg-blue-100 p-2 sm:p-3 rounded-full">🎫</div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-xs sm:text-sm font-medium text-gray-500 uppercase">Active</p>
                        <p class="text-xl sm:text-3xl font-bold text-green-600"><?php echo $stats['active_vouchers'] ?? 0; ?></p>
                    </div>
                    <div class="bg-green-100 p-2 sm:p-3 rounded-full">✨</div>
                </div>
            </div>

            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-xs sm:text-sm font-medium text-gray-500 uppercase">Redeemed</p>
                        <p class="text-xl sm:text-3xl font-bold text-gray-600"><?php echo $stats['redeemed_vouchers'] ?? 0; ?></p>
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

        <!-- Export Forms -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            <!-- Vouchers Export -->
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <h2 class="text-lg font-bold text-gray-800 mb-4">🎫 Export Vouchers</h2>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="vouchers">
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Date From</label>
                            <input type="date" name="date_from" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Date To</label>
                            <input type="date" name="date_to" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        </div>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Format</label>
                        <select name="format" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                            <option value="csv">CSV</option>
                            <option value="json">JSON</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg transition">
                        📥 Export Vouchers
                    </button>
                </form>
            </div>

            <!-- Users Export -->
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <h2 class="text-lg font-bold text-gray-800 mb-4">👥 Export Users</h2>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="users">
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Date From</label>
                            <input type="date" name="date_from" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Date To</label>
                            <input type="date" name="date_to" 
                                   class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                        </div>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Format</label>
                        <select name="format" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                            <option value="csv">CSV</option>
                            <option value="json">JSON</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg transition">
                        📥 Export Users
                    </button>
                </form>
            </div>

            <!-- Categories Export -->
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <h2 class="text-lg font-bold text-gray-800 mb-4">🏷️ Export Categories</h2>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="categories">
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Format</label>
                        <select name="format" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                            <option value="csv">CSV</option>
                            <option value="json">JSON</option>
                        </select>
                    </div>
                    
                    <div class="bg-gray-50 p-3 rounded-lg">
                        <p class="text-sm text-gray-600">Includes voucher counts and statistics for each category.</p>
                    </div>
                    
                    <button type="submit" class="w-full bg-yellow-600 hover:bg-yellow-700 text-white py-2 px-4 rounded-lg transition">
                        📥 Export Categories
                    </button>
                </form>
            </div>

            <!-- Statistics Export -->
            <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
                <h2 class="text-lg font-bold text-gray-800 mb-4">📊 Export Statistics</h2>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="statistics">
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Format</label>
                        <select name="format" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                            <option value="csv">CSV</option>
                            <option value="json">JSON</option>
                        </select>
                    </div>
                    
                    <div class="bg-gray-50 p-3 rounded-lg">
                        <p class="text-sm text-gray-600">Comprehensive statistics report including overall metrics and breakdown by category.</p>
                    </div>
                    
                    <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2 px-4 rounded-lg transition">
                        📥 Export Statistics
                    </button>
                </form>
            </div>
        </div>

        <!-- Quick Reports -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mt-8">
            <h2 class="text-lg font-bold text-gray-800 mb-4">⚡ Quick Reports</h2>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <form method="POST" class="inline">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="vouchers">
                    <input type="hidden" name="format" value="csv">
                    <input type="hidden" name="date_from" value="<?php echo date('Y-m-d', strtotime('-7 days')); ?>">
                    <button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded-lg text-sm transition">
                        📅 Last 7 Days
                    </button>
                </form>
                
                <form method="POST" class="inline">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="vouchers">
                    <input type="hidden" name="format" value="csv">
                    <input type="hidden" name="date_from" value="<?php echo date('Y-m-d', strtotime('-30 days')); ?>">
                    <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-lg text-sm transition">
                        📅 Last 30 Days
                    </button>
                </form>
                
                <form method="POST" class="inline">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="vouchers">
                    <input type="hidden" name="format" value="csv">
                    <input type="hidden" name="date_from" value="<?php echo date('Y-m-01'); ?>">
                    <button type="submit" class="w-full bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg text-sm transition">
                        📅 This Month
                    </button>
                </form>
                
                <form method="POST" class="inline">
                    <input type="hidden" name="export" value="1">
                    <input type="hidden" name="export_type" value="vouchers">
                    <input type="hidden" name="format" value="csv">
                    <button type="submit" class="w-full bg-gray-600 hover:bg-gray-700 text-white py-2 px-4 rounded-lg text-sm transition">
                        📅 All Time
                    </button>
                </form>
            </div>
        </div>

        <!-- Export Information -->
        <div class="bg-blue-50 border border-blue-200 rounded-xl p-4 sm:p-6 mt-8">
            <h3 class="text-lg font-bold text-blue-900 mb-2">ℹ️ Export Information</h3>
            <div class="text-sm text-blue-800 space-y-2">
                <div><strong>CSV Format:</strong> Comma-separated values, compatible with Excel and Google Sheets</div>
                <div><strong>JSON Format:</strong> Machine-readable format for API integration and data processing</div>
                <div><strong>Date Filters:</strong> Leave empty to export all data</div>
                <div><strong>File Names:</strong> Automatically include timestamp for organization</div>
                <div><strong>Data Included:</strong> All relevant fields including user info, timestamps, and status</div>
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

        // Set today as max date for date inputs
        document.addEventListener('DOMContentLoaded', function() {
            const today = new Date().toISOString().split('T')[0];
            const dateInputs = document.querySelectorAll('input[type="date"]');
            dateInputs.forEach(input => {
                input.max = today;
            });
        });
    </script>
</body>
</html>
