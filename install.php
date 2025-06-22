<?php
session_start();

// Check if already installed 
$configExists = file_exists(__DIR__ . '/config/app_config.php');
$installationComplete = false;

if ($configExists) {
    try {
        define('CONFIG_ACCESS', true);
        require_once __DIR__ . '/config/app_config.php';
        
        if (defined('INSTALLATION_COMPLETE') && INSTALLATION_COMPLETE === true) {
            $installationComplete = true;
        }
    } catch (Exception $e) {
        // Config file exists but is not valid
        $installationComplete = false;
    }
}

// only allow installation if not already complete
$currentStep = $_GET['step'] ?? 1;
$currentStep = max(1, min(8, intval($currentStep)));

if ($installationComplete && $currentStep != 8) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Installation Blocked - Voucher System</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen bg-white">
        <!-- Header -->
        <div class="bg-white shadow-sm border-b">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center h-16">
                    <div class="flex items-center">
                        <span class="text-2xl mr-3">🎫</span>
                        <span class="text-xl font-bold text-gray-900">Voucher System</span>
                        <span class="ml-3 text-sm text-gray-500">Installation</span>
                    </div>
                    <div class="text-sm text-gray-500">
                        Installed: <?php echo defined('INSTALLATION_DATE') ? INSTALLATION_DATE : 'Unknown'; ?>
                    </div>
                </div>
            </div>
        </div>

        <div class="flex items-center justify-center min-h-screen py-12 px-4 sm:px-6 lg:px-8">
            <div class="max-w-md w-full space-y-8">
                <div class="bg-white rounded-3xl shadow-2xl p-8 text-center border border-gray-200">
                    <div class="text-8xl mb-6">🔒</div>
                    <h1 class="text-3xl font-bold text-gray-900 mb-4">Installation Blocked</h1>
                    <p class="text-gray-600 mb-8">The voucher system is already installed and configured. The installation is locked for security reasons.</p>
                    
                    <div class="bg-red-50 border border-red-200 rounded-2xl p-4 mb-8 text-left">
                        <div class="flex">
                            <div class="flex-shrink-0">
                                <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                </svg>
                            </div>
                            <div class="ml-3">
                                <h3 class="text-sm font-medium text-red-800">Security Warning</h3>
                                <div class="mt-2 text-sm text-red-700">
                                    <p>Please delete the <code class="bg-red-100 px-1 rounded font-mono">install.php</code> file immediately!</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="space-y-3">
                        <a href="login.php" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-2xl shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300 transform hover:scale-105">
                            <span class="mr-2">🚀</span> Go to Login
                        </a>
                        <a href="dashboard.php" class="w-full flex justify-center py-3 px-4 border border-gray-300 rounded-2xl shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300">
                            <span class="mr-2">📊</span> Go to Dashboard
                        </a>
                    </div>
                    
                    <div class="mt-8 pt-6 border-t border-gray-200">
                        <p class="text-xs text-gray-500 mb-2">To reinstall, delete the config file:</p>
                        <code class="text-xs bg-gray-100 px-2 py-1 rounded font-mono">rm config/app_config.php</code>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Installation steps
$steps = [
    1 => 'Database Configuration',
    2 => 'Database Setup', 
    3 => 'Admin User Creation',
    4 => 'Application Configuration',
    5 => 'Logo & Branding',
    6 => 'Pretix Integration',
    7 => 'SSO Configuration',
    8 => 'Installation Complete'
];

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    switch ($currentStep) {
        case 1:
            // Database configuration
            $_SESSION['db_config'] = [
                'host' => $_POST['db_host'],
                'name' => $_POST['db_name'],
                'user' => $_POST['db_user'],
                'pass' => $_POST['db_pass']
            ];
            
            // Test database connection
            try {
                $pdo = new PDO(
                    "mysql:host=" . $_POST['db_host'] . ";charset=utf8mb4",
                    $_POST['db_user'],
                    $_POST['db_pass'],
                    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
                );
                $_SESSION['db_test'] = true;
                header('Location: install.php?step=2');
                exit;
            } catch (PDOException $e) {
                $error = "Database connection failed: " . $e->getMessage();
            }
            break;
            
        case 2:
            // Database setup
            if (isset($_SESSION['db_config']) && $_SESSION['db_test']) {
                try {
                    $config = $_SESSION['db_config'];
                    $pdo = new PDO(
                        "mysql:host=" . $config['host'] . ";charset=utf8mb4",
                        $config['user'],
                        $config['pass'],
                        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
                    );
                    
                    // Create database
                    $pdo->exec("CREATE DATABASE IF NOT EXISTS `" . $config['name'] . "` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
                    $pdo->exec("USE `" . $config['name'] . "`");
                    
                    // Create tables
                    createTables($pdo);
                    
                    $_SESSION['db_setup'] = true;
                    header('Location: install.php?step=3');
                    exit;
                } catch (PDOException $e) {
                    $error = "Database setup failed: " . $e->getMessage();
                }
            }
            break;
            
        case 3:
            // Admin user creation
            if (isset($_SESSION['db_config']) && $_SESSION['db_setup']) {
                $_SESSION['admin_config'] = [
                    'username' => $_POST['admin_username'],
                    'password' => $_POST['admin_password'],
                    'email' => $_POST['admin_email'] ?: null,
                    'first_name' => $_POST['admin_first_name'] ?: null,
                    'last_name' => $_POST['admin_last_name'] ?: null
                ];
                
                try {
                    $config = $_SESSION['db_config'];
                    $pdo = new PDO(
                        "mysql:host=" . $config['host'] . ";dbname=" . $config['name'] . ";charset=utf8mb4",
                        $config['user'],
                        $config['pass'],
                        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
                    );
                    
                    createAdminUser($pdo, $_SESSION['admin_config']);
                    $_SESSION['admin_setup'] = true;
                    header('Location: install.php?step=4');
                    exit;
                } catch (PDOException $e) {
                    $error = "Admin user creation failed: " . $e->getMessage();
                }
            }
            break;
            
        case 4:
            // Application configuration
            $_SESSION['app_config'] = [
                'app_name' => $_POST['app_name'],
                'company_name' => $_POST['company_name'],
                'app_url' => rtrim($_POST['app_url'], '/'),
                'app_version' => $_POST['app_version']
            ];
            
            header('Location: install.php?step=5');
            exit;
            break;
            
        case 5:
            // Logo & Branding configuration
            $_SESSION['branding_config'] = [
                'logo_url' => $_POST['logo_url'] ?: null,
                'sso_logo_url' => $_POST['sso_logo_url'] ?: null
            ];
            
            header('Location: install.php?step=6');
            exit;
            break;
            
        case 6:
            // Pretix configuration
            $_SESSION['pretix_config'] = [
                'enabled' => isset($_POST['pretix_enabled']) ? 1 : 0,
                'api_url' => rtrim($_POST['pretix_api_url'] ?: '', '/'),
                'api_token' => $_POST['pretix_api_token'] ?: '',
                'organizer' => $_POST['pretix_organizer'] ?: '',
                'event' => $_POST['pretix_event'] ?: ''
            ];
            
            header('Location: install.php?step=7');
            exit;
            break;
            
        case 7:
            // SSO configuration
            $_SESSION['sso_config'] = [
                'enabled' => isset($_POST['sso_enabled']) ? 1 : 0,
                'issuer' => $_POST['sso_issuer'] ?: '',
                'client_id' => $_POST['sso_client_id'] ?: '',
                'client_secret' => $_POST['sso_client_secret'] ?: '',
                'redirect_uri' => $_POST['sso_redirect_uri'] ?: ''
            ];
            
            // Generate config file and save integrations
            if (generateConfigFile($_SESSION['db_config'], $_SESSION['app_config'], $_SESSION['branding_config']) && 
                saveIntegrations($_SESSION['db_config'], $_SESSION['pretix_config'], $_SESSION['sso_config'])) {
                $_SESSION['config_generated'] = true;
                header('Location: install.php?step=8');
                exit;
            } else {
                $error = "Failed to generate configuration file or save integrations. Please check file permissions.";
            }
            break;
    }
}

function createTables($pdo) {
    // Create users table WITH OIDC columns
    $pdo->exec("
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(64) NOT NULL UNIQUE,
        email VARCHAR(128) DEFAULT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        first_name VARCHAR(64) DEFAULT NULL,
        last_name VARCHAR(64) DEFAULT NULL,
        oidc_sub VARCHAR(255) DEFAULT NULL,
        oidc_email VARCHAR(255) DEFAULT NULL,
        oidc_name VARCHAR(255) DEFAULT NULL,
        oidc_provider VARCHAR(50) DEFAULT 'default',
        is_active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT NULL,
        last_login DATETIME DEFAULT NULL,
        INDEX idx_oidc_sub (oidc_sub),
        INDEX idx_oidc_email (oidc_email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    // Create user_roles table
    $pdo->exec("
    CREATE TABLE IF NOT EXISTS user_roles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        role VARCHAR(32) NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    // Create voucher_types table (with new fields)
    $pdo->exec("
    CREATE TABLE IF NOT EXISTS voucher_types (
        id INT AUTO_INCREMENT PRIMARY KEY,
        type_key VARCHAR(32) NOT NULL UNIQUE,
        name VARCHAR(128) NOT NULL,
        icon VARCHAR(8) DEFAULT '🎫',
        default_price DECIMAL(10,2) DEFAULT 0,
        default_value DECIMAL(10,2) DEFAULT 0,
        is_permanent_type TINYINT(1) DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    // Create vouchers table (with new fields)
    $pdo->exec("
    CREATE TABLE IF NOT EXISTS vouchers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        voucher_code VARCHAR(32) NOT NULL UNIQUE,
        type VARCHAR(32) NOT NULL,
        user_id INT DEFAULT NULL,
        price DECIMAL(10,2) DEFAULT 0,
        actual_value DECIMAL(10,2) DEFAULT 0,
        is_permanent TINYINT(1) DEFAULT 0,
        is_active TINYINT(1) DEFAULT 1,
        is_redeemed TINYINT(1) DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        redeemed_at DATETIME DEFAULT NULL,
        expires_at DATETIME DEFAULT NULL,
        redeemed_by INT DEFAULT NULL,
        pretix_voucher_id VARCHAR(64) DEFAULT NULL,
        pretix_published TINYINT(1) DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (redeemed_by) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    // Create system_integrations table
    $pdo->exec("
    CREATE TABLE IF NOT EXISTS system_integrations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        integration VARCHAR(64) NOT NULL UNIQUE,
        is_enabled TINYINT(1) DEFAULT 0,
        settings TEXT DEFAULT NULL,
        updated_at DATETIME DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ");

    // Insert default integrations
    $integrations = [
        ['openid_connect', 0, '{}'],
        ['pretix', 0, '{}']
    ];
    foreach ($integrations as $integration) {
        $stmt = $pdo->prepare("INSERT IGNORE INTO system_integrations (integration, is_enabled, settings) VALUES (?, ?, ?)");
        $stmt->execute($integration);
    }

    // Insert default voucher types
    $defaultTypes = [
        ['food', 'Food Voucher', '🍕', 10.00, 10.00, 0],
        ['drink', 'Drink Voucher', '🥤', 5.00, 5.00, 0],
        ['merchandise', 'Merchandise Voucher', '👕', 15.00, 15.00, 0],
        ['general', 'General Voucher', '🎫', 10.00, 10.00, 0]
    ];
    
    foreach ($defaultTypes as $type) {
        $stmt = $pdo->prepare("INSERT IGNORE INTO voucher_types (type_key, name, icon, default_price, default_value, is_permanent_type) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute($type);
    }
}

function createAdminUser($pdo, $adminConfig) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
    $stmt->execute([$adminConfig['username']]);
    
    if ($stmt->fetchColumn() == 0) {
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash, first_name, last_name, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, NOW())");
        $stmt->execute([
            $adminConfig['username'],
            $adminConfig['email'],
            password_hash($adminConfig['password'], PASSWORD_DEFAULT),
            $adminConfig['first_name'],
            $adminConfig['last_name']
        ]);
        
        $adminId = $pdo->lastInsertId();
        $pdo->prepare("INSERT INTO user_roles (user_id, role) VALUES (?, 'admin')")->execute([$adminId]);
    }
}

function generateConfigFile($dbConfig, $appConfig, $brandingConfig) {
    $configContent = "<?php
// Auto-generated configuration file
// Generated on: " . date('Y-m-d H:i:s') . "
// Installation completed: " . date('Y-m-d H:i:s') . "

if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

// Installation Status - PREVENTS REINSTALLATION
define('INSTALLATION_COMPLETE', true);
define('INSTALLATION_DATE', '" . date('Y-m-d H:i:s') . "');

// Database Configuration
define('DB_HOST', '" . addslashes($dbConfig['host']) . "');
define('DB_NAME', '" . addslashes($dbConfig['name']) . "');
define('DB_USER', '" . addslashes($dbConfig['user']) . "');
define('DB_PASS', '" . addslashes($dbConfig['pass']) . "');

// Application Configuration
define('APP_NAME', '" . addslashes($appConfig['app_name']) . "');
define('COMPANY_NAME', '" . addslashes($appConfig['company_name']) . "');
define('APP_URL', '" . addslashes($appConfig['app_url']) . "');
define('APP_VERSION', '" . addslashes($appConfig['app_version']) . "');

// Branding Configuration
define('LOGO_URL', " . ($brandingConfig['logo_url'] ? "'" . addslashes($brandingConfig['logo_url']) . "'" : 'null') . ");
define('SSO_LOGO_URL', " . ($brandingConfig['sso_logo_url'] ? "'" . addslashes($brandingConfig['sso_logo_url']) . "'" : 'null') . ");

// Helper Functions
function getAppName() {
    return APP_NAME;
}

function getCompanyName() {
    return COMPANY_NAME;
}

function getAppUrl() {
    return APP_URL;
}

function getAppVersion() {
    return APP_VERSION;
}

function getLogoUrl() {
    return LOGO_URL;
}

function getSsoLogoUrl() {
    return SSO_LOGO_URL;
}

// Security Settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);

// Timezone
date_default_timezone_set('Europe/Berlin');
";

    $configDir = __DIR__ . '/config';
    if (!is_dir($configDir)) {
        mkdir($configDir, 0755, true);
    }
    
    return file_put_contents($configDir . '/app_config.php', $configContent) !== false;
}

function saveIntegrations($dbConfig, $pretixConfig, $ssoConfig) {
    try {
        $pdo = new PDO(
            "mysql:host=" . $dbConfig['host'] . ";dbname=" . $dbConfig['name'] . ";charset=utf8mb4",
            $dbConfig['user'],
            $dbConfig['pass'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        
        // Save Pretix configuration
        $pretixSettings = [
            'api_url' => $pretixConfig['api_url'],
            'api_token' => $pretixConfig['api_token'],
            'organizer' => $pretixConfig['organizer'],
            'event' => $pretixConfig['event']
        ];
        
        $stmt = $pdo->prepare("UPDATE system_integrations SET is_enabled = ?, settings = ?, updated_at = NOW() WHERE integration = 'pretix'");
        $stmt->execute([$pretixConfig['enabled'], json_encode($pretixSettings)]);
        
        // Save SSO configuration
        $ssoSettings = [
            'issuer' => $ssoConfig['issuer'],
            'client_id' => $ssoConfig['client_id'],
            'client_secret' => $ssoConfig['client_secret'],
            'redirect_uri' => $ssoConfig['redirect_uri']
        ];
        
        $stmt = $pdo->prepare("UPDATE system_integrations SET is_enabled = ?, settings = ?, updated_at = NOW() WHERE integration = 'openid_connect'");
        $stmt->execute([$ssoConfig['enabled'], json_encode($ssoSettings)]);
        
        return true;
    } catch (Exception $e) {
        return false;
    }
}

// Generate correct OIDC redirect URI
function generateOidcRedirectUri() {
    $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'];
    $path = dirname($_SERVER['REQUEST_URI']);
    
    // Remove trailing slash and ensure single slash
    $path = rtrim($path, '/');
    
    return $protocol . '://' . $host . $path . '/oidc.php';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Voucher System Installation</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-gray-100">
    <!-- Header -->
    <div class="bg-white shadow-sm border-b">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between items-center h-16">
                <div class="flex items-center">
                    <span class="text-2xl mr-3">🎫</span>
                    <span class="text-xl font-bold text-gray-900">Voucher System</span>
                    <span class="ml-3 text-sm text-gray-500">Installation Wizard</span>
                </div>
                <div class="hidden md:flex items-center space-x-4">
                    <div class="text-sm text-gray-600">
                        <span class="font-medium">Step <?php echo $currentStep; ?> of 8</span>
                        <div class="text-xs text-purple-600"><?php echo $steps[$currentStep]; ?></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <!-- Clean Progress Bar -->
        <div class="bg-white rounded-3xl shadow-lg p-6 mb-8 border border-gray-200">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-xl font-bold text-purple-600">Installation Progress</h2>
                <span class="text-sm font-medium text-gray-600">
                    Schritt: <span class="font-semibold text-purple-600"><?php echo $steps[$currentStep]; ?></span>
                </span>
            </div>
            
            <!-- Pulsing Progress Bar -->
            <div class="relative">
                <div class="w-full bg-gray-200 rounded-full h-4 overflow-hidden">
                    <div class="h-full bg-gradient-to-r from-purple-500 via-pink-500 to-purple-600 rounded-full transition-all duration-1000 ease-out relative animate-pulse" 
                         style="width: <?php echo ($currentStep / 8) * 100; ?>%">
                        <!-- Glowing effect -->
                        <div class="absolute inset-0 bg-white opacity-30 animate-pulse"></div>
                        <!-- Moving shimmer -->
                        <div class="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-50 animate-pulse"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Error Message -->
        <?php if (isset($error)): ?>
            <div class="bg-red-50 border border-red-200 rounded-2xl p-4 mb-6">
                <div class="flex">
                    <div class="flex-shrink-0">
                        <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                        </svg>
                    </div>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-red-800">Installation Error</h3>
                        <div class="mt-2 text-sm text-red-700">
                            <p><?php echo htmlspecialchars($error); ?></p>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>

        <!-- Installation Steps -->
        <div class="bg-white rounded-3xl shadow-lg border border-gray-200">
            <div class="p-6 sm:p-8">
                <?php if ($currentStep == 1): ?>
                    <!-- Step 1: Database Configuration -->
                    <div class="text-center mb-8">
                        <div class="text-5xl mb-4">🗄️</div>
                        <h2 class="text-3xl font-bold text-gray-900 mb-2">Database Configuration</h2>
                        <p class="text-gray-600">Configure your MySQL database connection to get started.</p>
                    </div>
                    
                    <form method="POST" class="space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Database Host</label>
                                <input type="text" name="db_host" value="localhost" required 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Database Name</label>
                                <input type="text" name="db_name" value="voucher_system" required 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Database Username</label>
                                <input type="text" name="db_user" required 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Database Password</label>
                                <input type="password" name="db_pass" 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                        </div>
                        
                        <div class="flex justify-end pt-6">
                            <button type="submit" class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-8 py-3 rounded-2xl font-medium transition duration-300 transform hover:scale-105 shadow-lg">
                                Test Connection & Continue →
                            </button>
                        </div>
                    </form>

                <?php elseif ($currentStep == 2): ?>
                    <!-- Step 2: Database Setup -->
                    <div class="text-center mb-8">
                        <div class="text-5xl mb-4">⚙️</div>
                        <h2 class="text-3xl font-bold text-gray-900 mb-2">Database Setup</h2>
                        <p class="text-gray-600">Create database tables and default data.</p>
                    </div>
                    
                    <div class="bg-blue-50 border border-blue-200 rounded-2xl p-6 mb-8">
                        <h3 class="font-medium text-blue-800 mb-4 flex items-center">
                            <span class="mr-2">📋</span> What will be created:
                        </h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-700">
                            <ul class="space-y-2">
                                <li class="flex items-center"><span class="mr-2">✓</span> Users and roles tables (with OIDC support)</li>
                                <li class="flex items-center"><span class="mr-2">✓</span> Voucher system tables</li>
                            </ul>
                            <ul class="space-y-2">
                                <li class="flex items-center"><span class="mr-2">✓</span> Integration settings</li>
                                <li class="flex items-center"><span class="mr-2">✓</span> Default voucher categories</li>
                            </ul>
                        </div>
                    </div>
                    
                    <form method="POST">
                        <div class="flex justify-between">
                            <a href="install.php?step=1" class="bg-gray-500 hover:bg-gray-600 text-white px-8 py-3 rounded-2xl font-medium transition duration-300">
                                ← Back
                            </a>
                            <button type="submit" class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-8 py-3 rounded-2xl font-medium transition duration-300 transform hover:scale-105 shadow-lg">
                                Create Database & Tables →
                            </button>
                        </div>
                    </form>

                <?php elseif ($currentStep == 3): ?>
                    <!-- Step 3: Admin User Creation -->
                    <div class="text-center mb-8">
                        <div class="text-5xl mb-4">👤</div>
                        <h2 class="text-3xl font-bold text-gray-900 mb-2">Admin User Creation</h2>
                        <p class="text-gray-600">Create the administrator account for your voucher system.</p>
                    </div>
                    
                    <form method="POST" class="space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Username *</label>
                                <input type="text" name="admin_username" value="admin" required 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Email</label>
                                <input type="email" name="admin_email" 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">First Name</label>
                                <input type="text" name="admin_first_name" 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Last Name</label>
                                <input type="text" name="admin_last_name" 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Password *</label>
                            <input type="password" name="admin_password" required minlength="6" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            <p class="text-xs text-gray-500 mt-2">Minimum 6 characters</p>
                        </div>
                        
                        <div class="flex justify-between pt-6">
                            <a href="install.php?step=2" class="bg-gray-500 hover:bg-gray-600 text-white px-8 py-3 rounded-2xl font-medium transition duration-300">
                                ← Back
                            </a>
                            <button type="submit" class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-8 py-3 rounded-2xl font-medium transition duration-300 transform hover:scale-105 shadow-lg">
                                Create Admin User →
                            </button>
                        </div>
                    </form>

                <?php elseif ($currentStep == 4): ?>
                    <!-- Step 4: Application Configuration -->
                    <div class="text-center mb-8">
                        <div class="text-5xl mb-4">🎫</div>
                        <h2 class="text-3xl font-bold text-gray-900 mb-2">Application Configuration</h2>
                        <p class="text-gray-600">Configure your application settings and branding.</p>
                    </div>
                    
                    <form method="POST" class="space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Application Name *</label>
                                <input type="text" name="app_name" value="Voucher System" required 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Company Name *</label>
                                <input type="text" name="company_name" value="Your Company" required 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Application URL *</label>
                            <input type="url" name="app_url" value="<?php echo 'http' . (isset($_SERVER['HTTPS']) ? 's' : '') . '://' . $_SERVER['HTTP_HOST'] . rtrim(dirname($_SERVER['REQUEST_URI']), '/'); ?>" required 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            <p class="text-xs text-gray-500 mt-2">The base URL of your application</p>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Version</label>
                            <input type="text" name="app_version" value="1.0.0" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                        </div>
                        
                        <div class="flex justify-between pt-6">
                            <a href="install.php?step=3" class="bg-gray-500 hover:bg-gray-600 text-white px-8 py-3 rounded-2xl font-medium transition duration-300">
                                ← Back
                            </a>
                            <button type="submit" class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-8 py-3 rounded-2xl font-medium transition duration-300 transform hover:scale-105 shadow-lg">
                                Continue →
                            </button>
                        </div>
                    </form>

                <?php elseif ($currentStep == 5): ?>
                    <!-- Step 5: Logo & Branding -->
                    <div class="text-center mb-8">
                        <div class="text-5xl mb-4">🎨</div>
                        <h2 class="text-3xl font-bold text-gray-900 mb-2">Logo & Branding</h2>
                        <p class="text-gray-600">Configure your logos and branding (optional).</p>
                    </div>
                    
                    <form method="POST" class="space-y-6">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">Company Logo URL</label>
                            <input type="url" name="logo_url" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                                   placeholder="https://example.com/logo.png">
                            <p class="text-xs text-gray-500 mt-2">URL to your company logo (shown in navigation)</p>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">SSO Provider Logo URL</label>
                            <input type="url" name="sso_logo_url" 
                                   class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                                   placeholder="https://example.com/sso-logo.png">
                            <p class="text-xs text-gray-500 mt-2">URL to your SSO provider logo (shown on login button)</p>
                        </div>
                        
                        <div class="bg-blue-50 border border-blue-200 rounded-2xl p-6">
                            <h3 class="font-medium text-blue-800 mb-3 flex items-center">
                                <span class="mr-2">💡</span> Logo Requirements:
                            </h3>
                            <ul class="text-sm text-blue-700 space-y-1">
                                <li>• Recommended formats: PNG, SVG, JPG</li>
                                <li>• Company logo: Max height 50px (will be auto-scaled)</li>
                                <li>• SSO logo: Max 24x24px for button icons</li>
                                <li>• Use publicly accessible URLs</li>
                            </ul>
                        </div>
                        
                        <div class="flex justify-between pt-6">
                            <a href="install.php?step=4" class="bg-gray-500 hover:bg-gray-600 text-white px-8 py-3 rounded-2xl font-medium transition duration-300">
                                ← Back
                            </a>
                            <button type="submit" class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-8 py-3 rounded-2xl font-medium transition duration-300 transform hover:scale-105 shadow-lg">
                                Continue →
                            </button>
                        </div>
                    </form>

                <?php elseif ($currentStep == 6): ?>
                    <!-- Step 6: Pretix Integration -->
                    <div class="text-center mb-8">
                        <div class="text-5xl mb-4">🎟️</div>
                        <h2 class="text-3xl font-bold text-gray-900 mb-2">Pretix Integration</h2>
                        <p class="text-gray-600">Configure Pretix integration for ticket sales (optional).</p>
                    </div>
                    
                    <form method="POST" class="space-y-6">
                        <div class="flex items-center p-4 bg-gray-50 rounded-2xl">
                            <input type="checkbox" id="pretix_enabled" name="pretix_enabled" class="rounded border-gray-300 text-purple-600 focus:ring-purple-500 h-4 w-4">
                            <label for="pretix_enabled" class="ml-3 text-sm font-medium text-gray-700">Enable Pretix Integration</label>
                        </div>
                        
                        <div id="pretix_config" class="space-y-6" style="display: none;">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Pretix API URL</label>
                                <input type="url" name="pretix_api_url" 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                                       placeholder="https://pretix.example.com">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">API Token</label>
                                <input type="text" name="pretix_api_token" 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                            </div>
                            
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Organizer Slug</label>
                                    <input type="text" name="pretix_organizer" 
                                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Event Slug</label>
                                    <input type="text" name="pretix_event" 
                                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                                </div>
                            </div>
                        </div>
                        
                        <div class="bg-yellow-50 border border-yellow-200 rounded-2xl p-6">
                            <h3 class="font-medium text-yellow-800 mb-3 flex items-center">
                                <span class="mr-2">ℹ️</span> Pretix Integration Info:
                            </h3>
                            <ul class="text-sm text-yellow-700 space-y-1">
                                <li>• Vouchers will be automatically synced to Pretix</li>
                                <li>• You can configure this later in the admin panel</li>
                                <li>• API token needs "Can change vouchers" permission</li>
                            </ul>
                        </div>
                        
                        <div class="flex justify-between pt-6">
                            <a href="install.php?step=5" class="bg-gray-500 hover:bg-gray-600 text-white px-8 py-3 rounded-2xl font-medium transition duration-300">
                                ← Back
                            </a>
                            <button type="submit" class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-8 py-3 rounded-2xl font-medium transition duration-300 transform hover:scale-105 shadow-lg">
                                Continue →
                            </button>
                        </div>
                    </form>

                <?php elseif ($currentStep == 7): ?>
                    <!-- Step 7: SSO Configuration -->
                    <div class="text-center mb-8">
                        <div class="text-5xl mb-4">🔐</div>
                        <h2 class="text-3xl font-bold text-gray-900 mb-2">SSO Configuration</h2>
                        <p class="text-gray-600">Configure Single Sign-On with OpenID Connect (optional).</p>
                    </div>
                    
                    <form method="POST" class="space-y-6">
                        <div class="flex items-center p-4 bg-gray-50 rounded-2xl">
                            <input type="checkbox" id="sso_enabled" name="sso_enabled" class="rounded border-gray-300 text-purple-600 focus:ring-purple-500 h-4 w-4">
                            <label for="sso_enabled" class="ml-3 text-sm font-medium text-gray-700">Enable SSO Integration</label>
                        </div>
                        
                        <div id="sso_config" class="space-y-6" style="display: none;">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Issuer URL</label>
                                <input type="url" name="sso_issuer" 
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                                       placeholder="https://auth.example.com/realms/master">
                            </div>
                            
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Client ID</label>
                                    <input type="text" name="sso_client_id" 
                                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Client Secret</label>
                                    <input type="password" name="sso_client_secret" 
                                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                                </div>
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Redirect URI</label>
                                <input type="url" name="sso_redirect_uri" 
                                       value="<?php echo generateOidcRedirectUri(); ?>"
                                       class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition">
                                <p class="text-xs text-gray-500 mt-2">This URL must be configured in your OIDC provider</p>
                            </div>
                        </div>
                        
                        <div class="bg-blue-50 border border-blue-200 rounded-2xl p-6">
                            <h3 class="font-medium text-blue-800 mb-3 flex items-center">
                                <span class="mr-2">ℹ️</span> SSO Integration Info:
                            </h3>
                            <ul class="text-sm text-blue-700 space-y-1">
                                <li>• Supports OpenID Connect providers (Keycloak, Auth0, etc.)</li>
                                <li>• Users can login with SSO or regular accounts</li>
                                <li>• You can configure this later in the admin panel</li>
                                <li>• The redirect URI points to <code>/oidc.php</code></li>
                            </ul>
                        </div>
                        
                        <div class="flex justify-between pt-6">
                            <a href="install.php?step=6" class="bg-gray-500 hover:bg-gray-600 text-white px-8 py-3 rounded-2xl font-medium transition duration-300">
                                ← Back
                            </a>
                            <button type="submit" class="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-8 py-3 rounded-2xl font-medium transition duration-300 transform hover:scale-105 shadow-lg">
                                Complete Installation 🎉
                            </button>
                        </div>
                    </form>

                <?php elseif ($currentStep == 8): ?>
                    <!-- Step 8: Installation Complete -->
                    <div class="text-center">
                        <div class="text-8xl mb-8 animate-bounce">🎉</div>
                        <h2 class="text-4xl font-bold bg-gradient-to-r from-green-600 to-emerald-600 bg-clip-text text-transparent mb-4">Installation Complete!</h2>
                        <p class="text-xl text-gray-600 mb-12">Your voucher system has been successfully installed and configured.</p>
                        
                        <div class="bg-gradient-to-r from-green-50 to-emerald-50 border border-green-200 rounded-3xl p-8 mb-8 text-left">
                            <h3 class="font-bold text-green-800 mb-6 text-xl flex items-center justify-center">
                                <span class="mr-2">✅</span> What's been set up:
                            </h3>
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-8 text-sm text-green-700">
                                <div>
                                    <h4 class="font-bold mb-4 text-lg flex items-center">
                                        <span class="mr-2">🗄️</span> Database & Tables
                                    </h4>
                                    <ul class="space-y-2">
                                        <li class="flex items-center"><span class="mr-2">✓</span> Users and roles system (with OIDC support)</li>
                                        <li class="flex items-center"><span class="mr-2">✓</span> Voucher management</li>
                                        <li class="flex items-center"><span class="mr-2">✓</span> Category system</li>
                                        <li class="flex items-center"><span class="mr-2">✓</span> Integration settings</li>
                                    </ul>
                                </div>
                                <div>
                                    <h4 class="font-bold mb-4 text-lg flex items-center">
                                        <span class="mr-2">⚙️</span> Configuration
                                    </h4>
                                    <ul class="space-y-2">
                                        <li class="flex items-center"><span class="mr-2">✓</span> Admin user created</li>
                                        <li class="flex items-center"><span class="mr-2">✓</span> Application settings</li>
                                        <li class="flex items-center"><span class="mr-2">✓</span> Branding configured</li>
                                        <li class="flex items-center"><span class="mr-2">✓</span> Integrations set up</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                        
                        <div class="bg-red-50 border border-red-200 rounded-2xl p-6 mb-8">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                    </svg>
                                </div>
                                <div class="ml-3">
                                    <h3 class="text-sm font-medium text-red-800">🔒 Critical Security Notice</h3>
                                    <div class="mt-2 text-sm text-red-700">
                                        <p><strong>Please delete the <code class="bg-red-100 px-1 rounded font-mono">install.php</code> file immediately for security reasons!</strong></p>
                                        <p class="mt-1">This file contains sensitive installation functions and should not remain on your server.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="space-y-6">
                            <div class="flex flex-col sm:flex-row gap-4 justify-center">
                                <a href="login.php" class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white px-12 py-4 rounded-2xl text-lg font-medium transition duration-300 transform hover:scale-105 shadow-lg flex items-center justify-center">
                                    <span class="mr-2">🚀</span> Go to Login
                                </a>
                                <a href="dashboard.php" class="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white px-12 py-4 rounded-2xl text-lg font-medium transition duration-300 transform hover:scale-105 shadow-lg flex items-center justify-center">
                                    <span class="mr-2">📊</span> Go to Dashboard
                                </a>
                            </div>
                            
                            <div class="bg-gray-50 rounded-2xl p-6 text-sm text-gray-600">
                                <h4 class="font-medium text-gray-800 mb-2">Default admin credentials:</h4>
                                <p><strong>Username:</strong> <?php echo htmlspecialchars($_SESSION['admin_config']['username'] ?? 'admin'); ?></p>
                                <p><strong>Password:</strong> [as configured in step 3]</p>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        // Toggle Pretix configuration fields
        document.getElementById('pretix_enabled')?.addEventListener('change', function() {
            document.getElementById('pretix_config').style.display = this.checked ? 'block' : 'none';
        });

        // Toggle SSO configuration fields
        document.getElementById('sso_enabled')?.addEventListener('change', function() {
            document.getElementById('sso_config').style.display = this.checked ? 'block' : 'none';
        });
    </script>
</body>
</html>
