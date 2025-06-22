<?php
define('CONFIG_ACCESS', true);

// Check if config exists
if (!file_exists(__DIR__ . '/config/app_config.php')) {
    header('Location: install.php');
    exit;
}

require_once __DIR__ . '/config/app_config.php';

// Database connection
try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
        DB_USER,
        DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Check if SSO is enabled
$ssoEnabled = false;
$ssoSettings = [];
try {
    $stmt = $pdo->prepare("SELECT is_enabled, settings FROM system_integrations WHERE integration = 'openid_connect'");
    $stmt->execute();
    $ssoIntegration = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($ssoIntegration && $ssoIntegration['is_enabled']) {
        $ssoEnabled = true;
        $ssoSettings = json_decode($ssoIntegration['settings'], true) ?: [];
    }
} catch (Exception $e) {
    // SSO check failed, continue without SSO
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo getAppName(); ?> - Welcome</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .logo-container {
            max-height: 80px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .logo-container img {
            max-height: 80px;
            max-width: 300px;
            width: auto;
            height: auto;
            object-fit: contain;
        }
    </style>
</head>
<body class="min-h-screen bg-white flex flex-col">
    <!-- Main Content -->
    <div class="flex-1 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div class="text-center">
                <!-- Logo or Icon -->
                <?php if (getLogoUrl()): ?>
                    <div class="logo-container mb-6">
                        <img src="<?php echo htmlspecialchars(getLogoUrl()); ?>" alt="<?php echo htmlspecialchars(getCompanyName()); ?>">
                    </div>
                <?php else: ?>
                    <div class="text-6xl mb-6">🎫</div>
                <?php endif; ?>
                
                <h2 class="text-3xl font-bold text-gray-900 mb-2">
                    Welcome to <?php echo htmlspecialchars(getAppName()); ?>
                </h2>
                <p class="text-gray-600">
                    Please choose an option to continue
                </p>
            </div>

            <div class="space-y-4">
                <!-- Login Button -->
                <a href="login.php" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-2xl shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300 transform hover:scale-105">
                    <span class="mr-2">🔑</span>
                    Login
                </a>

                <!-- Register Button -->
                <a href="register.php" class="w-full flex justify-center py-3 px-4 border border-purple-600 rounded-2xl shadow-sm text-sm font-medium text-purple-600 bg-white hover:bg-purple-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300 transform hover:scale-105">
                    <span class="mr-2">📝</span>
                    Register
                </a>

                <?php if ($ssoEnabled): ?>
                    <!-- SSO Button -->
                    <a href="oidc.php" class="w-full flex justify-center py-3 px-4 border border-gray-300 rounded-2xl shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300 transform hover:scale-105">
                        <?php if (getSsoLogoUrl()): ?>
                            <img src="<?php echo htmlspecialchars(getSsoLogoUrl()); ?>" alt="SSO" class="w-5 h-5 mr-2">
                        <?php else: ?>
                            <span class="mr-2">🔐</span>
                        <?php endif; ?>
                        Login with SSO
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-white border-t py-8">
        <div class="text-center space-y-2">
            <p class="text-sm text-gray-500">
                Version <?php echo htmlspecialchars(getAppVersion()); ?>
            </p>
            <p class="text-sm text-gray-500">
                © <?php echo date('Y'); ?> <?php echo htmlspecialchars(getCompanyName()); ?>
            </p>
        </div>
    </footer>
</body>
</html>
