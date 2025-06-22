<?php
session_start();
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

$error = '';
$success = '';

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (empty($username) || empty($password)) {
        $error = 'Please fill in all fields.';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id, username, password_hash, is_active FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && password_verify($password, $user['password_hash'])) {
                if ($user['is_active']) {
                    // Update last login
                    $stmt = $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                    $stmt->execute([$user['id']]);
                    
                    // Set session
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    
                    // Redirect to dashboard
                    header('Location: dashboard.php');
                    exit;
                } else {
                    $error = 'Your account has been deactivated. Please contact an administrator.';
                }
            } else {
                $error = 'Invalid username or password.';
            }
        } catch (PDOException $e) {
            $error = 'Login failed. Please try again.';
        }
    }
}

// Get error from URL parameter (e.g., from SSO)
if (isset($_GET['error'])) {
    $error = urldecode($_GET['error']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?php echo getAppName(); ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-white flex flex-col">
    <!-- Main Content -->
    <div class="flex-1 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div class="text-center">
                <div class="text-6xl mb-6">🔑</div>
                <h2 class="text-3xl font-bold text-gray-900 mb-2">
                    Sign in to your account
                </h2>
                <p class="text-gray-600">
                    Welcome back! Please enter your credentials
                </p>
                
                <!-- Back to Home Link -->
                <div class="mt-4">
                    <a href="index.php" class="text-purple-600 hover:text-purple-800 text-sm font-medium transition duration-300">
                        ← Back to Home
                    </a>
                </div>
            </div>

            <!-- Error Message -->
            <?php if ($error): ?>
                <div class="bg-red-50 border border-red-200 rounded-2xl p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <h3 class="text-sm font-medium text-red-800">Login Error</h3>
                            <div class="mt-2 text-sm text-red-700">
                                <p><?php echo htmlspecialchars($error); ?></p>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Success Message -->
            <?php if ($success): ?>
                <div class="bg-green-50 border border-green-200 rounded-2xl p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-green-800"><?php echo htmlspecialchars($success); ?></p>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <!-- Login Form -->
            <form method="POST" class="space-y-6">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700 mb-2">
                        Username
                    </label>
                    <input id="username" name="username" type="text" required 
                           value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                           placeholder="Enter your username">
                </div>

                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                        Password
                    </label>
                    <input id="password" name="password" type="password" required 
                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                           placeholder="Enter your password">
                </div>

                <div>
                    <button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-2xl shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300 transform hover:scale-105">
                        <span class="mr-2">🚀</span>
                        Sign in
                    </button>
                </div>
            </form>

            <!-- Alternative Login Options -->
            <div class="space-y-4">
                <?php if ($ssoEnabled): ?>
                    <div class="relative">
                        <div class="absolute inset-0 flex items-center">
                            <div class="w-full border-t border-gray-300"></div>
                        </div>
                        <div class="relative flex justify-center text-sm">
                            <span class="px-2 bg-white text-gray-500">Or continue with</span>
                        </div>
                    </div>

                    <a href="oidc.php" class="w-full flex justify-center py-3 px-4 border border-gray-300 rounded-2xl shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300 transform hover:scale-105">
                        <?php if (getSsoLogoUrl()): ?>
                            <img src="<?php echo htmlspecialchars(getSsoLogoUrl()); ?>" alt="SSO" class="w-5 h-5 mr-2">
                        <?php else: ?>
                            <span class="mr-2">🔐</span>
                        <?php endif; ?>
                        Login with SSO
                    </a>
                <?php endif; ?>

                <!-- Register Link -->
                <div class="text-center pt-4">
                    <p class="text-sm text-gray-600">
                        Don't have an account? 
                        <a href="register.php" class="text-purple-600 hover:text-purple-800 font-medium transition duration-300">
                            Register here
                        </a>
                    </p>
                </div>
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
