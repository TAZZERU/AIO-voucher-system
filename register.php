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

// Handle registration
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $firstName = trim($_POST['first_name'] ?? '');
    $lastName = trim($_POST['last_name'] ?? '');
    
    // Validation
    if (empty($username) || empty($password) || empty($confirmPassword)) {
        $error = 'Please fill in all required fields.';
    } elseif (strlen($username) < 3) {
        $error = 'Username must be at least 3 characters long.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters long.';
    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match.';
    } elseif (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please enter a valid email address.';
    } else {
        try {
            // Check if username already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $error = 'Username already exists. Please choose a different one.';
            } else {
                // Check if email already exists (if provided)
                if (!empty($email)) {
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                    $stmt->execute([$email]);
                    if ($stmt->fetch()) {
                        $error = 'Email address already exists. Please use a different one.';
                    }
                }
                
                if (!$error) {
                    // Create user
                    $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash, first_name, last_name, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, NOW())");
                    $stmt->execute([
                        $username,
                        !empty($email) ? $email : null,
                        $passwordHash,
                        !empty($firstName) ? $firstName : null,
                        !empty($lastName) ? $lastName : null
                    ]);
                    
                    $success = 'Account created successfully! You can now log in.';
                    
                    // Clear form data
                    $_POST = [];
                }
            }
        } catch (PDOException $e) {
            $error = 'Registration failed. Please try again.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - <?php echo getAppName(); ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-white flex flex-col">
    <!-- Main Content -->
    <div class="flex-1 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div class="text-center">
                <div class="text-6xl mb-6">📝</div>
                <h2 class="text-3xl font-bold text-gray-900 mb-2">
                    Create your account
                </h2>
                <p class="text-gray-600">
                    Join us and start managing your vouchers
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
                            <h3 class="text-sm font-medium text-red-800">Registration Error</h3>
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

            <!-- Registration Form -->
            <form method="POST" class="space-y-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label for="first_name" class="block text-sm font-medium text-gray-700 mb-2">
                            First Name
                        </label>
                        <input id="first_name" name="first_name" type="text" 
                               value="<?php echo htmlspecialchars($_POST['first_name'] ?? ''); ?>"
                               class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                               placeholder="Enter your first name">
                    </div>

                    <div>
                        <label for="last_name" class="block text-sm font-medium text-gray-700 mb-2">
                            Last Name
                        </label>
                        <input id="last_name" name="last_name" type="text" 
                               value="<?php echo htmlspecialchars($_POST['last_name'] ?? ''); ?>"
                               class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                               placeholder="Enter your last name">
                    </div>
                </div>

                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700 mb-2">
                        Username *
                    </label>
                    <input id="username" name="username" type="text" required 
                           value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                           placeholder="Choose a username">
                </div>

                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700 mb-2">
                        Email Address
                    </label>
                    <input id="email" name="email" type="email" 
                           value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>"
                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                           placeholder="Enter your email (optional)">
                </div>

                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700 mb-2">
                        Password *
                    </label>
                    <input id="password" name="password" type="password" required 
                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                           placeholder="Choose a password">
                    <p class="text-xs text-gray-500 mt-1">Minimum 6 characters</p>
                </div>

                <div>
                    <label for="confirm_password" class="block text-sm font-medium text-gray-700 mb-2">
                        Confirm Password *
                    </label>
                    <input id="confirm_password" name="confirm_password" type="password" required 
                           class="w-full px-4 py-3 border border-gray-300 rounded-2xl focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                           placeholder="Confirm your password">
                </div>

                <div>
                    <button type="submit" class="w-full flex justify-center py-3 px-4 border border-transparent rounded-2xl shadow-sm text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-purple-500 transition duration-300 transform hover:scale-105">
                        <span class="mr-2">🚀</span>
                        Create Account
                    </button>
                </div>
            </form>

            <!-- Alternative Registration Options -->
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
                        Register with SSO
                    </a>
                <?php endif; ?>

                <!-- Login Link -->
                <div class="text-center pt-4">
                    <p class="text-sm text-gray-600">
                        Already have an account? 
                        <a href="login.php" class="text-purple-600 hover:text-purple-800 font-medium transition duration-300">
                            Sign in here
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
