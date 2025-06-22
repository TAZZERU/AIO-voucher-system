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
    }
}
$permissions = array_unique($permissions);

function hasPermission($perm, $perms) {
    return in_array($perm, $perms);
}

$canConfigure = hasPermission('configure_system', $permissions);

if (!$canConfigure) {
    header('Location: dashboard.php');
    exit;
}

$message = '';
$message_type = '';

// Save settings
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_settings'])) {
    $integration = $_POST['integration'];
    $enabled = isset($_POST['enabled']) ? 1 : 0;
    
    if ($integration === 'openid_connect') {
        $settings = [
            'issuer' => trim($_POST['issuer']),
            'client_id' => trim($_POST['client_id']),
            'client_secret' => trim($_POST['client_secret']),
            'redirect_uri' => trim($_POST['redirect_uri'])
        ];
    } elseif ($integration === 'pretix') {
        $settings = [
            'api_url' => rtrim(trim($_POST['api_url']), '/'),
            'api_token' => trim($_POST['api_token']),
            'organizer' => trim($_POST['organizer']),
            'event' => trim($_POST['event'])
        ];
    }
    
    try {
        $stmt = $pdo->prepare("UPDATE system_integrations SET is_enabled = ?, settings = ?, updated_at = NOW() WHERE integration = ?");
        $result = $stmt->execute([$enabled, json_encode($settings), $integration]);
        
        if ($result) {
            $message = ucfirst($integration) . ' settings saved successfully!';
            $message_type = 'success';
        } else {
            $message = 'Error saving settings';
            $message_type = 'error';
        }
    } catch (Exception $e) {
        $message = 'Database error: ' . $e->getMessage();
        $message_type = 'error';
    }
}

// Test Pretix connection
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['test_pretix'])) {
    $api_url = rtrim(trim($_POST['api_url']), '/');
    $api_token = trim($_POST['api_token']);
    $organizer = trim($_POST['organizer']);
    $event = trim($_POST['event']);
    
    if (empty($api_url) || empty($api_token) || empty($organizer) || empty($event)) {
        $message = 'Please fill in all Pretix fields before testing';
        $message_type = 'error';
    } else {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api_url . '/api/v1/organizers/' . $organizer . '/events/' . $event . '/');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Token ' . $api_token
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200) {
            $eventData = json_decode($response, true);
            $message = 'Pretix connection successful! Event: ' . ($eventData['name']['en'] ?? $eventData['name'] ?? 'Unknown');
            $message_type = 'success';
        } else {
            $message = 'Pretix connection failed. HTTP Code: ' . $httpCode;
            $message_type = 'error';
        }
    }
}

// Load current settings
$stmt = $pdo->query("SELECT * FROM system_integrations ORDER BY integration");
$integrations = $stmt->fetchAll(PDO::FETCH_ASSOC);

$oidcSettings = [];
$pretixSettings = [];

foreach ($integrations as $integration) {
    $settings = json_decode($integration['settings'], true) ?: [];
    
    if ($integration['integration'] === 'openid_connect') {
        $oidcSettings = $settings;
        $oidcSettings['enabled'] = $integration['is_enabled'];
    } elseif ($integration['integration'] === 'pretix') {
        $pretixSettings = $settings;
        $pretixSettings['enabled'] = $integration['is_enabled'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings - <?php echo getAppName(); ?></title>
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
                    <span class="hidden md:inline ml-4 text-base lg:text-lg text-gray-600">/ Settings</span>
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
            <h1 class="text-xl sm:text-2xl font-bold text-gray-800">⚙️ System Settings</h1>
            <p class="text-gray-600 mt-2">Configure integrations and system settings</p>
        </div>

        <!-- Messages -->
        <?php if ($message): ?>
            <div class="mb-6 p-4 rounded-lg <?php echo $message_type === 'success' ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <!-- Pretix Integration -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h2 class="text-xl font-bold text-gray-800">🎟️ Pretix Integration</h2>
                    <p class="text-gray-600">Connect with Pretix for voucher synchronization</p>
                </div>
                <div class="flex items-center">
                    <span class="text-sm text-gray-500 mr-2">Status:</span>
                    <span class="px-2 py-1 rounded-full text-xs <?php echo $pretixSettings['enabled'] ?? false ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>">
                        <?php echo $pretixSettings['enabled'] ?? false ? 'Enabled' : 'Disabled'; ?>
                    </span>
                </div>
            </div>

            <!-- Webhook URL Info -->
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
                <h4 class="font-medium text-blue-900 mb-2">Webhook Configuration</h4>
                <div class="text-sm text-blue-800">
                    <p class="mb-2">Configure this webhook URL in your Pretix event settings:</p>
                    <div class="bg-white border rounded p-2 font-mono text-xs break-all">
                        <?php echo getAppUrl() . '/pretix_webhook.php'; ?>
                    </div>
                    <p class="mt-2 text-xs">Enable webhooks for: <code>voucher.redeemed</code>, <code>voucher.deleted</code>, <code>voucher.created</code>, <code>voucher.changed</code></p>
                </div>
            </div>

            <form method="POST" class="space-y-4">
                <input type="hidden" name="integration" value="pretix">
                
                <div class="flex items-center">
                    <input type="checkbox" name="enabled" id="pretix_enabled" 
                           class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                           <?php echo $pretixSettings['enabled'] ?? false ? 'checked' : ''; ?>>
                    <label for="pretix_enabled" class="ml-2 text-sm font-medium text-gray-700">Enable Pretix Integration</label>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">API URL *</label>
                        <input type="url" name="api_url" required 
                               value="<?php echo htmlspecialchars($pretixSettings['api_url'] ?? ''); ?>"
                               placeholder="https://pretix.eu"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">API Token *</label>
                        <input type="password" name="api_token" required 
                               value="<?php echo htmlspecialchars($pretixSettings['api_token'] ?? ''); ?>"
                               placeholder="Your Pretix API token"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Organizer Slug *</label>
                        <input type="text" name="organizer" required 
                               value="<?php echo htmlspecialchars($pretixSettings['organizer'] ?? ''); ?>"
                               placeholder="your-organizer"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Event Slug *</label>
                        <input type="text" name="event" required 
                               value="<?php echo htmlspecialchars($pretixSettings['event'] ?? ''); ?>"
                               placeholder="your-event"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                </div>

                <div class="flex gap-2">
                    <button type="submit" name="save_settings" value="1" 
                            class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition">
                        💾 Save Pretix Settings
                    </button>
                    <button type="submit" name="test_pretix" value="1" 
                            class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition">
                        🧪 Test Connection
                    </button>
                </div>
            </form>
        </div>

        <!-- OIDC Integration -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex items-center justify-between mb-6">
                <div>
                    <h2 class="text-xl font-bold text-gray-800">🔐 OAuth/OIDC Integration</h2>
                    <p class="text-gray-600">Single Sign-On with OAuth providers (Google, Azure, Keycloak, etc.)</p>
                </div>
                <div class="flex items-center">
                    <span class="text-sm text-gray-500 mr-2">Status:</span>
                    <span class="px-2 py-1 rounded-full text-xs <?php echo $oidcSettings['enabled'] ?? false ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>">
                        <?php echo $oidcSettings['enabled'] ?? false ? 'Enabled' : 'Disabled'; ?>
                    </span>
                </div>
            </div>

            <!-- Provider Examples -->
            <div class="bg-purple-50 border border-purple-200 rounded-lg p-4 mb-6">
                <h4 class="font-medium text-purple-900 mb-2">Supported OAuth Providers:</h4>
                <div class="text-sm text-purple-800 space-y-1">
                    <div><strong>Google:</strong> Set issuer to "https://accounts.google.com"</div>
                    <div><strong>Microsoft:</strong> Set issuer to "https://login.microsoftonline.com/[tenant-id]/v2.0"</div>
                    <div><strong>Keycloak:</strong> Set issuer to "https://your-keycloak.com/auth/realms/[realm]"</div>
                    <div><strong>Auth0:</strong> Set issuer to "https://your-domain.auth0.com"</div>
                    <div><strong>Okta:</strong> Set issuer to "https://your-domain.okta.com/oauth2/default"</div>
                </div>
            </div>

            <form method="POST" class="space-y-4">
                <input type="hidden" name="integration" value="openid_connect">
                
                <div class="flex items-center">
                    <input type="checkbox" name="enabled" id="oidc_enabled" 
                           class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                           <?php echo $oidcSettings['enabled'] ?? false ? 'checked' : ''; ?>>
                    <label for="oidc_enabled" class="ml-2 text-sm font-medium text-gray-700">Enable OAuth/OIDC Integration</label>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Issuer URL *</label>
                        <input type="url" name="issuer" required 
                               value="<?php echo htmlspecialchars($oidcSettings['issuer'] ?? ''); ?>"
                               placeholder="https://accounts.google.com"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Client ID *</label>
                        <input type="text" name="client_id" required 
                               value="<?php echo htmlspecialchars($oidcSettings['client_id'] ?? ''); ?>"
                               placeholder="Your OAuth Client ID"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Client Secret *</label>
                        <input type="password" name="client_secret" required 
                               value="<?php echo htmlspecialchars($oidcSettings['client_secret'] ?? ''); ?>"
                               placeholder="Your OAuth Client Secret"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Redirect URI *</label>
                        <input type="url" name="redirect_uri" required 
                               value="<?php echo htmlspecialchars($oidcSettings['redirect_uri'] ?? getAppUrl() . '/oidc.php'); ?>"
                               placeholder="<?php echo getAppUrl(); ?>/oidc.php"
                               class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    </div>
                </div>

                <button type="submit" name="save_settings" value="1" 
                        class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition">
                    💾 Save OAuth Settings
                </button>
            </form>
        </div>

        <!-- System Information -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
            <h2 class="text-xl font-bold text-gray-800 mb-4">📊 System Information</h2>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                    <strong>Application:</strong> <?php echo getAppName(); ?> v<?php echo getAppVersion(); ?>
                </div>
                <div>
                    <strong>Company:</strong> <?php echo getCompanyName(); ?>
                </div>
                <div>
                    <strong>PHP Version:</strong> <?php echo PHP_VERSION; ?>
                </div>
                <div>
                    <strong>Database:</strong> MySQL <?php echo $pdo->query('SELECT VERSION()')->fetchColumn(); ?>
                </div>
                <div>
                    <strong>App URL:</strong> <?php echo getAppUrl(); ?>
                </div>
                <div>
                    <strong>Webhook URL:</strong> <?php echo getAppUrl(); ?>pretix_webhook.php
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
    </script>
</body>
</html>
