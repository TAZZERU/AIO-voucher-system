<?php
session_start();

define('CONFIG_ACCESS', true);
require_once 'config/app_config.php';

$pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Check if OIDC is enabled
$stmt = $pdo->query("SELECT is_enabled, settings FROM system_integrations WHERE integration = 'openid_connect'");
$oidcConfig = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$oidcConfig || !$oidcConfig['is_enabled']) {
    header('Location: login.php?error=' . urlencode('SSO is not enabled'));
    exit;
}

$settings = json_decode($oidcConfig['settings'], true);
if (empty($settings['issuer']) || empty($settings['client_id']) || empty($settings['client_secret'])) {
    header('Location: login.php?error=' . urlencode('SSO is not properly configured'));
    exit;
}

// Google-specific URLs
$isGoogle = (strpos($settings['issuer'], 'accounts.google.com') !== false);

if ($isGoogle) {
    $tokenUrl = 'https://oauth2.googleapis.com/token';
    $userinfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
    $authUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
} else {
    $tokenUrl = $settings['issuer'] . '/token';
    $userinfoUrl = $settings['issuer'] . '/userinfo';
    $authUrl = $settings['issuer'] . '/auth';
}

// Handle callback
if (isset($_GET['code'])) {
    try {
        // Exchange code for token
        $tokenData = [
            'grant_type' => 'authorization_code',
            'code' => $_GET['code'],
            'redirect_uri' => $settings['redirect_uri'],
            'client_id' => $settings['client_id'],
            'client_secret' => $settings['client_secret']
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $tokenUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($tokenData));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            throw new Exception('Token exchange failed with HTTP ' . $httpCode . ': ' . $response);
        }
        
        $tokenResponse = json_decode($response, true);
        if (!isset($tokenResponse['access_token'])) {
            throw new Exception('No access token received');
        }
        
        // Get user info
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $userinfoUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $tokenResponse['access_token']
        ]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        
        $userResponse = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            throw new Exception('User info request failed with HTTP ' . $httpCode . ': ' . $userResponse);
        }
        
        $userInfo = json_decode($userResponse, true);
        
        // Flexible User ID handling
        $userSub = $userInfo['sub'] ?? $userInfo['id'] ?? null;
        if (!$userSub) {
            throw new Exception('No user ID received (neither sub nor id field found)');
        }
        
        // Check if user exists
        $stmt = $pdo->prepare("SELECT id, username, is_active FROM users WHERE oidc_sub = ?");
        $stmt->execute([$userSub]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            // Check if user is active
            if (!$user['is_active']) {
                header('Location: login.php?error=' . urlencode('Your account has been deactivated. Please contact an administrator.'));
                exit;
            }
            
            // Update last login
            $stmt = $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
            $stmt->execute([$user['id']]);
            
            // Login user
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['login_method'] = 'oidc';
            
            header('Location: dashboard.php');
            exit;
        } else {
            // Create new user - KORRIGIERTE USERNAME-LOGIK
            $firstName = $userInfo['given_name'] ?? '';
            $lastName = $userInfo['family_name'] ?? '';
            $email = $userInfo['email'] ?? null;
            
            // Username-priority: 1. preferred_username, 2. Vollname, 3. Vorname, 4. E-Mail, 5. Fallback
            if (!empty($userInfo['preferred_username'])) {
                $username = $userInfo['preferred_username'];
            } elseif (!empty($firstName) && !empty($lastName)) {
                $username = $firstName . '.' . $lastName;
            } elseif (!empty($firstName)) {
                $username = $firstName;
            } elseif (!empty($userInfo['name'])) {
                $username = str_replace(' ', '.', $userInfo['name']);
            } elseif (!empty($email)) {
                $username = explode('@', $email)[0]; // Teil vor dem @
            } else {
                $username = 'oidc_user_' . substr($userSub, 0, 8);
            }
            
            // Username defense: remove special characters and ensure it's valid
            $username = preg_replace('/[^a-zA-Z0-9._]/', '', $username);
            $originalUsername = $username;
            
            // Check if username already exists
            $counter = 1;
            while (true) {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
                $stmt->execute([$username]);
                if ($stmt->fetchColumn() == 0) {
                    break; // Username is available
                }
                $username = $originalUsername . '_' . $counter;
                $counter++;
            }
            
            $stmt = $pdo->prepare("INSERT INTO users (username, email, first_name, last_name, oidc_sub, password_hash, is_active, created_at, last_login) VALUES (?, ?, ?, ?, ?, ?, 1, NOW(), NOW())");
            $result = $stmt->execute([
                $username,
                $email,
                $firstName,
                $lastName,
                $userSub,
                password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT)
            ]);
            
            if ($result) {
                $newUserId = $pdo->lastInsertId();
                
                // Assign default user role
                $stmt = $pdo->prepare("INSERT INTO user_roles (user_id, role) VALUES (?, 'user')");
                $stmt->execute([$newUserId]);
                
                // Login user
                $_SESSION['user_id'] = $newUserId;
                $_SESSION['username'] = $username;
                $_SESSION['login_method'] = 'oidc';
                
                header('Location: dashboard.php');
                exit;
            } else {
                throw new Exception('Failed to create user account');
            }
        }
        
    } catch (Exception $e) {
        error_log('OIDC Error: ' . $e->getMessage());
        header('Location: login.php?error=' . urlencode('SSO login failed: ' . $e->getMessage()));
        exit;
    }
}

// Redirect to authorization server
$params = [
    'response_type' => 'code',
    'client_id' => $settings['client_id'],
    'redirect_uri' => $settings['redirect_uri'],
    'scope' => 'openid profile email',
    'state' => bin2hex(random_bytes(16))
];

$_SESSION['oidc_state'] = $params['state'];

$finalAuthUrl = $authUrl . '?' . http_build_query($params);
header('Location: ' . $finalAuthUrl);
exit;
?>
