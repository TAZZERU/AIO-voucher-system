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
        case 'scanner':
            $permissions = array_merge($permissions, ['scan_vouchers']);
            break;
    }
}
$permissions = array_unique($permissions);

function hasPermission($perm, $perms) {
    return in_array($perm, $perms);
}

$canScan = hasPermission('scan_vouchers', $permissions);

if (!$canScan) {
    header('Location: dashboard.php');
    exit;
}

$message = '';
$message_type = '';

// Pretix functions
function removePretixVoucher($voucherCode, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // find Vouchers
        $stmt = $pdo->prepare("SELECT pretix_voucher_id FROM vouchers WHERE voucher_code = ?");
        $stmt->execute([$voucherCode]);
        $pretixId = $stmt->fetchColumn();
        
        if (!$pretixId) return false;
        
        // delete from Pretix
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
        
        if ($httpCode === 204) {
            return true;
        }
        
        return false;
    } catch (Exception $e) {
        error_log('Pretix remove error: ' . $e->getMessage());
        return false;
    }
}

function markPretixVoucherAsRedeemed($voucherCode, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // find vouchers in pretix
        $stmt = $pdo->prepare("SELECT pretix_voucher_id FROM vouchers WHERE voucher_code = ?");
        $stmt->execute([$voucherCode]);
        $pretixId = $stmt->fetchColumn();
        
        if (!$pretixId) return false;
        
        // Mark as redeemed in Pretix
        $data = [
            'redeemed' => 1  // Markiere als eingelöst
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $settings['api_url'] . '/api/v1/organizers/' . $settings['organizer'] . '/events/' . $settings['event'] . '/vouchers/' . $pretixId . '/');
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Token ' . $settings['api_token'],
            'Content-Type: application/json'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return $httpCode === 200;
    } catch (Exception $e) {
        error_log('Pretix mark redeemed error: ' . $e->getMessage());
        return false;
    }
}

function pushToPretix($voucherCode, $type, $price, $actualValue, $isPermanent, $expiresAt, $pdo) {
    try {
        $stmt = $pdo->query("SELECT settings FROM system_integrations WHERE integration = 'pretix' AND is_enabled = 1");
        $pretixSettings = $stmt->fetchColumn();
        
        if (!$pretixSettings) return false;
        
        $settings = json_decode($pretixSettings, true);
        if (empty($settings['api_url']) || empty($settings['api_token'])) return false;
        
        // Hole Kategorie-Details für bessere Beschreibung
        $stmt = $pdo->prepare("SELECT name, icon FROM voucher_types WHERE type_key = ?");
        $stmt->execute([$type]);
        $categoryInfo = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $categoryName = $categoryInfo['name'] ?? $type;
        $categoryIcon = $categoryInfo['icon'] ?? '🎫';
        
        $comment = $categoryIcon . ' ' . $categoryName;
        if ($actualValue != $price) {
            $comment .= ' (Value: €' . number_format($actualValue, 2) . ', Price: €' . number_format($price, 2) . ')';
        }
        if ($isPermanent) {
            $comment .= ' - PERMANENT VOUCHER';
        }
        $comment .= ' - Auto-created from Voucher System';
        
        $data = [
            'code' => $voucherCode,
            'max_usages' => 1,
            'valid_until' => $isPermanent ? null : $expiresAt,
            'price_mode' => 'set',
            'value' => $price,
            'tag' => $type,
            'comment' => $comment
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

// Redeem voucher
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['redeem_voucher'])) {
    $voucher_code = trim($_POST['voucher_code']);
    
    if (empty($voucher_code)) {
        $message = 'Please enter voucher code';
        $message_type = 'error';
    } else {
        try {
            // Prüfe Kategorie-Status und Ablauf vor Einlösung
            $stmt = $pdo->prepare("
                SELECT v.*, vt.is_active as category_active 
                FROM vouchers v 
                LEFT JOIN voucher_types vt ON v.type = vt.type_key 
                WHERE v.voucher_code = ? AND v.is_redeemed = 0 AND v.is_active = 1
            ");
            $stmt->execute([$voucher_code]);
            $voucher = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$voucher) {
                $message = "Voucher {$voucher_code} not found or already redeemed or deactivated";
                $message_type = 'error';
            } elseif (!$voucher['category_active']) {
                $message = "Voucher category is deactivated";
                $message_type = 'error';
            } elseif (!$voucher['is_permanent'] && $voucher['expires_at'] && strtotime($voucher['expires_at']) < time()) {
                $message = "Voucher has expired on " . date('m/d/Y', strtotime($voucher['expires_at']));
                $message_type = 'error';
            } else {
                $stmt = $pdo->prepare("UPDATE vouchers SET is_redeemed = 1, redeemed_at = NOW(), redeemed_by = ? WHERE voucher_code = ?");
                $result = $stmt->execute([$userId, $voucher_code]);
                
                if ($result && $stmt->rowCount() > 0) {
                    // Pretix Sync
                    markPretixVoucherAsRedeemed($voucher_code, $pdo);
                    
                    $message = "Voucher {$voucher_code} successfully redeemed!";
                    $message_type = 'success';
                } else {
                    $message = "Error redeeming voucher {$voucher_code}";
                    $message_type = 'error';
                }
            }
        } catch (Exception $e) {
            $message = 'Error redeeming voucher';
            $message_type = 'error';
        }
    }
}

// Reactivate voucher
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reactivate_voucher'])) {
    $voucher_code = trim($_POST['voucher_code']);
    
    if (empty($voucher_code)) {
        $message = 'Please enter voucher code';
        $message_type = 'error';
    } else {
        try {
            // get Voucher-Details for Pretix-Push
            $stmt = $pdo->prepare("
                SELECT v.*, vt.is_active as category_active 
                FROM vouchers v 
                LEFT JOIN voucher_types vt ON v.type = vt.type_key 
                WHERE v.voucher_code = ? AND v.is_redeemed = 1
            ");
            $stmt->execute([$voucher_code]);
            $voucher = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$voucher) {
                $message = "Voucher {$voucher_code} not found or not redeemed";
                $message_type = 'error';
            } else {
                $stmt = $pdo->prepare("UPDATE vouchers SET is_redeemed = 0, redeemed_at = NULL WHERE voucher_code = ?");
                $result = $stmt->execute([$voucher_code]);
                
                if ($result && $stmt->rowCount() > 0) {
                    // Pretix Sync 
                    if ($voucher['category_active'] && $voucher['is_active']) {
                        pushToPretix($voucher_code, $voucher['type'], $voucher['price'], $voucher['actual_value'], $voucher['is_permanent'], $voucher['expires_at'], $pdo);
                    }
                    
                    $message = "Voucher {$voucher_code} successfully reactivated!";
                    $message_type = 'success';
                } else {
                    $message = "Error reactivating voucher {$voucher_code}";
                    $message_type = 'error';
                }
            }
        } catch (Exception $e) {
            $message = 'Error reactivating voucher';
            $message_type = 'error';
        }
    }
}

// AJAX Handler for QR scan
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'scan_qr') {
    header('Content-Type: application/json');
    
    $voucher_code = trim($_POST['voucher_code'] ?? '');
    
    if (empty($voucher_code)) {
        echo json_encode(['success' => false, 'message' => 'Voucher code missing']);
        exit;
    }
    
    try {
        // Load voucher information WITH user status AND category status
        $stmt = $pdo->prepare("
            SELECT v.*, u.username, u.is_active as user_active, vt.name as type_name, vt.icon as type_icon, vt.is_active as category_active
            FROM vouchers v 
            LEFT JOIN users u ON v.user_id = u.id 
            LEFT JOIN voucher_types vt ON v.type = vt.type_key 
            WHERE v.voucher_code = ?
        ");
        $stmt->execute([$voucher_code]);
        $voucher = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$voucher) {
            echo json_encode(['success' => false, 'message' => 'Voucher not found']);
            exit;
        }
        
        // Check if user is deactivated
        if (!$voucher['user_active']) {
            echo json_encode([
                'success' => false, 
                'message' => 'Voucher owner account is deactivated',
                'voucher' => $voucher,
                'reason' => 'user_deactivated'
            ]);
            exit;
        }
        
        // Check if category is deactivated
        if (!$voucher['category_active']) {
            echo json_encode([
                'success' => false, 
                'message' => 'Voucher category is deactivated',
                'voucher' => $voucher,
                'reason' => 'category_deactivated'
            ]);
            exit;
        }
        
        // Check if expired (only if not permanent)
        if (!$voucher['is_permanent'] && $voucher['expires_at'] && strtotime($voucher['expires_at']) < time()) {
            echo json_encode([
                'success' => false, 
                'message' => 'Voucher has expired on ' . date('m/d/Y', strtotime($voucher['expires_at'])),
                'voucher' => $voucher,
                'reason' => 'expired'
            ]);
            exit;
        }
        
        if ($voucher['is_redeemed']) {
            echo json_encode([
                'success' => false, 
                'message' => 'Voucher already redeemed on ' . date('m/d/Y H:i', strtotime($voucher['redeemed_at'])),
                'voucher' => $voucher
            ]);
            exit;
        }
        
        if (!$voucher['is_active']) {
            echo json_encode(['success' => false, 'message' => 'Voucher is deactivated', 'voucher' => $voucher]);
            exit;
        }
        
        // Redeem voucher
        $stmt = $pdo->prepare("UPDATE vouchers SET is_redeemed = 1, redeemed_at = NOW(), redeemed_by = ? WHERE voucher_code = ?");
        $result = $stmt->execute([$userId, $voucher_code]);
        
        if ($result) {
            // Pretix Sync - Voucher als redeemed markieren (nicht löschen!)
            markPretixVoucherAsRedeemed($voucher_code, $pdo);
            
            echo json_encode([
                'success' => true, 
                'message' => 'Voucher successfully redeemed',
                'voucher' => $voucher
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Error redeeming voucher']);
        }
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Voucher Scanner - <?php echo getAppName(); ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script>
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
        
        .scanner-wrapper {
            position: relative;
            display: inline-block;
        }
        
        #qr-reader {
            width: 300px !important;
            height: 300px !important;
            border-radius: 12px;
            overflow: hidden;
            background: #000;
            transition: border-color 0.3s ease;
        }
        
        #qr-reader div[style*="border"] {
            border: none !important;
        }
        
        #qr-reader video {
            width: 100% !important;
            height: 100% !important;
            object-fit: cover !important;
            display: block !important;
        }
        
        #qr-reader canvas {
            width: 100% !important;
            height: 100% !important;
            object-fit: cover !important;
        }
        
        .corner {
            position: absolute;
            width: 25px;
            height: 25px;
            border: 3px solid #3b82f6;
            transition: border-color 0.3s ease;
            z-index: 2;
            pointer-events: none;
        }
        
        .corner-top-left {
            top: 15px;
            left: 15px;
            border-right: none;
            border-bottom: none;
            border-top-left-radius: 6px;
        }
        
        .corner-top-right {
            top: 15px;
            right: 15px;
            border-left: none;
            border-bottom: none;
            border-top-right-radius: 6px;
        }
        
        .corner-bottom-left {
            bottom: 15px;
            left: 15px;
            border-right: none;
            border-top: none;
            border-bottom-left-radius: 6px;
        }
        
        .corner-bottom-right {
            bottom: 15px;
            right: 15px;
            border-left: none;
            border-top: none;
            border-bottom-right-radius: 6px;
        }
        
        .scanner-wrapper.scanning .corner {
            border-color: #3b82f6;
        }
        
        .scanner-wrapper.validating .corner {
            border-color: #f59e0b;
            animation: pulse 0.5s infinite;
        }
        
        .scanner-wrapper.valid .corner {
            border-color: #10b981;
        }
        
        .scanner-wrapper.invalid .corner {
            border-color: #ef4444;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .countdown {
            font-weight: bold;
            color: #3b82f6;
        }
        
        @media (max-width: 640px) {
            #qr-reader {
                width: 280px !important;
                height: 280px !important;
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
                    <span class="hidden md:inline ml-4 text-base lg:text-lg text-gray-600">/ Scanner</span>
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

    <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Header -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <div class="flex flex-col sm:flex-row justify-between items-center">
                <div>
                    <h1 class="text-2xl sm:text-3xl font-bold text-gray-800 mb-2">📱 Voucher Scanner</h1>
                    <p class="text-gray-600">Scan QR codes to redeem vouchers (syncs with Pretix)</p>
                </div>
            </div>
        </div>
        
        <!-- Messages -->
        <?php if ($message): ?>
            <div class="mb-6 p-4 rounded-lg <?php echo $message_type === 'success' ? 'bg-green-100 text-green-800 border border-green-200' : 'bg-red-100 text-red-800 border border-red-200'; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>
        
        <!-- Scanner Section -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <!-- Camera Selection -->
            <div id="cameraSelection" class="mb-6">
                <label for="cameraSelect" class="block text-sm font-medium text-gray-700 mb-2">Select camera:</label>
                <select id="cameraSelect" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    <option value="">Loading cameras...</option>
                </select>
            </div>
            
            <!-- Scanner -->
            <div class="text-center">
                <div class="scanner-wrapper scanning" id="scannerWrapper">
                    <div id="qr-reader" class="border-4 border-blue-500 mx-auto"></div>
                    <div class="corner corner-top-left"></div>
                    <div class="corner corner-top-right"></div>
                    <div class="corner corner-bottom-left"></div>
                    <div class="corner corner-bottom-right"></div>
                </div>
            </div>
            
            <!-- Controls -->
            <div class="text-center mt-6 space-y-4">
                <div class="flex flex-wrap justify-center gap-2 sm:gap-4">
                    <button id="startBtn" onclick="startScanner()" 
                            class="bg-green-500 hover:bg-green-600 text-white font-semibold py-2 px-4 sm:px-6 rounded-lg transition duration-300 transform hover:scale-105 shadow-md">
                        Start Scanner
                    </button>
                    <button id="stopBtn" onclick="stopScanner()" style="display: none;"
                            class="bg-red-500 hover:bg-red-600 text-white font-semibold py-2 px-4 sm:px-6 rounded-lg transition duration-300 transform hover:scale-105 shadow-md">
                        Stop Scanner
                    </button>
                    <button id="switchCamera" onclick="switchCamera()" style="display: none;"
                            class="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-2 px-4 sm:px-6 rounded-lg transition duration-300 transform hover:scale-105 shadow-md">
                        Switch Camera
                    </button>
                    <button id="clearResult" onclick="clearLastResult()" style="display: none;"
                            class="bg-gray-500 hover:bg-gray-600 text-white font-semibold py-2 px-4 sm:px-6 rounded-lg transition duration-300 transform hover:scale-105 shadow-md">
                        Clear Result
                    </button>
                </div>
            </div>
            
            <div id="result" class="mt-6"></div>
        </div>
        
        <!-- Manual Entry -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6 mb-8">
            <h3 class="text-lg sm:text-xl font-semibold text-gray-800 mb-4">Manual Entry</h3>
            <p class="text-gray-600 mb-4 text-sm sm:text-base">If scanning doesn't work, you can enter the voucher code manually:</p>
            <div class="flex flex-col sm:flex-row gap-2 sm:gap-4">
                <input type="text" id="manualCode" placeholder="Enter voucher code (XXXX-XXXX-XXXX)" 
                       class="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono">
                <button onclick="validateManualCode()" 
                        class="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 px-4 sm:px-6 rounded-lg transition duration-300 transform hover:scale-105 shadow-md">
                    Validate
                </button>
            </div>
        </div>

        <!-- Voucher Reactivation -->
        <div class="bg-white rounded-xl shadow-lg p-4 sm:p-6">
            <h3 class="text-lg sm:text-xl font-semibold text-gray-800 mb-4">Reactivate Voucher</h3>
            <p class="text-gray-600 mb-4 text-sm sm:text-base">Already redeemed vouchers can be reactivated here (also syncs with Pretix):</p>
            <form method="POST" class="flex flex-col sm:flex-row gap-2 sm:gap-4">
                <input type="text" name="voucher_code" placeholder="Enter voucher code" 
                       class="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent font-mono">
                <button type="submit" name="reactivate_voucher" value="1"
                        class="bg-orange-500 hover:bg-orange-600 text-white font-semibold py-3 px-4 sm:px-6 rounded-lg transition duration-300 transform hover:scale-105 shadow-md">
                    Reactivate
                </button>
            </form>
        </div>
    </div>
    
    <script>
        let html5QrcodeScanner = null;
        let cameras = [];
        let currentCameraIndex = 0;
        let isScanning = false;
        let lastScannedCode = null;
        let scanCooldown = false;
        let lastScanResult = null;
        let scanTimestamp = null;
        let autoResumeTimeout = null;
        let currentVoucherData = null;
        
        document.addEventListener('DOMContentLoaded', function() {
            loadCameras();
            setupManualInput();
        });
        
        function setupManualInput() {
            const manualInput = document.getElementById('manualCode');
            
            // Code formatting
            manualInput.addEventListener('input', function(e) {
                let value = e.target.value.replace(/[^A-Z0-9]/g, '').toUpperCase();
                if (value.length > 12) value = value.substring(0, 12);
                
                if (value.length > 8) {
                    value = value.substring(0, 4) + '-' + value.substring(4, 8) + '-' + value.substring(8);
                } else if (value.length > 4) {
                    value = value.substring(0, 4) + '-' + value.substring(4);
                }
                
                e.target.value = value;
            });
            
            // Enter key
            manualInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    validateManualCode();
                }
            });
        }
        
        async function loadCameras() {
            try {
                const devices = await Html5Qrcode.getCameras();
                cameras = devices;
                
                const select = document.getElementById('cameraSelect');
                select.innerHTML = '';
                
                if (devices.length === 0) {
                    select.innerHTML = '<option value="">No cameras found</option>';
                    return;
                }
                
                devices.forEach((device, index) => {
                    const option = document.createElement('option');
                    option.value = device.id;
                    option.textContent = device.label || `Camera ${index + 1}`;
                    if (index === 0) option.selected = true;
                    select.appendChild(option);
                });
                
                // Auto-start with first camera
                if (devices.length > 0) {
                    setTimeout(() => startScanner(), 500);
                }
                
            } catch (err) {
                console.error('Error loading cameras:', err);
                document.getElementById('cameraSelect').innerHTML = '<option value="">Error loading cameras</option>';
            }
        }
        
        async function startScanner() {
            if (isScanning) return;
            
            const selectedCameraId = document.getElementById('cameraSelect').value;
            if (!selectedCameraId) {
                alert('Please select a camera');
                return;
            }
            
            try {
                html5QrcodeScanner = new Html5Qrcode("qr-reader");
                
                const config = {
                    fps: 10,
                    qrbox: { width: 250, height: 250 },
                    aspectRatio: 1.0,
                    disableFlip: false
                };
                
                await html5QrcodeScanner.start(
                    selectedCameraId,
                    config,
                    onScanSuccess,
                    onScanFailure
                );
                
                isScanning = true;
                document.getElementById('startBtn').style.display = 'none';
                document.getElementById('stopBtn').style.display = 'inline-block';
                document.getElementById('switchCamera').style.display = cameras.length > 1 ? 'inline-block' : 'none';
                
                updateScannerState('scanning');
                
            } catch (err) {
                console.error('Error starting scanner:', err);
                alert('Error starting camera: ' + err.message);
            }
        }
        
        async function stopScanner() {
            if (!isScanning || !html5QrcodeScanner) return;
            
            try {
                await html5QrcodeScanner.stop();
                html5QrcodeScanner = null;
                isScanning = false;
                
                document.getElementById('startBtn').style.display = 'inline-block';
                document.getElementById('stopBtn').style.display = 'none';
                document.getElementById('switchCamera').style.display = 'none';
                
                updateScannerState('scanning');
                
            } catch (err) {
                console.error('Error stopping scanner:', err);
            }
        }
        
        async function switchCamera() {
            if (!isScanning || cameras.length <= 1) return;
            
            await stopScanner();
            
            currentCameraIndex = (currentCameraIndex + 1) % cameras.length;
            document.getElementById('cameraSelect').selectedIndex = currentCameraIndex;
            
            setTimeout(() => startScanner(), 500);
        }
        
        function updateScannerState(state) {
            const wrapper = document.getElementById('scannerWrapper');
            wrapper.className = `scanner-wrapper ${state}`;
        }
        
        async function onScanSuccess(decodedText, decodedResult) {
            if (scanCooldown) return;
            
            // Prevent multiple scans of same code
            if (lastScannedCode === decodedText && Date.now() - scanTimestamp < 3000) {
                return;
            }
            
            lastScannedCode = decodedText;
            scanTimestamp = Date.now();
            scanCooldown = true;
            
            updateScannerState('validating');
            
            try {
                await validateVoucher(decodedText);
            } catch (error) {
                console.error('Validation error:', error);
                showResult('Error validating voucher', 'error');
                updateScannerState('invalid');
            }
            
            // Resume scanning after delay
            setTimeout(() => {
                scanCooldown = false;
                if (isScanning) {
                    updateScannerState('scanning');
                }
            }, 3000);
        }
        
        function onScanFailure(error) {
            // Silent - scanning failures are normal
        }
        
        async function validateManualCode() {
            const code = document.getElementById('manualCode').value.trim();
            if (!code) {
                alert('Please enter a voucher code');
                return;
            }
            
            await validateVoucher(code);
        }
        
        async function validateVoucher(voucherCode) {
            try {
                const formData = new FormData();
                formData.append('action', 'scan_qr');
                formData.append('voucher_code', voucherCode);
                
                const response = await fetch('scanner.php', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showResult(`✅ Voucher ${voucherCode} successfully redeemed!`, 'success', result.voucher);
                    updateScannerState('valid');
                    document.getElementById('manualCode').value = '';
                } else {
                    showResult(`❌ ${result.message}`, 'error', result.voucher);
                    updateScannerState('invalid');
                }
                
                currentVoucherData = result.voucher;
                
            } catch (error) {
                showResult('❌ Network error', 'error');
                updateScannerState('invalid');
            }
        }
        
        function showResult(message, type, voucher = null) {
            const resultDiv = document.getElementById('result');
            const isSuccess = type === 'success';
            
            let voucherInfo = '';
            if (voucher) {
                const now = new Date();
                const expiresAt = voucher.expires_at ? new Date(voucher.expires_at) : null;
                const isExpired = !voucher.is_permanent && expiresAt && expiresAt < now;
                
                voucherInfo = `
                    <div class="mt-4 p-4 bg-gray-50 rounded-lg">
                        <h4 class="font-semibold text-gray-800 mb-2">Voucher Details:</h4>
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                            <div><strong>Code:</strong> ${voucher.voucher_code}</div>
                            <div><strong>Value:</strong> €${parseFloat(voucher.actual_value || voucher.price).toFixed(2)}</div>
                            ${voucher.actual_value != voucher.price ? `<div><strong>Price:</strong> €${parseFloat(voucher.price).toFixed(2)}</div>` : ''}
                            <div><strong>Type:</strong> ${voucher.type_icon || '🎫'} ${voucher.type_name || voucher.type}</div>
                            <div><strong>Owner:</strong> ${voucher.username || 'Unknown'}</div>
                            ${voucher.is_permanent ? '<div><strong>Type:</strong> ♾️ Permanent Voucher</div>' : ''}
                            ${voucher.expires_at && !voucher.is_permanent ? `<div><strong>Expires:</strong> ${new Date(voucher.expires_at).toLocaleDateString()}</div>` : ''}
                            ${voucher.redeemed_at ? `<div><strong>Redeemed:</strong> ${new Date(voucher.redeemed_at).toLocaleString()}</div>` : ''}
                        </div>
                    </div>
                `;
            }
            
            resultDiv.innerHTML = `
                <div class="p-4 rounded-lg border ${isSuccess ? 'bg-green-50 border-green-200 text-green-800' : 'bg-red-50 border-red-200 text-red-800'}">
                    <div class="flex items-center justify-between">
                        <div class="flex-1">
                            <p class="font-semibold text-lg">${message}</p>
                            ${voucherInfo}
                        </div>
                        <button onclick="clearLastResult()" class="ml-4 text-gray-500 hover:text-gray-700">
                            <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                            </svg>
                        </button>
                    </div>
                </div>
            `;
            
            document.getElementById('clearResult').style.display = 'inline-block';
            
            // Auto-clear after 10 seconds for success
            if (isSuccess) {
                setTimeout(() => {
                    clearLastResult();
                }, 10000);
            }
        }
        
        function clearLastResult() {
            document.getElementById('result').innerHTML = '';
            document.getElementById('clearResult').style.display = 'none';
            currentVoucherData = null;
            
            if (isScanning) {
                updateScannerState('scanning');
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
        
        // Cleanup on page unload
        window.addEventListener('beforeunload', function() {
            if (isScanning && html5QrcodeScanner) {
                html5QrcodeScanner.stop().catch(console.error);
            }
        });
    </script>
</body>
</html>
