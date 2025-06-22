<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

/**
 * Utility Functions for Voucher Management System
 */

function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function requireCSRF() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!verifyCSRFToken($token)) {
            http_response_code(403);
            die(json_encode(['error' => 'CSRF token mismatch']));
        }
    }
}

function formatCurrency($amount, $currency = 'EUR') {
    return number_format($amount, 2) . ' ' . $currency;
}

function formatDate($date, $format = 'Y-m-d H:i:s') {
    if (!$date) return '';
    
    try {
        $dateTime = new DateTime($date);
        return $dateTime->format($format);
    } catch (Exception $e) {
        return $date;
    }
}

function formatDateHuman($date) {
    if (!$date) return '';
    
    try {
        $dateTime = new DateTime($date);
        $now = new DateTime();
        $interval = $now->diff($dateTime);
        
        if ($interval->days === 0) {
            if ($interval->h === 0) {
                return $interval->i . ' minutes ago';
            }
            return $interval->h . ' hours ago';
        } elseif ($interval->days === 1) {
            return 'Yesterday';
        } elseif ($interval->days < 7) {
            return $interval->days . ' days ago';
        } else {
            return $dateTime->format('M d, Y');
        }
    } catch (Exception $e) {
        return $date;
    }
}

function getClientIP() {
    $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (!empty($_SERVER[$key])) {
            $ips = explode(',', $_SERVER[$key]);
            $ip = trim($ips[0]);
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function isAjaxRequest() {
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
           strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

function jsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function redirectTo($url, $statusCode = 302) {
    http_response_code($statusCode);
    header("Location: $url");
    exit;
}

function getIntegrationSettings($integration) {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        $stmt = $db->prepare("SELECT is_enabled, settings FROM system_integrations WHERE integration = ?");
        $stmt->execute([$integration]);
        $row = $stmt->fetch();
        
        if ($row) {
            return [
                'is_enabled' => (bool)$row['is_enabled'],
                'settings' => $row['settings'] ? json_decode($row['settings'], true) : []
            ];
        } else {
            // Create default entry if not exists
            $stmt = $db->prepare("INSERT INTO system_integrations (integration, is_enabled, settings) VALUES (?, 0, '{}')");
            $stmt->execute([$integration]);
            
            return ['is_enabled' => false, 'settings' => []];
        }
    } catch (Exception $e) {
        error_log('getIntegrationSettings error: ' . $e->getMessage());
        return ['is_enabled' => false, 'settings' => []];
    }
}

function saveIntegrationSettings($integration, $enabled, $settings) {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        $stmt = $db->prepare("
            INSERT INTO system_integrations (integration, is_enabled, settings, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON DUPLICATE KEY UPDATE 
            is_enabled = VALUES(is_enabled), 
            settings = VALUES(settings),
            updated_at = VALUES(updated_at)
        ");
        return $stmt->execute([$integration, $enabled ? 1 : 0, json_encode($settings)]);
    } catch (Exception $e) {
        error_log('saveIntegrationSettings error: ' . $e->getMessage());
        return false;
    }
}

function validateVoucherCode($code) {
    // Validate format: XXXX-XXXX-XXXX
    return preg_match('/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/', $code);
}

function rateLimitCheck($key, $maxAttempts = 5, $timeWindow = 300) {
    $cacheFile = __DIR__ . '/../cache/rate_limit_' . md5($key) . '.json';
    $cacheDir = dirname($cacheFile);
    
    if (!is_dir($cacheDir)) {
        mkdir($cacheDir, 0755, true);
    }
    
    $now = time();
    $attempts = [];
    
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        $attempts = $data['attempts'] ?? [];
    }
    
    // Remove old attempts outside time window
    $attempts = array_filter($attempts, function($timestamp) use ($now, $timeWindow) {
        return ($now - $timestamp) < $timeWindow;
    });
    
    if (count($attempts) >= $maxAttempts) {
        return false; // Rate limit exceeded
    }
    
    // Add current attempt
    $attempts[] = $now;
    
    // Save to cache
    file_put_contents($cacheFile, json_encode(['attempts' => $attempts]));
    
    return true;
}

function clearRateLimit($key) {
    $cacheFile = __DIR__ . '/../cache/rate_limit_' . md5($key) . '.json';
    if (file_exists($cacheFile)) {
        unlink($cacheFile);
    }
}

function getSystemStats() {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        $stats = [];
        
        // User stats
        $stmt = $db->prepare("SELECT COUNT(*) as total, SUM(is_active) as active FROM users");
        $stmt->execute();
        $stats['users'] = $stmt->fetch();
        
        // Voucher stats
        $stmt = $db->prepare("
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN is_redeemed = 0 AND is_active = 1 THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN is_redeemed = 1 THEN 1 ELSE 0 END) as redeemed,
                SUM(CASE WHEN is_redeemed = 0 AND is_active = 1 THEN price ELSE 0 END) as active_value,
                SUM(CASE WHEN is_redeemed = 1 THEN price ELSE 0 END) as redeemed_value
            FROM vouchers WHERE is_active = 1
        ");
        $stmt->execute();
        $stats['vouchers'] = $stmt->fetch();
        
        // Integration status
        $stmt = $db->prepare("SELECT integration, is_enabled, last_sync FROM system_integrations");
        $stmt->execute();
        $integrations = $stmt->fetchAll();
        $stats['integrations'] = [];
        foreach ($integrations as $integration) {
            $stats['integrations'][$integration['integration']] = [
                'enabled' => (bool)$integration['is_enabled'],
                'last_sync' => $integration['last_sync']
            ];
        }
        
        return $stats;
    } catch (Exception $e) {
        error_log('getSystemStats error: ' . $e->getMessage());
        return [];
    }
}

// Debug function for OIDC
function debugOIDCSettings() {
    try {
        $database = new Database();
        $db = $database->getConnection();
        
        $stmt = $db->prepare("SELECT * FROM system_integrations WHERE integration = 'openid_connect'");
        $stmt->execute();
        $result = $stmt->fetch();
        
        error_log("OIDC Debug - Raw DB result: " . json_encode($result));
        
        if ($result) {
            $settings = json_decode($result['settings'], true);
            error_log("OIDC Debug - Parsed settings: " . json_encode($settings));
            error_log("OIDC Debug - is_enabled: " . $result['is_enabled']);
        } else {
            error_log("OIDC Debug - No database entry found");
        }
        
        return $result;
    } catch (Exception $e) {
        error_log("OIDC Debug error: " . $e->getMessage());
        return null;
    }
}
?>
