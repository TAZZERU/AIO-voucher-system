<?php
define('CONFIG_ACCESS', true);
require_once __DIR__ . '/../config/app_config.php';
require_once __DIR__ . '/../includes/PretixService.php';
require_once __DIR__ . '/../includes/functions.php';

header('Content-Type: application/json');

// Rate limiting for webhooks
$clientIP = getClientIP();
if (!rateLimitCheck("webhook_$clientIP", 50, 60)) {
    http_response_code(429);
    echo json_encode(['error' => 'Rate limit exceeded']);
    exit;
}

try {
    $payload = file_get_contents('php://input');
    $signature = $_SERVER['HTTP_X_PRETIX_SIGNATURE'] ?? null;
    
    if (empty($payload)) {
        http_response_code(400);
        echo json_encode(['error' => 'Empty payload']);
        exit;
    }
    
    $pretixService = new PretixService();
    
    if (!$pretixService->isEnabled()) {
        http_response_code(503);
        echo json_encode(['error' => 'Pretix integration disabled']);
        exit;
    }
    
    $result = $pretixService->handleWebhook($payload, $signature);
    
    if ($result) {
        logActivity('Pretix webhook processed successfully', 'info', [
            'payload_size' => strlen($payload),
            'signature_provided' => !empty($signature)
        ]);
        
        http_response_code(200);
        echo json_encode(['success' => true, 'message' => 'Webhook processed']);
    } else {
        logActivity('Pretix webhook processing failed', 'warning', [
            'payload_size' => strlen($payload),
            'signature_provided' => !empty($signature)
        ]);
        
        http_response_code(400);
        echo json_encode(['error' => 'Webhook processing failed']);
    }
    
} catch (Exception $e) {
    error_log('Webhook error: ' . $e->getMessage());
    logActivity('Webhook error: ' . $e->getMessage(), 'error');
    
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}
?>
