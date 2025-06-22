<?php
define('CONFIG_ACCESS', true);
require_once 'config/app_config.php';

// Log webhook requests for debugging
error_log('Pretix webhook received: ' . file_get_contents('php://input'));

$pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4", DB_USER, DB_PASS);

// Webhook von Pretix empfangen
$input = file_get_contents('php://input');
$data = json_decode($input, true);

if (!$data) {
    http_response_code(400);
    exit('Invalid JSON');
}

try {
    switch ($data['action']) {
        case 'pretix.event.voucher.redeemed':
            // Voucher to be redeemed in Pretix
            $voucherCode = $data['data']['code'];
            
            $stmt = $pdo->prepare("UPDATE vouchers SET is_redeemed = 1, redeemed_at = NOW() WHERE voucher_code = ? AND is_redeemed = 0");
            $result = $stmt->execute([$voucherCode]);
            
            if ($result && $stmt->rowCount() > 0) {
                error_log("Pretix webhook: Voucher $voucherCode marked as redeemed via Pretix");
            } else {
                error_log("Pretix webhook: Voucher $voucherCode not found or already redeemed");
            }
            break;
            
        case 'pretix.event.voucher.deleted':
            // Voucher deleted in Pretix
            $voucherCode = $data['data']['code'];
            
            $stmt = $pdo->prepare("UPDATE vouchers SET pretix_voucher_id = NULL, pretix_published = 0 WHERE voucher_code = ?");
            $result = $stmt->execute([$voucherCode]);
            
            error_log("Pretix webhook: Voucher $voucherCode unpublished from Pretix");
            break;
            
        case 'pretix.event.voucher.created':
            // Voucher created in Pretix
            $voucherCode = $data['data']['code'];
            $pretixId = $data['data']['id'];
            
            $stmt = $pdo->prepare("UPDATE vouchers SET pretix_voucher_id = ?, pretix_published = 1 WHERE voucher_code = ?");
            $result = $stmt->execute([$pretixId, $voucherCode]);
            
            error_log("Pretix webhook: Voucher $voucherCode linked to Pretix ID $pretixId");
            break;
            
        case 'pretix.event.voucher.changed':
            // Voucher changed in Pretix
            $voucherCode = $data['data']['code'];
            $pretixId = $data['data']['id'];
            
            // check if the voucher is redeemed
            if (isset($data['data']['redeemed']) && $data['data']['redeemed'] > 0) {
                $stmt = $pdo->prepare("UPDATE vouchers SET is_redeemed = 1, redeemed_at = NOW() WHERE voucher_code = ? AND is_redeemed = 0");
                $result = $stmt->execute([$voucherCode]);
                
                if ($result && $stmt->rowCount() > 0) {
                    error_log("Pretix webhook: Voucher $voucherCode marked as redeemed via changed event");
                }
            }
            break;
            
        default:
            error_log("Pretix webhook: Unknown action " . $data['action']);
            break;
    }
    
    http_response_code(200);
    echo 'OK';
    
} catch (Exception $e) {
    error_log('Pretix webhook error: ' . $e->getMessage());
    http_response_code(500);
    echo 'Error: ' . $e->getMessage();
}
?>
