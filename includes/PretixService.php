<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

class PretixService {
    private $config;
    private $baseUrl;
    private $headers;
    private $db;
    
    public function __construct() {
        $this->config = getPretixConfig();
        $this->baseUrl = rtrim($this->config['api_url'], '/');
        $this->headers = [
            'Authorization: Token ' . $this->config['api_token'],
            'Content-Type: application/json',
            'Accept: application/json'
        ];
        
        try {
            $database = new Database();
            $this->db = $database->getConnection();
        } catch (Exception $e) {
            error_log('PretixService database error: ' . $e->getMessage());
            $this->db = null;
        }
    }
    
    public function isEnabled() {
        return $this->config['enabled'] && !empty($this->config['api_token']);
    }
    
    public function testConnection() {
        if (!$this->isEnabled()) {
            return ['success' => false, 'message' => 'Pretix integration not enabled'];
        }
        
        try {
            $response = $this->makeRequest('GET', '/api/v1/organizers/');
            return [
                'success' => true, 
                'message' => 'Connection successful', 
                'organizers' => count($response['results'] ?? [])
            ];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Connection failed: ' . $e->getMessage()];
        }
    }
    
    public function getOrganizers() {
        if (!$this->isEnabled()) return [];
        
        try {
            $response = $this->makeRequest('GET', '/api/v1/organizers/');
            return $response['results'] ?? [];
        } catch (Exception $e) {
            error_log('Pretix get organizers error: ' . $e->getMessage());
            return [];
        }
    }
    
    public function getEvents($organizer = null) {
        if (!$this->isEnabled()) return [];
        
        $organizer = $organizer ?? $this->config['organizer'];
        if (!$organizer) return [];
        
        try {
            $response = $this->makeRequest('GET', "/api/v1/organizers/$organizer/events/");
            return $response['results'] ?? [];
        } catch (Exception $e) {
            error_log('Pretix get events error: ' . $e->getMessage());
            return [];
        }
    }
    
    public function createVoucher($voucherCode, $data = []) {
        if (!$this->isEnabled()) return false;
        
        $organizer = $this->config['organizer'];
        if (!$organizer) return false;
        
        $events = $this->getEvents($organizer);
        if (empty($events)) return false;
        
        $event = $events[0]['slug']; // Use first event
        
        $defaultData = [
            'code' => $voucherCode,
            'max_usages' => 1,
            'valid_until' => null,
            'block_quota' => false,
            'allow_ignore_quota' => false,
            'price_mode' => 'set',
            'value' => '0.00',
            'tag' => 'webapp',
            'comment' => 'Created via Voucher Management System'
        ];
        
        $voucherData = array_merge($defaultData, $data);
        
        try {
            $response = $this->makeRequest('POST', "/api/v1/organizers/$organizer/events/$event/vouchers/", $voucherData);
            
            // Update local database
            if ($this->db && isset($response['id'])) {
                $stmt = $this->db->prepare("
                    UPDATE vouchers 
                    SET pretix_voucher_id = ?, pretix_published = 1 
                    WHERE voucher_code = ?
                ");
                $stmt->execute([$response['id'], $voucherCode]);
            }
            
            return $response;
        } catch (Exception $e) {
            error_log('Pretix create voucher error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function getVoucher($voucherCode, $organizer = null, $event = null) {
        if (!$this->isEnabled()) return false;
        
        $organizer = $organizer ?? $this->config['organizer'];
        if (!$organizer) return false;
        
        if (!$event) {
            $events = $this->getEvents($organizer);
            if (empty($events)) return false;
            $event = $events[0]['slug'];
        }
        
        try {
            $response = $this->makeRequest('GET', "/api/v1/organizers/$organizer/events/$event/vouchers/$voucherCode/");
            return $response;
        } catch (Exception $e) {
            error_log('Pretix get voucher error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function redeemVoucher($voucherCode) {
        try {
            $voucher = $this->getVoucher($voucherCode);
            if ($voucher) {
                return $this->updateVoucher($voucherCode, [
                    'comment' => ($voucher['comment'] ?? '') . ' [REDEEMED via webapp at ' . date('Y-m-d H:i:s') . ']'
                ]);
            }
            return false;
        } catch (Exception $e) {
            error_log('Pretix redeem voucher error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function updateVoucher($voucherCode, $data, $organizer = null, $event = null) {
        if (!$this->isEnabled()) return false;
        
        $organizer = $organizer ?? $this->config['organizer'];
        if (!$organizer) return false;
        
        if (!$event) {
            $events = $this->getEvents($organizer);
            if (empty($events)) return false;
            $event = $events[0]['slug'];
        }
        
        try {
            $response = $this->makeRequest('PATCH', "/api/v1/organizers/$organizer/events/$event/vouchers/$voucherCode/", $data);
            return $response;
        } catch (Exception $e) {
            error_log('Pretix update voucher error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function syncVouchers() {
        if (!$this->isEnabled() || !$this->db) {
            return ['success' => false, 'message' => 'Pretix not enabled or database error'];
        }
        
        try {
            $organizer = $this->config['organizer'];
            $events = $this->getEvents($organizer);
            
            $syncedCount = 0;
            $errors = [];
            
            foreach ($events as $event) {
                try {
                    $vouchers = $this->makeRequest('GET', "/api/v1/organizers/$organizer/events/{$event['slug']}/vouchers/");
                    
                    foreach ($vouchers['results'] ?? [] as $pretixVoucher) {
                        // Update local voucher if exists
                        $stmt = $this->db->prepare("
                            UPDATE vouchers 
                            SET pretix_voucher_id = ?, pretix_published = 1, updated_at = CURRENT_TIMESTAMP
                            WHERE voucher_code = ?
                        ");
                        $stmt->execute([$pretixVoucher['id'], $pretixVoucher['code']]);
                        
                        if ($stmt->rowCount() > 0) {
                            $syncedCount++;
                        }
                    }
                } catch (Exception $e) {
                    $errors[] = "Event {$event['slug']}: " . $e->getMessage();
                }
            }
            
            // Update last sync time
            $stmt = $this->db->prepare("
                UPDATE system_integrations 
                SET last_sync = CURRENT_TIMESTAMP 
                WHERE integration = 'pretix'
            ");
            $stmt->execute();
            
            return [
                'success' => true,
                'synced' => $syncedCount,
                'errors' => $errors,
                'message' => "Synced $syncedCount vouchers" . (count($errors) > 0 ? " with " . count($errors) . " errors" : "")
            ];
            
        } catch (Exception $e) {
            error_log('Pretix sync error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Sync failed: ' . $e->getMessage()];
        }
    }
    
    public function handleWebhook($payload, $signature = null) {
        if (!$this->isEnabled()) return false;
        
        // Verify webhook signature if secret is configured
        if (!empty($this->config['webhook_secret']) && $signature) {
            $expectedSignature = 'sha256=' . hash_hmac('sha256', $payload, $this->config['webhook_secret']);
            if (!hash_equals($expectedSignature, $signature)) {
                error_log('Pretix webhook signature mismatch');
                return false;
            }
        }
        
        try {
            $data = json_decode($payload, true);
            
            if (!$data || !isset($data['action'])) {
                return false;
            }
            
            switch ($data['action']) {
                case 'pretix.event.order.paid':
                    return $this->handleOrderPaid($data);
                case 'pretix.event.voucher.redeemed':
                    return $this->handleVoucherRedeemed($data);
                case 'pretix.event.voucher.created':
                    return $this->handleVoucherCreated($data);
                default:
                    // Log unknown webhook action
                    error_log('Unknown Pretix webhook action: ' . $data['action']);
                    return true; // Return true to acknowledge receipt
            }
        } catch (Exception $e) {
            error_log('Pretix webhook error: ' . $e->getMessage());
            return false;
        }
    }
    
    private function handleOrderPaid($data) {
        try {
            if ($this->db) {
                $stmt = $this->db->prepare("
                    INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address) 
                    VALUES (NULL, 'pretix_order_paid', 'webhook', ?, ?, ?)
                ");
                $stmt->execute([
                    $data['order'] ?? null,
                    json_encode($data),
                    $_SERVER['REMOTE_ADDR'] ?? 'webhook'
                ]);
            }
            return true;
        } catch (Exception $e) {
            error_log('Handle order paid error: ' . $e->getMessage());
            return false;
        }
    }
    
    private function handleVoucherRedeemed($data) {
        try {
            if ($this->db) {
                $voucherCode = $data['voucher_code'] ?? null;
                if ($voucherCode) {
                    // Update local voucher status
                    $stmt = $this->db->prepare("
                        UPDATE vouchers 
                        SET is_redeemed = 1, redeemed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                        WHERE voucher_code = ? AND is_redeemed = 0
                    ");
                    $stmt->execute([$voucherCode]);
                }
                
                // Log the webhook
                $stmt = $this->db->prepare("
                    INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address) 
                    VALUES (NULL, 'pretix_voucher_redeemed', 'webhook', ?, ?, ?)
                ");
                $stmt->execute([
                    $voucherCode,
                    json_encode($data),
                    $_SERVER['REMOTE_ADDR'] ?? 'webhook'
                ]);
            }
            return true;
        } catch (Exception $e) {
            error_log('Handle voucher redeemed error: ' . $e->getMessage());
            return false;
        }
    }
    
    private function handleVoucherCreated($data) {
        try {
            if ($this->db) {
                $stmt = $this->db->prepare("
                    INSERT INTO audit_logs (user_id, action, resource_type, resource_id, new_values, ip_address) 
                    VALUES (NULL, 'pretix_voucher_created', 'webhook', ?, ?, ?)
                ");
                $stmt->execute([
                    $data['voucher_code'] ?? null,
                    json_encode($data),
                    $_SERVER['REMOTE_ADDR'] ?? 'webhook'
                ]);
            }
            return true;
        } catch (Exception $e) {
            error_log('Handle voucher created error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function getWebhookURL() {
        return rtrim($_SERVER['HTTP_HOST'] ?? 'localhost', '/') . '/api/webhook.php';
    }
    
    public function validateWebhookConfiguration() {
        if (!$this->isEnabled()) {
            return ['valid' => false, 'message' => 'Pretix not enabled'];
        }
        
        $issues = [];
        
        if (empty($this->config['organizer'])) {
            $issues[] = 'Organizer not configured';
        }
        
        if (empty($this->config['webhook_secret'])) {
            $issues[] = 'Webhook secret not configured (recommended for security)';
        }
        
        // Test if webhook URL is reachable
        $webhookURL = $this->getWebhookURL();
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'http://' . $webhookURL);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 0) {
            $issues[] = 'Webhook URL not reachable: ' . $webhookURL;
        }
        
        return [
            'valid' => empty($issues),
            'issues' => $issues,
            'webhook_url' => $webhookURL
        ];
    }
    
    private function makeRequest($method, $endpoint, $data = null) {
        $url = $this->baseUrl . $endpoint;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $this->headers);
        curl_setopt($ch, CURLOPT_USERAGENT, 'VoucherManagementSystem/1.0');
        
        switch (strtoupper($method)) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                if ($data) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                }
                break;
            case 'PATCH':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
                if ($data) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                }
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                if ($data) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
                }
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;
        }
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception("cURL error: $error");
        }
        
        if ($httpCode >= 400) {
            throw new Exception("HTTP error $httpCode: $response");
        }
        
        $decodedResponse = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Invalid JSON response: $response");
        }
        
        return $decodedResponse;
    }
    
    public function getStatistics() {
        if (!$this->isEnabled()) {
            return ['enabled' => false];
        }
        
        try {
            $organizers = $this->getOrganizers();
            $events = $this->getEvents();
            
            $stats = [
                'enabled' => true,
                'organizers_count' => count($organizers),
                'events_count' => count($events),
                'last_sync' => null
            ];
            
            if ($this->db) {
                $stmt = $this->db->prepare("SELECT last_sync FROM system_integrations WHERE integration = 'pretix'");
                $stmt->execute();
                $result = $stmt->fetch();
                $stats['last_sync'] = $result['last_sync'] ?? null;
            }
            
            return $stats;
        } catch (Exception $e) {
            return [
                'enabled' => true,
                'error' => $e->getMessage()
            ];
        }
    }
}
?>
