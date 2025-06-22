<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/AuditLogger.php';
require_once __DIR__ . '/PretixService.php';

class VoucherManager {
    private $db;
    private $auditLogger;
    private $pretixService;
    
    public function __construct() {
        try {
            $database = new Database();
            $this->db = $database->getConnection();
            $this->auditLogger = new AuditLogger($this->db);
            $this->pretixService = new PretixService();
        } catch (Exception $e) {
            error_log('VoucherManager initialization error: ' . $e->getMessage());
            $this->db = null;
        }
    }
    
    public function createVoucher($userId, $type, $price = 0.00, $taxRate = 19.00, $metadata = []) {
        if (!$this->db) {
            return false;
        }
        
        try {
            // Check if user is active
            $stmt = $this->db->prepare("SELECT is_active FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            
            if (!$user || !$user['is_active']) {
                return false;
            }
            
            // Generate unique voucher code
            $voucherCode = $this->generateVoucherCode();
            
            // Insert voucher
            $stmt = $this->db->prepare("
                INSERT INTO vouchers (user_id, voucher_code, type, price, tax_rate, metadata, is_active) 
                VALUES (?, ?, ?, ?, ?, ?, 1)
            ");
            
            $result = $stmt->execute([
                $userId, 
                $voucherCode, 
                $type, 
                $price, 
                $taxRate, 
                json_encode($metadata)
            ]);
            
            if ($result) {
                $voucherId = $this->db->lastInsertId();
                
                // Try to publish to Pretix if enabled
                $this->publishToPretix($voucherCode, $type, $price, $metadata);
                
                // Log audit
                $this->auditLogger->log(
                    $_SESSION['user_id'] ?? null, 
                    'voucher_created', 
                    'voucher', 
                    $voucherId, 
                    null, 
                    [
                        'voucher_code' => $voucherCode,
                        'user_id' => $userId,
                        'type' => $type,
                        'price' => $price
                    ]
                );
                
                return $voucherCode;
            }
            
            return false;
        } catch (Exception $e) {
            error_log('Voucher creation error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function createBulkVouchers($userIds, $type, $price = 0.00, $taxRate = 19.00, $metadata = []) {
        if (!$this->db) {
            return ['success' => false, 'message' => 'Database error'];
        }
        
        $createdVouchers = [];
        $errors = [];
        
        $this->db->beginTransaction();
        
        try {
            foreach ($userIds as $userId) {
                $voucherCode = $this->createVoucher($userId, $type, $price, $taxRate, $metadata);
                if ($voucherCode) {
                    $createdVouchers[] = $voucherCode;
                } else {
                    $errors[] = "Failed to create voucher for user ID: $userId";
                }
            }
            
            $this->db->commit();
            
            return [
                'success' => true,
                'created' => count($createdVouchers),
                'vouchers' => $createdVouchers,
                'errors' => $errors
            ];
            
        } catch (Exception $e) {
            $this->db->rollBack();
            error_log('Bulk voucher creation error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Bulk creation failed: ' . $e->getMessage()];
        }
    }
    
    public function redeemVoucher($voucherCode, $redeemedBy = null) {
        if (!$this->db) {
            return false;
        }
        
        try {
            // Get voucher details with validation
            $stmt = $this->db->prepare("
                SELECT v.*, u.is_active as user_is_active, vt.is_active as type_is_active 
                FROM vouchers v 
                LEFT JOIN users u ON v.user_id = u.id
                LEFT JOIN voucher_types vt ON v.type = vt.type_key
                WHERE v.voucher_code = ? AND v.is_redeemed = 0 AND v.is_active = 1
            ");
            $stmt->execute([$voucherCode]);
            $voucher = $stmt->fetch();
            
            if (!$voucher) {
                return false;
            }
            
            // Validate voucher can be redeemed
            if (!$voucher['user_is_active'] || !$voucher['type_is_active']) {
                return false;
            }
            
            $redeemedBy = $redeemedBy ?? ($_SESSION['user_id'] ?? null);
            
            // Redeem voucher
            $stmt = $this->db->prepare("
                UPDATE vouchers 
                SET is_redeemed = 1, redeemed_at = CURRENT_TIMESTAMP, redeemed_by = ? 
                WHERE voucher_code = ? AND is_redeemed = 0
            ");
            $result = $stmt->execute([$redeemedBy, $voucherCode]);
            
            if ($result && $stmt->rowCount() > 0) {
                // Sync with Pretix
                $this->pretixService->redeemVoucher($voucherCode);
                
                // Log audit
                $this->auditLogger->log(
                    $redeemedBy, 
                    'voucher_redeemed', 
                    'voucher', 
                    $voucher['id'], 
                    ['is_redeemed' => false], 
                    [
                        'is_redeemed' => true,
                        'voucher_code' => $voucherCode,
                        'redeemed_by' => $redeemedBy
                    ]
                );
                
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            error_log('Voucher redemption error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function undoRedemption($voucherCode, $undoneBy = null) {
        if (!$this->db) {
            return false;
        }
        
        try {
            $stmt = $this->db->prepare("SELECT * FROM vouchers WHERE voucher_code = ? AND is_redeemed = 1");
            $stmt->execute([$voucherCode]);
            $voucher = $stmt->fetch();
            
            if (!$voucher) {
                return false;
            }
            
            $undoneBy = $undoneBy ?? ($_SESSION['user_id'] ?? null);
            
            $stmt = $this->db->prepare("
                UPDATE vouchers 
                SET is_redeemed = 0, redeemed_at = NULL, redeemed_by = NULL 
                WHERE voucher_code = ? AND is_redeemed = 1
            ");
            $result = $stmt->execute([$voucherCode]);
            
            if ($result && $stmt->rowCount() > 0) {
                // Log audit
                $this->auditLogger->log(
                    $undoneBy, 
                    'voucher_redemption_undone', 
                    'voucher', 
                    $voucher['id'], 
                    ['is_redeemed' => true], 
                    [
                        'is_redeemed' => false,
                        'voucher_code' => $voucherCode,
                        'undone_by' => $undoneBy
                    ]
                );
                
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            error_log('Undo redemption error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function getUserVouchers($userId, $includeRedeemed = true) {
        if (!$this->db) {
            return [];
        }
        
        try {
            $sql = "
                SELECT v.*, vt.name as type_name, vt.icon as type_icon, vt.is_active as type_is_active,
                       rb.username as redeemed_by_username
                FROM vouchers v
                LEFT JOIN voucher_types vt ON v.type = vt.type_key
                LEFT JOIN users rb ON v.redeemed_by = rb.id
                WHERE v.user_id = ? AND v.is_active = 1
            ";
            
            if (!$includeRedeemed) {
                $sql .= " AND v.is_redeemed = 0";
            }
            
            $sql .= " ORDER BY v.created_at DESC";
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute([$userId]);
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('Get user vouchers error: ' . $e->getMessage());
            return [];
        }
    }
    
    public function getAllVouchers($filters = [], $limit = 50, $offset = 0) {
        if (!$this->db) {
            return [];
        }
        
        try {
            $sql = "
                SELECT v.*, u.username, vt.name as type_name, vt.icon as type_icon,
                       rb.username as redeemed_by_username
                FROM vouchers v
                LEFT JOIN users u ON v.user_id = u.id
                LEFT JOIN voucher_types vt ON v.type = vt.type_key
                LEFT JOIN users rb ON v.redeemed_by = rb.id
                WHERE 1=1
            ";
            $params = [];
            
            if (!empty($filters['user_id'])) {
                $sql .= " AND v.user_id = ?";
                $params[] = $filters['user_id'];
            }
            
            if (!empty($filters['type'])) {
                $sql .= " AND v.type = ?";
                $params[] = $filters['type'];
            }
            
            if (isset($filters['is_redeemed'])) {
                $sql .= " AND v.is_redeemed = ?";
                $params[] = $filters['is_redeemed'];
            }
            
            if (!empty($filters['date_from'])) {
                $sql .= " AND v.created_at >= ?";
                $params[] = $filters['date_from'];
            }
            
            if (!empty($filters['date_to'])) {
                $sql .= " AND v.created_at <= ?";
                $params[] = $filters['date_to'];
            }
            
            if (!empty($filters['search'])) {
                $sql .= " AND (v.voucher_code LIKE ? OR u.username LIKE ?)";
                $searchTerm = '%' . $filters['search'] . '%';
                $params[] = $searchTerm;
                $params[] = $searchTerm;
            }
            
            $sql .= " ORDER BY v.created_at DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('Get all vouchers error: ' . $e->getMessage());
            return [];
        }
    }
    
    public function getVoucherStats($userId = null) {
        if (!$this->db) {
            return [];
        }
        
        try {
            $sql = "
                SELECT 
                    COUNT(*) as total_vouchers,
                    SUM(CASE WHEN is_redeemed = 0 AND is_active = 1 THEN 1 ELSE 0 END) as active_vouchers,
                    SUM(CASE WHEN is_redeemed = 1 THEN 1 ELSE 0 END) as redeemed_vouchers,
                    SUM(CASE WHEN is_redeemed = 0 AND is_active = 1 THEN price ELSE 0 END) as active_value,
                    SUM(CASE WHEN is_redeemed = 1 THEN price ELSE 0 END) as redeemed_value,
                    AVG(price) as average_value
                FROM vouchers 
                WHERE is_active = 1
            ";
            $params = [];
            
            if ($userId) {
                $sql .= " AND user_id = ?";
                $params[] = $userId;
            }
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            return $stmt->fetch();
        } catch (Exception $e) {
            error_log('Get voucher stats error: ' . $e->getMessage());
            return [];
        }
    }
    
    public function updateVoucher($voucherId, $data) {
        if (!$this->db) {
            return false;
        }
        
        try {
            // Get old values for audit
            $stmt = $this->db->prepare("SELECT * FROM vouchers WHERE id = ?");
            $stmt->execute([$voucherId]);
            $oldVoucher = $stmt->fetch();
            
            if (!$oldVoucher) {
                return false;
            }
            
            $updateFields = [];
            $params = [];
            
            if (isset($data['type'])) {
                $updateFields[] = "type = ?";
                $params[] = $data['type'];
            }
            
            if (isset($data['price'])) {
                $updateFields[] = "price = ?";
                $params[] = $data['price'];
            }
            
            if (isset($data['tax_rate'])) {
                $updateFields[] = "tax_rate = ?";
                $params[] = $data['tax_rate'];
            }
            
            if (isset($data['is_active'])) {
                $updateFields[] = "is_active = ?";
                $params[] = $data['is_active'];
            }
            
            if (isset($data['metadata'])) {
                $updateFields[] = "metadata = ?";
                $params[] = json_encode($data['metadata']);
            }
            
            if (empty($updateFields)) {
                return false;
            }
            
            $updateFields[] = "updated_at = CURRENT_TIMESTAMP";
            $params[] = $voucherId;
            
            $sql = "UPDATE vouchers SET " . implode(', ', $updateFields) . " WHERE id = ?";
            $stmt = $this->db->prepare($sql);
            $result = $stmt->execute($params);
            
            if ($result) {
                $this->auditLogger->log(
                    $_SESSION['user_id'] ?? null, 
                    'voucher_updated', 
                    'voucher', 
                    $voucherId, 
                    $oldVoucher, 
                    $data
                );
            }
            
            return $result;
        } catch (Exception $e) {
            error_log('Update voucher error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function deleteVoucher($voucherId) {
        if (!$this->db) {
            return false;
        }
        
        try {
            $stmt = $this->db->prepare("SELECT * FROM vouchers WHERE id = ?");
            $stmt->execute([$voucherId]);
            $voucher = $stmt->fetch();
            
            if (!$voucher) {
                return false;
            }
            
            // Soft delete
            $stmt = $this->db->prepare("UPDATE vouchers SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
            $result = $stmt->execute([$voucherId]);
            
            if ($result) {
                $this->auditLogger->log(
                    $_SESSION['user_id'] ?? null, 
                    'voucher_deleted', 
                    'voucher', 
                    $voucherId, 
                    $voucher, 
                    ['is_active' => false]
                );
            }
            
            return $result;
        } catch (Exception $e) {
            error_log('Delete voucher error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function generateVoucherCode() {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $codeLength = 12;
        
        do {
            $code = '';
            for ($i = 0; $i < $codeLength; $i++) {
                $code .= $characters[random_int(0, strlen($characters) - 1)];
            }
            
            $formattedCode = substr($code, 0, 4) . '-' . substr($code, 4, 4) . '-' . substr($code, 8, 4);
            
            if ($this->db) {
                $stmt = $this->db->prepare("SELECT id FROM vouchers WHERE voucher_code = ?");
                $stmt->execute([$formattedCode]);
                $exists = $stmt->fetch();
            } else {
                $exists = false;
            }
            
        } while ($exists);
        
        return $formattedCode;
    }
    
    private function publishToPretix($voucherCode, $type, $price, $metadata) {
        try {
            $pretixConfig = getPretixConfig();
            if ($pretixConfig['enabled']) {
                $result = $this->pretixService->createVoucher($voucherCode, [
                    'code' => $voucherCode,
                    'max_usages' => 1,
                    'price_mode' => 'set',
                    'value' => $price,
                    'tag' => 'webapp_' . $type,
                    'comment' => 'Created via Voucher Management System'
                ]);
                
                if ($result) {
                    $stmt = $this->db->prepare("UPDATE vouchers SET pretix_published = 1, pretix_voucher_id = ? WHERE voucher_code = ?");
                    $stmt->execute([$result['id'] ?? null, $voucherCode]);
                }
            }
        } catch (Exception $e) {
            error_log('Pretix publish error: ' . $e->getMessage());
        }
    }
    
    public function exportVouchers($filters = [], $format = 'csv') {
        $vouchers = $this->getAllVouchers($filters, 10000, 0);
        
        if ($format === 'csv') {
            return $this->exportToCSV($vouchers);
        } elseif ($format === 'json') {
            return json_encode($vouchers, JSON_PRETTY_PRINT);
        }
        
        return false;
    }
    
    private function exportToCSV($vouchers) {
        $output = fopen('php://temp', 'r+');
        
        // Headers
        fputcsv($output, [
            'Voucher Code', 'Username', 'Type', 'Price', 'Tax Rate', 
            'Is Active', 'Is Redeemed', 'Created At', 'Redeemed At', 'Redeemed By'
        ]);
        
        foreach ($vouchers as $voucher) {
            fputcsv($output, [
                $voucher['voucher_code'],
                $voucher['username'],
                $voucher['type_name'] ?? $voucher['type'],
                $voucher['price'],
                $voucher['tax_rate'],
                $voucher['is_active'] ? 'Yes' : 'No',
                $voucher['is_redeemed'] ? 'Yes' : 'No',
                $voucher['created_at'],
                $voucher['redeemed_at'],
                $voucher['redeemed_by_username']
            ]);
        }
        
        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);
        
        return $csv;
    }
}
?>
