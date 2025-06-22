<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

class AuditLogger {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    public function log($userId, $action, $resourceType = null, $resourceId = null, $oldValues = null, $newValues = null) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO audit_logs (user_id, action, resource_type, resource_id, old_values, new_values, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $userId,
                $action,
                $resourceType,
                $resourceId,
                $oldValues ? json_encode($oldValues) : null,
                $newValues ? json_encode($newValues) : null,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
            
            return true;
        } catch (Exception $e) {
            error_log('Audit log error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function getAuditLogs($limit = 100, $offset = 0, $filters = []) {
        try {
            $sql = "
                SELECT al.*, u.username 
                FROM audit_logs al 
                LEFT JOIN users u ON al.user_id = u.id 
                WHERE 1=1
            ";
            $params = [];
            
            if (!empty($filters['user_id'])) {
                $sql .= " AND al.user_id = ?";
                $params[] = $filters['user_id'];
            }
            
            if (!empty($filters['action'])) {
                $sql .= " AND al.action = ?";
                $params[] = $filters['action'];
            }
            
            if (!empty($filters['resource_type'])) {
                $sql .= " AND al.resource_type = ?";
                $params[] = $filters['resource_type'];
            }
            
            if (!empty($filters['date_from'])) {
                $sql .= " AND al.created_at >= ?";
                $params[] = $filters['date_from'];
            }
            
            if (!empty($filters['date_to'])) {
                $sql .= " AND al.created_at <= ?";
                $params[] = $filters['date_to'];
            }
            
            $sql .= " ORDER BY al.created_at DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;
            
            $stmt = $this->db->prepare($sql);
            $stmt->execute($params);
            
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('Get audit logs error: ' . $e->getMessage());
            return [];
        }
    }
}
?>
