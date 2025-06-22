<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

define('CONFIG_ACCESS', true);
require_once __DIR__ . '/../config/app_config.php';
require_once __DIR__ . '/../includes/Auth.php';
require_once __DIR__ . '/../includes/VoucherManager.php';
require_once __DIR__ . '/../includes/PretixService.php';
require_once __DIR__ . '/../includes/OIDCService.php';
require_once __DIR__ . '/../includes/functions.php';

class APIRouter {
    private $auth;
    private $voucherManager;
    private $pretixService;
    private $oidcService;
    
    public function __construct() {
        $this->auth = new Auth();
        $this->voucherManager = new VoucherManager();
        $this->pretixService = new PretixService();
        $this->oidcService = new OIDCService();
    }
    
    public function route() {
        $method = $_SERVER['REQUEST_METHOD'];
        
        // Pasrse the request URI to get the path segments
        $requestUri = $_SERVER['REQUEST_URI'];
        $path = parse_url($requestUri, PHP_URL_PATH);
        
        // Remove leading '/api/' and trailing slashes
        $path = preg_replace('#^/+api/?#', '', $path);
        $path = trim($path, '/');
        $segments = $path ? explode('/', $path) : [];
        
        // Debugging information
        if (!$this->isProduction()) {
            error_log("API Debug - URI: $requestUri, Path: $path, Segments: " . json_encode($segments));
        }
        
        try {
            $endpoint = $segments[0] ?? '';
            
            // Debug endpoint
            if ($endpoint === 'debug') {
                return $this->success([
                    'method' => $method,
                    'original_uri' => $requestUri,
                    'parsed_path' => $path,
                    'segments' => $segments,
                    'endpoint' => $endpoint,
                    'available_endpoints' => ['vouchers', 'users', 'scan', 'redeem', 'stats', 'integrations', 'config', 'audit', 'export']
                ]);
            }
            
            switch ($endpoint) {
                case 'vouchers':
                    return $this->handleVouchers($method, array_slice($segments, 1));
                case 'users':
                    return $this->handleUsers($method, array_slice($segments, 1));
                case 'scan':
                    return $this->handleScan($method, array_slice($segments, 1));
                case 'redeem':
                    return $this->handleRedeem($method, array_slice($segments, 1));
                case 'stats':
                    return $this->handleStats($method, array_slice($segments, 1));
                case 'integrations':
                    return $this->handleIntegrations($method, array_slice($segments, 1));
                case 'config':
                    return $this->handleConfig($method, array_slice($segments, 1));
                case 'audit':
                    return $this->handleAudit($method, array_slice($segments, 1));
                case 'export':
                    return $this->handleExport($method, array_slice($segments, 1));
                case '':
                    return $this->success(['message' => 'API is working', 'version' => '1.0']);
                default:
                    return $this->error("Endpoint '$endpoint' not found. Available: vouchers, users, scan, redeem, stats, integrations, config, audit, export", 404);
            }
        } catch (Exception $e) {
            error_log('API Error: ' . $e->getMessage());
            return $this->error('Internal server error: ' . $e->getMessage(), 500);
        }
    }
    
    private function isProduction() {
        return ($_ENV['APP_ENV'] ?? 'development') === 'production';
    }
    
    private function handleVouchers($method, $segments) {
        switch ($method) {
            case 'GET':
                if (empty($segments)) {
                    $this->requirePermission(['create_vouchers', 'edit_vouchers', 'view_own_vouchers']);
                    $filters = $_GET;
                    $limit = min(intval($_GET['limit'] ?? 50), 1000);
                    $offset = intval($_GET['offset'] ?? 0);
                    
                    // If user can only view own vouchers, filter by user_id
                    if (!$this->auth->hasPermission('create_vouchers') && !$this->auth->hasPermission('edit_vouchers')) {
                        $filters['user_id'] = $this->auth->getCurrentUserId();
                    }
                    
                    $vouchers = $this->voucherManager->getAllVouchers($filters, $limit, $offset);
                    return $this->success($vouchers);
                } else {
                    $code = $segments[0];
                    if (!validateVoucherCode($code)) {
                        return $this->error('Invalid voucher code format', 400);
                    }
                    
                    $voucher = $this->getVoucherByCode($code);
                    if (!$voucher) {
                        return $this->error('Voucher not found', 404);
                    }
                    
                    return $this->success($voucher);
                }
                
            case 'POST':
                $this->requirePermission('create_vouchers');
                $data = $this->getJsonInput();
                
                if (isset($data['bulk']) && $data['bulk']) {
                    return $this->createBulkVouchers($data);
                } else {
                    return $this->createSingleVoucher($data);
                }
                
            case 'PUT':
                $this->requirePermission('edit_vouchers');
                if (empty($segments)) {
                    return $this->error('Voucher ID required', 400);
                }
                
                $voucherId = intval($segments[0]);
                $data = $this->getJsonInput();
                
                $result = $this->voucherManager->updateVoucher($voucherId, $data);
                return $result ? $this->success(['message' => 'Voucher updated']) : $this->error('Update failed', 400);
                
            case 'DELETE':
                $this->requirePermission('delete_vouchers');
                if (empty($segments)) {
                    return $this->error('Voucher ID required', 400);
                }
                
                $voucherId = intval($segments[0]);
                $result = $this->voucherManager->deleteVoucher($voucherId);
                return $result ? $this->success(['message' => 'Voucher deleted']) : $this->error('Delete failed', 400);
                
            default:
                return $this->error('Method not allowed', 405);
        }
    }
    
    private function handleUsers($method, $segments) {
        $this->requirePermission('manage_users');
        
        switch ($method) {
            case 'GET':
                if (empty($segments)) {
                    $users = $this->auth->getAllUsers();
                    return $this->success($users);
                } else {
                    $userId = intval($segments[0]);
                    $user = $this->getUserById($userId);
                    return $user ? $this->success($user) : $this->error('User not found', 404);
                }
                
            case 'POST':
                $data = $this->getJsonInput();
                $result = $this->auth->createUser($data);
                return $result['success'] ? $this->success($result) : $this->error($result['message'], 400);
                
            case 'PUT':
                if (empty($segments)) {
                    return $this->error('User ID required', 400);
                }
                
                $userId = intval($segments[0]);
                $data = $this->getJsonInput();
                $result = $this->auth->updateUser($userId, $data);
                return $result['success'] ? $this->success($result) : $this->error($result['message'], 400);
                
            default:
                return $this->error('Method not allowed', 405);
        }
    }
    
    private function handleScan($method, $segments) {
        $this->requirePermission('scan_vouchers');
        
        if ($method !== 'POST') {
            return $this->error('Method not allowed', 405);
        }
        
        $data = $this->getJsonInput();
        $voucherCode = $data['code'] ?? '';
        
        if (!validateVoucherCode($voucherCode)) {
            return $this->error('Invalid voucher code format', 400);
        }
        
        $voucher = $this->getVoucherByCode($voucherCode);
        if (!$voucher) {
            return $this->error('Voucher not found', 404);
        }
        
        if ($voucher['is_redeemed']) {
            return $this->success([
                'voucher' => $voucher,
                'status' => 'already_redeemed',
                'message' => 'Voucher already redeemed on ' . formatDate($voucher['redeemed_at'])
            ]);
        }
        
        if (!$voucher['is_active'] || !$voucher['user_is_active'] || !$voucher['type_is_active']) {
            return $this->error('Voucher is not valid', 400);
        }
        
        return $this->success([
            'voucher' => $voucher,
            'status' => 'valid',
            'message' => 'Voucher is valid and ready for redemption'
        ]);
    }
    
    private function handleRedeem($method, $segments) {
        $this->requirePermission('redeem_vouchers');
        
        switch ($method) {
            case 'POST':
                $data = $this->getJsonInput();
                $voucherCode = $data['code'] ?? '';
                
                if (!validateVoucherCode($voucherCode)) {
                    return $this->error('Invalid voucher code format', 400);
                }
                
                $result = $this->voucherManager->redeemVoucher($voucherCode, $this->auth->getCurrentUserId());
                
                if ($result) {
                    $voucher = $this->getVoucherByCode($voucherCode);
                    return $this->success([
                        'voucher' => $voucher,
                        'message' => 'Voucher redeemed successfully'
                    ]);
                } else {
                    return $this->error('Redemption failed', 400);
                }
                
            case 'DELETE':
                $this->requirePermission('undo_redemption');
                $data = $this->getJsonInput();
                $voucherCode = $data['code'] ?? '';
                
                if (!validateVoucherCode($voucherCode)) {
                    return $this->error('Invalid voucher code format', 400);
                }
                
                $result = $this->voucherManager->undoRedemption($voucherCode, $this->auth->getCurrentUserId());
                
                if ($result) {
                    $voucher = $this->getVoucherByCode($voucherCode);
                    return $this->success([
                        'voucher' => $voucher,
                        'message' => 'Redemption undone successfully'
                    ]);
                } else {
                    return $this->error('Undo failed', 400);
                }
                
            default:
                return $this->error('Method not allowed', 405);
        }
    }
    
    private function handleStats($method, $segments) {
        if ($method !== 'GET') {
            return $this->error('Method not allowed', 405);
        }
        
        $userId = null;
        if (!$this->auth->hasPermission('view_all_stats')) {
            $userId = $this->auth->getCurrentUserId();
        }
        
        $stats = $this->voucherManager->getVoucherStats($userId);
        $systemStats = $this->auth->hasPermission('view_all_stats') ? getSystemStats() : null;
        
        return $this->success([
            'voucher_stats' => $stats,
            'system_stats' => $systemStats
        ]);
    }
    
    private function handleIntegrations($method, $segments) {
        $this->requirePermission('configure_system');
        
        switch ($method) {
            case 'GET':
                if (empty($segments)) {
                    $oidc = getIntegrationSettings('openid_connect');
                    $pretix = getIntegrationSettings('pretix');
                    
                    return $this->success([
                        'openid_connect' => [
                            'enabled' => $oidc['is_enabled'],
                            'configured' => !empty($oidc['settings']['issuer']),
                            'settings' => $oidc['settings']
                        ],
                        'pretix' => [
                            'enabled' => $pretix['is_enabled'],
                            'configured' => !empty($pretix['settings']['api_token']),
                            'settings' => $pretix['settings']
                        ]
                    ]);
                } else {
                    $integration = $segments[0];
                    if ($integration === 'pretix') {
                        if (isset($segments[1]) && $segments[1] === 'test') {
                            $result = $this->pretixService->testConnection();
                            return $this->success($result);
                        } elseif (isset($segments[1]) && $segments[1] === 'sync' && $_SERVER['REQUEST_METHOD'] === 'POST') {
                            $result = $this->pretixService->syncVouchers();
                            return $this->success($result);
                        }
                    } elseif ($integration === 'oidc') {
                        if (isset($segments[1]) && $segments[1] === 'test') {
                            $result = $this->oidcService->testConnection();
                            return $this->success($result);
                        }
                    }
                }
                break;
                
            case 'PUT':
                if (!empty($segments)) {
                    $integration = $segments[0];
                    $data = $this->getJsonInput();
                    
                    $result = saveIntegrationSettings(
                        $integration,
                        $data['enabled'] ?? false,
                        $data['settings'] ?? []
                    );
                    
                    return $result ? $this->success(['message' => 'Settings saved']) : $this->error('Failed to save settings', 400);
                }
                break;
        }
        
        return $this->error('Invalid integration endpoint', 400);
    }
    
    private function handleConfig($method, $segments) {
        $this->requirePermission('configure_system');
        
        if ($method === 'GET') {
            $config = [
                'app_name' => getAppName(),
                'company_name' => getCompanyName(),
                'roles' => getRolesConfig(),
                'voucher_types' => $this->getVoucherTypes()
            ];
            return $this->success($config);
        }
        
        return $this->error('Method not allowed', 405);
    }
    
    private function handleAudit($method, $segments) {
        $this->requirePermission('view_audit_logs');
        
        if ($method !== 'GET') {
            return $this->error('Method not allowed', 405);
        }
        
        $filters = $_GET;
        $limit = min(intval($_GET['limit'] ?? 100), 1000);
        $offset = intval($_GET['offset'] ?? 0);
        
        $auditLogger = new AuditLogger($this->getDatabase());
        $logs = $auditLogger->getAuditLogs($limit, $offset, $filters);
        
        return $this->success($logs);
    }
    
    private function handleExport($method, $segments) {
        $this->requirePermission('export_data');
        
        if ($method !== 'GET') {
            return $this->error('Method not allowed', 405);
        }
        
        $type = $segments[0] ?? 'vouchers';
        $format = $_GET['format'] ?? 'csv';
        
        switch ($type) {
            case 'vouchers':
                $filters = $_GET;
                unset($filters['format']);
                
                $data = $this->voucherManager->exportVouchers($filters, $format);
                
                if ($format === 'csv') {
                    header('Content-Type: text/csv');
                    header('Content-Disposition: attachment; filename="vouchers_' . date('Y-m-d') . '.csv"');
                    echo $data;
                    exit;
                } else {
                    return $this->success(['data' => $data]);
                }
                break;
                
            default:
                return $this->error('Invalid export type', 400);
        }
    }
    
    private function createSingleVoucher($data) {
        $required = ['user_id', 'type'];
        foreach ($required as $field) {
            if (!isset($data[$field])) {
                return $this->error("Missing required field: $field", 400);
            }
        }
        
        $voucherCode = $this->voucherManager->createVoucher(
            $data['user_id'],
            $data['type'],
            $data['price'] ?? 0.00,
            $data['tax_rate'] ?? 19.00,
            $data['metadata'] ?? []
        );
        
        if ($voucherCode) {
            $voucher = $this->getVoucherByCode($voucherCode);
            return $this->success(['voucher' => $voucher, 'message' => 'Voucher created successfully']);
        } else {
            return $this->error('Voucher creation failed', 400);
        }
    }
    
    private function createBulkVouchers($data) {
        $required = ['user_ids', 'type'];
        foreach ($required as $field) {
            if (!isset($data[$field])) {
                return $this->error("Missing required field: $field", 400);
            }
        }
        
        if (!is_array($data['user_ids']) || empty($data['user_ids'])) {
            return $this->error('user_ids must be a non-empty array', 400);
        }
        
        $result = $this->voucherManager->createBulkVouchers(
            $data['user_ids'],
            $data['type'],
            $data['price'] ?? 0.00,
            $data['tax_rate'] ?? 19.00,
            $data['metadata'] ?? []
        );
        
        return $this->success($result);
    }
    
    private function getVoucherByCode($code) {
        try {
            $database = new Database();
            $db = $database->getConnection();
            
            $stmt = $db->prepare("
                SELECT v.*, u.username, u.is_active as user_is_active,
                       vt.name as type_name, vt.icon as type_icon, vt.is_active as type_is_active,
                       rb.username as redeemed_by_username
                FROM vouchers v
                LEFT JOIN users u ON v.user_id = u.id
                LEFT JOIN voucher_types vt ON v.type = vt.type_key
                LEFT JOIN users rb ON v.redeemed_by = rb.id
                WHERE v.voucher_code = ?
            ");
            $stmt->execute([$code]);
            return $stmt->fetch();
        } catch (Exception $e) {
            error_log('getVoucherByCode error: ' . $e->getMessage());
            return null;
        }
    }
    
    private function getUserById($userId) {
        try {
            $database = new Database();
            $db = $database->getConnection();
            
            $stmt = $db->prepare("
                SELECT u.*, GROUP_CONCAT(ur.role) as roles
                FROM users u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                WHERE u.id = ?
                GROUP BY u.id
            ");
            $stmt->execute([$userId]);
            return $stmt->fetch();
        } catch (Exception $e) {
            error_log('getUserById error: ' . $e->getMessage());
            return null;
        }
    }
    
    private function getVoucherTypes() {
        try {
            $database = new Database();
            $db = $database->getConnection();
            
            $stmt = $db->prepare("SELECT * FROM voucher_types WHERE is_active = 1 ORDER BY name");
            $stmt->execute();
            return $stmt->fetchAll();
        } catch (Exception $e) {
            error_log('getVoucherTypes error: ' . $e->getMessage());
            return [];
        }
    }
    
    private function getDatabase() {
        $database = new Database();
        return $database->getConnection();
    }
    
    private function requirePermission($permissions) {
        if (!$this->auth->isLoggedIn()) {
            http_response_code(401);
            echo json_encode(['success' => false, 'error' => 'Authentication required']);
            exit;
        }
        
        if (is_string($permissions)) {
            $permissions = [$permissions];
        }
        
        foreach ($permissions as $permission) {
            if ($this->auth->hasPermission($permission)) {
                return true;
            }
        }
        
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Insufficient permissions']);
        exit;
    }
    
    private function getJsonInput() {
        $input = file_get_contents('php://input');
        $data = json_decode($input, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid JSON']);
            exit;
        }
        
        return $data ?? [];
    }
    
    private function success($data, $statusCode = 200) {
        http_response_code($statusCode);
        echo json_encode(['success' => true, 'data' => $data]);
        exit;
    }
    
    private function error($message, $statusCode = 400) {
        http_response_code($statusCode);
        echo json_encode(['success' => false, 'error' => $message]);
        exit;
    }
}

// Rate limiting
$clientIP = getClientIP();
if (!rateLimitCheck("api_$clientIP", 100, 60)) {
    http_response_code(429);
    echo json_encode(['success' => false, 'error' => 'Rate limit exceeded']);
    exit;
}

// Initialize and route
$router = new APIRouter();
$router->route();
?>
