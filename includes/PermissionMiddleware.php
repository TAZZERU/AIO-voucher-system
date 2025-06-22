<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

class PermissionMiddleware {
    private $auth;
    
    public function __construct($auth) {
        $this->auth = $auth;
    }
    
    public function check($requiredPermissions) {
        if (!$this->auth->isLoggedIn()) {
            $this->unauthorized('Not logged in');
            return false;
        }
        
        if (is_string($requiredPermissions)) {
            $requiredPermissions = [$requiredPermissions];
        }
        
        foreach ($requiredPermissions as $permission) {
            if (!$this->auth->hasPermission($permission)) {
                $this->forbidden("Missing permission: $permission");
                return false;
            }
        }
        
        return true;
    }
    
    public function checkAny($permissions) {
        if (!$this->auth->isLoggedIn()) {
            $this->unauthorized('Not logged in');
            return false;
        }
        
        foreach ($permissions as $permission) {
            if ($this->auth->hasPermission($permission)) {
                return true;
            }
        }
        
        $this->forbidden("Missing any of required permissions");
        return false;
    }
    
    private function unauthorized($message) {
        http_response_code(401);
        if ($this->isAjaxRequest()) {
            header('Content-Type: application/json');
            echo json_encode(['error' => $message, 'redirect' => '/login.php']);
        } else {
            header('Location: /login.php');
        }
        exit;
    }
    
    private function forbidden($message) {
        http_response_code(403);
        if ($this->isAjaxRequest()) {
            header('Content-Type: application/json');
            echo json_encode(['error' => $message]);
        } else {
            include __DIR__ . '/../pages/403.php';
        }
        exit;
    }
    
    private function isAjaxRequest() {
        return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && 
               strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
    }
}
?>
