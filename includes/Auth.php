<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/AuditLogger.php';

class Auth {
    private $db;
    private $currentUser = null;
    
    public function __construct() {
        try {
            $database = new Database();
            $this->db = $database->getConnection();
        } catch (Exception $e) {
            error_log('Auth database connection error: ' . $e->getMessage());
            throw new Exception('Database connection failed');
        }
    }
    
    public function login($username, $password) {
        try {
            // Rate limiting check
            $clientIP = getClientIP();
            if (!rateLimitCheck("login_$clientIP", 5, 300)) {
                return ['success' => false, 'message' => 'Too many login attempts. Please try again later.'];
            }
            
            // Find user
            $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ? AND is_active = 1");
            $stmt->execute([$username]);
            $user = $stmt->fetch();
            
            if (!$user || !password_verify($password, $user['password_hash'])) {
                // Log failed attempt
                $auditLogger = new AuditLogger($this->db);
                $auditLogger->log(null, 'login_failed', 'user', null, null, [
                    'username' => $username,
                    'ip_address' => $clientIP
                ]);
                
                return ['success' => false, 'message' => 'Invalid username or password'];
            }
            
            // Successful login
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['login_method'] = 'password';
            $_SESSION['login_time'] = time();
            
            // Update last login
            $stmt = $this->db->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([$user['id']]);
            
            // Clear rate limit
            clearRateLimit("login_$clientIP");
            
            // Log successful login
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($user['id'], 'user_login', 'user', $user['id'], null, [
                'username' => $username,
                'ip_address' => $clientIP
            ]);
            
            return ['success' => true, 'message' => 'Login successful'];
            
        } catch (Exception $e) {
            error_log('Login error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Login failed due to system error'];
        }
    }
    
public function loginWithOIDC($userInfo, $groups = []) {
    try {
        $email = $userInfo->email ?? null;
        $sub = $userInfo->sub ?? null;
        
        if (!$email || !$sub) {
            return ['success' => false, 'message' => 'Missing required user information (email or sub)'];
        }
        
        // search for existing user by OIDC sub or email
        $stmt = $this->db->prepare("SELECT * FROM users WHERE oidc_sub = ? OR email = ?");
        $stmt->execute([$sub, $email]);
        $user = $stmt->fetch();
        
        if (!$user) {
            // automatic User creation
            $username = $this->generateUniqueUsername($userInfo);
            
            $stmt = $this->db->prepare("
                INSERT INTO users (username, email, first_name, last_name, oidc_sub, is_active, created_at) 
                VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
            ");
            $stmt->execute([
                $username,
                $email,
                $userInfo->given_name ?? $userInfo->name ?? '',
                $userInfo->family_name ?? '',
                $sub
            ]);
            
            $userId = $this->db->lastInsertId();
            
            // standard User roles
            $stmt = $this->db->prepare("INSERT INTO user_roles (user_id, role, granted_at) VALUES (?, 'user', CURRENT_TIMESTAMP)");
            $stmt->execute([$userId]);
            
            // Log user creation
            try {
                $auditLogger = new AuditLogger($this->db);
                $auditLogger->log($userId, 'user_auto_created_oidc', 'user', $userId, null, [
                    'email' => $email,
                    'provider' => 'oidc',
                    'sub' => $sub
                ]);
            } catch (Exception $e) {
                error_log('Audit log error: ' . $e->getMessage());
            }
            
        } else {
            $userId = $user['id'];
            
            if (!$user['is_active']) {
                return ['success' => false, 'message' => 'User account is deactivated'];
            }
            
            // Update OIDC sub 
            if ($user['oidc_sub'] !== $sub) {
                $stmt = $this->db->prepare("UPDATE users SET oidc_sub = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->execute([$sub, $userId]);
            }
            
            // Update user info 
            $updates = [];
            $params = [];
            
            $newFirstName = $userInfo->given_name ?? $userInfo->name ?? '';
            $newLastName = $userInfo->family_name ?? '';
            
            if ($user['first_name'] !== $newFirstName) {
                $updates[] = 'first_name = ?';
                $params[] = $newFirstName;
            }
            
            if ($user['last_name'] !== $newLastName) {
                $updates[] = 'last_name = ?';
                $params[] = $newLastName;
            }
            
            if (!empty($updates)) {
                $updates[] = 'updated_at = CURRENT_TIMESTAMP';
                $params[] = $userId;
                
                $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
                $stmt = $this->db->prepare($sql);
                $stmt->execute($params);
            }
        }
        
        // Login 
        $_SESSION['user_id'] = $userId;
        $_SESSION['login_method'] = 'oidc';
        $_SESSION['login_time'] = time();
        
        // Update last login
        $stmt = $this->db->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$userId]);
        
        // Log successful OIDC login
        try {
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($userId, 'user_login_oidc', 'user', $userId, null, [
                'email' => $email,
                'provider' => 'oidc'
            ]);
        } catch (Exception $e) {
            error_log('Audit log error: ' . $e->getMessage());
        }
        
        return ['success' => true, 'message' => 'OIDC login successful'];
        
    } catch (Exception $e) {
        error_log('OIDC login error: ' . $e->getMessage());
        return ['success' => false, 'message' => 'OIDC login failed'];
    }
}

private function generateUniqueUsername($userInfo) {
    // Try different fields for username
    $baseUsername = '';
    
    if (!empty($userInfo->preferred_username)) {
        $baseUsername = $userInfo->preferred_username;
    } elseif (!empty($userInfo->name)) {
        $baseUsername = $userInfo->name;
    } elseif (!empty($userInfo->email)) {
        $baseUsername = explode('@', $userInfo->email)[0];
    } else {
        $baseUsername = 'oidc_user';
    }
    
    // delete unwanted characters and limit length
    $baseUsername = preg_replace('/[^a-zA-Z0-9_]/', '', $baseUsername);
    $baseUsername = substr($baseUsername, 0, 20);
    
    if (empty($baseUsername)) {
        $baseUsername = 'oidc_user';
    }
    
    // Try to create a unique username
    $username = $baseUsername;
    $counter = 1;
    
    while ($this->usernameExists($username)) {
        $username = $baseUsername . '_' . $counter;
        $counter++;
        
        // endless loop prevention
        if ($counter > 1000) {
            $username = 'oidc_user_' . time();
            break;
        }
    }
    
    return $username;
}

private function usernameExists($username) {
    try {
        $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch() !== false;
    } catch (Exception $e) {
        return false;
    }
}

            // Search User in DB
            $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ? OR oidc_sub = ?");
            $stmt->execute([$email, $userInfo->sub ?? '']);
            $user = $stmt->fetch();
            
            if (!$user) {
                // create new User
                $stmt = $this->db->prepare("
                    INSERT INTO users (username, email, first_name, last_name, oidc_sub, is_active, created_at) 
                    VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                ");
                $stmt->execute([
                    $username,
                    $email,
                    $userInfo->given_name ?? '',
                    $userInfo->family_name ?? '',
                    $userInfo->sub ?? ''
                ]);
                
                $userId = $this->db->lastInsertId();
                
                // Standard User roles
                $stmt = $this->db->prepare("INSERT INTO user_roles (user_id, role) VALUES (?, 'user')");
                $stmt->execute([$userId]);
                
                // Log user creation
                $auditLogger = new AuditLogger($this->db);
                $auditLogger->log($userId, 'user_created_oidc', 'user', $userId, null, [
                    'email' => $email,
                    'provider' => 'oidc'
                ]);
                
            } else {
                $userId = $user['id'];
                
                if (!$user['is_active']) {
                    return ['success' => false, 'message' => 'User account is deactivated'];
                }
                
                // Update OIDC sub if necessary
                if (empty($user['oidc_sub']) && !empty($userInfo->sub)) {
                    $stmt = $this->db->prepare("UPDATE users SET oidc_sub = ? WHERE id = ?");
                    $stmt->execute([$userInfo->sub, $userId]);
                }
            }
            
            // Login 
            $_SESSION['user_id'] = $userId;
            $_SESSION['login_method'] = 'oidc';
            $_SESSION['login_time'] = time();
            
            // Update last login
            $stmt = $this->db->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([$userId]);
            
            // Log successful OIDC login
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($userId, 'user_login_oidc', 'user', $userId, null, [
                'email' => $email,
                'provider' => 'oidc'
            ]);
            
            return ['success' => true, 'message' => 'OIDC login successful'];
            
        } catch (Exception $e) {
            error_log('OIDC login error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'OIDC login failed'];
        }
    }
    
    public function logout() {
        try {
            if ($this->isLoggedIn()) {
                $userId = $_SESSION['user_id'];
                
                // Log logout
                $auditLogger = new AuditLogger($this->db);
                $auditLogger->log($userId, 'user_logout', 'user', $userId);
            }
            
            // Clear session
            $_SESSION = [];
            
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            
            session_destroy();
            
            return true;
        } catch (Exception $e) {
            error_log('Logout error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function isLoggedIn() {
        return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
    }
    
    public function getCurrentUserId() {
        return $_SESSION['user_id'] ?? null;
    }
    
    public function getCurrentUser() {
        if ($this->currentUser === null && $this->isLoggedIn()) {
            try {
                $stmt = $this->db->prepare("
                    SELECT u.*, GROUP_CONCAT(ur.role) as roles
                    FROM users u
                    LEFT JOIN user_roles ur ON u.id = ur.user_id
                    WHERE u.id = ? AND u.is_active = 1
                    GROUP BY u.id
                ");
                $stmt->execute([$this->getCurrentUserId()]);
                $user = $stmt->fetch();
                
                if ($user) {
                    $user['roles'] = $user['roles'] ? explode(',', $user['roles']) : [];
                    $user['permissions'] = $this->getUserPermissions($user['roles']);
                    $this->currentUser = $user;
                }
            } catch (Exception $e) {
                error_log('Get current user error: ' . $e->getMessage());
                return null;
            }
        }
        
        return $this->currentUser;
    }
    
    public function hasRole($role) {
        $user = $this->getCurrentUser();
        return $user && in_array($role, $user['roles']);
    }
    
    public function hasPermission($permission) {
        $user = $this->getCurrentUser();
        return $user && in_array($permission, $user['permissions']);
    }
    
    public function getUserPermissions($roles) {
        $permissions = [];
        $rolesConfig = getRolesConfig();
        
        foreach ($roles as $role) {
            if (isset($rolesConfig[$role])) {
                $permissions = array_merge($permissions, $rolesConfig[$role]['permissions']);
            }
        }
        
        return array_unique($permissions);
    }
    
    public function createUser($data) {
        try {
            // Validate required fields
            if (empty($data['username']) || empty($data['password'])) {
                return ['success' => false, 'message' => 'Username and password are required'];
            }
            
            // Check if username exists
            $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$data['username']]);
            if ($stmt->fetch()) {
                return ['success' => false, 'message' => 'Username already exists'];
            }
            
            // Check if email exists (if provided)
            if (!empty($data['email'])) {
                $stmt = $this->db->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$data['email']]);
                if ($stmt->fetch()) {
                    return ['success' => false, 'message' => 'Email already exists'];
                }
            }
            
            // Create user
            $stmt = $this->db->prepare("
                INSERT INTO users (username, email, password_hash, first_name, last_name, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ");
            $stmt->execute([
                $data['username'],
                $data['email'] ?? null,
                password_hash($data['password'], PASSWORD_DEFAULT),
                $data['first_name'] ?? '',
                $data['last_name'] ?? '',
                $data['is_active'] ?? true
            ]);
            
            $userId = $this->db->lastInsertId();
            
            // Assign default role
            $defaultRole = $data['role'] ?? 'user';
            $stmt = $this->db->prepare("INSERT INTO user_roles (user_id, role, granted_by) VALUES (?, ?, ?)");
            $stmt->execute([$userId, $defaultRole, $this->getCurrentUserId()]);
            
            // Log user creation
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($this->getCurrentUserId(), 'user_created', 'user', $userId, null, [
                'username' => $data['username'],
                'email' => $data['email'] ?? null
            ]);
            
            return ['success' => true, 'message' => 'User created successfully', 'user_id' => $userId];
            
        } catch (Exception $e) {
            error_log('Create user error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to create user'];
        }
    }
    
    public function updateUser($userId, $data) {
        try {
            $user = $this->getUserById($userId);
            if (!$user) {
                return ['success' => false, 'message' => 'User not found'];
            }
            
            $updates = [];
            $params = [];
            
            if (isset($data['username']) && $data['username'] !== $user['username']) {
                // Check if new username exists
                $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
                $stmt->execute([$data['username'], $userId]);
                if ($stmt->fetch()) {
                    return ['success' => false, 'message' => 'Username already exists'];
                }
                $updates[] = 'username = ?';
                $params[] = $data['username'];
            }
            
            if (isset($data['email']) && $data['email'] !== $user['email']) {
                if (!empty($data['email'])) {
                    $stmt = $this->db->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
                    $stmt->execute([$data['email'], $userId]);
                    if ($stmt->fetch()) {
                        return ['success' => false, 'message' => 'Email already exists'];
                    }
                }
                $updates[] = 'email = ?';
                $params[] = $data['email'];
            }
            
            if (isset($data['first_name'])) {
                $updates[] = 'first_name = ?';
                $params[] = $data['first_name'];
            }
            
            if (isset($data['last_name'])) {
                $updates[] = 'last_name = ?';
                $params[] = $data['last_name'];
            }
            
            if (isset($data['is_active'])) {
                $updates[] = 'is_active = ?';
                $params[] = $data['is_active'] ? 1 : 0;
            }
            
            if (isset($data['password']) && !empty($data['password'])) {
                $updates[] = 'password_hash = ?';
                $params[] = password_hash($data['password'], PASSWORD_DEFAULT);
            }
            
            if (!empty($updates)) {
                $updates[] = 'updated_at = CURRENT_TIMESTAMP';
                $params[] = $userId;
                
                $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
                $stmt = $this->db->prepare($sql);
                $stmt->execute($params);
            }
            
            // Update roles if provided
            if (isset($data['roles']) && is_array($data['roles'])) {
                $this->updateUserRoles($userId, $data['roles']);
            }
            
            // Log user update
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($this->getCurrentUserId(), 'user_updated', 'user', $userId, $user, $data);
            
            return ['success' => true, 'message' => 'User updated successfully'];
            
        } catch (Exception $e) {
            error_log('Update user error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to update user'];
        }
    }
    
    public function updateUserRoles($userId, $roles) {
        try {
            // Get current roles
            $stmt = $this->db->prepare("SELECT role FROM user_roles WHERE user_id = ?");
            $stmt->execute([$userId]);
            $currentRoles = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            // Remove old roles
            $stmt = $this->db->prepare("DELETE FROM user_roles WHERE user_id = ?");
            $stmt->execute([$userId]);
            
            // Add new roles
            $stmt = $this->db->prepare("INSERT INTO user_roles (user_id, role, granted_by, granted_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)");
            foreach ($roles as $role) {
                $stmt->execute([$userId, $role, $this->getCurrentUserId()]);
            }
            
            // Log role changes
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($this->getCurrentUserId(), 'roles_updated', 'user', $userId, 
                ['roles' => $currentRoles], 
                ['roles' => $roles]
            );
            
            return true;
        } catch (Exception $e) {
            error_log('Update user roles error: ' . $e->getMessage());
            return false;
        }
    }
    
    public function getUserById($userId) {
        try {
            $stmt = $this->db->prepare("
                SELECT u.*, GROUP_CONCAT(ur.role) as roles
                FROM users u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                WHERE u.id = ?
                GROUP BY u.id
            ");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            
            if ($user) {
                $user['roles'] = $user['roles'] ? explode(',', $user['roles']) : [];
            }
            
            return $user;
        } catch (Exception $e) {
            error_log('Get user by ID error: ' . $e->getMessage());
            return null;
        }
    }
    
    public function getAllUsers() {
        try {
            $stmt = $this->db->prepare("
                SELECT u.*, GROUP_CONCAT(ur.role) as roles,
                       COUNT(v.id) as voucher_count
                FROM users u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                LEFT JOIN vouchers v ON u.id = v.user_id
                GROUP BY u.id
                ORDER BY u.username
            ");
            $stmt->execute();
            $users = $stmt->fetchAll();
            
            foreach ($users as &$user) {
                $user['roles'] = $user['roles'] ? explode(',', $user['roles']) : [];
            }
            
            return $users;
        } catch (Exception $e) {
            error_log('Get all users error: ' . $e->getMessage());
            return [];
        }
    }
    
    public function deleteUser($userId) {
        try {
            // Don't allow deleting own account
            if ($userId == $this->getCurrentUserId()) {
                return ['success' => false, 'message' => 'Cannot delete your own account'];
            }
            
            $user = $this->getUserById($userId);
            if (!$user) {
                return ['success' => false, 'message' => 'User not found'];
            }
            
            // Check if user has vouchers
            $stmt = $this->db->prepare("SELECT COUNT(*) FROM vouchers WHERE user_id = ?");
            $stmt->execute([$userId]);
            $voucherCount = $stmt->fetchColumn();
            
            if ($voucherCount > 0) {
                return ['success' => false, 'message' => 'Cannot delete user with existing vouchers'];
            }
            
            // Delete user roles first
            $stmt = $this->db->prepare("DELETE FROM user_roles WHERE user_id = ?");
            $stmt->execute([$userId]);
            
            // Delete user
            $stmt = $this->db->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            
            // Log user deletion
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($this->getCurrentUserId(), 'user_deleted', 'user', $userId, $user, null);
            
            return ['success' => true, 'message' => 'User deleted successfully'];
            
        } catch (Exception $e) {
            error_log('Delete user error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to delete user'];
        }
    }
    
    public function changePassword($userId, $currentPassword, $newPassword) {
        try {
            $user = $this->getUserById($userId);
            if (!$user) {
                return ['success' => false, 'message' => 'User not found'];
            }
            
            // Verify current password (only if not OIDC user)
            if (!empty($user['password_hash']) && !password_verify($currentPassword, $user['password_hash'])) {
                return ['success' => false, 'message' => 'Current password is incorrect'];
            }
            
            // Update password
            $stmt = $this->db->prepare("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([password_hash($newPassword, PASSWORD_DEFAULT), $userId]);
            
            // Log password change
            $auditLogger = new AuditLogger($this->db);
            $auditLogger->log($this->getCurrentUserId(), 'password_changed', 'user', $userId);
            
            return ['success' => true, 'message' => 'Password changed successfully'];
            
        } catch (Exception $e) {
            error_log('Change password error: ' . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to change password'];
        }
    }
    
    public function requirePermission($permission) {
        if (!$this->isLoggedIn()) {
            throw new Exception('Authentication required');
        }
        
        if (!$this->hasPermission($permission)) {
            throw new Exception('Insufficient permissions');
        }
        
        return true;
    }
    
    public function requireRole($role) {
        if (!$this->isLoggedIn()) {
            throw new Exception('Authentication required');
        }
        
        if (!$this->hasRole($role)) {
            throw new Exception('Insufficient role');
        }
        
        return true;
    }
    
    public function getSessionInfo() {
        if (!$this->isLoggedIn()) {
            return null;
        }
        
        return [
            'user_id' => $_SESSION['user_id'],
            'login_method' => $_SESSION['login_method'] ?? 'unknown',
            'login_time' => $_SESSION['login_time'] ?? null,
            'session_id' => session_id()
        ];
    }
    
    public function extendSession() {
        if ($this->isLoggedIn()) {
            $_SESSION['login_time'] = time();
            return true;
        }
        return false;
    }
    
    public function isSessionExpired($maxLifetime = 3600) {
        if (!$this->isLoggedIn()) {
            return true;
        }
        
        $loginTime = $_SESSION['login_time'] ?? 0;
        return (time() - $loginTime) > $maxLifetime;
    }
}
?>
