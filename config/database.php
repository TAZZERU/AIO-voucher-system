<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

require_once __DIR__ . '/app_config.php';

class Database {
    private $host;
    private $db_name;
    private $username;
    private $password;
    private $conn;
    
    public function __construct() {
        $this->host = DB_HOST;
        $this->db_name = DB_NAME;
        $this->username = DB_USER;
        $this->password = DB_PASS;
    }
    
    public function getConnection() {
        $this->conn = null;
        
        try {
            // Use utf8mb4 
            $this->conn = new PDO(
                "mysql:host=" . $this->host . ";dbname=" . $this->db_name . ";charset=utf8mb4",
                $this->username,
                $this->password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
                ]
            );
            
            $this->conn->exec("SET CHARACTER SET utf8mb4");
            $this->conn->exec("SET COLLATION_CONNECTION = utf8mb4_unicode_ci");
            
        } catch(PDOException $exception) {
            error_log("Database connection error: " . $exception->getMessage());
            throw new Exception("Database connection failed");
        }
        
        return $this->conn;
    }
    
    public function createTables() {
        // Ensure the connection is established
        try {
            $this->conn->exec("ALTER DATABASE `" . $this->db_name . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        } catch (Exception $e) {
            // IIgnore errors if the database already has the correct charset
            error_log("Could not alter database charset: " . $e->getMessage());
        }
        
        $sql = "
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE,
            password_hash VARCHAR(255),
            first_name VARCHAR(100),
            last_name VARCHAR(100),
            oidc_sub VARCHAR(255) UNIQUE,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            last_login TIMESTAMP NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS roles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(50) UNIQUE NOT NULL,
            display_name VARCHAR(100) NOT NULL,
            description TEXT,
            permissions JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS user_roles (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            role VARCHAR(50) NOT NULL,
            granted_by INT,
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL,
            UNIQUE KEY unique_user_role (user_id, role)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS voucher_types (
            id INT AUTO_INCREMENT PRIMARY KEY,
            type_key VARCHAR(50) UNIQUE NOT NULL,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            icon VARCHAR(10) DEFAULT NULL,
            default_price DECIMAL(10,2) DEFAULT 0.00,
            default_tax_rate DECIMAL(5,2) DEFAULT 19.00,
            is_active BOOLEAN DEFAULT TRUE,
            pretix_category_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS vouchers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            voucher_code VARCHAR(20) UNIQUE NOT NULL,
            user_id INT NOT NULL,
            type VARCHAR(50) NOT NULL,
            price DECIMAL(10,2) DEFAULT 0.00,
            tax_rate DECIMAL(5,2) DEFAULT 19.00,
            is_active BOOLEAN DEFAULT TRUE,
            is_redeemed BOOLEAN DEFAULT FALSE,
            redeemed_at TIMESTAMP NULL,
            redeemed_by INT NULL,
            pretix_voucher_id INT,
            pretix_published BOOLEAN DEFAULT FALSE,
            metadata JSON,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (redeemed_by) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_voucher_code (voucher_code),
            INDEX idx_user_id (user_id),
            INDEX idx_redeemed (is_redeemed)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS system_integrations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            integration VARCHAR(50) UNIQUE NOT NULL,
            is_enabled BOOLEAN DEFAULT FALSE,
            settings JSON,
            last_sync TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            action VARCHAR(100) NOT NULL,
            resource_type VARCHAR(50),
            resource_id INT,
            old_values JSON,
            new_values JSON,
            ip_address VARCHAR(45),
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_user_action (user_id, action),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

        CREATE TABLE IF NOT EXISTS pretix_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            pretix_id INT UNIQUE NOT NULL,
            organizer VARCHAR(100) NOT NULL,
            slug VARCHAR(100) NOT NULL,
            name VARCHAR(255) NOT NULL,
            date_from DATETIME,
            date_to DATETIME,
            is_active BOOLEAN DEFAULT TRUE,
            settings JSON,
            last_sync TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ";
        
        $this->conn->exec($sql);
        $this->seedInitialData();
    }
    
    private function seedInitialData() {
        // Create default admin user
        $stmt = $this->conn->prepare("SELECT COUNT(*) FROM users WHERE username = 'admin'");
        $stmt->execute();
        
        if ($stmt->fetchColumn() == 0) {
            $stmt = $this->conn->prepare("
                INSERT INTO users (username, email, password_hash, first_name, last_name, is_active) 
                VALUES ('admin', 'admin@system.local', ?, 'System', 'Administrator', 1)
            ");
            $stmt->execute([password_hash('changeme123', PASSWORD_DEFAULT)]);
            $admin_id = $this->conn->lastInsertId();
            
            // Assign admin role
            $stmt = $this->conn->prepare("INSERT INTO user_roles (user_id, role, granted_by) VALUES (?, 'admin', ?)");
            $stmt->execute([$admin_id, $admin_id]);
        }
        
        // Create default roles
        $roles = getRolesConfig();
        foreach ($roles as $role_key => $role_data) {
            $stmt = $this->conn->prepare("
                INSERT INTO roles (name, display_name, description, permissions) 
                VALUES (?, ?, ?, ?) 
                ON DUPLICATE KEY UPDATE 
                display_name = VALUES(display_name),
                permissions = VALUES(permissions)
            ");
            $stmt->execute([
                $role_key,
                $role_data['name'],
                'System role: ' . $role_data['name'],
                json_encode($role_data['permissions'])
            ]);
        }
        
        // Create default voucher types
        $default_types = [
            ['food', 'Food Voucher', '🍕', 10.00],
            ['drink', 'Drink Voucher', '🥤', 5.00],
            ['merchandise', 'Merchandise Voucher', '👕', 25.00],
            ['general', 'General Voucher', '🎫', 0.00]
        ];
        
        foreach ($default_types as $type) {
            $stmt = $this->conn->prepare("
                INSERT INTO voucher_types (type_key, name, icon, default_price) 
                VALUES (?, ?, ?, ?) 
                ON DUPLICATE KEY UPDATE name = VALUES(name), icon = VALUES(icon)
            ");
            $stmt->execute($type);
        }
        
        // Initialize system integrations
        $integrations = [
            ['openid_connect', false, '{}'],
            ['pretix', false, '{}']
        ];
        
        foreach ($integrations as $integration) {
            $stmt = $this->conn->prepare("
                INSERT INTO system_integrations (integration, is_enabled, settings) 
                VALUES (?, ?, ?) 
                ON DUPLICATE KEY UPDATE integration = integration
            ");
            $stmt->execute($integration);
        }
    }
}
?>
