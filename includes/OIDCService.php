<?php
if (!defined('CONFIG_ACCESS')) {
    die('Direct access not allowed');
}

class OIDCService {
    private $config;
    private $client;
    
    public function __construct() {
        $this->loadConfig();
        if ($this->isEnabled()) {
            $this->initializeClient();
        }
    }
    
    private function loadConfig() {
        try {
            $settings = getIntegrationSettings('openid_connect');
            $this->config = [
                'enabled' => $settings['is_enabled'] ?? false,
                'issuer' => $settings['settings']['issuer'] ?? '',
                'client_id' => $settings['settings']['client_id'] ?? '',
                'client_secret' => $settings['settings']['client_secret'] ?? '',
                'redirect_uri' => $settings['settings']['redirect_uri'] ?? ''
            ];
        } catch (Exception $e) {
            error_log('OIDC config load error: ' . $e->getMessage());
            $this->config = [
                'enabled' => false,
                'issuer' => '',
                'client_id' => '',
                'client_secret' => '',
                'redirect_uri' => ''
            ];
        }
    }
    
    public function isEnabled() {
        return $this->config['enabled'] && 
               !empty($this->config['issuer']) && 
               !empty($this->config['client_id']) && 
               !empty($this->config['client_secret']);
    }
    
    private function initializeClient() {
        try {
            //  OpenIDConnectClient 
            $clientPath = __DIR__ . '/vendor/openid-connect/OpenIDConnectClient.php';
            if (!file_exists($clientPath)) {
                error_log('OpenIDConnectClient not found at: ' . $clientPath);
                $this->client = null;
                return;
            }
            
            require_once $clientPath;
            
            if (!class_exists('Jumbojett\OpenIDConnectClient')) {
                error_log('OpenIDConnectClient class not found');
                $this->client = null;
                return;
            }
            
            $this->client = new Jumbojett\OpenIDConnectClient(
                $this->config['issuer'],
                $this->config['client_id'],
                $this->config['client_secret']
            );
            
            $this->client->setRedirectURL($this->config['redirect_uri']);
            
            // Google-specific scopes
            if ($this->isGoogleProvider()) {
                $this->client->addScope(['openid', 'email', 'profile']);
            } else {
                $this->client->addScope(['openid', 'email', 'profile', 'groups']);
            }
            
            $this->client->setCodeChallengeMethod('S256');
            
        } catch (Exception $e) {
            error_log('OIDC client initialization error: ' . $e->getMessage());
            $this->client = null;
        }
    }
    
    private function isGoogleProvider() {
        return strpos($this->config['issuer'], 'google') !== false || 
               strpos($this->config['issuer'], 'accounts.google.com') !== false;
    }
    
    public function getAuthorizationURL($state = null) {
        if (!$this->isEnabled() || !$this->client) {
            error_log('OIDC not enabled or client not initialized');
            return null;
        }
        
        try {
            if ($state) {
                $this->client->setState($state);
            }
            
            return $this->client->getAuthorizationURL();
        } catch (Exception $e) {
            error_log('OIDC get authorization URL error: ' . $e->getMessage());
            return null;
        }
    }
    
    public function handleCallback($code, $state = null) {
        if (!$this->isEnabled() || !$this->client) {
            throw new Exception('OIDC not properly configured');
        }
        
        try {
            if ($state) {
                $this->client->setState($state);
            }
            
            // Token exchange
            $this->client->authenticate();
            
            // User info request
            $userInfo = $this->client->requestUserInfo();
            
            // groups extraction
            $groups = $this->extractGroups($userInfo);
            
            return [
                'user_info' => $userInfo,
                'groups' => $groups,
                'access_token' => $this->client->getAccessToken(),
                'id_token' => $this->client->getIdToken()
            ];
            
        } catch (Exception $e) {
            error_log('OIDC callback handling error: ' . $e->getMessage());
            throw new Exception('OIDC callback failed: ' . $e->getMessage());
        }
    }
    
    private function extractGroups($userInfo) {
        $groups = [];
        
        $groupClaims = ['groups', 'roles', 'memberOf', 'group_membership'];
        
        foreach ($groupClaims as $claim) {
            if (isset($userInfo->$claim)) {
                $claimValue = $userInfo->$claim;
                
                if (is_array($claimValue)) {
                    $groups = array_merge($groups, $claimValue);
                } elseif (is_string($claimValue)) {
                    $groups = array_merge($groups, explode(',', $claimValue));
                }
            }
        }
        
        return array_map('trim', $groups);
    }
    
    public function testConnection() {
        if (!$this->isEnabled()) {
            return ['success' => false, 'message' => 'OIDC not enabled'];
        }
        
        try {
            $metadata = $this->getProviderMetadata();
            
            if ($metadata && isset($metadata['issuer'])) {
                return [
                    'success' => true,
                    'message' => 'OIDC provider accessible',
                    'provider' => $metadata['issuer']
                ];
            }
            
            return ['success' => false, 'message' => 'Unable to fetch provider metadata'];
            
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'Connection test failed: ' . $e->getMessage()];
        }
    }
    
    public function getProviderMetadata() {
        if (!$this->isEnabled()) {
            return null;
        }
        
        try {
            if ($this->isGoogleProvider()) {
                $discoveryUrl = 'https://accounts.google.com/.well-known/openid_configuration';
            } else {
                $discoveryUrl = rtrim($this->config['issuer'], '/') . '/.well-known/openid_configuration';
            }
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $discoveryUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode === 200) {
                return json_decode($response, true);
            }
            
            return null;
        } catch (Exception $e) {
            error_log('OIDC metadata error: ' . $e->getMessage());
            return null;
        }
    }
}
?>
