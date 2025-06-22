<?php
namespace Jumbojett;

class OpenIDConnectClient {
    private $provider_url;
    private $client_id;
    private $client_secret;
    private $redirect_url;
    private $scopes = ['openid'];
    private $state;
    private $nonce;
    private $code_challenge_method;
    private $code_verifier;
    private $code_challenge;
    private $access_token;
    private $id_token;
    
    public function __construct($provider_url, $client_id, $client_secret) {
        $this->provider_url = rtrim($provider_url, '/');
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->state = bin2hex(random_bytes(16));
        $this->nonce = bin2hex(random_bytes(16));
    }
    
    public function setRedirectURL($redirect_url) {
        $this->redirect_url = $redirect_url;
    }
    
    public function addScope($scopes) {
        if (is_array($scopes)) {
            $this->scopes = array_merge($this->scopes, $scopes);
        } else {
            $this->scopes[] = $scopes;
        }
        $this->scopes = array_unique($this->scopes);
    }
    
    public function setState($state) {
        $this->state = $state;
    }
    
    public function getState() {
        return $this->state;
    }
    
    public function setCodeChallengeMethod($method) {
        $this->code_challenge_method = $method;
        if ($method === 'S256') {
            $this->code_verifier = bin2hex(random_bytes(64));
            $this->code_challenge = rtrim(strtr(base64_encode(hash('sha256', $this->code_verifier, true)), '+/', '-_'), '=');
        }
    }
    
    public function getAuthorizationURL() {
        $params = [
            'response_type' => 'code',
            'client_id' => $this->client_id,
            'redirect_uri' => $this->redirect_url,
            'scope' => implode(' ', $this->scopes),
            'state' => $this->state,
            'nonce' => $this->nonce
        ];
        
        if ($this->code_challenge_method === 'S256') {
            $params['code_challenge'] = $this->code_challenge;
            $params['code_challenge_method'] = 'S256';
        }
        
        // Google-spezifischer Endpoint
        if ($this->isGoogleProvider()) {
            $auth_endpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
        } else {
            $auth_endpoint = $this->provider_url . '/oauth2/v2.0/authorize';
        }
        
        return $auth_endpoint . '?' . http_build_query($params);
    }
    
    public function authenticate() {
        if (isset($_GET['code'])) {
            return $this->handleCallback();
        } else {
            $this->requestAuthorization();
        }
    }
    
    private function handleCallback() {
        if (isset($_GET['error'])) {
            throw new \Exception('Authorization error: ' . ($_GET['error_description'] ?? $_GET['error']));
        }
        
        if (!isset($_GET['code'])) {
            throw new \Exception('No authorization code received');
        }
        
        $token_data = $this->requestTokens($_GET['code']);
        $this->access_token = $token_data['access_token'];
        $this->id_token = $token_data['id_token'] ?? null;
        
        return true;
    }
    
    private function requestTokens($code) {
        if ($this->isGoogleProvider()) {
            $token_endpoint = 'https://oauth2.googleapis.com/token';
        } else {
            $token_endpoint = $this->provider_url . '/oauth2/v2.0/token';
        }
        
        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirect_url,
            'client_id' => $this->client_id,
            'client_secret' => $this->client_secret
        ];
        
        if ($this->code_challenge_method === 'S256') {
            $params['code_verifier'] = $this->code_verifier;
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $token_endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded',
            'Accept: application/json'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new \Exception('cURL error: ' . $error);
        }
        
        if ($http_code !== 200) {
            throw new \Exception('Token request failed (HTTP ' . $http_code . '): ' . $response);
        }
        
        $token_data = json_decode($response, true);
        if (!$token_data || !isset($token_data['access_token'])) {
            throw new \Exception('Invalid token response');
        }
        
        return $token_data;
    }
    
    public function requestUserInfo() {
        if (!$this->access_token) {
            throw new \Exception('No access token available');
        }
        
        if ($this->isGoogleProvider()) {
            $userinfo_endpoint = 'https://www.googleapis.com/oauth2/v2/userinfo';
        } else {
            $userinfo_endpoint = 'https://graph.microsoft.com/oidc/userinfo';
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $userinfo_endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $this->access_token,
            'Accept: application/json'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code !== 200) {
            throw new \Exception('UserInfo request failed (HTTP ' . $http_code . ')');
        }
        
        return json_decode($response);
    }
    
    public function getAccessToken() {
        return $this->access_token;
    }
    
    public function getIdToken() {
        return $this->id_token;
    }
    
    private function isGoogleProvider() {
        return strpos($this->provider_url, 'google') !== false || 
               strpos($this->provider_url, 'accounts.google.com') !== false;
    }
    
    private function requestAuthorization() {
        $auth_url = $this->getAuthorizationURL();
        header('Location: ' . $auth_url);
        exit;
    }
    
    public function getLogoutURL($post_logout_redirect_uri = null) {
        return $post_logout_redirect_uri; // Vereinfacht für Google
    }
}
?>
