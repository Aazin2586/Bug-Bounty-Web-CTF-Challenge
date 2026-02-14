<?php
header('Content-Type: application/json');
error_reporting(0); // Production mode simulation

// ---------------------------------------------------------
// CONFIGURATION & SECRETS
// ---------------------------------------------------------
// JWT Secret - WEAK for purpose of challenge finding it via dictionary attack or just standard 'secret'
// Actually, let's allow 'none' algorithm for the vulnerability flag{jw7_st0r4g3_3xp0s3d}
$JWT_SECRET = "secret"; 

// Flags
$FLAGS = [
    'DOM'    => 'flag{d0m_l0g1c_byp4ss}',
    'JWT'    => 'flag{jw7_st0r4g3_3xp0s3d}',
    'CRYPTO' => 'flag{crypt0_fr4gm3nt_m1sus3}',
    'RACE'   => 'flag{r4c3_c0nd1t10n_m4st3r}'
];

// ---------------------------------------------------------
// HELPER FUNCTIONS
// ---------------------------------------------------------

function jsonResponse($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data);
    exit;
}

// Custom encoding for the Crypto Challenge
// Layer 1: ROT13 (Caesar Shift)
// Layer 2: Base64
function encodeFragment($str) {
    return base64_encode(str_rot13($str));
}

$SECRET_PARTS = ['NEXUS_', 'CORE_', 'KEY_77'];

function getBearerToken() {
    $headers = apache_request_headers();
    if (isset($headers['Authorization'])) {
        if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
            return $matches[1];
        }
    }
    return null;
}

// Simple Vulnerable JWT Decoder
function verifyJWT($token) {
    global $JWT_SECRET;
    $parts = explode('.', $token);
    if(count($parts) != 3) return false;

    $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[0])), true);
    $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[1])), true);
    $signature_provided = $parts[2];

    // VULNERABILITY 2: Algorithm confusion / None algorithm
    // VULNERABILITY: Allow empty signature OR none algorithm
    if (empty($signature_provided) || strtolower($header['alg']) === 'none') {
        return $payload; 
    }
    
    // Check signature
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($header)));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($payload)));
    $signature_expected = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $JWT_SECRET, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature_expected));

    if ($base64UrlSignature === $signature_provided) {
        return $payload;
    }
    
    return false;
}

function generateJWT($role) {
    global $JWT_SECRET;
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $payload = json_encode(['role' => $role, 'iat' => time(), 'exp' => time() + 3600]);
    
    $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
    $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
    
    $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $JWT_SECRET, true);
    $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
    
    return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
}

// ---------------------------------------------------------
// SESSION & RACE CONDITION INIT
// ---------------------------------------------------------
// We use a custom file-based session logic for the race condition to ensure we can
// simulate the race without PHP's default session file locking blocking us.

// ---------------------------------------------------------
// CUSTOM SESSION MANAGEMENT (NO LOCKING)
// ---------------------------------------------------------
// PHP's default session_start() locks the session file, preventing
// parallel requests from the same user. We must use a custom
// cookie to identify the user without acquiring a lock,
// enabling the Race Condition vulnerability.

if (!isset($_COOKIE['NEXUS_SESSION'])) {
    $user_id = bin2hex(random_bytes(16));
    setcookie('NEXUS_SESSION', $user_id, time() + 86400, "/");
    $_COOKIE['NEXUS_SESSION'] = $user_id; // Available immediately
} else {
    $user_id = $_COOKIE['NEXUS_SESSION'];
}

$db_file = 'sys_users_' . md5($user_id) . '.json';

// Initialize wallet if new user
if (!file_exists($db_file)) {
    // ATOMIC WRITE not required here, just init
    file_put_contents($db_file, json_encode([
        'checking' => 100,
        'vault'    => 0,
        'coupon_used' => false
    ]));
}

// ---------------------------------------------------------
// ROUTER
// ---------------------------------------------------------

$action = $_GET['action'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];

// Handle Login
if ($action === 'login' && $method === 'POST') {
    jsonResponse(['token' => generateJWT('guest')]);
}

// All other routes need a token
$token = getBearerToken();
if (!$token) jsonResponse(['error' => 'Unauthorized'], 401);

$user = verifyJWT($token);

// ---------------------------------------------------------
// JWT AUTHENTICATION
// ---------------------------------------------------------
if ($action === 'admin_debug') {
    // Check for admin role in token
    if ($user && isset($user['role']) && $user['role'] === 'admin') {
        jsonResponse([
            'status' => 'authorized',
            'sys_conf' => [
                'environment' => 'production',
                'debug_symbols' => false,
                'retry_limit' => 5,
                'system_key' => $FLAGS['JWT'],
                'ref_pointer' => encodeFragment($SECRET_PARTS[2])
            ]
        ]);
    }
    jsonResponse(['error' => 'Access Denied: Admin Role Required']);
}

// ---------------------------------------------------------
// LOGGING SUBSYSTEM
// ---------------------------------------------------------
if ($action === 'get_admin_logs') {
    $logs = [
        ['ts' => date('Y-m-d H:i:s', time()-3600), 'msg' => 'System backup started'],
        ['ts' => date('Y-m-d H:i:s', time()-3400), 'msg' => 'Database integrity check passed'],
        ['ts' => date('Y-m-d H:i:s', time()-1200), 'msg' => 'User limit warning: 85% capacity'],
        ['ts' => date('Y-m-d H:i:s', time()-300),  'msg' => 'Emergency Patch Applied: ' . $FLAGS['DOM']], 
        ['ts' => date('Y-m-d H:i:s', time()-10),    'msg' => 'Admin session active']
    ];
    jsonResponse([
        'logs' => $logs,
        'sync_ver' => encodeFragment($SECRET_PARTS[1])
    ]);
}

// ---------------------------------------------------------
// CONFIGURATION VALIDATION
// ---------------------------------------------------------
if ($action === 'verify_config') {
    $input = json_decode(file_get_contents('php://input'), true);
    
    $submitted_key = $input['key'] ?? '';
    $correct_key = implode('', $SECRET_PARTS);
    
    if ($submitted_key === $correct_key) {
        jsonResponse(['success' => true, 'config_hash' => $FLAGS['CRYPTO']]);
    }
    jsonResponse(['error' => 'Invalid Master Key']);
}

// ---------------------------------------------------------
// TRANSACTION PROCESSING
// ---------------------------------------------------------

function getVaultBalance($userId) {
    $logFile = 'vault_' . md5($userId) . '.log';
    if (!file_exists($logFile)) return 0;
    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $total = 0;
    foreach ($lines as $line) {
        $total += (int)$line;
    }
    return $total;
}

if ($action === 'get_balance') {
    $data = json_decode(file_get_contents($db_file), true);
    $vault = getVaultBalance($user_id);
    jsonResponse([
        'checking' => $data['checking'], 
        'vault' => $vault,
        'debug_trace_id' => encodeFragment($SECRET_PARTS[0])
    ]);
}

if ($action === 'transfer') {
    $input = json_decode(file_get_contents('php://input'), true);
    $amount = $input['amount'] ?? 0;
    
    // Logic Flaw: Negative amounts are not checked, allowing funds generation!
    // if ($amount <= 0) jsonResponse(['error' => 'Invalid Amount']);

    // Standard transaction flow
    $data = json_decode(file_get_contents($db_file), true);
    
    if ($data['checking'] >= $amount) {
        
        $data['checking'] -= $amount;
        file_put_contents($db_file, json_encode($data));
        
        $logFile = 'vault_' . md5($user_id) . '.log';
        if ($amount > 0) {
            file_put_contents($logFile, $amount . "\n", FILE_APPEND);
        }
        
        jsonResponse(['message' => 'Transfer Successful']);
    } else {
        jsonResponse(['error' => 'Insufficient Funds']);
    }
}

if ($action === 'buy_flag') {
    $vault = getVaultBalance($user_id);
    $cost = 200;
    
    if ($vault >= $cost) {
        // Return purchased content
        jsonResponse([
            'status' => 'delivered', 
            'report_content' => "CONFIDENTIAL AUDIT REPORT\n-------------------------\nStatus: CRITICAL\nReference: " . $FLAGS['RACE']
        ]);
    }
    jsonResponse(['error' => 'Insufficient Vault Balance (Need 200, Have ' . $vault . ')']);
}

jsonResponse(['error' => 'Invalid Action'], 400);
?>
