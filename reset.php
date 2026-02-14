<?php
// Reset Script for Bug Bounty Web Challenge

// 1. Clear Backend Data
$files = glob('sys_users_*.json');
foreach ($files as $file) {
    if (is_file($file)) {
        unlink($file);
    }
}

$logs = glob('vault_*.log');
foreach ($logs as $log) {
    if (is_file($log)) {
        unlink($log);
    }
}

// 2. Clear Session/Cookie
if (isset($_COOKIE['NEXUS_SESSION'])) {
    unset($_COOKIE['NEXUS_SESSION']);
    setcookie('NEXUS_SESSION', '', time() - 3600, '/'); // empty value and old timestamp
}

// 3. Response
header('Content-Type: application/json');
echo json_encode(['message' => 'Website Reset Successfully. Please refresh the page and clear your Local Storage if needed.']);
?>
