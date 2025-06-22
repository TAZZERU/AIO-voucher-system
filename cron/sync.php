<?php
define('CONFIG_ACCESS', true);
require_once __DIR__ . '/../config/app_config.php';
require_once __DIR__ . '/../includes/PretixService.php';

// Check if the script is run from command line
if (php_sapi_name() !== 'cli') {
    die('This script can only be run from command line');
}

$pretixService = new PretixService();

if ($pretixService->isEnabled()) {
    echo "Starting Pretix sync...\n";
    $result = $pretixService->syncVouchers();
    
    if ($result['success']) {
        echo "Sync completed: " . $result['message'] . "\n";
    } else {
        echo "Sync failed: " . $result['message'] . "\n";
    }
} else {
    echo "Pretix integration not enabled\n";
}
?>
