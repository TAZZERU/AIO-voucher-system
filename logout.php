<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Session destruction
$_SESSION = [];
session_destroy();

//redirect to index.php with logout parameter
header('Location: index.php?logout=1');
exit;
?>
