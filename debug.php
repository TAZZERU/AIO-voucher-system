<?php
echo "<h1>Rewrite Test</h1>";
echo "REQUEST_URI: " . $_SERVER['REQUEST_URI'] . "<br>";
echo "SCRIPT_NAME: " . $_SERVER['SCRIPT_NAME'] . "<br>";
echo "QUERY_STRING: " . $_SERVER['QUERY_STRING'] . "<br>";

if (isset($_SERVER['REDIRECT_ORIGINAL_URI'])) {
    echo "ORIGINAL_URI: " . $_SERVER['REDIRECT_ORIGINAL_URI'] . "<br>";
}

// Test ob mod_rewrite aktiv ist
if (function_exists('apache_get_modules')) {
    $modules = apache_get_modules();
    echo "mod_rewrite: " . (in_array('mod_rewrite', $modules) ? 'Aktiviert' : 'Nicht aktiviert') . "<br>";
}
?>
