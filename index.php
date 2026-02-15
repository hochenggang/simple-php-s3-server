<?php

while (ob_get_level() > 0) {
    ob_end_clean();
}

ini_set('output_buffering', '0');
ini_set('implicit_flush', '1');
ini_set('display_errors', '1');
error_reporting(E_ALL);

define('ERROR_LOG_FILE', __DIR__ . '/error_log');

require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/Config.php';

S3Gateway\Logger::init(ERROR_LOG_FILE);

set_error_handler(function($errno, $errstr, $errfile, $errline) {
    S3Gateway\Logger::error(sprintf("Error [%d]: %s in %s:%d", $errno, $errstr, $errfile, $errline));
    return false;
});

set_exception_handler(function($e) {
    S3Gateway\Logger::exception($e, 'Uncaught Exception');
    
    http_response_code(500);
    header('Content-Type: application/xml');
    echo '<?xml version="1.0" encoding="UTF-8"?>';
    echo '<Error><Code>InternalError</Code><Message>' . $e->getMessage() . '</Message></Error>';
});

spl_autoload_register(function ($class) {
    $prefix = 'S3Gateway\\';
    $baseDir = __DIR__ . '/src/';
    
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }
    
    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';
    
    if (file_exists($file)) {
        require $file;
    }
});

use S3Gateway\Http\Router;

try {
    $router = new Router();
    $router->handle();
} catch (Throwable $e) {
    S3Gateway\Logger::exception($e, 'Unhandled Throwable');
    
    http_response_code(500);
    header('Content-Type: application/xml');
    echo '<?xml version="1.0" encoding="UTF-8"?>';
    echo '<Error><Code>InternalError</Code><Message>' . $e->getMessage() . '</Message></Error>';
}
