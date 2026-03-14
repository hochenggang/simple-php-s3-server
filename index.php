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

// 立即记录一些初始化信息
S3Gateway\Logger::info("=== S3 Gateway Initializing ===");
S3Gateway\Logger::info("PHP Version: " . phpversion());
S3Gateway\Logger::info("Error log file: " . ERROR_LOG_FILE);

// 测试配置加载
try {
    $appDebug = S3Gateway\Config::appDebug();
    S3Gateway\Logger::info("Config loaded - APP_DEBUG: " . var_export($appDebug, true));
} catch (Exception $e) {
    S3Gateway\Logger::error("Error loading config: " . $e->getMessage());
}

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
