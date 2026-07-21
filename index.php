<?php

while (ob_get_level() > 0) {
    ob_end_clean();
}

ini_set('output_buffering', '0');
ini_set('implicit_flush', '1');
ini_set('display_errors', '1');
error_reporting(E_ALL);

define('ERROR_LOG_FILE', __DIR__ . '/error_log');

require_once __DIR__ . '/vendor/autoload.php';

// All timestamps (logs, XML CreationDate/LastModified, HTTP Last-Modified) use UTC
// to match the "Z" suffix emitted by XmlResponse and the RFC 7232 HTTP-date spec.
date_default_timezone_set('UTC');

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
    echo '<Error><Code>InternalError</Code><Message>Internal server error</Message></Error>';
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
    echo '<Error><Code>InternalError</Code><Message>Internal server error</Message></Error>';
}
