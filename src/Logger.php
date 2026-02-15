<?php

namespace S3Gateway;

class Logger
{
    private static ?string $logFile = null;

    public static function init(string $logFile): void
    {
        self::$logFile = $logFile;
        self::ensureWritable();
    }

    public static function log(string $message, string $level = 'INFO'): void
    {
        if (self::$logFile === null) {
            return;
        }

        $timestamp = date('Y-m-d H:i:s');
        $logLine = sprintf("[%s] [%s] %s\n", $timestamp, $level, $message);
        @error_log($logLine, 3, self::$logFile);
    }

    public static function error(string $message): void
    {
        self::log($message, 'ERROR');
    }

    public static function warning(string $message): void
    {
        self::log($message, 'WARN');
    }

    public static function info(string $message): void
    {
        self::log($message, 'INFO');
    }

    public static function debug(string $message): void
    {
        if (Config::authDebug()) {
            self::log($message, 'DEBUG');
        }
    }

    public static function exception(\Throwable $e, string $context = ''): void
    {
        $message = sprintf(
            "%s: %s in %s:%d\nTrace:\n%s",
            $context ?: get_class($e),
            $e->getMessage(),
            self::sanitizePath($e->getFile()),
            $e->getLine(),
            $e->getTraceAsString()
        );
        self::error($message);
    }

    public static function request(string $method, string $uri, int $statusCode = 0): void
    {
        $message = sprintf("%s %s", $method, $uri);
        if ($statusCode > 0) {
            $message .= sprintf(" -> %d", $statusCode);
        }
        self::info($message);
    }

    private static function ensureWritable(): void
    {
        if (self::$logFile === null) {
            return;
        }

        if (!file_exists(self::$logFile)) {
            @touch(self::$logFile);
            @chmod(self::$logFile, 0666);
        }

        if (file_exists(self::$logFile) && !is_writable(self::$logFile)) {
            @chmod(self::$logFile, 0666);
        }
    }

    private static function sanitizePath(string $path): string
    {
        $basePath = dirname(__DIR__);
        if (strpos($path, $basePath) === 0) {
            return '[PROJECT]' . substr($path, strlen($basePath));
        }
        return $path;
    }
}
