<?php

namespace S3Gateway;

class Config
{
    private static ?array $env = null;

    private static function load(): void
    {
        if (self::$env !== null) {
            return;
        }

        self::$env = [];

        $envFile = dirname(__DIR__) . '/.env';
        if (file_exists($envFile)) {
            $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if ($lines !== false) {
                foreach ($lines as $line) {
                    $line = trim($line);
                    if (empty($line) || $line[0] === '#') {
                        continue;
                    }
                    $pos = strpos($line, '=');
                    if ($pos !== false) {
                        $key = trim(substr($line, 0, $pos));
                        $value = trim(substr($line, $pos + 1));
                        if (strlen($value) >= 2 && $value[0] === '"' && $value[-1] === '"') {
                            $value = substr($value, 1, -1);
                        }
                        self::$env[$key] = $value;
                    }
                }
            }
        }
    }

    public static function get(string $key, $default = null)
    {
        self::load();
        return self::$env[$key] ?? $_ENV[$key] ?? $_SERVER[$key] ?? $default;
    }

    public static function dataDir(): string
    {
        $dir = self::get('DATA_DIR', dirname(__DIR__) . '/data');
        return self::resolvePath($dir);
    }

    public static function resolvePath(string $path): string
    {
        if (strpos($path, '/') === 0 || strpos($path, ':\\') === 1) {
            return $path;
        }
        return dirname(__DIR__) . '/' . $path;
    }

    public static function authDebug(): bool
    {
        return self::get('AUTH_DEBUG', 'false') === 'true';
    }

    public static function appDebug(): bool
    {
        return self::get('APP_DEBUG', 'false') === 'true';
    }

    public static function maxUploadSize(): int
    {
        return (int)self::get('MAX_REQUEST_SIZE', 5 * 1024 * 1024 * 1024);
    }

    public static function isAccessKeyAllowed(string $accessKeyId): bool
    {
        $allowedKeys = self::get('ALLOWED_ACCESS_KEYS', '');
        if (empty($allowedKeys)) {
            return true;
        }

        $allowedList = array_map('trim', explode(',', $allowedKeys));
        return in_array($accessKeyId, $allowedList, true);
    }

    public static function getSecretKey(string $accessKeyId): ?string
    {
        if (!self::isAccessKeyAllowed($accessKeyId)) {
            return null;
        }

        return self::get('DEFAULT_SECRET_KEY');
    }

    public static function bearerToken(): ?string
    {
        return self::get('BEARER_TOKEN');
    }
}
