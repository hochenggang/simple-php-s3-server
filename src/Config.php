<?php

namespace S3Gateway;

class Config
{
    private static ?array $env = null;
    private static ?array $accessKeys = null;

    private static function load(): void
    {
        if (self::$env !== null) {
            return;
        }

        self::$env = [];

        $iniFile = dirname(__DIR__) . '/.config.ini';
        if (file_exists($iniFile)) {
            $iniContent = parse_ini_file($iniFile, true);
            if ($iniContent !== false) {
                // 处理全局配置
                if (isset($iniContent[0])) {
                    self::$env = $iniContent[0];
                }
                // 其他配置也添加到全局
                foreach ($iniContent as $key => $value) {
                    if (is_array($value)) {
                        // 跳过访问密钥部分，由 parseAccessKeys 处理
                        continue;
                    }
                    self::$env[$key] = $value;
                }
            }
        }
    }

    private static function parseAccessKeys(): void
    {
        if (self::$accessKeys !== null) {
            return;
        }

        self::$accessKeys = [];

        $iniFile = dirname(__DIR__) . '/.config.ini';
        if (file_exists($iniFile)) {
            $iniContent = parse_ini_file($iniFile, true);
            if ($iniContent !== false) {
                foreach ($iniContent as $section => $value) {
                    if (is_array($value) && strpos($section, 'keys.') === 0) {
                        $accessKeyId = substr($section, 5);
                        
                        if (!isset($value['secret_key'])) {
                            continue;
                        }

                        $accessKey = [
                            'secret_key' => $value['secret_key'],
                            'allowed_buckets' => ['*'],
                            'file_max_size' => 0
                        ];
                        
                        if (isset($value['allowed_buckets'])) {
                            if ($value['allowed_buckets'] === '*') {
                                $accessKey['allowed_buckets'] = ['*'];
                            } else {
                                $accessKey['allowed_buckets'] = array_map('trim', explode(',', $value['allowed_buckets']));
                            }
                        }
                        
                        if (isset($value['file_max_size'])) {
                            $accessKey['file_max_size'] = (int)$value['file_max_size'] * 1024;
                        }
                        
                        self::$accessKeys[$accessKeyId] = $accessKey;
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
        return self::appDebug();
    }

    public static function appDebug(): bool
    {
        return self::get('APP_DEBUG', 'false') === 'true';
    }

    public static function isAccessKeyAllowed(string $accessKeyId): bool
    {
        self::parseAccessKeys();
        return isset(self::$accessKeys[$accessKeyId]);
    }

    public static function getSecretKey(string $accessKeyId): ?string
    {
        self::parseAccessKeys();
        if (!isset(self::$accessKeys[$accessKeyId])) {
            return null;
        }

        return self::$accessKeys[$accessKeyId]['secret_key'] ?? null;
    }

    public static function isBucketAllowed(string $accessKeyId, string $bucketName): bool
    {
        self::parseAccessKeys();
        if (!isset(self::$accessKeys[$accessKeyId])) {
            return false;
        }

        $allowedBuckets = self::$accessKeys[$accessKeyId]['allowed_buckets'] ?? [];
        
        if (in_array('*', $allowedBuckets, true)) {
            return true;
        }
        
        return in_array($bucketName, $allowedBuckets, true);
    }

    public static function getFileMaxSize(string $accessKeyId): int
    {
        self::parseAccessKeys();
        if (!isset(self::$accessKeys[$accessKeyId])) {
            return 0;
        }

        return self::$accessKeys[$accessKeyId]['file_max_size'] ?? 0;
    }

    public static function bearerToken(): ?string
    {
        return self::get('BEARER_TOKEN');
    }
}
