<?php

namespace S3Gateway;

use Symfony\Component\Filesystem\Path;

class Config
{
    private static ?array $config = null;
    private static ?array $accessKeys = null;

    private static function load(): void
    {
        if (self::$config !== null) {
            return;
        }

        self::$config = [];
        self::$accessKeys = [];

        $iniFile = Path::join(dirname(__DIR__, 2), 'config.ini');
        if (file_exists($iniFile)) {
            $iniContent = parse_ini_file($iniFile, true);
            if ($iniContent !== false) {
                foreach ($iniContent as $section => $value) {
                    if ($section === 'general' && is_array($value)) {
                        self::$config = array_merge(self::$config, $value);
                    } elseif (is_array($value) && str_starts_with($section, 'keys.')) {
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
                            // Integer KB only.
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
        return self::$config[$key] ?? $default;
    }

    public static function dataDir(): string
    {
        $default = Path::join(dirname(__DIR__), 'data');
        $dir = self::get('DATA_DIR', $default);
        // Guard against an explicit empty value collapsing to the project root.
        $dir = trim((string)$dir);
        if ($dir === '') {
            $dir = $default;
        }
        return self::resolvePath($dir);
    }

    public static function resolvePath(string $path): string
    {
        if (Path::isAbsolute($path)) {
            return $path;
        }
        return Path::join(dirname(__DIR__), $path);
    }

    public static function appDebug(): bool
    {
        return self::get('APP_DEBUG', 'false') === 'true';
    }

    public static function maxKeys(): int
    {
        return (int)self::get('MAX_KEYS', 100000);
    }

    public static function maxTimestampSkew(): int
    {
        return (int)self::get('MAX_TIMESTAMP_SKEW', 300);
    }

    /**
     * Global per-request / per-part upload size limit in bytes.
     * Reads MAX_UPLOAD_SIZE (unit KB, default 8192 = 8MB). 0 means no limit.
     */
    public static function maxUploadSize(): int
    {
        return (int)self::get('MAX_UPLOAD_SIZE', 8192) * 1024;
    }

    public static function multipartUploadTtl(): int
    {
        return (int)self::get('MULTIPART_UPLOAD_TTL', 86400);
    }

    public static function listBucketsCacheTimeout(): int
    {
        return (int)self::get('LIST_BUCKETS_CACHE_TIMEOUT', 60);
    }

    public static function getSecretKey(string $accessKeyId): ?string
    {
        self::load();
        if (!isset(self::$accessKeys[$accessKeyId])) {
            return null;
        }

        return self::$accessKeys[$accessKeyId]['secret_key'] ?? null;
    }

    public static function isBucketAllowed(string $accessKeyId, string $bucketName): bool
    {
        self::load();
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
        self::load();
        if (!isset(self::$accessKeys[$accessKeyId])) {
            return 0;
        }

        return self::$accessKeys[$accessKeyId]['file_max_size'] ?? 0;
    }

    /**
     * Whether to trust X-Forwarded-* headers from a reverse proxy.
     * Defaults to false so direct-exposure deployments are not vulnerable to
     * client-supplied forwarding headers. Enable explicitly behind a trusted proxy.
     */
    public static function trustProxyHeaders(): bool
    {
        return self::get('TRUST_PROXY_HEADERS', 'false') === 'true';
    }
}
