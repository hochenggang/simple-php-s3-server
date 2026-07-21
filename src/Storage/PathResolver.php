<?php

namespace S3Gateway\Storage;

use S3Gateway\Config;
use Symfony\Component\Filesystem\Path;

class PathResolver
{
    private string $dataDir;

    public function __construct()
    {
        $this->dataDir = $this->normalize(Config::dataDir());
        $this->ensureDir($this->dataDir);
    }

    public function getDataDir(): string
    {
        return $this->dataDir;
    }

    public function bucketPath(string $bucket): string
    {
        $this->validateBucketName($bucket);
        return $this->normalize(Path::join($this->dataDir, $bucket));
    }

    public function objectPath(string $bucket, string $key): string
    {
        $this->validateBucketName($bucket);
        $key = $this->sanitizeKey($key);
        return $this->normalize(Path::join($this->dataDir, $bucket, $key));
    }

    public function multipartPath(string $bucket, string $uploadId): string
    {
        $this->validateBucketName($bucket);
        $this->validateUploadId($uploadId);
        return $this->normalize(Path::join($this->dataDir, $bucket, '.multipart', $uploadId));
    }

    /**
     * Validate uploadId format: 32-char hexadecimal (matches bin2hex(random_bytes(16))).
     * Prevents path traversal via malicious client-supplied uploadId.
     */
    private function validateUploadId(string $uploadId): void
    {
        if (strlen($uploadId) !== 32 || !ctype_xdigit($uploadId)) {
            throw new \InvalidArgumentException('Invalid uploadId format');
        }
    }

    public function partPath(string $bucket, string $uploadId, int $partNumber): string
    {
        $this->validateUploadId($uploadId);
        return $this->normalize(Path::join($this->dataDir, $bucket, '.multipart', $uploadId, (string)$partNumber));
    }

    public function ensureDir(string $path): bool
    {
        $path = $this->normalize($path);
        if (!file_exists($path)) {
            return @mkdir($path, 0755, true);
        }
        return is_dir($path);
    }

    public function ensureParentDir(string $filePath): bool
    {
        return $this->ensureDir(Path::getDirectory($filePath));
    }

    public function normalize(string $path): string
    {
        // Path::normalize 只替换反斜杠，不合并多斜杠
        $path = Path::normalize($path);
        $path = preg_replace('#/+#', '/', $path);
        return rtrim($path, '/');
    }

    public function validateBucketName(string $bucket): void
    {
        if (empty($bucket)) {
            throw new \InvalidArgumentException('Bucket name is required');
        }

        $length = strlen($bucket);
        if ($length < 3 || $length > 63) {
            throw new \InvalidArgumentException('Bucket name must be 3-63 characters');
        }

        if (!preg_match('/^[a-z0-9.-]+$/', $bucket)) {
            throw new \InvalidArgumentException('Bucket name can only contain lowercase letters, numbers, hyphens, and dots');
        }

        if (!preg_match('/^[a-z0-9].*[a-z0-9]$/', $bucket)) {
            throw new \InvalidArgumentException('Bucket name must start and end with a letter or number');
        }

        if (str_contains($bucket, '..')) {
            throw new \InvalidArgumentException('Bucket name cannot contain consecutive dots');
        }

        if (str_starts_with($bucket, '.') || str_ends_with($bucket, '.')) {
            throw new \InvalidArgumentException('Bucket name cannot start or end with a dot');
        }

        // Reject Windows reserved device names (CON/NUL/PRN/AUX/COM1-9/LPT1-9) so the
        // directory can be created on Windows and behaves consistently cross-platform.
        if ($this->isWindowsReservedName($bucket)) {
            throw new \InvalidArgumentException('Bucket name uses a reserved device name');
        }

        // Reject IPv4/IPv6 address forms (S3 forbids them).
        if (filter_var($bucket, FILTER_VALIDATE_IP) !== false) {
            throw new \InvalidArgumentException('Bucket name cannot be an IP address');
        }

        // Reject punycode prefix (reserved by DNS/S3).
        if (str_starts_with($bucket, 'xn--')) {
            throw new \InvalidArgumentException('Bucket name cannot use punycode prefix');
        }
    }

    /**
     * Windows reserved device names: CON, PRN, AUX, NUL, COM1-9, LPT1-9 (case-insensitive).
     */
    private function isWindowsReservedName(string $name): bool
    {
        $upper = strtoupper($name);
        if (in_array($upper, ['CON', 'PRN', 'AUX', 'NUL'], true)) {
            return true;
        }
        if (preg_match('/^(COM|LPT)([1-9])$/', $upper)) {
            return true;
        }
        return false;
    }

    public function isValidBucketName(string $bucket): bool
    {
        try {
            $this->validateBucketName($bucket);
            return true;
        } catch (\InvalidArgumentException $e) {
            return false;
        }
    }

    /**
     * 返回 key 的规范化形式（解码、去遍历段、去控制字符），用于 ETag 计算等需要
     * 与磁盘实际 key 一致的场景。与 sanitizeKey 行为相同，暴露为公共 API。
     */
    public function canonicalizeKey(string $key): string
    {
        return $this->sanitizeKey($key);
    }

    private function sanitizeKey(string $key): string
    {
        if (strlen($key) > 1024) {
            throw new \InvalidArgumentException('Key length exceeds maximum of 1024 characters');
        }

        if (str_contains($key, "\0")) {
            throw new \InvalidArgumentException('Key contains null bytes');
        }

        $key = str_replace('+', ' ', $key);
        $key = rawurldecode($key);
        $key = str_replace('\\', '/', $key);

        // Segment-based canonicalization: drop empty, "." and ".." segments.
        // This neutralizes traversal (../, ....//) without corrupting legitimate
        // filenames that happen to contain ".." as a substring (e.g. "file..txt").
        // Also reject segments that would collide with the multipart staging dir
        // (.multipart) or contain control/Windows-illegal characters.
        $segments = [];
        foreach (explode('/', $key) as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                continue;
            }

            if ($segment === '.multipart') {
                throw new \InvalidArgumentException('Key segment ".multipart" is reserved');
            }

            if (preg_match('/[\x00-\x1f\x7f]/', $segment)) {
                throw new \InvalidArgumentException('Key segment contains control characters');
            }

            // Windows filesystem illegal characters: : * ? " < > |
            if (preg_match('/[:*?"<>|]/', $segment)) {
                throw new \InvalidArgumentException('Key segment contains illegal characters');
            }

            // Windows reserved device names as a pure segment (CON, NUL, COM1, etc.)
            if ($this->isWindowsReservedName($segment)) {
                throw new \InvalidArgumentException('Key segment uses a reserved device name');
            }

            $segments[] = $segment;
        }

        return implode('/', $segments);
    }

    public function getRelativePath(string $basePath, string $fullPath): string
    {
        $basePath = $this->normalize($basePath);
        $fullPath = $this->normalize($fullPath);

        if (str_starts_with($fullPath, $basePath)) {
            return ltrim(substr($fullPath, strlen($basePath)), '/');
        }

        return $fullPath;
    }
}
