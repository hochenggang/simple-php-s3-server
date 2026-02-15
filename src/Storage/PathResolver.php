<?php

namespace S3Gateway\Storage;

use S3Gateway\Config;

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
        return $this->normalize($this->dataDir . '/' . $bucket);
    }

    public function objectPath(string $bucket, string $key): string
    {
        $key = $this->sanitizeKey($key);
        return $this->normalize($this->dataDir . '/' . $bucket . '/' . $key);
    }

    public function multipartPath(string $bucket, string $uploadId): string
    {
        return $this->normalize($this->dataDir . '/' . $bucket . '/.multipart/' . $uploadId);
    }

    public function partPath(string $bucket, string $uploadId, int $partNumber): string
    {
        return $this->normalize($this->dataDir . '/' . $bucket . '/.multipart/' . $uploadId . '/' . $partNumber);
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
        return $this->ensureDir(dirname($filePath));
    }

    public function normalize(string $path): string
    {
        $path = str_replace('\\', '/', $path);
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

        if (strpos($bucket, '..') !== false) {
            throw new \InvalidArgumentException('Bucket name cannot contain consecutive dots');
        }

        if (str_starts_with($bucket, '.') || str_ends_with($bucket, '.')) {
            throw new \InvalidArgumentException('Bucket name cannot start or end with a dot');
        }
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

    private function sanitizeKey(string $key): string
    {
        if (strlen($key) > 1024) {
            throw new \InvalidArgumentException('Key length exceeds maximum of 1024 characters');
        }

        if (strpos($key, "\0") !== false) {
            throw new \InvalidArgumentException('Key contains null bytes');
        }

        $key = str_replace('+', ' ', $key);
        $key = rawurldecode($key);

        $key = str_replace('..', '', $key);
        $key = str_replace('\\', '/', $key);
        $key = ltrim($key, "/\0");

        return $key;
    }

    public function validatePath(string $path, string $allowedPrefix): bool
    {
        $normalizedPath = $this->normalize($path);
        $normalizedPrefix = $this->normalize($allowedPrefix);

        return strpos($normalizedPath, $normalizedPrefix) === 0;
    }

    public function getRelativePath(string $basePath, string $fullPath): string
    {
        $basePath = $this->normalize($basePath);
        $fullPath = $this->normalize($fullPath);

        if (strpos($fullPath, $basePath) === 0) {
            return ltrim(substr($fullPath, strlen($basePath)), '/');
        }

        return $fullPath;
    }
}
