<?php

namespace S3Gateway\Storage;

class MetaReader
{
    private PathResolver $pathResolver;

    public function __construct(PathResolver $pathResolver)
    {
        $this->pathResolver = $pathResolver;
    }

    public function getObjectMeta(string $bucket, string $key): ?array
    {
        $filePath = $this->pathResolver->objectPath($bucket, $key);
        \S3Gateway\Logger::debug("[getObjectMeta] bucket={$bucket}, key={$key}, path={$filePath}");

        if (!file_exists($filePath)) {
            \S3Gateway\Logger::debug("[getObjectMeta] File not found: {$filePath}");
            return null;
        }

        clearstatcache(true, $filePath);

        $size = filesize($filePath);
        \S3Gateway\Logger::debug("[getObjectMeta] filesize result: " . ($size === false ? 'false' : $size));

        if ($size === false) {
            return null;
        }

        $mtime = filemtime($filePath);
        if ($mtime === false) {
            return null;
        }

        $mime = $this->detectMimeType($filePath);
        $etag = $this->calculateEtag($key, $size);

        \S3Gateway\Logger::debug("[getObjectMeta] Returning: size={$size}, mtime={$mtime}, etag={$etag}");

        return [
            'size' => $size,
            'mtime' => $mtime,
            'mime' => $mime,
            'etag' => $etag
        ];
    }

    public function getFileSize(string $filePath): int
    {
        if (!file_exists($filePath)) {
            return 0;
        }

        clearstatcache(true, $filePath);
        $size = filesize($filePath);

        return $size !== false ? $size : 0;
    }

    public function getFileMtime(string $filePath): int
    {
        if (!file_exists($filePath)) {
            return 0;
        }

        clearstatcache(true, $filePath);
        $mtime = filemtime($filePath);

        return $mtime !== false ? $mtime : 0;
    }

    public function calculateEtag(string $key, int $size): string
    {
        return md5($key . $size);
    }

    private function detectMimeType(string $filePath): string
    {
        $mime = @mime_content_type($filePath);
        return $mime !== false ? $mime : 'application/octet-stream';
    }

    public function getPartMeta(string $bucket, string $uploadId, int $partNumber): ?array
    {
        $partPath = $this->pathResolver->partPath($bucket, $uploadId, $partNumber);

        if (!file_exists($partPath)) {
            return null;
        }

        clearstatcache(true, $partPath);

        $size = filesize($partPath);
        if ($size === false) {
            return null;
        }

        $mtime = filemtime($partPath);
        if ($mtime === false) {
            return null;
        }

        return [
            'number' => $partNumber,
            'size' => $size,
            'mtime' => $mtime,
            'etag' => $this->calculateEtag((string)$partNumber, $size)
        ];
    }
}
