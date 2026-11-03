<?php

namespace S3Gateway\Storage;

class MetaReader
{
    private PathResolver $pathResolver;
    private EtagStore $etagStore;

    public function __construct(PathResolver $pathResolver, ?EtagStore $etagStore = null)
    {
        $this->pathResolver = $pathResolver;
        $this->etagStore = $etagStore ?? new EtagStore($pathResolver);
    }

    public function getObjectMeta(string $bucket, string $key): ?array
    {
        $filePath = $this->pathResolver->objectPath($bucket, $key);

        if (!is_file($filePath)) {
            return null;
        }

        clearstatcache(true, $filePath);

        $size = filesize($filePath);

        if ($size === false) {
            return null;
        }

        $mtime = filemtime($filePath);
        if ($mtime === false) {
            return null;
        }

        $mime = $this->detectMimeType($filePath);
        $etag = $this->etagStore->get($filePath);
        if ($etag === null) {
            return null;
        }

        return [
            'size' => $size,
            'mtime' => $mtime,
            'mime' => $mime,
            'etag' => $etag
        ];
    }

    public function getFileSize(string $filePath): int
    {
        if (!is_file($filePath)) {
            return 0;
        }

        clearstatcache(true, $filePath);
        $size = filesize($filePath);

        return $size !== false ? $size : 0;
    }

    public function getFileMtime(string $filePath): int
    {
        if (!is_file($filePath)) {
            return 0;
        }

        clearstatcache(true, $filePath);
        $mtime = filemtime($filePath);

        return $mtime !== false ? $mtime : 0;
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

        $etag = $this->etagStore->get($partPath);
        if ($etag === null) {
            return null;
        }

        return [
            'number' => $partNumber,
            'size' => $size,
            'mtime' => $mtime,
            'etag' => $etag
        ];
    }
}
