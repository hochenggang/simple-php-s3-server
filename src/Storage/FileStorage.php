<?php

namespace S3Gateway\Storage;

class FileStorage
{
    private const STREAM_BUFFER_SIZE = 65536;

    private PathResolver $pathResolver;
    private MetaReader $metaReader;

    public function __construct()
    {
        $this->pathResolver = new PathResolver();
        $this->metaReader = new MetaReader($this->pathResolver);
    }

    public function getPathResolver(): PathResolver
    {
        return $this->pathResolver;
    }

    public function getMetaReader(): MetaReader
    {
        return $this->metaReader;
    }

    public function listBuckets(): array
    {
        $dataDir = $this->pathResolver->getDataDir();

        if (!is_dir($dataDir)) {
            return [];
        }

        $buckets = [];
        $items = @scandir($dataDir);

        if ($items === false) {
            return [];
        }

        foreach ($items as $item) {
            if ($item === '.' || $item === '..' || $item[0] === '.') {
                continue;
            }

            $path = $this->pathResolver->bucketPath($item);
            if (is_dir($path)) {
                $buckets[] = $item;
            }
        }

        return $buckets;
    }

    public function listObjects(string $bucket, string $prefix = '', int $maxKeys = 1000, int $skip = 0): array
    {
        $files = $this->scanFilesystem($bucket, $prefix);

        usort($files, function ($a, $b) {
            return strcmp($a['key'], $b['key']);
        });

        $totalCount = count($files);
        $files = array_slice($files, $skip, $maxKeys);

        return [
            'objects' => $files,
            'totalCount' => $totalCount,
            'isTruncated' => ($skip + count($files)) < $totalCount
        ];
    }

    private function scanFilesystem(string $bucket, string $prefix = ''): array
    {
        $bucketPath = $this->pathResolver->bucketPath($bucket);

        if (!is_dir($bucketPath)) {
            return [];
        }

        $decodedPrefix = $prefix ? rawurldecode(str_replace('+', ' ', $prefix)) : '';
        $files = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($bucketPath, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $fileInfo) {
            $path = $fileInfo->getPathname();

            if (strpos($path, '/.multipart/') !== false || strpos($path, '\\.multipart\\') !== false) {
                continue;
            }

            if ($fileInfo->isFile()) {
                $relativePath = $this->pathResolver->getRelativePath($bucketPath, $path);

                if ($decodedPrefix && strpos($relativePath, $decodedPrefix) !== 0) {
                    continue;
                }

                $s3Key = $this->encodeKey($relativePath);
                clearstatcache(true, $path);
                $size = $fileInfo->getSize();

                $files[] = [
                    'key' => $s3Key,
                    'size' => $size,
                    'timestamp' => $fileInfo->getMTime(),
                    'etag' => $this->metaReader->calculateEtag($s3Key, $size)
                ];
            }
        }

        return $files;
    }

    private function encodeKey(string $path): string
    {
        $parts = explode('/', $path);
        $encodedParts = array_map('rawurlencode', $parts);
        return implode('/', $encodedParts);
    }

    public function createBucket(string $bucket): bool
    {
        if (!$this->pathResolver->isValidBucketName($bucket)) {
            return false;
        }

        $bucketPath = $this->pathResolver->bucketPath($bucket);
        return $this->pathResolver->ensureDir($bucketPath);
    }

    public function deleteBucket(string $bucket): bool
    {
        $bucketPath = $this->pathResolver->bucketPath($bucket);

        if (!file_exists($bucketPath)) {
            return false;
        }

        $this->cleanupAllMultipartDirs($bucket);

        $items = @scandir($bucketPath);
        if ($items === false) {
            return false;
        }

        $items = array_diff($items, ['.', '..']);

        if (count($items) === 1 && isset($items['.multipart'])) {
            @rmdir($bucketPath . '/.multipart');
            return @rmdir($bucketPath);
        }

        return count($items) === 0 && @rmdir($bucketPath);
    }

    public function bucketExists(string $bucket): bool
    {
        return is_dir($this->pathResolver->bucketPath($bucket));
    }

    public function isBucketEmpty(string $bucket): bool
    {
        $bucketPath = $this->pathResolver->bucketPath($bucket);

        if (!is_dir($bucketPath)) {
            return true;
        }

        $items = @scandir($bucketPath);
        if ($items === false) {
            return true;
        }

        $items = array_diff($items, ['.', '..']);

        if (count($items) === 1) {
            $item = array_values($items)[0];
            if ($item === '.multipart') {
                $mpDir = $bucketPath . '/.multipart';
                $mpItems = @scandir($mpDir);
                if ($mpItems !== false && count(array_diff($mpItems, ['.', '..'])) === 0) {
                    @rmdir($mpDir);
                    return true;
                }
            }
        }

        return count($items) === 0;
    }

    public function getObjectMeta(string $bucket, string $key): ?array
    {
        return $this->metaReader->getObjectMeta($bucket, $key);
    }

    public function putObjectFromString(string $bucket, string $key, string $content): bool
    {
        $filePath = $this->pathResolver->objectPath($bucket, $key);

        if (!$this->pathResolver->ensureParentDir($filePath)) {
            return false;
        }

        $result = @file_put_contents($filePath, $content);
        return $result !== false;
    }

    public function putObjectFromStream(string $bucket, string $key, $stream): bool
    {
        $filePath = $this->pathResolver->objectPath($bucket, $key);

        if (!$this->pathResolver->ensureParentDir($filePath)) {
            return false;
        }

        return $this->streamCopy($stream, $filePath);
    }

    public function copyObject(string $sourceBucket, string $sourceKey, string $destBucket, string $destKey): bool
    {
        $sourcePath = $this->pathResolver->objectPath($sourceBucket, $sourceKey);
        $destPath = $this->pathResolver->objectPath($destBucket, $destKey);

        if (!file_exists($sourcePath)) {
            return false;
        }

        if (!$this->pathResolver->ensureParentDir($destPath)) {
            return false;
        }

        return @copy($sourcePath, $destPath);
    }

    public function deleteObject(string $bucket, string $key): bool
    {
        $filePath = $this->pathResolver->objectPath($bucket, $key);

        if (!file_exists($filePath)) {
            return false;
        }

        $result = @unlink($filePath);

        if ($result) {
            $this->cleanupEmptyDirectories($bucket, dirname($filePath));
        }

        return $result;
    }

    public function objectExists(string $bucket, string $key): bool
    {
        return file_exists($this->pathResolver->objectPath($bucket, $key));
    }

    private function cleanupEmptyDirectories(string $bucket, string $startDir): void
    {
        $bucketPath = $this->pathResolver->bucketPath($bucket);
        $dir = $this->pathResolver->normalize($startDir);

        $maxIterations = 100;
        $iterations = 0;

        while ($dir !== $bucketPath && $dir !== $this->pathResolver->getDataDir() && is_dir($dir) && $iterations < $maxIterations) {
            $items = @scandir($dir);
            if ($items === false) {
                break;
            }

            $items = array_diff($items, ['.', '..']);
            if (count($items) === 0) {
                @rmdir($dir);
                $dir = $this->pathResolver->normalize(dirname($dir));
            } else {
                break;
            }
            $iterations++;
        }
    }

    public function listParts(string $bucket, string $uploadId): array
    {
        $uploadDir = $this->pathResolver->multipartPath($bucket, $uploadId);

        if (!is_dir($uploadDir)) {
            return [];
        }

        $parts = [];
        $items = @scandir($uploadDir);

        if ($items === false) {
            return [];
        }

        foreach ($items as $item) {
            if (!ctype_digit($item)) {
                continue;
            }

            $partMeta = $this->metaReader->getPartMeta($bucket, $uploadId, (int)$item);
            if ($partMeta !== null) {
                $parts[] = $partMeta;
            }
        }

        usort($parts, function ($a, $b) {
            return $a['number'] <=> $b['number'];
        });

        return $parts;
    }

    public function savePart(string $bucket, string $uploadId, int $partNumber, string $content): bool
    {
        $uploadDir = $this->pathResolver->multipartPath($bucket, $uploadId);
        $contentLength = strlen($content);
        \S3Gateway\Logger::debug("[savePart] bucket={$bucket}, uploadId={$uploadId}, partNumber={$partNumber}, contentLength={$contentLength}");

        if (!$this->pathResolver->ensureDir($uploadDir)) {
            \S3Gateway\Logger::debug("[savePart] Error: Failed to ensure upload dir: {$uploadDir}");
            return false;
        }

        $partPath = $this->pathResolver->partPath($bucket, $uploadId, $partNumber);
        \S3Gateway\Logger::debug("[savePart] Saving to: {$partPath}");

        $result = @file_put_contents($partPath, $content);
        $saved = $result !== false;

        if ($saved) {
            $savedSize = filesize($partPath);
            \S3Gateway\Logger::debug("[savePart] Success: saved {$savedSize} bytes to {$partPath}");
        } else {
            \S3Gateway\Logger::debug("[savePart] Error: file_put_contents failed for {$partPath}");
        }

        return $saved;
    }

    public function completeMultipartUpload(string $bucket, string $key, string $uploadId, array $parts): ?array
    {
        $uploadDir = $this->pathResolver->multipartPath($bucket, $uploadId);
        $filePath = $this->pathResolver->objectPath($bucket, $key);

        if (!file_exists($uploadDir)) {
            return null;
        }

        if (!$this->pathResolver->ensureParentDir($filePath)) {
            return null;
        }

        if (file_exists($filePath)) {
            @unlink($filePath);
        }

        $fp = @fopen($filePath, 'wb');
        if (!$fp) {
            return null;
        }

        $totalBytesWritten = 0;

        try {
            ksort($parts);

            foreach (array_keys($parts) as $partNumber) {
                $partPath = $this->pathResolver->partPath($bucket, $uploadId, $partNumber);
                if (!file_exists($partPath)) {
                    fclose($fp);
                    @unlink($filePath);
                    return null;
                }

                clearstatcache(true, $partPath);
                $partSize = filesize($partPath);

                $partFp = @fopen($partPath, 'rb');
                if (!$partFp) {
                    fclose($fp);
                    @unlink($filePath);
                    return null;
                }

                while (!feof($partFp)) {
                    $buffer = fread($partFp, self::STREAM_BUFFER_SIZE);
                    if ($buffer !== false && $buffer !== '') {
                        fwrite($fp, $buffer);
                    }
                }

                fclose($partFp);
                $totalBytesWritten += $partSize;
            }

            fclose($fp);

            clearstatcache(true, $filePath);
            $finalSize = filesize($filePath);

            if ($finalSize !== $totalBytesWritten) {
                @unlink($filePath);
                return null;
            }

            $this->safeDeleteDirectory($uploadDir);

            $etag = $this->metaReader->calculateEtag($key, $finalSize);

            \S3Gateway\Logger::info("Multipart upload completed: bucket={$bucket}, key={$key}, uploadId={$uploadId}, size={$finalSize}, etag={$etag}");

            return [
                'size' => $finalSize,
                'etag' => $etag,
            ];
        } catch (\Exception $e) {
            fclose($fp);
            @unlink($filePath);
            error_log('FileStorage::completeMultipartUpload error: ' . $e->getMessage());
            return null;
        }
    }

    public function abortMultipartUpload(string $bucket, string $uploadId): bool
    {
        $uploadDir = $this->pathResolver->multipartPath($bucket, $uploadId);

        if (file_exists($uploadDir)) {
            $this->safeDeleteDirectory($uploadDir);
        }

        return true;
    }

    public function cleanupAllMultipartDirs(string $bucket): void
    {
        $multipartBaseDir = $this->pathResolver->bucketPath($bucket) . '/.multipart';

        if (!is_dir($multipartBaseDir)) {
            return;
        }

        $this->safeDeleteDirectory($multipartBaseDir);
    }

    public function createMultipartUpload(string $bucket, string $uploadId): bool
    {
        $uploadDir = $this->pathResolver->multipartPath($bucket, $uploadId);
        return $this->pathResolver->ensureDir($uploadDir);
    }

    private function safeDeleteDirectory(string $dir): bool
    {
        if (!file_exists($dir)) {
            return true;
        }

        if (!is_dir($dir)) {
            return false;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) {
                @rmdir($file->getPathname());
            } else {
                @unlink($file->getPathname());
            }
        }

        return @rmdir($dir);
    }

    private function streamCopy(string $source, string $dest, ?int $limit = null): bool
    {
        $inputStream = fopen($source, 'rb');
        if (!$inputStream) {
            return false;
        }

        $outputStream = fopen($dest, 'wb');
        if (!$outputStream) {
            fclose($inputStream);
            return false;
        }

        $totalBytes = 0;
        $bufferSize = self::STREAM_BUFFER_SIZE;

        while (!feof($inputStream)) {
            if ($limit !== null && $totalBytes >= $limit) {
                break;
            }

            $readSize = $bufferSize;
            if ($limit !== null) {
                $remaining = $limit - $totalBytes;
                $readSize = min($bufferSize, $remaining);
            }

            $buffer = fread($inputStream, $readSize);
            if ($buffer === false) {
                break;
            }

            $bytesWritten = fwrite($outputStream, $buffer);
            if ($bytesWritten === false) {
                fclose($inputStream);
                fclose($outputStream);
                @unlink($dest);
                return false;
            }

            $totalBytes += $bytesWritten;
        }

        fclose($inputStream);
        fclose($outputStream);

        return $totalBytes > 0 || file_exists($dest);
    }
}
