<?php

namespace S3Gateway\Storage;

use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Logger;
use Symfony\Component\Filesystem\Path;

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

            // Skip entries that don't satisfy bucket-name rules (e.g. leftover
            // non-bucket directories) so listBuckets never crashes on them.
            if (!$this->pathResolver->isValidBucketName($item)) {
                continue;
            }

            $path = $this->pathResolver->bucketPath($item);
            if (is_dir($path)) {
                $buckets[] = $item;
            }
        }

        return $buckets;
    }

    public function listObjects(
        string $bucket,
        string $prefix = '',
        int $maxKeys = 1000,
        int $skip = 0,
        string $delimiter = '',
        string $startAfter = '',
        string $marker = ''
    ): array {
        $allFiles = $this->getScanCache($bucket);
        if ($allFiles === null) {
            $allFiles = $this->scanFilesystem($bucket);
            $this->setScanCache($bucket, $allFiles);
        }

        // prefix 过滤在内存中执行（缓存的是完整扫描结果）
        $decodedPrefix = $prefix ? rawurldecode(str_replace('+', ' ', $prefix)) : '';
        if ($decodedPrefix !== '') {
            $allFiles = array_filter($allFiles, fn($f) => str_starts_with($f['key'], $decodedPrefix));
            $allFiles = array_values($allFiles);
        }

        usort($allFiles, fn($a, $b) => strcmp($a['key'], $b['key']));

        // 1. delimiter 分组（不再先过滤文件列表，过滤移到合并列表上以正确处理
        //    common prefix 的 marker/startAfter 续页）。
        $commonPrefixes = [];
        $objects = [];

        if ($delimiter !== '') {
            $seenPrefixes = [];
            foreach ($allFiles as $file) {
                $keyAfterPrefix = $prefix !== '' ? substr($file['key'], strlen($prefix)) : $file['key'];
                $delimPos = strpos($keyAfterPrefix, $delimiter);

                if ($delimPos !== false) {
                    $commonPrefix = $prefix . substr($keyAfterPrefix, 0, $delimPos + strlen($delimiter));
                    if (!isset($seenPrefixes[$commonPrefix])) {
                        $seenPrefixes[$commonPrefix] = true;
                        $commonPrefixes[] = $commonPrefix;
                    }
                } else {
                    $objects[] = $file;
                }
            }
        } else {
            $objects = $allFiles;
        }

        // 2. 合并为统一排序列表（object 和 common prefix 按 sortKey 混排）。
        $merged = [];
        foreach ($objects as $obj) {
            $merged[] = ['type' => 'object', 'sortKey' => $obj['key'], 'data' => $obj];
        }
        foreach ($commonPrefixes as $cp) {
            $merged[] = ['type' => 'prefix', 'sortKey' => $cp, 'data' => $cp];
        }
        usort($merged, fn($a, $b) => strcmp($a['sortKey'], $b['sortKey']));

        // 3. 在合并列表上过滤 marker/startAfter（V2 startAfter 优先于 V1 marker）。
        //    过滤 merged 而非原始文件列表，确保 delimiter 续页时 common prefix 不重复。
        $filterAfter = $startAfter !== '' ? $startAfter : $marker;
        if ($filterAfter !== '') {
            $merged = array_filter($merged, fn($item) => strcmp($item['sortKey'], $filterAfter) > 0);
            $merged = array_values($merged);
        }

        // 4. 分页。
        $totalCount = count($merged);
        $sliced = array_slice($merged, $skip, $maxKeys);
        $isTruncated = ($skip + count($sliced)) < $totalCount;

        $resultObjects = [];
        $resultPrefixes = [];
        $nextMarker = '';
        foreach ($sliced as $item) {
            if ($item['type'] === 'object') {
                $resultObjects[] = $item['data'];
            } else {
                $resultPrefixes[] = $item['data'];
            }
            $nextMarker = $item['sortKey'];
        }

        return [
            'objects' => $resultObjects,
            'commonPrefixes' => $resultPrefixes,
            'isTruncated' => $isTruncated,
            'nextMarker' => $isTruncated ? $nextMarker : '',
        ];
    }

    private function scanFilesystem(string $bucket): array
    {
        $bucketPath = $this->pathResolver->bucketPath($bucket);

        if (!is_dir($bucketPath)) {
            return [];
        }

        $files = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($bucketPath, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $fileInfo) {
            $path = $fileInfo->getPathname();

            if (str_contains($this->pathResolver->normalize($path), '/.multipart/')) {
                continue;
            }

            if ($fileInfo->isFile()) {
                $relativePath = $this->pathResolver->getRelativePath($bucketPath, $path);

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

    /**
     * ListObjects 结果缓存：缓存完整扫描结果，分页请求复用同一份缓存。
     * 格式 JSON 数组，每元素 [key, size, mtime, etag] 四元组（紧凑）。
     * TTL 由 LIST_BUCKETS_CACHE_TIMEOUT 配置（默认 60 秒），按文件 mtime 判断。
     */
    private function getScanCache(string $bucket): ?array
    {
        $cacheFile = $this->scanCachePath($bucket);
        if (!file_exists($cacheFile)) {
            return null;
        }

        $ttl = Config::listBucketsCacheTimeout();
        if ($ttl <= 0) {
            return null;
        }
        if ((time() - filemtime($cacheFile)) > $ttl) {
            return null;
        }

        $data = json_decode((string)file_get_contents($cacheFile), true);
        if (!is_array($data)) {
            return null;
        }

        $files = [];
        foreach ($data as $row) {
            $files[] = [
                'key' => $row[0],
                'size' => $row[1],
                'timestamp' => $row[2],
                'etag' => $row[3],
            ];
        }
        return $files;
    }

    private function setScanCache(string $bucket, array $files): void
    {
        if (Config::listBucketsCacheTimeout() <= 0) {
            return;
        }
        $cacheFile = $this->scanCachePath($bucket);
        $dir = dirname($cacheFile);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
            if (!is_dir($dir)) {
                return;
            }
        }

        $rows = [];
        foreach ($files as $f) {
            $rows[] = [$f['key'], $f['size'], $f['timestamp'], $f['etag']];
        }

        // 原子写入：先写 .tmp 再 rename
        $tmp = $cacheFile . '.tmp';
        if (file_put_contents($tmp, json_encode($rows)) === false) {
            return;
        }
        @rename($tmp, $cacheFile);
    }

    private function scanCachePath(string $bucket): string
    {
        return Path::join(dirname(__DIR__, 2), 'tmp', 'listbuckets', $bucket . '.json');
    }

    /**
     * Convert a filesystem-relative path to the S3 key form.
     * The key is returned in its raw (decoded) form; URL-encoding for
     * encoding-type=url responses is applied at the XML layer (XmlResponse).
     */
    private function encodeKey(string $path): string
    {
        return $path;
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

        // Remove any multipart staging dir so it doesn't block bucket removal.
        $this->cleanupAllMultipartDirs($bucket);

        $items = @scandir($bucketPath);
        if ($items === false) {
            return false;
        }

        $items = array_values(array_diff($items, ['.', '..', '.multipart']));

        // Only delete when no business entries remain.
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

        // Atomic write: temp file in the same directory, then rename.
        $tempPath = $filePath . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tempPath, $content) === false) {
            @unlink($tempPath);
            return false;
        }

        if (!@rename($tempPath, $filePath)) {
            @unlink($tempPath);
            return false;
        }

        return true;
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

        usort($parts, fn($a, $b) => $a['number'] <=> $b['number']);

        return $parts;
    }

    public function savePart(string $bucket, string $uploadId, int $partNumber, string $content): bool
    {
        $uploadDir = $this->pathResolver->multipartPath($bucket, $uploadId);

        if (!$this->pathResolver->ensureDir($uploadDir)) {
            return false;
        }

        $partPath = $this->pathResolver->partPath($bucket, $uploadId, $partNumber);

        $result = @file_put_contents($partPath, $content);
        return $result !== false;
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

        // Atomic assemble: write to a sibling temp file, then rename onto the
        // final path. The original object stays untouched on any failure.
        $tempPath = $filePath . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $fp = @fopen($tempPath, 'wb');
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
                    @unlink($tempPath);
                    return null;
                }

                clearstatcache(true, $partPath);
                $partSize = filesize($partPath);

                $partFp = @fopen($partPath, 'rb');
                if (!$partFp) {
                    fclose($fp);
                    @unlink($tempPath);
                    return null;
                }

                try {
                    while (!feof($partFp)) {
                        $buffer = fread($partFp, self::STREAM_BUFFER_SIZE);
                        if ($buffer !== false && $buffer !== '') {
                            fwrite($fp, $buffer);
                        }
                    }
                } finally {
                    fclose($partFp);
                }

                $totalBytesWritten += $partSize;
            }

            fclose($fp);

            clearstatcache(true, $tempPath);
            $finalSize = filesize($tempPath);

            if ($finalSize !== $totalBytesWritten) {
                @unlink($tempPath);
                return null;
            }

            if (Config::maxUploadSize() > 0 && $finalSize > Config::maxUploadSize()) {
                @unlink($tempPath);
                throw S3Exception::entityTooLarge($finalSize, Config::maxUploadSize());
            }

            if (!@rename($tempPath, $filePath)) {
                @unlink($tempPath);
                return null;
            }

            $this->safeDeleteDirectory($uploadDir);

            $etag = $this->metaReader->calculateEtag($this->pathResolver->canonicalizeKey($key), $finalSize);

            \S3Gateway\Logger::info("Multipart upload completed: bucket={$bucket}, key={$key}, uploadId={$uploadId}, size={$finalSize}, etag={$etag}");

            return [
                'size' => $finalSize,
                'etag' => $etag,
            ];
        } catch (S3Exception $e) {
            throw $e;
        } catch (\Exception $e) {
            fclose($fp);
            @unlink($tempPath);
            Logger::error('FileStorage::completeMultipartUpload error: ' . $e->getMessage());
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
}
