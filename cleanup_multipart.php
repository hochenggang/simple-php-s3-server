<?php

/**
 * Multipart upload 残留清理脚本
 *
 * 清理超过 MULTIPART_UPLOAD_TTL（默认 86400 秒 = 1 天）未完成的分片上传。
 * 建议通过 crontab 每日执行：
 *   0 3 * * * /usr/bin/php /path/to/simple-php-s3-server/cleanup_multipart.php
 */

require_once __DIR__ . '/vendor/autoload.php';

date_default_timezone_set('UTC');

use S3Gateway\Config;
use Symfony\Component\Filesystem\Path;

$ttl = Config::multipartUploadTtl();
$dataDir = Config::dataDir();

if (!is_dir($dataDir)) {
    echo "Data directory not found: {$dataDir}\n";
    exit(0);
}

$now = time();
$removedCount = 0;
$freedBytes = 0;

foreach (glob($dataDir . '/*', GLOB_ONLYDIR) as $bucketDir) {
    $bucket = basename($bucketDir);
    $multipartDir = Path::join($bucketDir, '.multipart');

    if (!is_dir($multipartDir)) {
        continue;
    }

    foreach (glob($multipartDir . '/*', GLOB_ONLYDIR) as $uploadDir) {
        $uploadId = basename($uploadDir);
        $mtime = filemtime($uploadDir);

        if (($now - $mtime) <= $ttl) {
            continue;
        }

        $size = dirSize($uploadDir);
        if (removeDir($uploadDir)) {
            $removedCount++;
            $freedBytes += $size;
            echo "Removed expired upload: {$bucket}/{$uploadId} (age: " . ($now - $mtime) . "s)\n";
        }
    }
}

echo "\nCleanup complete: removed {$removedCount} upload(s), freed " . formatBytes($freedBytes) . "\n";

function dirSize(string $dir): int
{
    $size = 0;
    foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS)) as $file) {
        if ($file->isFile()) {
            $size += $file->getSize();
        }
    }
    return $size;
}

function removeDir(string $dir): bool
{
    $files = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
        \RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($files as $file) {
        if ($file->isDir()) {
            @rmdir($file->getRealPath());
        } else {
            @unlink($file->getRealPath());
        }
    }
    return @rmdir($dir);
}

function formatBytes(int $bytes): string
{
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    }
    if ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    }
    if ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    }
    return $bytes . ' B';
}
