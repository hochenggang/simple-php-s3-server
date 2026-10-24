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
use S3Gateway\Storage\MultipartStorage;
use S3Gateway\Storage\StorageFactory;

$storage = StorageFactory::create();
if (!$storage instanceof MultipartStorage) {
    echo "Selected storage backend has no multipart uploads to clean up.\n";
    exit(0);
}
$result = $storage->cleanupExpiredMultipartUploads(time() - Config::multipartUploadTtl());
echo 'Cleanup complete: removed ' . $result['removed'] . ' upload(s), freed ' . $result['bytes'] . " bytes\n";
