<?php

namespace S3Gateway\S3;

use S3Gateway\Config;

class XmlResponse
{
    private static string $xmlNs = 'http://s3.amazonaws.com/doc/2006-03-01/';

    public static function error(string $code, string $message, string $resource = ''): string
    {
        $requestId = bin2hex(random_bytes(8));
        $code = self::escape($code);
        $message = self::escape($message);
        $resource = self::escape($resource);

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>{$code}</Code>
    <Message>{$message}</Message>
    <Resource>{$resource}</Resource>
    <RequestId>{$requestId}</RequestId>
</Error>
XML;
    }

    public static function listBuckets(array $buckets, string $dataDir): string
    {
        $xmlNs = self::$xmlNs;
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="{$xmlNs}">
    <Owner>
        <ID>s3-server</ID>
        <DisplayName>s3-server</DisplayName>
    </Owner>
    <Buckets>
XML;

        foreach ($buckets as $bucket) {
            $bucketName = self::escape($bucket);
            $creationDate = date('Y-m-d\TH:i:s.000\Z', @filemtime($dataDir . '/' . $bucket) ?: time());
            $xml .= "        <Bucket><Name>{$bucketName}</Name><CreationDate>{$creationDate}</CreationDate></Bucket>\n";
        }

        $xml .= <<<XML
    </Buckets>
</ListAllMyBucketsResult>
XML;
        return $xml;
    }

    public static function listObjects(array $files, string $bucket, string $prefix = ''): string
    {
        $xmlNs = self::$xmlNs;
        $bucket = self::escape($bucket);
        $prefix = self::escape($prefix);

        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="{$xmlNs}">
    <Name>{$bucket}</Name>
    <Prefix>{$prefix}</Prefix>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
XML;

        foreach ($files as $file) {
            $key = self::escape($file['key']);
            $lastModified = date('Y-m-d\TH:i:s.000\Z', $file['timestamp']);
            $size = (int)$file['size'];
            $etag = self::escape($file['etag'] ?? '');
            $xml .= <<<XML
    <Contents>
        <Key>{$key}</Key>
        <LastModified>{$lastModified}</LastModified>
        <Size>{$size}</Size>
        <ETag>{$etag}</ETag>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
XML;
        }

        $xml .= "</ListBucketResult>";
        return $xml;
    }

    public static function listObjectsV2(
        array $files,
        string $bucket,
        string $prefix = '',
        int $maxKeys = 1000,
        string $continuationToken = '',
        string $nextContinuationToken = '',
        string $startAfter = '',
        bool $fetchOwner = false
    ): string {
        $xmlNs = self::$xmlNs;
        $keyCount = count($files);
        $isTruncated = $nextContinuationToken ? 'true' : 'false';

        $bucket = self::escape($bucket);
        $prefix = self::escape($prefix);

        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="{$xmlNs}">
    <Name>{$bucket}</Name>
    <Prefix>{$prefix}</Prefix>
    <MaxKeys>{$maxKeys}</MaxKeys>
    <KeyCount>{$keyCount}</KeyCount>
    <IsTruncated>{$isTruncated}</IsTruncated>
XML;

        if ($continuationToken) {
            $xml .= "    <ContinuationToken>" . self::escape($continuationToken) . "</ContinuationToken>\n";
        }

        if ($startAfter) {
            $xml .= "    <StartAfter>" . self::escape($startAfter) . "</StartAfter>\n";
        }

        if ($nextContinuationToken) {
            $xml .= "    <NextContinuationToken>" . self::escape($nextContinuationToken) . "</NextContinuationToken>\n";
        }

        foreach ($files as $file) {
            $key = self::escape($file['key']);
            $lastModified = date('Y-m-d\TH:i:s.000\Z', $file['timestamp']);
            $size = (int)$file['size'];
            $etag = self::escape($file['etag'] ?? '');
            $xml .= <<<XML
    <Contents>
        <Key>{$key}</Key>
        <LastModified>{$lastModified}</LastModified>
        <Size>{$size}</Size>
        <ETag>{$etag}</ETag>
        <StorageClass>STANDARD</StorageClass>
XML;
            if ($fetchOwner) {
                $xml .= "        <Owner><ID>s3-server</ID><DisplayName>s3-server</DisplayName></Owner>\n";
            }
            $xml .= "    </Contents>\n";
        }

        $xml .= "</ListBucketResult>";
        return $xml;
    }

    public static function createMultipartUpload(string $bucket, string $key, string $uploadId): string
    {
        $xmlNs = self::$xmlNs;
        $bucket = self::escape($bucket);
        $key = self::escape($key);

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="{$xmlNs}">
    <Bucket>{$bucket}</Bucket>
    <Key>{$key}</Key>
    <UploadId>{$uploadId}</UploadId>
</InitiateMultipartUploadResult>
XML;
    }

    public static function completeMultipartUpload(string $bucket, string $key, string $location, string $etag, int $size): string
    {
        $xmlNs = self::$xmlNs;
        $bucket = self::escape($bucket);
        $key = self::escape($key);
        $location = self::escape($location);
        $etag = self::escape($etag);
        if (strpos($etag, '"') !== 0) {
            $etag = '"' . $etag . '"';
        }

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="{$xmlNs}">
    <Location>{$location}</Location>
    <Bucket>{$bucket}</Bucket>
    <Key>{$key}</Key>
    <ETag>{$etag}</ETag>
    <Size>{$size}</Size>
</CompleteMultipartUploadResult>
XML;
    }

    public static function listParts(string $bucket, string $key, string $uploadId, array $parts): string
    {
        $xmlNs = self::$xmlNs;
        $bucket = self::escape($bucket);
        $key = self::escape($key);
        $uploadId = self::escape($uploadId);

        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="{$xmlNs}">
    <Bucket>{$bucket}</Bucket>
    <Key>{$key}</Key>
    <UploadId>{$uploadId}</UploadId>
    <MaxParts>1000</MaxParts>
    <IsTruncated>false</IsTruncated>
XML;

        foreach ($parts as $part) {
            $number = (int)$part['number'];
            $lastModified = date('Y-m-d\TH:i:s.000\Z', $part['mtime'] ?? $part['timestamp']);
            $etag = $part['etag'];
            if (strpos($etag, '"') !== 0) {
                $etag = '"' . $etag . '"';
            }
            $etag = self::escape($etag);
            $size = (int)$part['size'];
            $xml .= <<<XML
    <Part>
        <PartNumber>{$number}</PartNumber>
        <LastModified>{$lastModified}</LastModified>
        <ETag>{$etag}</ETag>
        <Size>{$size}</Size>
    </Part>
XML;
        }

        $xml .= "</ListPartsResult>";
        return $xml;
    }

    public static function copyObject(string $etag, int $lastModified): string
    {
        $xmlNs = self::$xmlNs;
        $lastModifiedStr = date('Y-m-d\TH:i:s.000\Z', $lastModified);
        if (strpos($etag, '"') !== 0) {
            $etag = '"' . $etag . '"';
        }
        $etag = self::escape($etag);

        return <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="{$xmlNs}">
    <LastModified>{$lastModifiedStr}</LastModified>
    <ETag>{$etag}</ETag>
</CopyObjectResult>
XML;
    }

    public static function deleteObjects(array $deleted, array $errors): string
    {
        $xmlNs = self::$xmlNs;
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="{$xmlNs}">
XML;

        foreach ($deleted as $key) {
            $key = self::escape($key);
            $xml .= "    <Deleted><Key>{$key}</Key></Deleted>\n";
        }

        foreach ($errors as $error) {
            $key = self::escape($error['key']);
            $code = self::escape($error['code']);
            $message = self::escape($error['message']);
            $xml .= "    <Error><Key>{$key}</Key><Code>{$code}</Code><Message>{$message}</Message></Error>\n";
        }

        $xml .= "</DeleteResult>";
        return $xml;
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
