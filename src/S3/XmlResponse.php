<?php

namespace S3Gateway\S3;

use Spatie\ArrayToXml\ArrayToXml;

class XmlResponse
{
    private static string $xmlNs = 'http://s3.amazonaws.com/doc/2006-03-01/';

    /**
     * Build root element config with xmlns attribute
     */
    private static function rootElement(string $name): array
    {
        return [
            'rootElementName' => $name,
            '_attributes' => ['xmlns' => self::$xmlNs],
        ];
    }

    public static function error(string $code, string $message, string $resource = ''): string
    {
        return ArrayToXml::convert([
            'Code' => $code,
            'Message' => $message,
            'Resource' => $resource,
            'RequestId' => bin2hex(random_bytes(8)),
        ], self::rootElement('Error'), false);
    }

    public static function listBuckets(array $buckets, string $dataDir): string
    {
        $bucketNodes = [];
        foreach ($buckets as $bucket) {
            $creationDate = gmdate('Y-m-d\TH:i:s.000\Z', @filemtime($dataDir . '/' . $bucket) ?: time());
            $bucketNodes[] = [
                'Name' => $bucket,
                'CreationDate' => $creationDate,
            ];
        }

        $data = [
            'Owner' => [
                'ID' => 's3-server',
                'DisplayName' => 's3-server',
            ],
            'Buckets' => empty($bucketNodes) ? [] : ['Bucket' => $bucketNodes],
        ];

        return ArrayToXml::convert($data, self::rootElement('ListAllMyBucketsResult'), false);
    }

    public static function listObjects(
        array $files,
        string $bucket,
        string $prefix = '',
        int $maxKeys = 1000,
        string $marker = '',
        string $delimiter = '',
        array $commonPrefixes = [],
        bool $isTruncated = false,
        string $encodingType = '',
        string $nextMarker = ''
    ): string {
        $data = [
            'Name' => $bucket,
            'Prefix' => $prefix,
            'MaxKeys' => (string)$maxKeys,
            'IsTruncated' => $isTruncated ? 'true' : 'false',
        ];

        if ($marker !== '') {
            $data['Marker'] = $marker;
        }

        if ($delimiter !== '') {
            $data['Delimiter'] = $delimiter;
        }

        if ($encodingType !== '') {
            $data['EncodingType'] = $encodingType;
        }

        if ($isTruncated && $delimiter !== '' && $nextMarker !== '') {
            $data['NextMarker'] = $nextMarker;
        }

        $contents = self::buildContentsArray($files, $encodingType);
        if (!empty($contents)) {
            $data['Contents'] = $contents;
        }

        $cpNodes = self::buildCommonPrefixesArray($commonPrefixes, $encodingType);
        if (!empty($cpNodes)) {
            $data['CommonPrefixes'] = $cpNodes;
        }

        return ArrayToXml::convert($data, self::rootElement('ListBucketResult'), false);
    }

    public static function listObjectsV2(
        array $files,
        string $bucket,
        string $prefix = '',
        int $maxKeys = 1000,
        string $continuationToken = '',
        string $nextContinuationToken = '',
        string $startAfter = '',
        bool $fetchOwner = false,
        string $delimiter = '',
        array $commonPrefixes = [],
        string $encodingType = ''
    ): string {
        $isTruncated = $nextContinuationToken !== '';
        $keyCount = count($files);

        $data = [
            'Name' => $bucket,
            'Prefix' => $prefix,
            'MaxKeys' => (string)$maxKeys,
            'KeyCount' => (string)$keyCount,
            'IsTruncated' => $isTruncated ? 'true' : 'false',
        ];

        if ($delimiter !== '') {
            $data['Delimiter'] = $delimiter;
        }

        if ($encodingType !== '') {
            $data['EncodingType'] = $encodingType;
        }

        if ($continuationToken !== '') {
            $data['ContinuationToken'] = $continuationToken;
        }

        if ($startAfter !== '') {
            $data['StartAfter'] = $startAfter;
        }

        if ($nextContinuationToken !== '') {
            $data['NextContinuationToken'] = $nextContinuationToken;
        }

        $contents = self::buildContentsArray($files, $encodingType, $fetchOwner);
        if (!empty($contents)) {
            $data['Contents'] = $contents;
        }

        $cpNodes = self::buildCommonPrefixesArray($commonPrefixes, $encodingType);
        if (!empty($cpNodes)) {
            $data['CommonPrefixes'] = $cpNodes;
        }

        return ArrayToXml::convert($data, self::rootElement('ListBucketResult'), false);
    }

    /**
     * Build Contents child array for XML
     * Returns an array suitable for spatie/array-to-xml repeated element handling
     */
    private static function buildContentsArray(array $files, string $encodingType = '', bool $fetchOwner = false): array
    {
        $contents = [];
        foreach ($files as $file) {
            $key = $file['key'];
            if ($encodingType === 'url') {
                $key = rawurlencode($key);
            }

            $content = [
                'Key' => $key,
                'LastModified' => gmdate('Y-m-d\TH:i:s.000\Z', $file['timestamp']),
                'ETag' => self::formatEtag($file['etag'] ?? ''),
                'Size' => (string)(int)$file['size'],
                'StorageClass' => 'STANDARD',
            ];

            if ($fetchOwner) {
                $content['Owner'] = [
                    'ID' => 's3-server',
                    'DisplayName' => 's3-server',
                ];
            }

            $contents[] = $content;
        }

        return $contents;
    }

    /**
     * Build CommonPrefixes child array for XML
     */
    private static function buildCommonPrefixesArray(array $commonPrefixes, string $encodingType = ''): array
    {
        $nodes = [];
        foreach ($commonPrefixes as $prefix) {
            if ($encodingType === 'url') {
                $prefix = rawurlencode($prefix);
            }
            $nodes[] = ['Prefix' => $prefix];
        }
        return $nodes;
    }

    public static function createMultipartUpload(string $bucket, string $key, string $uploadId): string
    {
        return ArrayToXml::convert([
            'Bucket' => $bucket,
            'Key' => $key,
            'UploadId' => $uploadId,
        ], self::rootElement('InitiateMultipartUploadResult'), false);
    }

    public static function completeMultipartUpload(string $bucket, string $key, string $location, string $etag, int $size): string
    {
        return ArrayToXml::convert([
            'Location' => $location,
            'Bucket' => $bucket,
            'Key' => $key,
            'ETag' => self::formatEtag($etag),
            'Size' => (string)$size,
        ], self::rootElement('CompleteMultipartUploadResult'), false);
    }

    public static function listParts(string $bucket, string $key, string $uploadId, array $parts): string
    {
        $partNodes = [];
        foreach ($parts as $part) {
            $partNodes[] = [
                'PartNumber' => (string)(int)$part['number'],
                'LastModified' => gmdate('Y-m-d\TH:i:s.000\Z', $part['mtime'] ?? $part['timestamp']),
                'ETag' => self::formatEtag($part['etag']),
                'Size' => (string)(int)$part['size'],
            ];
        }

        $data = [
            'Bucket' => $bucket,
            'Key' => $key,
            'UploadId' => $uploadId,
            'MaxParts' => '1000',
            'IsTruncated' => 'false',
        ];

        if (!empty($partNodes)) {
            $data['Part'] = $partNodes;
        }

        return ArrayToXml::convert($data, self::rootElement('ListPartsResult'), false);
    }

    public static function copyObject(string $etag, int $lastModified): string
    {
        return ArrayToXml::convert([
            'LastModified' => gmdate('Y-m-d\TH:i:s.000\Z', $lastModified),
            'ETag' => self::formatEtag($etag),
        ], self::rootElement('CopyObjectResult'), false);
    }

    public static function deleteObjects(array $deleted, array $errors): string
    {
        $data = [];

        $deletedNodes = [];
        foreach ($deleted as $key) {
            $deletedNodes[] = ['Key' => $key];
        }
        if (!empty($deletedNodes)) {
            $data['Deleted'] = $deletedNodes;
        }

        $errorNodes = [];
        foreach ($errors as $error) {
            $errorNodes[] = [
                'Key' => $error['key'],
                'Code' => $error['code'],
                'Message' => $error['message'],
            ];
        }
        if (!empty($errorNodes)) {
            $data['Error'] = $errorNodes;
        }

        return ArrayToXml::convert($data, self::rootElement('DeleteResult'), false);
    }

    /**
     * Format ETag with surrounding quotes if not already present
     */
    private static function formatEtag(string $etag): string
    {
        if ($etag !== '' && !str_starts_with($etag, '"')) {
            return '"' . $etag . '"';
        }
        return $etag;
    }
}
