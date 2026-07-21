<?php

namespace S3Gateway\S3;

use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\Storage\FileStorage;

class ObjectController
{
    private FileStorage $storage;

    public function __construct(FileStorage $storage)
    {
        $this->storage = $storage;
    }

    public function putObject(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if (empty($key)) {
            throw S3Exception::invalidRequest('Key required');
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $copySource = $request->getHeader('X-Amz-Copy-Source');

        if ($copySource) {
            $this->handleCopyObject($copySource, $bucket, $key, $response);
            return;
        }

        $body = $request->getBody();

        if (!$this->storage->putObjectFromString($bucket, $key, $body)) {
            throw S3Exception::internalError('Failed to write object file', "/{$bucket}/{$key}");
        }

        $etag = $this->storage->getMetaReader()->calculateEtag(
            $this->storage->getPathResolver()->canonicalizeKey($key),
            strlen($body)
        );

        $response
            ->setHeader('ETag', '"' . $etag . '"')
            ->setHeader('Content-Type', 'application/xml')
            ->sendEmpty(200);
    }

    private function handleCopyObject(string $copySource, string $destBucket, string $destKey, Response $response): void
    {
        $copySource = rawurldecode($copySource);
        $copySource = ltrim($copySource, '/');
        $sourceParts = explode('/', $copySource, 2);

        if (count($sourceParts) < 2) {
            throw S3Exception::invalidRequest('Invalid x-amz-copy-source header format');
        }

        $sourceBucket = $sourceParts[0];
        $sourceKey = $sourceParts[1];

        if (str_contains($sourceKey, '?versionId=')) {
            [$sourceKey, ] = explode('?versionId=', $sourceKey, 2);
        }

        $sourcePath = $this->storage->getPathResolver()->objectPath($sourceBucket, $sourceKey);
        $destPath = $this->storage->getPathResolver()->objectPath($destBucket, $destKey);

        if (!file_exists($sourcePath)) {
            throw S3Exception::noSuchKey($copySource);
        }

        if (!$this->storage->copyObject($sourceBucket, $sourceKey, $destBucket, $destKey)) {
            throw S3Exception::internalError('Failed to copy object', "/{$destBucket}/{$destKey}");
        }

        $meta = $this->storage->getObjectMeta($destBucket, $destKey);
        if ($meta === null) {
            throw S3Exception::internalError('Failed to read object metadata', "/{$destBucket}/{$destKey}");
        }

        $etag = $this->storage->getMetaReader()->calculateEtag(
            $this->storage->getPathResolver()->canonicalizeKey($destKey),
            $meta['size']
        );
        $lastModified = $meta['mtime'];

        $xml = XmlResponse::copyObject('"' . $etag . '"', $lastModified);

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    public function getObject(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();

        if (empty($bucket) || empty($key)) {
            throw S3Exception::invalidRequest('Bucket and key required');
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $filePath = $this->storage->getPathResolver()->objectPath($bucket, $key);

        // is_file covers both "not exists" and "is a directory" (key maps to a folder).
        if (!is_file($filePath)) {
            throw S3Exception::noSuchKey("/{$bucket}/{$key}");
        }

        $meta = $this->storage->getObjectMeta($bucket, $key);
        if ($meta === null) {
            throw S3Exception::noSuchKey("/{$bucket}/{$key}");
        }

        $fileSize = $meta['size'];
        $rangeHeader = $request->getHeader('Range') ?? '';
        $options = [
            'filename' => basename(rawurldecode($key)),
            'mime' => $meta['mime'],
            'etag' => $meta['etag'],
            'lastModified' => $meta['mtime'],
        ];

        if ($rangeHeader) {
            $rangeInfo = $this->parseRangeHeader($rangeHeader, $fileSize);

            if ($rangeInfo === null) {
                throw S3Exception::rangeNotSatisfiable("/{$bucket}/{$key}");
            }

            $options['start'] = $rangeInfo['start'];
            $options['end'] = $rangeInfo['end'];
            $options['partial'] = true;
        }

        $response->sendFile($filePath, $options);
    }

    private function parseRangeHeader(string $rangeHeader, int $fileSize): ?array
    {
        $rangeHeader = trim($rangeHeader);

        if (preg_match('/^bytes=(\d+)-(\d*)$/', $rangeHeader, $matches)) {
            $start = (int)$matches[1];

            if ($matches[2] !== '') {
                $end = (int)$matches[2];
            } else {
                $end = $fileSize - 1;
            }

            if ($start < 0 || $start >= $fileSize) {
                return null;
            }

            if ($end >= $fileSize) {
                $end = $fileSize - 1;
            }

            if ($start > $end) {
                return null;
            }

            return ['start' => $start, 'end' => $end];
        }

        if (preg_match('/^bytes=-(\d+)$/', $rangeHeader, $matches)) {
            $suffix = (int)$matches[1];

            // bytes=-0 means "last 0 bytes" → unsatisfiable (RFC 7233). Return null
            // so the caller emits 416 instead of serving the whole file as 206.
            if ($suffix <= 0) {
                return null;
            }

            if ($suffix > $fileSize) {
                $suffix = $fileSize;
            }

            $start = $fileSize - $suffix;
            return ['start' => $start, 'end' => $fileSize - 1];
        }

        return null;
    }

    public function headObject(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();

        if (empty($bucket) || empty($key)) {
            throw S3Exception::invalidRequest('Bucket and key required');
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $meta = $this->storage->getObjectMeta($bucket, $key);

        if ($meta === null) {
            throw S3Exception::noSuchKey("/{$bucket}/{$key}");
        }

        // Mirror GET's Content-Disposition so HEAD exposes the same metadata.
        $filename = basename(rawurldecode($key));
        $asciiFallback = preg_replace('/[^\x20-\x7e]/', '_', $filename);
        $asciiFallback = str_replace('"', '\\"', $asciiFallback);
        $disposition = 'inline; filename="' . $asciiFallback . '"; filename*=UTF-8\'\'' . rawurlencode($filename);

        $response
            ->setHeader('Content-Length', (string)$meta['size'])
            ->setHeader('Content-Type', $meta['mime'])
            ->setHeader('Content-Disposition', $disposition)
            ->setHeader('Last-Modified', gmdate('D, d M Y H:i:s \G\M\T', $meta['mtime']))
            ->setHeader('ETag', '"' . $meta['etag'] . '"')
            ->setHeader('Accept-Ranges', 'bytes')
            ->sendEmpty(200);
    }

    public function deleteObject(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        if (empty($key)) {
            throw S3Exception::invalidRequest('Key required');
        }

        $this->storage->deleteObject($bucket, $key);
        $response->sendEmpty(204);
    }

    public function deleteObjects(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        $input = $request->getBody();

        if (empty($input)) {
            throw S3Exception::invalidXML();
        }

        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($input);

        if (!$xml) {
            throw S3Exception::invalidXML();
        }

        $objectCount = count($xml->Object);
        if ($objectCount > 1000) {
            throw S3Exception::invalidRequest('Cannot delete more than 1000 keys in a single request');
        }

        $deleted = [];
        $errors = [];
        $seen = [];

        foreach ($xml->Object as $object) {
            $key = (string)($object->Key ?? '');
            if (empty($key)) {
                continue;
            }

            // Deduplicate: a repeated Key should appear only once in the response.
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;

            if ($this->storage->objectExists($bucket, $key)) {
                if ($this->storage->deleteObject($bucket, $key)) {
                    $deleted[] = $key;
                } else {
                    $errors[] = [
                        'key' => $key,
                        'code' => 'InternalError',
                        'message' => 'Error deleting file'
                    ];
                }
            } else {
                $deleted[] = $key;
            }
        }

        $xml = XmlResponse::deleteObjects($deleted, $errors);

        $response
            ->setStatusCode(200)
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }
}
