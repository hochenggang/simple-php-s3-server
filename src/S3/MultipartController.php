<?php

namespace S3Gateway\S3;

use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\Storage\FileStorage;

class MultipartController
{
    private FileStorage $storage;

    public function __construct(FileStorage $storage)
    {
        $this->storage = $storage;
    }

    public function createMultipartUpload(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if (empty($key)) {
            throw S3Exception::invalidRequest('Key required for multipart upload');
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $uploadId = bin2hex(random_bytes(16));

        if (!$this->storage->createMultipartUpload($bucket, $uploadId)) {
            throw S3Exception::internalError('Failed to create multipart upload', "/{$bucket}/{$key}");
        }

        $xml = XmlResponse::createMultipartUpload($bucket, $key, $uploadId);

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    public function uploadPart(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();
        $uploadId = $request->getQueryParam('uploadId');
        $partNumber = (int)$request->getQueryParam('partNumber');

        if (empty($bucket) || empty($key)) {
            throw S3Exception::invalidRequest('Bucket and key required');
        }

        if (empty($uploadId)) {
            throw S3Exception::invalidRequest('uploadId required');
        }

        if ($partNumber <= 0) {
            throw S3Exception::invalidRequest('Invalid partNumber');
        }

        $uploadDir = $this->storage->getPathResolver()->multipartPath($bucket, $uploadId);
        if (!file_exists($uploadDir)) {
            throw S3Exception::noSuchUpload("/{$bucket}/{$key}");
        }

        $body = $request->getBody();

        if (!$this->storage->savePart($bucket, $uploadId, $partNumber, $body)) {
            throw S3Exception::internalError('Failed to write part file', "/{$bucket}/{$key}");
        }

        $partMeta = $this->storage->getMetaReader()->getPartMeta($bucket, $uploadId, $partNumber);
        if ($partMeta === null) {
            throw S3Exception::internalError('Failed to read part metadata', "/{$bucket}/{$key}");
        }

        $response
            ->setHeader('ETag', '"' . $partMeta['etag'] . '"')
            ->sendEmpty(200);
    }

    public function listParts(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();
        $uploadId = $request->getQueryParam('uploadId');

        if (empty($bucket) || empty($key)) {
            throw S3Exception::invalidRequest('Bucket and key required');
        }

        if (empty($uploadId)) {
            throw S3Exception::invalidRequest('uploadId required');
        }

        $uploadDir = $this->storage->getPathResolver()->multipartPath($bucket, $uploadId);
        if (!file_exists($uploadDir)) {
            throw S3Exception::noSuchUpload("/{$bucket}/{$key}");
        }

        $parts = $this->storage->listParts($bucket, $uploadId);
        $xml = XmlResponse::listParts($bucket, $key, $uploadId, $parts);

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    public function completeMultipartUpload(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();
        $uploadId = $request->getQueryParam('uploadId');

        if (empty($bucket) || empty($key)) {
            throw S3Exception::invalidRequest('Bucket and key required');
        }

        if (empty($uploadId)) {
            throw S3Exception::invalidRequest('uploadId required');
        }

        $uploadDir = $this->storage->getPathResolver()->multipartPath($bucket, $uploadId);
        if (!file_exists($uploadDir)) {
            throw S3Exception::noSuchUpload("/{$bucket}/{$key}");
        }

        $input = $request->getBody();
        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($input);

        if (!$xml) {
            throw S3Exception::invalidXML("/{$bucket}/{$key}");
        }

        $parts = [];
        foreach ($xml->Part as $part) {
            $partNumber = (int)$part->PartNumber;
            $parts[$partNumber] = (string)$part->ETag;
        }

        if (empty($parts)) {
            throw S3Exception::invalidRequest('No parts specified', "/{$bucket}/{$key}");
        }

        foreach (array_keys($parts) as $partNumber) {
            $partPath = $this->storage->getPathResolver()->partPath($bucket, $uploadId, $partNumber);
            if (!file_exists($partPath)) {
                throw S3Exception::invalidPart("Part file missing: {$partNumber}", "/{$bucket}/{$key}");
            }
        }

        if (!$this->storage->completeMultipartUpload($bucket, $key, $uploadId, $parts)) {
            throw S3Exception::internalError('Failed to complete multipart upload', "/{$bucket}/{$key}");
        }

        $location = "http://{$_SERVER['HTTP_HOST']}/{$bucket}/{$key}";
        $xml = XmlResponse::completeMultipartUpload($bucket, $key, $location);

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    public function abortMultipartUpload(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $key = $request->getKey();
        $uploadId = $request->getQueryParam('uploadId');

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if (empty($uploadId)) {
            throw S3Exception::invalidRequest('uploadId required');
        }

        $this->storage->abortMultipartUpload($bucket, $uploadId);
        $response->sendEmpty(204);
    }
}
