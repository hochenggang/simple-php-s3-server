<?php

namespace S3Gateway\S3;

use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\Storage\FileStorage;

class BucketController
{
    private FileStorage $storage;

    public function __construct(FileStorage $storage)
    {
        $this->storage = $storage;
    }

    public function listBuckets(Request $request, Response $response): void
    {
        $buckets = $this->storage->listBuckets();
        $dataDir = $this->storage->getPathResolver()->getDataDir();
        $xml = XmlResponse::listBuckets($buckets, $dataDir);

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    public function createBucket(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if ($this->storage->bucketExists($bucket)) {
            throw S3Exception::bucketAlreadyExists($bucket);
        }

        if (!$this->storage->createBucket($bucket)) {
            throw S3Exception::internalError('Failed to create bucket', '/' . $bucket);
        }

        $response->sendEmpty(200);
    }

    public function deleteBucket(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        if (!$this->storage->isBucketEmpty($bucket)) {
            throw S3Exception::bucketNotEmpty($bucket);
        }

        if (!$this->storage->deleteBucket($bucket)) {
            throw S3Exception::internalError('Failed to delete bucket', '/' . $bucket);
        }

        $response->sendEmpty(204);
    }

    public function listObjects(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $prefix = $request->getQueryParam('prefix') ?? '';
        $maxKeys = (int)($request->getQueryParam('max-keys') ?? 1000);
        $delimiter = $request->getQueryParam('delimiter') ?? '';

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $result = $this->storage->listObjects($bucket, $prefix, $maxKeys);

        $xml = XmlResponse::listObjects($result['objects'], $bucket, $prefix);

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    public function listObjectsV2(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $prefix = $request->getQueryParam('prefix') ?? '';
        $maxKeys = (int)($request->getQueryParam('max-keys') ?? 1000);
        $continuationToken = $request->getQueryParam('continuation-token') ?? '';
        $startAfter = $request->getQueryParam('start-after') ?? '';
        $fetchOwner = strtolower($request->getQueryParam('fetch-owner') ?? '') === 'true';

        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $skip = 0;
        if ($continuationToken) {
            $skip = (int)base64_decode($continuationToken);
        }

        $result = $this->storage->listObjects($bucket, $prefix, $maxKeys, $skip);

        $nextToken = '';
        if ($result['isTruncated']) {
            $nextToken = base64_encode((string)($skip + count($result['objects'])));
        }

        $xml = XmlResponse::listObjectsV2(
            $result['objects'],
            $bucket,
            $prefix,
            $maxKeys,
            $continuationToken,
            $nextToken,
            $startAfter,
            $fetchOwner
        );

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }
}
