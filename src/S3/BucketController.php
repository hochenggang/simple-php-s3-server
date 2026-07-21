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

        $this->validateBucket($bucket);

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

        $this->validateBucket($bucket);

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
        $this->validateBucket($bucket);

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $prefix = $request->getQueryParam('prefix') ?? '';
        $maxKeys = max(0, min(1000, (int)($request->getQueryParam('max-keys') ?? 1000)));
        $marker = $request->getQueryParam('marker') ?? '';
        $delimiter = $request->getQueryParam('delimiter') ?? '';
        $encodingType = $request->getQueryParam('encoding-type') ?? '';

        $result = $this->storage->listObjects(
            $bucket, $prefix, $maxKeys, 0, $delimiter, '', $marker
        );

        $xml = XmlResponse::listObjects(
            $result['objects'],
            $bucket,
            $prefix,
            $maxKeys,
            $marker,
            $delimiter,
            $result['commonPrefixes'],
            $result['isTruncated'],
            $encodingType,
            $result['nextMarker']
        );

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    public function listObjectsV2(Request $request, Response $response): void
    {
        $bucket = $request->getBucket();
        $this->validateBucket($bucket);

        if (!$this->storage->bucketExists($bucket)) {
            throw S3Exception::noSuchBucket('/' . $bucket);
        }

        $prefix = $request->getQueryParam('prefix') ?? '';
        $maxKeys = max(0, min(1000, (int)($request->getQueryParam('max-keys') ?? 1000)));
        $continuationToken = $request->getQueryParam('continuation-token') ?? '';
        $startAfter = $request->getQueryParam('start-after') ?? '';
        $fetchOwner = strtolower($request->getQueryParam('fetch-owner') ?? '') === 'true';
        $delimiter = $request->getQueryParam('delimiter') ?? '';
        $encodingType = $request->getQueryParam('encoding-type') ?? '';

        // token = urlSafeBase64(lastItem)，解码后作为 startAfter。
        // startAfter 仅在无 continuationToken 时生效（AWS 规范）。
        $effectiveStartAfter = '';
        if ($continuationToken !== '') {
            $decoded = self::decodeContinuationToken($continuationToken);
            if ($decoded === null) {
                throw S3Exception::invalidRequest('Invalid continuation token');
            }
            $effectiveStartAfter = $decoded;
        } elseif ($startAfter !== '') {
            $effectiveStartAfter = $startAfter;
        }

        $result = $this->storage->listObjects(
            $bucket, $prefix, $maxKeys, 0, $delimiter, $effectiveStartAfter
        );

        $nextToken = '';
        if ($result['isTruncated']) {
            $nextToken = self::encodeContinuationToken($result['nextMarker']);
        }

        $xml = XmlResponse::listObjectsV2(
            $result['objects'],
            $bucket,
            $prefix,
            $maxKeys,
            $continuationToken,
            $nextToken,
            $startAfter,
            $fetchOwner,
            $delimiter,
            $result['commonPrefixes'],
            $encodingType
        );

        $response
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    /**
     * URL-safe base64 编码：避免 + / 被 parse_str 解码为空格/路径分隔符。
     * = 填充保留（parse_str 对值中的 = 透明）。
     */
    private static function encodeContinuationToken(string $lastKey): string
    {
        return strtr(base64_encode($lastKey), '+/', '-_');
    }

    private static function decodeContinuationToken(string $token): ?string
    {
        $decoded = base64_decode(strtr($token, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    private function validateBucket(string $bucket): void
    {
        if (empty($bucket)) {
            throw S3Exception::invalidBucketName();
        }
    }
}
