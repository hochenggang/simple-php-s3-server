<?php

namespace S3Gateway\Storage;

/** Backend-neutral operations. Keys are opaque identifiers, not paths. */
interface Storage
{
    public function validateBucketName(string $bucket): void;
    /** @return list<string> */
    public function listBuckets(): array;
    public function getBucketCreationTime(string $bucket): int;
    public function createBucket(string $bucket): bool;
    public function deleteBucket(string $bucket): bool;
    public function bucketExists(string $bucket): bool;
    public function isBucketEmpty(string $bucket): bool;
    public function listObjects(string $bucket, string $prefix = '', int $maxKeys = 1000, int $skip = 0, string $delimiter = '', string $startAfter = '', string $marker = ''): array;
    /** @return array{size:int,mtime:int,mime:string,etag:string}|null */
    public function getObjectMeta(string $bucket, string $key): ?array;
    /** @return resource|false Caller-owned readable stream at the requested offset; need not be seekable. */
    public function openObject(string $bucket, string $key, int $start = 0, ?int $length = null);
    /** Consume input at its current position; do not close it. Return committed metadata or null on failure. */
    public function putObjectFromStream(string $bucket, string $key, $input): ?array;
    public function copyObject(string $sourceBucket, string $sourceKey, string $destBucket, string $destKey): bool;
    public function deleteObject(string $bucket, string $key): bool;
    public function objectExists(string $bucket, string $key): bool;
}
