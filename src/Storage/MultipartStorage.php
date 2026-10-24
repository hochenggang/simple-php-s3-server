<?php

namespace S3Gateway\Storage;

/** Optional capability; backends without it return S3 NotImplemented. */
interface MultipartStorage extends Storage
{
    public function createMultipartUpload(string $bucket, string $uploadId): bool;
    public function multipartUploadExists(string $bucket, string $uploadId): bool;
    public function getPartMeta(string $bucket, string $uploadId, int $partNumber): ?array;
    public function listParts(string $bucket, string $uploadId): array;
    /** Caller retains ownership of input. Return committed part metadata or null. */
    public function savePartFromStream(string $bucket, string $uploadId, int $partNumber, $input): ?array;
    public function completeMultipartUpload(string $bucket, string $key, string $uploadId, array $parts): ?array;
    public function abortMultipartUpload(string $bucket, string $uploadId): bool;
    /** @return array{removed:int,bytes:int} Remove uploads older than the Unix timestamp. */
    public function cleanupExpiredMultipartUploads(int $before): array;
}
