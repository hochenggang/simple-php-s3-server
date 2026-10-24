<?php

namespace S3Gateway\Exception;

class S3Exception extends \Exception
{
    private string $s3Code;
    private string $resource;

    public function __construct(string $s3Code, string $message, int $httpStatus, string $resource = '')
    {
        parent::__construct($message, $httpStatus);
        $this->s3Code = $s3Code;
        $this->resource = $resource;
    }

    public function getS3Code(): string
    {
        return $this->s3Code;
    }

    public function getResource(): string
    {
        return $this->resource;
    }

    public function getHttpStatus(): int
    {
        return $this->code;
    }

    public static function accessDenied(string $message = 'Access Denied'): self
    {
        return new self('AccessDenied', $message, 401);
    }

    public static function invalidAccessKeyId(): self
    {
        return new self('InvalidAccessKeyId', 'The AWS Access Key Id you provided does not exist in our records.', 403);
    }

    public static function signatureDoesNotMatch(string $message = 'The request signature we calculated does not match the signature you provided.'): self
    {
        return new self('SignatureDoesNotMatch', $message, 403);
    }

    public static function noSuchBucket(string $resource = ''): self
    {
        return new self('NoSuchBucket', 'The specified bucket does not exist', 404, $resource);
    }

    public static function noSuchKey(string $resource = ''): self
    {
        return new self('NoSuchKey', 'The specified key does not exist.', 404, $resource);
    }

    public static function bucketAlreadyExists(string $bucket): self
    {
        return new self('BucketAlreadyExists', 'The requested bucket name is not available.', 409, '/' . $bucket);
    }

    public static function bucketNotEmpty(string $bucket): self
    {
        return new self('BucketNotEmpty', 'The bucket you tried to delete is not empty.', 409, '/' . $bucket);
    }

    public static function invalidBucketName(): self
    {
        return new self('InvalidBucketName', 'The specified bucket is not valid.', 400);
    }

    public static function invalidRequest(string $message = 'Invalid request'): self
    {
        return new self('InvalidRequest', $message, 400);
    }

    public static function invalidArgument(string $message): self
    {
        return new self('InvalidArgument', $message, 400);
    }

    public static function metadataTooLarge(): self
    {
        return new self('MetadataTooLarge', 'Your metadata headers exceed the maximum allowed metadata size.', 400);
    }

    public static function invalidXML(string $resource = ''): self
    {
        return new self('MalformedXML', 'The XML you provided was not well-formed.', 400, $resource);
    }

    public static function internalError(string $message = 'Internal Error', string $resource = ''): self
    {
        return new self('InternalError', $message, 500, $resource);
    }

    public static function methodNotAllowed(): self
    {
        return new self('MethodNotAllowed', 'The specified method is not allowed against this resource.', 405);
    }

    public static function noSuchUpload(string $resource = ''): self
    {
        return new self('NoSuchUpload', 'The specified multipart upload does not exist.', 404, $resource);
    }

    public static function invalidPart(string $message = 'Invalid part', string $resource = ''): self
    {
        return new self('InvalidPart', $message, 400, $resource);
    }

    public static function entityTooLarge(int $actualSize, int $maxSize): self
    {
        return new self('EntityTooLarge', "Your proposed upload exceeds the maximum allowed size. Actual: {$actualSize}, Max: {$maxSize}", 400);
    }

    public static function rangeNotSatisfiable(string $resource = ''): self
    {
        return new self('InvalidRange', 'The requested range cannot be satisfied.', 416, $resource);
    }

    public static function expiredToken(string $message = 'The provided token has expired.'): self
    {
        return new self('ExpiredToken', $message, 400);
    }

    public static function xAmzContentSha256Mismatch(): self
    {
        return new self(
            'XAmzContentSHA256Mismatch',
            'The provided x-amz-content-sha256 header does not match what was computed.',
            400
        );
    }

    public static function xAmzContentChecksumInvalid(string $message = 'Provided value did not match the computed checksum', string $resource = ''): self
    {
        return new self('XAmzContentChecksumInvalid', $message, 400, $resource);
    }
}
