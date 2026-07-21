<?php

namespace S3Gateway\Tests\Exception;

use PHPUnit\Framework\TestCase;
use S3Gateway\Exception\S3Exception;

class S3ExceptionTest extends TestCase
{
    public function testAccessDenied(): void
    {
        $e = S3Exception::accessDenied();
        $this->assertEquals('AccessDenied', $e->getS3Code());
        $this->assertEquals(401, $e->getHttpStatus());
    }

    public function testNoSuchBucket(): void
    {
        $e = S3Exception::noSuchBucket('/mybucket');
        $this->assertEquals('NoSuchBucket', $e->getS3Code());
        $this->assertEquals(404, $e->getHttpStatus());
        $this->assertEquals('/mybucket', $e->getResource());
    }

    public function testNoSuchKey(): void
    {
        $e = S3Exception::noSuchKey('/bucket/key');
        $this->assertEquals('NoSuchKey', $e->getS3Code());
        $this->assertEquals(404, $e->getHttpStatus());
    }

    public function testBucketAlreadyExists(): void
    {
        $e = S3Exception::bucketAlreadyExists('mybucket');
        $this->assertEquals('BucketAlreadyExists', $e->getS3Code());
        $this->assertEquals(409, $e->getHttpStatus());
    }

    public function testBucketNotEmpty(): void
    {
        $e = S3Exception::bucketNotEmpty('mybucket');
        $this->assertEquals('BucketNotEmpty', $e->getS3Code());
        $this->assertEquals(409, $e->getHttpStatus());
    }

    public function testInvalidBucketName(): void
    {
        $e = S3Exception::invalidBucketName();
        $this->assertEquals('InvalidBucketName', $e->getS3Code());
        $this->assertEquals(400, $e->getHttpStatus());
    }

    public function testSignatureDoesNotMatch(): void
    {
        $e = S3Exception::signatureDoesNotMatch();
        $this->assertEquals('SignatureDoesNotMatch', $e->getS3Code());
        $this->assertEquals(403, $e->getHttpStatus());
    }

    public function testEntityTooLarge(): void
    {
        $e = S3Exception::entityTooLarge(5000, 1000);
        $this->assertEquals('EntityTooLarge', $e->getS3Code());
        $this->assertEquals(400, $e->getHttpStatus());
        $this->assertStringContainsString('5000', $e->getMessage());
    }

    public function testExpiredToken(): void
    {
        $e = S3Exception::expiredToken();
        $this->assertEquals('ExpiredToken', $e->getS3Code());
        $this->assertEquals(400, $e->getHttpStatus());
    }

    public function testInternalError(): void
    {
        $e = S3Exception::internalError('Something went wrong', '/resource');
        $this->assertEquals('InternalError', $e->getS3Code());
        $this->assertEquals(500, $e->getHttpStatus());
        $this->assertEquals('/resource', $e->getResource());
    }
}
