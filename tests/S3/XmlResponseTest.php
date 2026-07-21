<?php

namespace S3Gateway\Tests\S3;

use PHPUnit\Framework\TestCase;
use S3Gateway\S3\XmlResponse;

class XmlResponseTest extends TestCase
{
    public function testError(): void
    {
        $xml = XmlResponse::error('NoSuchBucket', 'The bucket does not exist', '/mybucket');

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        $this->assertEquals('NoSuchBucket', (string)$parsed->Code);
        $this->assertEquals('The bucket does not exist', (string)$parsed->Message);
        $this->assertEquals('/mybucket', (string)$parsed->Resource);
        $this->assertNotEmpty((string)$parsed->RequestId);
    }

    public function testListBuckets(): void
    {
        $tmpDir = sys_get_temp_dir();
        $xml = XmlResponse::listBuckets(['bucket-a', 'bucket-b'], $tmpDir);

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        $this->assertEquals('s3-server', (string)$parsed->Owner->ID);
        $bucketNames = [];
        foreach ($parsed->Buckets->Bucket as $bucket) {
            $bucketNames[] = (string)$bucket->Name;
        }
        $this->assertCount(2, $bucketNames);
        $this->assertContains('bucket-a', $bucketNames);
        $this->assertContains('bucket-b', $bucketNames);
    }

    public function testListBucketsEmpty(): void
    {
        $xml = XmlResponse::listBuckets([], sys_get_temp_dir());

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        $this->assertEquals('s3-server', (string)$parsed->Owner->ID);
        // Empty buckets list - Buckets element exists but no Bucket children
        $this->assertEquals(0, $parsed->Buckets->Bucket->count());
    }

    public function testListObjectsV1(): void
    {
        $files = [
            ['key' => 'file1.txt', 'size' => 100, 'timestamp' => time(), 'etag' => 'abc123'],
            ['key' => 'file2.txt', 'size' => 200, 'timestamp' => time(), 'etag' => 'def456'],
        ];

        $xml = XmlResponse::listObjects($files, 'mybucket', 'dir/', 1000, '', '', [], false);

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        $this->assertEquals('mybucket', (string)$parsed->Name);
        $this->assertEquals('dir/', (string)$parsed->Prefix);
        $this->assertEquals('1000', (string)$parsed->MaxKeys);
        $this->assertEquals('false', (string)$parsed->IsTruncated);
        $this->assertCount(2, $parsed->Contents);
    }

    public function testListObjectsV1WithMarker(): void
    {
        $files = [
            ['key' => 'b.txt', 'size' => 50, 'timestamp' => time(), 'etag' => 'xyz'],
        ];

        $xml = XmlResponse::listObjects($files, 'mybucket', '', 1000, 'a.txt', '', [], false);

        $parsed = simplexml_load_string($xml);
        $this->assertEquals('a.txt', (string)$parsed->Marker);
    }

    public function testListObjectsV1WithDelimiter(): void
    {
        $files = [
            ['key' => 'readme.txt', 'size' => 50, 'timestamp' => time(), 'etag' => 'xyz'],
        ];

        $xml = XmlResponse::listObjects($files, 'mybucket', '', 1000, '', '/', ['photos/'], true);

        $parsed = simplexml_load_string($xml);
        $this->assertEquals('/', (string)$parsed->Delimiter);
        $this->assertEquals('true', (string)$parsed->IsTruncated);
        $this->assertCount(1, $parsed->CommonPrefixes);
        $this->assertEquals('photos/', (string)$parsed->CommonPrefixes->Prefix);
    }

    public function testListObjectsV2(): void
    {
        $files = [
            ['key' => 'file1.txt', 'size' => 100, 'timestamp' => time(), 'etag' => 'abc123'],
        ];

        $xml = XmlResponse::listObjectsV2(
            $files, 'mybucket', '', 1000,
            '', '', '', false, '', [], ''
        );

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        $this->assertEquals('mybucket', (string)$parsed->Name);
        $this->assertEquals('1', (string)$parsed->KeyCount);
        $this->assertEquals('false', (string)$parsed->IsTruncated);
    }

    public function testListObjectsV2WithContinuationToken(): void
    {
        $files = [];

        $xml = XmlResponse::listObjectsV2(
            $files, 'mybucket', '', 1000,
            'token123', 'nextToken456', 'after-key', true, '/', ['dir/'], 'url'
        );

        $parsed = simplexml_load_string($xml);
        $this->assertEquals('token123', (string)$parsed->ContinuationToken);
        $this->assertEquals('nextToken456', (string)$parsed->NextContinuationToken);
        $this->assertEquals('after-key', (string)$parsed->StartAfter);
        $this->assertEquals('true', (string)$parsed->IsTruncated);
        $this->assertEquals('/', (string)$parsed->Delimiter);
        $this->assertEquals('url', (string)$parsed->EncodingType);
        $this->assertCount(1, $parsed->CommonPrefixes);
    }

    public function testListObjectsV2WithFetchOwner(): void
    {
        $files = [
            ['key' => 'file1.txt', 'size' => 100, 'timestamp' => time(), 'etag' => 'abc'],
        ];

        $xml = XmlResponse::listObjectsV2(
            $files, 'mybucket', '', 1000,
            '', '', '', true, '', [], ''
        );

        $parsed = simplexml_load_string($xml);
        $this->assertEquals('s3-server', (string)$parsed->Contents->Owner->ID);
    }

    public function testCreateMultipartUpload(): void
    {
        $xml = XmlResponse::createMultipartUpload('mybucket', 'file.txt', 'upload123');

        $parsed = simplexml_load_string($xml);
        $this->assertEquals('mybucket', (string)$parsed->Bucket);
        $this->assertEquals('file.txt', (string)$parsed->Key);
        $this->assertEquals('upload123', (string)$parsed->UploadId);
    }

    public function testCompleteMultipartUpload(): void
    {
        $xml = XmlResponse::completeMultipartUpload('mybucket', 'file.txt', 'http://example.com', 'abc123', 1024);

        $parsed = simplexml_load_string($xml);
        $this->assertEquals('mybucket', (string)$parsed->Bucket);
        $this->assertEquals('file.txt', (string)$parsed->Key);
        $this->assertEquals('"abc123"', (string)$parsed->ETag);
        $this->assertEquals('1024', (string)$parsed->Size);
    }

    public function testListParts(): void
    {
        $parts = [
            ['number' => 1, 'size' => 100, 'mtime' => time(), 'etag' => 'abc'],
            ['number' => 2, 'size' => 200, 'mtime' => time(), 'etag' => 'def'],
        ];

        $xml = XmlResponse::listParts('mybucket', 'file.txt', 'upload123', $parts);

        $parsed = simplexml_load_string($xml);
        $this->assertCount(2, $parsed->Part);
        $this->assertEquals('1', (string)$parsed->Part[0]->PartNumber);
    }

    public function testCopyObject(): void
    {
        $xml = XmlResponse::copyObject('abc123', time());

        $parsed = simplexml_load_string($xml);
        $this->assertEquals('"abc123"', (string)$parsed->ETag);
    }

    public function testDeleteObjects(): void
    {
        $xml = XmlResponse::deleteObjects(['file1.txt', 'file2.txt'], []);

        $parsed = simplexml_load_string($xml);
        $this->assertCount(2, $parsed->Deleted);
        $keys = [];
        foreach ($parsed->Deleted as $d) {
            $keys[] = (string)$d->Key;
        }
        $this->assertContains('file1.txt', $keys);
        $this->assertContains('file2.txt', $keys);
    }

    public function testDeleteObjectsWithErrors(): void
    {
        $errors = [
            ['key' => 'locked.txt', 'code' => 'AccessDenied', 'message' => 'Object is locked'],
        ];

        $xml = XmlResponse::deleteObjects(['file1.txt'], $errors);

        $parsed = simplexml_load_string($xml);
        $this->assertCount(1, $parsed->Deleted);
        $this->assertCount(1, $parsed->Error);
        $this->assertEquals('AccessDenied', (string)$parsed->Error->Code);
    }

    public function testXssEscapingInError(): void
    {
        $xml = XmlResponse::error('Test', '<script>alert("xss")</script>');

        $this->assertStringNotContainsString('<script>', $xml);
        $this->assertStringContainsString('&lt;script&gt;', $xml);
    }

    public function testListObjectsV1NextMarker(): void
    {
        $files = [
            ['key' => 'photos/img1.jpg', 'size' => 100, 'timestamp' => time(), 'etag' => 'abc'],
        ];

        $xml = XmlResponse::listObjects(
            $files, 'mybucket', '', 1, '', '/', ['photos/'], true, '', 'photos/'
        );

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        $this->assertEquals('true', (string)$parsed->IsTruncated);
        $this->assertEquals('/', (string)$parsed->Delimiter);
        $this->assertEquals('photos/', (string)$parsed->NextMarker);
    }

    public function testListObjectsV2KeyCountOnlyFiles(): void
    {
        $files = [
            ['key' => 'file1.txt', 'size' => 100, 'timestamp' => time(), 'etag' => 'abc'],
        ];

        $xml = XmlResponse::listObjectsV2(
            $files, 'mybucket', '', 1000,
            '', '', '', false, '/', ['dir1/', 'dir2/'], ''
        );

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        // KeyCount counts only files (Contents), not common prefixes
        $this->assertEquals('1', (string)$parsed->KeyCount);
        $this->assertCount(2, $parsed->CommonPrefixes);
    }

    public function testCommonPrefixesUrlEncoded(): void
    {
        $files = [];
        $commonPrefixes = ['dir with space/', 'dir+plus/'];

        $xml = XmlResponse::listObjectsV2(
            $files, 'mybucket', '', 1000,
            '', '', '', false, '/', $commonPrefixes, 'url'
        );

        $parsed = simplexml_load_string($xml);
        $this->assertNotFalse($parsed);
        // Iterate each <CommonPrefixes> sibling, then read its <Prefix>.
        // Using ->CommonPrefixes->Prefix directly only yields the first sibling's child.
        $prefixes = [];
        foreach ($parsed->CommonPrefixes as $cp) {
            $prefixes[] = (string)$cp->Prefix;
        }
        $this->assertContains(rawurlencode('dir with space/'), $prefixes);
        $this->assertContains(rawurlencode('dir+plus/'), $prefixes);
    }
}
