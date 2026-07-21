<?php

namespace S3Gateway\Tests\S3;

use PHPUnit\Framework\TestCase;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\S3\BucketController;
use S3Gateway\Storage\FileStorage;
use S3Gateway\Tests\ResetsConfig;

class BucketControllerTest extends TestCase
{
    use ResetsConfig;

    private BucketController $controller;
    private FileStorage $storage;
    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_bucket_test_' . uniqid();
        $this->resetConfig($this->testDir);
        $this->storage = new FileStorage();
        $this->controller = new BucketController($this->storage);
    }

    protected function tearDown(): void
    {
        $this->cleanupDir($this->testDir);
    }

    private function createRequest(string $method, string $uri, string $queryString = '', array $extraServer = []): Request
    {
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['REQUEST_URI'] = $uri;
        $_SERVER['QUERY_STRING'] = $queryString;
        foreach ($extraServer as $key => $value) {
            $_SERVER[$key] = $value;
        }
        return new Request();
    }

    // ─── List Buckets ────────────────────────────────────────────────

    public function testListBucketsEmpty(): void
    {
        $request = $this->createRequest('GET', '/');
        $response = new Response();

        ob_start();
        $this->controller->listBuckets($request, $response);
        $output = ob_get_clean();

        $this->assertStringContainsString('ListAllMyBucketsResult', $output);
        $this->assertStringContainsString('s3-server', $output);
    }

    public function testListBucketsWithBuckets(): void
    {
        $this->storage->createBucket('test-bucket-a');
        $this->storage->createBucket('test-bucket-b');

        $request = $this->createRequest('GET', '/');
        $response = new Response();

        ob_start();
        $this->controller->listBuckets($request, $response);
        $output = ob_get_clean();

        $parsed = simplexml_load_string($output);
        $this->assertNotFalse($parsed);
        $bucketNames = [];
        foreach ($parsed->Buckets->Bucket as $bucket) {
            $bucketNames[] = (string)$bucket->Name;
        }
        $this->assertContains('test-bucket-a', $bucketNames);
        $this->assertContains('test-bucket-b', $bucketNames);
    }

    // ─── Create Bucket ───────────────────────────────────────────────

    public function testCreateBucket(): void
    {
        $request = $this->createRequest('PUT', '/new-bucket');
        $response = new Response();

        ob_start();
        $this->controller->createBucket($request, $response);
        ob_end_clean();

        $this->assertTrue($this->storage->bucketExists('new-bucket'));
    }

    // ─── Delete Bucket ───────────────────────────────────────────────

    public function testDeleteBucket(): void
    {
        $this->storage->createBucket('del-bucket');

        $request = $this->createRequest('DELETE', '/del-bucket');
        $response = new Response();

        ob_start();
        $this->controller->deleteBucket($request, $response);
        ob_end_clean();

        $this->assertFalse($this->storage->bucketExists('del-bucket'));
    }

    public function testDeleteNonExistentBucket(): void
    {
        $request = $this->createRequest('DELETE', '/no-such-bucket');
        $response = new Response();

        $this->expectException(\S3Gateway\Exception\S3Exception::class);
        $this->controller->deleteBucket($request, $response);
    }

    public function testCreateBucketWithInvalidNameThrowsInvalidBucketName(): void
    {
        // Uppercase letters are rejected by PathResolver::validateBucketName.
        // The controller must surface this as InvalidBucketName (400), not let
        // the InvalidArgumentException bubble up as InvalidRequest.
        $request = $this->createRequest('PUT', '/INVALID-BUCKET');
        $response = new Response();

        try {
            $this->controller->createBucket($request, $response);
            $this->fail('Expected InvalidBucketName exception');
        } catch (\S3Gateway\Exception\S3Exception $e) {
            $this->assertEquals('InvalidBucketName', $e->getS3Code());
            $this->assertEquals(400, $e->getHttpStatus());
        }
    }

    // ─── List Objects V1 ─────────────────────────────────────────────

    public function testListObjectsV1(): void
    {
        $this->storage->createBucket('list-v1-bucket');
        $this->storage->putObjectFromString('list-v1-bucket', 'file1.txt', 'data1');
        $this->storage->putObjectFromString('list-v1-bucket', 'file2.txt', 'data2');

        $request = $this->createRequest('GET', '/list-v1-bucket');
        $response = new Response();

        ob_start();
        $this->controller->listObjects($request, $response);
        $output = ob_get_clean();

        $parsed = simplexml_load_string($output);
        $this->assertNotFalse($parsed);
        $this->assertEquals('list-v1-bucket', (string)$parsed->Name);
        $this->assertCount(2, $parsed->Contents);
    }

    public function testListObjectsV1WithMarker(): void
    {
        $this->storage->createBucket('marker-v1-bucket');
        $this->storage->putObjectFromString('marker-v1-bucket', 'a.txt', 'a');
        $this->storage->putObjectFromString('marker-v1-bucket', 'b.txt', 'b');
        $this->storage->putObjectFromString('marker-v1-bucket', 'c.txt', 'c');

        $request = $this->createRequest('GET', '/marker-v1-bucket', 'marker=a.txt');
        $response = new Response();

        ob_start();
        $this->controller->listObjects($request, $response);
        $output = ob_get_clean();

        $parsed = simplexml_load_string($output);
        $this->assertNotFalse($parsed);
        $this->assertEquals('a.txt', (string)$parsed->Marker);
        // Should only contain b.txt and c.txt
        $this->assertCount(2, $parsed->Contents);
    }

    // ─── List Objects V2 ─────────────────────────────────────────────

    public function testListObjectsV2(): void
    {
        $this->storage->createBucket('list-v2-bucket');
        $this->storage->putObjectFromString('list-v2-bucket', 'file1.txt', 'data1');

        $request = $this->createRequest('GET', '/list-v2-bucket', 'list-type=2');
        $response = new Response();

        ob_start();
        $this->controller->listObjectsV2($request, $response);
        $output = ob_get_clean();

        $parsed = simplexml_load_string($output);
        $this->assertNotFalse($parsed);
        $this->assertEquals('list-v2-bucket', (string)$parsed->Name);
        $this->assertEquals('1', (string)$parsed->KeyCount);
    }

    public function testListObjectsV2WithStartAfter(): void
    {
        $this->storage->createBucket('startafter-v2-bucket');
        $this->storage->putObjectFromString('startafter-v2-bucket', 'a.txt', 'a');
        $this->storage->putObjectFromString('startafter-v2-bucket', 'b.txt', 'b');

        $request = $this->createRequest('GET', '/startafter-v2-bucket', 'list-type=2&start-after=a.txt');
        $response = new Response();

        ob_start();
        $this->controller->listObjectsV2($request, $response);
        $output = ob_get_clean();

        $parsed = simplexml_load_string($output);
        $this->assertNotFalse($parsed);
        $this->assertEquals('a.txt', (string)$parsed->StartAfter);
        $this->assertEquals('1', (string)$parsed->KeyCount);
    }

    public function testListObjectsV2WithDelimiter(): void
    {
        $this->storage->createBucket('delim-v2-bucket');
        $this->storage->putObjectFromString('delim-v2-bucket', 'photos/img.jpg', 'img');
        $this->storage->putObjectFromString('delim-v2-bucket', 'readme.txt', 'readme');

        $request = $this->createRequest('GET', '/delim-v2-bucket', 'list-type=2&delimiter=/');
        $response = new Response();

        ob_start();
        $this->controller->listObjectsV2($request, $response);
        $output = ob_get_clean();

        $parsed = simplexml_load_string($output);
        $this->assertNotFalse($parsed);
        $this->assertEquals('/', (string)$parsed->Delimiter);
        $this->assertCount(1, $parsed->CommonPrefixes);
        $this->assertEquals('photos/', (string)$parsed->CommonPrefixes->Prefix);
        $this->assertCount(1, $parsed->Contents);
    }
}
