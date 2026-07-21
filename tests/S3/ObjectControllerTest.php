<?php

namespace S3Gateway\Tests\S3;

use PHPUnit\Framework\TestCase;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\S3\ObjectController;
use S3Gateway\Storage\FileStorage;
use S3Gateway\Tests\ResetsConfig;

class ObjectControllerTest extends TestCase
{
    use ResetsConfig;

    private ObjectController $controller;
    private FileStorage $storage;
    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_object_test_' . uniqid();
        $this->resetConfig($this->testDir);
        $this->storage = new FileStorage();
        $this->controller = new ObjectController($this->storage);
    }

    protected function tearDown(): void
    {
        $this->cleanupDir($this->testDir);
    }

    private function createRequest(string $method, string $uri, string $queryString = ''): Request
    {
        $_SERVER['REQUEST_METHOD'] = $method;
        $_SERVER['REQUEST_URI'] = $uri;
        $_SERVER['QUERY_STRING'] = $queryString;
        return new Request();
    }

    public function testGetObjectReturnsContentAndMetadataHeaders(): void
    {
        $this->storage->createBucket('obj-bucket');
        $this->storage->putObjectFromString('obj-bucket', 'file.txt', 'hello world');

        $request = $this->createRequest('GET', '/obj-bucket/file.txt');

        // Spy that captures the options getObject hands to sendFile, instead of
        // emitting headers (headers_list() is unreliable in the CLI SAPI).
        $response = new class extends Response {
            public ?string $capturedFile = null;
            public array $capturedOptions = [];
            public function sendFile(string $filePath, array $options = []): void
            {
                $this->capturedFile = $filePath;
                $this->capturedOptions = $options;
            }
        };

        $this->controller->getObject($request, $response);

        $this->assertNotNull($response->capturedFile);
        $this->assertEquals('hello world', file_get_contents($response->capturedFile));

        // GET must pass through the same metadata HEAD exposes.
        $this->assertNotEmpty($response->capturedOptions['etag']);
        $this->assertArrayHasKey('lastModified', $response->capturedOptions);
        $this->assertArrayHasKey('mime', $response->capturedOptions);
        $this->assertEquals('file.txt', $response->capturedOptions['filename']);
    }

    public function testGetObjectOnDirectoryKeyReturnsNoSuchKey(): void
    {
        $this->storage->createBucket('dir-bucket');
        // Putting a nested key creates the 'folder' directory on disk.
        $this->storage->putObjectFromString('dir-bucket', 'folder/file.txt', 'data');

        $request = $this->createRequest('GET', '/dir-bucket/folder');
        $response = new Response();

        $this->expectException(S3Exception::class);
        $this->controller->getObject($request, $response);
    }

    public function testGetObjectOnMissingKeyReturnsNoSuchKey(): void
    {
        $this->storage->createBucket('missing-bucket');

        $request = $this->createRequest('GET', '/missing-bucket/nope.txt');
        $response = new Response();

        $this->expectException(S3Exception::class);
        $this->controller->getObject($request, $response);
    }

    public function testPutThenListEtagConsistency(): void
    {
        $this->storage->createBucket('etag-bucket');
        $this->storage->putObjectFromString('etag-bucket', 'my%20file.txt', 'test data');

        // ETag as calculated by putObject's controller logic (canonicalizeKey)
        $expectedEtag = $this->storage->getMetaReader()->calculateEtag(
            $this->storage->getPathResolver()->canonicalizeKey('my%20file.txt'),
            strlen('test data')
        );

        // ETag as returned by LIST (from disk, decoded key)
        $result = $this->storage->listObjects('etag-bucket');
        $this->assertCount(1, $result['objects']);
        $this->assertEquals($expectedEtag, $result['objects'][0]['etag']);
    }

    public function testCopyThenListEtagConsistency(): void
    {
        $this->storage->createBucket('copy-bucket');
        $this->storage->putObjectFromString('copy-bucket', 'source.txt', 'data');
        $this->storage->copyObject('copy-bucket', 'source.txt', 'copy-bucket', 'dest%20file.txt');

        // ETag as calculated by handleCopyObject's controller logic (canonicalizeKey)
        $expectedEtag = $this->storage->getMetaReader()->calculateEtag(
            $this->storage->getPathResolver()->canonicalizeKey('dest%20file.txt'),
            4 // strlen('data')
        );

        // ETag as returned by LIST (from disk, decoded key)
        $result = $this->storage->listObjects('copy-bucket');
        $destObj = null;
        foreach ($result['objects'] as $obj) {
            if ($obj['key'] === 'dest file.txt') {
                $destObj = $obj;
                break;
            }
        }
        $this->assertNotNull($destObj, 'Copied object not found in LIST');
        $this->assertEquals($expectedEtag, $destObj['etag']);
    }

    public function testGetObjectOnNonExistentBucketThrowsNoSuchBucket(): void
    {
        $request = $this->createRequest('GET', '/nonexistent-bucket/file.txt');
        $response = new Response();

        try {
            $this->controller->getObject($request, $response);
            $this->fail('Expected NoSuchBucket exception');
        } catch (S3Exception $e) {
            $this->assertEquals('NoSuchBucket', $e->getS3Code());
            $this->assertEquals(404, $e->getHttpStatus());
        }
    }

    public function testDeleteObjectsRejectsTooManyKeys(): void
    {
        $this->storage->createBucket('del-bucket');

        // Build XML with 1001 keys
        $xml = '<Delete>';
        for ($i = 0; $i < 1001; $i++) {
            $xml .= '<Object><Key>file' . $i . '.txt</Key></Object>';
        }
        $xml .= '</Delete>';

        $request = $this->createRequest('POST', '/del-bucket', 'delete');
        $bodyRef = new \ReflectionProperty(Request::class, 'body');
        $bodyRef->setValue($request, $xml);

        $response = new Response();

        try {
            $this->controller->deleteObjects($request, $response);
            $this->fail('Expected InvalidRequest exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidRequest', $e->getS3Code());
        }
    }
}