<?php

namespace S3Gateway\Tests\S3;

use PHPUnit\Framework\TestCase;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\S3\MultipartController;
use S3Gateway\Storage\FileStorage;
use S3Gateway\Tests\ResetsConfig;

class MultipartControllerTest extends TestCase
{
    use ResetsConfig;

    private MultipartController $controller;
    private FileStorage $storage;
    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_multipart_test_' . uniqid();
        $this->resetConfig($this->testDir);
        $this->storage = new FileStorage();
        $this->controller = new MultipartController($this->storage);
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

    /**
     * completeMultipartUpload builds the Location header from the request Host.
     * A HEAD/GET-style fallback to localhost is exercised to ensure Config import
     * (regression: MultipartController previously called Config::trustProxyHeaders()
     * without importing S3Gateway\Config, turning every complete into a 500).
     */
    public function testCompleteMultipartUploadReturnsLocationAndEtag(): void
    {
        $this->storage->createBucket('mp-bucket');

        // Initiate multipart upload via the controller so we exercise the full path.
        $initRequest = $this->createRequest('POST', '/mp-bucket/merged.txt', 'uploads=');
        $initResponse = new class extends Response {
            public string $capturedBody = '';
            public function setBody(string $body): self
            {
                $this->capturedBody = $body;
                return parent::setBody($body);
            }
            public function send(): void
            {
                // Suppress CLI header emission noise.
            }
        };
        $this->controller->createMultipartUpload($initRequest, $initResponse);

        $parsed = simplexml_load_string($initResponse->capturedBody);
        $this->assertNotFalse($parsed);
        $uploadId = (string)$parsed->UploadId;

        // Upload two parts directly through storage (controller uploadPart path
        // is covered indirectly; here we focus on completion).
        $this->storage->savePart('mp-bucket', $uploadId, 1, 'part1data');
        $this->storage->savePart('mp-bucket', $uploadId, 2, 'part2data');

        $part1Etag = $this->storage->getMetaReader()->getPartMeta('mp-bucket', $uploadId, 1)['etag'];
        $part2Etag = $this->storage->getMetaReader()->getPartMeta('mp-bucket', $uploadId, 2)['etag'];

        $completeXml = '<CompleteMultipartUpload>'
            . '<Part><PartNumber>1</PartNumber><ETag>"' . $part1Etag . '"</ETag></Part>'
            . '<Part><PartNumber>2</PartNumber><ETag>"' . $part2Etag . '"</ETag></Part>'
            . '</CompleteMultipartUpload>';

        $_SERVER['HTTP_HOST'] = 'mp-example.local';
        $completeRequest = $this->createRequest('POST', '/mp-bucket/merged.txt', 'uploadId=' . $uploadId);
        $bodyRef = new \ReflectionProperty(Request::class, 'body');
        $bodyRef->setValue($completeRequest, $completeXml);

        $completeResponse = new class extends Response {
            public string $capturedBody = '';
            public function setBody(string $body): self
            {
                $this->capturedBody = $body;
                return parent::setBody($body);
            }
            public function send(): void
            {
            }
        };

        // This must NOT throw — the Config import regression would surface as
        // an uncaught Error here.
        $this->controller->completeMultipartUpload($completeRequest, $completeResponse);

        $result = simplexml_load_string($completeResponse->capturedBody);
        $this->assertNotFalse($result);
        $this->assertEquals('mp-bucket', (string)$result->Bucket);
        $this->assertEquals('merged.txt', (string)$result->Key);
        // 'part1data' (9) + 'part2data' (9) = 18 bytes
        $this->assertEquals('18', (string)$result->Size);
        $this->assertStringContainsString('mp-example.local', (string)$result->Location);
        $this->assertTrue($this->storage->objectExists('mp-bucket', 'merged.txt'));

        unset($_SERVER['HTTP_HOST']);
    }

    public function testCompleteMultipartUploadRejectsEtagMismatch(): void
    {
        $this->storage->createBucket('mp-mismatch-bucket');
        $uploadId = bin2hex(random_bytes(16));
        $this->storage->createMultipartUpload('mp-mismatch-bucket', $uploadId);
        $this->storage->savePart('mp-mismatch-bucket', $uploadId, 1, 'part1data');

        $completeXml = '<CompleteMultipartUpload>'
            . '<Part><PartNumber>1</PartNumber><ETag>"deadbeef"</ETag></Part>'
            . '</CompleteMultipartUpload>';

        $request = $this->createRequest('POST', '/mp-mismatch-bucket/merged.txt', 'uploadId=' . $uploadId);
        $bodyRef = new \ReflectionProperty(Request::class, 'body');
        $bodyRef->setValue($request, $completeXml);

        try {
            $this->controller->completeMultipartUpload($request, new Response());
            $this->fail('Expected InvalidPart exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidPart', $e->getS3Code());
            $this->assertEquals(400, $e->getHttpStatus());
        }
    }
}
