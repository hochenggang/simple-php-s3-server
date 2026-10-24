<?php

namespace S3Gateway\Tests\Storage;

use PHPUnit\Framework\TestCase;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\S3\BucketController;
use S3Gateway\S3\ObjectController;
use S3Gateway\S3\MultipartController;
use S3Gateway\Storage\FileStorage;
use S3Gateway\Storage\Storage;
use S3Gateway\Storage\StorageFactory;
use S3Gateway\Tests\ResetsConfig;

/** Controllers must work with a backend exposing no paths or filesystem helpers. */
class BackendBoundaryTest extends TestCase
{
    use ResetsConfig;

    protected function setUp(): void
    {
        $this->resetConfig(sys_get_temp_dir() . '/unused-s3-backend');
    }

    private function request(string $method, string $uri, string $body = '', string $query = '', string $range = ''): Request
    {
        $_SERVER = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'QUERY_STRING' => $query];
        if ($range !== '') {
            $_SERVER['HTTP_RANGE'] = $range;
        }
        $request = new Request();
        (new \ReflectionProperty(Request::class, 'body'))->setValue($request, $body);
        return $request;
    }

    private function response(): Response
    {
        return new class extends Response {
            public string $content = '';
            public array $options = [];
            public array $capturedHeaders = [];
            public $stream;
            public function setHeader(string $name, string $value): self
            {
                $this->capturedHeaders[$name] = $value;
                return parent::setHeader($name, $value);
            }
            public function setBody(string $body): self
            {
                $this->content = $body;
                return parent::setBody($body);
            }
            public function send(): void {}
            public function sendEmpty(int $statusCode = 204): void {}
            public function sendStream($stream, int $length, array $options = []): void
            {
                $this->stream = $stream;
                $this->content = stream_get_contents($stream, $length);
                $this->options = $options;
            }
        };
    }

    public function testPutUsesBackendMetadataRatherThanFilesystemEtag(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->method('bucketExists')->willReturn(true);
        $storage->expects(self::once())->method('putObjectFromStream')->willReturnCallback(function ($bucket, $key, $stream) {
            self::assertSame('remote-bucket', $bucket);
            self::assertSame('key', $key);
            self::assertSame("a\0b", stream_get_contents($stream));
            return ['size' => 3, 'mtime' => 1700000000, 'mime' => 'application/octet-stream', 'etag' => 'backend-generation'];
        });
        $response = $this->response();
        (new ObjectController($storage))->putObject($this->request('PUT', '/remote-bucket/key', "a\0b"), $response);
        self::assertSame('"backend-generation"', $response->capturedHeaders['ETag']);
    }

    public function testRangeGetOpensBackendRangeAndClosesReturnedStream(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->method('bucketExists')->willReturn(true);
        $storage->method('getObjectMeta')->willReturn(['size' => 10, 'mtime' => 1700000000, 'mime' => 'text/plain', 'etag' => 'remote-etag']);
        $storage->expects(self::once())->method('openObject')->with('remote-bucket', 'key', 2, 4)->willReturnCallback(function () {
            $stream = fopen('php://temp', 'w+b');
            fwrite($stream, '2345');
            rewind($stream);
            return $stream;
        });
        $response = $this->response();
        (new ObjectController($storage))->getObject($this->request('GET', '/remote-bucket/key', range: 'bytes=2-5'), $response);
        self::assertSame('2345', $response->content);
        self::assertTrue($response->options['partial']);
        self::assertSame(10, $response->options['size']);
        self::assertSame('remote-etag', $response->options['etag']);
        self::assertFalse(is_resource($response->stream));
    }

    public function testCopyUsesBackendExistenceAndDestinationMetadata(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->method('bucketExists')->willReturn(true);
        $storage->expects(self::once())->method('objectExists')->with('source-bucket', 'key')->willReturn(true);
        $storage->expects(self::once())->method('copyObject')->with('source-bucket', 'key', 'dest-bucket', 'copy')->willReturn(true);
        $storage->method('getObjectMeta')->willReturn(['size' => 9, 'mtime' => 1700000000, 'mime' => 'text/plain', 'etag' => 'copy-generation']);
        $request = $this->request('PUT', '/dest-bucket/copy');
        $_SERVER['HTTP_X_AMZ_COPY_SOURCE'] = '/source-bucket/key';
        $request = new Request();
        $response = $this->response();
        (new ObjectController($storage))->putObject($request, $response);
        self::assertStringContainsString('copy-generation', $response->content);
    }

    public function testBucketDatesComeFromBackendMetadata(): void
    {
        $storage = $this->createMock(Storage::class);
        $storage->method('listBuckets')->willReturn(['remote-bucket']);
        $storage->method('getBucketCreationTime')->with('remote-bucket')->willReturn(1700000000);
        $response = $this->response();
        (new BucketController($storage))->listBuckets($this->request('GET', '/'), $response);
        self::assertStringContainsString('2023-11-14T22:13:20.000Z', $response->content);
    }

    public function testEveryMultipartOperationRejectsUnsupportedBackend(): void
    {
        $controller = new MultipartController($this->createMock(Storage::class));
        foreach (['createMultipartUpload', 'uploadPart', 'listParts', 'completeMultipartUpload', 'abortMultipartUpload'] as $operation) {
            try {
                $controller->$operation($this->request('POST', '/remote-bucket/key'), $this->response());
                self::fail('Expected unsupported multipart error');
            } catch (S3Exception $e) {
                self::assertSame(501, $e->getHttpStatus());
                self::assertSame('NotImplemented', $e->getS3Code());
            }
        }
    }

    public function testFactoryValidatesBackendClass(): void
    {
        $this->setConfigValue('STORAGE_CLASS', \stdClass::class);
        $this->expectException(\InvalidArgumentException::class);
        StorageFactory::create();
    }

    public function testFilesystemStreamsPreserveExistingObjectOnInvalidInput(): void
    {
        $directory = sys_get_temp_dir() . '/s3-stream-write-' . bin2hex(random_bytes(6));
        $this->resetConfig($directory);
        try {
            $storage = new FileStorage();
            $storage->createBucket('test-bucket');
            $storage->putObjectFromString('test-bucket', 'key', 'original');
            self::assertNull($storage->putObjectFromStream('test-bucket', 'key', null));
            $original = $storage->openObject('test-bucket', 'key');
            self::assertSame('original', stream_get_contents($original));
            fclose($original);
            $input = fopen('php://temp', 'w+b');
            fwrite($input, 'skipreplacement');
            fseek($input, 4);
            $meta = $storage->putObjectFromStream('test-bucket', 'key', $input);
            self::assertSame(11, $meta['size']);
            self::assertIsResource($input);
            fclose($input);
            $output = $storage->openObject('test-bucket', 'key', 2, 4);
            self::assertSame('plac', fread($output, 4));
            fclose($output);
        } finally {
            $this->cleanupDir($directory);
        }
    }

    public function testResponseDoesNotRequireSeekableInputAndKeepsOwnership(): void
    {
        $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        if ($pair === false) {
            self::markTestSkipped('Socket pairs are unavailable');
        }
        [$stream, $writer] = $pair;
        fwrite($writer, 'payload-tail');
        fclose($writer);
        self::assertFalse(stream_get_meta_data($stream)['seekable']);
        ob_start();
        (new Response())->sendStream($stream, 7, ['mime' => 'application/octet-stream']);
        self::assertSame('payload', ob_get_clean());
        self::assertIsResource($stream);
        self::assertSame('-tail', stream_get_contents($stream));
        fclose($stream);
    }
}
