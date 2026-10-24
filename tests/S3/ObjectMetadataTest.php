<?php

namespace S3Gateway\Tests\S3;

use PHPUnit\Framework\TestCase;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\S3\MultipartController;
use S3Gateway\S3\ObjectController;
use S3Gateway\Storage\FileStorage;
use S3Gateway\Storage\ObjectMetadata;
use S3Gateway\Tests\ResetsConfig;

/** Content-Type and x-amz-meta-* user metadata, as rclone uses for modification times. */
class ObjectMetadataTest extends TestCase
{
    use ResetsConfig;

    private FileStorage $storage;
    private ObjectController $objects;
    private string $testDir;
    private array $originalServer;

    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
        $this->testDir = sys_get_temp_dir() . '/s3gateway_metadata_test_' . uniqid();
        $this->resetConfig($this->testDir);
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '0');
        $this->storage = new FileStorage();
        $this->objects = new ObjectController($this->storage);
        $this->storage->createBucket('bucket');
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;
        $this->cleanupDir($this->testDir);
    }

    /** @param array<string,string> $server extra $_SERVER entries (headers as HTTP_*) */
    private function request(string $method, string $uri, array $server = [], string $body = '', string $query = ''): Request
    {
        $_SERVER = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'QUERY_STRING' => $query] + $server;
        $input = fopen('php://temp', 'w+b');
        fwrite($input, $body);
        rewind($input);
        return new Request($input);
    }

    private function response(): Response
    {
        return new class extends Response {
            public array $captured = [];
            public string $body = '';
            public string $content = '';
            public function setHeader(string $name, string $value): self
            {
                $this->captured[$name] = $value;
                return parent::setHeader($name, $value);
            }
            public function setBody(string $body): self
            {
                $this->body = $body;
                return parent::setBody($body);
            }
            public function send(): void {}
            public function sendEmpty(int $statusCode = 204): void {}
            public function sendStream($stream, int $length, array $options = []): void
            {
                $this->captured['Content-Type'] = $options['mime'];
                $this->content = (string)stream_get_contents($stream, $length);
            }
        };
    }

    private function head(string $key): array
    {
        $response = $this->response();
        $this->objects->headObject($this->request('HEAD', '/bucket/' . $key), $response);
        return $response->captured;
    }

    private function put(string $key, string $body, array $server = []): void
    {
        $this->objects->putObject($this->request('PUT', '/bucket/' . $key, $server, $body), $this->response());
    }

    private function copy(string $from, string $to, array $server = []): void
    {
        $this->objects->putObject(
            $this->request('PUT', '/bucket/' . $to, ['HTTP_X_AMZ_COPY_SOURCE' => '/bucket/' . $from] + $server),
            $this->response()
        );
    }

    // ─── Storage ──────────────────────────────────────────────────────

    public function testStorageRoundTripsMetadata(): void
    {
        $in = fopen('php://temp', 'w+b');
        fwrite($in, 'data');
        rewind($in);
        $meta = $this->storage->putObjectFromStream('bucket', 'a.bin', $in, new ObjectMetadata('image/png', ['mtime' => '1710505845.0']));

        $this->assertSame('image/png', $meta['mime']);
        $this->assertSame(['mtime' => '1710505845.0'], $meta['metadata']);
    }

    public function testObjectsWithoutMetadataUseDetectedType(): void
    {
        $this->storage->putObjectFromString('bucket', 'plain.txt', 'hello');
        $meta = $this->storage->getObjectMeta('bucket', 'plain.txt');
        $this->assertSame('text/plain', $meta['mime']);
        $this->assertSame([], $meta['metadata']);
    }

    // ─── PUT / HEAD / GET ─────────────────────────────────────────────

    public function testPutStoresMetadataReturnedByHeadAndGet(): void
    {
        $this->put('photo.jpg', 'jpegdata', [
            'CONTENT_TYPE' => 'image/jpeg',
            'HTTP_X_AMZ_META_MTIME' => '1710505845.123',
            'HTTP_X_AMZ_META_OWNER' => 'pwa',
        ]);

        $head = $this->head('photo.jpg');
        $this->assertSame('image/jpeg', $head['Content-Type']);
        $this->assertSame('1710505845.123', $head['x-amz-meta-mtime']);
        $this->assertSame('pwa', $head['x-amz-meta-owner']);

        $response = $this->response();
        $this->objects->getObject($this->request('GET', '/bucket/photo.jpg'), $response);
        $this->assertSame('jpegdata', $response->content);
        $this->assertSame('image/jpeg', $response->captured['Content-Type']);
        $this->assertSame('1710505845.123', $response->captured['x-amz-meta-mtime']);
    }

    public function testOverwriteReplacesMetadata(): void
    {
        $this->put('a.txt', 'one', ['HTTP_X_AMZ_META_MTIME' => '1']);
        $this->put('a.txt', 'two');
        $this->assertArrayNotHasKey('x-amz-meta-mtime', $this->head('a.txt'));
    }

    public function testMetadataAboveTwoKilobytesIsRejected(): void
    {
        $this->expectException(S3Exception::class);
        try {
            $this->put('big.txt', 'x', ['HTTP_X_AMZ_META_NOTE' => str_repeat('a', 2045)]);
        } catch (S3Exception $e) {
            $this->assertSame('MetadataTooLarge', $e->getS3Code());
            $this->assertFalse($this->storage->objectExists('bucket', 'big.txt'));
            throw $e;
        }
    }

    // ─── CopyObject ───────────────────────────────────────────────────

    public function testCopyKeepsSourceMetadataByDefault(): void
    {
        $this->put('src.txt', 'data', ['CONTENT_TYPE' => 'text/x-src', 'HTTP_X_AMZ_META_MTIME' => '42']);
        $this->copy('src.txt', 'dst.txt', ['CONTENT_TYPE' => 'text/x-ignored', 'HTTP_X_AMZ_META_MTIME' => '99']);

        $head = $this->head('dst.txt');
        $this->assertSame('text/x-src', $head['Content-Type']);
        $this->assertSame('42', $head['x-amz-meta-mtime']);
    }

    public function testCopyWithReplaceDirectiveUsesRequestMetadata(): void
    {
        $this->put('src.txt', 'data', ['HTTP_X_AMZ_META_MTIME' => '42']);
        $this->copy('src.txt', 'dst.txt', [
            'HTTP_X_AMZ_METADATA_DIRECTIVE' => 'REPLACE',
            'CONTENT_TYPE' => 'text/x-new',
            'HTTP_X_AMZ_META_MTIME' => '99',
        ]);

        $head = $this->head('dst.txt');
        $this->assertSame('text/x-new', $head['Content-Type']);
        $this->assertSame('99', $head['x-amz-meta-mtime']);
        $this->assertSame('42', $this->head('src.txt')['x-amz-meta-mtime']);
    }

    public function testSelfCopyWithReplaceUpdatesOnlyMetadata(): void
    {
        // rclone sets modification times this way on every sync.
        $this->put('self.bin', 'unchanged content', ['HTTP_X_AMZ_META_MTIME' => '1']);
        $before = $this->storage->getObjectMeta('bucket', 'self.bin');

        $this->copy('self.bin', 'self.bin', ['HTTP_X_AMZ_METADATA_DIRECTIVE' => 'REPLACE', 'HTTP_X_AMZ_META_MTIME' => '2']);

        $after = $this->storage->getObjectMeta('bucket', 'self.bin');
        $this->assertSame(['mtime' => '2'], $after['metadata']);
        $this->assertSame($before['etag'], $after['etag']);
        $this->assertSame('unchanged content', file_get_contents($this->testDir . '/bucket/self.bin'));
    }

    public function testSelfCopyWithoutReplaceIsRejected(): void
    {
        $this->put('self.bin', 'content');
        $this->expectException(S3Exception::class);
        try {
            $this->copy('self.bin', 'self.bin');
        } catch (S3Exception $e) {
            $this->assertSame('InvalidRequest', $e->getS3Code());
            $this->assertSame('content', file_get_contents($this->testDir . '/bucket/self.bin'));
            throw $e;
        }
    }

    public function testUnknownMetadataDirectiveIsRejected(): void
    {
        $this->put('src.txt', 'data');
        $this->expectException(S3Exception::class);
        try {
            $this->copy('src.txt', 'dst.txt', ['HTTP_X_AMZ_METADATA_DIRECTIVE' => 'MERGE']);
        } catch (S3Exception $e) {
            $this->assertSame('InvalidArgument', $e->getS3Code());
            throw $e;
        }
    }

    // ─── Multipart ────────────────────────────────────────────────────

    public function testMultipartMetadataFromCreateIsAppliedOnCompletion(): void
    {
        $multipart = new MultipartController($this->storage);
        $created = $this->response();
        $multipart->createMultipartUpload($this->request('POST', '/bucket/big.bin', [
            'CONTENT_TYPE' => 'application/x-big',
            'HTTP_X_AMZ_META_MTIME' => '7',
        ], '', 'uploads='), $created);
        $uploadId = (string)simplexml_load_string($created->body)->UploadId;

        $this->storage->savePart('bucket', $uploadId, 1, 'part one');
        $etag = $this->storage->getPartMeta('bucket', $uploadId, 1)['etag'];
        $xml = '<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"' . $etag . '"</ETag></Part></CompleteMultipartUpload>';
        $multipart->completeMultipartUpload(
            $this->request('POST', '/bucket/big.bin', ['HTTP_HOST' => 'localhost', 'CONTENT_TYPE' => 'application/xml'], $xml, 'uploadId=' . $uploadId),
            $this->response()
        );

        $head = $this->head('big.bin');
        $this->assertSame('application/x-big', $head['Content-Type']);
        $this->assertSame('7', $head['x-amz-meta-mtime']);
    }
}
