<?php

namespace S3Gateway\Tests\Storage;

use PHPUnit\Framework\TestCase;
use S3Gateway\Storage\MetaReader;
use S3Gateway\Storage\PathResolver;
use S3Gateway\Tests\ResetsConfig;

class MetaReaderTest extends TestCase
{
    use ResetsConfig;

    private MetaReader $metaReader;
    private string $testDir;
    private string $bucketDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_meta_test_' . uniqid();
        $this->resetConfig($this->testDir);

        $pathResolver = new PathResolver();
        $this->metaReader = new MetaReader($pathResolver);

        // Create test bucket and file
        $this->bucketDir = $this->testDir . '/test-bucket';
        mkdir($this->bucketDir, 0755, true);
        file_put_contents($this->bucketDir . '/test.txt', 'hello world');
    }

    protected function tearDown(): void
    {
        $this->cleanupDir($this->testDir);
    }

    public function testGetObjectMeta(): void
    {
        $meta = $this->metaReader->getObjectMeta('test-bucket', 'test.txt');

        $this->assertNotNull($meta);
        $this->assertEquals(11, $meta['size']); // 'hello world' = 11 bytes
        $this->assertArrayHasKey('mtime', $meta);
        $this->assertArrayHasKey('mime', $meta);
        $this->assertArrayHasKey('etag', $meta);
    }

    public function testGetObjectMetaNotFound(): void
    {
        $meta = $this->metaReader->getObjectMeta('test-bucket', 'nonexistent.txt');
        $this->assertNull($meta);
    }

    public function testEtagIsContentMd5(): void
    {
        // Files without a sidecar (written out of band or by older versions)
        // get their MD5 computed on first access.
        $meta = $this->metaReader->getObjectMeta('test-bucket', 'test.txt');
        $this->assertSame(md5('hello world'), $meta['etag']);
    }

    public function testEtagFollowsContentChangesOfSameSize(): void
    {
        $this->assertSame(md5('hello world'), $this->metaReader->getObjectMeta('test-bucket', 'test.txt')['etag']);

        // Same size, different content, replaced out of band (new inode).
        $path = $this->bucketDir . '/test.txt';
        file_put_contents($path . '.new', 'HELLO WORLD');
        rename($path . '.new', $path);
        $this->assertSame(md5('HELLO WORLD'), $this->metaReader->getObjectMeta('test-bucket', 'test.txt')['etag']);
    }

    public function testGetFileSize(): void
    {
        $filePath = $this->bucketDir . '/test.txt';
        $this->assertEquals(11, $this->metaReader->getFileSize($filePath));
    }

    public function testGetFileSizeNotFound(): void
    {
        $this->assertEquals(0, $this->metaReader->getFileSize('/nonexistent/file.txt'));
    }

    public function testGetPartMeta(): void
    {
        // Use a valid 32-hex uploadId (matches production format).
        $uploadId = bin2hex(random_bytes(16));

        // Create multipart dir and part file
        $mpDir = $this->bucketDir . '/.multipart/' . $uploadId;
        mkdir($mpDir, 0755, true);
        file_put_contents($mpDir . '/1', 'part data');

        $meta = $this->metaReader->getPartMeta('test-bucket', $uploadId, 1);

        $this->assertNotNull($meta);
        $this->assertEquals(1, $meta['number']);
        $this->assertEquals(9, $meta['size']); // 'part data' = 9 bytes
        $this->assertArrayHasKey('etag', $meta);
    }

    public function testEtagConsistencyForEncodedKey(): void
    {
        // Write a file whose key contains a character that differs between
        // URL-encoded and decoded forms.
        file_put_contents($this->bucketDir . '/my file.txt', 'data');

        $meta = $this->metaReader->getObjectMeta('test-bucket', 'my%20file.txt');

        $this->assertNotNull($meta);
        $this->assertEquals(md5('data'), $meta['etag']);
    }
}
