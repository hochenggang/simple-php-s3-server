<?php

namespace S3Gateway\Tests\Storage;

use PHPUnit\Framework\TestCase;
use S3Gateway\Storage\SidecarStore;
use S3Gateway\Storage\FileStorage;
use S3Gateway\Tests\ResetsConfig;

/** Content ETags (MD5) as S3 clients such as rclone verify them. */
class SidecarStoreTest extends TestCase
{
    use ResetsConfig;

    private FileStorage $storage;
    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_etag_test_' . uniqid();
        $this->resetConfig($this->testDir);
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '0');
        $this->storage = new FileStorage();
        $this->storage->createBucket('bucket');
    }

    protected function tearDown(): void
    {
        $this->cleanupDir($this->testDir);
    }

    /** @return resource */
    private static function streamOf(string $bytes)
    {
        $s = fopen('php://temp', 'w+b');
        fwrite($s, $bytes);
        rewind($s);
        return $s;
    }

    private function listedEtags(): array
    {
        return array_column($this->storage->listObjects('bucket', '', 1000)['objects'], 'etag', 'key');
    }

    public function testPutFromStreamReturnsAndListsContentMd5(): void
    {
        $payload = random_bytes(200000);
        $meta = $this->storage->putObjectFromStream('bucket', 'dir/blob.bin', self::streamOf($payload));

        $this->assertSame(md5($payload), $meta['etag']);
        $this->assertSame(md5($payload), $this->storage->getObjectMeta('bucket', 'dir/blob.bin')['etag']);
        $this->assertSame(['dir/blob.bin' => md5($payload)], $this->listedEtags());
    }

    public function testOverwriteWithSameSizeChangesEtag(): void
    {
        $this->storage->putObjectFromStream('bucket', 'a.txt', self::streamOf('aaaa'));
        $meta = $this->storage->putObjectFromStream('bucket', 'a.txt', self::streamOf('bbbb'));
        $this->assertSame(md5('bbbb'), $meta['etag']);
        $this->assertSame(['a.txt' => md5('bbbb')], $this->listedEtags());
    }

    public function testSidecarsStayOutOfListingsAndBuckets(): void
    {
        $this->storage->putObjectFromStream('bucket', 'a.txt', self::streamOf('x'));
        $this->assertFileExists($this->testDir . '/.meta/bucket/a.txt.json');
        $this->assertSame(['a.txt'], array_keys($this->listedEtags()));
        $this->assertSame(['bucket'], $this->storage->listBuckets());
    }

    public function testCopyKeepsSourceEtag(): void
    {
        $this->storage->putObjectFromStream('bucket', 'src.txt', self::streamOf('copy me'));
        $this->assertTrue($this->storage->copyObject('bucket', 'src.txt', 'bucket', 'dst.txt'));
        $this->assertSame(md5('copy me'), $this->storage->getObjectMeta('bucket', 'dst.txt')['etag']);
    }

    public function testMultipartUsesPartMd5sAndS3CompositeEtag(): void
    {
        $uploadId = bin2hex(random_bytes(16));
        $this->storage->createMultipartUpload('bucket', $uploadId);
        $one = random_bytes(5000);
        $two = random_bytes(3000);
        $partOne = $this->storage->savePartFromStream('bucket', $uploadId, 1, self::streamOf($one));
        $this->assertTrue($this->storage->savePart('bucket', $uploadId, 2, $two));

        $this->assertSame(md5($one), $partOne['etag']);
        $this->assertSame([md5($one), md5($two)], array_column($this->storage->listParts('bucket', $uploadId), 'etag'));

        $result = $this->storage->completeMultipartUpload('bucket', 'big.bin', $uploadId, [1 => true, 2 => true]);
        $expected = md5(md5($one, true) . md5($two, true)) . '-2';
        $this->assertSame($expected, $result['etag']);
        $this->assertSame($expected, $this->storage->getObjectMeta('bucket', 'big.bin')['etag']);
        $this->assertSame(['big.bin' => $expected], $this->listedEtags());
    }

    public function testPartSidecarsAreNotParts(): void
    {
        $uploadId = bin2hex(random_bytes(16));
        $this->storage->createMultipartUpload('bucket', $uploadId);
        $this->storage->savePart('bucket', $uploadId, 1, 'part');
        $this->assertFileExists($this->testDir . "/bucket/.multipart/{$uploadId}/1.meta.json");
        $this->assertSame([1], array_column($this->storage->listParts('bucket', $uploadId), 'number'));
    }

    public function testDeleteRemovesSidecarAndEmptyDirectories(): void
    {
        $this->storage->putObjectFromStream('bucket', 'deep/er/a.txt', self::streamOf('x'));
        $this->assertTrue($this->storage->deleteObject('bucket', 'deep/er/a.txt'));
        $this->assertFileDoesNotExist($this->testDir . '/.meta/bucket/deep');
    }

    public function testDeleteBucketRemovesItsSidecars(): void
    {
        $this->storage->putObjectFromStream('bucket', 'a.txt', self::streamOf('x'));
        // Simulate a leftover sidecar without its object.
        $this->storage->deleteObject('bucket', 'a.txt');
        @mkdir($this->testDir . '/.meta/bucket', 0755, true);
        file_put_contents($this->testDir . '/.meta/bucket/orphan.json', '{}');

        $this->assertTrue($this->storage->deleteBucket('bucket'));
        $this->assertFileDoesNotExist($this->testDir . '/.meta/bucket');
    }

    public function testMissingOrStaleSidecarIsRepairedFromContent(): void
    {
        $this->storage->putObjectFromStream('bucket', 'a.txt', self::streamOf('first'));
        $sidecar = $this->testDir . '/.meta/bucket/a.txt.json';

        // Crash after the object was replaced but before its sidecar: the old
        // sidecar still describes the previous file (different inode).
        $path = $this->testDir . '/bucket/a.txt';
        file_put_contents($path . '.new', 'second');
        rename($path . '.new', $path);
        $this->assertSame(md5('second'), $this->storage->getObjectMeta('bucket', 'a.txt')['etag']);

        unlink($sidecar);
        $this->assertSame(md5('second'), $this->storage->getObjectMeta('bucket', 'a.txt')['etag']);
        $this->assertFileExists($sidecar);
    }

    public function testStaleSidecarDropsMetadata(): void
    {
        $this->storage->putObjectFromStream('bucket', 'a.txt', self::streamOf('first'), new \S3Gateway\Storage\ObjectMetadata('text/x-first', ['mtime' => '1']));

        // Content replaced on disk: the recorded metadata no longer applies.
        $path = $this->testDir . '/bucket/a.txt';
        file_put_contents($path . '.new', 'second');
        rename($path . '.new', $path);

        $meta = $this->storage->getObjectMeta('bucket', 'a.txt');
        $this->assertSame(md5('second'), $meta['etag']);
        $this->assertSame([], $meta['metadata']);
        $this->assertNotSame('text/x-first', $meta['mime']);
    }

    public function testMultipartEtagFormat(): void
    {
        $this->assertSame(md5(md5('a', true)) . '-1', SidecarStore::multipartEtag([md5('a')]));
    }
}
