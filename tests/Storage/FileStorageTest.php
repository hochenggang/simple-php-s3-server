<?php

namespace S3Gateway\Tests\Storage;

use PHPUnit\Framework\TestCase;
use S3Gateway\Storage\FileStorage;
use S3Gateway\Tests\ResetsConfig;

class FileStorageTest extends TestCase
{
    use ResetsConfig;

    private FileStorage $storage;
    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_storage_test_' . uniqid();
        $this->resetConfig($this->testDir);
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '0');
        $this->storage = new FileStorage();
    }

    protected function tearDown(): void
    {
        $this->cleanupDir($this->testDir);
    }

    private function createTestBucket(string $name): void
    {
        $this->storage->createBucket($name);
    }

    private function createTestObject(string $bucket, string $key, string $content = 'test'): void
    {
        $this->storage->putObjectFromString($bucket, $key, $content);
    }

    // ─── Bucket Operations ────────────────────────────────────────────

    public function testCreateBucket(): void
    {
        $this->assertTrue($this->storage->createBucket('test-bucket'));
        $this->assertTrue($this->storage->bucketExists('test-bucket'));
    }

    public function testCreateInvalidBucket(): void
    {
        $this->assertFalse($this->storage->createBucket('INVALID'));
    }

    public function testListBuckets(): void
    {
        $this->createTestBucket('bucket-a');
        $this->createTestBucket('bucket-b');

        $buckets = $this->storage->listBuckets();
        sort($buckets);
        $this->assertEquals(['bucket-a', 'bucket-b'], $buckets);
    }

    public function testListBucketsEmpty(): void
    {
        $buckets = $this->storage->listBuckets();
        $this->assertEquals([], $buckets);
    }

    public function testListObjectsCacheHitOnSecondCall(): void
    {
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '60');
        $this->createTestBucket('cache-bucket');
        $this->createTestObject('cache-bucket', 'a.txt');
        $this->createTestObject('cache-bucket', 'b.txt');

        // First call: scans filesystem and writes cache
        $result1 = $this->storage->listObjects('cache-bucket', '', 1000);

        $cacheFile = \Symfony\Component\Filesystem\Path::join(
            dirname(__DIR__, 2),
            'tmp',
            'listbuckets',
            'cache-bucket.json'
        );
        $this->assertFileExists($cacheFile);

        // Second call: hits cache, same result
        $result2 = $this->storage->listObjects('cache-bucket', '', 1000);

        $this->assertEquals(count($result1['objects']), count($result2['objects']));
        $this->assertEquals(2, count($result2['objects']));

        @unlink($cacheFile);
    }

    public function testDeleteBucket(): void
    {
        $this->createTestBucket('del-bucket');
        $this->assertTrue($this->storage->deleteBucket('del-bucket'));
        $this->assertFalse($this->storage->bucketExists('del-bucket'));
    }

    public function testDeleteNonEmptyBucket(): void
    {
        $this->createTestBucket('nonempty');
        $this->createTestObject('nonempty', 'file.txt');
        $this->assertFalse($this->storage->deleteBucket('nonempty'));
    }

    public function testIsBucketEmpty(): void
    {
        $this->createTestBucket('empty-bucket');
        $this->assertTrue($this->storage->isBucketEmpty('empty-bucket'));

        $this->createTestObject('empty-bucket', 'file.txt');
        $this->assertFalse($this->storage->isBucketEmpty('empty-bucket'));
    }

    // ─── Object CRUD ──────────────────────────────────────────────────

    public function testPutAndGetObject(): void
    {
        $this->createTestBucket('obj-bucket');
        $this->assertTrue($this->storage->putObjectFromString('obj-bucket', 'test.txt', 'hello world'));
        $this->assertTrue($this->storage->objectExists('obj-bucket', 'test.txt'));
    }

    public function testObjectExistsFalse(): void
    {
        $this->createTestBucket('obj-bucket');
        $this->assertFalse($this->storage->objectExists('obj-bucket', 'nonexistent.txt'));
    }

    public function testDeleteObject(): void
    {
        $this->createTestBucket('obj-bucket');
        $this->createTestObject('obj-bucket', 'del.txt', 'content');
        $this->assertTrue($this->storage->deleteObject('obj-bucket', 'del.txt'));
        $this->assertFalse($this->storage->objectExists('obj-bucket', 'del.txt'));
    }

    public function testDeleteNonExistentObject(): void
    {
        $this->createTestBucket('obj-bucket');
        $this->assertFalse($this->storage->deleteObject('obj-bucket', 'nope.txt'));
    }

    public function testCopyObject(): void
    {
        $this->createTestBucket('obj-bucket');
        $this->createTestObject('obj-bucket', 'source.txt', 'copy me');

        $this->assertTrue($this->storage->copyObject('obj-bucket', 'source.txt', 'obj-bucket', 'dest.txt'));
        $this->assertTrue($this->storage->objectExists('obj-bucket', 'dest.txt'));
    }

    // ─── List Objects ─────────────────────────────────────────────────

    public function testListObjectsBasic(): void
    {
        $this->createTestBucket('list-bucket');
        $this->createTestObject('list-bucket', 'a.txt');
        $this->createTestObject('list-bucket', 'b.txt');

        $result = $this->storage->listObjects('list-bucket');
        $this->assertCount(2, $result['objects']);
        $this->assertFalse($result['isTruncated']);
        $this->assertEmpty($result['commonPrefixes']);
    }

    public function testListObjectsWithPrefix(): void
    {
        $this->createTestBucket('prefix-bucket');
        $this->createTestObject('prefix-bucket', 'dir/file1.txt');
        $this->createTestObject('prefix-bucket', 'dir/file2.txt');
        $this->createTestObject('prefix-bucket', 'other.txt');

        $result = $this->storage->listObjects('prefix-bucket', 'dir/');
        $this->assertCount(2, $result['objects']);
    }

    public function testListObjectsWithMaxKeys(): void
    {
        $this->createTestBucket('maxkeys-bucket');
        for ($i = 0; $i < 5; $i++) {
            $this->createTestObject('maxkeys-bucket', "file{$i}.txt");
        }

        $result = $this->storage->listObjects('maxkeys-bucket', '', 3);
        $this->assertCount(3, $result['objects']);
        $this->assertTrue($result['isTruncated']);
    }

    public function testListObjectsWithDelimiter(): void
    {
        $this->createTestBucket('delim-bucket');
        $this->createTestObject('delim-bucket', 'photos/2023/img1.jpg');
        $this->createTestObject('delim-bucket', 'photos/2023/img2.jpg');
        $this->createTestObject('delim-bucket', 'photos/2024/img3.jpg');
        $this->createTestObject('delim-bucket', 'readme.txt');

        $result = $this->storage->listObjects('delim-bucket', '', 1000, 0, '/');
        $this->assertCount(1, $result['objects']);
        $keys = array_map(fn($o) => $o['key'], $result['objects']);
        $this->assertContains('readme.txt', $keys);
        $this->assertCount(1, $result['commonPrefixes']);
        $this->assertContains('photos/', $result['commonPrefixes']);
    }

    public function testListObjectsWithDelimiterAndPrefix(): void
    {
        $this->createTestBucket('delim2-bucket');
        $this->createTestObject('delim2-bucket', 'photos/2023/img1.jpg');
        $this->createTestObject('delim2-bucket', 'photos/2024/img2.jpg');
        $this->createTestObject('delim2-bucket', 'docs/readme.txt');

        $result = $this->storage->listObjects('delim2-bucket', 'photos/', 1000, 0, '/');
        $this->assertCount(0, $result['objects']);
        $this->assertCount(2, $result['commonPrefixes']);
        $this->assertContains('photos/2023/', $result['commonPrefixes']);
        $this->assertContains('photos/2024/', $result['commonPrefixes']);
    }

    public function testListObjectsWithMarker(): void
    {
        $this->createTestBucket('marker-bucket');
        $this->createTestObject('marker-bucket', 'a.txt');
        $this->createTestObject('marker-bucket', 'b.txt');
        $this->createTestObject('marker-bucket', 'c.txt');

        $result = $this->storage->listObjects('marker-bucket', '', 1000, 0, '', '', 'a.txt');
        $this->assertCount(2, $result['objects']);
        $keys = array_map(fn($o) => $o['key'], $result['objects']);
        $this->assertContains('b.txt', $keys);
        $this->assertContains('c.txt', $keys);
        $this->assertNotContains('a.txt', $keys);
    }

    public function testListObjectsWithStartAfter(): void
    {
        $this->createTestBucket('startafter-bucket');
        $this->createTestObject('startafter-bucket', 'a.txt');
        $this->createTestObject('startafter-bucket', 'b.txt');
        $this->createTestObject('startafter-bucket', 'c.txt');

        $result = $this->storage->listObjects('startafter-bucket', '', 1000, 0, '', 'b.txt');
        $this->assertCount(1, $result['objects']);
        $this->assertEquals('c.txt', $result['objects'][0]['key']);
    }

    // ─── Multipart Upload ─────────────────────────────────────────────

    public function testMultipartUpload(): void
    {
        $this->createTestBucket('mp-bucket');
        $uploadId = bin2hex(random_bytes(16));

        $this->assertTrue($this->storage->createMultipartUpload('mp-bucket', $uploadId));
        $this->assertTrue($this->storage->savePart('mp-bucket', $uploadId, 1, 'part1data'));
        $this->assertTrue($this->storage->savePart('mp-bucket', $uploadId, 2, 'part2data'));

        $parts = $this->storage->listParts('mp-bucket', $uploadId);
        $this->assertCount(2, $parts);

        $result = $this->storage->completeMultipartUpload('mp-bucket', 'merged.txt', $uploadId, [1 => true, 2 => true]);
        $this->assertNotNull($result);
        // 'part1data' (9) + 'part2data' (9) = 18 bytes
        $this->assertEquals(18, $result['size']);
        $this->assertTrue($this->storage->objectExists('mp-bucket', 'merged.txt'));
    }

    public function testAbortMultipartUpload(): void
    {
        $this->createTestBucket('mp-bucket');
        $uploadId = bin2hex(random_bytes(16));

        $this->storage->createMultipartUpload('mp-bucket', $uploadId);
        $this->storage->savePart('mp-bucket', $uploadId, 1, 'data');

        $this->assertTrue($this->storage->abortMultipartUpload('mp-bucket', $uploadId));
        $this->assertCount(0, $this->storage->listParts('mp-bucket', $uploadId));
    }

    public function testDeleteBucketWithOnlyMultipartDir(): void
    {
        $this->createTestBucket('mp-only-bucket');
        $uploadId = bin2hex(random_bytes(16));
        $this->storage->createMultipartUpload('mp-only-bucket', $uploadId);
        $this->storage->savePart('mp-only-bucket', $uploadId, 1, 'data');

        // Bucket contains only the .multipart staging dir; delete should succeed.
        $this->assertTrue($this->storage->deleteBucket('mp-only-bucket'));
        $this->assertFalse($this->storage->bucketExists('mp-only-bucket'));
    }

    public function testPutObjectLeavesNoTempFiles(): void
    {
        $this->createTestBucket('atomic-bucket');
        $this->storage->putObjectFromString('atomic-bucket', 'file.txt', 'hello');

        // A successful atomic write must rename away the temp file, leaving none behind.
        $bucketPath = $this->storage->getPathResolver()->bucketPath('atomic-bucket');
        $leftover = glob($bucketPath . '/*' . '.tmp');
        $this->assertEmpty($leftover, 'No .tmp files should remain after a successful put');
        $this->assertTrue($this->storage->objectExists('atomic-bucket', 'file.txt'));
    }

    public function testCompleteMultipartUploadPreservesOriginalOnFailure(): void
    {
        $this->createTestBucket('mp-atomic-bucket');
        // Pre-existing object that must survive a failed completion.
        $this->storage->putObjectFromString('mp-atomic-bucket', 'merged.txt', 'ORIGINAL');

        $uploadId = bin2hex(random_bytes(16));
        $this->storage->createMultipartUpload('mp-atomic-bucket', $uploadId);
        $this->storage->savePart('mp-atomic-bucket', $uploadId, 1, 'part1data');

        // Part 99 was never uploaded -> completion must fail and leave the original intact.
        $result = $this->storage->completeMultipartUpload(
            'mp-atomic-bucket', 'merged.txt', $uploadId, [1 => true, 99 => true]
        );

        $this->assertNull($result);
        $meta = $this->storage->getObjectMeta('mp-atomic-bucket', 'merged.txt');
        $this->assertNotNull($meta);
        $this->assertEquals(8, $meta['size']); // 'ORIGINAL' = 8 bytes
        $this->assertEquals('ORIGINAL', file_get_contents(
            $this->storage->getPathResolver()->objectPath('mp-atomic-bucket', 'merged.txt')
        ));
    }

    // ─── Edge cases: non-existent resources ───────────────────────────

    public function testDeleteBucketReturnsFalseWhenBucketMissing(): void
    {
        $this->assertFalse($this->storage->deleteBucket('no-such-bucket'));
    }

    public function testIsBucketEmptyReturnsTrueWhenBucketMissing(): void
    {
        $this->assertTrue($this->storage->isBucketEmpty('no-such-bucket'));
    }

    public function testListObjectsOnNonExistentBucketReturnsEmpty(): void
    {
        $result = $this->storage->listObjects('no-such-bucket');
        $this->assertCount(0, $result['objects']);
        $this->assertFalse($result['isTruncated']);
    }

    public function testCopyObjectReturnsFalseWhenSourceMissing(): void
    {
        $this->createTestBucket('copy-bucket');
        $this->assertFalse($this->storage->copyObject('copy-bucket', 'nope.txt', 'copy-bucket', 'dest.txt'));
        $this->assertFalse($this->storage->objectExists('copy-bucket', 'dest.txt'));
    }

    public function testGetObjectMetaReturnsNullWhenObjectMissing(): void
    {
        $this->createTestBucket('meta-bucket');
        $this->assertNull($this->storage->getObjectMeta('meta-bucket', 'no-such-file.txt'));
    }

    // ─── ListObjects cache behavior ───────────────────────────────────

    public function testCacheDisabledWhenTimeoutZero(): void
    {
        // TTL=0 is set in setUp(); verify no cache file is created.
        $this->createTestBucket('nocache-bucket');
        $this->createTestObject('nocache-bucket', 'a.txt');

        $this->storage->listObjects('nocache-bucket');

        $cacheFile = \Symfony\Component\Filesystem\Path::join(
            dirname(__DIR__, 2), 'tmp', 'listbuckets', 'nocache-bucket.json'
        );
        $this->assertFileDoesNotExist($cacheFile);
    }

    public function testCacheReturnsStaleDataWithinTtl(): void
    {
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '60');
        $this->createTestBucket('stale-bucket');
        $this->createTestObject('stale-bucket', 'original.txt');

        // First call populates the cache.
        $result1 = $this->storage->listObjects('stale-bucket');
        $this->assertCount(1, $result1['objects']);

        // Write a new object directly to the filesystem, bypassing cache invalidation.
        $this->createTestObject('stale-bucket', 'added-later.txt');

        // Second call within TTL must return the cached (stale) result.
        $result2 = $this->storage->listObjects('stale-bucket');
        $this->assertCount(1, $result2['objects'], 'Cache should return stale data within TTL');

        $this->cleanupCacheFile('stale-bucket');
    }

    public function testCacheRescansAfterTtlExpiry(): void
    {
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '60');
        $this->createTestBucket('ttl-bucket');
        $this->createTestObject('ttl-bucket', 'first.txt');

        // Populate cache.
        $this->storage->listObjects('ttl-bucket');

        $cacheFile = \Symfony\Component\Filesystem\Path::join(
            dirname(__DIR__, 2), 'tmp', 'listbuckets', 'ttl-bucket.json'
        );
        $this->assertFileExists($cacheFile);

        // Backdate the cache file so it's older than the TTL.
        $oldTime = time() - 120;
        touch($cacheFile, $oldTime);

        // Add a new object after the cache was populated.
        $this->createTestObject('ttl-bucket', 'second.txt');

        // Cache is expired -> should rescan and see both objects.
        $result = $this->storage->listObjects('ttl-bucket');
        $this->assertCount(2, $result['objects'], 'Expired cache should trigger rescan');

        $this->cleanupCacheFile('ttl-bucket');
    }

    public function testCacheSurvivesAcrossPaginatedRequests(): void
    {
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '60');
        $this->createTestBucket('paged-bucket');
        for ($i = 0; $i < 5; $i++) {
            $this->createTestObject('paged-bucket', "file{$i}.txt");
        }

        // First page.
        $page1 = $this->storage->listObjects('paged-bucket', '', 2);
        $this->assertCount(2, $page1['objects']);
        $this->assertTrue($page1['isTruncated']);

        // Second page using marker. Should use the same cache.
        $marker = $page1['objects'][1]['key'];
        $page2 = $this->storage->listObjects('paged-bucket', '', 2, 0, '', '', $marker);
        $this->assertCount(2, $page2['objects']);

        // All 5 objects should be covered across pages.
        $allKeys = array_merge(
            array_column($page1['objects'], 'key'),
            array_column($page2['objects'], 'key')
        );
        $this->assertCount(4, $allKeys);

        $this->cleanupCacheFile('paged-bucket');
    }

    private function cleanupCacheFile(string $bucket): void
    {
        $cacheFile = \Symfony\Component\Filesystem\Path::join(
            dirname(__DIR__, 2), 'tmp', 'listbuckets', $bucket . '.json'
        );
        if (file_exists($cacheFile)) {
            @unlink($cacheFile);
        }
        // Also clean up the .tmp file if atomic write left one.
        $tmpFile = $cacheFile . '.tmp';
        if (file_exists($tmpFile)) {
            @unlink($tmpFile);
        }
    }

    // ─── listBuckets filtering ────────────────────────────────────────

    public function testListBucketsSkipsHiddenDirectories(): void
    {
        $dataDir = $this->storage->getPathResolver()->getDataDir();

        // Create a valid bucket and hidden directories (starting with '.').
        $this->createTestBucket('visible-bucket');
        @mkdir($dataDir . '/.hidden-dir');
        @mkdir($dataDir . '/.cache');

        $buckets = $this->storage->listBuckets();
        $this->assertContains('visible-bucket', $buckets);
        $this->assertNotContains('.hidden-dir', $buckets);
        $this->assertNotContains('.cache', $buckets);

        @rmdir($dataDir . '/.hidden-dir');
        @rmdir($dataDir . '/.cache');
    }

    public function testListBucketsSkipsInvalidBucketNames(): void
    {
        $dataDir = $this->storage->getPathResolver()->getDataDir();

        $this->createTestBucket('valid-bucket');
        // Uppercase names are invalid per S3 bucket naming rules.
        @mkdir($dataDir . '/INVALID-Bucket');
        // Two-letter name is too short (min 3 chars).
        @mkdir($dataDir . '/ab');

        $buckets = $this->storage->listBuckets();
        $this->assertContains('valid-bucket', $buckets);
        $this->assertNotContains('INVALID-Bucket', $buckets);
        $this->assertNotContains('ab', $buckets);

        @rmdir($dataDir . '/INVALID-Bucket');
        @rmdir($dataDir . '/ab');
    }
}
