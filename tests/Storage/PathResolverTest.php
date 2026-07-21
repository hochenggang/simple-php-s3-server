<?php

namespace S3Gateway\Tests\Storage;

use PHPUnit\Framework\TestCase;
use S3Gateway\Storage\PathResolver;
use S3Gateway\Tests\ResetsConfig;

class PathResolverTest extends TestCase
{
    use ResetsConfig;

    private PathResolver $pathResolver;
    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_path_test_' . uniqid();
        $this->resetConfig($this->testDir);
        $this->pathResolver = new PathResolver();
    }

    protected function tearDown(): void
    {
        $this->cleanupDir($this->testDir);
    }

    public function testGetDataDir(): void
    {
        $this->assertEquals($this->pathResolver->normalize($this->testDir), $this->pathResolver->getDataDir());
    }

    public function testBucketPath(): void
    {
        $path = $this->pathResolver->bucketPath('mybucket');
        $this->assertStringContainsString('mybucket', $path);
        $this->assertStringEndsWith('/mybucket', $path);
    }

    public function testObjectPath(): void
    {
        $path = $this->pathResolver->objectPath('mybucket', 'folder/file.txt');
        $this->assertStringContainsString('mybucket/folder/file.txt', $path);
    }

    public function testMultipartPath(): void
    {
        $uploadId = bin2hex(random_bytes(16));
        $path = $this->pathResolver->multipartPath('mybucket', $uploadId);
        $this->assertStringContainsString('.multipart/' . $uploadId, $path);
    }

    public function testPartPath(): void
    {
        $uploadId = bin2hex(random_bytes(16));
        $path = $this->pathResolver->partPath('mybucket', $uploadId, 1);
        $this->assertStringContainsString('.multipart/' . $uploadId . '/1', $path);
    }

    public function testMultipartPathRejectsTraversalUploadId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->pathResolver->multipartPath('mybucket', '../../etc');
    }

    public function testMultipartPathRejectsShortUploadId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->pathResolver->multipartPath('mybucket', 'upload123');
    }

    public function testValidateBucketNameValid(): void
    {
        $this->assertTrue($this->pathResolver->isValidBucketName('my-bucket'));
        $this->assertTrue($this->pathResolver->isValidBucketName('bucket123'));
        $this->assertTrue($this->pathResolver->isValidBucketName('a.b'));
    }

    public function testValidateBucketNameInvalid(): void
    {
        $this->assertFalse($this->pathResolver->isValidBucketName(''));
        $this->assertFalse($this->pathResolver->isValidBucketName('ab')); // too short
        $this->assertFalse($this->pathResolver->isValidBucketName('MY-BUCKET')); // uppercase
        $this->assertFalse($this->pathResolver->isValidBucketName('bucket..name')); // consecutive dots
        $this->assertFalse($this->pathResolver->isValidBucketName('.bucket')); // starts with dot
    }

    public function testValidateBucketNameThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->pathResolver->validateBucketName('INVALID');
    }

    public function testNormalize(): void
    {
        $this->assertEquals('/a/b/c', $this->pathResolver->normalize('/a//b///c/'));
    }

    public function testGetRelativePath(): void
    {
        $base = $this->testDir . '/mybucket';
        $full = $this->testDir . '/mybucket/folder/file.txt';
        $this->assertEquals('folder/file.txt', $this->pathResolver->getRelativePath($base, $full));
    }

    public function testSanitizeKeyPathTraversal(): void
    {
        // The resulting path should not allow escaping the bucket directory
        $path = $this->pathResolver->objectPath('mybucket', '../etc/passwd');
        // Should not contain .. in a way that escapes the bucket
        $bucketPath = $this->pathResolver->bucketPath('mybucket');
        $this->assertStringStartsWith($bucketPath, $path);
    }

    public function testSanitizeKeyDoubleDotSlashTraversal(): void
    {
        $path = $this->pathResolver->objectPath('mybucket', '....//etc/passwd');
        $bucketPath = $this->pathResolver->bucketPath('mybucket');
        $this->assertStringStartsWith($bucketPath, $path);
    }

    public function testSanitizeKeyPreservesDoubleDotInName(): void
    {
        // Legitimate filenames containing ".." as a substring must not be corrupted.
        $path = $this->pathResolver->objectPath('mybucket', 'file..txt');
        $this->assertStringEndsWith('/file..txt', $path);
        $this->assertStringNotContainsString('filetxt', $path);
    }

    public function testEnsureDir(): void
    {
        $dirPath = $this->testDir . '/test-new-dir';
        $this->assertTrue($this->pathResolver->ensureDir($dirPath));
        $this->assertTrue(is_dir($dirPath));
    }

    public function testObjectPathRejectsInvalidBucket(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->pathResolver->objectPath('..', 'file.txt');
    }

    public function testMultipartPathRejectsInvalidBucket(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $uploadId = bin2hex(random_bytes(16));
        $this->pathResolver->multipartPath('..', $uploadId);
    }

    public function testCanonicalizeKey(): void
    {
        // URL-encoded key → decoded canonical form
        $this->assertEquals('my file', $this->pathResolver->canonicalizeKey('my%20file'));
        // Traversal segments are dropped
        $this->assertEquals('etc', $this->pathResolver->canonicalizeKey('../etc'));
        // Legitimate ".." in filename is preserved
        $this->assertEquals('file..txt', $this->pathResolver->canonicalizeKey('file..txt'));
        // Plus sign decoded to space (form-encoding compatibility)
        $this->assertEquals('my file', $this->pathResolver->canonicalizeKey('my+file'));
    }
}
