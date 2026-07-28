<?php

namespace S3Gateway\Tests;

use PHPUnit\Framework\TestCase;
use S3Gateway\Config;

class ConfigTest extends TestCase
{
    use ResetsConfig;

    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_config_test_' . uniqid();
    }

    protected function tearDown(): void
    {
        s3gw_test_unset_env('APP_DEBUG');
        s3gw_test_unset_env('DATA_DIR');
    }

    public function testGetFromConfig(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('APP_DEBUG', 'true');
        $this->assertEquals('true', Config::get('APP_DEBUG'));
    }

    public function testGetDefault(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertNull(Config::get('NONEXISTENT_KEY'));
        $this->assertEquals('default', Config::get('NONEXISTENT_KEY', 'default'));
    }

    public function testAppDebugTrue(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('APP_DEBUG', 'true');
        $this->assertTrue(Config::appDebug());
    }

    public function testAppDebugFalse(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('APP_DEBUG', 'false');
        $this->assertFalse(Config::appDebug());
    }

    public function testMaxKeysDefault(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertEquals(100000, Config::maxKeys());
    }

    public function testMaxKeysConfigured(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_KEYS', '5000');
        $this->assertEquals(5000, Config::maxKeys());
    }

    public function testMaxTimestampSkewDefault(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertEquals(300, Config::maxTimestampSkew());
    }

    public function testMaxUploadSizeDefault(): void
    {
        $this->resetConfig($this->testDir);
        // 8192 KB = 8388608 bytes (8 MB)
        $this->assertEquals(8388608, Config::maxUploadSize());
    }

    public function testMaxUploadSizeZeroMeansNoLimit(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_UPLOAD_SIZE', '0');
        $this->assertEquals(0, Config::maxUploadSize());
    }

    public function testMultipartUploadTtlDefault(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertEquals(86400, Config::multipartUploadTtl());
    }

    public function testListBucketsCacheTimeoutDefault(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertEquals(60, Config::listBucketsCacheTimeout());
    }

    public function testGetSecretKeyNotConfigured(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertNull(Config::getSecretKey('unknown-key'));
    }

    public function testDataDir(): void
    {
        $this->resetConfig($this->testDir);
        $dataDir = Config::dataDir();
        $this->assertNotEmpty($dataDir);
    }

    public function testDataDirFallsBackWhenEmpty(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('DATA_DIR', '');
        $dataDir = Config::dataDir();
        $this->assertNotEmpty($dataDir);
        // Empty DATA_DIR must fall back to the default data dir (ends with '/data'),
        // never collapse to the project root (which would end with the project name).
        $this->assertStringEndsWith('/data', $dataDir);
    }

    public function testResolvePathAbsoluteIsReturnedAsIs(): void
    {
        $this->resetConfig($this->testDir);
        $absolute = '/absolute/path/to/somewhere';
        $this->assertEquals($absolute, Config::resolvePath($absolute));
    }

    public function testResolvePathRelativeIsJoinedToProjectRoot(): void
    {
        $this->resetConfig($this->testDir);
        $resolved = Config::resolvePath('foo/bar');
        // Relative paths are resolved against the project src/ parent (project root).
        $this->assertStringEndsWith('foo/bar', $resolved);
        $this->assertStringNotContainsString('..', $resolved);
    }

    public function testTrustProxyHeadersDefaultFalse(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertFalse(Config::trustProxyHeaders());
    }

    public function testTrustProxyHeadersTrueWhenConfigured(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('TRUST_PROXY_HEADERS', 'true');
        $this->assertTrue(Config::trustProxyHeaders());
    }

    public function testTrustProxyHeadersFalseWhenNotTrueLiteral(): void
    {
        $this->resetConfig($this->testDir);
        // Any value other than the literal 'true' must be treated as false,
        // so a misconfigured proxy header cannot silently enable spoofing.
        $this->setConfigValue('TRUST_PROXY_HEADERS', '1');
        $this->assertFalse(Config::trustProxyHeaders());
    }

    public function testMaxTimestampSkewConfigured(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_TIMESTAMP_SKEW', '60');
        $this->assertEquals(60, Config::maxTimestampSkew());
    }

    public function testMaxUploadSizeConfiguredInBytes(): void
    {
        $this->resetConfig($this->testDir);
        // 100 KB = 102400 bytes
        $this->setConfigValue('MAX_UPLOAD_SIZE', '100');
        $this->assertEquals(102400, Config::maxUploadSize());
    }

    public function testMultipartUploadTtlConfigured(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MULTIPART_UPLOAD_TTL', '3600');
        $this->assertEquals(3600, Config::multipartUploadTtl());
    }

    public function testListBucketsCacheTimeoutConfigured(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '120');
        $this->assertEquals(120, Config::listBucketsCacheTimeout());
    }

    public function testListBucketsCacheTimeoutZeroDisablesCache(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('LIST_BUCKETS_CACHE_TIMEOUT', '0');
        $this->assertEquals(0, Config::listBucketsCacheTimeout());
    }

    // ─── Access key configuration ─────────────────────────────────────

    private function injectAccessKey(string $accessKeyId, array $data): void
    {
        $ref = new \ReflectionClass(Config::class);
        $keysProp = $ref->getProperty('accessKeys');
        $current = $keysProp->getValue() ?? [];
        $current[$accessKeyId] = $data;
        $keysProp->setValue(null, $current);
    }

    public function testGetSecretKeyReturnsConfiguredKey(): void
    {
        $this->resetConfig($this->testDir);
        $this->injectAccessKey('ak1', [
            'secret_key' => 'secret-1',
            'allowed_buckets' => ['*'],
            'file_max_size' => 0,
        ]);
        $this->assertEquals('secret-1', Config::getSecretKey('ak1'));
    }

    public function testGetFileMaxSizeReturnsBytesForConfiguredKey(): void
    {
        $this->resetConfig($this->testDir);
        // 256 KB -> 262144 bytes
        $this->injectAccessKey('sized-key', [
            'secret_key' => 's',
            'allowed_buckets' => ['*'],
            'file_max_size' => 262144,
        ]);
        $this->assertEquals(262144, Config::getFileMaxSize('sized-key'));
    }

    public function testGetFileMaxSizeZeroForUnknownKey(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertEquals(0, Config::getFileMaxSize('unknown-key'));
    }

    public function testGetFileMaxSizeZeroWhenUnset(): void
    {
        $this->resetConfig($this->testDir);
        $this->injectAccessKey('nosize-key', [
            'secret_key' => 's',
            'allowed_buckets' => ['*'],
            'file_max_size' => 0,
        ]);
        $this->assertEquals(0, Config::getFileMaxSize('nosize-key'));
    }

    public function testIsBucketAllowedWildcardAllowsAnyBucket(): void
    {
        $this->resetConfig($this->testDir);
        $this->injectAccessKey('wildcard-key', [
            'secret_key' => 's',
            'allowed_buckets' => ['*'],
            'file_max_size' => 0,
        ]);
        $this->assertTrue(Config::isBucketAllowed('wildcard-key', 'anything'));
        $this->assertTrue(Config::isBucketAllowed('wildcard-key', 'other-bucket'));
    }

    public function testIsBucketAllowedSpecificListPermitsOnlyListedBuckets(): void
    {
        $this->resetConfig($this->testDir);
        $this->injectAccessKey('limited-key', [
            'secret_key' => 's',
            'allowed_buckets' => ['bucket-a', 'bucket-b'],
            'file_max_size' => 0,
        ]);
        $this->assertTrue(Config::isBucketAllowed('limited-key', 'bucket-a'));
        $this->assertTrue(Config::isBucketAllowed('limited-key', 'bucket-b'));
        $this->assertFalse(Config::isBucketAllowed('limited-key', 'bucket-c'));
    }

    public function testIsBucketAllowedFalseForUnknownAccessKey(): void
    {
        $this->resetConfig($this->testDir);
        // Unknown access key must never be allowed, regardless of bucket name.
        $this->assertFalse(Config::isBucketAllowed('unknown-key', 'any-bucket'));
    }

    public function testGetSecretKeyReturnsNullForUnknownKey(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertNull(Config::getSecretKey('does-not-exist'));
    }
}
