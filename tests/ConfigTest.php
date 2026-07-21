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
        s3gw_test_unset_env('BEARER_TOKEN');
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

    public function testBearerToken(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('BEARER_TOKEN', 'my-secret-token');
        $this->assertEquals('my-secret-token', Config::bearerToken());
    }

    public function testBearerTokenNotSet(): void
    {
        $this->resetConfig($this->testDir);
        $this->assertNull(Config::bearerToken());
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
}
