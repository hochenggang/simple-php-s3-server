<?php

namespace S3Gateway\Tests\Auth;

use PHPUnit\Framework\TestCase;
use S3Gateway\Auth\Authenticator;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Tests\ResetsConfig;

class AuthenticatorTest extends TestCase
{
    use ResetsConfig;

    private string $testDir;

    protected function setUp(): void
    {
        $this->testDir = sys_get_temp_dir() . '/s3gateway_auth_test_' . uniqid();
        $this->resetConfig($this->testDir);
    }

    protected function tearDown(): void
    {
        $this->cleanupDir($this->testDir);
        s3gw_test_unset_env('BEARER_TOKEN');
    }

    private function createRequest(array $serverVars): Request
    {
        $_SERVER = array_merge($_SERVER, $serverVars);
        return new Request();
    }

    // ─── No Authorization Header ─────────────────────────────────────

    public function testAccessDeniedNoHeader(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
        ]);
        $auth = new Authenticator($request);

        $this->expectException(S3Exception::class);
        $auth->authenticate();
    }

    // ─── Bearer Token ────────────────────────────────────────────────

    public function testBearerTokenSuccess(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('BEARER_TOKEN', 'my-secret-token');

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'Bearer my-secret-token',
        ]);
        $auth = new Authenticator($request);

        // Should not throw
        $result = $auth->authenticate();
        $this->assertEquals('', $result); // Bearer returns empty string
    }

    public function testBearerTokenInvalid(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('BEARER_TOKEN', 'correct-token');

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'Bearer wrong-token',
        ]);
        $auth = new Authenticator($request);

        $this->expectException(S3Exception::class);
        $auth->authenticate();
    }

    public function testBearerTokenNotConfigured(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'Bearer some-token',
        ]);
        $auth = new Authenticator($request);

        $this->expectException(S3Exception::class);
        $auth->authenticate();
    }

    // ─── Invalid Authorization Format ────────────────────────────────

    public function testInvalidAuthFormat(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'Basic dXNlcjpwYXNz',
        ]);
        $auth = new Authenticator($request);

        $this->expectException(S3Exception::class);
        $auth->authenticate();
    }

    // ─── V4 Header Parsing ───────────────────────────────────────────

    public function testV4HeaderInvalidFormat(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 InvalidFormat',
        ]);
        $auth = new Authenticator($request);

        $this->expectException(S3Exception::class);
        $auth->authenticate();
    }

    public function testV4HeaderUnknownAccessKey(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123',
            'HTTP_X_AMZ_DATE' => gmdate('Ymd\THis\Z'),
        ]);
        $auth = new Authenticator($request);

        $this->expectException(S3Exception::class);
        $auth->authenticate();
    }

    // ─── Request Size Check ──────────────────────────────────────────

    public function testCheckRequestSizeNoLimit(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'HTTP_AUTHORIZATION' => 'Bearer test',
        ]);

        $this->resetConfig($this->testDir);
        $this->setConfigValue('BEARER_TOKEN', 'test');

        $auth = new Authenticator($request);
        // No exception when no file_max_size configured
        $auth->checkRequestSize('');
        $this->assertTrue(true); // No exception means pass
    }
}
