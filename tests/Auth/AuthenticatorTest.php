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
    private array $originalServer;

    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
        $this->testDir = sys_get_temp_dir() . '/s3gateway_auth_test_' . uniqid();
        $this->resetConfig($this->testDir);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;
        $this->cleanupDir($this->testDir);
        s3gw_test_unset_env('BEARER_TOKEN');
    }

    private function createRequest(array $serverVars): Request
    {
        // Start from a clean baseline so headers/QUERY_STRING from previous
        // tests don't leak into the current one. Only keep essential CGI vars.
        $_SERVER = array_merge([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'QUERY_STRING' => '',
        ], $serverVars);
        return new Request();
    }

    /**
     * Inject an access key into Config's static cache for tests that need to
     * progress past the access-key lookup step in authenticate().
     */
    private function injectAccessKey(string $accessKeyId, string $secretKey, array $allowedBuckets = ['*']): void
    {
        $ref = new \ReflectionClass(\S3Gateway\Config::class);
        $keysProp = $ref->getProperty('accessKeys');
        $current = $keysProp->getValue() ?? [];
        $current[$accessKeyId] = [
            'secret_key' => $secretKey,
            'allowed_buckets' => $allowedBuckets,
            'file_max_size' => 0,
        ];
        $keysProp->setValue(null, $current);
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
        ]);

        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_UPLOAD_SIZE', '0');

        $auth = new Authenticator($request);
        // No exception when both file_max_size and MAX_UPLOAD_SIZE are unset (0)
        $auth->checkRequestSize('');
        $this->assertTrue(true); // No exception means pass
    }

    /**
     * Regression: a client could forge Content-Length: 0 to bypass per-key
     * upload limits while streaming a large body. checkRequestSize must use
     * the larger of the header and the actual decoded body length.
     */
    public function testCheckRequestSizeRejectsForgedContentLengthZero(): void
    {
        $this->resetConfig($this->testDir);

        // Inject an access key with a 100-byte upload cap.
        $ref = new \ReflectionClass(\S3Gateway\Config::class);
        $keysProp = $ref->getProperty('accessKeys');
        $keysProp->setValue(null, [
            'size-key' => [
                'secret_key' => 'secret',
                'allowed_buckets' => ['*'],
                'file_max_size' => 100,
            ],
        ]);

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '0', // forged
        ]);

        // Simulate a 200-byte body that the client actually sent.
        $bodyRef = new \ReflectionProperty(Request::class, 'body');
        $bodyRef->setValue($request, str_repeat('x', 200));

        $auth = new Authenticator($request);

        try {
            $auth->checkRequestSize('size-key');
            $this->fail('Expected EntityTooLarge exception');
        } catch (S3Exception $e) {
            $this->assertEquals('EntityTooLarge', $e->getS3Code());
            $this->assertEquals(400, $e->getHttpStatus());
        }
    }

    // ─── checkEarlyRequestSize (pre-auth header check) ───────────────

    public function testCheckEarlyRequestSizeRejectsOversizedHeader(): void
    {
        $this->resetConfig($this->testDir);
        // 1 KB limit
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1');

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '2048', // 2 KB > 1 KB limit
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->checkEarlyRequestSize();
            $this->fail('Expected EntityTooLarge exception');
        } catch (S3Exception $e) {
            $this->assertEquals('EntityTooLarge', $e->getS3Code());
            $this->assertEquals(400, $e->getHttpStatus());
        }
    }

    public function testCheckEarlyRequestSizeAllowsWithinLimit(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_UPLOAD_SIZE', '10'); // 10 KB

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '5120', // 5 KB < 10 KB
        ]);

        $auth = new Authenticator($request);
        // No exception means pass.
        $auth->checkEarlyRequestSize();
        $this->assertTrue(true);
    }

    public function testCheckEarlyRequestSizeSkipsWhenNoContentLength(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1');

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            // No Content-Length header
        ]);

        $auth = new Authenticator($request);
        $auth->checkEarlyRequestSize();
        $this->assertTrue(true);
    }

    public function testCheckEarlyRequestSizeSkipsWhenLimitDisabled(): void
    {
        $this->resetConfig($this->testDir);
        // MAX_UPLOAD_SIZE = 0 means no global limit
        $this->setConfigValue('MAX_UPLOAD_SIZE', '0');

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '999999999',
        ]);

        $auth = new Authenticator($request);
        $auth->checkEarlyRequestSize();
        $this->assertTrue(true);
    }

    // ─── checkRequestSize global fallback ─────────────────────────────

    public function testCheckRequestSizeUsesGlobalMaxWhenPerKeyUnset(): void
    {
        $this->resetConfig($this->testDir);
        // Global limit 1 KB; per-key file_max_size unset (0)
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1');

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
        ]);

        // Body larger than 1 KB (1024 bytes)
        $bodyRef = new \ReflectionProperty(Request::class, 'body');
        $bodyRef->setValue($request, str_repeat('x', 2048));

        $auth = new Authenticator($request);

        try {
            $auth->checkRequestSize('key-without-per-key-limit');
            $this->fail('Expected EntityTooLarge exception');
        } catch (S3Exception $e) {
            $this->assertEquals('EntityTooLarge', $e->getS3Code());
        }
    }

    // ─── Presigned URL parameter validation ───────────────────────────

    public function testPresignedUrlMissingParamsThrowsAccessDenied(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            'QUERY_STRING' => 'X-Amz-Credential=ak/20260101/us-east-1/s3/aws4_request',
            // Missing X-Amz-Algorithm, X-Amz-Date, X-Amz-Expires, etc.
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected AccessDenied exception');
        } catch (S3Exception $e) {
            $this->assertEquals('AccessDenied', $e->getS3Code());
            $this->assertStringContainsString('Missing required presigned URL', $e->getMessage());
        }
    }

    public function testPresignedUrlInvalidExpiresRangeTooSmall(): void
    {
        // Build a presigned URL with X-Amz-Expires=0 (below the 1..604800 range).
        $qs = http_build_query([
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => 'ak/20260101/us-east-1/s3/aws4_request',
            'X-Amz-Date' => gmdate('Ymd\THis\Z'),
            'X-Amz-Expires' => '0',
            'X-Amz-SignedHeaders' => 'host',
            'X-Amz-Signature' => 'deadbeef',
        ]);

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            'QUERY_STRING' => $qs,
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected InvalidRequest exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidRequest', $e->getS3Code());
            $this->assertStringContainsString('X-Amz-Expires', $e->getMessage());
        }
    }

    public function testPresignedUrlInvalidExpiresRangeTooLarge(): void
    {
        $qs = http_build_query([
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => 'ak/20260101/us-east-1/s3/aws4_request',
            'X-Amz-Date' => gmdate('Ymd\THis\Z'),
            'X-Amz-Expires' => '604801', // > 7 days
            'X-Amz-SignedHeaders' => 'host',
            'X-Amz-Signature' => 'deadbeef',
        ]);

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            'QUERY_STRING' => $qs,
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected InvalidRequest exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidRequest', $e->getS3Code());
        }
    }

    public function testPresignedUrlExpiredThrowsExpiredToken(): void
    {
        // Date far in the past + short expiry => expired
        $qs = http_build_query([
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => 'ak/20200101/us-east-1/s3/aws4_request',
            'X-Amz-Date' => '20200101T000000Z',
            'X-Amz-Expires' => '60',
            'X-Amz-SignedHeaders' => 'host',
            'X-Amz-Signature' => 'deadbeef',
        ]);

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            'QUERY_STRING' => $qs,
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected ExpiredToken exception');
        } catch (S3Exception $e) {
            $this->assertEquals('ExpiredToken', $e->getS3Code());
        }
    }

    public function testPresignedUrlInvalidDateFormatThrowsInvalidRequest(): void
    {
        $qs = http_build_query([
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => 'ak/20260101/us-east-1/s3/aws4_request',
            'X-Amz-Date' => 'not-a-date',
            'X-Amz-Expires' => '60',
            'X-Amz-SignedHeaders' => 'host',
            'X-Amz-Signature' => 'deadbeef',
        ]);

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            'QUERY_STRING' => $qs,
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected InvalidRequest exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidRequest', $e->getS3Code());
            $this->assertStringContainsString('X-Amz-Date', $e->getMessage());
        }
    }

    public function testPresignedUrlCredentialWithTooFewPartsThrowsInvalidAccessKeyId(): void
    {
        $qs = http_build_query([
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            // Only 3 parts instead of 5
            'X-Amz-Credential' => 'ak/20260101/us-east-1',
            'X-Amz-Date' => gmdate('Ymd\THis\Z'),
            'X-Amz-Expires' => '60',
            'X-Amz-SignedHeaders' => 'host',
            'X-Amz-Signature' => 'deadbeef',
        ]);

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            'QUERY_STRING' => $qs,
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected InvalidAccessKeyId exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidAccessKeyId', $e->getS3Code());
        }
    }

    // ─── Timestamp validation (V4 header path) ────────────────────────
    // These tests inject a valid access key so authenticate() progresses
    // past the access-key lookup and reaches validateTimestamp(). The
    // signature itself is never checked because timestamp validation runs
    // before signature calculation.

    public function testV4HeaderTimestampSkewTooLargeThrowsExpiredToken(): void
    {
        $this->injectAccessKey('ak', 'secret');
        // X-Amz-Date far in the past => skew exceeds MAX_TIMESTAMP_SKEW
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=ak/20200101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123',
            'HTTP_X_AMZ_DATE' => '20200101T000000Z',
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected ExpiredToken exception');
        } catch (S3Exception $e) {
            $this->assertEquals('ExpiredToken', $e->getS3Code());
        }
    }

    public function testV4HeaderMissingAmzDateFallsBackToSignatureFailure(): void
    {
        $this->injectAccessKey('ak', 'secret');
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=ak/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123',
            // No X-Amz-Date and no Date header. getAmzDate() falls back to the
            // current time, so timestamp validation passes; the invalid signature
            // 'abc123' then causes SignatureDoesNotMatch.
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected SignatureDoesNotMatch exception');
        } catch (S3Exception $e) {
            $this->assertEquals('SignatureDoesNotMatch', $e->getS3Code());
        }
    }

    public function testV4HeaderInvalidAmzDateFormatThrowsInvalidRequest(): void
    {
        $this->injectAccessKey('ak', 'secret');
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=ak/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc123',
            'HTTP_X_AMZ_DATE' => 'invalid-format',
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected InvalidRequest exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidRequest', $e->getS3Code());
            $this->assertStringContainsString('X-Amz-Date', $e->getMessage());
        }
    }

    public function testV4HeaderCredentialWithTooFewPartsThrowsInvalidAccessKeyId(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
            // Credential has only 3 parts instead of 5
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=ak/20260101/us-east-1, SignedHeaders=host, Signature=abc123',
            'HTTP_X_AMZ_DATE' => gmdate('Ymd\THis\Z'),
        ]);

        $auth = new Authenticator($request);

        try {
            $auth->authenticate();
            $this->fail('Expected InvalidAccessKeyId exception');
        } catch (S3Exception $e) {
            $this->assertEquals('InvalidAccessKeyId', $e->getS3Code());
        }
    }
}
