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

    private function createRequest(array $serverVars, mixed $body = null): Request
    {
        // Start from a clean baseline so headers/QUERY_STRING from previous
        // tests don't leak into the current one. Only keep essential CGI vars.
        $_SERVER = array_merge([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'QUERY_STRING' => '',
        ], $serverVars);
        if (is_resource($body)) {
            return new Request($body);
        }
        if (is_string($body) && $body !== '') {
            $input = fopen('php://temp/maxmemory:2097152', 'w+b');
            fwrite($input, $body);
            rewind($input);
            return new Request($input);
        }
        return new Request();
    }

    /**
     * Inject an access key into Config's static cache for tests that need to
     * progress past the access-key lookup step in authenticate().
     */
    private function injectAccessKey(string $accessKeyId, string $secretKey, array $allowedBuckets = ['*'], int $fileMaxSize = 0): void
    {
        $ref = new \ReflectionClass(\S3Gateway\Config::class);
        $keysProp = $ref->getProperty('accessKeys');
        $current = $keysProp->getValue() ?? [];
        $current[$accessKeyId] = [
            'secret_key' => $secretKey,
            'allowed_buckets' => $allowedBuckets,
            'file_max_size' => $fileMaxSize,
        ];
        $keysProp->setValue(null, $current);
    }

    // ─── No Authorization Header ─────────────────────────────────────

    /**
     * Produce a valid SigV4 signature for the exact request described by the
     * given header values (minimal canonical set: host, content hash, date).
     */
    private function signPutRequest(string $secret, string $amzDate, string $payloadHash): string
    {
        $canonicalRequest = implode("\n", [
            'PUT',
            '/bucket/key',
            '',
            "host:example.local\nx-amz-content-sha256:{$payloadHash}\nx-amz-date:{$amzDate}",
            '',
            'host;x-amz-content-sha256;x-amz-date',
            $payloadHash,
        ]);
        $date = substr($amzDate, 0, 8);
        $scope = "{$date}/us-east-1/s3/aws4_request";
        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secret, true);
        $kRegion = hash_hmac('sha256', 'us-east-1', $kDate, true);
        $kService = hash_hmac('sha256', 's3', $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        return hash_hmac('sha256', $stringToSign, $kSigning);
    }

    private function signedPutRequest(string $secret, string $payloadHash, string $body): Request
    {
        $amzDate = gmdate('Ymd\THis\Z');
        $signature = $this->signPutRequest($secret, $amzDate, $payloadHash);
        return $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'HTTP_HOST' => 'example.local',
            'HTTP_X_AMZ_DATE' => $amzDate,
            'HTTP_X_AMZ_CONTENT_SHA256' => $payloadHash,
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=ak/' . substr($amzDate, 0, 8) . '/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=' . $signature,
        ], $body);
    }

    public function testValidSignatureArmsAndPassesPayloadHash(): void
    {
        $this->injectAccessKey('ak', 'secret');
        $body = 'verified-body';
        $request = $this->signedPutRequest('secret', hash('sha256', $body), $body);

        $auth = new Authenticator($request);
        $this->assertSame('ak', $auth->authenticate());

        // Authentication alone must not have read the body.
        $request->enforceBodyLimit();
        $this->assertSame($body, stream_get_contents($request->getBodyStream()));
    }

    public function testValidSignatureWithMismatchedPayloadHashRejectedAtSpool(): void
    {
        $this->injectAccessKey('ak', 'secret');
        // The signature legitimately covers the declared hash; the body sent
        // afterwards differs. Integrity fails when the spool computes it.
        $request = $this->signedPutRequest('secret', hash('sha256', 'declared-body'), 'tampered-body');

        $auth = new Authenticator($request);
        $this->assertSame('ak', $auth->authenticate());

        $this->expectException(S3Exception::class);
        try {
            $request->enforceBodyLimit();
        } catch (S3Exception $e) {
            $this->assertSame('XAmzContentSHA256Mismatch', $e->getS3Code());
            throw $e;
        }
    }

    /**
     * Signed-streaming PUT without Content-Encoding: the chunk chain is
     * seeded by the real request signature and must still be verified.
     */
    private function signedStreamingPutRequest(string $secret, array $chunks, bool $tamper = false): Request
    {
        $mode = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD';
        $amzDate = gmdate('Ymd\THis\Z');
        $date = substr($amzDate, 0, 8);
        $signature = $this->signPutRequest($secret, $amzDate, $mode);

        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secret, true);
        $kRegion = hash_hmac('sha256', 'us-east-1', $kDate, true);
        $kService = hash_hmac('sha256', 's3', $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        $previous = $signature;
        $wire = '';
        foreach ([...$chunks, ''] as $chunk) {
            $previous = hash_hmac('sha256', implode("\n", [
                'AWS4-HMAC-SHA256-PAYLOAD', $amzDate, "{$date}/us-east-1/s3/aws4_request",
                $previous, hash('sha256', ''), hash('sha256', $chunk),
            ]), $kSigning);
            $sent = $tamper && $chunk !== '' ? strrev($chunk) : $chunk;
            $wire .= dechex(strlen($sent)) . ';chunk-signature=' . $previous . "\r\n" . ($sent === '' ? '' : $sent . "\r\n");
        }
        $wire .= "\r\n";

        return $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'HTTP_HOST' => 'example.local',
            'HTTP_X_AMZ_DATE' => $amzDate,
            'HTTP_X_AMZ_CONTENT_SHA256' => $mode,
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=ak/' . $date . '/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=' . $signature,
        ], $wire);
    }

    public function testSignedStreamingWithoutContentEncodingIsDecodedAndVerified(): void
    {
        $this->injectAccessKey('ak', 'secret');
        $request = $this->signedStreamingPutRequest('secret', ['abc', 'defg']);
        $auth = new Authenticator($request);
        $this->assertSame('ak', $auth->authenticate());
        $auth->checkRequestSize('ak');
        $this->assertSame('abcdefg', $request->getBody());
    }

    public function testSignedStreamingWithoutContentEncodingTamperRejected(): void
    {
        $this->injectAccessKey('ak', 'secret');
        $request = $this->signedStreamingPutRequest('secret', ['abc', 'defg'], true);
        $auth = new Authenticator($request);
        $this->assertSame('ak', $auth->authenticate());
        $this->expectException(S3Exception::class);
        try {
            $auth->checkRequestSize('ak');
        } catch (S3Exception $e) {
            $this->assertSame('SignatureDoesNotMatch', $e->getS3Code());
            throw $e;
        }
    }

    public function testUnsupportedStreamingModeRejected(): void
    {
        $this->injectAccessKey('ak', 'secret');
        $request = $this->signedPutRequest('secret', 'STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD', "0\r\n\r\n");
        $this->expectException(S3Exception::class);
        try {
            (new Authenticator($request))->authenticate();
        } catch (S3Exception $e) {
            $this->assertSame('InvalidRequest', $e->getS3Code());
            throw $e;
        }
    }

    public function testHashlessV4SpoolsUnderPerKeyLimitBeforeSignatureCheck(): void
    {
        // Global limit disabled, per-key limit 50 bytes: the pre-auth spool
        // done for signature calculation must still stop at the key's limit.
        $this->setConfigValue('MAX_UPLOAD_SIZE', '0');
        $this->injectAccessKey('ak', 'secret', ['*'], 50);
        $amzDate = gmdate('Ymd\THis\Z');
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'HTTP_HOST' => 'example.local',
            'HTTP_X_AMZ_DATE' => $amzDate,
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=ak/' . substr($amzDate, 0, 8) . '/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=' . str_repeat('0', 64),
        ], str_repeat('x', 60));

        $this->expectException(S3Exception::class);
        try {
            (new Authenticator($request))->authenticate();
        } catch (S3Exception $e) {
            $this->assertSame('EntityTooLarge', $e->getS3Code());
            $this->assertNull($request->getAccessKeyId());
            throw $e;
        }
    }

    public function testAwsChunkedEarlyCheckUsesDecodedHint(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1'); // 1 KiB

        // Wire 5000 bytes (framing overhead), decoded 900 → allowed.
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '5000',
            'HTTP_CONTENT_ENCODING' => 'aws-chunked',
            'HTTP_X_AMZ_DECODED_CONTENT_LENGTH' => '900',
        ]);
        $auth = new Authenticator($request);
        $auth->checkEarlyRequestSize();
        $this->assertTrue(true);
    }

    public function testAwsChunkedEarlyCheckRejectsOversizedDecodedHint(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1'); // 1 KiB

        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '5000',
            'HTTP_CONTENT_ENCODING' => 'aws-chunked',
            'HTTP_X_AMZ_DECODED_CONTENT_LENGTH' => '4500',
        ]);
        $auth = new Authenticator($request);

        $this->expectException(S3Exception::class);
        try {
            $auth->checkEarlyRequestSize();
        } catch (S3Exception $e) {
            $this->assertSame('EntityTooLarge', $e->getS3Code());
            throw $e;
        }
    }

    public function testAwsChunkedEarlyCheckDefersWithoutHint(): void
    {
        $this->resetConfig($this->testDir);
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1');

        // No decoded hint: cannot judge the decoded size from the wire length
        // alone; must not reject here (spool-time enforcement decides).
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '1200',
            'HTTP_CONTENT_ENCODING' => 'aws-chunked',
        ]);
        $auth = new Authenticator($request);
        $auth->checkEarlyRequestSize();
        $this->assertTrue(true);
    }

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
     * upload limits while streaming a large body. The spool counts decoded
     * bytes while reading, so checkRequestSize must still reject it.
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

        // 200-byte actual body with a forged Content-Length: 0.
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_LENGTH' => '0',
        ], str_repeat('x', 200));

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
        ], str_repeat('x', 2048));

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
