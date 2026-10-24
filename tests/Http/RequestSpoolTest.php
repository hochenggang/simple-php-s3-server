<?php

namespace S3Gateway\Tests\Http;

use PHPUnit\Framework\TestCase;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Tests\ResetsConfig;

/**
 * Body pipeline tests: bounded spooling, ownership, payload verification,
 * and aws-chunked integration at the Request level.
 */
class RequestSpoolTest extends TestCase
{
    use ResetsConfig;

    private string $testDir;
    private array $originalServer;

    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
        $this->testDir = sys_get_temp_dir() . '/s3gateway_spool_test_' . uniqid();
        $this->resetConfig($this->testDir);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;
        $this->cleanupDir($this->testDir);
    }

    /** @return resource */
    private static function streamOf(string $bytes)
    {
        $s = fopen('php://temp/maxmemory:2097152', 'w+b');
        fwrite($s, $bytes);
        rewind($s);
        return $s;
    }

    private function createRequest(array $serverVars, $input = null): Request
    {
        $_SERVER = array_merge([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'QUERY_STRING' => '',
        ], $serverVars);
        return new Request($input);
    }

    public function testGetBodyStreamReturnsDecodedContentAndReplays(): void
    {
        $body = random_bytes(100000);
        $request = $this->createRequest([], self::streamOf($body));

        $stream = $request->getBodyStream();
        $this->assertSame($body, stream_get_contents($stream));

        // Repeat calls rewind instead of re-reading the (consumed) input.
        $stream2 = $request->getBodyStream();
        $this->assertSame($body, stream_get_contents($stream2));
        $this->assertSame(strlen($body), $request->spoolSize());
    }

    public function testGetBodyMatchesStreamContent(): void
    {
        $body = "hello spool";
        $request = $this->createRequest([], self::streamOf($body));
        $this->assertSame($body, $request->getBody());
        $this->assertSame(hash('sha256', $body), $request->getPayloadSha256());
    }

    public function testHeadNeverReadsInputStream(): void
    {
        $input = self::streamOf('unused');
        $request = $this->createRequest(['REQUEST_METHOD' => 'HEAD'], $input);
        $this->assertSame('', $request->getBody());
        // Position untouched: the spool never opened the source.
        $this->assertSame(0, ftell($input));
    }

    public function testGetRequestDoesNotSpoolBody(): void
    {
        $input = self::streamOf('ignore-me');
        $request = $this->createRequest(['REQUEST_METHOD' => 'GET'], $input);
        $request->enforceBodyLimit();
        $this->assertNull($request->spoolSize());
        $this->assertSame(0, ftell($input));
    }

    public function testDeclaredPayloadHashMismatchRejected(): void
    {
        $request = $this->createRequest([], self::streamOf('actual-body'));
        $request->armPayloadVerification(hash('sha256', 'different-body'));

        $this->expectException(S3Exception::class);
        try {
            $request->getBodyStream();
        } catch (S3Exception $e) {
            $this->assertSame('XAmzContentSHA256Mismatch', $e->getS3Code());
            throw $e;
        }
    }

    public function testDeclaredPayloadHashMatchAccepted(): void
    {
        $body = 'actual-body';
        $request = $this->createRequest([], self::streamOf($body));
        $request->armPayloadVerification(hash('sha256', $body));
        $this->assertSame($body, stream_get_contents($request->getBodyStream()));
    }

    public function testStreamingPlaceholderSkipsHashComparison(): void
    {
        $request = $this->createRequest([], self::streamOf('whatever'));
        $request->armPayloadVerification('UNSIGNED-PAYLOAD');
        $this->assertSame('whatever', stream_get_contents($request->getBodyStream()));
    }

    public function testSizeLimitEnforcedDuringSpool(): void
    {
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1'); // 1 KiB
        $request = $this->createRequest([], self::streamOf(str_repeat('x', 5000)));

        $this->expectException(S3Exception::class);
        try {
            $request->enforceBodyLimit();
        } catch (S3Exception $e) {
            $this->assertSame('EntityTooLarge', $e->getS3Code());
            throw $e;
        }
    }

    public function testPerKeyLimitOverridesGlobal(): void
    {
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1024'); // 1 MiB global
        $ref = new \ReflectionClass(\S3Gateway\Config::class);
        $keysProp = $ref->getProperty('accessKeys');
        $keysProp->setValue(null, [
            'small-key' => [
                'secret_key' => 's',
                'allowed_buckets' => ['*'],
                'file_max_size' => 50,
            ],
        ]);
        $request = $this->createRequest([], self::streamOf(str_repeat('x', 60)));
        $request->setAccessKeyId('small-key');

        $this->expectException(S3Exception::class);
        $request->enforceBodyLimit();
    }

    public function testAwsChunkedDecodedThroughRequest(): void
    {
        $payload = random_bytes(40000);
        $wire = dechex(strlen($payload)) . "\r\n" . $payload . "\r\n0\r\n\r\n";
        $request = $this->createRequest(
            ['HTTP_CONTENT_ENCODING' => 'aws-chunked'],
            self::streamOf($wire)
        );
        $this->assertTrue($request->isAwsChunked());
        $this->assertSame($payload, stream_get_contents($request->getBodyStream()));
        $this->assertSame(strlen($payload), $request->spoolSize());
        $this->assertSame(hash('sha256', $payload), $request->getPayloadSha256());
    }

    public function testAwsChunkedOverheadIgnoredByLimit(): void
    {
        // 1 KiB object limit; exactly 1 KiB decoded with chunk framing above it.
        $this->setConfigValue('MAX_UPLOAD_SIZE', '1');
        $payload = random_bytes(1024);
        $chunks = str_split($payload, 64); // framing far beyond the payload
        $wire = '';
        foreach ($chunks as $chunk) {
            $wire .= dechex(strlen($chunk)) . "\r\n" . $chunk . "\r\n";
        }
        $wire .= "0\r\n\r\n";
        $this->assertGreaterThan(strlen($payload) * 1.05, strlen($wire));

        $request = $this->createRequest(
            ['HTTP_CONTENT_ENCODING' => 'aws-chunked'],
            self::streamOf($wire)
        );
        $request->enforceBodyLimit();
        $this->assertSame(1024, $request->spoolSize());
    }

    public function testStreamingHashImpliesAwsChunkedWithoutContentEncoding(): void
    {
        $wire = "5\r\nhello\r\n0\r\n\r\n";
        $request = $this->createRequest(
            ['HTTP_X_AMZ_CONTENT_SHA256' => 'STREAMING-UNSIGNED-PAYLOAD-TRAILER'],
            self::streamOf($wire)
        );
        $this->assertTrue($request->isAwsChunked());
        $this->assertSame('hello', $request->getBody());
    }

    public function testTransferEncodingChunkedBodyIsNotDecodedAgain(): void
    {
        // The SAPI already removed HTTP chunked framing; a body that merely
        // looks like chunk framing must be stored verbatim.
        $body = "5\r\nhello\r\n0\r\n\r\n";
        $request = $this->createRequest(
            ['HTTP_TRANSFER_ENCODING' => 'chunked'],
            self::streamOf($body)
        );
        $this->assertSame($body, $request->getBody());
    }

    public function testMissingAnnouncedChecksumTrailerRejected(): void
    {
        $wire = "5\r\nhello\r\n0\r\n\r\n";
        $request = $this->createRequest([
            'HTTP_CONTENT_ENCODING' => 'aws-chunked',
            'HTTP_X_AMZ_TRAILER' => 'x-amz-checksum-crc32',
        ], self::streamOf($wire));
        $this->expectException(S3Exception::class);
        try {
            $request->enforceBodyLimit();
        } catch (S3Exception $e) {
            $this->assertSame('InvalidRequest', $e->getS3Code());
            throw $e;
        }
    }

    public function testSignedTrailerChainVerified(): void
    {
        $crc = base64_encode(pack('N', crc32('hello world')));
        $request = $this->signedTrailerRequest(['hello ', 'world'], ['x-amz-checksum-crc32' => $crc]);
        $request->enforceBodyLimit();
        $this->assertSame('hello world', $request->getBody());
    }

    public function testSignedTrailerTamperRejected(): void
    {
        $crc = base64_encode(pack('N', crc32('hello world')));
        // The trailer signature covers the original checksum; swapping in
        // another (self-consistent) checksum must fail the chain.
        $request = $this->signedTrailerRequest(
            ['hello ', 'world'],
            ['x-amz-checksum-crc32' => $crc],
            ['x-amz-checksum-crc32' => base64_encode(pack('N', crc32('other')))]
        );
        $this->expectException(S3Exception::class);
        try {
            $request->enforceBodyLimit();
        } catch (S3Exception $e) {
            $this->assertSame('SignatureDoesNotMatch', $e->getS3Code());
            throw $e;
        }
    }

    public function testSignedTrailerMissingSignatureRejected(): void
    {
        $crc = base64_encode(pack('N', crc32('hi')));
        $request = $this->signedTrailerRequest(['hi'], ['x-amz-checksum-crc32' => $crc], null, false);
        $this->expectException(S3Exception::class);
        $request->enforceBodyLimit();
    }

    public function testClaimedKeyLimitAppliesBeforeAuthentication(): void
    {
        $this->setConfigValue('MAX_UPLOAD_SIZE', '0');
        $ref = new \ReflectionClass(\S3Gateway\Config::class);
        $ref->getProperty('accessKeys')->setValue(null, [
            'small-key' => ['secret_key' => 's', 'allowed_buckets' => ['*'], 'file_max_size' => 50],
        ]);
        $request = $this->createRequest([], self::streamOf(str_repeat('x', 60)));
        $request->setClaimedAccessKeyId('small-key');
        $this->assertNull($request->getAccessKeyId());

        $this->expectException(S3Exception::class);
        $request->getPayloadSha256();
    }

    /**
     * Build a STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER request whose chain
     * is seeded by $seed. $wireTrailers replaces the trailers on the wire
     * (after signing) to simulate tampering.
     */
    private function signedTrailerRequest(
        array $chunks,
        array $trailers,
        ?array $wireTrailers = null,
        bool $withSignature = true
    ): Request {
        $secret = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
        $amzDate = '20260101T000000Z';
        $scope = '20260101/us-east-1/s3/aws4_request';
        $kDate = hash_hmac('sha256', '20260101', 'AWS4' . $secret, true);
        $kRegion = hash_hmac('sha256', 'us-east-1', $kDate, true);
        $kService = hash_hmac('sha256', 's3', $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        $seed = hash('sha256', 'seed');

        $previous = $seed;
        $wire = '';
        foreach ([...$chunks, ''] as $chunk) {
            $previous = hash_hmac('sha256', implode("\n", [
                'AWS4-HMAC-SHA256-PAYLOAD', $amzDate, $scope, $previous,
                hash('sha256', ''), hash('sha256', $chunk),
            ]), $kSigning);
            $wire .= dechex(strlen($chunk)) . ';chunk-signature=' . $previous . "\r\n";
            $wire .= $chunk === '' ? '' : $chunk . "\r\n";
        }
        $canonical = '';
        foreach ($trailers as $name => $value) {
            $canonical .= "{$name}:{$value}\n";
        }
        $trailerSig = hash_hmac('sha256', implode("\n", [
            'AWS4-HMAC-SHA256-TRAILER', $amzDate, $scope, $previous, hash('sha256', $canonical),
        ]), $kSigning);
        // Layout as minio-go sends it: LF-terminated trailers, a blank line,
        // then the signature and the terminating blank line.
        foreach ($wireTrailers ?? $trailers as $name => $value) {
            $wire .= "{$name}:{$value}\n";
        }
        $wire .= "\r\n";
        if ($withSignature) {
            $wire .= "x-amz-trailer-signature:{$trailerSig}\r\n\r\n";
        }

        $request = $this->createRequest([
            'HTTP_X_AMZ_CONTENT_SHA256' => 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER',
            'HTTP_X_AMZ_TRAILER' => implode(',', array_keys($trailers)),
        ], self::streamOf($wire));
        $request->armPayloadVerification('STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER', [
            'secret' => $secret,
            'amzDate' => $amzDate,
            'region' => 'us-east-1',
            'service' => 's3',
            'signature' => $seed,
            'trailer' => true,
        ]);
        return $request;
    }

    public function testDecodedLengthHintParsed(): void
    {
        $request = $this->createRequest(['HTTP_X_AMZ_DECODED_CONTENT_LENGTH' => '123']);
        $this->assertSame(123, $request->getDecodedLengthHint());
        $request = $this->createRequest(['HTTP_X_AMZ_DECODED_CONTENT_LENGTH' => 'bogus']);
        $this->assertNull($request->getDecodedLengthHint());
    }
}
