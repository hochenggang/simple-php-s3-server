<?php

namespace S3Gateway\Tests\Http;

use PHPUnit\Framework\TestCase;
use S3Gateway\Auth\ChunkSignVerifier;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\BodySpool;

class BodySpoolTest extends TestCase
{
    /** @return resource */
    private static function streamOf(string $bytes)
    {
        $s = fopen('php://temp/maxmemory:2097152', 'w+b');
        fwrite($s, $bytes);
        rewind($s);
        return $s;
    }

    private static function drain($stream): string
    {
        rewind($stream);
        return (string)stream_get_contents($stream);
    }

    /** Build an unsigned aws-chunked or HTTP chunked wire body. */
    private static function framing(array $chunks, bool $withSignature, bool $withTrailers): string
    {
        $wire = '';
        foreach ($chunks as $chunk) {
            $header = dechex(strlen($chunk));
            if ($withSignature) {
                $header .= ';chunk-signature=' . str_repeat('0', 64);
            }
            $wire .= $header . "\r\n" . $chunk . "\r\n";
        }
        $wire .= '0' . ($withSignature ? ';chunk-signature=' . str_repeat('0', 64) : '') . "\r\n";
        if ($withTrailers) {
            $wire .= "x-amz-checksum-mode: ENABLED\r\n\r\n";
        } else {
            $wire .= "\r\n";
        }
        return $wire;
    }

    public function testPlainRoundtripHashAndSize(): void
    {
        $payload = random_bytes(300000);
        $spool = BodySpool::create(self::streamOf($payload), BodySpool::MODE_PLAIN, null);
        $this->assertSame(strlen($payload), $spool->getSize());
        $this->assertSame(hash('sha256', $payload), $spool->getSha256());
        $this->assertSame($payload, self::drain($spool->getStream()));
    }

    public function testEmptyBody(): void
    {
        $spool = BodySpool::create(self::streamOf(''), BodySpool::MODE_PLAIN, null);
        $this->assertSame(0, $spool->getSize());
        $this->assertSame(hash('sha256', ''), $spool->getSha256());
    }

    public function testLimitAbortsOnExcessDecodedBytes(): void
    {
        $this->expectException(S3Exception::class);
        try {
            BodySpool::create(self::streamOf(str_repeat('a', 100)), BodySpool::MODE_PLAIN, 64);
        } catch (S3Exception $e) {
            $this->assertSame('EntityTooLarge', $e->getS3Code());
            throw $e;
        }
    }

    public function testLimitCountsDecodedNotFramingBytes(): void
    {
        // Payload of exactly 64 bytes arrives with framing overhead well above
        // the 64-byte object limit; framing must not count against it.
        $payload = str_repeat('a', 64);
        $chunks = array_fill(0, 16, str_repeat('a', 4)); // 64 B in 16 small chunks
        $wire = $this->framing($chunks, false, false);
        $this->assertGreaterThan(strlen($payload) * 1.2, strlen($wire));
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, 64);
        $this->assertSame(64, $spool->getSize());
        $this->assertSame($payload, self::drain($spool->getStream()));
    }

    public function testAwsChunkedDecodeWithTrailers(): void
    {
        $chunks = [str_repeat('1', 50000), str_repeat('2', 33333), 'tail'];
        $wire = $this->framing($chunks, false, true);
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        $decoded = implode('', $chunks);
        $this->assertSame($decoded, self::drain($spool->getStream()));
        $this->assertSame(strlen($decoded), $spool->getSize());
        $this->assertSame(hash('sha256', $decoded), $spool->getSha256());
        $this->assertSame('ENABLED', $spool->getTrailers()['x-amz-checksum-mode']);
    }

    public function testAwsChunkedFeedFragmentationInvariance(): void
    {
        $chunks = [random_bytes(70000), 'x'];
        $wire = $this->framing($chunks, false, false);
        $reference = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);

        // Same wire fed in 7-byte fragments through the state machine.
        $spool = BodySpool::open(BodySpool::MODE_AWS_CHUNKED, null);
        for ($i = 0; $i < strlen($wire); $i += 7) {
            $spool->feed(substr($wire, $i, 7));
        }
        $spool->finish();

        $this->assertSame(self::drain($reference->getStream()), self::drain($spool->getStream()));
        $this->assertSame($reference->getSha256(), $spool->getSha256());
        $this->assertSame($reference->getSize(), $spool->getSize());
    }

    public function testAwsChunkedIncompleteRejected(): void
    {
        // Missing the terminating zero chunk.
        $wire = "5\r\nhello\r\n";
        $this->expectException(S3Exception::class);
        try {
            BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        } catch (S3Exception $e) {
            $this->assertSame('InvalidRequest', $e->getS3Code());
            throw $e;
        }
    }

    public function testAwsChunkedBadChunkSizeRejected(): void
    {
        $wire = "zz\r\nhello\r\n0\r\n\r\n";
        $this->expectException(S3Exception::class);
        BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
    }

    public function testSha256CanBeReadRepeatedly(): void
    {
        $spool = BodySpool::create(self::streamOf('abc'), BodySpool::MODE_PLAIN, null);
        $this->assertSame(hash('sha256', 'abc'), $spool->getSha256());
        $this->assertSame(hash('sha256', 'abc'), $spool->getSha256());
    }

    public function testTrailerSignatureAfterBlankLineIsParsed(): void
    {
        // minio-go wire layout for STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER.
        $wire = "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAA\n\r\nx-amz-trailer-signature:"
            . str_repeat('a', 64) . "\r\n\r\n";
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        $this->assertSame([
            'x-amz-checksum-crc32' => 'AAAA',
            'x-amz-trailer-signature' => str_repeat('a', 64),
        ], $spool->getTrailers());
    }

    public function testUnsignedTrailersEndingAtEofAccepted(): void
    {
        $wire = "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAA\r\n\r\n";
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        $this->assertSame(['x-amz-checksum-crc32' => 'AAAA'], $spool->getTrailers());
    }

    public function testTrailersWithoutTerminatingBlankLineRejected(): void
    {
        $wire = "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:AAAA\r\n";
        $this->expectException(S3Exception::class);
        BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
    }

    public function testOversizedTrailerRejected(): void
    {
        $wire = "3\r\nabc\r\n0\r\nx-amz-checksum-sha256: " . str_repeat('A', 20000);
        $this->expectException(S3Exception::class);
        try {
            BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        } catch (S3Exception $e) {
            $this->assertSame('InvalidRequest', $e->getS3Code());
            throw $e;
        }
    }

    public function testChecksumTrailerVerification(): void
    {
        $payload = 'hello world';
        $trailer = 'x-amz-checksum-sha256: ' . base64_encode(hex2bin(hash('sha256', $payload))) . "\r\n";
        $wire = "b\r\n{$payload}\r\n0\r\n{$trailer}\r\n";
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        $spool->verifyChecksumTrailers(); // must not throw
        $this->assertSame($payload, self::drain($spool->getStream()));
    }

    public function testChecksumTrailerMismatchRejected(): void
    {
        $payload = 'hello world';
        $wrong = base64_encode(hex2bin(hash('sha256', 'other')));
        $wire = "b\r\n{$payload}\r\n0\r\nx-amz-checksum-sha256: {$wrong}\r\n\r\n";
        $this->expectException(S3Exception::class);
        try {
            $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
            $spool->verifyChecksumTrailers();
        } catch (S3Exception $e) {
            $this->assertSame('XAmzContentChecksumInvalid', $e->getS3Code());
            throw $e;
        }
    }

    public function testCrc32TrailerVerification(): void
    {
        // Value as S3/SDKs compute it: big-endian IEEE CRC32 (zlib's crc32()),
        // base64. Deliberately not built with the code's own hash call.
        $payload = 'hello';
        $value = base64_encode(pack('N', crc32($payload)));
        $this->assertSame('NhCmhg==', $value);
        $wire = $this->framingFramed($payload, "x-amz-checksum-crc32: {$value}\r\n");
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        $spool->verifyChecksumTrailers();
        $this->assertSame($payload, self::drain($spool->getStream()));
    }

    public function testCrc32cTrailerVerification(): void
    {
        // RFC 3720 check value: CRC32C("123456789") = 0xE3069283.
        $payload = '123456789';
        $value = base64_encode(pack('N', 0xE3069283));
        $wire = $this->framingFramed($payload, "x-amz-checksum-crc32c: {$value}\r\n");
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        $spool->verifyChecksumTrailers();
        $this->assertSame($payload, self::drain($spool->getStream()));
    }

    public function testCrc32cTrailerMismatchRejected(): void
    {
        $value = base64_encode(pack('N', 0xE3069283));
        $wire = $this->framingFramed('12345678X', "x-amz-checksum-crc32c: {$value}\r\n");
        $this->expectException(S3Exception::class);
        $spool = BodySpool::create(self::streamOf($wire), BodySpool::MODE_AWS_CHUNKED, null);
        $spool->verifyChecksumTrailers();
    }

    private function framingFramed(string $payload, string $trailerBlock): string
    {
        return dechex(strlen($payload)) . "\r\n" . $payload . "\r\n0\r\n" . $trailerBlock . "\r\n";
    }

    public function testSignedChunksVerifiedDuringSpool(): void
    {
        [$wire, $verifier] = $this->signedWire(['hello', 'world!!']);
        $spool = BodySpool::create($wire, BodySpool::MODE_AWS_CHUNKED, null, $verifier);
        $this->assertSame('helloworld!!', self::drain($spool->getStream()));
    }

    public function testSignedChunkTamperRejected(): void
    {
        [$wire, $verifier] = $this->signedWire(['hello', 'world!!']);
        // Flip one payload byte; its signature no longer matches.
        $wire = self::streamOf(str_replace('hello', 'hellx', $this->wireToString($wire)));
        $this->expectException(S3Exception::class);
        try {
            BodySpool::create($wire, BodySpool::MODE_AWS_CHUNKED, null, $verifier);
        } catch (S3Exception $e) {
            $this->assertSame('SignatureDoesNotMatch', $e->getS3Code());
            throw $e;
        }
    }

    /** @return array{resource, callable} wire stream and chained verifier */
    private function signedWire(array $chunks): array
    {
        $secret = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
        $amzDate = '20260101T000000Z';
        $seed = hash('sha256', 'seed');
        $wire = '';
        $previous = $seed;
        foreach ($chunks as $chunk) {
            $sig = $this->chunkSignature($secret, $amzDate, $previous, $chunk);
            $wire .= dechex(strlen($chunk)) . ';chunk-signature=' . $sig . "\r\n" . $chunk . "\r\n";
            $previous = $sig;
        }
        $sig = $this->chunkSignature($secret, $amzDate, $previous, '');
        $wire .= '0;chunk-signature=' . $sig . "\r\n\r\n";

        $verifierObj = new ChunkSignVerifier($secret, $amzDate, 'us-east-1', 's3', $seed);
        $verifier = static function (string $dataHashHex, ?string $signatureHex) use ($verifierObj): void {
            $verifierObj->verify($dataHashHex, $signatureHex ?? '');
        };
        return [self::streamOf($wire), $verifier];
    }

    private function wireToString($stream): string
    {
        rewind($stream);
        return (string)stream_get_contents($stream);
    }

    private function chunkSignature(string $secret, string $amzDate, string $previous, string $data): string
    {
        $kDate = hash_hmac('sha256', substr($amzDate, 0, 8), 'AWS4' . $secret, true);
        $kRegion = hash_hmac('sha256', 'us-east-1', $kDate, true);
        $kService = hash_hmac('sha256', 's3', $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256-PAYLOAD',
            $amzDate,
            substr($amzDate, 0, 8) . '/us-east-1/s3/aws4_request',
            $previous,
            hash('sha256', ''),
            hash('sha256', $data),
        ]);
        return hash_hmac('sha256', $stringToSign, $kSigning);
    }
}
