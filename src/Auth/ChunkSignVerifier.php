<?php

namespace S3Gateway\Auth;

use S3Gateway\Exception\S3Exception;

/**
 * Verifies the chunk signature chain of
 * x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD uploads.
 *
 * Each chunk is signed with:
 *   StringToSign = "AWS4-HMAC-SHA256-PAYLOAD\n"
 *                . date "\n" . scope "\n"
 *                . previous-signature "\n"
 *                . sha256("") "\n"
 *                . sha256(chunk-data)
 * seeded by the SigV4 signature of the request itself. The terminating
 * zero chunk carries the signature over empty data.
 *
 * STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER continues the chain with one
 * more signature, sent as the x-amz-trailer-signature trailer:
 *   StringToSign = "AWS4-HMAC-SHA256-TRAILER\n"
 *                . date "\n" . scope "\n"
 *                . previous-signature "\n"
 *                . sha256(canonical trailers)
 * where each trailer contributes "name:value\n" in the order received.
 */
final class ChunkSignVerifier
{
    private string $amzDate;
    private string $scope;
    private string $kSigning;
    private string $previous;

    public function __construct(
        string $secretKey,
        string $amzDate,
        string $region,
        string $service,
        string $requestSignature
    ) {
        $date = substr($amzDate, 0, 8);
        $this->amzDate = $amzDate;
        $this->scope = "{$date}/{$region}/{$service}/aws4_request";

        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $this->kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);
        $this->previous = $requestSignature;
    }

    /**
     * @param string $dataHashHex    sha256 hex of the complete chunk payload
     * @param string $providedHex    signature announced in the chunk header
     * @throws S3Exception SignatureDoesNotMatch
     */
    public function verify(string $dataHashHex, string $providedHex): void
    {
        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256-PAYLOAD',
            $this->amzDate,
            $this->scope,
            $this->previous,
            hash('sha256', ''),
            $dataHashHex,
        ]);
        $this->check($stringToSign, $providedHex, 'Chunk signature verification failed');
    }

    /**
     * @param array<string,string> $trailers lowercased name => value, in wire
     *                                       order, without the signature itself
     * @param string $providedHex            x-amz-trailer-signature value
     * @throws S3Exception SignatureDoesNotMatch
     */
    public function verifyTrailer(array $trailers, string $providedHex): void
    {
        $canonical = '';
        foreach ($trailers as $name => $value) {
            $canonical .= "{$name}:{$value}\n";
        }
        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256-TRAILER',
            $this->amzDate,
            $this->scope,
            $this->previous,
            hash('sha256', $canonical),
        ]);
        $this->check($stringToSign, strtolower(trim($providedHex)), 'Trailer signature verification failed');
    }

    private function check(string $stringToSign, string $providedHex, string $message): void
    {
        $expected = hash_hmac('sha256', $stringToSign, $this->kSigning);
        if ($providedHex === '' || !hash_equals($expected, $providedHex)) {
            throw S3Exception::signatureDoesNotMatch($message);
        }
        $this->previous = $providedHex;
    }
}
