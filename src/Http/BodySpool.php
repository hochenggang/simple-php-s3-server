<?php

namespace S3Gateway\Http;

use S3Gateway\Exception\S3Exception;

/**
 * Incrementally spools a request body from a readable stream into a bounded
 * memory/disk temp stream while computing its SHA-256 payload hash.
 *
 * The full body never becomes a PHP string: bytes move in blocks of at most
 * 64 KiB, and php://temp spills to disk past 2 MiB. The "aws-chunked"
 * framing is decoded during the same pass: hex(size)[;chunk-signature=hex]
 * data ... terminating zero chunk, then optional trailers (x-amz-checksum-*,
 * x-amz-trailer-signature). Signatures, when a verifier is supplied, are
 * checked chunk by chunk.
 *
 * HTTP Transfer-Encoding: chunked is not decoded here: every PHP SAPI
 * (Apache, FPM behind nginx, the built-in server) hands php://input to the
 * script already de-chunked, so decoding again would corrupt the body.
 *
 * The limit applies to decoded bytes and aborts the read as soon as the
 * excess arrives, so an oversized upload fails without ever materializing.
 */
final class BodySpool
{
    public const MODE_PLAIN = 'plain';
    public const MODE_AWS_CHUNKED = 'aws-chunked';

    private const BLOCK = 65536;
    private const MAX_HEADER_LINE = 16384;

    private const STATE_HEADER = 0;
    private const STATE_DATA = 1;
    private const STATE_CRLF = 2;
    private const STATE_TRAILERS = 3;
    private const STATE_DONE = 4;

    /** @var resource */
    private $stream;
    /** @var \HashContext */
    private $hash;
    /** finalized hex of $hash; hash_final() may only run once per context */
    private ?string $sha256 = null;
    /** @var resource|null */
    private $input;
    private string $mode;
    private ?int $maxBytes;
    /** @var callable(null):void $chunkVerifier(string $dataHashHex, ?string $signatureHex) */
    private $chunkVerifier;

    private int $size = 0;
    private string $pending = '';
    private int $state = self::STATE_HEADER;
    private int $chunkRemaining = 0;
    private string $chunkSignature = '';
    /** @var \HashContext|null SHA-256 over the current whole chunk while it arrives */
    private $chunkHash = null;
    private bool $finished = false;
    /** a blank line followed at least one trailer (signature may still follow) */
    private bool $trailerBlockClosed = false;
    /** @var array<string,string> lowercased trailer name => value */
    private array $trailers = [];

    /**
     * @param resource $input            readable source (php://input or test stream)
     * @param callable|null $chunkVerifier called as ($dataHashHex, $signatureHex|null);
     *                                     must throw on rejection
     */
    private function __construct(string $mode, ?int $maxBytes, ?callable $chunkVerifier)
    {
        $stream = fopen('php://temp/maxmemory:2097152', 'w+b');
        if ($stream === false) {
            throw new \RuntimeException('Cannot allocate request body spool');
        }
        $this->stream = $stream;
        $this->hash = hash_init('sha256');
        $this->mode = $mode;
        $this->maxBytes = $maxBytes;
        $this->chunkVerifier = $chunkVerifier;
    }

    /**
     * Incremental API: open a spool, feed arbitrary blocks, finish().
     * create() is the common read-to-completion path.
     *
     * @param callable|null $chunkVerifier see create()
     */
    public static function open(string $mode, ?int $maxBytes, ?callable $chunkVerifier = null): self
    {
        return new self($mode, $maxBytes, $chunkVerifier);
    }

    /**
     * Reads the source to completion. On any exception the spool stays usable
     * for cleanup but must not be treated as a valid body.
     */
    public static function create($input, string $mode, ?int $maxBytes, ?callable $chunkVerifier = null): self
    {
        if (!is_resource($input)) {
            throw new \InvalidArgumentException('Body spool input must be a stream resource');
        }
        $spool = new self($mode, $maxBytes, $chunkVerifier);
        try {
            while (!feof($input)) {
                $block = fread($input, self::BLOCK);
                if ($block === false) {
                    throw S3Exception::invalidRequest('Failed reading request body');
                }
                if ($block === '') {
                    continue;
                }
                $spool->feed($block);
            }
            $spool->finish();
        } catch (\Throwable $e) {
            fclose($spool->stream);
            $spool->stream = fopen('php://memory', 'r+b');
            throw $e;
        }
        rewind($spool->stream);
        return $spool;
    }

    /**
     * Feed one arbitrary-length block of wire bytes (public for tests).
     */
    public function feed(string $bytes): void
    {
        if ($this->finished) {
            throw S3Exception::invalidRequest('Request body already finished');
        }
        if ($this->mode === self::MODE_PLAIN) {
            $this->write($bytes);
            return;
        }
        if ($this->state === self::STATE_DONE) {
            return; // trailing bytes after the terminating chunk are ignored
        }

        $this->pending .= $bytes;
        while (true) {
            switch ($this->state) {
                case self::STATE_HEADER:
                    if (!$this->consumeHeader()) {
                        return;
                    }
                    break;
                case self::STATE_DATA:
                    if (!$this->consumeData()) {
                        return;
                    }
                    break;
                case self::STATE_CRLF:
                    if (strlen($this->pending) < 2) {
                        if ($this->pending !== '' && $this->pending !== "\r") {
                            throw S3Exception::invalidRequest('Malformed chunked request body');
                        }
                        return;
                    }
                    if (substr($this->pending, 0, 2) !== "\r\n") {
                        throw S3Exception::invalidRequest('Malformed chunked request body');
                    }
                    $this->pending = substr($this->pending, 2);
                    $this->state = self::STATE_HEADER;
                    break;
                case self::STATE_TRAILERS:
                    if (!$this->consumeTrailers()) {
                        return;
                    }
                    break;
                default: // STATE_DONE
                    $this->pending = '';
                    return;
            }
        }
    }

    public function finish(): void
    {
        if ($this->finished) {
            return;
        }
        $this->finished = true;
        if ($this->mode === self::MODE_PLAIN) {
            return;
        }
        // Chunked framings must end with their terminating zero chunk.
        // Truncation here means the declared stream ended mid-framing; the
        // legacy decoder silently accepted that and stored partial bodies.
        // Unsigned trailers end with a blank line followed by EOF.
        $trailersEnded = $this->state === self::STATE_TRAILERS
            && $this->trailerBlockClosed
            && trim($this->pending) === '';
        if ($this->state !== self::STATE_DONE && !$trailersEnded) {
            throw S3Exception::invalidRequest('Incomplete chunked request body');
        }
    }

    /** @return resource stream positioned at 0 */
    public function getStream()
    {
        return $this->stream;
    }

    public function getSize(): int
    {
        return $this->size;
    }

    /** SHA-256 hex of the decoded bytes. */
    public function getSha256(): string
    {
        return $this->sha256 ??= hash_final($this->hash);
    }

    /** @return array<string,string> */
    public function getTrailers(): array
    {
        return $this->trailers;
    }

    /**
     * Verify x-amz-checksum-* trailers against the spooled bytes.
     * Unknown trailer algorithms (e.g. x-amz-checksum-crc64nvme, which PHP's
     * hash extension lacks) are ignored.
     */
    public function verifyChecksumTrailers(): void
    {
        // S3's CRC32 is the IEEE/zlib variant, which PHP names "crc32b";
        // PHP's "crc32" is the bzip2 variant and never matches.
        $algorithms = [
            'x-amz-checksum-crc32' => 'crc32b',
            'x-amz-checksum-crc32c' => 'crc32c',
            'x-amz-checksum-sha1' => 'sha1',
            'x-amz-checksum-sha256' => 'sha256',
        ];
        foreach ($this->trailers as $name => $value) {
            if (!isset($algorithms[$name])) {
                continue;
            }
            $context = hash_init($algorithms[$name]);
            rewind($this->stream);
            while (!feof($this->stream)) {
                $block = fread($this->stream, self::BLOCK);
                if ($block === false || $block === '') {
                    break;
                }
                hash_update($context, $block);
            }
            rewind($this->stream);
            $binary = hex2bin(hash_final($context));
            if (!hash_equals(base64_encode($binary), trim($value))) {
                throw S3Exception::xAmzContentChecksumInvalid(
                    "Checksum mismatch for trailer {$name}"
                );
            }
        }
    }

    // ─── state machine ────────────────────────────────────────────────

    /** @return bool true when the state advanced and the loop should continue */
    private function consumeHeader(): bool
    {
        $pos = strpos($this->pending, "\n");
        if ($pos === false) {
            if (strlen($this->pending) > self::MAX_HEADER_LINE) {
                throw S3Exception::invalidRequest('Malformed chunk header in request body');
            }
            return false;
        }
        $line = rtrim(substr($this->pending, 0, $pos), "\r");
        $this->pending = substr($this->pending, $pos + 1);

        $semicolon = strpos($line, ';');
        $sizePart = trim($semicolon !== false ? substr($line, 0, $semicolon) : $line);
        $this->chunkSignature = '';
        if ($semicolon !== false) {
            if (preg_match('/chunk-signature=([a-f0-9]{64})/i', substr($line, $semicolon + 1), $m)) {
                $this->chunkSignature = strtolower($m[1]);
            }
        }
        if ($sizePart === '' || preg_match('/^[0-9a-fA-F]{1,16}$/', $sizePart) !== 1) {
            throw S3Exception::invalidRequest('Malformed chunk size in request body');
        }
        $size = (int) hexdec($sizePart);
        if ($size === 0) {
            if ($this->chunkVerifier !== null) {
                // Signed streaming also signs the terminating empty chunk.
                ($this->chunkVerifier)(hash('sha256', ''), $this->chunkSignature);
            }
            $this->state = self::STATE_TRAILERS;
            return true;
        }
        $this->chunkRemaining = $size;
        if ($this->chunkVerifier !== null) {
            $this->chunkHash = hash_init('sha256');
        }
        $this->state = self::STATE_DATA;
        return true;
    }

    /** @return bool true when more of the pending buffer can be consumed */
    private function consumeData(): bool
    {
        if ($this->pending === '') {
            return false;
        }
        $take = min($this->chunkRemaining, strlen($this->pending));
        $data = substr($this->pending, 0, $take);
        $this->pending = substr($this->pending, $take);
        $this->chunkRemaining -= $take;
        if ($this->chunkHash !== null) {
            hash_update($this->chunkHash, $data);
        }
        $this->write($data);
        if ($this->chunkRemaining === 0) {
            if ($this->chunkHash !== null && $this->chunkVerifier !== null) {
                // AWS chunk signatures cover the complete chunk payload.
                ($this->chunkVerifier)(hash_final($this->chunkHash), $this->chunkSignature);
                $this->chunkHash = null;
            }
            $this->state = self::STATE_CRLF;
        }
        return $this->pending !== '';
    }

    /** @return bool true when the state advanced and the loop should continue */
    private function consumeTrailers(): bool
    {
        while (true) {
            $pos = strpos($this->pending, "\n");
            if ($pos === false) {
                // Dropping an oversized trailer would silently skip its
                // checksum (or signature) verification.
                if (strlen($this->pending) > self::MAX_HEADER_LINE) {
                    throw S3Exception::invalidRequest('Malformed trailer in request body');
                }
                return false;
            }
            $line = rtrim(substr($this->pending, 0, $pos), "\r");
            $this->pending = substr($this->pending, $pos + 1);
            if ($line === '') {
                // Signed-trailer clients (minio-go, AWS) put a blank line
                // between the checksum trailers and x-amz-trailer-signature:
                //   x-amz-checksum-crc32:…\n \r\n x-amz-trailer-signature:…\r\n \r\n
                // so a blank line after trailers ends the block only once the
                // signature arrived or the stream ends (see finish()).
                if ($this->trailers === [] || isset($this->trailers['x-amz-trailer-signature'])) {
                    $this->state = self::STATE_DONE;
                    return false;
                }
                $this->trailerBlockClosed = true;
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon !== false) {
                $this->trailers[strtolower(trim(substr($line, 0, $colon)))] = trim(substr($line, $colon + 1));
            }
        }
    }

    private function write(string $data): void
    {
        $len = strlen($data);
        if ($len === 0) {
            return;
        }
        if ($this->maxBytes !== null && $this->size + $len > $this->maxBytes) {
            throw S3Exception::entityTooLarge($this->size + $len, $this->maxBytes);
        }
        hash_update($this->hash, $data);
        $written = fwrite($this->stream, $data);
        if ($written === false || $written !== $len) {
            throw S3Exception::internalError('Failed writing request body spool');
        }
        $this->size += $len;
    }
}
