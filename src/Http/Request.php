<?php

namespace S3Gateway\Http;

use S3Gateway\Auth\ChunkSignVerifier;
use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Logger;

class Request
{
    private string $method;
    private string $uri;
    private string $queryString;
    private array $headers = [];
    /** @var array<string,string> lowercased header name => value, for O(1) lookup */
    private array $lowerHeaders = [];
    private string $bucket = '';
    private string $key = '';
    private array $queryParams = [];

    /** @var resource|null injected body source for tests; null reads php://input */
    private $inputStream;
    private ?BodySpool $spool = null;
    private ?string $accessKeyId = null;
    private ?string $claimedAccessKeyId = null;
    /** @var string|null declared x-amz-content-sha256 armed by the Authenticator */
    private ?string $declaredPayloadHash = null;
    /** @var array{secret:string,amzDate:string,region:string,service:string,signature:string,trailer?:bool}|null */
    private ?array $streamingPayloadCtx = null;

    /**
     * @param resource|null $inputStream body source override (tests); production
     *                                   passes null and the body is read from
     *                                   php://input exactly once, on demand.
     */
    public function __construct($inputStream = null)
    {
        $originalMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->method = $this->detectMethod($originalMethod);
        $this->uri = $this->parseUri();
        $this->queryString = $_SERVER['QUERY_STRING'] ?? '';
        $this->headers = $this->parseHeaders();
        $this->inputStream = $inputStream;
        // The body is never read eagerly: HEAD/GET/list requests never touch
        // php://input, and uploads are spooled to disk-backed temp storage in
        // bounded blocks instead of being loaded into a PHP string.
        $this->parsePath();
        $this->parseQueryParams();
    }

    /**
     * Detect the actual HTTP method, handling HEAD->GET conversion by web servers
     */
    private function detectMethod(string $originalMethod): string
    {
        if ($originalMethod === 'HEAD') {
            return 'HEAD';
        }

        if ($originalMethod !== 'GET') {
            return $originalMethod;
        }

        // Check X-HTTP-Method-Override header
        if (isset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
            $override = strtoupper($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
            if ($override === 'HEAD') {
                return 'HEAD';
            }
        }

        return $originalMethod;
    }

    private function parseUri(): string
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $pos = strpos($uri, '?');
        if ($pos !== false) {
            $uri = substr($uri, 0, $pos);
        }
        return $uri;
    }

    private function parseHeaders(): array
    {
        $headers = [];
        $lower = [];
        $add = function (string $name, ?string $value) use (&$headers, &$lower): void {
            if ($value === null) {
                return;
            }
            // Clean line folding from proxy headers (e.g. Cloudflare)
            $value = str_replace(["\r\n", "\r", "\n"], ' ', $value);
            $value = preg_replace('/\s+/', ' ', $value);
            $value = trim($value);
            $upper = strtoupper($name);
            $headers[$upper] = $value;
            $lower[strtolower($name)] = $value;
        };

        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $headerName = str_replace('_', '-', substr($key, 5));
                $add($headerName, $value);
            }
        }

        if (isset($_SERVER['CONTENT_TYPE'])) {
            $add('Content-Type', $_SERVER['CONTENT_TYPE']);
        }
        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $add('Content-Length', $_SERVER['CONTENT_LENGTH']);
        }
        if (isset($_SERVER['HTTP_RANGE'])) {
            $add('Range', $_SERVER['HTTP_RANGE']);
        }

        // Trust X-Forwarded-Host only when explicitly enabled behind a reverse proxy.
        // Default false: prevents Host forgery when directly exposed.
        if (Config::trustProxyHeaders() && isset($lower['x-forwarded-host'])) {
            $add('Host', $lower['x-forwarded-host']);
        }

        $this->lowerHeaders = $lower;

        if (Config::appDebug()) {
            Logger::debug("[Request] Method: {$this->method}, URI: {$this->uri}");
            foreach ($headers as $name => $value) {
                Logger::debug("[Request] Header: {$name}: {$value}");
            }
        }

        return $headers;
    }

    private function parsePath(): void
    {
        $path = $this->uri;
        // Route relative to the front controller, but retain the full URI for
        // SigV4: clients sign the deployment prefix as part of the request path.
        $base = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/index.php'), '/');
        if ($base !== '' && str_starts_with($base, '/') && str_starts_with($path, $base . '/')) {
            $path = substr($path, strlen($base));
        }
        $path = trim($path, '/');
        $parts = explode('/', $path, 2);

        $this->bucket = $parts[0] ?? '';

        if (isset($parts[1])) {
            $this->key = $parts[1];
        }
    }

    private function parseQueryParams(): void
    {
        parse_str($this->queryString, $this->queryParams);
    }

    // ─── Body pipeline ────────────────────────────────────────────────

    /**
     * aws-chunked framing is implied by any STREAMING-* x-amz-content-sha256,
     * like S3 does: keying it on Content-Encoding alone would let a request
     * that omits (or strips an unsigned) Content-Encoding skip chunk
     * signature verification and store raw framing as the object.
     */
    public function isAwsChunked(): bool
    {
        $declared = $this->getHeader('X-Amz-Content-Sha256');
        if ($declared !== null && str_starts_with($declared, 'STREAMING-')) {
            return true;
        }
        $contentEncoding = $this->getHeader('Content-Encoding');
        return $contentEncoding !== null && stripos($contentEncoding, 'aws-chunked') !== false;
    }

    /**
     * X-Amz-Decoded-Content-Length sent by SDKs for aws-chunked uploads:
     * the exact size of the decoded payload, usable for size checks that must
     * not count framing/checksum overhead.
     */
    public function getDecodedLengthHint(): ?int
    {
        $value = $this->getHeader('X-Amz-Decoded-Content-Length');
        if ($value === null || preg_match('/^\d+$/', $value) !== 1) {
            return null;
        }
        return (int)$value;
    }

    public function setAccessKeyId(string $accessKeyId): void
    {
        $this->accessKeyId = $accessKeyId;
    }

    public function getAccessKeyId(): ?string
    {
        return $this->accessKeyId;
    }

    /**
     * Access key named by the request's credential, before its signature is
     * checked. Used only to select the body limit when the legacy hash-less
     * SigV4 path must spool during signature calculation; never treated as
     * authenticated.
     */
    public function setClaimedAccessKeyId(string $accessKeyId): void
    {
        $this->claimedAccessKeyId = $accessKeyId;
    }

    /**
     * Arm payload verification after successful authentication. Called by
     * the Authenticator once the signature over the headers matched.
     *
     * @param string|null $declared         x-amz-content-sha256 header value
     * @param array|null  $streamingCtx     secret/date/region/service/request
     *                                      signature for signed streaming chunks
     */
    public function armPayloadVerification(?string $declared, ?array $streamingCtx = null): void
    {
        $this->declaredPayloadHash = $declared;
        $this->streamingPayloadCtx = $streamingCtx;
        // The legacy hash-less path may already have spooled the body before
        // arming; verify immediately in that case.
        if ($this->spool !== null) {
            $this->verifyDeclaredPayloadHash();
        }
    }

    /**
     * Size limit applicable to this request's body: per-key override when
     * the authenticated key defines one, else global MAX_UPLOAD_SIZE.
     * 0 disables the limit.
     */
    public function maxBodyBytes(): ?int
    {
        $max = 0;
        $keyId = $this->accessKeyId ?? $this->claimedAccessKeyId;
        if ($keyId !== null) {
            $max = Config::getFileMaxSize($keyId);
        }
        if ($max <= 0) {
            $max = Config::maxUploadSize();
        }
        return $max > 0 ? $max : null;
    }

    /**
     * Read and spool the body under its effective limit. Methods without a
     * request body are skipped. This is the authoritative enforcement point
     * for upload size: decoded bytes are counted while streaming, and the
     * read aborts as soon as the limit is exceeded.
     */
    public function enforceBodyLimit(): void
    {
        if (in_array($this->method, ['GET', 'HEAD', 'DELETE', 'OPTIONS'], true)) {
            return;
        }
        $this->ensureSpooled();
    }

    public function spoolSize(): ?int
    {
        return $this->spool?->getSize();
    }

    private function ensureSpooled(): BodySpool
    {
        if ($this->spool !== null) {
            return $this->spool;
        }

        if ($this->method === 'HEAD') {
            $input = self::emptyStream();
            $mode = BodySpool::MODE_PLAIN;
        } else {
            $input = $this->inputStream ?? $this->openInputStream();
            // Transfer-Encoding: chunked is already decoded by the SAPI.
            $mode = $this->isAwsChunked() ? BodySpool::MODE_AWS_CHUNKED : BodySpool::MODE_PLAIN;
        }

        $verifier = null;
        $chunkSigner = null;
        if ($this->streamingPayloadCtx !== null) {
            $chunkSigner = new ChunkSignVerifier(
                $this->streamingPayloadCtx['secret'],
                $this->streamingPayloadCtx['amzDate'],
                $this->streamingPayloadCtx['region'],
                $this->streamingPayloadCtx['service'],
                $this->streamingPayloadCtx['signature']
            );
            $verifier = static function (string $dataHashHex, ?string $signatureHex) use ($chunkSigner): void {
                $chunkSigner->verify($dataHashHex, $signatureHex ?? '');
            };
        }

        $spool = BodySpool::create($input, $mode, $this->maxBodyBytes(), $verifier);
        $trailers = $spool->getTrailers();
        if ($chunkSigner !== null && ($this->streamingPayloadCtx['trailer'] ?? false)) {
            $signature = $trailers['x-amz-trailer-signature'] ?? '';
            unset($trailers['x-amz-trailer-signature']);
            $chunkSigner->verifyTrailer($trailers, $signature);
        }
        $this->requireDeclaredTrailers($trailers);
        $spool->verifyChecksumTrailers();
        $this->spool = $spool;
        $this->verifyDeclaredPayloadHash();
        return $this->spool;
    }

    /**
     * Checksum trailers announced in x-amz-trailer must actually arrive;
     * otherwise a client (or a truncating intermediary) could drop the
     * checksum and have the body accepted unverified.
     *
     * @param array<string,string> $trailers
     */
    private function requireDeclaredTrailers(array $trailers): void
    {
        $announced = $this->getHeader('X-Amz-Trailer');
        if ($announced === null || !$this->isAwsChunked()) {
            return;
        }
        foreach (explode(',', $announced) as $name) {
            $name = strtolower(trim($name));
            if (str_starts_with($name, 'x-amz-checksum-') && !isset($trailers[$name])) {
                throw S3Exception::invalidRequest("Missing announced trailer {$name}");
            }
        }
    }

    private function verifyDeclaredPayloadHash(): void
    {
        $declared = $this->declaredPayloadHash;
        if ($declared === null || $this->spool === null) {
            return;
        }
        // Streaming/unsigned placeholders are not content hashes. Signed
        // streaming was verified chunk by chunk during spooling.
        if (preg_match('/^[a-fA-F0-9]{64}$/', $declared) !== 1) {
            return;
        }
        if (!hash_equals($declared, $this->spool->getSha256())) {
            throw S3Exception::xAmzContentSha256Mismatch();
        }
    }

    /** @return resource */
    private function openInputStream()
    {
        $input = fopen('php://input', 'rb');
        if ($input === false) {
            return self::emptyStream();
        }
        return $input;
    }

    /** @return resource */
    private static function emptyStream()
    {
        $stream = fopen('php://memory', 'r+b');
        if ($stream === false) {
            throw new \RuntimeException('Cannot allocate empty stream');
        }
        return $stream;
    }

    // ─── Public accessors ─────────────────────────────────────────────

    public function getMethod(): string
    {
        return $this->method;
    }

    public function getUri(): string
    {
        return $this->uri;
    }

    public function getQueryString(): string
    {
        return $this->queryString;
    }

    public function getHeader(string $name): ?string
    {
        // O(1) case-insensitive lookup via the prebuilt lowercased map.
        return $this->lowerHeaders[strtolower($name)] ?? null;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Decoded request body as a string. Only intended for the small XML
     * request bodies (Delete, CompleteMultipartUpload) and legacy signature
     * fallbacks; upload endpoints use getBodyStream(). The result is bounded
     * by the configured upload limit.
     */
    public function getBody(): string
    {
        if ($this->method === 'HEAD') {
            return '';
        }
        $stream = $this->ensureSpooled()->getStream();
        rewind($stream);
        $data = stream_get_contents($stream);
        return $data === false ? '' : $data;
    }

    /**
     * Readable stream of the decoded request body, rewound to position 0.
     * The Request owns the stream and closes it implicitly at request end;
     * callers must read but must not fclose it. Repeat calls return the
     * stream again from position 0.
     */
    public function getBodyStream()
    {
        $stream = $this->ensureSpooled()->getStream();
        rewind($stream);
        return $stream;
    }

    /** SHA-256 hex over the decoded body (spools if needed). */
    public function getPayloadSha256(): string
    {
        return $this->ensureSpooled()->getSha256();
    }

    /** @return array<string,string> request trailers, lowercased names */
    public function getTrailers(): array
    {
        return $this->ensureSpooled()->getTrailers();
    }

    public function getBucket(): string
    {
        return $this->bucket;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getQueryParam(string $name): ?string
    {
        return $this->queryParams[$name] ?? null;
    }

    public function hasQueryParam(string $name): bool
    {
        return isset($this->queryParams[$name]);
    }

    public function isPreflight(): bool
    {
        return $this->method === 'OPTIONS';
    }
}
