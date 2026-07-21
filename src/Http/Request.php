<?php

namespace S3Gateway\Http;

use S3Gateway\Config;
use S3Gateway\Logger;

class Request
{
    private string $method;
    private string $uri;
    private string $queryString;
    private array $headers = [];
    /** @var array<string,string> lowercased header name => value, for O(1) lookup */
    private array $lowerHeaders = [];
    /** @var string|null null = body not yet read; lazy to avoid loading php://input on size-check-then-reject paths */
    private ?string $body = null;
    private string $bucket = '';
    private string $key = '';
    private array $queryParams = [];

    public function __construct()
    {
        $originalMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->method = $this->detectMethod($originalMethod);
        $this->uri = $this->parseUri();
        $this->queryString = $_SERVER['QUERY_STRING'] ?? '';
        $this->headers = $this->parseHeaders();
        // body is read lazily on first getBody() call so that early size checks
        // can reject oversized requests without first loading them into memory.
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

    private function readBody(): string
    {
        if ($this->method === 'HEAD') {
            return '';
        }

        $body = file_get_contents('php://input');

        if ($body === false || $body === '') {
            return '';
        }

        // Decide chunked decoding by headers, not by body content sniffing.
        // Sniffing the body is unsafe: a binary PUT whose first bytes happen to
        // look like a hex chunk size would be silently truncated.
        $contentEncoding = $this->getHeader('Content-Encoding');
        $transferEncoding = $this->getHeader('Transfer-Encoding');

        if ($contentEncoding !== null && stripos($contentEncoding, 'aws-chunked') !== false) {
            return $this->decodeAwsChunked($body);
        }

        if ($transferEncoding !== null && stripos($transferEncoding, 'chunked') !== false) {
            return $this->decodeChunked($body);
        }

        return $body;
    }

    private function decodeChunked(string $body): string
    {
        $decoded = '';
        $pos = 0;
        $len = strlen($body);

        while ($pos < $len) {
            $lineEnd = strpos($body, "\r\n", $pos);
            if ($lineEnd === false) {
                break;
            }

            $size = hexdec(trim(substr($body, $pos, $lineEnd - $pos)));
            if ($size === 0) {
                break;
            }

            $dataStart = $lineEnd + 2;
            if ($dataStart + $size > $len) {
                break;
            }

            $decoded .= substr($body, $dataStart, $size);
            $pos = $dataStart + $size + 2;
        }

        return $decoded;
    }

    /**
     * Decode AWS chunked encoding: hex(size);chunk-signature=signature\r\n data\r\n
     */
    private function decodeAwsChunked(string $body): string
    {
        $decoded = '';
        $pos = 0;
        $len = strlen($body);

        while ($pos < $len) {
            $lineEnd = strpos($body, "\r\n", $pos);
            if ($lineEnd === false) {
                break;
            }

            $chunkHeader = substr($body, $pos, $lineEnd - $pos);
            $semicolonPos = strpos($chunkHeader, ';');
            $sizeHex = $semicolonPos !== false
                ? trim(substr($chunkHeader, 0, $semicolonPos))
                : trim($chunkHeader);

            $size = hexdec($sizeHex);
            if ($size === 0) {
                break;
            }

            $dataStart = $lineEnd + 2;
            if ($dataStart + $size > $len) {
                break;
            }

            $decoded .= substr($body, $dataStart, $size);
            $pos = $dataStart + $size + 2;
        }

        return $decoded;
    }

    private function parsePath(): void
    {
        $path = trim($this->uri, '/');
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

    public function getBody(): string
    {
        // Lazy read: php://input is only opened on first getBody() call, so
        // HEAD/GET/list requests never touch the request body, and an early
        // size-check in Router can reject oversized PUTs before they load.
        return $this->body ??= $this->readBody();
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
