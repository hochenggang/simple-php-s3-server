<?php

namespace S3Gateway\Http;

use S3Gateway\Logger;

class Request
{
    private string $method;
    private string $uri;
    private string $queryString;
    private array $headers = [];
    private string $body = '';
    private string $bucket = '';
    private string $key = '';
    private array $queryParams = [];

    public function __construct()
    {
        $this->method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->uri = $this->parseUri();
        $this->queryString = $_SERVER['QUERY_STRING'] ?? '';
        $this->headers = $this->parseHeaders();
        $this->body = $this->readBody();
        $this->parsePath();
        $this->parseQueryParams();
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
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headerName = str_replace('_', '-', substr($key, 5));
                $headerKey = strtoupper($headerName);
                $headers[$headerKey] = $value;
            }
        }

        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['CONTENT-TYPE'] = $_SERVER['CONTENT_TYPE'];
        }
        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $headers['CONTENT-LENGTH'] = $_SERVER['CONTENT_LENGTH'];
        }
        if (isset($_SERVER['HTTP_RANGE'])) {
            $headers['RANGE'] = $_SERVER['HTTP_RANGE'];
        }

        return $headers;
    }

    private function readBody(): string
    {
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 'not set';
        $transferEncoding = $_SERVER['HTTP_TRANSFER_ENCODING'] ?? 'not set';
        Logger::debug("[readBody] Content-Length: {$contentLength}, Transfer-Encoding: {$transferEncoding}");

        $body = file_get_contents('php://input');
        $rawLength = strlen($body);
        Logger::debug("[readBody] Raw body length from php://input: {$rawLength}");

        if ($body === false || $body === '') {
            Logger::debug("[readBody] Body is empty, returning empty string");
            return '';
        }

        // Log first 200 bytes in hex for debugging chunked encoding
        $hexPreview = bin2hex(substr($body, 0, 200));
        Logger::debug("[readBody] Body hex preview (first 200 bytes): {$hexPreview}");

        // Check if body starts with hex number (chunked encoding marker)
        $isChunkedPattern = preg_match('/^[0-9a-fA-F]+\r\n/', $body) === 1;
        Logger::debug("[readBody] Is chunked pattern: " . ($isChunkedPattern ? 'yes' : 'no'));

        if ($this->isChunked($body)) {
            Logger::debug("[readBody] Detected chunked encoding, decoding...");
            $decodedBody = $this->decodeChunked($body);
            $decodedLength = strlen($decodedBody);
            Logger::debug("[readBody] Decoded body length: {$decodedLength}");
            return $decodedBody;
        }

        Logger::debug("[readBody] Returning raw body, length: {$rawLength}");
        return $body;
    }

    private function isChunked(string $body): bool
    {
        return preg_match('/^[0-9a-fA-F]+\r\n/', $body) === 1;
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

            $sizeHex = substr($body, $pos, $lineEnd - $pos);
            $size = hexdec(trim($sizeHex));

            if ($size === 0) {
                break;
            }

            $dataStart = $lineEnd + 2;
            $dataEnd = $dataStart + $size;

            if ($dataEnd > $len) {
                break;
            }

            $decoded .= substr($body, $dataStart, $size);
            $pos = $dataEnd + 2;
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
        $key = strtoupper(str_replace('-', '_', $name));
        
        foreach ($this->headers as $headerKey => $value) {
            if (strcasecmp($headerKey, $key) === 0 || strcasecmp($headerKey, $name) === 0) {
                return $value;
            }
        }
        
        return null;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function getBody(): string
    {
        return $this->body;
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
