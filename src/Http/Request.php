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
    private string $body = '';
    private string $bucket = '';
    private string $key = '';
    private array $queryParams = [];

    public function __construct()
    {
        $this->method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $this->uri = $this->parseUri();
        $this->queryString = $_SERVER['QUERY_STRING'] ?? '';
        
        // 在解析头部之前记录原始请求信息
        $this->logRequestArrival();
        
        $this->headers = $this->parseHeaders();
        $this->body = $this->readBody();
        $this->parsePath();
        $this->parseQueryParams();
    }
    
    /**
     * 记录请求到达时的原始信息，用于调试 CDN 后的请求头变化
     */
    private function logRequestArrival(): void
    {
        if (!Config::appDebug()) {
            return;
        }
        
        Logger::debug("[RequestArrival] ========== New Request ==========");
        Logger::debug("[RequestArrival] Method: {$this->method}");
        $requestUri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'N/A';
        Logger::debug("[RequestArrival] URI: {$requestUri}");
        Logger::debug("[RequestArrival] Query String: {$this->queryString}");
        $clientIp = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'N/A';
        Logger::debug("[RequestArrival] Client IP: {$clientIp}");
        
        // 记录所有原始 HTTP 头部（从 $_SERVER 中提取）
        Logger::debug("[RequestArrival] --- Raw HTTP Headers from \$_SERVER ---");
        $httpHeaders = [];
        foreach ($_SERVER as $key => $value) {
            if (strpos($key, 'HTTP_') === 0) {
                $headerName = str_replace('_', '-', substr($key, 5));
                $httpHeaders[$headerName] = $value;
                Logger::debug("[RequestArrival]   {$headerName}: {$value}");
            }
        }
        
        // 记录特殊头部
        Logger::debug("[RequestArrival] --- Special Headers ---");
        $specialHeaders = ['CONTENT_TYPE', 'CONTENT_LENGTH', 'REQUEST_METHOD', 'REQUEST_URI', 'QUERY_STRING', 'SERVER_NAME', 'SERVER_PORT', 'HTTPS'];
        foreach ($specialHeaders as $header) {
            if (isset($_SERVER[$header])) {
                Logger::debug("[RequestArrival]   {$header}: {$_SERVER[$header]}");
            }
        }
        
        // 记录 CDN 相关头部（如果有）
        Logger::debug("[RequestArrival] --- CDN/Proxy Headers ---");
        $cdnHeaders = ['HTTP_CF_CONNECTING_IP', 'HTTP_CF_RAY', 'HTTP_CF_VISITOR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_HOST', 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_REAL_IP'];
        $hasCdnHeaders = false;
        foreach ($cdnHeaders as $header) {
            if (isset($_SERVER[$header])) {
                $hasCdnHeaders = true;
                $cleanName = str_replace('HTTP_', '', $header);
                $cleanName = str_replace('_', '-', $cleanName);
                Logger::debug("[RequestArrival]   {$cleanName}: {$_SERVER[$header]}");
            }
        }
        if (!$hasCdnHeaders) {
            Logger::debug("[RequestArrival]   (No CDN headers detected)");
        }
        
        // 检查 Authorization 头部并解析 SignedHeaders
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            Logger::debug("[RequestArrival] --- Authorization Header Analysis ---");
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
            Logger::debug("[RequestArrival]   Raw: {$authHeader}");
            
            // 解析 SignedHeaders
            if (preg_match('/SignedHeaders=([^,]+)/i', $authHeader, $matches)) {
                $signedHeaders = $matches[1];
                Logger::debug("[RequestArrival]   SignedHeaders: {$signedHeaders}");
                
                // 列出每个被签名的头部
                $headersList = explode(';', $signedHeaders);
                Logger::debug("[RequestArrival]   Signed Headers List:");
                foreach ($headersList as $header) {
                    $header = trim($header);
                    // 检查这个头部是否在请求中存在
                    $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
                    $exists = isset($_SERVER[$serverKey]) ? '✓' : '✗';
                    $value = $_SERVER[$serverKey] ?? 'NOT FOUND';
                    Logger::debug("[RequestArrival]     [{$exists}] {$header}: {$value}");
                }
            } else {
                Logger::debug("[RequestArrival]   SignedHeaders: NOT FOUND in Authorization header");
            }
        } else {
            Logger::debug("[RequestArrival] --- No Authorization Header ---");
        }
        
        Logger::debug("[RequestArrival] ========== End Request Arrival Log ==========");
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
                // 清理 header 值中的换行符和多余空格
                // Cloudflare 等代理可能会在 header 中插入换行符（line folding）
                if ($value !== null) {
                    $value = str_replace(["\r\n", "\r", "\n"], ' ', $value);
                    $value = preg_replace('/\s+/', ' ', $value);
                    $value = trim($value);
                }
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

        // Cloudflare 支持：使用 X-Forwarded-Host 作为 Host 头部（如果存在）
        if (isset($headers['X-FORWARDED-HOST'])) {
            $originalHost = $headers['HOST'] ?? 'not-set';
            $headers['HOST'] = $headers['X-FORWARDED-HOST'];
            if (Config::appDebug()) {
                Logger::debug("[parseHeaders] X-Forwarded-Host detected, overriding HOST: {$originalHost} -> {$headers['HOST']}");
            }
        }

        // 调试模式：输出所有头部到错误日志
        if (Config::appDebug()) {
            Logger::debug("[parseHeaders] All headers:");
            foreach ($headers as $name => $value) {
                Logger::debug("[parseHeaders]   {$name}: {$value}");
            }
        }

        return $headers;
    }

    private function readBody(): string
    {
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 'not set';
        $transferEncoding = $_SERVER['HTTP_TRANSFER_ENCODING'] ?? 'not set';
        $contentEncoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? 'not set';
        $decodedContentLength = $_SERVER['HTTP_X_AMZ_DECODED_CONTENT_LENGTH'] ?? 'not set';
        Logger::debug("[readBody] Content-Length: {$contentLength}, Transfer-Encoding: {$transferEncoding}, Content-Encoding: {$contentEncoding}, X-Amz-Decoded-Content-Length: {$decodedContentLength}");

        $body = file_get_contents('php://input');
        $rawLength = strlen($body);
        Logger::debug("[readBody] Raw body length from php://input: {$rawLength}");

        // 如果 php://input 为空，但请求使用 chunked 编码，尝试从 stdin 读取
        if (($body === false || $body === '') && ($transferEncoding === 'chunked' || $contentEncoding === 'aws-chunked')) {
            Logger::debug("[readBody] php://input is empty, trying alternative methods...");
            
            // 方法1: 尝试从 php://stdin 读取
            $stdinBody = @file_get_contents('php://stdin');
            if ($stdinBody !== false && strlen($stdinBody) > 0) {
                Logger::debug("[readBody] Read " . strlen($stdinBody) . " bytes from php://stdin");
                $body = $stdinBody;
            }
        }

        if ($body === false || $body === '') {
            Logger::debug("[readBody] Body is empty, returning empty string");
            return '';
        }

        // Log first 200 bytes in hex for debugging chunked encoding
        $hexPreview = bin2hex(substr($body, 0, 200));
        Logger::debug("[readBody] Body hex preview (first 200 bytes): {$hexPreview}");

        // Check if body starts with hex number (chunked encoding marker)
        $isChunkedPattern = preg_match('/^[0-9a-fA-F]+\r\n/', $body) === 1;
        $isAwsChunkedPattern = preg_match('/^[0-9a-fA-F]+;chunk-signature=/', $body) === 1;
        Logger::debug("[readBody] Is chunked pattern: " . ($isChunkedPattern ? 'yes' : 'no') . ", Is aws-chunked: " . ($isAwsChunkedPattern ? 'yes' : 'no'));

        // 检测 aws-chunked 编码
        if ($isAwsChunkedPattern || $contentEncoding === 'aws-chunked') {
            Logger::debug("[readBody] Detected aws-chunked encoding, decoding...");
            $decodedBody = $this->decodeAwsChunked($body);
            $decodedLength = strlen($decodedBody);
            Logger::debug("[readBody] Decoded aws-chunked body length: {$decodedLength}");
            return $decodedBody;
        }

        if ($this->isChunked($body)) {
            Logger::debug("[readBody] Detected standard chunked encoding, decoding...");
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

    /**
     * 解码 AWS chunked 编码
     * 格式: hex(size);chunk-signature=signature\r\n data\r\n
     */
    private function decodeAwsChunked(string $body): string
    {
        $decoded = '';
        $pos = 0;
        $len = strlen($body);

        Logger::debug("[decodeAwsChunked] Starting to decode aws-chunked body, length: {$len}");

        while ($pos < $len) {
            // 查找 chunk 头结束位置
            $lineEnd = strpos($body, "\r\n", $pos);
            if ($lineEnd === false) {
                Logger::debug("[decodeAwsChunked] No more chunks found at position {$pos}");
                break;
            }

            // 解析 chunk 头: hex(size);chunk-signature=...
            $chunkHeader = substr($body, $pos, $lineEnd - $pos);
            Logger::debug("[decodeAwsChunked] Chunk header: {$chunkHeader}");

            // 提取大小（在分号之前）
            $semicolonPos = strpos($chunkHeader, ';');
            if ($semicolonPos === false) {
                // 可能是标准 chunked 编码
                $sizeHex = trim($chunkHeader);
            } else {
                $sizeHex = trim(substr($chunkHeader, 0, $semicolonPos));
            }

            $size = hexdec($sizeHex);
            Logger::debug("[decodeAwsChunked] Chunk size: {$size}");

            if ($size === 0) {
                // 结束块，后面可能有 trailer
                Logger::debug("[decodeAwsChunked] Found end chunk");
                break;
            }

            $dataStart = $lineEnd + 2;
            $dataEnd = $dataStart + $size;

            if ($dataEnd > $len) {
                Logger::debug("[decodeAwsChunked] Chunk data exceeds body length");
                break;
            }

            $chunkData = substr($body, $dataStart, $size);
            $decoded .= $chunkData;
            Logger::debug("[decodeAwsChunked] Added {$size} bytes to decoded body");

            // 跳过 chunk 数据后的 \r\n
            $pos = $dataEnd + 2;
        }

        $decodedLen = strlen($decoded);
        Logger::debug("[decodeAwsChunked] Decoded body length: {$decodedLen}");

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
