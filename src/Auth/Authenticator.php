<?php

namespace S3Gateway\Auth;

use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Logger;

/**
 * AWS Signature Version 4 (SigV4) 认证器
 * 
 * 严格遵循 AWS SigV4 规范实现，支持：
 * - 标准 Authorization Header 认证
 * - 预签名 URL 认证
 * - CloudFront/Cloudflare 代理适配
 * - 完整调试日志
 */
class Authenticator
{
    private bool $debug;
    private Request $request;
    
    // SigV4 时间戳允许的最大偏差（5分钟，单位：秒）
    private const MAX_TIMESTAMP_SKEW = 300;
    
    // Hop-by-hop 头部 - 不应包含在签名中
    private const HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade', 'x-amzn-trace-id'
    ];

    public function __construct(bool $debug, Request $request)
    {
        $this->debug = $debug;
        $this->request = $request;
    }

    /**
     * 执行认证
     */
    public function authenticate(): void
    {
        $authHeader = $this->request->getHeader('Authorization');
        
        $this->logDebug("=== Authentication Start ===");
        $this->logDebug("Request Method: " . $this->request->getMethod());
        $this->logDebug("Request URI: " . $this->request->getUri());
        $this->logDebug("Query String: " . $this->request->getQueryString());
        $this->logDebug("Authorization Header: " . ($authHeader ?? 'null'));

        // 检查是否为预签名 URL 请求
        if ($this->isPresignedUrlRequest()) {
            $this->logDebug("Detected presigned URL request");
            $this->authenticatePresignedUrl();
            $this->logDebug("=== Authentication Success (Presigned URL) ===");
            return;
        }

        if (empty($authHeader)) {
            $this->logDebug("No Authorization header found");
            throw S3Exception::accessDenied();
        }

        // 根据认证类型分发
        if (strpos($authHeader, 'AWS4-HMAC-SHA256') === 0) {
            $this->logDebug("Detected AWS4-HMAC-SHA256 signature");
            $this->authenticateAwsSignatureV4($authHeader);
        } elseif (strpos($authHeader, 'AWS ') === 0) {
            $this->logDebug("Detected AWS Signature V2");
            $this->authenticateAwsSignatureV2($authHeader);
        } elseif (strpos($authHeader, 'Bearer ') === 0) {
            $this->logDebug("Detected Bearer token");
            $this->authenticateBearerToken($authHeader);
        } else {
            $this->logDebug("Unknown authorization type: " . substr($authHeader, 0, 50));
            throw S3Exception::accessDenied();
        }
        
        $this->logDebug("=== Authentication Success ===");
    }

    /**
     * 检查是否为预签名 URL 请求
     */
    private function isPresignedUrlRequest(): bool
    {
        return $this->request->hasQueryParam('X-Amz-Credential') ||
               $this->request->hasQueryParam('x-amz-credential');
    }

    /**
     * AWS Signature Version 4 认证
     */
    private function authenticateAwsSignatureV4(string $authHeader): void
    {
        try {
            // 解析 Authorization header
            $signatureData = $this->parseSignatureV4Header($authHeader);
            
            $accessKeyId = $signatureData['Credential']['AccessKeyId'] ?? null;
            if ($accessKeyId === null) {
                throw S3Exception::invalidAccessKeyId();
            }

            // 获取密钥
            $secretKey = Config::getSecretKey($accessKeyId);
            if ($secretKey === null) {
                $this->logDebug("Secret key not found for AccessKeyId: {$accessKeyId}");
                throw S3Exception::invalidAccessKeyId();
            }

            $this->logDebug("AWS4 Auth: AccessKeyId={$accessKeyId}, Region={$signatureData['Credential']['Region']}, Service={$signatureData['Credential']['Service']}");
            $this->logDebug("SignedHeaders: {$signatureData['SignedHeaders']}");

            // 验证时间戳（防止重放攻击）
            $this->validateTimestamp($signatureData);

            // 构建 StringToSign
            $stringToSign = $this->buildStringToSign($signatureData);
            $this->logDebug("StringToSign:\n{$stringToSign}");

            // 计算签名
            $calculatedSignature = $this->calculateSignatureV4($stringToSign, $secretKey, $signatureData);
            $this->logDebug("Calculated Signature: {$calculatedSignature}");
            $this->logDebug("Provided Signature: {$signatureData['Signature']}");

            // 验证签名
            if (!hash_equals($calculatedSignature, $signatureData['Signature'])) {
                $this->logSignatureMismatch($signatureData, $stringToSign, $calculatedSignature);
                throw S3Exception::signatureDoesNotMatch();
            }

            $this->logDebug("Signature verified successfully");

        } catch (S3Exception $e) {
            throw $e;
        } catch (\Exception $e) {
            $this->logDebug("Authentication error: " . $e->getMessage());
            throw S3Exception::accessDenied();
        }
    }

    /**
     * 解析 SigV4 Authorization Header
     */
    private function parseSignatureV4Header(string $authHeader): array
    {
        // 记录原始 header
        $this->logDebug("Original Authorization header: " . $authHeader);
        
        // 清理 header 中的换行符和多余空格
        // Cloudflare 等代理可能会在 header 中插入换行符（line folding）
        $cleanedHeader = str_replace(["\r\n", "\r", "\n"], ' ', $authHeader);
        $cleanedHeader = preg_replace('/\s+/', ' ', $cleanedHeader);
        $cleanedHeader = trim($cleanedHeader);
        
        if ($cleanedHeader !== $authHeader) {
            $this->logDebug("Cleaned Authorization header: " . $cleanedHeader);
        }
        
        // AWS4-HMAC-SHA256 Credential=.../.../.../.../..., SignedHeaders=..., Signature=...
        $pattern = '/AWS4-HMAC-SHA256\s+Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([a-f0-9]+)/i';
        
        if (!preg_match($pattern, $cleanedHeader, $matches)) {
            $this->logDebug("Failed to parse Authorization header. Pattern mismatch.");
            throw S3Exception::accessDenied('Invalid Authorization header format');
        }

        $credential = $matches[1];
        $signedHeaders = $matches[2];
        $signature = $matches[3];

        // 解析 Credential: AccessKeyId/Date/Region/Service/aws4_request
        $credentialParts = explode('/', $credential);
        if (count($credentialParts) < 5) {
            $this->logDebug("Invalid credential format. Parts: " . count($credentialParts));
            throw S3Exception::invalidAccessKeyId();
        }

        $result = [
            'Credential' => [
                'AccessKeyId' => $credentialParts[0],
                'Date' => $credentialParts[1],
                'Region' => $credentialParts[2],
                'Service' => $credentialParts[3],
                'RequestType' => $credentialParts[4],
            ],
            'SignedHeaders' => $signedHeaders,
            'Signature' => $signature,
        ];

        $this->logDebug("Parsed Credential - AccessKeyId: {$result['Credential']['AccessKeyId']}, Date: {$result['Credential']['Date']}, Region: {$result['Credential']['Region']}, Service: {$result['Credential']['Service']}");

        return $result;
    }

    /**
     * 验证时间戳（防止重放攻击）
     */
    private function validateTimestamp(array $signatureData): void
    {
        $amzDate = $this->getAmzDate($this->request->getHeaders());
        if (empty($amzDate)) {
            $this->logDebug("X-Amz-Date header not found");
            throw S3Exception::invalidRequest('X-Amz-Date header is required');
        }

        $requestTime = \DateTime::createFromFormat('Ymd\THis\Z', $amzDate, new \DateTimeZone('UTC'));
        if ($requestTime === false) {
            $this->logDebug("Invalid X-Amz-Date format: {$amzDate}");
            throw S3Exception::invalidRequest('Invalid X-Amz-Date format');
        }

        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $diff = abs($now->getTimestamp() - $requestTime->getTimestamp());

        $this->logDebug("Request time: {$amzDate}, Server time: {$now->format('Ymd\THis\Z')}, Diff: {$diff}s");

        if ($diff > self::MAX_TIMESTAMP_SKEW) {
            $this->logDebug("Request timestamp skew too large: {$diff}s (max: " . self::MAX_TIMESTAMP_SKEW . "s)");
            throw S3Exception::expiredToken('Request timestamp skew too large');
        }
    }

    /**
     * 构建 StringToSign
     */
    private function buildStringToSign(array $signatureData): string
    {
        $method = $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();
        $body = $this->request->getBody();

        // 构建规范请求的各个部分
        $canonicalUri = $this->encodeUri($uri);
        $canonicalQueryString = $this->normalizeQueryString($queryString);
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $signatureData['SignedHeaders']);
        $signedHeaders = strtolower($signatureData['SignedHeaders']);
        $hashedPayload = $this->getPayloadHash($headers, $body);

        $this->logDebug("Canonical URI: {$canonicalUri}");
        $this->logDebug("Canonical Query String: {$canonicalQueryString}");
        $this->logDebug("Canonical Headers:\n{$canonicalHeaders}");
        $this->logDebug("Signed Headers: {$signedHeaders}");
        $this->logDebug("Hashed Payload: {$hashedPayload}");

        // 构建规范请求
        $canonicalRequest = implode("\n", [
            $method,
            $canonicalUri,
            $canonicalQueryString,
            $canonicalHeaders,
            '',  // 空行
            $signedHeaders,
            $hashedPayload,
        ]);

        $this->logDebug("Canonical Request:\n{$canonicalRequest}");

        // 获取时间戳
        $amzDate = $this->getAmzDate($headers);
        $date = substr($amzDate, 0, 8);
        $region = $signatureData['Credential']['Region'];
        $service = $signatureData['Credential']['Service'];
        $scope = "{$date}/{$region}/{$service}/aws4_request";

        // 构建 StringToSign
        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);

        return $stringToSign;
    }

    /**
     * URI 编码（遵循 AWS 规范）
     */
    private function encodeUri(string $uri): string
    {
        $uri = $uri ?: '/';
        
        // 分割路径并编码每个部分
        $parts = explode('/', $uri);
        $encodedParts = [];
        
        foreach ($parts as $part) {
            if ($part === '') {
                $encodedParts[] = '';
            } else {
                // 先解码再编码，确保一致性
                $decoded = rawurldecode($part);
                $encodedParts[] = rawurlencode($decoded);
            }
        }
        
        $result = implode('/', $encodedParts);
        
        // 确保路径以 / 开头
        if (!str_starts_with($result, '/')) {
            $result = '/' . $result;
        }
        
        return $result;
    }

    /**
     * 获取 X-Amz-Date 头部值
     */
    private function getAmzDate(array $headers): string
    {
        // 优先使用 x-amz-date
        $amzDate = $this->findHeader($headers, 'x-amz-date');
        if ($amzDate !== null) {
            return $amzDate;
        }

        // 回退到 Date 头部
        $dateHeader = $this->findHeader($headers, 'date');
        if ($dateHeader !== null) {
            $timestamp = strtotime($dateHeader);
            if ($timestamp !== false) {
                return gmdate('Ymd\THis\Z', $timestamp);
            }
        }

        // 最后使用当前时间
        return gmdate('Ymd\THis\Z');
    }

    /**
     * 获取请求体哈希
     */
    private function getPayloadHash(array $headers, string $body): string
    {
        // 优先使用 x-amz-content-sha256 头部
        $contentSha256 = $this->findHeader($headers, 'x-amz-content-sha256');
        if ($contentSha256 !== null) {
            return $contentSha256;
        }

        // 计算请求体的 SHA256
        return hash('sha256', $body);
    }

    /**
     * 规范化查询字符串
     */
    private function normalizeQueryString(string $queryString): string
    {
        if (empty($queryString)) {
            return '';
        }

        $params = [];
        $pairs = explode('&', $queryString);
        
        foreach ($pairs as $pair) {
            if (strpos($pair, '=') !== false) {
                list($key, $value) = explode('=', $pair, 2);
                $decodedKey = rawurldecode($key);
                $decodedValue = rawurldecode($value);
                $params[$decodedKey] = $decodedValue;
            } else {
                $params[rawurldecode($pair)] = '';
            }
        }

        // 按键排序
        ksort($params, SORT_STRING);

        // 重新编码
        $normalized = [];
        foreach ($params as $key => $value) {
            $normalized[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $normalized);
    }

    /**
     * 构建规范头部
     */
    private function buildCanonicalHeaders(array $headers, string $signedHeaders): string
    {
        $signedHeadersList = explode(';', strtolower($signedHeaders));
        $canonicalHeaders = [];

        foreach ($signedHeadersList as $headerName) {
            $headerName = trim($headerName);
            if (empty($headerName)) {
                continue;
            }
            
            $value = $this->findHeader($headers, $headerName);
            if ($value !== null) {
                $normalizedValue = $this->normalizeHeaderValue($value);
                $canonicalHeaders[] = strtolower($headerName) . ':' . $normalizedValue;
                
                $this->logDebug("CanonicalHeader: {$headerName} = {$normalizedValue}");
            } else {
                $this->logDebug("Warning: Signed header '{$headerName}' not found in request");
            }
        }

        // 按字母顺序排序
        sort($canonicalHeaders, SORT_STRING);

        return implode("\n", $canonicalHeaders);
    }

    /**
     * 规范化头部值
     */
    private function normalizeHeaderValue(string $value): string
    {
        // 去除首尾空格
        $value = trim($value);
        // 将连续多个空格替换为单个空格
        $value = preg_replace('/\s+/', ' ', $value);
        return $value;
    }

    /**
     * 查找头部（不区分大小写）
     */
    private function findHeader(array $headers, string $name): ?string
    {
        $name = strtolower($name);
        foreach ($headers as $key => $value) {
            if (strtolower($key) === $name) {
                return $value;
            }
        }
        return null;
    }

    /**
     * 计算 SigV4 签名
     */
    private function calculateSignatureV4(string $stringToSign, string $secretKey, array $signatureData): string
    {
        $amzDate = $this->getAmzDate($this->request->getHeaders());
        $date = substr($amzDate, 0, 8);
        $region = $signatureData['Credential']['Region'];
        $service = $signatureData['Credential']['Service'];

        return $this->calculateSignatureV4WithDate($stringToSign, $secretKey, $date, $region, $service);
    }

    /**
     * 使用指定日期计算 SigV4 签名
     */
    private function calculateSignatureV4WithDate(string $stringToSign, string $secretKey, string $date, string $region, string $service): string
    {
        // 派生签名密钥
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        // 计算最终签名
        return hash_hmac('sha256', $stringToSign, $kSigning);
    }

    /**
     * 预签名 URL 认证
     */
    private function authenticatePresignedUrl(): void
    {
        try {
            $presignedData = $this->parsePresignedUrlParams();
            
            $this->logDebug("Presigned URL Auth: AccessKeyId={$presignedData['Credential']['AccessKeyId']}");
            $this->logDebug("Expires: " . ($presignedData['Expires'] ?? 'not set'));

            // 检查签名是否过期
            $this->checkPresignedUrlExpiry($presignedData);

            $accessKeyId = $presignedData['Credential']['AccessKeyId'];
            $secretKey = Config::getSecretKey($accessKeyId);
            if ($secretKey === null) {
                $this->logDebug("Secret key not found for presigned URL: {$accessKeyId}");
                throw S3Exception::invalidAccessKeyId();
            }

            // 构建 StringToSign
            $stringToSign = $this->buildPresignedUrlStringToSign($presignedData);
            $this->logDebug("Presigned URL StringToSign:\n{$stringToSign}");

            // 计算签名
            $calculatedSignature = $this->calculatePresignedUrlSignature($stringToSign, $secretKey, $presignedData);
            $this->logDebug("Calculated Signature: {$calculatedSignature}");
            $this->logDebug("Provided Signature: {$presignedData['Signature']}");

            // 验证签名
            if (!hash_equals($calculatedSignature, $presignedData['Signature'])) {
                $this->logDebug("Presigned URL signature mismatch");
                throw S3Exception::signatureDoesNotMatch();
            }

            $this->logDebug("Presigned URL signature verified successfully");

        } catch (S3Exception $e) {
            throw $e;
        } catch (\Exception $e) {
            $this->logDebug("Presigned URL authentication error: " . $e->getMessage());
            throw S3Exception::accessDenied();
        }
    }

    /**
     * 解析预签名 URL 参数
     */
    private function parsePresignedUrlParams(): array
    {
        // 获取参数（不区分大小写）
        $credential = $this->request->getQueryParam('X-Amz-Credential') ??
                      $this->request->getQueryParam('x-amz-credential');
        $algorithm = $this->request->getQueryParam('X-Amz-Algorithm') ??
                     $this->request->getQueryParam('x-amz-algorithm');
        $date = $this->request->getQueryParam('X-Amz-Date') ??
                $this->request->getQueryParam('x-amz-date');
        $expires = $this->request->getQueryParam('X-Amz-Expires') ??
                   $this->request->getQueryParam('x-amz-expires');
        $signedHeaders = $this->request->getQueryParam('X-Amz-SignedHeaders') ??
                         $this->request->getQueryParam('x-amz-signedheaders');
        $signature = $this->request->getQueryParam('X-Amz-Signature') ??
                     $this->request->getQueryParam('x-amz-signature');

        if (empty($credential) || empty($algorithm) || empty($date) ||
            empty($signedHeaders) || empty($signature)) {
            $this->logDebug("Missing required presigned URL parameters");
            throw S3Exception::accessDenied('Missing required presigned URL parameters');
        }

        // 解析 Credential
        $credentialParts = explode('/', $credential);
        if (count($credentialParts) < 5) {
            throw S3Exception::invalidAccessKeyId();
        }

        return [
            'Algorithm' => $algorithm,
            'Credential' => [
                'AccessKeyId' => $credentialParts[0],
                'Date' => $credentialParts[1],
                'Region' => $credentialParts[2],
                'Service' => $credentialParts[3],
                'RequestType' => $credentialParts[4],
            ],
            'AmzDate' => $date,
            'Expires' => $expires ? (int)$expires : null,
            'SignedHeaders' => $signedHeaders,
            'Signature' => $signature,
        ];
    }

    /**
     * 检查预签名 URL 是否过期
     */
    private function checkPresignedUrlExpiry(array $presignedData): void
    {
        $expires = $presignedData['Expires'];
        if ($expires === null) {
            return; // 未指定过期时间
        }

        $amzDate = $presignedData['AmzDate'];
        $requestTime = \DateTime::createFromFormat('Ymd\THis\Z', $amzDate, new \DateTimeZone('UTC'));

        if ($requestTime === false) {
            throw S3Exception::invalidRequest('Invalid X-Amz-Date format');
        }

        $expiryTime = clone $requestTime;
        $expiryTime->modify("+{$expires} seconds");

        $now = new \DateTime('now', new \DateTimeZone('UTC'));

        if ($now > $expiryTime) {
            $this->logDebug("Presigned URL expired. Expiry: {$expiryTime->format('Y-m-d H:i:s')}, Now: {$now->format('Y-m-d H:i:s')}");
            throw S3Exception::expiredToken('Request has expired');
        }
    }

    /**
     * 构建预签名 URL 的 StringToSign
     */
    private function buildPresignedUrlStringToSign(array $presignedData): string
    {
        $method = $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();

        $canonicalUri = $this->encodeUri($uri);
        $canonicalQueryString = $this->buildPresignedCanonicalQueryString($queryString);
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $presignedData['SignedHeaders']);
        $signedHeaders = strtolower($presignedData['SignedHeaders']);

        // 预签名 URL 使用 UNSIGNED-PAYLOAD
        $hashedPayload = 'UNSIGNED-PAYLOAD';

        $canonicalRequest = implode("\n", [
            $method,
            $canonicalUri,
            $canonicalQueryString,
            $canonicalHeaders,
            '',
            $signedHeaders,
            $hashedPayload,
        ]);

        $amzDate = $presignedData['AmzDate'];
        $date = $presignedData['Credential']['Date'];
        $region = $presignedData['Credential']['Region'];
        $service = $presignedData['Credential']['Service'];
        $scope = "{$date}/{$region}/{$service}/aws4_request";

        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);

        if ($this->debug) {
            $this->logDebug("Presigned URL CanonicalRequest:\n{$canonicalRequest}");
        }

        return $stringToSign;
    }

    /**
     * 构建预签名 URL 的规范查询字符串
     */
    private function buildPresignedCanonicalQueryString(string $queryString): string
    {
        if (empty($queryString)) {
            return '';
        }

        $params = [];
        $pairs = explode('&', $queryString);

        foreach ($pairs as $pair) {
            if (strpos($pair, '=') !== false) {
                list($key, $value) = explode('=', $pair, 2);
                $decodedKey = rawurldecode($key);

                // 排除 X-Amz-Signature
                if (strcasecmp($decodedKey, 'X-Amz-Signature') === 0) {
                    continue;
                }

                $params[$decodedKey] = rawurldecode($value);
            } else {
                $decodedKey = rawurldecode($pair);
                if (strcasecmp($decodedKey, 'X-Amz-Signature') === 0) {
                    continue;
                }
                $params[$decodedKey] = '';
            }
        }

        // 按键排序
        ksort($params, SORT_STRING);

        // 重新编码
        $normalized = [];
        foreach ($params as $key => $value) {
            $normalized[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $normalized);
    }

    /**
     * 计算预签名 URL 签名
     */
    private function calculatePresignedUrlSignature(string $stringToSign, string $secretKey, array $presignedData): string
    {
        $date = $presignedData['Credential']['Date'];
        $region = $presignedData['Credential']['Region'];
        $service = $presignedData['Credential']['Service'];

        return $this->calculateSignatureV4WithDate($stringToSign, $secretKey, $date, $region, $service);
    }

    /**
     * AWS Signature Version 2 认证（遗留支持）
     */
    private function authenticateAwsSignatureV2(string $authHeader): void
    {
        $pattern = '/AWS\s+([^:]+):(.+)/';
        if (!preg_match($pattern, $authHeader, $matches)) {
            throw S3Exception::accessDenied();
        }

        $accessKeyId = $matches[1];
        $signature = $matches[2];

        $secretKey = Config::getSecretKey($accessKeyId);
        if ($secretKey === null) {
            throw S3Exception::invalidAccessKeyId();
        }

        $stringToSign = $this->request->getMethod() . "\n\n\n" . 
                        $this->request->getHeader('Date') . "\n" . 
                        $this->request->getUri();

        $expectedSignature = base64_encode(hash_hmac('sha1', $stringToSign, $secretKey, true));

        if (!hash_equals($expectedSignature, $signature)) {
            throw S3Exception::signatureDoesNotMatch();
        }
    }

    /**
     * Bearer Token 认证
     */
    private function authenticateBearerToken(string $authHeader): void
    {
        $token = substr($authHeader, 7);
        $validToken = Config::bearerToken();

        if ($validToken === null || !hash_equals($validToken, $token)) {
            throw S3Exception::accessDenied();
        }
    }

    /**
     * 检查请求大小
     */
    public function checkRequestSize(): void
    {
        $contentLength = $this->request->getHeader('Content-Length');
        $maxSize = Config::maxUploadSize();

        if ($contentLength !== null && (int)$contentLength > $maxSize) {
            throw S3Exception::entityTooLarge((int)$contentLength, $maxSize);
        }
    }

    /**
     * 记录签名不匹配调试信息
     */
    private function logSignatureMismatch(array $signatureData, string $stringToSign, string $calculatedSignature): void
    {
        if (!$this->debug) {
            return;
        }

        $this->logDebug("=== Signature Mismatch Details ===");
        $this->logDebug("Expected: {$calculatedSignature}");
        $this->logDebug("Got: {$signatureData['Signature']}");
        $this->logDebug("StringToSign:\n{$stringToSign}");
        
        // 记录请求头部信息以便调试
        $headers = $this->request->getHeaders();
        $this->logDebug("Request Headers:");
        foreach ($headers as $name => $value) {
            $this->logDebug("  {$name}: {$value}");
        }
    }

    /**
     * 调试日志记录
     */
    private function logDebug(string $message): void
    {
        if ($this->debug) {
            Logger::debug("[Authenticator] {$message}");
        }
    }
}
