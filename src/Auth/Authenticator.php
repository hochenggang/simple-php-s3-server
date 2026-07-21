<?php

namespace S3Gateway\Auth;

use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Logger;

/**
 * AWS Signature Version 4 (SigV4) authenticator
 *
 * Supports:
 * - AWS4-HMAC-SHA256 Authorization Header
 * - Presigned URL (X-Amz-Credential query param)
 * - AWS Signature V2 (legacy)
 * - Bearer Token
 */
class Authenticator
{
    private Request $request;

    private const MAX_TIMESTAMP_SKEW = 300;

    private const HOP_BY_HOP_HEADERS = [
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
        'te', 'trailer', 'transfer-encoding', 'upgrade', 'x-amzn-trace-id'
    ];

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Execute authentication
     * @return string Returns the accessKeyId
     */
    public function authenticate(): string
    {
        $authHeader = $this->request->getHeader('Authorization');

        if ($this->isPresignedUrlRequest()) {
            $accessKeyId = $this->authenticatePresignedUrl();
            $this->checkBucketPermission($accessKeyId);
            return $accessKeyId;
        }

        if (empty($authHeader)) {
            throw S3Exception::accessDenied();
        }

        $accessKeyId = null;
        if (str_starts_with($authHeader, 'AWS4-HMAC-SHA256')) {
            $accessKeyId = $this->authenticateAwsSignatureV4($authHeader);
        } elseif (str_starts_with($authHeader, 'AWS ')) {
            $accessKeyId = $this->authenticateAwsSignatureV2($authHeader);
        } elseif (str_starts_with($authHeader, 'Bearer ')) {
            $this->authenticateBearerToken($authHeader);
            return '';
        } else {
            throw S3Exception::accessDenied();
        }

        $this->checkBucketPermission($accessKeyId);
        return $accessKeyId;
    }

    /**
     * Check bucket permission for the access key
     */
    private function checkBucketPermission(string $accessKeyId): void
    {
        $bucketName = $this->request->getBucket();
        if ($bucketName !== '' && !Config::isBucketAllowed($accessKeyId, $bucketName)) {
            throw S3Exception::accessDenied("Access denied for bucket: {$bucketName}");
        }
    }

    private function isPresignedUrlRequest(): bool
    {
        return $this->request->hasQueryParam('X-Amz-Credential') ||
               $this->request->hasQueryParam('x-amz-credential');
    }

    // ─── AWS Signature Version 4 ──────────────────────────────────────

    private function authenticateAwsSignatureV4(string $authHeader): string
    {
        try {
            $signatureData = $this->parseSignatureV4Header($authHeader);

            $accessKeyId = $signatureData['Credential']['AccessKeyId'] ?? null;
            if ($accessKeyId === null) {
                throw S3Exception::invalidAccessKeyId();
            }

            $secretKey = Config::getSecretKey($accessKeyId);
            if ($secretKey === null) {
                throw S3Exception::invalidAccessKeyId();
            }

            $this->validateTimestamp($signatureData);

            // Try current method first, then alternate for HEAD/GET compatibility
            $methodsToTry = $this->getMethodsWithFallback();

            foreach ($methodsToTry as $method) {
                $stringToSign = $this->buildStringToSign($signatureData, $method);
                $calculatedSignature = $this->calculateSignatureV4($stringToSign, $secretKey, $signatureData);

                if (hash_equals($calculatedSignature, $signatureData['Signature'])) {
                    return $accessKeyId;
                }
            }

            throw S3Exception::signatureDoesNotMatch();
        } catch (S3Exception $e) {
            throw $e;
        } catch (\Exception $e) {
            Logger::error("[Auth] V4 authentication error: " . $e->getMessage());
            throw S3Exception::accessDenied();
        }
    }

    private function parseSignatureV4Header(string $authHeader): array
    {
        // Clean line folding from proxy headers
        $cleanedHeader = preg_replace('/\s+/', ' ', str_replace(["\r\n", "\r", "\n"], ' ', $authHeader));
        $cleanedHeader = trim($cleanedHeader);

        $pattern = '/AWS4-HMAC-SHA256\s+Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([a-f0-9]+)/i';

        if (!preg_match($pattern, $cleanedHeader, $matches)) {
            throw S3Exception::accessDenied('Invalid Authorization header format');
        }

        $credentialParts = explode('/', $matches[1]);
        if (count($credentialParts) < 5) {
            throw S3Exception::invalidAccessKeyId();
        }

        return [
            'Credential' => [
                'AccessKeyId' => $credentialParts[0],
                'Date' => $credentialParts[1],
                'Region' => $credentialParts[2],
                'Service' => $credentialParts[3],
                'RequestType' => $credentialParts[4],
            ],
            'SignedHeaders' => $matches[2],
            'Signature' => $matches[3],
        ];
    }

    private function validateTimestamp(array $signatureData): void
    {
        $amzDate = $this->getAmzDate($this->request->getHeaders());
        if (empty($amzDate)) {
            throw S3Exception::invalidRequest('X-Amz-Date header is required');
        }

        $requestTime = \DateTime::createFromFormat('Ymd\THis\Z', $amzDate, new \DateTimeZone('UTC'));
        if ($requestTime === false) {
            throw S3Exception::invalidRequest('Invalid X-Amz-Date format');
        }

        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $diff = abs($now->getTimestamp() - $requestTime->getTimestamp());

        if ($diff > self::MAX_TIMESTAMP_SKEW) {
            throw S3Exception::expiredToken('Request timestamp skew too large');
        }
    }

    /**
     * Get methods to try, with HEAD/GET fallback for web server compatibility
     */
    private function getMethodsWithFallback(): array
    {
        $currentMethod = $this->request->getMethod();
        $methods = [$currentMethod];

        if ($currentMethod === 'GET' || $currentMethod === 'HEAD') {
            $methods[] = ($currentMethod === 'GET') ? 'HEAD' : 'GET';
        }

        return $methods;
    }

    private function buildStringToSign(array $signatureData, ?string $overrideMethod = null): string
    {
        $method = $overrideMethod ?? $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();
        $body = $this->request->getBody();

        $canonicalUri = $this->encodeUri($uri);
        $canonicalQueryString = $this->normalizeQueryString($queryString);
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $signatureData['SignedHeaders']);
        $signedHeaders = strtolower($signatureData['SignedHeaders']);
        $hashedPayload = $this->getPayloadHash($headers, $body, $method);

        $canonicalRequest = implode("\n", [
            $method,
            $canonicalUri,
            $canonicalQueryString,
            $canonicalHeaders,
            '',
            $signedHeaders,
            $hashedPayload,
        ]);

        $amzDate = $this->getAmzDate($headers);
        $date = substr($amzDate, 0, 8);
        $region = $signatureData['Credential']['Region'];
        $service = $signatureData['Credential']['Service'];
        $scope = "{$date}/{$region}/{$service}/aws4_request";

        return implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);
    }

    private function encodeUri(string $uri): string
    {
        $uri = $uri ?: '/';

        $parts = explode('/', $uri);
        $encodedParts = [];

        foreach ($parts as $part) {
            if ($part === '') {
                $encodedParts[] = '';
            } else {
                $encodedParts[] = rawurlencode(rawurldecode($part));
            }
        }

        $result = implode('/', $encodedParts);

        if (!str_starts_with($result, '/')) {
            $result = '/' . $result;
        }

        return $result;
    }

    private function getAmzDate(array $headers): string
    {
        $amzDate = $this->findHeader($headers, 'x-amz-date');
        if ($amzDate !== null) {
            return $amzDate;
        }

        $dateHeader = $this->findHeader($headers, 'date');
        if ($dateHeader !== null) {
            $timestamp = strtotime($dateHeader);
            if ($timestamp !== false) {
                return gmdate('Ymd\THis\Z', $timestamp);
            }
        }

        return gmdate('Ymd\THis\Z');
    }

    private function getPayloadHash(array $headers, string $body, ?string $overrideMethod = null): string
    {
        $contentSha256 = $this->findHeader($headers, 'x-amz-content-sha256');
        if ($contentSha256 !== null) {
            return $contentSha256;
        }

        $method = $overrideMethod ?? $this->request->getMethod();

        // HEAD, GET, DELETE have no body — use empty string SHA256
        if (in_array($method, ['HEAD', 'GET', 'DELETE'])) {
            return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        }

        return hash('sha256', $body);
    }

    private function normalizeQueryString(string $queryString): string
    {
        if (empty($queryString)) {
            return '';
        }

        $params = [];
        $pairs = explode('&', $queryString);

        foreach ($pairs as $pair) {
            if (str_contains($pair, '=')) {
                [$key, $value] = explode('=', $pair, 2);
                $params[rawurldecode($key)] = rawurldecode($value);
            } else {
                $params[rawurldecode($pair)] = '';
            }
        }

        ksort($params, SORT_STRING);

        $normalized = [];
        foreach ($params as $key => $value) {
            $normalized[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $normalized);
    }

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
                $normalizedValue = trim(preg_replace('/\s+/', ' ', $value));
                $canonicalHeaders[] = strtolower($headerName) . ':' . $normalizedValue;
            }
        }

        sort($canonicalHeaders, SORT_STRING);

        return implode("\n", $canonicalHeaders);
    }

    private function findHeader(array $headers, string $name): ?string
    {
        // Delegate to Request's O(1) lowercased-header map. The $headers param
        // is kept for signature compatibility but unused.
        return $this->request->getHeader($name);
    }

    private function calculateSignatureV4(string $stringToSign, string $secretKey, array $signatureData): string
    {
        $amzDate = $this->getAmzDate($this->request->getHeaders());
        $date = substr($amzDate, 0, 8);
        $region = $signatureData['Credential']['Region'];
        $service = $signatureData['Credential']['Service'];

        return $this->calculateSignatureV4WithDate($stringToSign, $secretKey, $date, $region, $service);
    }

    private function calculateSignatureV4WithDate(string $stringToSign, string $secretKey, string $date, string $region, string $service): string
    {
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        return hash_hmac('sha256', $stringToSign, $kSigning);
    }

    // ─── Presigned URL ──────────────────────────────────────────────────

    private function authenticatePresignedUrl(): string
    {
        try {
            $presignedData = $this->parsePresignedUrlParams();

            $accessKeyId = $presignedData['Credential']['AccessKeyId'];
            $this->checkPresignedUrlExpiry($presignedData);

            $secretKey = Config::getSecretKey($accessKeyId);
            if ($secretKey === null) {
                throw S3Exception::invalidAccessKeyId();
            }

            $methodsToTry = $this->getMethodsWithFallback();

            foreach ($methodsToTry as $method) {
                $stringToSign = $this->buildPresignedUrlStringToSign($presignedData, $method);
                $calculatedSignature = $this->calculatePresignedUrlSignature($stringToSign, $secretKey, $presignedData);

                if (hash_equals($calculatedSignature, $presignedData['Signature'])) {
                    return $accessKeyId;
                }
            }

            throw S3Exception::signatureDoesNotMatch();
        } catch (S3Exception $e) {
            throw $e;
        } catch (\Exception $e) {
            Logger::error("[Auth] Presigned URL authentication error: " . $e->getMessage());
            throw S3Exception::accessDenied();
        }
    }

    private function parsePresignedUrlParams(): array
    {
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
            empty($signedHeaders) || empty($signature) || empty($expires)) {
            throw S3Exception::accessDenied('Missing required presigned URL parameters');
        }

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
            'Expires' => (int)$expires,
            'SignedHeaders' => $signedHeaders,
            'Signature' => $signature,
        ];
    }

    private function checkPresignedUrlExpiry(array $presignedData): void
    {
        $expires = $presignedData['Expires'];

        // S3 spec: X-Amz-Expires must be 1..604800 (7 days).
        if ($expires < 1 || $expires > 604800) {
            throw S3Exception::invalidRequest('X-Amz-Expires must be between 1 and 604800 seconds');
        }

        $requestTime = \DateTime::createFromFormat('Ymd\THis\Z', $presignedData['AmzDate'], new \DateTimeZone('UTC'));
        if ($requestTime === false) {
            throw S3Exception::invalidRequest('Invalid X-Amz-Date format');
        }

        $expiryTime = clone $requestTime;
        $expiryTime->modify("+{$expires} seconds");

        if (new \DateTime('now', new \DateTimeZone('UTC')) > $expiryTime) {
            throw S3Exception::expiredToken('Request has expired');
        }
    }

    private function buildPresignedUrlStringToSign(array $presignedData, ?string $overrideMethod = null): string
    {
        $method = $overrideMethod ?? $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();

        $canonicalUri = $this->encodeUri($uri);
        $canonicalQueryString = $this->buildPresignedCanonicalQueryString($queryString);
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $presignedData['SignedHeaders']);
        $signedHeaders = strtolower($presignedData['SignedHeaders']);

        $canonicalRequest = implode("\n", [
            $method,
            $canonicalUri,
            $canonicalQueryString,
            $canonicalHeaders,
            '',
            $signedHeaders,
            'UNSIGNED-PAYLOAD',
        ]);

        $amzDate = $presignedData['AmzDate'];
        $date = $presignedData['Credential']['Date'];
        $region = $presignedData['Credential']['Region'];
        $service = $presignedData['Credential']['Service'];
        $scope = "{$date}/{$region}/{$service}/aws4_request";

        return implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);
    }

    private function buildPresignedCanonicalQueryString(string $queryString): string
    {
        if (empty($queryString)) {
            return '';
        }

        $params = [];
        $pairs = explode('&', $queryString);

        foreach ($pairs as $pair) {
            if (str_contains($pair, '=')) {
                [$key, $value] = explode('=', $pair, 2);
                $decodedKey = rawurldecode($key);

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

        ksort($params, SORT_STRING);

        $normalized = [];
        foreach ($params as $key => $value) {
            $normalized[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $normalized);
    }

    private function calculatePresignedUrlSignature(string $stringToSign, string $secretKey, array $presignedData): string
    {
        return $this->calculateSignatureV4WithDate(
            $stringToSign,
            $secretKey,
            $presignedData['Credential']['Date'],
            $presignedData['Credential']['Region'],
            $presignedData['Credential']['Service']
        );
    }

    // ─── AWS Signature Version 2 (legacy) ──────────────────────────────

    private function authenticateAwsSignatureV2(string $authHeader): string
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

        return $accessKeyId;
    }

    // ─── Bearer Token ──────────────────────────────────────────────────

    private function authenticateBearerToken(string $authHeader): void
    {
        $token = substr($authHeader, 7);
        $validToken = Config::bearerToken();

        if ($validToken === null || !hash_equals($validToken, $token)) {
            throw S3Exception::accessDenied();
        }
    }

    // ─── Request size check ────────────────────────────────────────────

    public function checkRequestSize(string $accessKeyId): void
    {
        $maxSize = Config::getFileMaxSize($accessKeyId);
        if ($maxSize <= 0) {
            return;
        }

        // Prefer Content-Length header; fall back to decoded body length so that
        // aws-chunked / chunked transfers (which may omit a meaningful Content-Length)
        // cannot bypass the per-key upload size limit.
        $contentLength = $this->request->getHeader('Content-Length');
        $actualSize = $contentLength !== null ? (int)$contentLength : strlen($this->request->getBody());

        if ($actualSize > $maxSize) {
            throw S3Exception::entityTooLarge($actualSize, $maxSize);
        }
    }

    /**
     * 早期请求大小检查：基于 Content-Length 头，在认证前拒绝超大请求。
     * 全局上限 = 所有 access key 中最大的 file_max_size。
     * 若所有 key 均无限制（返回 0），跳过，回退到认证后的 per-key checkRequestSize()。
     */
    public function checkEarlyRequestSize(): void
    {
        $contentLength = $this->request->getHeader('Content-Length');
        if ($contentLength === null) {
            return;
        }
        $globalMax = Config::getMaxUploadSize();
        if ($globalMax > 0 && (int)$contentLength > $globalMax) {
            throw S3Exception::entityTooLarge((int)$contentLength, $globalMax);
        }
    }
}
