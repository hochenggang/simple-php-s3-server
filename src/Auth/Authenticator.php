<?php

namespace S3Gateway\Auth;

use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Logger;

class Authenticator
{
    private bool $debug;
    private Request $request;

    public function __construct(bool $debug, Request $request)
    {
        $this->debug = $debug;
        $this->request = $request;
    }

    public function authenticate(): void
    {
        $authHeader = $this->request->getHeader('Authorization');

        // Check for presigned URL request (X-Amz-Credential in query string)
        if ($this->isPresignedUrlRequest()) {
            $this->authenticatePresignedUrl();
            return;
        }

        if (empty($authHeader)) {
            throw S3Exception::accessDenied();
        }

        if (strpos($authHeader, 'AWS4-HMAC-SHA256') === 0) {
            $this->authenticateAwsSignatureV4($authHeader);
        } elseif (strpos($authHeader, 'AWS ') === 0) {
            $this->authenticateAwsSignatureV2($authHeader);
        } elseif (strpos($authHeader, 'Bearer ') === 0) {
            $this->authenticateBearerToken($authHeader);
        } else {
            throw S3Exception::accessDenied();
        }
    }

    private function isPresignedUrlRequest(): bool
    {
        return $this->request->hasQueryParam('X-Amz-Credential') ||
               $this->request->hasQueryParam('x-amz-credential');
    }

    private function authenticateAwsSignatureV4(string $authHeader): void
    {
        $signatureData = $this->parseSignatureV4Header($authHeader);

        $accessKeyId = $signatureData['Credential']['AccessKeyId'] ?? null;
        if ($accessKeyId === null) {
            throw S3Exception::invalidAccessKeyId();
        }

        $secretKey = Config::getSecretKey($accessKeyId);
        if ($secretKey === null) {
            throw S3Exception::invalidAccessKeyId();
        }

        if ($this->debug) {
            Logger::debug("AWS4 Auth: AccessKeyId={$accessKeyId}");
        }

        $stringToSign = $this->buildStringToSign($signatureData);
        $signature = $this->calculateSignatureV4($stringToSign, $secretKey, $signatureData);

        if (!hash_equals($signature, $signatureData['Signature'])) {
            if ($this->debug) {
                Logger::debug("AWS4 Signature mismatch: expected={$signature}, got={$signatureData['Signature']}");
                Logger::debug("StringToSign:\n" . $stringToSign);
            }
            throw S3Exception::signatureDoesNotMatch();
        }
    }

    private function parseSignatureV4Header(string $authHeader): array
    {
        $pattern = '/AWS4-HMAC-SHA256\s+Credential=([^,]+),\s*SignedHeaders=([^,]+),\s*Signature=([a-f0-9]+)/i';
        if (!preg_match($pattern, $authHeader, $matches)) {
            throw S3Exception::accessDenied();
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

    private function buildStringToSign(array $signatureData): string
    {
        $method = $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();
        $body = $this->request->getBody();

        $canonicalUri = $this->encodeUri($uri);
        $canonicalQueryString = $this->normalizeQueryString($queryString);
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $signatureData['SignedHeaders']);
        $signedHeaders = strtolower($signatureData['SignedHeaders']);
        $hashedPayload = $this->getPayloadHash($headers, $body);

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

        $stringToSign = implode("\n", [
            'AWS4-HMAC-SHA256',
            $amzDate,
            $scope,
            hash('sha256', $canonicalRequest),
        ]);

        return $stringToSign;
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
        return implode('/', $encodedParts);
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

    private function getPayloadHash(array $headers, string $body): string
    {
        $contentSha256 = $this->findHeader($headers, 'x-amz-content-sha256');
        if ($contentSha256 !== null) {
            return $contentSha256;
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
            if (strpos($pair, '=') !== false) {
                list($key, $value) = explode('=', $pair, 2);
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
                $canonicalHeaders[] = strtolower($headerName) . ':' . $this->normalizeHeaderValue($value);
            }
        }

        $result = implode("\n", $canonicalHeaders);
        
        if ($this->debug && strpos($signedHeaders, 'range') !== false) {
            Logger::debug("CanonicalHeaders (with range):\n" . $result);
        }
        
        return $result;
    }

    private function normalizeHeaderValue(string $value): string
    {
        $value = trim($value);
        $value = preg_replace('/\s+/', ' ', $value);
        return $value;
    }

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

    private function calculateSignatureV4(string $stringToSign, string $secretKey, array $signatureData): string
    {
        $amzDate = $this->getAmzDate($this->request->getHeaders());
        $date = substr($amzDate, 0, 8);
        $region = $signatureData['Credential']['Region'];
        $service = $signatureData['Credential']['Service'];

        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        return hash_hmac('sha256', $stringToSign, $kSigning);
    }

    private function calculateSignatureV4WithDate(string $stringToSign, string $secretKey, string $date, string $region, string $service): string
    {
        $kDate = hash_hmac('sha256', $date, 'AWS4' . $secretKey, true);
        $kRegion = hash_hmac('sha256', $region, $kDate, true);
        $kService = hash_hmac('sha256', $service, $kRegion, true);
        $kSigning = hash_hmac('sha256', 'aws4_request', $kService, true);

        return hash_hmac('sha256', $stringToSign, $kSigning);
    }

    private function authenticatePresignedUrl(): void
    {
        $presignedData = $this->parsePresignedUrlParams();

        // Check if signature has expired
        $this->checkPresignedUrlExpiry($presignedData);

        $accessKeyId = $presignedData['Credential']['AccessKeyId'];
        $secretKey = Config::getSecretKey($accessKeyId);
        if ($secretKey === null) {
            throw S3Exception::invalidAccessKeyId();
        }

        if ($this->debug) {
            Logger::debug("Presigned URL Auth: AccessKeyId={$accessKeyId}");
        }

        // Build string to sign for presigned URL
        $stringToSign = $this->buildPresignedUrlStringToSign($presignedData);
        $signature = $this->calculatePresignedUrlSignature($stringToSign, $secretKey, $presignedData);

        if (!hash_equals($signature, $presignedData['Signature'])) {
            if ($this->debug) {
                Logger::debug("Presigned URL Signature mismatch: expected={$signature}, got={$presignedData['Signature']}");
                Logger::debug("StringToSign:\n" . $stringToSign);
            }
            throw S3Exception::signatureDoesNotMatch();
        }
    }

    private function parsePresignedUrlParams(): array
    {
        // Get parameters from query string (case-insensitive)
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
            throw S3Exception::accessDenied();
        }

        // Parse credential: AccessKeyId/Date/Region/Service/aws4_request
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

    private function checkPresignedUrlExpiry(array $presignedData): void
    {
        $expires = $presignedData['Expires'];
        if ($expires === null) {
            return; // No expiry specified
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
            throw S3Exception::expiredToken('Request has expired.');
        }
    }

    private function buildPresignedUrlStringToSign(array $presignedData): string
    {
        $method = $this->request->getMethod();
        $uri = $this->request->getUri();
        $queryString = $this->request->getQueryString();
        $headers = $this->request->getHeaders();

        $canonicalUri = $this->encodeUri($uri);

        // Build canonical query string for presigned URL (excluding X-Amz-Signature)
        $canonicalQueryString = $this->buildPresignedCanonicalQueryString($queryString);

        // Build canonical headers
        $canonicalHeaders = $this->buildCanonicalHeaders($headers, $presignedData['SignedHeaders']);
        $signedHeaders = strtolower($presignedData['SignedHeaders']);

        // For presigned URLs, use 'UNSIGNED-PAYLOAD' as the payload hash
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
            Logger::debug("Presigned URL CanonicalRequest:\n" . $canonicalRequest);
            Logger::debug("Presigned URL StringToSign:\n" . $stringToSign);
        }

        return $stringToSign;
    }

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

                // Exclude X-Amz-Signature from canonical query string
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

        // Sort parameters by key
        ksort($params, SORT_STRING);

        // Build normalized query string
        $normalized = [];
        foreach ($params as $key => $value) {
            $normalized[] = rawurlencode($key) . '=' . rawurlencode($value);
        }

        return implode('&', $normalized);
    }

    private function calculatePresignedUrlSignature(string $stringToSign, string $secretKey, array $presignedData): string
    {
        $date = $presignedData['Credential']['Date'];
        $region = $presignedData['Credential']['Region'];
        $service = $presignedData['Credential']['Service'];

        return $this->calculateSignatureV4WithDate($stringToSign, $secretKey, $date, $region, $service);
    }

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

    private function authenticateBearerToken(string $authHeader): void
    {
        $token = substr($authHeader, 7);
        $validToken = Config::bearerToken();

        if ($validToken === null || !hash_equals($validToken, $token)) {
            throw S3Exception::accessDenied();
        }
    }

    public function checkRequestSize(): void
    {
        $contentLength = $this->request->getHeader('Content-Length');
        $maxSize = Config::maxUploadSize();

        if ($contentLength !== null && (int)$contentLength > $maxSize) {
            throw S3Exception::entityTooLarge((int)$contentLength, $maxSize);
        }
    }
}
