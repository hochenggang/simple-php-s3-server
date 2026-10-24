<?php

namespace S3Gateway\S3;

use S3Gateway\Exception\S3Exception;
use S3Gateway\Http\Request;
use S3Gateway\Http\Response;
use S3Gateway\Storage\ObjectMetadata;

/** Maps object metadata to and from S3 request and response headers. */
final class MetadataHeaders
{
    private const PREFIX = 'x-amz-meta-';
    /** S3 limit: total UTF-8 bytes of user metadata names and values. */
    private const MAX_USER_BYTES = 2048;

    /** Content-Type and x-amz-meta-* headers of an upload or copy request. */
    public static function fromRequest(Request $request): ObjectMetadata
    {
        $user = [];
        $bytes = 0;
        foreach ($request->getHeaders() as $name => $value) {
            $name = strtolower($name);
            if (!str_starts_with($name, self::PREFIX) || strlen($name) === strlen(self::PREFIX)) {
                continue;
            }
            $name = substr($name, strlen(self::PREFIX));
            $user[$name] = $value;
            $bytes += strlen($name) + strlen($value);
        }
        if ($bytes > self::MAX_USER_BYTES) {
            throw S3Exception::metadataTooLarge();
        }
        ksort($user);
        $contentType = $request->getHeader('Content-Type');
        return new ObjectMetadata($contentType !== null && $contentType !== '' ? $contentType : null, $user);
    }

    /** @param array<string,string> $user */
    public static function apply(Response $response, array $user): void
    {
        foreach ($user as $name => $value) {
            // Stored values came from single-line request headers; strip
            // line breaks anyway so a sidecar can never inject headers.
            $response->setHeader(self::PREFIX . $name, str_replace(["\r", "\n"], ' ', $value));
        }
    }
}
