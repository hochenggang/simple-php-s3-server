<?php

namespace S3Gateway\Storage;

/**
 * Client-supplied object metadata: the Content-Type given at upload and
 * user metadata (x-amz-meta-* headers, keyed by lowercase name without the
 * prefix). Backends store it with the object and return it unchanged.
 */
final class ObjectMetadata
{
    /** @param array<string,string> $user */
    public function __construct(
        public readonly ?string $contentType = null,
        public readonly array $user = [],
    ) {
    }

    /** @param array<string,mixed> $data as produced by toArray() */
    public static function fromArray(array $data): self
    {
        $user = [];
        foreach ((array)($data['user'] ?? []) as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $user[$name] = $value;
            }
        }
        $type = $data['contentType'] ?? null;
        return new self(is_string($type) ? $type : null, $user);
    }

    /** @return array{contentType:?string,user:array<string,string>} */
    public function toArray(): array
    {
        return ['contentType' => $this->contentType, 'user' => $this->user];
    }
}
