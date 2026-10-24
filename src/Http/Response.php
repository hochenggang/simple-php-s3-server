<?php

namespace S3Gateway\Http;

use S3Gateway\Config;
use S3Gateway\Logger;

class Response
{
    private int $statusCode = 200;
    private array $headers = [];
    private string $body = '';

    public function setStatusCode(int $code): self
    {
        $this->statusCode = $code;
        return $this;
    }

    public function setHeader(string $name, string $value): self
    {
        $this->headers[$name] = $value;
        return $this;
    }

    public function setBody(string $body): self
    {
        $this->body = $body;
        return $this;
    }

    public function send(): void
    {
        $this->logResponse();

        http_response_code($this->statusCode);

        foreach ($this->headers as $name => $value) {
            header("{$name}: {$value}");
        }

        echo $this->body;
    }

    /**
     * Log response info in debug mode
     */
    private function logResponse(): void
    {
        if (!Config::appDebug()) {
            return;
        }

        Logger::debug("[Response] Status: {$this->statusCode}, Body: " . strlen($this->body) . " bytes");
    }

    public function sendEmpty(int $statusCode = 204): void
    {
        $this->statusCode = $statusCode;
        http_response_code($this->statusCode);

        foreach ($this->headers as $name => $value) {
            header("{$name}: {$value}", true);
        }
    }

    /** Legacy convenience method. Object controllers use backend streams. */
    public function sendFile(string $filePath, array $options = []): void
    {
        $fp = @fopen($filePath, 'rb');
        if ($fp === false) {
            http_response_code(404);
            return;
        }
        try {
            $size = fstat($fp)['size'];
            $start = $options['start'] ?? 0;
            if ($start > 0 && fseek($fp, $start) !== 0) {
                throw new \RuntimeException('Cannot seek object stream');
            }
            $options += ['size' => $size, 'mime' => $this->detectMimeType($filePath), 'filename' => basename($filePath)];
            $length = !empty($options['partial']) ? ($options['end'] ?? ($size - 1)) - $start + 1 : $size;
            $this->sendStream($fp, $length, $options);
        } finally {
            fclose($fp);
        }
    }

    /** Send a positioned readable stream; the caller retains ownership. */
    public function sendStream($stream, int $length, array $options = []): void
    {
        if (!is_resource($stream) || $length < 0) {
            throw new \InvalidArgumentException('Invalid response stream or length');
        }
        $partial = $options['partial'] ?? false;
        http_response_code($partial ? 206 : 200);
        foreach ($this->headers as $name => $value) {
            header($name . ': ' . $value);
        }
        header('Content-Type: ' . ($options['mime'] ?? 'application/octet-stream'));
        header('Content-Length: ' . $length);
        header('Accept-Ranges: bytes');
        if ($partial) {
            $start = $options['start'] ?? 0;
            header('Content-Range: bytes ' . $start . '-' . ($start + $length - 1) . '/' . $options['size']);
        }
        $filename = $options['filename'] ?? 'object';
        $fallback = preg_replace('/[^\x20-\x7e]/', '_', $filename);
        $fallback = str_replace('"', '\\"', $fallback);
        header('Content-Disposition: inline; filename="' . $fallback . '"; filename*=UTF-8\'\'' . rawurlencode($filename));
        if (!empty($options['etag'])) {
            header('ETag: "' . trim($options['etag'], '"') . '"');
        }
        if (isset($options['lastModified'])) {
            header('Last-Modified: ' . gmdate('D, d M Y H:i:s \G\M\T', (int) $options['lastModified']));
        }
        while ($length > 0 && !feof($stream)) {
            $buffer = fread($stream, min(65536, $length));
            if ($buffer === false || $buffer === '') {
                break;
            }
            echo $buffer;
            $length -= strlen($buffer);
        }
        if ($length !== 0) {
            Logger::error('Response stream ended before the declared Content-Length');
        }
    }

    private function detectMimeType(string $filePath): string
    {
        clearstatcache(true, $filePath);
        $mime = @mime_content_type($filePath);
        return $mime !== false ? $mime : 'application/octet-stream';
    }
}
