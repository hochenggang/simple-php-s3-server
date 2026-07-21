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

    public function sendFile(string $filePath, array $options = []): void
    {
        if (!file_exists($filePath)) {
            http_response_code(404);
            header('Content-Type: text/plain');
            echo 'File not found';
            return;
        }

        clearstatcache(true, $filePath);
        $fileSize = filesize($filePath);

        if ($fileSize === false || $fileSize < 0) {
            http_response_code(500);
            header('Content-Type: text/plain');
            echo 'Cannot read file size';
            return;
        }

        // Open the file BEFORE emitting any headers so a fopen failure can still
        // produce a clean 500 without a stale Content-Length confusing the client.
        $fp = fopen($filePath, 'rb');
        if ($fp === false) {
            http_response_code(500);
            header('Content-Type: text/plain');
            echo 'Failed to open file';
            return;
        }

        $start = $options['start'] ?? 0;
        $end = $options['end'] ?? ($fileSize - 1);
        $partial = $options['partial'] ?? false;

        if ($start > 0) {
            if (fseek($fp, $start) !== 0) {
                fclose($fp);
                http_response_code(500);
                header('Content-Type: text/plain');
                echo 'Seek failed';
                return;
            }
        }

        if ($partial) {
            $statusCode = 206;
            $contentLength = $end - $start + 1;
            $contentRange = 'Content-Range: bytes ' . $start . '-' . $end . '/' . $fileSize;
            $contentLengthHeader = 'Content-Length: ' . $contentLength;
        } else {
            $statusCode = 200;
            $contentLengthHeader = 'Content-Length: ' . $fileSize;
            $contentRange = null;
        }

        $mimeType = $options['mime'] ?? $this->detectMimeType($filePath);
        $filename = $options['filename'] ?? basename($filePath);

        // RFC 6266 Content-Disposition: ASCII fallback (quoted) + UTF-8 filename*
        // for non-ASCII names. Avoids the incomplete '"'→'\\"' escaping of the
        // previous implementation which left backslashes and control chars loose.
        $asciiFallback = preg_replace('/[^\x20-\x7e]/', '_', $filename);
        $asciiFallback = str_replace('"', '\\"', $asciiFallback);
        $disposition = 'inline; filename="' . $asciiFallback . '"; filename*=UTF-8\'\'' . rawurlencode($filename);

        http_response_code($statusCode);
        header('Content-Type: ' . $mimeType);
        header('Accept-Ranges: bytes');
        header('Content-Disposition: ' . $disposition);
        header($contentLengthHeader);
        if ($contentRange !== null) {
            header($contentRange);
        }

        // Metadata headers (kept consistent with HEAD responses).
        if (isset($options['etag']) && $options['etag'] !== '') {
            $etag = $options['etag'];
            if (!str_starts_with($etag, '"')) {
                $etag = '"' . $etag . '"';
            }
            header('ETag: ' . $etag);
        }
        if (isset($options['lastModified'])) {
            // RFC 7232 HTTP-date requires a literal "GMT" suffix; PHP's "T" yields "UTC".
            header('Last-Modified: ' . gmdate('D, d M Y H:i:s \G\M\T', (int)$options['lastModified']));
        }

        $bufferSize = 65536;
        $bytesSent = 0;
        $bytesToSend = $end - $start + 1;

        while (!feof($fp) && $bytesSent < $bytesToSend) {
            $remaining = $bytesToSend - $bytesSent;
            $readSize = min($bufferSize, $remaining);
            $buffer = fread($fp, $readSize);
            if ($buffer === false) {
                break;
            }
            echo $buffer;
            flush();
            $bytesSent += strlen($buffer);
        }

        fclose($fp);
    }

    private function detectMimeType(string $filePath): string
    {
        clearstatcache(true, $filePath);
        $mime = @mime_content_type($filePath);
        return $mime !== false ? $mime : 'application/octet-stream';
    }
}
