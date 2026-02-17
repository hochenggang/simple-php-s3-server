<?php

namespace S3Gateway\Http;

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
        http_response_code($this->statusCode);

        foreach ($this->headers as $name => $value) {
            header("{$name}: {$value}");
        }

        echo $this->body;
    }

    public function sendEmpty(int $statusCode = 204): void
    {
        $this->statusCode = $statusCode;
        http_response_code($this->statusCode);

        Logger::debug("[sendEmpty] Sending headers for status {$statusCode}:");
        // Send headers, ensuring Content-Length is preserved
        foreach ($this->headers as $name => $value) {
            Logger::debug("[sendEmpty]   {$name}: {$value}");
            header("{$name}: {$value}", true);
        }
        Logger::debug("[sendEmpty] Headers sent");
    }

    public function sendFile(string $filePath, array $options = []): void
    {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }

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

        $start = $options['start'] ?? 0;
        $end = $options['end'] ?? ($fileSize - 1);
        $partial = $options['partial'] ?? false;

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

        http_response_code($statusCode);
        header('Content-Type: ' . $mimeType);
        header('Accept-Ranges: bytes');
        header('Content-Disposition: inline; filename="' . $filename . '"');
        header($contentLengthHeader);
        if ($contentRange !== null) {
            header($contentRange);
        }

        $fp = fopen($filePath, 'rb');
        if ($fp === false) {
            http_response_code(500);
            echo 'Failed to open file';
            return;
        }

        if ($start > 0) {
            fseek($fp, $start);
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
