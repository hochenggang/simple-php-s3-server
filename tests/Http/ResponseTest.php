<?php

namespace S3Gateway\Tests\Http;

use PHPUnit\Framework\TestCase;
use S3Gateway\Http\Response;

class ResponseTest extends TestCase
{
    private Response $response;

    protected function setUp(): void
    {
        $this->response = new Response();
    }

    public function testSetStatusCode(): void
    {
        $result = $this->response->setStatusCode(404);
        $this->assertSame($this->response, $result);
    }

    public function testSetHeader(): void
    {
        $result = $this->response->setHeader('Content-Type', 'application/xml');
        $this->assertSame($this->response, $result);
    }

    public function testSetBody(): void
    {
        $result = $this->response->setBody('<xml>test</xml>');
        $this->assertSame($this->response, $result);
    }

    public function testChainedCalls(): void
    {
        // Verify fluent interface works
        $result = $this->response
            ->setStatusCode(200)
            ->setHeader('Content-Type', 'text/plain')
            ->setBody('hello');

        $this->assertSame($this->response, $result);
    }

    public function testMultipleHeaders(): void
    {
        $this->response
            ->setHeader('Content-Type', 'application/xml')
            ->setHeader('ETag', '"abc123"');

        // No assertion needed — just verifying no exceptions
        $this->assertTrue(true);
    }
}
