<?php

namespace S3Gateway\Tests\Http;

use PHPUnit\Framework\TestCase;
use S3Gateway\Http\Request;

class RequestTest extends TestCase
{
    private array $originalServer;

    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;
    }

    private function createRequest(array $serverVars = []): Request
    {
        $_SERVER = array_merge($this->originalServer, $serverVars);
        return new Request();
    }

    // ─── Method Detection ────────────────────────────────────────────

    public function testGetMethod(): void
    {
        $request = $this->createRequest(['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/']);
        $this->assertEquals('GET', $request->getMethod());
    }

    public function testPostMethod(): void
    {
        $request = $this->createRequest(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/bucket']);
        $this->assertEquals('POST', $request->getMethod());
    }

    public function testHeadMethod(): void
    {
        $request = $this->createRequest(['REQUEST_METHOD' => 'HEAD', 'REQUEST_URI' => '/bucket/key']);
        $this->assertEquals('HEAD', $request->getMethod());
    }

    public function testDeleteMethod(): void
    {
        $request = $this->createRequest(['REQUEST_METHOD' => 'DELETE', 'REQUEST_URI' => '/bucket/key']);
        $this->assertEquals('DELETE', $request->getMethod());
    }

    public function testMethodOverrideHeader(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket/key',
            'HTTP_X_HTTP_METHOD_OVERRIDE' => 'HEAD',
        ]);
        $this->assertEquals('HEAD', $request->getMethod());
    }

    // ─── URI Parsing ─────────────────────────────────────────────────

    public function testUriParsing(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/mybucket/mykey',
        ]);
        $this->assertEquals('/mybucket/mykey', $request->getUri());
    }

    public function testUriStripsQueryString(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/mybucket/mykey?foo=bar&baz=qux',
            'QUERY_STRING' => 'foo=bar&baz=qux',
        ]);
        $this->assertEquals('/mybucket/mykey', $request->getUri());
        $this->assertEquals('foo=bar&baz=qux', $request->getQueryString());
    }

    public function testRootUri(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
        ]);
        $this->assertEquals('/', $request->getUri());
    }

    // ─── Bucket & Key Parsing ────────────────────────────────────────

    public function testBucketAndKeyParsing(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/mybucket/folder/file.txt',
        ]);
        $this->assertEquals('mybucket', $request->getBucket());
        $this->assertEquals('folder/file.txt', $request->getKey());
    }

    public function testBucketOnlyNoKey(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/mybucket',
        ]);
        $this->assertEquals('mybucket', $request->getBucket());
        $this->assertEquals('', $request->getKey());
    }

    public function testNoBucketNoKey(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
        ]);
        $this->assertEquals('', $request->getBucket());
        $this->assertEquals('', $request->getKey());
    }

    // ─── Query Params ────────────────────────────────────────────────

    public function testQueryParam(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/mybucket?list-type=2&prefix=photos/',
            'QUERY_STRING' => 'list-type=2&prefix=photos/',
        ]);
        $this->assertEquals('2', $request->getQueryParam('list-type'));
        $this->assertEquals('photos/', $request->getQueryParam('prefix'));
    }

    public function testQueryParamMissing(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/mybucket',
            'QUERY_STRING' => '',
        ]);
        $this->assertNull($request->getQueryParam('nonexistent'));
    }

    public function testHasQueryParam(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/mybucket?uploads=',
            'QUERY_STRING' => 'uploads=',
        ]);
        $this->assertTrue($request->hasQueryParam('uploads'));
        $this->assertFalse($request->hasQueryParam('delete'));
    }

    // ─── Headers ─────────────────────────────────────────────────────

    public function testHeaderFromHttpPrefix(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'HTTP_AUTHORIZATION' => 'AWS4-HMAC-SHA256 Credential=test',
        ]);
        $this->assertEquals('AWS4-HMAC-SHA256 Credential=test', $request->getHeader('Authorization'));
    }

    public function testContentTypeHeader(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'PUT',
            'REQUEST_URI' => '/bucket/key',
            'CONTENT_TYPE' => 'application/xml',
        ]);
        $this->assertEquals('application/xml', $request->getHeader('Content-Type'));
    }

    public function testHeaderNotFound(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
        ]);
        $this->assertNull($request->getHeader('X-Custom-Header'));
    }

    // ─── Body ────────────────────────────────────────────────────────

    public function testHeadMethodReturnsEmptyBody(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'HEAD',
            'REQUEST_URI' => '/bucket/key',
        ]);
        $this->assertEquals('', $request->getBody());
    }

    // ─── Preflight ───────────────────────────────────────────────────

    public function testIsPreflight(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'OPTIONS',
            'REQUEST_URI' => '/bucket',
        ]);
        $this->assertTrue($request->isPreflight());
    }

    public function testIsNotPreflight(): void
    {
        $request = $this->createRequest([
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/bucket',
        ]);
        $this->assertFalse($request->isPreflight());
    }
}
