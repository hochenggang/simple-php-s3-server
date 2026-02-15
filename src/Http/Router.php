<?php

namespace S3Gateway\Http;

use S3Gateway\Auth\Authenticator;
use S3Gateway\Config;
use S3Gateway\Exception\S3Exception;
use S3Gateway\Logger;
use S3Gateway\S3\BucketController;
use S3Gateway\S3\ObjectController;
use S3Gateway\S3\MultipartController;
use S3Gateway\S3\XmlResponse;
use S3Gateway\Storage\FileStorage;

class Router
{
    private Request $request;
    private Response $response;
    private Authenticator $authenticator;
    private FileStorage $storage;
    private BucketController $bucketController;
    private ObjectController $objectController;
    private MultipartController $multipartController;

    public function __construct()
    {
        $this->request = new Request();
        $this->response = new Response();
        $this->authenticator = new Authenticator(Config::authDebug(), $this->request);
        $this->storage = new FileStorage();
        $this->bucketController = new BucketController($this->storage);
        $this->objectController = new ObjectController($this->storage);
        $this->multipartController = new MultipartController($this->storage);
    }

    public function handle(): void
    {
        try {
            if ($this->request->isPreflight()) {
                $this->response->sendEmpty(200);
                return;
            }

            $this->authenticator->authenticate();
            $this->authenticator->checkRequestSize();

            $this->dispatch();

        } catch (S3Exception $e) {
            $this->handleException($e);
        } catch (\InvalidArgumentException $e) {
            $this->handleException(S3Exception::invalidRequest($e->getMessage()));
        } catch (\Exception $e) {
            Logger::exception($e, 'Unexpected error');
            $this->handleException(S3Exception::internalError('Internal server error'));
        }
    }

    private function handleException(S3Exception $e): void
    {
        Logger::error(sprintf(
            "S3Exception: %s (Code: %s, HTTP: %d) - %s %s",
            $e->getMessage(),
            $e->getS3Code(),
            $e->getHttpStatus(),
            $this->request->getMethod(),
            $this->request->getUri()
        ));

        $xml = XmlResponse::error($e->getS3Code(), $e->getMessage(), $e->getResource());

        $this->response
            ->setStatusCode($e->getHttpStatus())
            ->setHeader('Content-Type', 'application/xml')
            ->setBody($xml)
            ->send();
    }

    private function dispatch(): void
    {
        $method = $this->request->getMethod();
        $bucket = $this->request->getBucket();
        $key = $this->request->getKey();

        switch ($method) {
            case 'GET':
                $this->handleGet($bucket, $key);
                break;

            case 'PUT':
                $this->handlePut($bucket, $key);
                break;

            case 'POST':
                $this->handlePost($bucket, $key);
                break;

            case 'DELETE':
                $this->handleDelete($bucket, $key);
                break;

            case 'HEAD':
                $this->handleHead($bucket, $key);
                break;

            case 'OPTIONS':
                $this->response->sendEmpty(200);
                break;

            default:
                throw S3Exception::methodNotAllowed();
        }
    }

    private function handleGet(string $bucket, string $key): void
    {
        if (empty($bucket)) {
            $this->bucketController->listBuckets($this->request, $this->response);
            return;
        }

        if (empty($key)) {
            if ($this->request->hasQueryParam('list-type') && $this->request->getQueryParam('list-type') === '2') {
                $this->bucketController->listObjectsV2($this->request, $this->response);
            } else {
                $this->bucketController->listObjects($this->request, $this->response);
            }
            return;
        }

        if ($this->request->hasQueryParam('uploadId')) {
            $this->multipartController->listParts($this->request, $this->response);
            return;
        }

        $this->objectController->getObject($this->request, $this->response);
    }

    private function handlePut(string $bucket, string $key): void
    {
        if (empty($key)) {
            $this->bucketController->createBucket($this->request, $this->response);
            return;
        }

        if ($this->request->hasQueryParam('partNumber') && $this->request->hasQueryParam('uploadId')) {
            $this->multipartController->uploadPart($this->request, $this->response);
            return;
        }

        $this->objectController->putObject($this->request, $this->response);
    }

    private function handlePost(string $bucket, string $key): void
    {
        if ($this->request->hasQueryParam('delete')) {
            $this->objectController->deleteObjects($this->request, $this->response);
            return;
        }

        if ($this->request->hasQueryParam('uploads')) {
            $this->multipartController->createMultipartUpload($this->request, $this->response);
            return;
        }

        if ($this->request->hasQueryParam('uploadId')) {
            $this->multipartController->completeMultipartUpload($this->request, $this->response);
            return;
        }

        throw S3Exception::invalidRequest('Invalid POST request');
    }

    private function handleDelete(string $bucket, string $key): void
    {
        if ($this->request->hasQueryParam('uploadId')) {
            $this->multipartController->abortMultipartUpload($this->request, $this->response);
            return;
        }

        if (empty($key)) {
            $this->bucketController->deleteBucket($this->request, $this->response);
            return;
        }

        $this->objectController->deleteObject($this->request, $this->response);
    }

    private function handleHead(string $bucket, string $key): void
    {
        $this->objectController->headObject($this->request, $this->response);
    }
}
