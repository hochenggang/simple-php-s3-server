# Design Document v2

## 1. Core Objective

Implement a lightweight, S3-compatible API gateway (PHP 8.1+) with a replaceable storage backend. The default filesystem backend uses folders as buckets and files as objects, without requiring a database or independent metadata storage. Alternative backends implement the same bucket, object, and metadata contracts.

## 2. Design Principles

- **Minimalism**: Explicitly excludes ACL, Versioning, Object Lock, Lifecycle, Server-Side Encryption, cross-region replication, and other non-core capabilities.
- **Backend-owned storage and metadata**: Controllers obtain size / mtime / mime / etag and bucket timestamps through storage interfaces. The default filesystem backend reads metadata from the filesystem; only content ETags are kept in small sidecar files.
- **Error boundary convergence**: External responses return fixed S3 error codes and short messages; internal details are written only to logs.
- **Backward compatibility**: Does not break the existing data directory structure or configuration file format.
- **Modern PHP**: Uses PHP 8.1+, typed properties, and explicit storage interfaces.

## 3. Architecture Overview

Request lifecycle (single entry point):

```
HTTP Request
   |
   v
Entry script  -- set error handling / timezone (UTC) / load dependencies
   |
   v
Routing dispatch
   |
   |- 1. OPTIONS preflight -> 200 directly (allow cross-origin for all hosts)
   |- 2. Early request size check  (reject oversized requests based on Content-Length header)
   |- 3. Authentication             (returns accessKeyId)
   |- 4. Per-key quota validation   (takes the larger of header and body length)
   |- 5. Dispatch -> route to controller by method / bucket / key / query params
                |
                v
      Bucket / Object / Multipart controller
                |
                v
      Storage interface (bucket/object operations, metadata, streams)
                |
                v
      Selected backend (default: FileStorage)
                |
                v
      Backend-owned storage (default: local filesystem)
```

Exception handling is unified in the routing layer: business exceptions are converted to the corresponding HTTP status code and XML error body; parameter validation exceptions are converted to `InvalidRequest`; other unexpected exceptions are converted to `InternalError` (500), with full stack traces recorded in logs.

`StorageFactory` selects the configured `STORAGE_CLASS`, defaulting to `FileStorage`; applications can alternatively inject a `Storage` instance into `Router`. Controllers do not access backend paths or metadata helper classes. `MultipartStorage` is an optional extension; multipart operations return `NotImplemented` (501) when the backend does not implement it.

For subdirectory deployments, bucket/key routing omits the front controller's `SCRIPT_NAME` directory, while signature verification retains the complete request URI. Client paths in the tables below are relative to the endpoint; configure clients with a trailing slash on a directory endpoint to avoid redirects.

## 4. Supported S3 Operations

### 4.1 Bucket

| Operation | Method | Path | Description |
| --- | --- | --- | --- |
| ListBuckets | GET | `/` | Lists backend buckets and creation timestamps; FileStorage enumerates valid bucket directories |
| CreateBucket | PUT | `/{bucket}` | Creates a bucket; returns `BucketAlreadyExists` (409) if it exists |
| DeleteBucket | DELETE | `/{bucket}` | Only empty buckets can be deleted; FileStorage also cleans .multipart remnants, with non-atomic check/delete |
| ListObjects (V1) | GET | `/{bucket}` | Supports `prefix` / `marker` / `max-keys` / `delimiter` / `encoding-type` |
| ListObjectsV2 | GET | `/{bucket}?list-type=2` | Supports `prefix` / `continuation-token` / `start-after` / `fetch-owner` / `delimiter` / `encoding-type` |

> The `max-keys` upper bound is controlled by the `MAX_KEYS` config (default 100000); `continuation-token` uses URL-safe base64(`lastKey`) encoding.

> **FileStorage result caching**: To alleviate disk pressure from full scans of large buckets, the complete scan result is cached at `./tmp/listbuckets/{bucket}.json`. The format is a JSON array where each element is a `[key, size, mtime, etag]` tuple (compact storage, avoiding field name redundancy). If the cache file exists and its age (judged by file mtime) is less than `LIST_BUCKETS_CACHE_TIMEOUT` (default 60 seconds), it is loaded directly and prefix filtering, delimiter grouping, and pagination are performed in memory; otherwise the filesystem is rescanned and the cache updated. Requests with pagination parameters (marker / continuation-token / max-keys / delimiter / prefix) also use the cache, reusing the same complete scan result. After writing/deleting objects, stale listings may be returned for up to the TTL (weak consistency).

> **FileStorage limitation**: On a cache miss, the entire bucket directory is still recursively scanned, sorted, and paginated. Future optimizations based on pure filesystem characteristics: when prefix matches a real subdirectory, scan only that subdirectory (directory convergence); when using a delimiter, scan only up to that level (early truncation); use directory entry lexicographic order for in-directory binary search of the marker.

### 4.2 Object

| Operation | Method | Path | Description |
| --- | --- | --- | --- |
| PutObject | PUT | `/{bucket}/{key}` | Controller passes a stream to the backend; the request body is spooled with bounded memory while streaming, and `MAX_UPLOAD_SIZE` applies to decoded bytes |
| CopyObject | PUT | `/{bucket}/{key}` | Triggered via `X-Amz-Copy-Source` header, server-side copy |
| GetObject | GET | `/{bucket}/{key}` | Supports `Range: bytes=` single-range requests (206) |
| HeadObject | HEAD | `/{bucket}/{key}` | Returns size/content-type/etag/last-modified/accept-ranges |
| DeleteObject | DELETE | `/{bucket}/{key}` | Delegates removal to the backend; FileStorage also cleans up empty directories |
| DeleteObjects | POST | `/{bucket}?delete` | Batch delete, up to 1000 keys per request, XML request/response |

### 4.3 Multipart Upload

Available when the selected backend implements `MultipartStorage` (including `FileStorage`). Physical part storage and final assembly are backend responsibilities.

| Operation | Method | Path | Description |
| --- | --- | --- | --- |
| CreateMultipartUpload | POST | `/{bucket}/{key}?uploads` | Returns a 32-character hexadecimal `uploadId` |
| UploadPart | PUT | `/{bucket}/{key}?partNumber=N&uploadId=ID` | partNumber in [1, 10000] |
| CompleteMultipartUpload | POST | `/{bucket}/{key}?uploadId=ID` | Validates each part ETag, then delegates completion; FileStorage assembles atomically |
| AbortMultipartUpload | DELETE | `/{bucket}/{key}?uploadId=ID` | Aborts the upload; FileStorage deletes `.multipart/{uploadId}` |
| ListParts | GET | `/{bucket}/{key}?uploadId=ID` | Returns in ascending partNumber order |

> **Residual cleanup**: When a client abandons an upload without aborting or a process crashes, uncompleted uploads can persist. The project root provides `cleanup_multipart.php`, which delegates removal of uploads older than `MULTIPART_UPLOAD_TTL` (default 86400 seconds) to the selected `MultipartStorage` backend. FileStorage removes expired `.multipart/{uploadId}` directories. Run the script periodically via crontab; backends without multipart support have nothing to clean up.

## 5. Authentication and Authorization

Supports 2 authentication methods, dispatched uniformly by the auth module:

| Method | Trigger | Description |
| --- | --- | --- |
| AWS SigV4 (Header) | `Authorization: AWS4-HMAC-SHA256 ...` | Fully supported, including `SignedHeaders` / `x-amz-content-sha256` |
| Presigned URL (SigV4) | Query params contain `X-Amz-Credential` | Supports GET and PUT through the normal routing path; payload is `UNSIGNED-PAYLOAD`; `X-Amz-Expires` in [1, 604800]. Browser POST-policy uploads are not implemented |

> SigV2 and Bearer Token are deprecated and no longer supported.

General constraints:

- Timestamp skew upper bound is controlled by `MAX_TIMESTAMP_SKEW` config (default 300 seconds); exceeding it returns `ExpiredToken`.
- Bucket permissions: each access key can configure `allowed_buckets` (`*` means all).
- HEAD/GET signature fallback: when a signature does not match, the alternate method is tried, working around some web servers that forward HEAD as GET.

## 6. Request Size Limits

Uses a dual-layer check of global upper bound and per-key quota:

1. **Early check** (pre-auth): Compares the `Content-Length` header against the global upper bound, rejecting oversized requests before reading the body. For `aws-chunked` uploads the wire length includes framing/checksum overhead, so only `X-Amz-Decoded-Content-Length` counts when present; otherwise the decision defers to the spool.
2. **Per-key check** (post-auth): Cheaply rejects declared sizes above the key's limit, then applies the limit authoritatively inside the body spool: decoded bytes are counted while streaming and the read aborts as soon as the limit is exceeded. A forged `Content-Length` cannot hide an oversized body; framing overhead never counts against the object limit. Violations return `EntityTooLarge` (400).
3. **Multipart assembly check**: Validates the final file size before persisting during multipart assembly.

The global upper bound is controlled by `MAX_UPLOAD_SIZE` (default 8192 KiB / 8 MiB), constraining requests and parts. FileStorage also applies this limit to the completed multipart object; multipart uploads therefore do not bypass the configured final-object limit. The per-key `file_max_size` further constrains request bodies (unit: integer KiB).

Request bodies flow through `Http\BodySpool`: bytes move from `php://input` in blocks of at most 64 KiB into a disk-spilling temp stream (`php://temp`, past 2 MiB on disk), so the full body never becomes a PHP string. The same pass computes the payload SHA-256, decodes `aws-chunked` framing (selected by `Content-Encoding: aws-chunked` or any `STREAMING-*` `x-amz-content-sha256`), and enforces the size limit. HTTP `Transfer-Encoding: chunked` is not decoded: the SAPI hands PHP an already de-chunked body. Verification is armed by the Authenticator after the signature matched: a declared 64-hex `x-amz-content-sha256` is compared against the spooled bytes (`XAmzContentSHA256Mismatch` on mismatch); `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and `-TRAILER` uploads have their per-chunk signature chain (plus `x-amz-trailer-signature`) verified while reading (`SignatureDoesNotMatch`); `x-amz-checksum-*` trailers (CRC32, CRC32C, SHA1, SHA256; CRC64NVME is not supported and ignored) are validated against the decoded payload, and trailers announced in `x-amz-trailer` must be present; `UNSIGNED-PAYLOAD`/`STREAMING-UNSIGNED-PAYLOAD-TRAILER` decode framing only, matching S3 semantics. Other streaming modes (ECDSA) are rejected. When no `x-amz-content-sha256` is sent, the signature calculation spools the body under the claimed key's limit. Authentication itself never reads the body. `Request::getBodyStream()` hands the spooled, decoded stream to controllers; the Request owns and closes it. Peak PHP memory for a 256 MiB upload measures ~6 MiB under a 64 MiB limit.

## 7. Storage Layout

The following layout and path-validation rules belong to `FileStorage`. Alternative backends own their physical layout and enforce the same controller-facing operation contracts without exposing paths.

| Type | Path |
| --- | --- |
| Data root directory | `{project}/data/` (configurable via `DATA_DIR`, relative paths based on project root) |
| Bucket | `{dataDir}/{bucket}` |
| Object | `{dataDir}/{bucket}/{key}` (`/` in key maps to directory hierarchy) |
| Multipart Parts | `{dataDir}/{bucket}/.multipart/{uploadId}/{partNumber}` |
| List scan result cache | `{project}/tmp/listbuckets/{bucket}.json` (JSON array, each element `[key, size, mtime, etag]`) |

Conventions:

- `.multipart` is a reserved directory name; no segment of an Object key may be `.multipart`.
- Bucket name validation: 3-63 characters, lowercase letters/digits/`-`/`.`, starts and ends with alphanumeric, no consecutive `.`, not an IP address, no `xn--` prefix, not a Windows reserved device name.
- Key sanitization: length <= 1024; URL-decoded; empty / `.` / `..` segments discarded; control characters and Windows illegal characters (`: * ? " < > |`) rejected.
- `uploadId` validation: 32 hexadecimal characters, preventing path traversal.
- Atomic writes: Both whole uploads and multipart assembly write to a temporary file first, then atomically replace the target file; on failure, rollback does not corrupt the original object.

## 8. Metadata Strategy

The storage backend returns object metadata (`size`, `mtime`, `mime`, unquoted `etag`) and bucket creation timestamps. Controllers use these values rather than deriving them from paths. FileStorage obtains object metadata as follows:

| Field | Source |
| --- | --- |
| size | file size |
| mtime | file modification time (UTC output) |
| mime | inferred via MIME detection, falls back to `application/octet-stream` on failure |
| etag | content MD5, as in S3; multipart objects use S3's composite form `md5(concatenated binary part MD5s)-{part count}` |

> The MD5 is computed while the upload is written, so no extra disk read is needed, and stored in a sidecar file: `{DATA_DIR}/.meta/{bucket}/{key}.json` for objects, `{n}.meta.json` inside the upload directory for parts. Each sidecar records the inode, size and mtime of its file; a missing or stale sidecar (crash between write and record, files changed directly on disk, data from older versions) is repaired by hashing the file once. Clients such as rclone verify uploads against the ETag.

### 8.1 Stream ownership

- `putObjectFromStream` and `savePartFromStream` consume a readable input from its current position. The caller retains ownership and closes it. Success returns committed metadata; failure returns `null`.
- `openObject` returns a caller-owned readable stream positioned at the requested offset, or `false` on failure. It need not be seekable. The controller closes it after `Response::sendStream` sends at most the requested length in bounded chunks.
- FileStorage copies input to a temporary sibling file before renaming it into place, preserving the original object if copying fails.

### 8.2 Empty-object HEAD responses

Apache 2.4's HTTP header filter removes a literal `Content-Length: 0` on HEAD. To preserve the size needed by S3 clients, empty-object HEAD responses use the equivalent decimal value `00`, permitted by [RFC 9110 section 8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6). Nonempty HEAD responses and GET lengths are unchanged.

## 9. Error Handling

- All business exceptions carry an S3 error code, message, HTTP status code, and resource identifier.
- The response body is XML (`Content-Type: application/xml`), containing `Code` / `Message` / `Resource` / `RequestId` (random identifier).
- Error code list:

| S3 Code | HTTP | Trigger |
| --- | --- | --- |
| AccessDenied | 401 | Missing/invalid authentication |
| InvalidAccessKeyId | 403 | access key does not exist |
| SignatureDoesNotMatch | 403 | Signature validation failed |
| NoSuchBucket | 404 | bucket does not exist |
| NoSuchKey | 404 | object does not exist |
| NoSuchUpload | 404 | multipart uploadId does not exist |
| BucketAlreadyExists | 409 | createBucket conflict |
| BucketNotEmpty | 409 | deleteBucket on non-empty |
| InvalidBucketName | 400 | bucket name validation failed |
| InvalidRequest | 400 | Parameter error / `InvalidArgumentException` |
| MalformedXML | 400 | Request XML parsing failed |
| InvalidPart | 400 | Part file missing or ETag mismatch |
| InvalidRange | 416 | Range not satisfiable |
| EntityTooLarge | 400 | Exceeds `file_max_size` |
| ExpiredToken | 400 | Timestamp skew too large or presigned URL expired |
| MethodNotAllowed | 405 | Unsupported HTTP method |
| InternalError | 500 | Unexpected exception |
| NotImplemented | 501 | Multipart request against a backend without `MultipartStorage` |

## 10. Configuration

The default configuration file is `../config.ini` (parent directory of the project). The `S3_CONFIG` environment variable can select another configuration file, for example when `open_basedir` prevents access to the default location. Keep the file outside the public document root and set permission `600`. INI format is divided into a `general` section and several `keys.{accessKeyId}` sections.

**General configuration (`[general]`)**

| Key | Required | Default | Description |
| --- | --- | --- | --- |
| DATA_DIR | No | `{project}/data` | FileStorage data root; relative paths are based on the project root |
| STORAGE_CLASS | No | `S3Gateway\Storage\FileStorage` | Autoloadable class implementing `Storage`, with no required constructor arguments |
| APP_DEBUG | No | `false` | Enable debug logging |
| MAX_KEYS | No | `100000` | Maximum number of objects returned |
| MAX_TIMESTAMP_SKEW | No | `300` | Maximum timestamp skew in seconds |
| MAX_UPLOAD_SIZE | No | `8192` | Request/part size limit in KiB (8 MiB); FileStorage also checks the completed multipart object |
| MULTIPART_UPLOAD_TTL | No | `86400` | Multipart upload residual timeout in seconds; expired ones are deleted by the cleanup script |
| LIST_BUCKETS_CACHE_TIMEOUT | No | `60` | ListObjects result cache validity period, in seconds |
| TRUST_PROXY_HEADERS | No | `false` | Whether to trust X-Forwarded-* (enable behind a reverse proxy) |

**Per-key configuration (`[keys.{accessKeyId}]`)**

| Key | Required | Default | Description |
| --- | --- | --- | --- |
| secret_key | Yes | - | Secret key |
| allowed_buckets | No | `*` (no limit) | Allowed buckets, comma-separated |
| file_max_size | No | `0` (no limit) | Single file size limit, in integer KB |

## 11. Dependencies and Runtime Environment

- PHP >= 8.1
- `spatie/array-to-xml` ^3.4 -- XML response generation
- `symfony/filesystem` ^6.4 -- Path normalization (`Path` utility)
- Dev dependency: `phpunit/phpunit` ^11.0 (requires PHP >= 8.2)
- Entry point: `index.php`, recommended behind PHP-FPM / Apache + mod_php; if behind a reverse proxy, enable `TRUST_PROXY_HEADERS` as needed.
- Maintenance script: `cleanup_multipart.php` (project root), recommended to run periodically via crontab to clean up expired multipart upload residuals.

### 11.1 Testing

Install development dependencies and run the suite from the project root:

```sh
composer install
php vendor/bin/phpunit
```

Tests cover authentication, requests, controllers, XML, filesystem storage, backend metadata, stream ownership, and nonseekable downloads. They use temporary storage and require no live storage service. Verify webserver routing, TLS, signatures, range responses, and multipart operations separately against a dedicated HTTP deployment with an S3 client.

See [Storage backends](docs/STORAGE_BACKENDS.md) for implementation contracts.

## 12. Out of Scope

- ACL / Bucket Policy / IAM policies
- Versioning / Object Lock / Lifecycle
- Server-side encryption (SSE-S3 / SSE-KMS / SSE-C)
- Cross-region replication, transfer acceleration
- Browser POST-policy uploads (presigned GET and PUT are supported)
- Multipart upload extensions like `x-amz-server-side-encryption`, `x-amz-storage-class`
- Virtual host-style addressing (host-style bucket); only path-style is supported
- SigV2 and Bearer Token authentication (deprecated)

The current CORS configuration permits cross-origin requests but does not expose ETag to browser JavaScript through `Access-Control-Expose-Headers`. Cross-origin multipart clients need that header exposure before they can collect part ETags.
