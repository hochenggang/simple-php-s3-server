# Design Document v2

## 1. Core Objective

Implement a lightweight, S3-compatible API gateway based on the local filesystem (PHP 8.1+). Focus on core S3 operations, using folders as buckets and files as objects, without introducing a database or independent metadata storage.

## 2. Design Principles

- **Minimalism**: Explicitly excludes ACL, Versioning, Object Lock, Lifecycle, Server-Side Encryption, cross-region replication, and other non-core capabilities.
- **Filesystem as source of truth**: All metadata (size / mtime / mime / etag) is read in real time from the filesystem, with no independent metadata storage.
- **Error boundary convergence**: External responses return fixed S3 error codes and short messages; internal details are written only to logs.
- **Backward compatibility**: Does not break the existing data directory structure or configuration file format.
- **Modern PHP**: Uses PHP 8.1+, typed properties, readonly-style immutable requests/responses.

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
      File storage layer (path resolution + metadata reading)
                |
                v
      Local filesystem (data/)
```

Exception handling is unified in the routing layer: business exceptions are converted to the corresponding HTTP status code and XML error body; parameter validation exceptions are converted to `InvalidRequest`; other unexpected exceptions are converted to `InternalError` (500), with full stack traces recorded in logs.

## 4. Supported S3 Operations

### 4.1 Bucket

| Operation | Method | Path | Description |
| --- | --- | --- | --- |
| ListBuckets | GET | `/` | Lists all valid bucket subdirectories under the data directory |
| CreateBucket | PUT | `/{bucket}` | Creates a directory; returns `BucketAlreadyExists` (409) if it exists |
| DeleteBucket | DELETE | `/{bucket}` | Only empty buckets can be deleted (.multipart remnants are auto-cleaned); check and delete are non-atomic, concurrent races allowed |
| ListObjects (V1) | GET | `/{bucket}` | Supports `prefix` / `marker` / `max-keys` / `delimiter` / `encoding-type` |
| ListObjectsV2 | GET | `/{bucket}?list-type=2` | Supports `prefix` / `continuation-token` / `start-after` / `fetch-owner` / `delimiter` / `encoding-type` |

> The `max-keys` upper bound is controlled by the `MAX_KEYS` config (default 100000); `continuation-token` uses URL-safe base64(`lastKey`) encoding.

> **Result caching**: To alleviate disk pressure from full scans of large buckets, the complete scan result is cached at `./tmp/listbuckets/{bucket}.json`. The format is a JSON array where each element is a `[key, size, mtime, etag]` tuple (compact storage, avoiding field name redundancy). If the cache file exists and its age (judged by file mtime) is less than `LIST_BUCKETS_CACHE_TIMEOUT` (default 60 seconds), it is loaded directly and prefix filtering, delimiter grouping, and pagination are performed in memory; otherwise the filesystem is rescanned and the cache updated. Requests with pagination parameters (marker / continuation-token / max-keys / delimiter / prefix) also use the cache, reusing the same complete scan result. After writing/deleting objects, stale listings may be returned for up to the TTL (weak consistency).

> **Known limitation**: On a cache miss, the entire bucket directory is still recursively scanned, sorted, and paginated. Future optimizations based on pure filesystem characteristics: when prefix matches a real subdirectory, scan only that subdirectory (directory convergence); when using a delimiter, scan only up to that level (early truncation); use directory entry lexicographic order for in-directory binary search of the marker.

### 4.2 Object

| Operation | Method | Path | Description |
| --- | --- | --- | --- |
| PutObject | PUT | `/{bucket}/{key}` | Whole upload, body loaded into memory at once; files exceeding `MAX_UPLOAD_SIZE` must use Multipart |
| CopyObject | PUT | `/{bucket}/{key}` | Triggered via `X-Amz-Copy-Source` header, server-side copy |
| GetObject | GET | `/{bucket}/{key}` | Supports `Range: bytes=` single-range requests (206) |
| HeadObject | HEAD | `/{bucket}/{key}` | Returns size/content-type/etag/last-modified/accept-ranges |
| DeleteObject | DELETE | `/{bucket}/{key}` | Cleans up empty directories after deletion |
| DeleteObjects | POST | `/{bucket}?delete` | Batch delete, up to 1000 keys per request, XML request/response |

### 4.3 Multipart Upload

| Operation | Method | Path | Description |
| --- | --- | --- | --- |
| CreateMultipartUpload | POST | `/{bucket}/{key}?uploads` | Returns a 32-bit hex `uploadId` |
| UploadPart | PUT | `/{bucket}/{key}?partNumber=N&uploadId=ID` | partNumber in [1, 10000] |
| CompleteMultipartUpload | POST | `/{bucket}/{key}?uploadId=ID` | Validates each part ETag then atomically assembles |
| AbortMultipartUpload | DELETE | `/{bucket}/{key}?uploadId=ID` | Deletes the `.multipart/{uploadId}` directory |
| ListParts | GET | `/{bucket}/{key}?uploadId=ID` | Returns in ascending partNumber order |

> **Residual cleanup**: When a client abandons an upload without aborting or a process crashes, `.multipart/{uploadId}` remnants persist. The project root provides a `cleanup_multipart.php` script that cleans up part directories exceeding `MULTIPART_UPLOAD_TTL` (default 86400 seconds); it is recommended to run it periodically via crontab.

## 5. Authentication and Authorization

Supports 2 authentication methods, dispatched uniformly by the auth module:

| Method | Trigger | Description |
| --- | --- | --- |
| AWS SigV4 (Header) | `Authorization: AWS4-HMAC-SHA256 ...` | Fully supported, including `SignedHeaders` / `x-amz-content-sha256` |
| Presigned URL (SigV4) | Query params contain `X-Amz-Credential` | Partial support: GET objects only; payload is always `UNSIGNED-PAYLOAD`; `X-Amz-Expires` in [1, 604800] |

> SigV2 and Bearer Token are deprecated and no longer supported.

General constraints:

- Timestamp skew upper bound is controlled by `MAX_TIMESTAMP_SKEW` config (default 300 seconds); exceeding it returns `ExpiredToken`.
- Bucket permissions: each access key can configure `allowed_buckets` (`*` means all).
- HEAD/GET signature fallback: when a signature does not match, the alternate method is tried, working around some web servers that forward HEAD as GET.

## 6. Request Size Limits

Uses a dual-layer check of global upper bound and per-key quota:

1. **Early check** (pre-auth): Compares the `Content-Length` header against the global upper bound, rejecting oversized requests before reading the body.
2. **Per-key check** (post-auth): Takes the larger of the `Content-Length` header and the actual body length, preventing `Content-Length: 0` forgery; returns `EntityTooLarge` (400) on violation.
3. **Multipart assembly check**: Validates the final file size before persisting during multipart assembly.

The global upper bound is controlled by `MAX_UPLOAD_SIZE` config (default 8MB), constraining both single-request body and single-part size; whole-object uploads exceeding this limit should use Multipart instead. The per-key quota `file_max_size` can further tighten the limit on top of the global upper bound (unit: integer KB).

## 7. Storage Layout

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
- `uploadId` validation: 32-bit hex, preventing path traversal.
- Atomic writes: Both whole uploads and multipart assembly write to a temporary file first, then atomically replace the target file; on failure, rollback does not corrupt the original object.

## 8. Metadata Strategy

No independent metadata storage; all read in real time by the storage layer:

| Field | Source |
| --- | --- |
| size | file size |
| mtime | file modification time (UTC output) |
| mime | inferred via MIME detection, falls back to `application/octet-stream` on failure |
| etag | hash computed from key and size (not a content hash); multipart composite etag uses the same formula |

> The ETag computation differs from the AWS standard (not based on content MD5); this is a known compatibility trade-off to avoid reading the disk for hashing. Clients should not use ETag as a content integrity check.

## 9. Error Handling

- All business exceptions carry an S3 error code, message, HTTP status code, and resource identifier.
- The response body is XML (`Content-Type: application/xml`), containing `Code` / `Message` / `Resource` / `RequestId` (random identifier).
- Error code list:

| S3 Code | HTTP | Trigger |
| --- | --- | --- |
| AccessDenied | 401 | Missing/invalid authentication |
| InvalidAccessKeyId | 403 | access key does not exist |
| SignatureDoesNotMatch | 403 | Signature validation failed |
| NoSuchBucket | 404 | bucket directory does not exist |
| NoSuchKey | 404 | object file does not exist |
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

## 10. Configuration

The configuration file is located at `../config.ini` (parent directory of the project); file permission `600` should be set to prevent other users from reading secrets. INI format, divided into a `general` section and several `keys.{accessKeyId}` sections.

**General configuration (`[general]`)**

| Key | Required | Default | Description |
| --- | --- | --- | --- |
| DATA_DIR | No | `../data` | Data root directory, relative path based on project root |
| APP_DEBUG | No | `false` | Enable debug logging |
| MAX_KEYS | No | `100000` | Maximum number of objects returned |
| MAX_TIMESTAMP_SKEW | No | `300` | Maximum timestamp skew in seconds |
| MAX_UPLOAD_SIZE | No | `8192` | Single-request body and single-part size limit, in KB (default 8MB) |
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
- Dev dependency: `phpunit/phpunit` ^11.0
- Entry point: `index.php`, recommended behind PHP-FPM / Apache + mod_php; if behind a reverse proxy, enable `TRUST_PROXY_HEADERS` as needed.
- Maintenance script: `cleanup_multipart.php` (project root), recommended to run periodically via crontab to clean up expired multipart upload residuals.

## 12. Out of Scope

- ACL / Bucket Policy / IAM policies
- Versioning / Object Lock / Lifecycle
- Server-side encryption (SSE-S3 / SSE-KMS / SSE-C)
- Cross-region replication, transfer acceleration
- Full Presigned URL support (POST / PUT not supported)
- Multipart upload extensions like `x-amz-server-side-encryption`, `x-amz-storage-class`
- Content-level ETag (known trade-off differing from AWS standard)
- Virtual host-style addressing (host-style bucket); only path-style is supported
- SigV2 and Bearer Token authentication (deprecated)
