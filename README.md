# PHP S3 Compatible Gateway

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87-zh-red)](./README-zh.md)

A lightweight S3-compatible object storage server implemented in PHP, using local filesystem as storage backend.

## Features

- S3 Object API compatibility (PUT/GET/DELETE/HEAD)
- Multipart upload support (create/UploadPart/complete/abort)
- AWS Signature V4 authentication (SigV2 / Bearer Token deprecated)
- Pure filesystem storage (no database required)
- Per-key upload size limits (integer KB)
- Per-key bucket access control
- ListObjects result caching for large buckets
- CORS preflight support

## Design Document

See [design-v2.en.md](./design-v2.en.md) for the full design specification.

## Quick Start

1. **Upload to your web server**

Upload all files to your website root directory.

2. **Configure**

Create `../config.ini` (parent directory of the project, set permission `600`). If a legacy `.config.ini` exists in the project root, it is automatically migrated on first run:
```ini
[general]
DATA_DIR=../data
APP_DEBUG=false

[keys.key1]
secret_key=your-secret-key1
allowed_buckets=bucket1,bucket2
file_max_size=10240

[keys.key2]
secret_key=your-secret-key2
allowed_buckets=bucket3

[keys.admin_key]
secret_key=admin-secret-key
```

3. **Start using**

Connect using any S3-compatible client:

```python
import boto3

s3 = boto3.client(
    's3',
    endpoint_url='https://your-domain.com',
    aws_access_key_id='key1',
    aws_secret_access_key='your-secret-key1',
    region_name='us-east-1',  # Can be any value
    verify=True
)

# Upload file
s3.upload_file('local.txt', 'bucket', 'remote.txt')

# Download file
s3.download_file('bucket', 'remote.txt', 'local.txt')
```

## Configuration

The configuration is stored in `../config.ini` (INI format), located in the parent directory of the project to avoid web exposure. Set file permission `600`.

**General (`[general]`)**

| Variable | Description | Default |
|----------|-------------|---------|
| `DATA_DIR` | Data storage directory | `../data` |
| `APP_DEBUG` | Application debug mode | `false` |
| `MAX_KEYS` | Max objects returned per listing | `100000` |
| `MAX_TIMESTAMP_SKEW` | Max auth timestamp skew (seconds) | `300` |
| `MAX_UPLOAD_SIZE` | Single-request/part size limit (KB) | `8192` (8MB) |
| `MULTIPART_UPLOAD_TTL` | Multipart residual timeout (seconds) | `86400` |
| `LIST_BUCKETS_CACHE_TIMEOUT` | ListObjects cache TTL (seconds) | `60` |
| `TRUST_PROXY_HEADERS` | Trust X-Forwarded-* headers | `false` |

Do not put `DATA_DIR` in the same directory as the gateway files. It is recommended to put it in a parent directory to avoid exposing the storage directory.

### Access Keys Configuration

Access keys are configured with the `keys.{access_key_id}` section format:

```ini
[keys.my_access_key]
secret_key=your-secret-key
allowed_buckets=bucket1,bucket2
file_max_size=10240
```

| Field | Required | Description |
|-------|----------|-------------|
| `secret_key` | Yes | The secret key for authentication |
| `allowed_buckets` | No | Comma-separated list of buckets, or `*` for all (default: `*`) |
| `file_max_size` | No | Max upload size in KB, unset means no limit |

## Supported Operations

- Bucket: List, Create, Delete
- Object: Put, Get, Head, Delete, Copy, List
- Multipart: Create, UploadPart, Complete, Abort, ListParts

## Storage

Objects are stored at: `DATA_DIR/{bucket}/{key}`

## Maintenance

Run `php cleanup_multipart.php` periodically (e.g. via crontab) to clean up abandoned multipart upload remnants:

```
0 3 * * * /usr/bin/php /path/to/simple-php-s3-server/cleanup_multipart.php
```

## Known Limitations

### MinIO Client Not Supported

This gateway does **not** support MinIO client of Python. It inserts line breaks (`\n`) in the `Authorization` header, which violates HTTP specifications:

```
Authorization: AWS4-HMAC-SHA256 Credential=key/date/\n /s3/aws4_request, ...
```

This causes Apache to fail parsing the request. LiteSpeed handles this correctly. Nginx has not been tested.

Please use AWS CLI, boto3, or other standard S3 clients instead.

## License

MIT
