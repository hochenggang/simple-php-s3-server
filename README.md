# PHP S3 Compatible Gateway

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87-zh-red)](./README-zh.md)

A lightweight S3-compatible object storage server implemented in PHP, using local filesystem as storage backend.

## Features

- S3 Object API compatibility (PUT/GET/DELETE/HEAD)
- Multipart upload support (create/UploadPart/complete/abort)
- AWS Signature V4 authentication
- Pure filesystem storage (no database required)
- Configuration via `.env` file

## Quick Start

1. **Upload to your web server**

Upload all files to your website root directory.

2. **Configure**

Edit `.env` file:
```env
ALLOWED_ACCESS_KEYS=your-access-key1,your-access-key2
DEFAULT_SECRET_KEY=your-secret-key
```

3. **Start using**

Connect using any S3-compatible client:

```python
import boto3

s3 = boto3.client(
    's3',
    endpoint_url='https://your-domain.com',
    aws_access_key_id='your-access-key1',
    aws_secret_access_key='your-secret-key',
    region_name='us-east-1',  # Can be any value
    verify=True
)

# Upload file
s3.upload_file('local.txt', 'bucket', 'remote.txt')

# Download file
s3.download_file('bucket', 'remote.txt', 'local.txt')
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DATA_DIR` | Data storage directory | `./data` |
| `ALLOWED_ACCESS_KEYS` | Access keys (comma-separated) | - |
| `DEFAULT_SECRET_KEY` | Secret key | - |
| `MAX_REQUEST_SIZE` | Max request size (bytes) | `104857600` |
| `AUTH_DEBUG` | Enable debug logging | `false` |

## Supported Operations

- Bucket: List, Create, Delete
- Object: Put, Get, Head, Delete, Copy, List
- Multipart: Create, UploadPart, Complete, Abort, ListParts

## Storage

Objects are stored at: `./data/{bucket}/{key}`

## License

MIT
