# PHP S3 兼容网关

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![English](https://img.shields.io/badge/English-en-red)](./README.md)

一个轻量级的 PHP 实现的 S3 兼容对象存储服务器，使用本地文件系统作为存储后端。

## 功能特性

- S3 对象 API 兼容（PUT/GET/DELETE/HEAD）
- 分片上传支持（create/UploadPart/complete/abort）
- AWS Signature V4 签名认证
- 纯文件系统存储（无需数据库）
- 支持按密钥限制上传大小（KB）
- 支持按密钥限制存储桶访问


## 快速开始

1. **上传到网站**

将所有文件上传到网站根目录。

2. **配置**

编辑 `.config.ini` 文件：
```ini
; Access Keys configuration
; Format: [keys.{access_key_id}]

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

3. **开始使用**

使用任何 S3 兼容客户端连接：

```python
import boto3

s3 = boto3.client(
    's3',
    endpoint_url='https://your-domain.com',
    aws_access_key_id='key1',
    aws_secret_access_key='your-secret-key1',
    region_name='us-east-1',  # 可以填任意值
    verify=True
)

# 上传文件
s3.upload_file('local.txt', 'bucket', 'remote.txt')

# 下载文件
s3.download_file('bucket', 'remote.txt', 'local.txt')
```

## 配置

配置存储在 `.config.ini` 文件中，使用 INI 格式：

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `DATA_DIR` | 数据存储目录 | `../data` |
| `APP_DEBUG` | 应用调试模式 | `false` |

**注意**：`DATA_DIR` 目录**不能**与网关文件在同一目录下。建议将其放在父目录下，避免暴露存储目录。

### 访问密钥配置

访问密钥使用 `keys.{access_key_id}` 格式配置：

```ini
[keys.my_access_key]
secret_key=your-secret-key
allowed_buckets=bucket1,bucket2
file_max_size=10240
```

| 字段 | 必填 | 说明 |
|------|------|------|
| `secret_key` | 是 | 认证密钥 |
| `allowed_buckets` | 否 | 可访问的存储桶列表（逗号分隔），或 `*` 表示所有（默认：`*`） |
| `file_max_size` | 否 | 最大上传大小（单位 KB），未设置则不限制 |

## 支持的操作

- 存储桶：列出、创建、删除
- 对象：上传、下载、获取元数据、删除、复制、列表
- 分片：创建、上传、完成、取消、列表

## 存储

对象存储在：`../data/{bucket}/{key}`

## 已知限制

### 不支持 MinIO 客户端

本网关**不支持 Python 版本** MinIO 客户端。其会在 `Authorization` 头中插入换行符（`\n`），这违反了 HTTP 规范：

```
Authorization: AWS4-HMAC-SHA256 Credential=key/date/\n /s3/aws4_request, ...
```

这会导致 Apache 无法正常解析请求。LiteSpeed 可以正常处理。Nginx 未测试。

请使用 AWS CLI、boto3 或其他标准 S3 客户端。

## 许可证

MIT
