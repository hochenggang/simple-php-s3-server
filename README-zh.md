# PHP S3 兼容网关

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![English](https://img.shields.io/badge/English-en-red)](./README.md)

一个轻量级的 PHP 实现的 S3 兼容对象存储服务器，使用本地文件系统作为存储后端。

## 功能特性

- S3 对象 API 兼容（PUT/GET/DELETE/HEAD）
- 分片上传支持（create/UploadPart/complete/abort）
- AWS Signature V4 签名认证
- 纯文件系统存储（无需数据库）
- 支持 `.env` 配置文件

## 快速开始

1. **上传到网站**

将所有文件上传到网站根目录。

2. **配置**

编辑 `.env` 文件：
```env
ALLOWED_ACCESS_KEYS=your-access-key1,your-access-key2
DEFAULT_SECRET_KEY=your-secret-key
```

3. **开始使用**

使用任何 S3 兼容客户端连接：

```python
import boto3

s3 = boto3.client(
    's3',
    endpoint_url='https://your-domain.com',
    aws_access_key_id='your-access-key1',
    aws_secret_access_key='your-secret-key',
    region_name='us-east-1',  # 可以填任意值
    verify=False
)

# 上传文件
s3.upload_file('local.txt', 'bucket', 'remote.txt')

# 下载文件
s3.download_file('bucket', 'remote.txt', 'local.txt')
```

## 配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `DATA_DIR` | 数据存储目录 | `./data` |
| `ALLOWED_ACCESS_KEYS` | 访问密钥（逗号分隔） | - |
| `DEFAULT_SECRET_KEY` | 密钥 | - |
| `MAX_REQUEST_SIZE` | 最大请求大小（字节） | `104857600` |
| `AUTH_DEBUG` | 启用调试日志 | `false` |

## 支持的操作

- 存储桶：列出、创建、删除
- 对象：上传、下载、获取元数据、删除、复制、列表
- 分片：创建、上传、完成、取消、列表

## 存储

对象存储在：`./data/{bucket}/{key}`

## 许可证

MIT
