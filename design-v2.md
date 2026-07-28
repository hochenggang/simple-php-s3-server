# Design Document v2

## 1. 核心目标

基于本地文件系统实现一个轻量、S3 兼容的 API 网关（PHP 8.1+）。聚焦核心 S3 操作，使用文件夹模拟 Bucket、文件模拟 Object，不引入数据库与独立元数据存储。

## 2. 设计原则

- **最小化**：明确排除 ACL、Versioning、Object Lock、Lifecycle、Server-Side Encryption、跨区域复制等非核心能力。
- **文件系统即真源**：所有元数据（size / mtime / mime / etag）从文件系统实时读取，无独立元数据存储。
- **错误边界收敛**：对外响应固定 S3 错误码与简短消息，内部细节仅写入日志。
- **保持兼容**：不破坏现有数据目录结构与配置文件格式。
- **现代 PHP**：使用 PHP 8.1+，类型化属性、只读风格的不可变请求/响应。

## 3. 架构总览

请求生命周期（单一入口）：

```
HTTP 请求
   │
   ▼
入口脚本  ── 设置错误处理 / 时区(UTC) / 加载依赖
   │
   ▼
路由分发
   │
   ├─ 1. OPTIONS 预检 → 直接 200（允许所有主机跨域）
   ├─ 2. 早期请求大小检查  （基于 Content-Length 头拒绝超大请求）
   ├─ 3. 认证               （返回 accessKeyId）
   ├─ 4. 按键级配额校验      （取 header 与 body 长度的较大值）
   └─ 5. 分发 → 按 方法 / bucket / key / 查询参数 路由到控制器
                │
                ▼
      Bucket / Object / Multipart 控制器
                │
                ▼
      文件存储层（路径解析 + 元数据读取）
                │
                ▼
      本地文件系统（data/）
```

异常处理统一在路由层：业务异常转为对应 HTTP 状态码与 XML 错误体；参数校验异常转为 `InvalidRequest`；其他未预期异常转为 `InternalError`（500），日志记录完整堆栈。

## 4. 支持的 S3 操作

### 4.1 Bucket

| 操作 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| ListBuckets | GET | `/` | 列出 data 目录下所有合法 bucket 子目录 |
| CreateBucket | PUT | `/{bucket}` | 创建目录，已存在返回 `BucketAlreadyExists` (409) |
| DeleteBucket | DELETE | `/{bucket}` | 仅空 bucket 可删（含 `.multipart` 残留时自动清理）；检查与删除非原子，允许并发竞态 |
| ListObjects (V1) | GET | `/{bucket}` | 支持 `prefix` / `marker` / `max-keys` / `delimiter` / `encoding-type` |
| ListObjectsV2 | GET | `/{bucket}?list-type=2` | 支持 `prefix` / `continuation-token` / `start-after` / `fetch-owner` / `delimiter` / `encoding-type` |

> `max-keys` 上限由 `MAX_KEYS` 配置（默认 100000）；`continuation-token` 采用 URL-safe base64(`lastKey`) 编码。

> **结果缓存**：为缓解大 bucket 全量扫描的磁盘压力，将完整扫描结果缓存于 `./tmp/listbuckets/{bucket}.json`。格式为 JSON 数组，每元素为 `[key, size, mtime, etag]` 四元组（紧凑存储，避免字段名冗余）。若缓存文件存在且年龄（按文件 mtime 判断）小于 `LIST_BUCKETS_CACHE_TIMEOUT`（默认 60 秒），直接载入并在内存中执行 prefix 过滤、delimiter 分组与分页；否则重新扫描文件系统并更新缓存。带分页参数（marker / continuation-token / max-keys / delimiter / prefix）的请求同样走缓存，复用同一份完整扫描结果。写入/删除对象后最多在 TTL 内可能返回旧列表（弱一致性）。

> **已知限制**：缓存未命中时仍递归扫描整个 bucket 目录后排序分页。后续可按纯文件系统特性进一步优化：prefix 命中真实子目录时直接进入该子目录扫描（目录收敛）；使用 delimiter 时只扫描到该层级（提前截断）；利用目录项字典序对 marker 做目录内二分定位。

### 4.2 Object

| 操作 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| PutObject | PUT | `/{bucket}/{key}` | 整体上传，body 一次性载入内存；超过 `MAX_UPLOAD_SIZE` 的大文件必须走 Multipart |
| CopyObject | PUT | `/{bucket}/{key}` | 通过 `X-Amz-Copy-Source` 头触发，服务端复制 |
| GetObject | GET | `/{bucket}/{key}` | 支持 `Range: bytes=` 单段范围请求（206） |
| HeadObject | HEAD | `/{bucket}/{key}` | 返回 size/content-type/etag/last-modified/accept-ranges |
| DeleteObject | DELETE | `/{bucket}/{key}` | 删除后清理空目录 |
| DeleteObjects | POST | `/{bucket}?delete` | 批量删除，单次上限 1000 key，XML 请求/响应 |

### 4.3 Multipart Upload

| 操作 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| CreateMultipartUpload | POST | `/{bucket}/{key}?uploads` | 返回 32 位 hex `uploadId` |
| UploadPart | PUT | `/{bucket}/{key}?partNumber=N&uploadId=ID` | partNumber ∈ [1, 10000] |
| CompleteMultipartUpload | POST | `/{bucket}/{key}?uploadId=ID` | 校验各 part ETag 后原子组装 |
| AbortMultipartUpload | DELETE | `/{bucket}/{key}?uploadId=ID` | 删除 `.multipart/{uploadId}` 目录 |
| ListParts | GET | `/{bucket}/{key}?uploadId=ID` | 按 partNumber 升序返回 |

> **残留清理**：客户端放弃未 abort 或进程崩溃时，`.multipart/{uploadId}` 会残留。项目根提供 `cleanup_multipart.php` 脚本，清理超过 `MULTIPART_UPLOAD_TTL`（默认 86400 秒）的分片目录，建议通过 crontab 定期执行。

## 5. 认证与授权

支持 2 种认证方式，由认证模块统一调度：

| 方式 | 触发条件 | 说明 |
| --- | --- | --- |
| AWS SigV4 (Header) | `Authorization: AWS4-HMAC-SHA256 ...` | 完整支持，含 `SignedHeaders` / `x-amz-content-sha256` |
| Presigned URL (SigV4) | 查询参数含 `X-Amz-Credential` | 部分支持：仅 GET 对象；payload 固定为 `UNSIGNED-PAYLOAD`；`X-Amz-Expires` ∈ [1, 604800] |

> SigV2 与 Bearer Token 已弃用，不再支持。

通用约束：

- 时间偏移上限由 `MAX_TIMESTAMP_SKEW` 配置（默认 300 秒），超限返回 `ExpiredToken`。
- Bucket 权限：每个 access key 可配置 `allowed_buckets`（`*` 表示全部）。
- HEAD/GET 签名兼容回退：当签名不匹配时尝试另一种方法，规避部分 Web 服务器把 HEAD 转发为 GET 的行为。

## 6. 请求大小限制

采用全局上限与按键配额双层检查：

1. **早期检查**（认证前）：基于 `Content-Length` 头与全局上限比较，拒绝超大请求，避免读 body。
2. **Per-key 检查**（认证后）：取 `Content-Length` 头与 body 实际长度的较大值，防止 `Content-Length: 0` 伪造；命中则返回 `EntityTooLarge` (400)。
3. **Multipart 组装检查**：多段上传组装时在落盘前校验最终文件大小。

全局上限由 `MAX_UPLOAD_SIZE` 配置（默认 8MB），同时约束单次请求 body 与单个分片大小；超过该上限的整对象上传应改用 Multipart。按键配额 `file_max_size` 可在全局上限之上进一步收紧（单位整数 KB）。

## 7. 存储布局

| 类型 | 路径 |
| --- | --- |
| 数据根目录 | `{project}/data/` （可由 `DATA_DIR` 配置，相对路径基于项目根） |
| Bucket | `{dataDir}/{bucket}` |
| Object | `{dataDir}/{bucket}/{key}` （key 中的 `/` 映射为目录层级） |
| Multipart Parts | `{dataDir}/{bucket}/.multipart/{uploadId}/{partNumber}` |
| List 扫描结果缓存 | `{project}/tmp/listbuckets/{bucket}.json`（JSON 数组，每元素 `[key, size, mtime, etag]`） |

约定：

- `.multipart` 为保留目录名，Object key 的任意段不得为 `.multipart`。
- Bucket 名校验：3-63 字符、小写字母/数字/`-`/`.`、首尾为字母数字、不含连续 `.`、非 IP 地址、非 `xn--` 前缀、非 Windows 保留设备名。
- Key 清洗：长度 ≤ 1024；URL 解码；丢弃空 / `.` / `..` 段；拒绝控制字符与 Windows 非法字符（`: * ? " < > |`）。
- `uploadId` 校验：32 位 hex，防止路径遍历。
- 原子写入：整体上传与多段组装均先写入临时文件再原子替换目标文件，失败回滚不污染原对象。

## 8. 元数据策略

无独立元数据存储，全部由存储层实时读取：

| 字段 | 来源 |
| --- | --- |
| size | 读取文件大小 |
| mtime | 读取文件修改时间（UTC 输出） |
| mime | 通过 MIME 检测推断，失败回退 `application/octet-stream` |
| etag | 基于 key 与 size 计算的哈希（非内容哈希）；多段上传的 composite etag 同样基于此公式 |

> ETag 计算方式与 AWS 标准不同（不基于内容 MD5），属于已知的兼容性取舍，旨在避免读盘计算哈希。客户端不应将 ETag 作为内容校验依据。

## 9. 错误处理

- 所有业务异常携带 S3 错误码、消息、HTTP 状态码与资源标识。
- 响应体为 XML（`Content-Type: application/xml`），包含 `Code` / `Message` / `Resource` / `RequestId`（随机标识）。
- 错误码清单：

| S3 Code | HTTP | 触发场景 |
| --- | --- | --- |
| AccessDenied | 401 | 缺失/无效认证 |
| InvalidAccessKeyId | 403 | access key 不存在 |
| SignatureDoesNotMatch | 403 | 签名校验失败 |
| NoSuchBucket | 404 | bucket 目录不存在 |
| NoSuchKey | 404 | object 文件不存在 |
| NoSuchUpload | 404 | multipart uploadId 不存在 |
| BucketAlreadyExists | 409 | createBucket 冲突 |
| BucketNotEmpty | 409 | deleteBucket 时非空 |
| InvalidBucketName | 400 | bucket 名校验失败 |
| InvalidRequest | 400 | 参数错误 / `InvalidArgumentException` |
| MalformedXML | 400 | 请求 XML 解析失败 |
| InvalidPart | 400 | part 文件缺失或 ETag 不匹配 |
| InvalidRange | 416 | Range 不可满足 |
| EntityTooLarge | 400 | 超出 `file_max_size` |
| ExpiredToken | 400 | 时间偏移过大或 presigned URL 过期 |
| MethodNotAllowed | 405 | 不支持的 HTTP 方法 |
| InternalError | 500 | 未预期异常 |

## 10. 配置

配置文件位于 `../config.ini`（项目上级目录），应设置文件权限 `600` 防止其他用户读取密钥。INI 格式，分 `general` 与若干 `keys.{accessKeyId}` section。

**通用配置（`[general]`）**

| 配置项 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| DATA_DIR | 否 | `../data` | 数据根目录，相对路径基于项目根 |
| APP_DEBUG | 否 | `false` | 是否开启调试日志 |
| MAX_KEYS | 否 | `100000` | 最大返回对象数 |
| MAX_TIMESTAMP_SKEW | 否 | `300` | 时间偏移最大秒数 |
| MAX_UPLOAD_SIZE | 否 | `8192` | 单次请求 body 与单分片大小上限，单位 KB（默认 8MB） |
| MULTIPART_UPLOAD_TTL | 否 | `86400` | 分片上传残留超时秒数，超时由清理脚本删除 |
| LIST_BUCKETS_CACHE_TIMEOUT | 否 | `60` | ListObjects 结果缓存有效期，单位秒 |
| TRUST_PROXY_HEADERS | 否 | `false` | 是否信任 X-Forwarded-*（反向代理后开启） |

**按键配置（`[keys.{accessKeyId}]`）**

| 配置项 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| secret_key | 是 | - | 密钥 |
| allowed_buckets | 否 | `*`（不限制） | 允许访问的 bucket，逗号分隔 |
| file_max_size | 否 | `0`（不限制） | 单文件大小上限，单位整数 KB |

## 11. 依赖与运行环境

- PHP ≥ 8.1
- `spatie/array-to-xml` ^3.4 —— XML 响应生成
- `symfony/filesystem` ^6.4 —— 路径规范化（`Path` 工具类）
- 开发依赖：`phpunit/phpunit` ^11.0
- 入口：`index.php`，建议置于 PHP-FPM / Apache + mod_php 之后；如置于反向代理后，按需开启 `TRUST_PROXY_HEADERS`。
- 维护脚本：`cleanup_multipart.php`（项目根），建议通过 crontab 定期执行，清理超时的分片上传残留。

## 12. 明确不做（Out of Scope）

- ACL / Bucket Policy / IAM 策略
- Versioning / Object Lock / Lifecycle
- 服务端加密（SSE-S3 / SSE-KMS / SSE-C）
- 跨区域复制、传输加速
- 完整的 Presigned URL（POST / PUT 不支持）
- 多段上传的 `x-amz-server-side-encryption`、`x-amz-storage-class` 等扩展头
- 对象内容级 ETag（与 AWS 标准不同的已知取舍）
- 虚拟主机风格寻址（host-style bucket），仅支持 path-style
- SigV2 与 Bearer Token 认证（已弃用）
