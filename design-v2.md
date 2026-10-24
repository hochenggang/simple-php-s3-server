# Design Document v2

## 1. 核心目标

实现一个轻量、S3 兼容的 API 网关（PHP 8.1+），存储后端可替换。默认的文件系统后端使用文件夹模拟 Bucket、文件模拟 Object，无需数据库与独立元数据存储。其他后端实现相同的 bucket、object 与元数据契约。

## 2. 设计原则

- **最小化**：明确排除 ACL、Versioning、Object Lock、Lifecycle、Server-Side Encryption、跨区域复制等非核心能力。
- **存储与元数据归后端所有**：控制器通过存储接口获取 size / mtime / mime / etag 与 bucket 时间戳。默认文件系统后端从文件系统读取元数据；内容 ETag 与客户端提供的元数据保存在小型旁路（sidecar）文件中。
- **错误边界收敛**：对外响应固定 S3 错误码与简短消息，内部细节仅写入日志。
- **保持兼容**：不破坏现有数据目录结构与配置文件格式。
- **现代 PHP**：使用 PHP 8.1+、类型化属性与显式的存储接口。

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
      存储接口（bucket/object 操作、元数据、流）
                │
                ▼
      所选后端（默认：FileStorage）
                │
                ▼
      后端自有存储（默认：本地文件系统）
```

异常处理统一在路由层：业务异常转为对应 HTTP 状态码与 XML 错误体；参数校验异常转为 `InvalidRequest`；其他未预期异常转为 `InternalError`（500），日志记录完整堆栈。

`StorageFactory` 按配置的 `STORAGE_CLASS` 选择后端，默认 `FileStorage`；应用也可以向 `Router` 注入 `Storage` 实例。控制器不访问后端路径或元数据辅助类。`MultipartStorage` 为可选扩展；后端未实现时，多段上传操作返回 `NotImplemented`（501）。

部署在子目录时，bucket/key 路由会去掉入口脚本 `SCRIPT_NAME` 所在目录，而签名校验保留完整请求 URI。下表中的客户端路径相对于 endpoint；目录形式的 endpoint 应在客户端配置中带结尾斜杠，以避免重定向。

## 4. 支持的 S3 操作

### 4.1 Bucket

| 操作 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| ListBuckets | GET | `/` | 列出后端的 bucket 及其创建时间；FileStorage 枚举合法的 bucket 目录 |
| CreateBucket | PUT | `/{bucket}` | 创建 bucket，已存在返回 `BucketAlreadyExists` (409) |
| DeleteBucket | DELETE | `/{bucket}` | 仅空 bucket 可删；FileStorage 同时清理 `.multipart` 残留，检查与删除非原子 |
| ListObjects (V1) | GET | `/{bucket}` | 支持 `prefix` / `marker` / `max-keys` / `delimiter` / `encoding-type` |
| ListObjectsV2 | GET | `/{bucket}?list-type=2` | 支持 `prefix` / `continuation-token` / `start-after` / `fetch-owner` / `delimiter` / `encoding-type` |

> `max-keys` 上限由 `MAX_KEYS` 配置（默认 100000）；`continuation-token` 采用 URL-safe base64(`lastKey`) 编码。

> **FileStorage 结果缓存**：为缓解大 bucket 全量扫描的磁盘压力，将完整扫描结果缓存于 `./tmp/listbuckets/{bucket}.json`。格式为 JSON 数组，每元素为 `[key, size, mtime, etag]` 四元组（紧凑存储，避免字段名冗余）。若缓存文件存在且年龄（按文件 mtime 判断）小于 `LIST_BUCKETS_CACHE_TIMEOUT`（默认 60 秒），直接载入并在内存中执行 prefix 过滤、delimiter 分组与分页；否则重新扫描文件系统并更新缓存。带分页参数（marker / continuation-token / max-keys / delimiter / prefix）的请求同样走缓存，复用同一份完整扫描结果。写入/删除对象后最多在 TTL 内可能返回旧列表（弱一致性）。

> **FileStorage 限制**：缓存未命中时仍递归扫描整个 bucket 目录后排序分页。后续可按纯文件系统特性进一步优化：prefix 命中真实子目录时直接进入该子目录扫描（目录收敛）；使用 delimiter 时只扫描到该层级（提前截断）；利用目录项字典序对 marker 做目录内二分定位。

### 4.2 Object

| 操作 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| PutObject | PUT | `/{bucket}/{key}` | 控制器向后端传递流；请求 body 在流式读取时以有界内存暂存，`MAX_UPLOAD_SIZE` 按解码后的字节计算 |
| CopyObject | PUT | `/{bucket}/{key}` | 通过 `X-Amz-Copy-Source` 头触发，服务端复制；`x-amz-metadata-directive` 为 `COPY`（默认）或 `REPLACE` |
| GetObject | GET | `/{bucket}/{key}` | 支持 `Range: bytes=` 单段范围请求（206） |
| HeadObject | HEAD | `/{bucket}/{key}` | 返回 size/content-type/etag/last-modified/accept-ranges 及 `x-amz-meta-*` 用户元数据 |
| DeleteObject | DELETE | `/{bucket}/{key}` | 删除由后端执行；FileStorage 同时清理空目录 |
| DeleteObjects | POST | `/{bucket}?delete` | 批量删除，单次上限 1000 key，XML 请求/响应 |

### 4.3 Multipart Upload

所选后端实现 `MultipartStorage` 时可用（`FileStorage` 已实现）。part 的物理存储与最终组装由后端负责。

| 操作 | 方法 | 路径 | 说明 |
| --- | --- | --- | --- |
| CreateMultipartUpload | POST | `/{bucket}/{key}?uploads` | 返回 32 个十六进制字符的 `uploadId` |
| UploadPart | PUT | `/{bucket}/{key}?partNumber=N&uploadId=ID` | partNumber ∈ [1, 10000] |
| CompleteMultipartUpload | POST | `/{bucket}/{key}?uploadId=ID` | 校验各 part ETag 后交由后端完成；FileStorage 原子组装 |
| AbortMultipartUpload | DELETE | `/{bucket}/{key}?uploadId=ID` | 中止上传；FileStorage 删除 `.multipart/{uploadId}` |
| ListParts | GET | `/{bucket}/{key}?uploadId=ID` | 按 partNumber 升序返回 |

> **残留清理**：客户端放弃未 abort 或进程崩溃时，未完成的上传会残留。项目根提供 `cleanup_multipart.php`，将超过 `MULTIPART_UPLOAD_TTL`（默认 86400 秒）的上传交由所选 `MultipartStorage` 后端清理。FileStorage 删除过期的 `.multipart/{uploadId}` 目录。建议通过 crontab 定期执行；不支持多段上传的后端无需清理。

## 5. 认证与授权

支持 2 种认证方式，由认证模块统一调度：

| 方式 | 触发条件 | 说明 |
| --- | --- | --- |
| AWS SigV4 (Header) | `Authorization: AWS4-HMAC-SHA256 ...` | 完整支持，含 `SignedHeaders` / `x-amz-content-sha256` |
| Presigned URL (SigV4) | 查询参数含 `X-Amz-Credential` | 通过常规路由支持 GET 与 PUT；payload 为 `UNSIGNED-PAYLOAD`；`X-Amz-Expires` ∈ [1, 604800]。不支持浏览器 POST policy 上传 |

> SigV2 与 Bearer Token 已弃用，不再支持。

通用约束：

- 时间偏移上限由 `MAX_TIMESTAMP_SKEW` 配置（默认 300 秒），超限返回 `ExpiredToken`。
- Bucket 权限：每个 access key 可配置 `allowed_buckets`（`*` 表示全部）。
- HEAD/GET 签名兼容回退：当签名不匹配时尝试另一种方法，规避部分 Web 服务器把 HEAD 转发为 GET 的行为。

## 6. 请求大小限制

采用全局上限与按键配额双层检查：

1. **早期检查**（认证前）：基于 `Content-Length` 头与全局上限比较，拒绝超大请求，避免读 body。对于 `aws-chunked` 上传，传输长度包含分帧与校验和开销，因此仅在存在 `X-Amz-Decoded-Content-Length` 时以其为准；否则交由暂存阶段判断。
2. **Per-key 检查**（认证后）：先以较低成本拒绝声明大小超过该 key 上限的请求，再在 body 暂存过程中权威地应用上限：流式读取时统计解码后的字节数，一旦超限立即中止读取。伪造的 `Content-Length` 无法隐藏超大的 body；分帧开销不计入对象上限。超限返回 `EntityTooLarge` (400)。
3. **Multipart 组装检查**：多段上传组装时在落盘前校验最终文件大小。

全局上限由 `MAX_UPLOAD_SIZE` 配置（默认 8192 KiB / 8 MiB），约束请求与分片大小。FileStorage 同样对合并后的多段对象应用该上限，因此多段上传无法绕过最终对象限制。按键配额 `file_max_size` 进一步约束请求 body（单位整数 KiB）。

请求 body 经由 `Http\BodySpool` 处理：数据以至多 64 KiB 的块从 `php://input` 写入可溢出到磁盘的临时流（`php://temp`，超过 2 MiB 写入磁盘），完整 body 从不成为 PHP 字符串。同一遍处理中计算 payload 的 SHA-256、解码 `aws-chunked` 分帧（由 `Content-Encoding: aws-chunked` 或任意 `STREAMING-*` 形式的 `x-amz-content-sha256` 触发），并执行大小限制。HTTP `Transfer-Encoding: chunked` 不做解码：SAPI 交给 PHP 的 body 已去除分块。签名匹配后由 Authenticator 启用校验：声明的 64 位十六进制 `x-amz-content-sha256` 与暂存的字节比对（不一致返回 `XAmzContentSHA256Mismatch`）；`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` 及 `-TRAILER` 上传在读取时校验逐块签名链（以及 `x-amz-trailer-signature`）（失败返回 `SignatureDoesNotMatch`）；`x-amz-checksum-*` trailer（CRC32、CRC32C、SHA1、SHA256；CRC64NVME 不支持，予以忽略）按解码后的 payload 校验，`x-amz-trailer` 中声明的 trailer 必须出现；`UNSIGNED-PAYLOAD` / `STREAMING-UNSIGNED-PAYLOAD-TRAILER` 仅解码分帧，与 S3 语义一致。其他流式模式（ECDSA）予以拒绝。未发送 `x-amz-content-sha256` 时，签名计算在所声明 key 的上限下暂存 body。认证本身从不读取 body。`Request::getBodyStream()` 将暂存并解码后的流交给控制器；该流由 Request 持有并负责关闭。在 64 MiB 内存上限下，256 MiB 上传的 PHP 内存峰值实测约 6 MiB。

## 7. 存储布局

以下布局与路径校验规则属于 `FileStorage`。其他后端自行决定物理布局，在不暴露路径的前提下遵守相同的面向控制器的操作契约。

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
- `uploadId` 校验：32 个十六进制字符，防止路径遍历。
- 原子写入：整体上传与多段组装均先写入临时文件再原子替换目标文件，失败回滚不污染原对象。

## 8. 元数据策略

存储后端返回对象元数据（`size`、`mtime`、`mime`、不带引号的 `etag`）与 bucket 创建时间。控制器使用这些值，而非从路径推导。FileStorage 按如下方式获取对象元数据：

| 字段 | 来源 |
| --- | --- |
| size | 读取文件大小 |
| mtime | 读取文件修改时间（UTC 输出） |
| mime | 上传时给定的 `Content-Type`；否则通过 MIME 检测推断，失败回退 `application/octet-stream` |
| metadata | 上传时（PutObject、CreateMultipartUpload）或 CopyObject 使用 `REPLACE` 时给定的 `x-amz-meta-*` 用户元数据 |
| etag | 内容 MD5（与 S3 一致）；多段上传对象使用 S3 的复合格式 `md5(各 part 二进制 MD5 拼接)-{part 数}` |

> MD5 在写入上传内容时同步计算，无需额外读盘，并保存在旁路文件中：对象为 `{DATA_DIR}/.meta/{bucket}/{key}.json`，part 为上传目录内的 `{n}.meta.json`。旁路文件记录对应文件的 inode、大小与 mtime；若缺失或过期（写入与记录之间崩溃、直接在磁盘上修改、旧版本数据），则对文件计算一次哈希进行修复；其客户端元数据无法恢复，予以丢弃。rclone 等客户端会依据 ETag 校验上传结果。

> 用户元数据遵循 S3：名称以小写存储，值保持不变，名称与值的总大小上限为 2 KB（`MetadataTooLarge`）。GET 与 HEAD 以 `x-amz-meta-*` 头返回。CopyObject 复制源对象的 Content-Type 与元数据，或在 `x-amz-metadata-directive: REPLACE` 时取自请求。将对象复制到自身需要 `REPLACE`，且只修改元数据；rclone 以此保存修改时间。PHP 通过 CGI 变量提供请求头，因此元数据名称中的 `-` 与 `_` 无法区分，名称统一以 `-` 表示。

### 8.1 流的所有权

- `putObjectFromStream` 与 `savePartFromStream` 从当前位置读取可读输入流，调用方保留所有权并负责关闭。成功返回已提交的元数据，失败返回 `null`。
- `openObject` 返回定位到请求偏移处、由调用方持有的可读流，失败返回 `false`，无需可 seek。控制器在 `Response::sendStream` 以有界分块发送至多请求长度的数据后关闭它。
- FileStorage 先将输入复制到同目录的临时文件再重命名就位，复制失败时原对象保持不变。

### 8.2 空对象的 HEAD 响应

Apache 2.4 的 HTTP 头过滤器会在 HEAD 请求中删除字面值 `Content-Length: 0`。为保留 S3 客户端所需的大小信息，空对象的 HEAD 响应使用等价的十进制值 `00`，这是 [RFC 9110 第 8.6 节](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6) 所允许的。非空对象的 HEAD 响应与 GET 的长度不变。

## 9. 错误处理

- 所有业务异常携带 S3 错误码、消息、HTTP 状态码与资源标识。
- 响应体为 XML（`Content-Type: application/xml`），包含 `Code` / `Message` / `Resource` / `RequestId`（随机标识）。
- 错误码清单：

| S3 Code | HTTP | 触发场景 |
| --- | --- | --- |
| AccessDenied | 401 | 缺失/无效认证 |
| InvalidAccessKeyId | 403 | access key 不存在 |
| SignatureDoesNotMatch | 403 | 签名校验失败 |
| NoSuchBucket | 404 | bucket 不存在 |
| NoSuchKey | 404 | object 不存在 |
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
| MetadataTooLarge | 400 | 用户元数据超过 2 KB |
| InvalidArgument | 400 | 未知的 `x-amz-metadata-directive` |
| InternalError | 500 | 未预期异常 |
| NotImplemented | 501 | 后端未实现 `MultipartStorage` 时的多段上传请求 |

## 10. 配置

默认配置文件为 `../config.ini`（项目上级目录）。可通过环境变量 `S3_CONFIG` 指定其他配置文件，例如 `open_basedir` 禁止访问默认位置时。配置文件应置于公开文档根目录之外，并设置权限 `600`。INI 格式，分 `general` 与若干 `keys.{accessKeyId}` section。

**通用配置（`[general]`）**

| 配置项 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| DATA_DIR | 否 | `{project}/data` | FileStorage 数据根目录，相对路径基于项目根 |
| STORAGE_CLASS | 否 | `S3Gateway\Storage\FileStorage` | 实现 `Storage` 的可自动加载类，构造函数不得有必填参数 |
| APP_DEBUG | 否 | `false` | 是否开启调试日志 |
| MAX_KEYS | 否 | `100000` | 最大返回对象数 |
| MAX_TIMESTAMP_SKEW | 否 | `300` | 时间偏移最大秒数 |
| MAX_UPLOAD_SIZE | 否 | `8192` | 请求与分片大小上限，单位 KiB（8 MiB）；FileStorage 同时校验合并后的多段对象 |
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
- 开发依赖：`phpunit/phpunit` ^11.0（需要 PHP ≥ 8.2）
- 入口：`index.php`，建议置于 PHP-FPM / Apache + mod_php 之后；如置于反向代理后，按需开启 `TRUST_PROXY_HEADERS`。
- 维护脚本：`cleanup_multipart.php`（项目根），建议通过 crontab 定期执行，清理超时的分片上传残留。

### 11.1 测试

在项目根安装开发依赖并运行测试：

```sh
composer install
php vendor/bin/phpunit
```

测试覆盖认证、请求、控制器、XML、文件系统存储、后端元数据、流的所有权与不可 seek 的下载。测试使用临时存储，无需真实存储服务。Web 服务器路由、TLS、签名、范围响应与多段上传操作应另行使用 S3 客户端对专用 HTTP 部署进行验证。

实现契约见 [存储后端](docs/STORAGE_BACKENDS.md)。

## 12. 明确不做（Out of Scope）

- ACL / Bucket Policy / IAM 策略
- Versioning / Object Lock / Lifecycle
- 服务端加密（SSE-S3 / SSE-KMS / SSE-C）
- 跨区域复制、传输加速
- 浏览器 POST policy 上传（支持预签名 GET 与 PUT）
- 多段上传的 `x-amz-server-side-encryption`、`x-amz-storage-class` 等扩展头
- 虚拟主机风格寻址（host-style bucket），仅支持 path-style
- SigV2 与 Bearer Token 认证（已弃用）

当前 CORS 配置允许跨域请求，但未通过 `Access-Control-Expose-Headers` 向浏览器 JavaScript 暴露 ETag。跨域的多段上传客户端需要该头的暴露才能获取各 part 的 ETag。
