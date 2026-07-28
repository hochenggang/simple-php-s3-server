#!/usr/bin/env python3
"""
full_test.py — PHP S3 兼容网关全 API 实测脚本

自动完成：
  1. 生成临时 config.ini（上级目录）
  2. 启动 PHP 内置服务器
  3. 用 boto3 逐一测试 Bucket / Object / Multipart 全部 API（含错误路径）
  4. 输出彩色通过/失败报告
  5. 无论成功失败，退出时清理临时数据与配置

也可指向已运行的服务器：
  S3GW_ENDPOINT=http://localhost:8080 python full_test.py

依赖：boto3
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError
    from botocore.config import Config as BotoConfig
except ImportError:
    print("缺少 boto3 依赖，请执行: pip install boto3")
    sys.exit(1)

# ─── 配置 ────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent
ACCESS_KEY_ID = "test-full-access-key"
SECRET_KEY = "test-full-secret-key"
REGION = "us-east-1"

# 测试用数据
TEST_BUCKET_PREFIX = "full-test-bucket"
TEST_OBJECT_KEY = "test-object.txt"
TEST_OBJECT_CONTENT = b"Hello, S3 Gateway Full Test! " * 10
TEST_COPY_KEY = "copied-object.txt"
TEST_MULTIPART_KEY = "multipart-object.bin"
PART_DATA_1 = b"A" * (1024 * 100)  # 100 KB
PART_DATA_2 = b"B" * (1024 * 100)  # 100 KB

# ─── 颜色输出 ────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

_passed = 0
_failed = 0


def ok(msg):
    global _passed
    _passed += 1
    print(f"  {GREEN}[PASS]{RESET} {msg}")


def fail(msg, detail=""):
    global _failed
    _failed += 1
    print(f"  {RED}[FAIL]{RESET} {msg}")
    if detail:
        print(f"         {detail}")


def section(title):
    print(f"\n{CYAN}━━ {title} ━━{RESET}")


# ─── 服务器管理 ──────────────────────────────────────────────────────

class ServerManager:
    """管理 PHP 内置服务器的启动与清理。"""

    def __init__(self):
        self.endpoint = os.environ.get("S3GW_ENDPOINT")
        self.proc = None
        self.tmp_data_dir = None
        self.config_path = None
        self.owns_server = False  # 标记是否由本脚本启动了服务器
        self.had_existing_config = False

        if self.endpoint:
            # 外部服务器模式，不做启动/清理
            return

        self.tmp_data_dir = tempfile.mkdtemp(prefix="s3gateway_test_data_")
        # config.ini 必须在项目上级目录
        self.config_path = PROJECT_ROOT.parent / "config.ini"

    def start(self):
        """启动 PHP 服务器，返回 endpoint URL。"""
        if self.endpoint:
            print(f"使用外部服务器: {self.endpoint}")
            return self.endpoint

        # 写入临时 config.ini
        config_content = f"""[general]
DATA_DIR={self.tmp_data_dir}
APP_DEBUG=false
MAX_UPLOAD_SIZE=102400
LIST_BUCKETS_CACHE_TIMEOUT=0

[keys.{ACCESS_KEY_ID}]
secret_key={SECRET_KEY}
allowed_buckets=*
"""
        # 如果已有 config.ini，备份它
        if self.config_path.exists():
            backup = self.config_path.with_suffix(".ini.bak")
            shutil.copy2(self.config_path, backup)
            self.had_existing_config = True
        self.config_path.write_text(config_content, encoding="utf-8")
        print(f"临时配置写入: {self.config_path}")
        print(f"临时数据目录: {self.tmp_data_dir}")

        # 启动 PHP 内置服务器
        port = self._find_free_port()
        self.endpoint = f"http://127.0.0.1:{port}"
        print(f"启动 PHP 服务器: {self.endpoint}")

        self.proc = subprocess.Popen(
            ["php", "-S", f"127.0.0.1:{port}", "-t", str(PROJECT_ROOT), "index.php"],
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # Windows 下需要用 creationflags 隐藏窗口
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        self.owns_server = True

        # 等待服务器就绪
        self._wait_ready()
        return self.endpoint

    def stop(self):
        """停止服务器并清理临时文件。"""
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            print("PHP 服务器已停止")

        if self.tmp_data_dir and os.path.exists(self.tmp_data_dir):
            shutil.rmtree(self.tmp_data_dir, ignore_errors=True)
            print(f"临时数据目录已清理: {self.tmp_data_dir}")

        if self.owns_server and self.config_path:
            # 只在自启动模式下清理配置
            if self.had_existing_config:
                # 恢复原配置
                backup = self.config_path.with_suffix(".ini.bak")
                if backup.exists():
                    shutil.move(str(backup), str(self.config_path))
                    print(f"原配置已恢复: {self.config_path}")
            else:
                # 删除临时配置
                if self.config_path.exists():
                    self.config_path.unlink()
                    print(f"临时配置已删除: {self.config_path}")

    @staticmethod
    def _find_free_port():
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _wait_ready(self, timeout=10):
        """轮询服务器直到响应或超时。"""
        import urllib.request
        import urllib.error
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                req = urllib.request.Request(self.endpoint, method="GET")
                urllib.request.urlopen(req, timeout=2)
                # 200 响应（不太可能，但算就绪）
                return
            except urllib.error.HTTPError:
                # 任何 HTTP 错误码（403/404 等）说明服务器已就绪
                return
            except (urllib.error.URLError, ConnectionError, OSError):
                # 连接被拒绝 → 服务器还没启动，继续等
                time.sleep(0.2)
        raise RuntimeError(f"服务器在 {timeout}s 内未就绪")


# ─── 测试用例 ────────────────────────────────────────────────────────

def make_client(endpoint):
    """创建 boto3 S3 客户端。"""
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=ACCESS_KEY_ID,
        aws_secret_access_key=SECRET_KEY,
        region_name=REGION,
        config=BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 0},
        ),
    )


def test_bucket_operations(s3, bucket_name):
    """测试 Bucket 相关 API。"""
    section("Bucket 操作")

    # 1. 创建 Bucket
    try:
        s3.create_bucket(Bucket=bucket_name)
        ok(f"create_bucket({bucket_name})")
    except Exception as e:
        fail(f"create_bucket({bucket_name})", str(e))
        return False

    # 2. 重复创建 → BucketAlreadyExists
    try:
        s3.create_bucket(Bucket=bucket_name)
        fail("create_bucket 重复创建应报错")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("BucketAlreadyExists", "BucketAlreadyOwnedByYou"):
            ok("create_bucket 重复创建正确返回 409")
        else:
            fail("create_bucket 重复创建错误码不匹配", f"got {code}")

    # 3. 列出 Bucket，应包含刚创建的
    try:
        resp = s3.list_buckets()
        names = [b["Name"] for b in resp["Buckets"]]
        if bucket_name in names:
            ok("list_buckets 包含新建 bucket")
        else:
            fail("list_buckets 未包含新建 bucket", str(names))
    except Exception as e:
        fail("list_buckets", str(e))

    # 4. 删除非空 Bucket → BucketNotEmpty
    # 先放一个对象
    try:
        s3.put_object(Bucket=bucket_name, Key="blocker.txt", Body=b"x")
        s3.delete_bucket(Bucket=bucket_name)
        fail("delete_bucket 非空 bucket 应报错")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "BucketNotEmpty":
            ok("delete_bucket 非空 bucket 正确返回 409")
        else:
            fail("delete_bucket 非空 bucket 错误码不匹配", f"got {code}")

    # 清理 blocker
    s3.delete_object(Bucket=bucket_name, Key="blocker.txt")

    return True


def test_object_operations(s3, bucket_name):
    """测试 Object 相关 API。"""
    section("Object 操作")

    # 1. PUT 对象
    try:
        resp = s3.put_object(Bucket=bucket_name, Key=TEST_OBJECT_KEY, Body=TEST_OBJECT_CONTENT)
        etag = resp.get("ETag", "").strip('"')
        if etag:
            ok(f"put_object({TEST_OBJECT_KEY})  etag={etag}")
        else:
            fail("put_object 缺少 ETag")
    except Exception as e:
        fail("put_object", str(e))
        return

    # 2. GET 对象
    try:
        resp = s3.get_object(Bucket=bucket_name, Key=TEST_OBJECT_KEY)
        body = resp["Body"].read()
        if body == TEST_OBJECT_CONTENT:
            ok("get_object 内容一致")
        else:
            fail("get_object 内容不一致", f"len={len(body)} expected={len(TEST_OBJECT_CONTENT)}")
    except Exception as e:
        fail("get_object", str(e))

    # 3. HEAD 对象
    try:
        resp = s3.head_object(Bucket=bucket_name, Key=TEST_OBJECT_KEY)
        if resp["ContentLength"] == len(TEST_OBJECT_CONTENT):
            ok(f"head_object ContentLength={resp['ContentLength']}")
        else:
            fail("head_object ContentLength 不匹配", str(resp.get("ContentLength")))
    except Exception as e:
        fail("head_object", str(e))

    # 4. GET 不存在的对象 → NoSuchKey
    try:
        s3.get_object(Bucket=bucket_name, Key="no-such-key.txt")
        fail("get_object 不存在的 key 应报错")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchKey":
            ok("get_object 不存在 key 正确返回 404")
        else:
            fail("get_object 不存在 key 错误码不匹配", f"got {code}")

    # 5. HEAD 不存在的对象 → 404
    try:
        s3.head_object(Bucket=bucket_name, Key="no-such-key.txt")
        fail("head_object 不存在的 key 应报错")
    except ClientError as e:
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        if status == 404:
            ok("head_object 不存在 key 正确返回 404")
        else:
            fail("head_object 不存在 key 状态码不匹配", f"got {status}")

    # 6. Copy 对象
    try:
        s3.copy_object(
            Bucket=bucket_name,
            Key=TEST_COPY_KEY,
            CopySource={"Bucket": bucket_name, "Key": TEST_OBJECT_KEY},
        )
        # 验证副本内容
        resp = s3.get_object(Bucket=bucket_name, Key=TEST_COPY_KEY)
        if resp["Body"].read() == TEST_OBJECT_CONTENT:
            ok(f"copy_object({TEST_COPY_KEY}) 内容一致")
        else:
            fail("copy_object 副本内容不一致")
    except Exception as e:
        fail("copy_object", str(e))

    # 7. Copy 不存在的源 → NoSuchKey
    try:
        s3.copy_object(
            Bucket=bucket_name,
            Key="fail-copy.txt",
            CopySource={"Bucket": bucket_name, "Key": "no-such-source.txt"},
        )
        fail("copy_object 不存在源应报错")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchKey", "NoSuchBucket"):
            ok("copy_object 不存在源正确返回错误")
        else:
            fail("copy_object 不存在源错误码不匹配", f"got {code}")

    # 8. Range GET
    try:
        resp = s3.get_object(Bucket=bucket_name, Key=TEST_OBJECT_KEY, Range="bytes=0-9")
        body = resp["Body"].read()
        if body == TEST_OBJECT_CONTENT[:10]:
            ok(f"get_object Range bytes=0-9  返回 {len(body)} 字节")
        else:
            fail("get_object Range 内容不匹配")
    except Exception as e:
        fail("get_object Range", str(e))

    # 9. DELETE 对象
    try:
        s3.delete_object(Bucket=bucket_name, Key=TEST_COPY_KEY)
        ok("delete_object 成功")
    except Exception as e:
        fail("delete_object", str(e))

    # 10. DELETE 不存在的对象（S3 语义：幂等，返回 204）
    try:
        s3.delete_object(Bucket=bucket_name, Key="already-deleted.txt")
        ok("delete_object 不存在 key 幂等成功")
    except Exception as e:
        fail("delete_object 不存在 key 应幂等", str(e))


def test_list_objects(s3, bucket_name):
    """测试 ListObjects V1/V2。"""
    section("ListObjects")

    # 准备多个对象
    keys = ["list/a.txt", "list/b.txt", "list/c.txt", "list/d.txt", "other.txt"]
    for k in keys:
        s3.put_object(Bucket=bucket_name, Key=k, Body=k.encode())

    # 1. ListObjectsV2 基本列举
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name)
        returned = sorted(obj["Key"] for obj in resp.get("Contents", []))
        # 包含之前创建的 TEST_OBJECT_KEY
        if "list/a.txt" in returned and "other.txt" in returned:
            ok(f"list_objects_v2 返回 {len(returned)} 个对象")
        else:
            fail("list_objects_v2 结果不完整", str(returned))
    except Exception as e:
        fail("list_objects_v2", str(e))

    # 2. ListObjectsV2 prefix 过滤
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name, Prefix="list/")
        returned = [obj["Key"] for obj in resp.get("Contents", [])]
        if len(returned) == 4 and all(k.startswith("list/") for k in returned):
            ok(f"list_objects_v2 prefix='list/' 返回 {len(returned)} 个")
        else:
            fail("list_objects_v2 prefix 过滤不正确", str(returned))
    except Exception as e:
        fail("list_objects_v2 prefix", str(e))

    # 3. ListObjectsV2 分页 (max-keys=2)
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=2)
        if resp.get("IsTruncated") and len(resp.get("Contents", [])) == 2:
            next_token = resp.get("NextContinuationToken")
            # 续页
            resp2 = s3.list_objects_v2(
                Bucket=bucket_name, MaxKeys=2, ContinuationToken=next_token
            )
            total = len(resp["Contents"]) + len(resp2.get("Contents", []))
            ok(f"list_objects_v2 分页：page1={len(resp['Contents'])} page2={len(resp2.get('Contents', []))}")
        else:
            fail("list_objects_v2 分页未截断", str(resp.get("IsTruncated")))
    except Exception as e:
        fail("list_objects_v2 分页", str(e))

    # 4. ListObjectsV2 delimiter
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name, Delimiter="/")
        prefixes = [p["Prefix"] for p in resp.get("CommonPrefixes", [])]
        if "list/" in prefixes:
            ok(f"list_objects_v2 delimiter='/'  common_prefixes={prefixes}")
        else:
            fail("list_objects_v2 delimiter 未分组", str(prefixes))
    except Exception as e:
        fail("list_objects_v2 delimiter", str(e))

    # 5. ListObjects V1
    try:
        resp = s3.list_objects(Bucket=bucket_name, Prefix="list/")
        returned = [obj["Key"] for obj in resp.get("Contents", [])]
        if len(returned) == 4:
            ok(f"list_objects (V1) prefix='list/' 返回 {len(returned)} 个")
        else:
            fail("list_objects V1 结果不完整", str(returned))
    except Exception as e:
        fail("list_objects V1", str(e))

    # 清理
    for k in keys:
        s3.delete_object(Bucket=bucket_name, Key=k)


def test_multipart_upload(s3, bucket_name):
    """测试分片上传全流程。"""
    section("Multipart Upload")

    # 1. 创建分片上传
    try:
        resp = s3.create_multipart_upload(Bucket=bucket_name, Key=TEST_MULTIPART_KEY)
        upload_id = resp["UploadId"]
        ok(f"create_multipart_upload  upload_id={upload_id[:12]}...")
    except Exception as e:
        fail("create_multipart_upload", str(e))
        return

    # 2. 上传分片
    parts = []
    try:
        for i, data in enumerate([PART_DATA_1, PART_DATA_2], 1):
            resp = s3.upload_part(
                Bucket=bucket_name,
                Key=TEST_MULTIPART_KEY,
                PartNumber=i,
                UploadId=upload_id,
                Body=data,
            )
            parts.append({"PartNumber": i, "ETag": resp["ETag"]})
        ok(f"upload_part x2  parts={[p['PartNumber'] for p in parts]}")
    except Exception as e:
        fail("upload_part", str(e))
        # 清理未完成的分片
        s3.abort_multipart_upload(Bucket=bucket_name, Key=TEST_MULTIPART_KEY, UploadId=upload_id)
        return

    # 3. ListParts
    try:
        resp = s3.list_parts(Bucket=bucket_name, Key=TEST_MULTIPART_KEY, UploadId=upload_id)
        listed_parts = resp.get("Parts", [])
        if len(listed_parts) == 2:
            ok(f"list_parts 返回 {len(listed_parts)} 个分片")
        else:
            fail("list_parts 数量不匹配", f"got {len(listed_parts)}")
    except Exception as e:
        fail("list_parts", str(e))

    # 4. 完成分片上传
    try:
        resp = s3.complete_multipart_upload(
            Bucket=bucket_name,
            Key=TEST_MULTIPART_KEY,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )
        ok(f"complete_multipart_upload  etag={resp.get('ETag', '')}")
    except Exception as e:
        fail("complete_multipart_upload", str(e))
        return

    # 5. 验证合并后的对象
    try:
        resp = s3.get_object(Bucket=bucket_name, Key=TEST_MULTIPART_KEY)
        body = resp["Body"].read()
        expected = PART_DATA_1 + PART_DATA_2
        if body == expected:
            ok(f"get_object(multipart) 内容一致  size={len(body)}")
        else:
            fail("get_object(multipart) 内容不一致", f"got {len(body)} expected {len(expected)}")
    except Exception as e:
        fail("get_object(multipart)", str(e))

    # 6. Abort multipart upload
    # 创建一个新的分片上传然后取消
    try:
        resp = s3.create_multipart_upload(Bucket=bucket_name, Key="abort-test.bin")
        abort_id = resp["UploadId"]
        s3.upload_part(
            Bucket=bucket_name,
            Key="abort-test.bin",
            PartNumber=1,
            UploadId=abort_id,
            Body=b"partial data",
        )
        s3.abort_multipart_upload(Bucket=bucket_name, Key="abort-test.bin", UploadId=abort_id)
        ok("abort_multipart_upload 成功")
    except Exception as e:
        fail("abort_multipart_upload", str(e))


def test_delete_batch(s3, bucket_name):
    """测试批量删除 (DeleteObjects)。"""
    section("DeleteObjects")

    # 准备多个对象
    keys = ["batch/a.txt", "batch/b.txt", "batch/c.txt"]
    for k in keys:
        s3.put_object(Bucket=bucket_name, Key=k, Body=b"x")

    # 批量删除
    try:
        resp = s3.delete_objects(
            Bucket=bucket_name,
            Delete={
                "Objects": [{"Key": k} for k in keys],
                "Quiet": False,
            },
        )
        deleted = resp.get("Deleted", [])
        if len(deleted) == 3:
            ok(f"delete_objects 删除 {len(deleted)} 个对象")
        else:
            fail("delete_objects 数量不匹配", str(resp))
    except Exception as e:
        fail("delete_objects", str(e))

    # 验证确实删了
    try:
        resp = s3.list_objects_v2(Bucket=bucket_name, Prefix="batch/")
        if len(resp.get("Contents", [])) == 0:
            ok("delete_objects 验证已删除")
        else:
            fail("delete_objects 后仍存在对象")
    except Exception as e:
        fail("delete_objects 验证", str(e))


def test_error_cases(s3):
    """测试错误路径。"""
    section("错误路径")

    # 1. 操作不存在的 bucket
    try:
        s3.list_objects_v2(Bucket="no-such-bucket-xyz")
        fail("list_objects_v2 不存在 bucket 应报错")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchBucket":
            ok("list_objects_v2 不存在 bucket 正确返回 404")
        else:
            fail("list_objects_v2 不存在 bucket 错误码", f"got {code}")

    # 2. 向不存在的 bucket PUT 对象
    try:
        s3.put_object(Bucket="no-such-bucket-xyz", Key="test.txt", Body=b"data")
        fail("put_object 不存在 bucket 应报错")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchBucket":
            ok("put_object 不存在 bucket 正确返回 404")
        else:
            fail("put_object 不存在 bucket 错误码", f"got {code}")

    # 3. 删除不存在的 bucket
    try:
        s3.delete_bucket(Bucket="no-such-bucket-xyz")
        fail("delete_bucket 不存在 bucket 应报错")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchBucket":
            ok("delete_bucket 不存在 bucket 正确返回 404")
        else:
            fail("delete_bucket 不存在 bucket 错误码", f"got {code}")

    # 4. 无效认证
    bad_client = boto3.client(
        "s3",
        endpoint_url=s3.meta.endpoint_url,
        aws_access_key_id="invalid-key",
        aws_secret_access_key="invalid-secret",
        region_name=REGION,
        config=BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 0},
        ),
    )
    try:
        bad_client.list_buckets()
        fail("无效凭证应被拒绝")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "InvalidAccessKeyId"):
            ok("无效凭证正确返回 401/403")
        else:
            fail("无效凭证错误码不匹配", f"got {code}")

    # 5. OPTIONS 预检
    try:
        import urllib.request
        req = urllib.request.Request(s3.meta.endpoint_url, method="OPTIONS")
        resp = urllib.request.urlopen(req, timeout=5)
        cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        if cors_origin == "*":
            ok("OPTIONS 预检返回 200 + CORS *")
        else:
            fail("OPTIONS 预检 CORS 头缺失", f"origin={cors_origin}")
    except Exception as e:
        fail("OPTIONS 预检", str(e))


def test_presigned_url(s3, bucket_name):
    """测试预签名 URL。"""
    section("Presigned URL")

    # 先放一个对象
    s3.put_object(Bucket=bucket_name, Key="presigned.txt", Body=b"presigned content")

    # 生成预签名 URL 并用 requests 下载
    try:
        url = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket_name, "Key": "presigned.txt"},
            ExpiresIn=60,
        )

        import urllib.request
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read()
        if body == b"presigned content":
            ok("presigned URL 下载成功")
        else:
            fail("presigned URL 内容不匹配")
    except Exception as e:
        fail("presigned URL", str(e))

    # 清理
    s3.delete_object(Bucket=bucket_name, Key="presigned.txt")


def main():
    print(f"{CYAN}╔══════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║   PHP S3 Gateway — 全 API 实测脚本      ║{RESET}")
    print(f"{CYAN}╚══════════════════════════════════════════╝{RESET}")

    manager = ServerManager()
    endpoint = None

    try:
        endpoint = manager.start()
        s3 = make_client(endpoint)

        # 生成唯一 bucket 名
        bucket_name = f"{TEST_BUCKET_PREFIX}-{int(time.time())}"

        # 运行所有测试
        if test_bucket_operations(s3, bucket_name):
            test_object_operations(s3, bucket_name)
            test_list_objects(s3, bucket_name)
            test_multipart_upload(s3, bucket_name)
            test_delete_batch(s3, bucket_name)
            test_presigned_url(s3, bucket_name)
            test_error_cases(s3)

            # 清理：删除测试 bucket 中的所有对象，然后删除 bucket
            section("清理")
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket_name):
                    for obj in page.get("Contents", []):
                        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
                s3.delete_bucket(Bucket=bucket_name)
                ok(f"测试 bucket 已删除: {bucket_name}")
            except Exception as e:
                fail("清理 bucket 失败", str(e))

    except Exception as e:
        fail("测试执行异常", str(e))
        import traceback
        traceback.print_exc()
    finally:
        manager.stop()

    # 汇总
    print(f"\n{CYAN}━━ 测试汇总 ━━{RESET}")
    total = _passed + _failed
    print(f"  总计: {total}  通过: {GREEN}{_passed}{RESET}  失败: {RED}{_failed}{RESET}")
    if _failed == 0:
        print(f"  {GREEN}✓ 全部通过{RESET}")
        sys.exit(0)
    else:
        print(f"  {RED}✗ 存在失败{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
