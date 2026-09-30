"""S3 (REST-XML プロトコル)。パス形式・仮想ホスト形式の両方に対応。"""
from __future__ import annotations

import base64
import json
import hashlib
import os
import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from typing import Any
from urllib.parse import unquote
from xml.sax.saxutils import escape

from ..core import ACCOUNT_ID, AwsError, Metric, Request, Response, Service
from ..iam_policy import parse_document

NS = "http://s3.amazonaws.com/doc/2006-03-01/"
BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
HOST_SUFFIX = "." + os.environ.get("AWSEMU_HOSTNAME", "localhost")
SIGNATURE_PARAMS = {"AWSAccessKeyId", "Signature", "Expires"}
UNSUPPORTED_SUBRESOURCES = {
    "acl", "tagging", "cors", "lifecycle", "website", "notification",
    "encryption", "replication", "logging", "object-lock", "ownershipControls",
    "publicAccessBlock", "intelligent-tiering", "inventory", "analytics",
    "accelerate", "requestPayment", "restore", "select", "torrent", "legal-hold", "retention",
    "versions",
}


@dataclass
class S3Object:
    data: bytes
    etag: str
    last_modified: float
    content_type: str = "binary/octet-stream"
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class Upload:
    key: str
    initiated: float
    content_type: str
    metadata: dict[str, str]
    parts: dict[int, tuple[bytes, str]] = field(default_factory=dict)


@dataclass
class Bucket:
    name: str
    region: str
    created: float
    objects: dict[str, S3Object] = field(default_factory=dict)
    uploads: dict[str, Upload] = field(default_factory=dict)
    policy: str | None = None
    metrics_configs: dict[str, str] = field(default_factory=dict)   # id -> プレフィックスフィルタ ("" は全体)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def http_date(ts: float) -> str:
    return formatdate(ts, usegmt=True)


def xml_doc(root: str, inner: str) -> bytes:
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<{root} xmlns="{NS}">{inner}</{root}>'.encode()


def tag(name: str, value: Any) -> str:
    if isinstance(value, bool):
        value = "true" if value else "false"
    return f"<{name}>{escape(str(value))}</{name}>"


def decode_aws_chunked(body: bytes) -> tuple[bytes, dict[str, str]]:
    """aws-chunked エンコード (署名付き/トレーラ付き) をデコードする。"""
    out = bytearray()
    trailers: dict[str, str] = {}
    pos = 0
    while True:
        eol = body.index(b"\r\n", pos)
        size = int(body[pos:eol].split(b";", 1)[0], 16)
        pos = eol + 2
        if size == 0:
            break
        out += body[pos:pos + size]
        pos += size + 2
    for line in body[pos:].split(b"\r\n"):
        if b":" in line:
            k, v = line.decode().split(":", 1)
            trailers[k.strip().lower()] = v.strip()
    return bytes(out), trailers


def children(elem: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in elem if c.tag.split("}")[-1] == name]


def child_text(elem: ET.Element, name: str) -> str | None:
    found = children(elem, name)
    return found[0].text if found else None


OP_ACTIONS = {
    "ListBuckets": "s3:ListAllMyBuckets", "HeadBucket": "s3:ListBucket", "ListObjects": "s3:ListBucket",
    "ListObjectsV2": "s3:ListBucket", "HeadObject": "s3:GetObject", "CreateMultipartUpload": "s3:PutObject",
    "UploadPart": "s3:PutObject", "CompleteMultipartUpload": "s3:PutObject", "ListParts": "s3:ListMultipartUploadParts",
    "ListMultipartUploads": "s3:ListBucketMultipartUploads", "DeleteObjects": "s3:DeleteObject",
    "PutBucketMetricsConfiguration": "s3:PutMetricsConfiguration",
    "GetBucketMetricsConfiguration": "s3:GetMetricsConfiguration",
    "DeleteBucketMetricsConfiguration": "s3:PutMetricsConfiguration",
    "ListBucketMetricsConfigurations": "s3:GetMetricsConfiguration",
}
OBJECT_OPS = {"PutObject", "GetObject", "HeadObject", "DeleteObject", "CopyObject", "CreateMultipartUpload",
              "UploadPart", "CompleteMultipartUpload", "AbortMultipartUpload", "ListParts"}
DATA_EVENTS = OBJECT_OPS | {"DeleteObjects", "ListObjects", "ListObjectsV2", "ListMultipartUploads"}
REQUEST_KIND = {"GET": "GetRequests", "PUT": "PutRequests", "DELETE": "DeleteRequests", "HEAD": "HeadRequests",
                "POST": "PostRequests"}


class S3(Service):
    name = "s3"
    iam_prefix = "s3"
    event_source = "s3.amazonaws.com"
    data_events = frozenset(DATA_EVENTS)
    invalid_token_code = "InvalidAccessKeyId"
    invalid_token_message = "The AWS Access Key Id you provided does not exist in our records."
    expired_token_status = 400

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self.buckets: dict[str, Bucket] = {}

    # ------------------------------------------------------------------ routing
    def _locate(self, req: Request) -> tuple[str | None, str | None]:
        host = (req.header("Host") or "").split(":")[0]
        if host.endswith(HOST_SUFFIX) and host != HOST_SUFFIX[1:]:
            bucket = host[: -len(HOST_SUFFIX)]
            key = req.path.lstrip("/")
            return bucket, (unquote(key) if key else None)
        parts = req.path.lstrip("/").split("/", 1)
        bucket = unquote(parts[0]) or None
        key = unquote(parts[1]) if len(parts) > 1 and parts[1] else None
        return bucket, key

    def operation(self, req: Request) -> str:
        bucket, key = self._locate(req)
        q, m = req.query, req.method
        if bucket is None:
            return "ListBuckets" if m == "GET" else "Unknown"
        if UNSUPPORTED_SUBRESOURCES & q.keys():
            return "Unsupported"
        if key is None:
            if "policy" in q:
                return {"PUT": "PutBucketPolicy", "GET": "GetBucketPolicy", "DELETE": "DeleteBucketPolicy"}.get(m, "Unknown")
            if "metrics" in q:
                if m == "GET" and "id" not in q:
                    return "ListBucketMetricsConfigurations"
                return {"PUT": "PutBucketMetricsConfiguration", "GET": "GetBucketMetricsConfiguration",
                        "DELETE": "DeleteBucketMetricsConfiguration"}.get(m, "Unknown")
            if m == "PUT":
                return "PutBucketVersioning" if "versioning" in q else "CreateBucket"
            if m == "DELETE":
                return "DeleteBucket"
            if m == "HEAD":
                return "HeadBucket"
            if m == "POST" and "delete" in q:
                return "DeleteObjects"
            if m == "GET":
                if "location" in q:
                    return "GetBucketLocation"
                if "versioning" in q:
                    return "GetBucketVersioning"
                if "uploads" in q:
                    return "ListMultipartUploads"
                return "ListObjectsV2" if q.get("list-type") == "2" else "ListObjects"
            return "Unknown"
        if m == "PUT":
            if "uploadId" in q:
                return "UploadPart"
            return "CopyObject" if req.header("x-amz-copy-source") else "PutObject"
        if m == "GET":
            return "ListParts" if "uploadId" in q else "GetObject"
        if m == "HEAD":
            return "HeadObject"
        if m == "DELETE":
            return "AbortMultipartUpload" if "uploadId" in q else "DeleteObject"
        if m == "POST":
            if "uploads" in q:
                return "CreateMultipartUpload"
            if "uploadId" in q:
                return "CompleteMultipartUpload"
        return "Unknown"

    def resource(self, req: Request, op: str) -> str:
        bucket, key = self._locate(req)
        return "/".join(p for p in (bucket, key) if p)

    # ------------------------------------------------------------------ IAM / CloudTrail / メトリクス
    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        bucket, key = self._locate(req)
        action = OP_ACTIONS.get(op, f"s3:{op}")
        if op == "ListBuckets":
            return [(action, "*")]
        if op == "CopyObject":
            source = unquote(req.header("x-amz-copy-source") or "").split("?", 1)[0].lstrip("/")
            return [("s3:GetObject", f"arn:aws:s3:::{source}"), ("s3:PutObject", f"arn:aws:s3:::{bucket}/{key}")]
        if op == "DeleteObjects":
            try:
                root = ET.fromstring(self._payload(req))
                keys = [child_text(o, "Key") or "" for o in children(root, "Object")]
            except (ET.ParseError, ValueError, AwsError):
                keys = []
            return [(action, f"arn:aws:s3:::{bucket}/{k}") for k in keys] or [(action, f"arn:aws:s3:::{bucket}/*")]
        if op in OBJECT_OPS:
            return [(action, f"arn:aws:s3:::{bucket}/{key}")]
        return [(action, f"arn:aws:s3:::{bucket}")]

    def authz_context(self, req: Request, op: str) -> dict[str, Any]:
        if op in ("ListObjects", "ListObjectsV2"):
            return {"s3:prefix": req.query.get("prefix", ""), "s3:delimiter": req.query.get("delimiter"),
                    "s3:max-keys": req.query.get("max-keys")}
        return {}

    def resource_policy(self, arn: str) -> dict[str, Any] | None:
        bucket = arn.removeprefix("arn:aws:s3:::").split("/", 1)[0]
        b = self.buckets.get(bucket)
        return json.loads(b.policy) if b and b.policy else None

    def trail_resources(self, req: Request, op: str) -> list[dict[str, str]]:
        bucket, key = self._locate(req)
        out = []
        if key:
            out.append({"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"})
        if bucket:
            out.append({"accountId": ACCOUNT_ID, "type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}"})
        return out

    def metrics(self, req: Request, op: str, status: int, error, duration_ms: float) -> list[Metric]:
        """リクエストメトリクス。AWS と同じく、バケットにメトリクス設定がある場合だけ発行する。"""
        bucket, key = self._locate(req)
        b = self.buckets.get(bucket or "")
        if b is None or not b.metrics_configs:
            return []
        out: list[Metric] = []
        for filter_id, prefix in b.metrics_configs.items():
            if prefix and not (key or req.query.get("prefix", "")).startswith(prefix):
                continue
            dims = {"BucketName": bucket, "FilterId": filter_id}
            values = [("AllRequests", 1.0, "Count")]
            kind = "ListRequests" if op.startswith("List") else REQUEST_KIND.get(req.method)
            if kind:
                values.append((kind, 1.0, "Count"))
            values.append(("4xxErrors", 1.0 if 400 <= status < 500 else 0.0, "Count"))
            values.append(("5xxErrors", 1.0 if status >= 500 else 0.0, "Count"))
            if req.method in ("PUT", "POST") and req.body:
                values.append(("BytesUploaded", float(len(req.body)), "Bytes"))
            if req.ctx.get("bytes_out"):
                values.append(("BytesDownloaded", float(req.ctx["bytes_out"]), "Bytes"))
            values.append(("TotalRequestLatency", duration_ms, "Milliseconds"))
            values.append(("FirstByteLatency", duration_ms, "Milliseconds"))
            out.extend(Metric("AWS/S3", n, v, dims, u) for n, v, u in values)
        return out

    def gauges(self) -> list[Metric]:
        """ストレージメトリクス (AWS では 1 日 1 回、日付の 0 時のタイムスタンプで発行される)。"""
        with self.lock:
            day = int(self.clock.now() // 86400) * 86400
            out = []
            for b in self.buckets.values():
                out.append(Metric("AWS/S3", "BucketSizeBytes", float(sum(len(o.data) for o in b.objects.values())),
                                  {"BucketName": b.name, "StorageType": "StandardStorage"}, "Bytes", day))
                out.append(Metric("AWS/S3", "NumberOfObjects", float(len(b.objects)),
                                  {"BucketName": b.name, "StorageType": "AllStorageTypes"}, "Count", day))
            return out

    def params_for_log(self, req: Request, op: str) -> Any:
        bucket, key = self._locate(req)
        params = {"Bucket": bucket, "Key": key, **{k: v for k, v in req.query.items()
                                                   if v and not k.startswith("X-Amz-") and k not in SIGNATURE_PARAMS}}
        if req.method in ("PUT", "POST") and req.body:
            params["ContentLength"] = len(req.body)
        return {k: v for k, v in params.items() if v is not None}

    def handle(self, req: Request, op: str) -> Response:
        bucket, key = self._locate(req)
        if op in ("Unsupported", "Unknown"):
            raise AwsError("NotImplemented", "This operation is not implemented by awsemu", 501)
        with self.lock:
            return getattr(self, f"op_{op}")(req, bucket, key)

    def error_response(self, req: Request, err: AwsError) -> Response:
        bucket, key = self._locate(req)
        extra = ""
        if err.code == "NoSuchKey" and key:
            extra = tag("Key", key)
        elif err.code in ("NoSuchBucket", "BucketNotEmpty", "BucketAlreadyOwnedByYou") and bucket:
            extra = tag("BucketName", bucket)
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>\n<Error>'
            f"{tag('Code', err.code)}{tag('Message', err.message)}{extra}"
            f"{tag('RequestId', req.request_id)}</Error>"
        ).encode()
        return Response(err.status, b"" if req.method == "HEAD" else body, {"Content-Type": "application/xml"})

    # ------------------------------------------------------------------ helpers
    def _bucket(self, name: str) -> Bucket:
        b = self.buckets.get(name)
        if b is None:
            raise AwsError("NoSuchBucket", "The specified bucket does not exist", 404)
        return b

    def _object(self, bucket: str, key: str) -> S3Object:
        obj = self._bucket(bucket).objects.get(key)
        if obj is None:
            raise AwsError("NoSuchKey", "The specified key does not exist.", 404)
        return obj

    def _payload(self, req: Request) -> bytes:
        body = req.body
        sha = req.header("x-amz-content-sha256") or ""
        if sha.startswith("STREAMING-") or "aws-chunked" in (req.header("Content-Encoding") or ""):
            body, _ = decode_aws_chunked(body)
        md5 = req.header("Content-MD5")
        if md5 and base64.b64encode(hashlib.md5(body).digest()).decode() != md5:
            raise AwsError("BadDigest", "The Content-MD5 you specified did not match what we received.")
        return body

    @staticmethod
    def _metadata(req: Request) -> dict[str, str]:
        return {k[len("x-amz-meta-"):].lower(): v for k, v in req.headers.items()
                if k.lower().startswith("x-amz-meta-")}

    @staticmethod
    def _object_headers(obj: S3Object) -> dict[str, str]:
        headers = {
            "ETag": obj.etag,
            "Last-Modified": http_date(obj.last_modified),
            "Content-Type": obj.content_type,
            "Accept-Ranges": "bytes",
        }
        headers.update({f"x-amz-meta-{k}": v for k, v in obj.metadata.items()})
        return headers

    @staticmethod
    def _check_conditions(req: Request, obj: S3Object) -> Response | None:
        if_match = req.header("If-Match")
        if if_match and if_match not in ("*", obj.etag) and f'"{if_match}"' != obj.etag:
            raise AwsError("PreconditionFailed", "At least one of the pre-conditions you specified did not hold", 412)
        if_none = req.header("If-None-Match")
        if if_none and (if_none == "*" or if_none == obj.etag or f'"{if_none}"' == obj.etag):
            return Response(304, b"", {"ETag": obj.etag})
        ims = req.header("If-Modified-Since")
        if ims:
            try:
                if int(obj.last_modified) <= parsedate_to_datetime(ims).timestamp():
                    return Response(304, b"", {"ETag": obj.etag})
            except (TypeError, ValueError):
                pass
        return None

    # ------------------------------------------------------------------ buckets
    def op_ListBuckets(self, req, bucket, key):
        items = "".join(
            f"<Bucket>{tag('Name', b.name)}{tag('CreationDate', iso(b.created))}{tag('BucketRegion', b.region)}</Bucket>"
            for b in sorted(self.buckets.values(), key=lambda b: b.name)
        )
        owner = f"<Owner>{tag('ID', 'awsemu')}{tag('DisplayName', 'awsemu')}</Owner>"
        return Response(200, xml_doc("ListAllMyBucketsResult", f"{owner}<Buckets>{items}</Buckets>"))

    def op_CreateBucket(self, req, bucket, key):
        if not BUCKET_RE.match(bucket) or ".." in bucket:
            raise AwsError("InvalidBucketName", "The specified bucket is not valid.")
        if bucket in self.buckets:
            raise AwsError("BucketAlreadyOwnedByYou",
                           "Your previous request to create the named bucket succeeded and you already own it.", 409)
        region = req.region
        if req.body.strip():
            loc = child_text(ET.fromstring(req.body), "LocationConstraint")
            region = loc or region
        self.buckets[bucket] = Bucket(bucket, region, self.clock.now())
        return Response(200, b"", {"Location": f"/{bucket}"})

    def op_DeleteBucket(self, req, bucket, key):
        b = self._bucket(bucket)
        if b.objects:
            raise AwsError("BucketNotEmpty", "The bucket you tried to delete is not empty", 409)
        del self.buckets[bucket]
        return Response(204)

    def op_HeadBucket(self, req, bucket, key):
        b = self._bucket(bucket)
        return Response(200, b"", {"x-amz-bucket-region": b.region})

    def op_GetBucketLocation(self, req, bucket, key):
        b = self._bucket(bucket)
        loc = "" if b.region == "us-east-1" else escape(b.region)
        return Response(200, f'<?xml version="1.0" encoding="UTF-8"?>\n<LocationConstraint xmlns="{NS}">{loc}</LocationConstraint>'.encode())

    def op_GetBucketVersioning(self, req, bucket, key):
        self._bucket(bucket)
        return Response(200, xml_doc("VersioningConfiguration", ""))

    def put_internal(self, bucket: str, key: str, data: bytes, content_type: str) -> str | None:
        """AWS サービス (CloudTrail など) による書き込み。失敗時はエラーコードを返す。"""
        with self.lock:
            b = self.buckets.get(bucket)
            if b is None:
                return "NoSuchBucket"
            b.objects[key] = S3Object(data, f'"{hashlib.md5(data).hexdigest()}"', self.clock.now(), content_type)
            return None

    # ------------------------------------------------------------------ bucket policy / metrics configuration
    def op_PutBucketPolicy(self, req, bucket, key):
        b = self._bucket(bucket)
        text = self._payload(req).decode()
        if not text.lstrip().startswith("{"):
            raise AwsError("MalformedPolicy", "Policies must be valid JSON and the first byte must be '{'")
        try:
            parse_document(text, identity_policy=False)
        except AwsError as err:
            raise AwsError("MalformedPolicy", err.message)
        b.policy = text
        return Response(204)

    def op_GetBucketPolicy(self, req, bucket, key):
        b = self._bucket(bucket)
        if not b.policy:
            raise AwsError("NoSuchBucketPolicy", "The bucket policy does not exist", 404)
        return Response(200, b.policy.encode(), {"Content-Type": "application/json"})

    def op_DeleteBucketPolicy(self, req, bucket, key):
        self._bucket(bucket).policy = None
        return Response(204)

    def op_PutBucketMetricsConfiguration(self, req, bucket, key):
        b = self._bucket(bucket)
        root = ET.fromstring(self._payload(req))
        filt = children(root, "Filter")
        b.metrics_configs[req.query["id"]] = (child_text(filt[0], "Prefix") or "") if filt else ""
        return Response(204)

    @staticmethod
    def _metrics_config_xml(filter_id: str, prefix: str) -> str:
        return tag("Id", filter_id) + (f"<Filter>{tag('Prefix', prefix)}</Filter>" if prefix else "")

    def op_GetBucketMetricsConfiguration(self, req, bucket, key):
        b = self._bucket(bucket)
        fid = req.query["id"]
        if fid not in b.metrics_configs:
            raise AwsError("NoSuchConfiguration", "The specified configuration does not exist.", 404)
        return Response(200, xml_doc("MetricsConfiguration", self._metrics_config_xml(fid, b.metrics_configs[fid])))

    def op_DeleteBucketMetricsConfiguration(self, req, bucket, key):
        b = self._bucket(bucket)
        if b.metrics_configs.pop(req.query["id"], None) is None:
            raise AwsError("NoSuchConfiguration", "The specified configuration does not exist.", 404)
        return Response(204)

    def op_ListBucketMetricsConfigurations(self, req, bucket, key):
        b = self._bucket(bucket)
        inner = "".join(f"<MetricsConfiguration>{self._metrics_config_xml(i, pfx)}</MetricsConfiguration>"
                        for i, pfx in b.metrics_configs.items())
        return Response(200, xml_doc("ListMetricsConfigurationsResult", tag("IsTruncated", False) + inner))

    def op_PutBucketVersioning(self, req, bucket, key):
        raise AwsError("NotImplemented", "Versioning is not implemented by awsemu", 501)

    # ------------------------------------------------------------------ listing
    def _list(self, b: Bucket, prefix: str, delimiter: str, marker: str, max_keys: int):
        """(objects, common_prefixes, truncated, last_emitted) を返す。"""
        contents: list[tuple[str, S3Object]] = []
        prefixes: list[str] = []
        truncated = False
        last = None
        for k in sorted(b.objects):
            if not k.startswith(prefix) or (marker and k <= marker):
                continue
            if marker and delimiter and marker.endswith(delimiter) and k.startswith(marker):
                continue
            if delimiter:
                idx = k.find(delimiter, len(prefix))
                if idx >= 0:
                    cp = k[: idx + len(delimiter)]
                    if prefixes and prefixes[-1] == cp:
                        continue
                    if len(contents) + len(prefixes) >= max_keys:
                        truncated = True
                        break
                    prefixes.append(cp)
                    last = cp
                    continue
            if len(contents) + len(prefixes) >= max_keys:
                truncated = True
                break
            contents.append((k, b.objects[k]))
            last = k
        return contents, prefixes, truncated, last

    @staticmethod
    def _contents_xml(contents, owner: bool = False) -> str:
        out = []
        for k, o in contents:
            out.append(
                f"<Contents>{tag('Key', k)}{tag('LastModified', iso(o.last_modified))}{tag('ETag', o.etag)}"
                f"{tag('Size', len(o.data))}{tag('StorageClass', 'STANDARD')}"
                + (f"<Owner>{tag('ID', 'awsemu')}</Owner>" if owner else "")
                + "</Contents>"
            )
        return "".join(out)

    @staticmethod
    def _max_keys(req: Request) -> int:
        try:
            return max(0, min(int(req.query.get("max-keys", 1000)), 1000))
        except ValueError:
            raise AwsError("InvalidArgument", "Provided max-keys not an integer or within integer range")

    def op_ListObjectsV2(self, req, bucket, key):
        b = self._bucket(bucket)
        q = req.query
        prefix, delimiter = q.get("prefix", ""), q.get("delimiter", "")
        token = q.get("continuation-token")
        marker = base64.urlsafe_b64decode(token).decode() if token else q.get("start-after", "")
        max_keys = self._max_keys(req)
        contents, prefixes, truncated, last = self._list(b, prefix, delimiter, marker, max_keys)
        inner = (
            tag("Name", bucket) + tag("Prefix", prefix)
            + (tag("Delimiter", delimiter) if delimiter else "")
            + tag("MaxKeys", max_keys) + tag("KeyCount", len(contents) + len(prefixes))
            + tag("IsTruncated", truncated)
            + (tag("ContinuationToken", token) if token else "")
            + (tag("StartAfter", q["start-after"]) if q.get("start-after") else "")
            + (tag("NextContinuationToken", base64.urlsafe_b64encode(last.encode()).decode()) if truncated else "")
            + self._contents_xml(contents)
            + "".join(f"<CommonPrefixes>{tag('Prefix', p)}</CommonPrefixes>" for p in prefixes)
        )
        return Response(200, xml_doc("ListBucketResult", inner))

    def op_ListObjects(self, req, bucket, key):
        b = self._bucket(bucket)
        q = req.query
        prefix, delimiter, marker = q.get("prefix", ""), q.get("delimiter", ""), q.get("marker", "")
        max_keys = self._max_keys(req)
        contents, prefixes, truncated, last = self._list(b, prefix, delimiter, marker, max_keys)
        inner = (
            tag("Name", bucket) + tag("Prefix", prefix) + tag("Marker", marker)
            + (tag("Delimiter", delimiter) if delimiter else "")
            + tag("MaxKeys", max_keys) + tag("IsTruncated", truncated)
            + (tag("NextMarker", last) if truncated else "")
            + self._contents_xml(contents, owner=True)
            + "".join(f"<CommonPrefixes>{tag('Prefix', p)}</CommonPrefixes>" for p in prefixes)
        )
        return Response(200, xml_doc("ListBucketResult", inner))

    # ------------------------------------------------------------------ objects
    def op_PutObject(self, req, bucket, key):
        b = self._bucket(bucket)
        if req.header("If-None-Match") == "*" and key in b.objects:
            raise AwsError("PreconditionFailed", "At least one of the pre-conditions you specified did not hold", 412)
        if_match = req.header("If-Match")
        if if_match:
            current = b.objects.get(key)
            if current is None:
                raise AwsError("NoSuchKey", "The specified key does not exist.", 404)
            if if_match != current.etag and f'"{if_match}"' != current.etag:
                raise AwsError("PreconditionFailed", "At least one of the pre-conditions you specified did not hold", 412)
        data = self._payload(req)
        obj = S3Object(
            data=data,
            etag=f'"{hashlib.md5(data).hexdigest()}"',
            last_modified=self.clock.now(),
            content_type=req.header("Content-Type") or "binary/octet-stream",
            metadata=self._metadata(req),
        )
        b.objects[key] = obj
        return Response(200, b"", {"ETag": obj.etag})

    def op_GetObject(self, req, bucket, key):
        obj = self._object(bucket, key)
        not_modified = self._check_conditions(req, obj)
        if not_modified:
            return not_modified
        headers = self._object_headers(obj)
        data, status = obj.data, 200
        rng = req.header("Range")
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng or "")
        if m and (m.group(1) or m.group(2)):
            size = len(obj.data)
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:
                start, end = max(0, size - int(m.group(2))), size - 1
            if start >= size or start > end:
                raise AwsError("InvalidRange", "The requested range is not satisfiable", 416)
            data, status = obj.data[start:end + 1], 206
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        for q, h in (("response-content-type", "Content-Type"), ("response-content-disposition", "Content-Disposition"),
                     ("response-cache-control", "Cache-Control")):
            if q in req.query:
                headers[h] = req.query[q]
        req.ctx["bytes_out"] = len(data)
        return Response(status, data, headers)

    def op_HeadObject(self, req, bucket, key):
        obj = self._object(bucket, key)
        not_modified = self._check_conditions(req, obj)
        if not_modified:
            return not_modified
        headers = self._object_headers(obj)
        headers["Content-Length"] = str(len(obj.data))
        return Response(200, b"", headers)

    def op_DeleteObject(self, req, bucket, key):
        self._bucket(bucket).objects.pop(key, None)
        return Response(204)

    def op_DeleteObjects(self, req, bucket, key):
        b = self._bucket(bucket)
        root = ET.fromstring(self._payload(req))
        quiet = (child_text(root, "Quiet") or "").lower() == "true"
        deleted = []
        for o in children(root, "Object"):
            k = child_text(o, "Key") or ""
            b.objects.pop(k, None)
            deleted.append(k)
        inner = "" if quiet else "".join(f"<Deleted>{tag('Key', k)}</Deleted>" for k in deleted)
        return Response(200, xml_doc("DeleteResult", inner))

    def op_CopyObject(self, req, bucket, key):
        dst = self._bucket(bucket)
        source = unquote(req.header("x-amz-copy-source") or "").split("?", 1)[0].lstrip("/")
        src_bucket, _, src_key = source.partition("/")
        src = self._object(src_bucket, src_key)
        directive = (req.header("x-amz-metadata-directive") or "COPY").upper()
        if directive == "COPY" and src_bucket == bucket and src_key == key:
            raise AwsError("InvalidRequest", "This copy request is illegal because it is trying to copy an object "
                           "to itself without changing the object's metadata.")
        obj = S3Object(
            data=src.data,
            etag=src.etag,
            last_modified=self.clock.now(),
            content_type=(req.header("Content-Type") or src.content_type) if directive == "REPLACE" else src.content_type,
            metadata=self._metadata(req) if directive == "REPLACE" else dict(src.metadata),
        )
        dst.objects[key] = obj
        inner = tag("ETag", obj.etag) + tag("LastModified", iso(obj.last_modified))
        return Response(200, xml_doc("CopyObjectResult", inner))

    # ------------------------------------------------------------------ multipart
    def _upload(self, bucket: str, upload_id: str) -> Upload:
        up = self._bucket(bucket).uploads.get(upload_id)
        if up is None:
            raise AwsError("NoSuchUpload", "The specified upload does not exist.", 404)
        return up

    def op_CreateMultipartUpload(self, req, bucket, key):
        b = self._bucket(bucket)
        upload_id = uuid.uuid4().hex
        b.uploads[upload_id] = Upload(key, self.clock.now(),
                                      req.header("Content-Type") or "binary/octet-stream", self._metadata(req))
        inner = tag("Bucket", bucket) + tag("Key", key) + tag("UploadId", upload_id)
        return Response(200, xml_doc("InitiateMultipartUploadResult", inner))

    def op_UploadPart(self, req, bucket, key):
        up = self._upload(bucket, req.query["uploadId"])
        number = int(req.query.get("partNumber", "0"))
        if not 1 <= number <= 10000:
            raise AwsError("InvalidArgument", "Part number must be an integer between 1 and 10000, inclusive")
        data = self._payload(req)
        etag = f'"{hashlib.md5(data).hexdigest()}"'
        up.parts[number] = (data, etag)
        return Response(200, b"", {"ETag": etag})

    def op_ListParts(self, req, bucket, key):
        up = self._upload(bucket, req.query["uploadId"])
        parts = "".join(
            f"<Part>{tag('PartNumber', n)}{tag('ETag', e)}{tag('Size', len(d))}</Part>"
            for n, (d, e) in sorted(up.parts.items())
        )
        inner = tag("Bucket", bucket) + tag("Key", key) + tag("UploadId", req.query["uploadId"]) + \
            tag("IsTruncated", False) + parts
        return Response(200, xml_doc("ListPartsResult", inner))

    def op_ListMultipartUploads(self, req, bucket, key):
        b = self._bucket(bucket)
        uploads = "".join(
            f"<Upload>{tag('Key', u.key)}{tag('UploadId', uid)}{tag('Initiated', iso(u.initiated))}</Upload>"
            for uid, u in b.uploads.items()
        )
        return Response(200, xml_doc("ListMultipartUploadsResult",
                                     tag("Bucket", bucket) + tag("IsTruncated", False) + uploads))

    def op_CompleteMultipartUpload(self, req, bucket, key):
        b = self._bucket(bucket)
        upload_id = req.query["uploadId"]
        up = self._upload(bucket, upload_id)
        root = ET.fromstring(self._payload(req))
        requested = [(int(child_text(p, "PartNumber") or 0), child_text(p, "ETag")) for p in children(root, "Part")]
        if [n for n, _ in requested] != sorted(n for n, _ in requested):
            raise AwsError("InvalidPartOrder", "The list of parts was not in ascending order.")
        chunks, digests = [], b""
        for n, etag in requested:
            part = up.parts.get(n)
            if part is None or (etag and etag.strip('"') != part[1].strip('"')):
                raise AwsError("InvalidPart", "One or more of the specified parts could not be found.")
            chunks.append(part[0])
            digests += bytes.fromhex(part[1].strip('"'))
        data = b"".join(chunks)
        obj = S3Object(data, f'"{hashlib.md5(digests).hexdigest()}-{len(requested)}"', self.clock.now(),
                       up.content_type, up.metadata)
        b.objects[key] = obj
        del b.uploads[upload_id]
        inner = tag("Location", f"/{bucket}/{key}") + tag("Bucket", bucket) + tag("Key", key) + tag("ETag", obj.etag)
        return Response(200, xml_doc("CompleteMultipartUploadResult", inner))

    def op_AbortMultipartUpload(self, req, bucket, key):
        self._upload(bucket, req.query["uploadId"])
        del self.buckets[bucket].uploads[req.query["uploadId"]]
        return Response(204)

    # ------------------------------------------------------------------ state
    def reset(self) -> None:
        with self.lock:
            self.buckets.clear()

    def state(self) -> dict[str, Any]:
        with self.lock:
            return {
                name: {
                    "region": b.region,
                    "created": iso(b.created),
                    "object_count": len(b.objects),
                    "total_bytes": sum(len(o.data) for o in b.objects.values()),
                    "objects": {
                        k: {"size": len(o.data), "etag": o.etag, "last_modified": iso(o.last_modified),
                            "content_type": o.content_type, "metadata": o.metadata}
                        for k, o in sorted(b.objects.items())
                    },
                    "policy": json.loads(b.policy) if b.policy else None,
                    "request_metrics_filters": b.metrics_configs,
                    "multipart_uploads": {
                        uid: {"key": u.key, "initiated": iso(u.initiated), "parts": sorted(u.parts)}
                        for uid, u in b.uploads.items()
                    },
                }
                for name, b in sorted(self.buckets.items())
            }

    def dump(self) -> dict[str, Any]:
        with self.lock:
            return {
                name: {
                    "region": b.region,
                    "created": b.created,
                    "policy": b.policy,
                    "metrics_configs": b.metrics_configs,
                    "objects": {
                        k: {"data": base64.b64encode(o.data).decode(), "etag": o.etag,
                            "last_modified": o.last_modified, "content_type": o.content_type,
                            "metadata": o.metadata}
                        for k, o in b.objects.items()
                    },
                }
                for name, b in self.buckets.items()
            }

    def load(self, data: dict[str, Any]) -> None:
        with self.lock:
            self.buckets = {
                name: Bucket(
                    name, b["region"], b["created"],
                    {k: S3Object(base64.b64decode(o["data"]), o["etag"], o["last_modified"],
                                 o["content_type"], o["metadata"]) for k, o in b["objects"].items()},
                    policy=b.get("policy"), metrics_configs=b.get("metrics_configs", {}),
                )
                for name, b in data.items()
            }
