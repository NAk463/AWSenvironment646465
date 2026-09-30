import urllib.request

import pytest
from botocore.exceptions import ClientError


def test_bucket_lifecycle(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="bucket-1", CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"})
    assert [b["Name"] for b in s3.list_buckets()["Buckets"]] == ["bucket-1"]
    assert s3.get_bucket_location(Bucket="bucket-1")["LocationConstraint"] == "ap-northeast-1"
    with pytest.raises(ClientError) as e:
        s3.create_bucket(Bucket="bucket-1")
    assert e.value.response["Error"]["Code"] == "BucketAlreadyOwnedByYou"
    s3.put_object(Bucket="bucket-1", Key="k", Body=b"x")
    with pytest.raises(ClientError) as e:
        s3.delete_bucket(Bucket="bucket-1")
    assert e.value.response["Error"]["Code"] == "BucketNotEmpty"
    s3.delete_object(Bucket="bucket-1", Key="k")
    s3.delete_bucket(Bucket="bucket-1")
    with pytest.raises(ClientError) as e:
        s3.head_bucket(Bucket="bucket-1")
    assert e.value.response["Error"]["Code"] == "404"


def test_objects_and_metadata(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="bkt")
    key = "日本語/ファイル name+1.txt"
    s3.put_object(Bucket="bkt", Key=key, Body=b"hello world", ContentType="text/plain", Metadata={"owner": "alice"})
    obj = s3.get_object(Bucket="bkt", Key=key)
    assert obj["Body"].read() == b"hello world"
    assert obj["ContentType"] == "text/plain"
    assert obj["Metadata"] == {"owner": "alice"}
    ranged = s3.get_object(Bucket="bkt", Key=key, Range="bytes=6-")
    assert ranged["Body"].read() == b"world"
    assert ranged["ContentRange"] == "bytes 6-10/11"
    assert [o["Key"] for o in s3.list_objects_v2(Bucket="bkt")["Contents"]] == [key]
    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket="bkt", Key="missing")
    assert e.value.response["Error"]["Code"] == "NoSuchKey"


def test_conditional_put(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="bkt")
    s3.put_object(Bucket="bkt", Key="lock", Body=b"1", IfNoneMatch="*")
    with pytest.raises(ClientError) as e:
        s3.put_object(Bucket="bkt", Key="lock", Body=b"2", IfNoneMatch="*")
    assert e.value.response["Error"]["Code"] == "PreconditionFailed"


def test_list_objects_v2_pagination_and_delimiter(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="bkt")
    for key in ["a/1", "a/2", "b/1", "c", "d"]:
        s3.put_object(Bucket="bkt", Key=key, Body=b"")
    top = s3.list_objects_v2(Bucket="bkt", Delimiter="/")
    assert [p["Prefix"] for p in top["CommonPrefixes"]] == ["a/", "b/"]
    assert [o["Key"] for o in top["Contents"]] == ["c", "d"]
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket="bkt", PaginationConfig={"PageSize": 2}):
        keys += [o["Key"] for o in page.get("Contents", [])]
    assert keys == ["a/1", "a/2", "b/1", "c", "d"]
    pages = list(s3.get_paginator("list_objects_v2").paginate(
        Bucket="bkt", Delimiter="/", PaginationConfig={"PageSize": 1}))
    seen = [p["Prefix"] for pg in pages for p in pg.get("CommonPrefixes", [])] + \
           [o["Key"] for pg in pages for o in pg.get("Contents", [])]
    assert sorted(seen) == ["a/", "b/", "c", "d"]


def test_copy_and_delete_objects(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="bkt")
    s3.put_object(Bucket="bkt", Key="src", Body=b"data")
    s3.copy_object(Bucket="bkt", Key="dst", CopySource={"Bucket": "bkt", "Key": "src"})
    assert s3.get_object(Bucket="bkt", Key="dst")["Body"].read() == b"data"
    res = s3.delete_objects(Bucket="bkt", Delete={"Objects": [{"Key": "src"}, {"Key": "dst"}]})
    assert sorted(d["Key"] for d in res["Deleted"]) == ["dst", "src"]
    assert s3.list_objects_v2(Bucket="bkt")["KeyCount"] == 0


def test_multipart_upload(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="bkt")
    up = s3.create_multipart_upload(Bucket="bkt", Key="big")
    parts = []
    for n, chunk in enumerate([b"a" * 5 * 1024 * 1024, b"b" * 100], start=1):
        r = s3.upload_part(Bucket="bkt", Key="big", UploadId=up["UploadId"], PartNumber=n, Body=chunk)
        parts.append({"PartNumber": n, "ETag": r["ETag"]})
    done = s3.complete_multipart_upload(Bucket="bkt", Key="big", UploadId=up["UploadId"],
                                        MultipartUpload={"Parts": parts})
    assert done["ETag"].endswith('-2"')
    assert s3.head_object(Bucket="bkt", Key="big")["ContentLength"] == 5 * 1024 * 1024 + 100


def test_presigned_url(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="bkt")
    s3.put_object(Bucket="bkt", Key="k", Body=b"presigned")
    url = s3.generate_presigned_url("get_object", Params={"Bucket": "bkt", "Key": "k"})
    assert urllib.request.urlopen(url).read() == b"presigned"
