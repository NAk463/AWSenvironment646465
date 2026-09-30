import json
import time
import urllib.request

import pytest
from botocore.exceptions import ClientError


def control(endpoint, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{endpoint}/_emulator/{path}", data=data, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def test_state_and_events(client, endpoint):
    s3 = client("s3")
    s3.create_bucket(Bucket="bkt")
    s3.put_object(Bucket="bkt", Key="k", Body=b"abc")
    state = control(endpoint, "GET", "state/s3")
    assert state["bkt"]["objects"]["k"]["size"] == 3
    events = control(endpoint, "GET", "events?service=s3")
    assert [e["operation"] for e in events] == ["CreateBucket", "PutObject"]
    assert events[1]["params"]["Key"] == "k"


def test_fault_injection(client, endpoint):
    sqs = client("sqs")
    url = sqs.create_queue(QueueName="q")["QueueUrl"]
    rule = control(endpoint, "POST", "faults", {"service": "sqs", "operation": "SendMessage",
                                                "error_code": "ServiceUnavailable", "status": 503, "count": 1})
    with pytest.raises(ClientError) as e:
        sqs.send_message(QueueUrl=url, MessageBody="x")
    assert e.value.response["Error"]["Code"] == "ServiceUnavailable"
    sqs.send_message(QueueUrl=url, MessageBody="x")  # count=1 なので 2 回目は成功
    errors = control(endpoint, "GET", "events?errors=1")
    assert errors[0]["fault_id"] == rule["id"]

    control(endpoint, "POST", "faults", {"service": "s3", "latency_ms": 300})
    started = time.monotonic()
    client("s3").list_buckets()
    assert time.monotonic() - started >= 0.3


def test_snapshot_roundtrip(client, endpoint):
    ddb = client("dynamodb")
    ddb.create_table(TableName="tbl", AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST")
    ddb.put_item(TableName="tbl", Item={"pk": {"S": "a"}, "v": {"N": "1"}})
    client("s3").create_bucket(Bucket="bkt")
    client("s3").put_object(Bucket="bkt", Key="k", Body=b"\x00\x01")
    client("sqs").create_queue(QueueName="q")
    snap = control(endpoint, "GET", "snapshot")
    control(endpoint, "POST", "reset")
    assert ddb.list_tables()["TableNames"] == []
    control(endpoint, "PUT", "snapshot", snap)
    assert ddb.get_item(TableName="tbl", Key={"pk": {"S": "a"}})["Item"]["v"] == {"N": "1"}
    assert client("s3").get_object(Bucket="bkt", Key="k")["Body"].read() == b"\x00\x01"
    assert client("sqs").list_queues()["QueueUrls"][0].endswith("/q")


def test_sts(client):
    assert client("sts").get_caller_identity()["Account"] == "000000000000"
    client("iam").create_role(RoleName="r", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                       "Action": "sts:AssumeRole"}]}))
    creds = client("sts").assume_role(RoleArn="arn:aws:iam::000000000000:role/r", RoleSessionName="sess")
    assert creds["AssumedRoleUser"]["Arn"].endswith("assumed-role/r/sess")
