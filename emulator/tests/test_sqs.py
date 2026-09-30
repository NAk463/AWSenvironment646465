import json

import pytest
from botocore.exceptions import ClientError


def test_send_receive_delete(client):
    sqs = client("sqs")
    url = sqs.create_queue(QueueName="q")["QueueUrl"]
    sqs.send_message(QueueUrl=url, MessageBody="hi",
                     MessageAttributes={"n": {"DataType": "Number", "StringValue": "1"},
                                        "s": {"DataType": "String", "StringValue": "x"}})
    msgs = sqs.receive_message(QueueUrl=url, MessageAttributeNames=["All"])["Messages"]
    assert msgs[0]["Body"] == "hi"
    assert msgs[0]["MessageAttributes"]["s"]["StringValue"] == "x"
    assert "Messages" not in sqs.receive_message(QueueUrl=url)  # 可視性タイムアウト中
    sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0"
    assert attrs["ApproximateNumberOfMessagesNotVisible"] == "0"


def test_visibility_timeout_and_clock(client, emulator):
    sqs = client("sqs")
    url = sqs.create_queue(QueueName="q", Attributes={"VisibilityTimeout": "30"})["QueueUrl"]
    sqs.send_message(QueueUrl=url, MessageBody="m")
    assert sqs.receive_message(QueueUrl=url)["Messages"]
    assert "Messages" not in sqs.receive_message(QueueUrl=url)
    emulator.clock.advance(31)
    msg = sqs.receive_message(QueueUrl=url, AttributeNames=["ApproximateReceiveCount"])["Messages"][0]
    assert msg["Attributes"]["ApproximateReceiveCount"] == "2"


def test_redrive_to_dlq(client, emulator):
    sqs = client("sqs")
    dlq = sqs.create_queue(QueueName="dlq")["QueueUrl"]
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    url = sqs.create_queue(QueueName="main", Attributes={
        "VisibilityTimeout": "1",
        "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "2"}),
    })["QueueUrl"]
    sqs.send_message(QueueUrl=url, MessageBody="poison")
    for _ in range(2):
        assert sqs.receive_message(QueueUrl=url)["Messages"]
        emulator.clock.advance(2)
    assert "Messages" not in sqs.receive_message(QueueUrl=url)
    moved = sqs.receive_message(QueueUrl=dlq, MessageSystemAttributeNames=["All"])["Messages"][0]
    assert moved["Body"] == "poison"
    assert moved["Attributes"]["DeadLetterQueueSourceArn"].endswith(":main")


def test_delay_and_long_polling(client, emulator):
    sqs = client("sqs")
    url = sqs.create_queue(QueueName="q")["QueueUrl"]
    sqs.send_message(QueueUrl=url, MessageBody="later", DelaySeconds=60)
    assert "Messages" not in sqs.receive_message(QueueUrl=url, WaitTimeSeconds=1)
    emulator.clock.advance(60)
    assert sqs.receive_message(QueueUrl=url)["Messages"][0]["Body"] == "later"


def test_fifo_dedup_and_group_ordering(client):
    sqs = client("sqs")
    url = sqs.create_queue(QueueName="q.fifo", Attributes={"FifoQueue": "true"})["QueueUrl"]
    for body, dedup in [("1", "a"), ("1-dup", "a"), ("2", "b")]:
        sqs.send_message(QueueUrl=url, MessageBody=body, MessageGroupId="g", MessageDeduplicationId=dedup)
    first = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10)["Messages"]
    assert [m["Body"] for m in first] == ["1"]  # 同一グループは処理中の間ブロックされる
    sqs.delete_message(QueueUrl=url, ReceiptHandle=first[0]["ReceiptHandle"])
    assert [m["Body"] for m in sqs.receive_message(QueueUrl=url)["Messages"]] == ["2"]


def test_batch_and_errors(client):
    sqs = client("sqs")
    url = sqs.create_queue(QueueName="q")["QueueUrl"]
    res = sqs.send_message_batch(QueueUrl=url, Entries=[{"Id": str(i), "MessageBody": str(i)} for i in range(3)])
    assert len(res["Successful"]) == 3
    with pytest.raises(ClientError) as e:
        sqs.get_queue_url(QueueName="nope")
    assert e.value.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue"
    with pytest.raises(ClientError) as e:
        sqs.create_queue(QueueName="q", Attributes={"VisibilityTimeout": "99"})
    assert e.value.response["Error"]["Code"] == "QueueAlreadyExists"
