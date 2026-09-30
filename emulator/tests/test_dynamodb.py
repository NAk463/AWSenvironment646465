import time

import pytest
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError


@pytest.fixture
def table(client, endpoint):
    import boto3
    ddb = client("dynamodb")
    ddb.create_table(
        TableName="tbl",
        AttributeDefinitions=[{"AttributeName": a, "AttributeType": "S"} for a in ("pk", "sk", "gpk")],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        GlobalSecondaryIndexes=[{"IndexName": "gsi", "KeySchema": [{"AttributeName": "gpk", "KeyType": "HASH"}],
                                 "Projection": {"ProjectionType": "KEYS_ONLY"}}],
        BillingMode="PAY_PER_REQUEST",
    )
    res = boto3.resource("dynamodb", endpoint_url=endpoint, region_name="ap-northeast-1",
                         aws_access_key_id="test", aws_secret_access_key="test")
    return res.Table("tbl")


def code(e):
    return e.value.response["Error"]["Code"]


def test_crud_and_conditions(table):
    table.put_item(Item={"pk": "u1", "sk": "a", "n": 1, "tags": {"x"}})
    with pytest.raises(ClientError) as e:
        table.put_item(Item={"pk": "u1", "sk": "a"}, ConditionExpression=Attr("pk").not_exists())
    assert code(e) == "ConditionalCheckFailedException"
    res = table.update_item(
        Key={"pk": "u1", "sk": "a"},
        UpdateExpression="SET n = n + :one, #s = :s ADD tags :t REMOVE gone",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":one": 1, ":s": "PAID", ":t": {"y"}},
        ReturnValues="ALL_NEW",
    )["Attributes"]
    assert res["n"] == 2 and res["status"] == "PAID" and res["tags"] == {"x", "y"}
    assert table.get_item(Key={"pk": "u1", "sk": "a"}, ProjectionExpression="n")["Item"] == {"n": 2}
    table.delete_item(Key={"pk": "u1", "sk": "a"})
    assert "Item" not in table.get_item(Key={"pk": "u1", "sk": "a"})


def test_validation_errors_match_aws(table):
    with pytest.raises(ClientError) as e:
        table.update_item(Key={"pk": "u", "sk": "a"}, UpdateExpression="SET status = :s",
                          ExpressionAttributeValues={":s": "x"})
    assert "reserved keyword: status" in e.value.response["Error"]["Message"]
    with pytest.raises(ClientError) as e:
        table.update_item(Key={"pk": "u", "sk": "a"}, UpdateExpression="SET a = :a",
                          ExpressionAttributeValues={":a": 1, ":unused": 2})
    assert "unused in expressions" in e.value.response["Error"]["Message"]
    with pytest.raises(ClientError) as e:
        table.put_item(Item={"pk": "u"})
    assert "Missing the key sk" in e.value.response["Error"]["Message"]
    with pytest.raises(ClientError) as e:
        table.get_item(Key={"pk": "u"})
    assert e.value.response["Error"]["Message"] == "The provided key element does not match the schema"
    with pytest.raises(ClientError) as e:
        table.update_item(Key={"pk": "u", "sk": "a"}, UpdateExpression="SET pk = :v",
                          ExpressionAttributeValues={":v": "z"})
    assert "part of the key" in e.value.response["Error"]["Message"]


def test_query_pagination_and_gsi(table):
    with table.batch_writer() as w:
        for i in range(5):
            w.put_item(Item={"pk": "u1", "sk": f"o#{i}", "gpk": "NEW" if i % 2 else "OLD", "amount": i})
        w.put_item(Item={"pk": "u2", "sk": "o#0", "gpk": "NEW"})
    res = table.query(KeyConditionExpression=Key("pk").eq("u1") & Key("sk").between("o#1", "o#3"),
                      ScanIndexForward=False)
    assert [i["sk"] for i in res["Items"]] == ["o#3", "o#2", "o#1"]
    page1 = table.query(KeyConditionExpression=Key("pk").eq("u1"), Limit=2)
    page2 = table.query(KeyConditionExpression=Key("pk").eq("u1"), Limit=2, ExclusiveStartKey=page1["LastEvaluatedKey"])
    assert [i["sk"] for i in page1["Items"] + page2["Items"]] == ["o#0", "o#1", "o#2", "o#3"]
    filtered = table.query(KeyConditionExpression=Key("pk").eq("u1"), FilterExpression=Attr("amount").gte(3))
    assert filtered["Count"] == 2 and filtered["ScannedCount"] == 5
    gsi = table.query(IndexName="gsi", KeyConditionExpression=Key("gpk").eq("NEW"))["Items"]
    assert len(gsi) == 3 and all("amount" not in i for i in gsi)  # KEYS_ONLY
    assert table.scan(Select="COUNT")["Count"] == 6
    with pytest.raises(ClientError) as e:
        table.query(KeyConditionExpression=Key("sk").eq("o#1"))
    assert code(e) == "ValidationException"


def test_transactions(client, table):
    ddb = client("dynamodb")
    table.put_item(Item={"pk": "acct", "sk": "a", "balance": 100})
    table.put_item(Item={"pk": "acct", "sk": "b", "balance": 0})

    def transfer(amount):
        ddb.transact_write_items(TransactItems=[
            {"Update": {"TableName": "tbl", "Key": {"pk": {"S": "acct"}, "sk": {"S": "a"}},
                        "UpdateExpression": "SET balance = balance - :v", "ConditionExpression": "balance >= :v",
                        "ExpressionAttributeValues": {":v": {"N": str(amount)}}}},
            {"Update": {"TableName": "tbl", "Key": {"pk": {"S": "acct"}, "sk": {"S": "b"}},
                        "UpdateExpression": "SET balance = balance + :v",
                        "ExpressionAttributeValues": {":v": {"N": str(amount)}}}},
        ])

    transfer(60)
    with pytest.raises(ClientError) as e:
        transfer(60)
    assert code(e) == "TransactionCanceledException"
    assert [r["Code"] for r in e.value.response["CancellationReasons"]] == ["ConditionalCheckFailed", "None"]
    assert table.get_item(Key={"pk": "acct", "sk": "a"})["Item"]["balance"] == 40
    assert table.get_item(Key={"pk": "acct", "sk": "b"})["Item"]["balance"] == 60


def test_ttl_and_deletion_protection(client, table, emulator):
    ddb = client("dynamodb")
    ddb.update_time_to_live(TableName="tbl", TimeToLiveSpecification={"Enabled": True, "AttributeName": "exp"})
    table.put_item(Item={"pk": "s", "sk": "1", "exp": int(time.time()) + 60})
    assert "Item" in table.get_item(Key={"pk": "s", "sk": "1"})
    emulator.clock.advance(61)
    assert "Item" not in table.get_item(Key={"pk": "s", "sk": "1"})
    ddb.update_table(TableName="tbl", DeletionProtectionEnabled=True)
    with pytest.raises(ClientError) as e:
        ddb.delete_table(TableName="tbl")
    assert code(e) == "ValidationException"


def test_table_errors(client, table):
    ddb = client("dynamodb")
    with pytest.raises(ClientError) as e:
        ddb.describe_table(TableName="nope")
    assert code(e) == "ResourceNotFoundException"
    with pytest.raises(ClientError) as e:
        ddb.create_table(TableName="tbl", AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                         KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], BillingMode="PAY_PER_REQUEST")
    assert code(e) == "ResourceInUseException"
    assert ddb.list_tables()["TableNames"] == ["tbl"]
