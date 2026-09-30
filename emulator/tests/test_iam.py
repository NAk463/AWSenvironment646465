import json

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "000000000000"


def code(e):
    return e.value.response["Error"]["Code"]


def make_user(client, name, *policy_arns, inline=None):
    iam = client("iam")
    iam.create_user(UserName=name)
    for arn in policy_arns:
        iam.attach_user_policy(UserName=name, PolicyArn=arn)
    if inline:
        iam.put_user_policy(UserName=name, PolicyName="inline", PolicyDocument=json.dumps(inline))
    key = iam.create_access_key(UserName=name)["AccessKey"]
    return lambda service: client(service, key["AccessKeyId"], key["SecretAccessKey"])


def test_unknown_key_is_rejected_per_service(client):
    with pytest.raises(ClientError) as e:
        client("s3", "AKIAUNKNOWN").list_buckets()
    assert code(e) == "InvalidAccessKeyId"
    with pytest.raises(ClientError) as e:
        client("dynamodb", "AKIAUNKNOWN").list_tables()
    assert code(e) == "UnrecognizedClientException"
    with pytest.raises(ClientError) as e:
        client("sts", "AKIAUNKNOWN").get_caller_identity()
    assert code(e) == "InvalidClientTokenId"


def test_identity_policy_allow_and_implicit_deny(client):
    client("s3").create_bucket(Bucket="data-bkt")
    alice = make_user(client, "alice", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
    assert alice("sts").get_caller_identity()["Arn"] == f"arn:aws:iam::{ACCOUNT}:user/alice"
    alice("s3").list_objects_v2(Bucket="data-bkt")
    with pytest.raises(ClientError) as e:
        alice("s3").put_object(Bucket="data-bkt", Key="k", Body=b"x")
    assert code(e) == "AccessDenied"
    assert "because no identity-based policy allows the s3:PutObject action" in e.value.response["Error"]["Message"]
    with pytest.raises(ClientError) as e:
        alice("dynamodb").list_tables()
    assert code(e) == "AccessDeniedException"


def test_explicit_deny_wins_and_conditions(client):
    client("s3").create_bucket(Bucket="data-bkt")
    bob = make_user(client, "bob", inline={"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::data-bkt/*"},
        {"Effect": "Deny", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::data-bkt",
         "Condition": {"StringNotLike": {"s3:prefix": ["home/${aws:username}/*"]}}},
    ]})
    bob("s3").put_object(Bucket="data-bkt", Key="k", Body=b"x")
    with pytest.raises(ClientError) as e:
        bob("s3").delete_object(Bucket="data-bkt", Key="k")
    assert "explicit deny in an identity-based policy" in e.value.response["Error"]["Message"]
    bob("s3").list_objects_v2(Bucket="data-bkt", Prefix="home/bob/")
    with pytest.raises(ClientError):
        bob("s3").list_objects_v2(Bucket="data-bkt", Prefix="home/alice/")


def test_group_and_managed_policy_versions(client):
    iam = client("iam")
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:ListQueues", "Resource": "*"}]}
    arn = iam.create_policy(PolicyName="list-queues", PolicyDocument=json.dumps(doc))["Policy"]["Arn"]
    iam.create_group(GroupName="ops")
    iam.attach_group_policy(GroupName="ops", PolicyArn=arn)
    carol = make_user(client, "carol")
    with pytest.raises(ClientError):
        carol("sqs").list_queues()
    iam.add_user_to_group(GroupName="ops", UserName="carol")
    carol("sqs").list_queues()
    deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "sqs:*", "Resource": "*"}]}
    iam.create_policy_version(PolicyArn=arn, PolicyDocument=json.dumps(deny), SetAsDefault=True)
    with pytest.raises(ClientError):
        carol("sqs").list_queues()
    with pytest.raises(ClientError) as e:
        iam.delete_policy(PolicyArn=arn)
    assert code(e) == "DeleteConflict"


def test_bucket_policy_resource_based_allow_and_deny(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="shared-bkt")
    s3.put_object(Bucket="shared-bkt", Key="public/a", Body=b"hi")
    dave = make_user(client, "dave")
    with pytest.raises(ClientError):
        dave("s3").get_object(Bucket="shared-bkt", Key="public/a")
    s3.put_bucket_policy(Bucket="shared-bkt", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/dave"}, "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::shared-bkt/public/*"},
        {"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteBucket", "Resource": "arn:aws:s3:::shared-bkt"},
    ]}))
    assert dave("s3").get_object(Bucket="shared-bkt", Key="public/a")["Body"].read() == b"hi"
    s3.delete_object(Bucket="shared-bkt", Key="public/a")
    with pytest.raises(ClientError) as e:  # root にもリソースポリシーの明示的 Deny は効く
        s3.delete_bucket(Bucket="shared-bkt")
    assert code(e) == "AccessDenied"


def test_assume_role_trust_policy_and_expiry(client, emulator):
    iam = client("iam")
    erin = make_user(client, "erin")
    trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/erin"}, "Action": "sts:AssumeRole"}]}
    iam.create_role(RoleName="reader", AssumeRolePolicyDocument=json.dumps(trust))
    iam.attach_role_policy(RoleName="reader", PolicyArn="arn:aws:iam::aws:policy/AmazonSQSReadOnlyAccess")
    iam.create_role(RoleName="other", AssumeRolePolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                                 "Action": "sts:AssumeRole"}]}))
    with pytest.raises(ClientError) as e:
        erin("sts").assume_role(RoleArn=f"arn:aws:iam::{ACCOUNT}:role/other", RoleSessionName="xx")
    assert code(e) == "AccessDenied"
    creds = erin("sts").assume_role(RoleArn=f"arn:aws:iam::{ACCOUNT}:role/reader", RoleSessionName="s1",
                                    DurationSeconds=900)["Credentials"]
    role = lambda svc: client(svc, creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"])  # noqa: E731
    assert role("sts").get_caller_identity()["Arn"] == f"arn:aws:sts::{ACCOUNT}:assumed-role/reader/s1"
    role("sqs").list_queues()
    emulator.advance(901)
    with pytest.raises(ClientError) as e:
        role("sqs").list_queues()
    assert code(e) == "ExpiredToken"


def test_simulate_principal_policy(client):
    make_user(client, "frank", "arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess")
    res = client("iam").simulate_principal_policy(
        PolicySourceArn=f"arn:aws:iam::{ACCOUNT}:user/frank", ActionNames=["dynamodb:GetItem", "dynamodb:PutItem"])
    assert {r["EvalActionName"]: r["EvalDecision"] for r in res["EvaluationResults"]} == {
        "dynamodb:GetItem": "allowed", "dynamodb:PutItem": "implicitDeny"}


def test_iam_off_mode_allows_everything(client, emulator):
    emulator.iam_mode = "off"
    client("s3", "ANY-KEY").list_buckets()


def test_sqs_queue_policy_allows_and_denies(client):
    sqs = client("sqs")
    url = sqs.create_queue(QueueName="inbox")["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    gina = make_user(client, "gina", "arn:aws:iam::aws:policy/AmazonSQSFullAccess")
    hank = make_user(client, "hank")
    with pytest.raises(ClientError) as e:
        hank("sqs").send_message(QueueUrl=url, MessageBody="x")
    assert code(e) == "AccessDenied"
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/hank"}, "Action": "sqs:SendMessage",
         "Resource": arn},
        {"Effect": "Deny", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/gina"}, "Action": "sqs:ReceiveMessage",
         "Resource": arn}]})})
    hank("sqs").send_message(QueueUrl=url, MessageBody="x")
    gina("sqs").send_message(QueueUrl=url, MessageBody="y")
    with pytest.raises(ClientError) as e:
        gina("sqs").receive_message(QueueUrl=url)
    assert "explicit deny in a resource-based policy" in e.value.response["Error"]["Message"]
