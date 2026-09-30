"""CloudTrail / CloudWatch / CloudWatch Logs のテスト。"""
import datetime as dt
import gzip
import json
import time

import pytest
from botocore.exceptions import ClientError

ACCOUNT = "000000000000"


def utc(seconds=0):
    return dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)


# ============================================================================ CloudTrail
def test_lookup_events_returns_management_events_only(client):
    s3 = client("s3")
    s3.create_bucket(Bucket="trail-test")
    s3.put_object(Bucket="trail-test", Key="k", Body=b"x")      # データイベント
    with pytest.raises(ClientError):
        client("sqs", "AKIAUNKNOWN").list_queues()
    events = client("cloudtrail").lookup_events()["Events"]
    names = [e["EventName"] for e in events]
    assert "CreateBucket" in names and "PutObject" not in names
    record = json.loads(next(e for e in events if e["EventName"] == "CreateBucket")["CloudTrailEvent"])
    assert record["userIdentity"]["type"] == "Root"
    assert record["eventSource"] == "s3.amazonaws.com"
    assert record["requestParameters"]["bucketName"] == "trail-test"
    only = client("cloudtrail").lookup_events(
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "CreateBucket"}])["Events"]
    assert {e["EventName"] for e in only} == {"CreateBucket"}


def test_access_denied_is_recorded_with_error_code(client):
    iam = client("iam")
    iam.create_user(UserName="mallory")
    key = iam.create_access_key(UserName="mallory")["AccessKey"]
    with pytest.raises(ClientError):
        client("s3", key["AccessKeyId"], key["SecretAccessKey"]).create_bucket(Bucket="nope-bkt")
    events = client("cloudtrail").lookup_events(
        LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": "mallory"}])["Events"]
    record = json.loads(events[0]["CloudTrailEvent"])
    assert record["errorCode"] == "AccessDenied"
    assert record["userIdentity"]["accessKeyId"] == key["AccessKeyId"]


def test_trail_delivers_data_events_to_s3_and_logs(client):
    s3, logs, ct = client("s3"), client("logs"), client("cloudtrail")
    s3.create_bucket(Bucket="ct-bucket")
    with pytest.raises(ClientError) as e:
        ct.create_trail(Name="t", S3BucketName="ct-bucket")
    assert e.value.response["Error"]["Code"] == "InsufficientS3BucketPolicyException"
    s3.put_bucket_policy(Bucket="ct-bucket", Policy=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl",
         "Resource": "arn:aws:s3:::ct-bucket"},
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::ct-bucket/*"}]}))
    logs.create_log_group(logGroupName="/ct")
    client("iam").create_role(RoleName="ct-role", AssumeRolePolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                                 "Action": "sts:AssumeRole"}]}))
    ct.create_trail(Name="t", S3BucketName="ct-bucket",
                    CloudWatchLogsLogGroupArn=f"arn:aws:logs:ap-northeast-1:{ACCOUNT}:log-group:/ct:*",
                    CloudWatchLogsRoleArn=f"arn:aws:iam::{ACCOUNT}:role/ct-role")
    ct.put_event_selectors(TrailName="t", EventSelectors=[{
        "ReadWriteType": "All", "IncludeManagementEvents": True,
        "DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::ct-bucket/app/"]}]}])
    ct.start_logging(Name="t")
    s3.put_object(Bucket="ct-bucket", Key="app/data.txt", Body=b"x")
    found = logs.filter_log_events(logGroupName="/ct", filterPattern='{ $.eventName = "PutObject" }')["events"]
    assert len(found) == 1
    objects = [o["Key"] for o in s3.list_objects_v2(Bucket="ct-bucket", Prefix="AWSLogs/")["Contents"]]
    records = [json.loads(gzip.decompress(s3.get_object(Bucket="ct-bucket", Key=k)["Body"].read()))["Records"][0]
               for k in objects]
    assert "PutObject" in {r["eventName"] for r in records}
    assert ct.get_trail_status(Name="t")["IsLogging"] is True


# ============================================================================ CloudWatch
def test_put_and_get_custom_metrics_with_math(client):
    cw = client("cloudwatch")
    now = utc()
    cw.put_metric_data(Namespace="App", MetricData=[
        {"MetricName": "Errors", "Value": 5, "Timestamp": now},
        {"MetricName": "Requests", "Value": 100, "Timestamp": now},
    ])
    with pytest.raises(ClientError) as e:
        cw.put_metric_data(Namespace="AWS/Fake", MetricData=[{"MetricName": "x", "Value": 1}])
    assert e.value.response["Error"]["Code"] == "InvalidParameterValue"
    res = cw.get_metric_data(StartTime=utc(-600), EndTime=utc(600), MetricDataQueries=[
        {"Id": "e", "MetricStat": {"Metric": {"Namespace": "App", "MetricName": "Errors"}, "Period": 60, "Stat": "Sum"},
         "ReturnData": False},
        {"Id": "r", "MetricStat": {"Metric": {"Namespace": "App", "MetricName": "Requests"}, "Period": 60,
                                   "Stat": "Sum"}, "ReturnData": False},
        {"Id": "rate", "Expression": "100 * e / r"}])["MetricDataResults"]
    assert res[0]["Id"] == "rate" and res[0]["Values"] == [5.0]
    names = {m["MetricName"] for m in cw.list_metrics(Namespace="App")["Metrics"]}
    assert names == {"Errors", "Requests"}


def test_service_metrics_and_alarm_transitions(client, emulator):
    sqs, cw = client("sqs"), client("cloudwatch")
    url = sqs.create_queue(QueueName="jobs")["QueueUrl"]
    for i in range(12):
        sqs.send_message(QueueUrl=url, MessageBody=str(i))
    sqs.receive_message(QueueUrl=url)
    stats = cw.get_metric_statistics(Namespace="AWS/SQS", MetricName="NumberOfMessagesSent",
                                     Dimensions=[{"Name": "QueueName", "Value": "jobs"}],
                                     StartTime=utc(-600), EndTime=utc(600), Period=1200, Statistics=["Sum"])
    assert stats["Datapoints"][0]["Sum"] == 12
    cw.put_metric_alarm(AlarmName="backlog", Namespace="AWS/SQS", MetricName="ApproximateNumberOfMessagesVisible",
                        Dimensions=[{"Name": "QueueName", "Value": "jobs"}], Statistic="Maximum", Period=60,
                        EvaluationPeriods=2, Threshold=5, ComparisonOperator="GreaterThanThreshold")
    assert cw.describe_alarms(AlarmNames=["backlog"])["MetricAlarms"][0]["StateValue"] == "INSUFFICIENT_DATA"
    emulator.advance(180)
    alarm = cw.describe_alarms(AlarmNames=["backlog"])["MetricAlarms"][0]
    assert alarm["StateValue"] == "ALARM"
    assert alarm["StateReason"].startswith("Threshold Crossed: 2 out of the last 2 datapoints")
    sqs.purge_queue(QueueUrl=url)
    emulator.advance(180)
    assert cw.describe_alarms(AlarmNames=["backlog"])["MetricAlarms"][0]["StateValue"] == "OK"
    history = [h["HistorySummary"] for h in cw.describe_alarm_history(AlarmName="backlog")["AlarmHistoryItems"]]
    assert "Alarm updated from ALARM to OK" in history and "Alarm updated from INSUFFICIENT_DATA to ALARM" in history


def test_dynamodb_provisioned_throttling_and_metrics(client):
    ddb, cw = client("dynamodb"), client("cloudwatch")
    ddb.create_table(TableName="hot", AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                     KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                     ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1})
    throttled = 0
    for i in range(120):
        try:
            ddb.put_item(TableName="hot", Item={"pk": {"S": str(i)}})
        except ClientError as e:
            assert e.response["Error"]["Code"] == "ProvisionedThroughputExceededException"
            throttled += 1
    assert throttled > 0
    # バッチは不足分を UnprocessedItems で返し、全件不足なら例外になる (AWS と同じ)
    try:
        res = ddb.batch_write_item(RequestItems={"hot": [{"PutRequest": {"Item": {"pk": {"S": f"b{i}"}}}}
                                                         for i in range(5)]})
        assert len(res["UnprocessedItems"].get("hot", [])) >= 1
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ProvisionedThroughputExceededException"
    stats = cw.get_metric_statistics(Namespace="AWS/DynamoDB", MetricName="ThrottledRequests",
                                     Dimensions=[{"Name": "TableName", "Value": "hot"},
                                                 {"Name": "Operation", "Value": "PutItem"}],
                                     StartTime=utc(-600), EndTime=utc(600), Period=1200, Statistics=["Sum"])
    assert stats["Datapoints"][0]["Sum"] == throttled
    ddb.update_table(TableName="hot", ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1000})
    time.sleep(0.01)
    consumed = ddb.put_item(TableName="hot", Item={"pk": {"S": "big"}, "v": {"S": "x" * 3000}},
                            ReturnConsumedCapacity="TOTAL")
    assert consumed["ConsumedCapacity"]["CapacityUnits"] == 3.0


# ============================================================================ Logs
def _put(logs, group, stream, messages):
    now = int(time.time() * 1000)
    logs.put_log_events(logGroupName=group, logStreamName=stream,
                        logEvents=[{"timestamp": now - (len(messages) - i), "message": m}
                                   for i, m in enumerate(messages)])


def test_logs_filter_patterns_and_metric_filter(client):
    logs, cw = client("logs"), client("cloudwatch")
    logs.create_log_group(logGroupName="/app")
    logs.create_log_stream(logGroupName="/app", logStreamName="s1")
    logs.put_metric_filter(logGroupName="/app", filterName="errors", filterPattern='{ $.level = "ERROR" }',
                           metricTransformations=[{"metricName": "Errors", "metricNamespace": "App",
                                                   "metricValue": "1"}])
    _put(logs, "/app", "s1", [json.dumps({"level": "ERROR", "ms": 900}), json.dumps({"level": "INFO", "ms": 10}),
                              "127.0.0.1 GET /index 500 1234", "plain WARN message"])
    match = lambda p: [e["message"] for e in logs.filter_log_events(logGroupName="/app", filterPattern=p)["events"]]  # noqa: E731
    assert len(match('{ $.ms > 100 }')) == 1
    assert match("WARN") == ["plain WARN message"]
    assert len(match("?WARN ?ERROR")) == 2
    assert match("[ip, method, path, status = 5*, bytes]") == ["127.0.0.1 GET /index 500 1234"]
    with pytest.raises(ClientError):
        logs.put_log_events(logGroupName="/app", logStreamName="s1", logEvents=[
            {"timestamp": 2000, "message": "b"}, {"timestamp": 1000, "message": "a"}])
    stats = cw.get_metric_statistics(Namespace="App", MetricName="Errors", StartTime=utc(-600), EndTime=utc(600),
                                     Period=1200, Statistics=["Sum"])
    assert stats["Datapoints"][0]["Sum"] == 1


def test_get_log_events_pagination_terminates(client):
    logs = client("logs")
    logs.create_log_group(logGroupName="/g")
    logs.create_log_stream(logGroupName="/g", logStreamName="s")
    _put(logs, "/g", "s", [f"line {i}" for i in range(25)])
    pages = list(logs.get_paginator("filter_log_events").paginate(logGroupName="/g",
                                                                   PaginationConfig={"PageSize": 10}))
    assert sum(len(p["events"]) for p in pages) == 25
    first = logs.get_log_events(logGroupName="/g", logStreamName="s", startFromHead=True, limit=10)
    assert first["events"][0]["message"] == "line 0"
    second = logs.get_log_events(logGroupName="/g", logStreamName="s", nextToken=first["nextForwardToken"], limit=100)
    assert len(second["events"]) == 15
    third = logs.get_log_events(logGroupName="/g", logStreamName="s", nextToken=second["nextForwardToken"])
    assert third["events"] == [] and third["nextForwardToken"] == second["nextForwardToken"]


def test_logs_insights_query(client):
    logs = client("logs")
    logs.create_log_group(logGroupName="/q")
    logs.create_log_stream(logGroupName="/q", logStreamName="s")
    _put(logs, "/q", "s", [json.dumps({"path": p, "ms": ms, "level": lv}) for p, ms, lv in
                           [("/a", 100, "INFO"), ("/a", 300, "ERROR"), ("/b", 50, "INFO"), ("/a", 500, "ERROR")]]
         + ["user=alice action=login"])
    now = int(time.time())
    qid = logs.start_query(logGroupName="/q", startTime=now - 600, endTime=now + 60,
                           queryString='filter level = "ERROR" | stats count(*) as n, avg(ms) as avg_ms by path')["queryId"]
    rows = logs.get_query_results(queryId=qid)["results"]
    assert [{f["field"]: f["value"] for f in r} for r in rows] == [{"path": "/a", "n": "2", "avg_ms": "400"}]
    qid = logs.start_query(logGroupName="/q", startTime=now - 600, endTime=now + 60,
                           queryString='parse @message "user=* action=*" as user, action | filter ispresent(user) '
                                       '| display user, action')["queryId"]
    rows = logs.get_query_results(queryId=qid)["results"]
    assert [(r[0]["value"], r[1]["value"]) for r in rows] == [("alice", "login")]
    with pytest.raises(ClientError) as e:
        logs.start_query(logGroupName="/q", startTime=now - 600, endTime=now, queryString="bogus command")
    assert e.value.response["Error"]["Code"] == "MalformedQueryException"
