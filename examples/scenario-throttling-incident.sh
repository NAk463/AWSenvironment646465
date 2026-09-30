#!/usr/bin/env bash
# 障害対応訓練シナリオ: 「注文 API でエラー急増」→ 原因は誰かが DynamoDB の容量を下げたこと
#
#   監視担当:     アラームが ALARM になったことに気づく
#   運用:         メトリクスと Logs Insights で影響範囲を確認する
#   インフラ/上級: CloudTrail で「誰が・いつ・何を変えたか」を突き止め、復旧する
#
# 実行すると障害を仕込んだあと、各ステップで現場と同じ AWS CLI コマンドを実行して結果を表示する。
# 前提: awsemu が起動していること (awsemu serve / docker compose up -d awsemu)
set -euo pipefail

EP="${AWSEMU_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=ap-northeast-1 AWS_PAGER=""
aws() { command aws --endpoint-url "$EP" "$@"; }
emu() { awsemu --url "$EP" "$@"; }
step() { printf '\n\033[36m== %s\033[0m\n' "$*"; }
cmd() { printf '\033[33m$ %s\033[0m\n' "$*"; "$@"; }

step "準備: テーブル・ログ・アラーム・運用ユーザーを作成"
emu reset >/dev/null
aws dynamodb create-table --table-name Orders --attribute-definitions AttributeName=orderId,AttributeType=S \
  --key-schema AttributeName=orderId,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=50,WriteCapacityUnits=50 >/dev/null
aws logs create-log-group --log-group-name /app/orders-api
aws logs create-log-stream --log-group-name /app/orders-api --log-stream-name api-1
aws logs put-metric-filter --log-group-name /app/orders-api --filter-name errors \
  --filter-pattern '{ $.level = "ERROR" }' \
  --metric-transformations metricName=OrderApiErrors,metricNamespace=OrdersApp,metricValue=1
aws cloudwatch put-metric-alarm --alarm-name orders-ddb-throttling --namespace AWS/DynamoDB \
  --metric-name ThrottledRequests --dimensions Name=TableName,Value=Orders Name=Operation,Value=PutItem \
  --statistic Sum --period 60 --evaluation-periods 1 --threshold 0 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching
aws iam create-user --user-name tanaka >/dev/null
aws iam put-user-policy --user-name tanaka --policy-name dynamodb-admin \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"}]}'
read -r TK TS <<<"$(aws iam create-access-key --user-name tanaka --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)"

step "(障害の仕込み) 運用ユーザー tanaka がコスト削減のつもりで WCU を 50 → 2 に変更"
AWS_ACCESS_KEY_ID=$TK AWS_SECRET_ACCESS_KEY=$TS aws dynamodb update-table --table-name Orders \
  --provisioned-throughput ReadCapacityUnits=50,WriteCapacityUnits=2 >/dev/null
emu time advance 600 >/dev/null

step "(障害の仕込み) 注文 API に書き込みが集中 (3KB x 300 件 = 900 WCU。バースト容量 2 WCU x 300 秒 = 600 を超える)"
python3 - "$EP" <<'PY'
import json, sys, time, boto3
from botocore.config import Config
kw = dict(endpoint_url=sys.argv[1], region_name="ap-northeast-1", aws_access_key_id="test", aws_secret_access_key="test")
ddb = boto3.client("dynamodb", config=Config(retries={"total_max_attempts": 1}), **kw)
logs = boto3.client("logs", **kw)
events = []
for i in range(300):
    ms = int(time.time() * 1000)
    try:
        ddb.put_item(TableName="Orders", Item={"orderId": {"S": f"o-{i}"}, "body": {"S": "x" * 2900}})
        events.append({"timestamp": ms, "message": json.dumps({"level": "INFO", "msg": "order saved", "orderId": f"o-{i}"})})
    except ddb.exceptions.ProvisionedThroughputExceededException:
        events.append({"timestamp": ms, "message": json.dumps({"level": "ERROR", "msg": "failed to save order",
                                                                "orderId": f"o-{i}", "error": "ProvisionedThroughputExceededException"})})
logs.put_log_events(logGroupName="/app/orders-api", logStreamName="api-1", logEvents=events)
PY
emu time advance 60 >/dev/null

step "[監視担当] アラームの状態を確認する"
cmd aws cloudwatch describe-alarms --state-value ALARM --query 'MetricAlarms[].[AlarmName,StateValue,StateReason]' --output text

step "[運用] スロットリング件数と、アプリのエラー件数を確認する"
START=$(date -u -d '-30 min' +%FT%TZ); END=$(date -u -d '+30 min' +%FT%TZ)
cmd aws cloudwatch get-metric-statistics --namespace AWS/DynamoDB --metric-name ThrottledRequests \
  --dimensions Name=TableName,Value=Orders Name=Operation,Value=PutItem \
  --start-time "$START" --end-time "$END" --period 3600 --statistics Sum --query 'Datapoints[].Sum' --output text
cmd aws cloudwatch get-metric-statistics --namespace OrdersApp --metric-name OrderApiErrors \
  --start-time "$START" --end-time "$END" --period 3600 --statistics Sum --query 'Datapoints[].Sum' --output text

step "[運用] Logs Insights でエラーの内訳を集計する"
QID=$(aws logs start-query --log-group-name /app/orders-api --start-time $(( $(date +%s) - 3600 )) \
  --end-time $(( $(date +%s) + 3600 )) \
  --query-string 'filter level = "ERROR" | stats count(*) as errors by error' --query queryId --output text)
cmd aws logs get-query-results --query-id "$QID" --query 'results[][].[field,value]' --output text

step "[インフラ/上級] テーブルの現在の設定を確認する"
cmd aws dynamodb describe-table --table-name Orders --query 'Table.ProvisionedThroughput.[ReadCapacityUnits,WriteCapacityUnits]' --output text

step "[インフラ/上級] CloudTrail で、誰がいつテーブル設定を変えたかを調べる"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateTable \
  --query 'Events[].CloudTrailEvent' --output json | python3 -c '
import json, sys
for raw in json.load(sys.stdin):
    e = json.loads(raw)
    print(e["eventTime"], e["userIdentity"]["arn"], e["userIdentity"].get("accessKeyId"),
          "->", json.dumps(e["requestParameters"].get("provisionedThroughput")))'

step "[復旧] 容量を戻し、アラームが OK に戻ることを確認する"
aws dynamodb update-table --table-name Orders --provisioned-throughput ReadCapacityUnits=50,WriteCapacityUnits=50 >/dev/null
emu time advance 120 >/dev/null
cmd aws cloudwatch describe-alarms --alarm-names orders-ddb-throttling --query 'MetricAlarms[].[AlarmName,StateValue]' --output text
cmd aws cloudwatch describe-alarm-history --alarm-name orders-ddb-throttling --history-item-type StateUpdate \
  --query 'AlarmHistoryItems[].[Timestamp,HistorySummary]' --output text
