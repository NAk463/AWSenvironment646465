#!/usr/bin/env bash
# 障害対応訓練シナリオ (インフラ層): 「Web サイトが 504 を返す」
#
#   原因: 運用担当 sato がセキュリティ強化のつもりで、Web サーバーの SG から
#         「ALB の SG からの 8080 番」を削除し、社内 CIDR からの許可に置き換えた
#   影響: ALB → ターゲットの通信が SG で破棄 → ヘルスチェックが Target.Timeout →
#         全ターゲット unhealthy → ALB はフェイルオープンで振り分け続ける → 10 秒の接続タイムアウトで 504
#
#   監視担当:      アラーム (HTTPCode_ELB_5XX_Count / UnHealthyHostCount) に気づく
#   運用:          ターゲットのヘルス状態の理由コード、ALB のメトリクスとアクセスログを見る
#   インフラ/上級: VPC フローログで REJECT を確認し、CloudTrail で誰が SG を変えたか突き止めて復旧する
#
# 前提: linux データプレーンで awsemu が動いていること (sudo awsemu serve)。ホストから 198.19.0.0/16 に届くこと。
set -euo pipefail

EP="${AWSEMU_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=ap-northeast-1 AWS_PAGER=""
aws() { command aws --endpoint-url "$EP" "$@"; }
emu() { awsemu --url "$EP" "$@"; }
step() { printf '\n\033[36m== %s\033[0m\n' "$*"; }
cmd() { printf '\033[33m$ %s\033[0m\n' "$*"; "$@"; }
q() { "$@" --output text; }

if ! curl -s "$EP/_emulator/state/ec2" | grep -q '"driver": "linux"'; then
  echo "linux データプレーンが必要です (sudo awsemu serve で起動してください)" >&2
  exit 1
fi

step "準備: VPC・ALB・Web サーバー 2 台・アラーム・フローログ"
emu reset >/dev/null
VPC=$(q aws ec2 create-vpc --cidr-block 10.0.0.0/16 --query Vpc.VpcId)
S1=$(q aws ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.0.1.0/24 --availability-zone ap-northeast-1a --query Subnet.SubnetId)
S2=$(q aws ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.0.2.0/24 --availability-zone ap-northeast-1c --query Subnet.SubnetId)
IGW=$(q aws ec2 create-internet-gateway --query InternetGateway.InternetGatewayId)
aws ec2 attach-internet-gateway --internet-gateway-id "$IGW" --vpc-id "$VPC"
RT=$(q aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC" --query 'RouteTables[0].RouteTableId')
aws ec2 create-route --route-table-id "$RT" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW" >/dev/null
ALBSG=$(q aws ec2 create-security-group --group-name alb-sg --description alb --vpc-id "$VPC" --query GroupId)
aws ec2 authorize-security-group-ingress --group-id "$ALBSG" --protocol tcp --port 80 --cidr 0.0.0.0/0 >/dev/null
WEBSG=$(q aws ec2 create-security-group --group-name web-sg --description web --vpc-id "$VPC" --query GroupId)
aws ec2 authorize-security-group-ingress --group-id "$WEBSG" --protocol tcp --port 8080 --source-group "$ALBSG" >/dev/null
UD='#!/bin/bash
mkdir -p www && cd www && echo "ok from $(hostname)" > index.html && echo ok > health
exec python3 -m http.server 8080'
W1=$(q aws ec2 run-instances --image-id ami-0a2023a1b2c3d4e5f --instance-type t3.micro --subnet-id "$S1" --security-group-ids "$WEBSG" --user-data "$UD" --query 'Instances[0].InstanceId')
W2=$(q aws ec2 run-instances --image-id ami-0a2023a1b2c3d4e5f --instance-type t3.micro --subnet-id "$S2" --security-group-ids "$WEBSG" --user-data "$UD" --query 'Instances[0].InstanceId')
LB=$(q aws elbv2 create-load-balancer --name shop-alb --subnets "$S1" "$S2" --security-groups "$ALBSG" --query 'LoadBalancers[0].LoadBalancerArn')
TG=$(q aws elbv2 create-target-group --name shop-tg --protocol HTTP --port 8080 --vpc-id "$VPC" --health-check-path /health \
  --health-check-interval-seconds 5 --health-check-timeout-seconds 2 --healthy-threshold-count 2 --unhealthy-threshold-count 2 \
  --query 'TargetGroups[0].TargetGroupArn')
aws elbv2 register-targets --target-group-arn "$TG" --targets "Id=$W1" "Id=$W2"
aws elbv2 create-listener --load-balancer-arn "$LB" --protocol HTTP --port 80 --default-actions "Type=forward,TargetGroupArn=$TG" >/dev/null
LBDIM=${LB#*loadbalancer/}
TGDIM=${TG##*:}
LBIP=$(q aws elbv2 describe-load-balancers --load-balancer-arns "$LB" --query 'LoadBalancers[0].AvailabilityZones[0].LoadBalancerAddresses[0].IpAddress')
aws cloudwatch put-metric-alarm --alarm-name shop-alb-5xx --namespace AWS/ApplicationELB --metric-name HTTPCode_ELB_5XX_Count \
  --dimensions "Name=LoadBalancer,Value=$LBDIM" --statistic Sum --period 60 --evaluation-periods 1 --threshold 0 \
  --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching
aws cloudwatch put-metric-alarm --alarm-name shop-unhealthy-hosts --namespace AWS/ApplicationELB --metric-name UnHealthyHostCount \
  --dimensions "Name=LoadBalancer,Value=$LBDIM" "Name=TargetGroup,Value=$TGDIM" --statistic Maximum --period 60 \
  --evaluation-periods 1 --threshold 0 --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching
aws iam create-role --role-name flowlogs-role --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"vpc-flow-logs.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
aws iam put-role-policy --role-name flowlogs-role --policy-name logs --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"*"}]}'
aws ec2 create-flow-logs --resource-type VPC --resource-ids "$VPC" --traffic-type ALL --log-group-name /vpc/shop \
  --deliver-logs-permission-arn arn:aws:iam::000000000000:role/flowlogs-role >/dev/null
aws iam create-user --user-name sato >/dev/null
aws iam attach-user-policy --user-name sato --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
read -r SK SS <<<"$(q aws iam create-access-key --user-name sato --query 'AccessKey.[AccessKeyId,SecretAccessKey]')"
echo "  ALB のパブリック IP: $LBIP (ヘルスチェックの完了を待っています...)"
sleep 12
for _ in 1 2 3; do curl -s -m 3 "http://$LBIP/"; done

step "(障害の仕込み) sato が web-sg を「社内からのみ」に変更"
AWS_ACCESS_KEY_ID=$SK AWS_SECRET_ACCESS_KEY=$SS aws ec2 authorize-security-group-ingress --group-id "$WEBSG" \
  --protocol tcp --port 8080 --cidr 192.168.10.0/24 >/dev/null
AWS_ACCESS_KEY_ID=$SK AWS_SECRET_ACCESS_KEY=$SS aws ec2 revoke-security-group-ingress --group-id "$WEBSG" \
  --protocol tcp --port 8080 --source-group "$ALBSG" >/dev/null
sleep 12
echo "  利用者のアクセス (各 10 秒ほどかかります):"
for _ in 1 2; do curl -s -m 15 -o /dev/null -w "  HTTP %{http_code} (%{time_total}s)\n" "http://$LBIP/" & done; wait
emu time advance 120 >/dev/null

step "[監視担当] アラームの通知履歴 (発火した時刻と理由)"
for alarm in shop-alb-5xx shop-unhealthy-hosts; do
  aws cloudwatch describe-alarm-history --alarm-name "$alarm" --history-item-type StateUpdate \
    --query 'AlarmHistoryItems[].[Timestamp,AlarmName,HistorySummary]' --output text | sed 's/^/  /'
done
cmd aws cloudwatch describe-alarms --alarm-names shop-unhealthy-hosts --query 'MetricAlarms[].[AlarmName,StateValue,StateReason]' --output text

step "[運用] ターゲットの状態と理由コード"
cmd aws elbv2 describe-target-health --target-group-arn "$TG" \
  --query 'TargetHealthDescriptions[].[Target.Id,TargetHealth.State,TargetHealth.Reason,TargetHealth.Description]' --output text
echo "  → Target.Timeout: ヘルスチェックの接続がタイムアウト = 経路か SG で通信が落ちている可能性"

step "[運用] ALB のエラー内訳 (ELB 自身が返した 5xx か、ターゲットが返したものか)"
for m in HTTPCode_ELB_504_Count HTTPCode_ELB_502_Count HTTPCode_Target_5XX_Count TargetConnectionErrorCount; do
  printf '  %-28s ' "$m"
  aws cloudwatch get-metric-statistics --namespace AWS/ApplicationELB --metric-name "$m" --dimensions "Name=LoadBalancer,Value=$LBDIM" \
    --start-time "$(date -u -d '-30 min' +%FT%TZ)" --end-time "$(date -u -d '+30 min' +%FT%TZ)" --period 3600 --statistics Sum \
    --query 'Datapoints[0].Sum' --output text
done

step "[インフラ] VPC フローログで ALB → ターゲット (8080) の REJECT を確認"
QID=$(q aws logs start-query --log-group-name /vpc/shop --start-time $(( $(date +%s) - 3600 )) --end-time $(( $(date +%s) + 3600 )) \
  --query-string 'parse @message "* * * * * * * * * * * * * *" as v, acct, eni, src, dst, sport, dport, proto, pk, by, st, en, action, status | filter action = "REJECT" and dport = "8080" | stats sum(pk) as packets by src, dst' \
  --query queryId)
cmd aws logs get-query-results --query-id "$QID" --query 'results[][].[field,value]' --output text

step "[インフラ] web-sg の現在のルール"
cmd aws ec2 describe-security-groups --group-ids "$WEBSG" \
  --query 'SecurityGroups[0].IpPermissions[].[IpProtocol,FromPort,IpRanges[0].CidrIp,UserIdGroupPairs[0].GroupId]' --output text
echo "  → ALB の SG ($ALBSG) からの許可が無い"

step "[上級] CloudTrail で、誰がいつ SG を変更したか"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=RevokeSecurityGroupIngress \
  --query 'Events[].CloudTrailEvent' --output json | python3 -c '
import json, sys
for raw in json.load(sys.stdin):
    e = json.loads(raw)
    print(" ", e["eventTime"], e["userIdentity"]["arn"], e["eventName"], json.dumps(e["requestParameters"], ensure_ascii=False)[:160])'

step "[復旧] ALB の SG からの許可を戻す"
cmd aws ec2 authorize-security-group-ingress --group-id "$WEBSG" --protocol tcp --port 8080 --source-group "$ALBSG" --output text --query Return
sleep 12
emu time advance 180 >/dev/null
for _ in 1 2; do curl -s -m 5 -o /dev/null -w "  HTTP %{http_code}\n" "http://$LBIP/"; done
cmd aws elbv2 describe-target-health --target-group-arn "$TG" --query 'TargetHealthDescriptions[].[Target.Id,TargetHealth.State]' --output text
cmd aws cloudwatch describe-alarms --alarm-names shop-alb-5xx shop-unhealthy-hosts --query 'MetricAlarms[].[AlarmName,StateValue]' --output text
