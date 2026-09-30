#!/usr/bin/env bash
# 障害再現シナリオ: SQS の可視性タイムアウト超過による二重処理
#
#   1. ワーカー A がメッセージを受信し、決済を DynamoDB に書き込む
#   2. A の処理が VisibilityTimeout (30 秒) を超える  ※ awsemu の時計を進めて再現
#   3. 同じメッセージがワーカー B にも配信される (二重処理)
#   4. B の書き込みは冪等性チェック (条件付き書き込み) で弾かれる
#   5. A が古い ReceiptHandle で DeleteMessage → 成功が返るが実際には削除されない
#
# 前提: awsemu が起動していること (awsemu serve / docker compose up -d awsemu)
set -euo pipefail

EP="${AWSEMU_URL:-http://localhost:4566}"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=ap-northeast-1 AWS_PAGER=""
aws() { command aws --endpoint-url "$EP" "$@"; }
emu() { awsemu --url "$EP" "$@"; }
step() { printf '\n\033[36m== %s\033[0m\n' "$*"; }

step "環境を初期化"
emu reset >/dev/null
aws dynamodb create-table --table-name Payments --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=orderId,AttributeType=S \
  --key-schema AttributeName=orderId,KeyType=HASH >/dev/null
Q=$(aws sqs create-queue --queue-name payments --attributes VisibilityTimeout=30 --query QueueUrl --output text)
aws sqs send-message --queue-url "$Q" --message-body '{"orderId":"o-1001","amount":5000}' >/dev/null

process() {  # $1=ワーカー名 -> ReceiptHandle を返す
  local msg handle
  msg=$(aws sqs receive-message --queue-url "$Q" --attribute-names ApproximateReceiveCount \
        --query 'Messages[0].[ReceiptHandle,Attributes.ApproximateReceiveCount]' --output text)
  handle=${msg%%$'\t'*}
  echo "[$1] 受信 (ApproximateReceiveCount=${msg##*$'\t'})" >&2
  if aws dynamodb put-item --table-name Payments \
       --item '{"orderId":{"S":"o-1001"},"amount":{"N":"5000"},"worker":{"S":"'"$1"'"}}' \
       --condition-expression 'attribute_not_exists(orderId)' 2>/dev/null; then
    echo "[$1] 決済を記録しました" >&2
  else
    echo "[$1] ConditionalCheckFailed: 既に処理済み (冪等性チェックで二重課金を回避)" >&2
  fi
  echo "$handle"
}

step "ワーカー A が処理開始"
HANDLE_A=$(process worker-A)

step "A の処理が 31 秒かかる (時計を進める)"
emu time advance 31 >/dev/null

step "可視性タイムアウトが切れ、ワーカー B にも同じメッセージが届く"
HANDLE_B=$(process worker-B)

step "A が古い ReceiptHandle で削除 → 成功が返るがメッセージは消えない"
aws sqs delete-message --queue-url "$Q" --receipt-handle "$HANDLE_A" && echo "[worker-A] DeleteMessage 成功"
emu state sqs | python3 -c 'import json,sys; m=json.load(sys.stdin)["payments"]["messages"]; print("キュー内のメッセージ数:", len(m), [x["state"] for x in m])'

step "B が削除 → ここで初めて消える"
aws sqs delete-message --queue-url "$Q" --receipt-handle "$HANDLE_B"
emu state sqs | python3 -c 'import json,sys; print("キュー内のメッセージ数:", len(json.load(sys.stdin)["payments"]["messages"]))'

step "API 呼び出しの時系列 (エラーのみ)"
emu events --errors

step "DynamoDB の最終状態"
emu state dynamodb | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["Payments"]["items"], ensure_ascii=False))'
