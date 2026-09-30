#!/usr/bin/env bash
# Toxiproxy を使って LocalStack への通信に障害を注入する
#
#   ./examples/chaos.sh latency 3000   # 3 秒の遅延 (タイムアウト・リトライ挙動の再現)
#   ./examples/chaos.sh timeout 5000   # 5 秒後に切断 (応答なしの再現)
#   ./examples/chaos.sh down           # 接続拒否 (エンドポイント障害の再現)
#   ./examples/chaos.sh reset          # 障害を解除
#   ./examples/chaos.sh status
#
# 障害を受ける側のアプリは endpoint を http://localhost:14566 に向けてください。
#   aws --profile localstack --endpoint-url http://localhost:14566 s3 ls
set -euo pipefail

API="${TOXIPROXY_API:-http://localhost:8474}"
PROXY="localstack"

api() { curl -fsS -H 'Content-Type: application/json' "$@"; }

ensure_proxy() {
  if ! api "$API/proxies/$PROXY" >/dev/null 2>&1; then
    api -X POST "$API/proxies" \
      -d "{\"name\":\"$PROXY\",\"listen\":\"0.0.0.0:14566\",\"upstream\":\"localstack:4566\",\"enabled\":true}" >/dev/null
  fi
}

reset() {
  api -X POST "$API/reset" >/dev/null
}

add_toxic() {
  api -X POST "$API/proxies/$PROXY/toxics" -d "$1" >/dev/null
}

api "$API/version" >/dev/null 2>&1 || {
  echo "Toxiproxy に接続できません。'docker compose --profile chaos up -d toxiproxy' を実行してください。" >&2
  exit 1
}
ensure_proxy

case "${1:-status}" in
  latency)
    reset
    add_toxic "{\"name\":\"latency\",\"type\":\"latency\",\"stream\":\"downstream\",\"attributes\":{\"latency\":${2:-3000},\"jitter\":${3:-0}}}"
    echo "遅延 ${2:-3000}ms を注入しました" ;;
  timeout)
    reset
    add_toxic "{\"name\":\"timeout\",\"type\":\"timeout\",\"stream\":\"downstream\",\"attributes\":{\"timeout\":${2:-5000}}}"
    echo "${2:-5000}ms 後に切断するよう設定しました" ;;
  down)
    api -X POST "$API/proxies/$PROXY" -d '{"enabled":false}' >/dev/null
    echo "プロキシを停止しました (接続拒否)" ;;
  reset)
    reset
    echo "障害を解除しました" ;;
  status)
    api "$API/proxies/$PROXY" | jq . ;;
  *)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
