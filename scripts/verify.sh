#!/usr/bin/env bash
# 導入済みツールのバージョンと Docker / LocalStack の稼働状況を確認する
set -uo pipefail

export PATH="$HOME/.local/bin:$PATH"
missing=0

check() {
  local name="$1"; shift
  if command -v "$name" >/dev/null 2>&1; then
    printf '  %-12s %s\n' "$name" "$("$@" 2>&1 | head -n1)"
  else
    printf '  %-12s \e[31mMISSING\e[0m\n' "$name"
    missing=$((missing + 1))
  fi
}

echo "== ツール =="
check docker     docker --version
check aws        aws --version
check localstack sh -c 'localstack --version 2>/dev/null | tail -n1'
check awslocal   awslocal --version
check sam        sam --version
check samlocal   samlocal --version
check terraform  terraform version
check tflocal    tflocal version
check node       node --version
check cdk        cdk --version
check cdklocal   cdklocal --version
check jq         jq --version

echo "== Docker =="
if docker info >/dev/null 2>&1; then
  echo "  daemon       running"
  docker compose version 2>/dev/null | sed 's/^/  /'
else
  echo "  daemon       停止中 or 権限なし (docker グループ反映には再ログインが必要)"
fi

echo "== エミュレータ =="
if out="$(curl -fsS -m 2 http://localhost:4566/_localstack/health 2>/dev/null)"; then
  echo "  LocalStack   running ($(echo "$out" | jq -r '.edition + " " + .version' 2>/dev/null))"
else
  echo "  LocalStack   未起動 (docker compose up -d localstack)"
fi
if curl -fsS -m 2 http://localhost:5000/moto-api/ >/dev/null 2>&1; then
  echo "  Moto         running"
else
  echo "  Moto         未起動 (docker compose --profile moto up -d moto)"
fi

if (( missing )); then
  echo "未導入のツールが ${missing} 個あります" >&2
  exit 1
fi
