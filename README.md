# AWS ローカル再現環境

実業務で起きた AWS 関連の障害を、個人 PC 上で再現・解析するためのツール群を自動インストールします。

## 導入されるツール

| コンポーネント | ツール | 用途 |
| --- | --- | --- |
| `base` | jq, git, unzip, python3, pipx | 基本ツール |
| `docker` | Docker Engine + Compose (macOS は Colima) | エミュレータの実行基盤 |
| `awscli` | AWS CLI v2 | AWS API の操作 |
| `pytools` | `localstack` CLI, `awslocal`, SAM CLI (`sam` / `samlocal`), `tflocal` | LocalStack の操作、Lambda/API Gateway のローカル実行、Terraform の LocalStack 向け実行 |
| `terraform` | Terraform (SHA256 検証付き) | 本番と同じ IaC で環境を再現 |
| `cdk` | Node.js, AWS CDK, `cdklocal` | CDK プロジェクトの再現 |
| `profile` | `~/.aws` の `localstack` プロファイル | `aws --profile localstack ...` で接続 |
| `env` | `.env` | docker compose の設定 |

`docker-compose.yml` で以下のコンテナも起動できます。

- **LocalStack** (`:4566`): S3 / SQS / SNS / DynamoDB / Lambda など多数の AWS サービスのエミュレータ
- **Moto** (`:5000`): Auth Token 不要の代替エミュレータ
- **Toxiproxy** (`:8474`, `:14566`): 遅延・タイムアウト・切断などのネットワーク障害注入

## 対応環境

- Ubuntu / Debian (x86_64, arm64)
- Windows は **WSL2 + Ubuntu** 上で実行 (Docker Desktop の WSL Integration を使う場合は `--skip docker`)
- macOS (Intel / Apple Silicon)。Homebrew が無ければ自動導入します

## 使い方

```bash
git clone <this repo> && cd AWSenvironment646465
./install.sh              # 全部入り (確認プロンプトあり)
./install.sh -y           # 確認なし
./install.sh --dry-run    # 実行内容の確認のみ
./install.sh --only awscli,pytools
./install.sh --skip cdk,terraform
./install.sh --upgrade    # 導入済みツールも最新化
./scripts/verify.sh       # 導入状況の確認
```

- `sudo` が必要なのは apt / Docker / Node.js (Linux) の導入時のみです。AWS CLI・Terraform・pipx・npm のツールは `~/.local` に入ります。
- 途中のコンポーネントが失敗しても残りは続行し、最後に失敗したものと再実行コマンドを表示します。
- Linux で初めて Docker を入れた場合、`docker` グループの反映のため一度ログアウトしてください。

## LocalStack の Auth Token について

LocalStack は 2026.03 以降、起動に Auth Token が必要になりました。

1. <https://app.localstack.cloud> でアカウントを作成し、Auth Token を取得 (非商用なら無料の Hobby プラン)
2. `.env` の `LOCALSTACK_AUTH_TOKEN=` に設定

業務起因の調査が Hobby プランの「非商用」に該当するかはご自身で規約を確認してください。
トークンを使わない場合は Moto を利用できます。

## 障害再現の流れ

```bash
# 1. エミュレータ起動
docker compose up -d localstack
./scripts/verify.sh

# 2. 本番と同じリソースを作成
#    - init/*.sh に awslocal コマンドを書く (起動時に自動実行。init/00-sample.sh.example 参照)
#    - または本番の IaC をそのまま流用
tflocal init && tflocal apply        # Terraform
cdklocal bootstrap && cdklocal deploy # CDK
samlocal deploy --guided              # SAM

# 3. 本番と同じ操作を実行
aws --profile localstack s3 ls
awslocal sqs list-queues

# 4. ログを確認
docker compose logs -f localstack    # LOCALSTACK_DEBUG=1 で詳細ログ
```

### ネットワーク障害の注入 (Toxiproxy)

タイムアウト、リトライ、スロットリング時の挙動など「通信が不安定なときにアプリがどう動くか」を再現できます。

```bash
docker compose --profile chaos up -d toxiproxy
./examples/chaos.sh latency 3000   # 3 秒遅延
./examples/chaos.sh timeout 5000   # 5 秒後に切断
./examples/chaos.sh down           # 接続拒否
./examples/chaos.sh reset          # 解除

# 障害を受ける側は 14566 番ポート経由で接続する
aws --profile localstack --endpoint-url http://localhost:14566 s3 ls \
  --cli-read-timeout 2 --cli-connect-timeout 2
```

### Moto を使う場合

```bash
docker compose --profile moto up -d moto
aws --profile localstack --endpoint-url http://localhost:5000 s3 ls
```

## 注意

- ローカルエミュレータは AWS の挙動を完全には再現しません (IAM 評価、クォータ、結果整合性の遅延など)。再現しない場合はエミュレータ側の差異も疑ってください。
- 業務データや本番の認証情報を個人 PC に持ち出さないよう、会社のルールに従ってください。ログや設定は必要に応じてマスキングしてから使いましょう。
