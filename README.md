# AWS ローカル再現環境

実業務で起きた AWS 関連の障害を、個人 PC 上で再現・解析するための環境です。

- **awsemu** (`emulator/`): LocalStack や Moto を使わない自作の AWS エミュレータ。AWS CLI / SDK から S3・SQS・DynamoDB・STS をそのまま叩けます。内部状態の表示、API 呼び出し履歴、障害注入、時計の操作ができます → [emulator/README.md](emulator/README.md)
- **install.sh**: AWS CLI などの周辺ツールを自動インストールします

## クイックスタート (awsemu)

```bash
git clone <this repo> && cd AWSenvironment646465
./install.sh --only base,awscli,awsemu,profile -y   # 最小構成
awsemu serve &                                      # http://localhost:4566

aws --profile localstack s3 mb s3://demo            # 本物の AWS CLI で操作
aws --profile localstack sqs create-queue --queue-name jobs
awsemu state                                        # 内部状態を確認
awsemu events --errors                              # エラーになった API 呼び出し
awsemu fault add --service dynamodb --operation PutItem \
  --error ProvisionedThroughputExceededException --status 400 --probability 0.5
awsemu time advance 60                              # 可視性タイムアウトや TTL を早送り
```

`localstack` プロファイルは install.sh が作る「endpoint_url=http://localhost:4566」の AWS CLI プロファイルです。名前に反して awsemu にもそのまま使えます。

障害再現のサンプル: `./examples/scenario-visibility-timeout.sh`
(SQS の可視性タイムアウト超過による二重処理と、古い ReceiptHandle での削除が効かない問題を再現)

## install.sh で導入されるツール

| コンポーネント | ツール | 用途 |
| --- | --- | --- |
| `base` | jq, git, unzip, python3, pipx | 基本ツール |
| `docker` | Docker Engine + Compose (macOS は Colima) | コンテナ実行基盤 |
| `awscli` | AWS CLI v2 | AWS API の操作 |
| `pytools` | `localstack` CLI, `awslocal`, SAM CLI (`sam` / `samlocal`), `tflocal` | LocalStack 用ツール、Lambda/API Gateway のローカル実行 |
| `awsemu` | 自作エミュレータ `awsemu` | S3 / SQS / DynamoDB / STS の再現 |
| `terraform` | Terraform (SHA256 検証付き) | 本番と同じ IaC で環境を再現 |
| `cdk` | Node.js, AWS CDK, `cdklocal` | CDK プロジェクトの再現 |
| `profile` | `~/.aws` の `localstack` プロファイル | `aws --profile localstack ...` で :4566 に接続 |
| `env` | `.env` | docker compose の設定 |

```bash
./install.sh              # 全部入り (確認プロンプトあり)
./install.sh -y           # 確認なし
./install.sh --dry-run    # 実行内容の確認のみ
./install.sh --only awscli,awsemu
./install.sh --skip cdk,terraform,pytools
./install.sh --upgrade    # 導入済みツールも最新化
./scripts/verify.sh       # 導入状況の確認
```

- 対応環境: Ubuntu / Debian (x86_64, arm64)、Windows は **WSL2 + Ubuntu**、macOS (Homebrew が無ければ自動導入)
- `sudo` が必要なのは apt / Docker / Node.js (Linux) の導入時のみです。それ以外は `~/.local` に入ります。
- 途中のコンポーネントが失敗しても残りは続行し、最後に失敗したものと再実行コマンドを表示します。
- Linux で初めて Docker を入れた場合、`docker` グループの反映のため一度ログアウトしてください。

## docker compose

```bash
docker compose up -d awsemu                            # awsemu (:4566、停止時に状態を保存)
docker compose --profile chaos up -d toxiproxy         # ネットワーク障害注入 (:8474, :14566)
docker compose --profile localstack up -d localstack   # LocalStack (要 Auth Token。awsemu と同じ :4566 なので排他)
docker compose --profile moto up -d moto               # Moto (:5000)
```

### ネットワーク障害の注入 (Toxiproxy)

awsemu 自体の障害注入は API 単位のエラーや遅延です。接続断や応答途中での切断など TCP レベルの障害は Toxiproxy で注入します。

```bash
docker compose up -d awsemu && docker compose --profile chaos up -d toxiproxy
./examples/chaos.sh latency 3000   # 3 秒遅延
./examples/chaos.sh timeout 5000   # 5 秒後に切断
./examples/chaos.sh down           # 接続拒否
./examples/chaos.sh reset          # 解除

# 障害を受ける側は 14566 番ポート経由で接続する
aws --profile localstack --endpoint-url http://localhost:14566 s3 ls \
  --cli-read-timeout 2 --cli-connect-timeout 2
```

LocalStack に向ける場合は `CHAOS_UPSTREAM=localstack:4566 ./examples/chaos.sh ...` としてください。

### LocalStack を使う場合

awsemu が対応していないサービス (Lambda、SNS、API Gateway など) が必要な場合は LocalStack を併用できます。
LocalStack は 2026.03 以降、起動に Auth Token が必要です。<https://app.localstack.cloud> で取得して `.env` の `LOCALSTACK_AUTH_TOKEN=` に設定してください (非商用なら無料の Hobby プラン。業務起因の調査が該当するかは規約をご確認ください)。

## 注意

- ローカルエミュレータは AWS の挙動を完全には再現しません (IAM 評価、クォータ、結果整合性の遅延など)。awsemu の制限事項は [emulator/README.md](emulator/README.md#制限事項) を参照してください。再現しない場合はエミュレータ側の差異も疑ってください。
- 業務データや本番の認証情報を個人 PC に持ち出さないよう、会社のルールに従ってください。ログや設定は必要に応じてマスキングしてから使いましょう。
