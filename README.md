# AWS ローカル再現環境

実業務で起きた AWS 関連の障害を、個人 PC 上で再現・解析するための環境です。

- **awsemu** (`emulator/`): LocalStack や Moto を使わない自作の AWS エミュレータ。AWS CLI / SDK から S3・SQS・DynamoDB・IAM・STS・CloudTrail・CloudWatch・CloudWatch Logs・EC2/VPC・ALB をそのまま叩けます。現場で見るもの (アラーム、メトリクス、ログ、CloudTrail、AccessDenied) を本物と同じ形式で再現し、EC2 / VPC / ALB は Linux のネットワーク名前空間で実際に動きます (SG・NACL・ルートテーブルで実際に通信が通る/通らない) → [emulator/README.md](emulator/README.md)
- **要件定義とロードマップ**: [docs/requirements.md](docs/requirements.md) (サーバーレス / VM・ネットワーク層 / ワークフロー / データ基盤まで段階的に拡張予定)
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
aws --profile localstack cloudwatch describe-alarms   # アラーム
aws --profile localstack logs tail /app/api --follow  # ログ
aws --profile localstack cloudtrail lookup-events     # 誰が何をしたか
awsemu time advance 60                              # 時計を早送り (アラーム評価・可視性タイムアウト・TTL)
```

`localstack` プロファイルは install.sh が作る「endpoint_url=http://localhost:4566」の AWS CLI プロファイルです。名前に反して awsemu にもそのまま使えます。

障害対応の訓練シナリオ:

| スクリプト | 内容 |
| --- | --- |
| `examples/scenario-throttling-incident.sh` | 「注文 API のエラー急増」を、監視担当 (アラーム) → 運用 (メトリクス・Logs Insights) → インフラ/上級 (CloudTrail で誰が DynamoDB の容量を下げたか特定) → 復旧、の流れで追体験 |
| `examples/scenario-alb-5xx-incident.sh` | 「Web サイトが 504 を返す」を、アラーム → ターゲットのヘルス状態 (Target.Timeout) → ALB メトリクス → VPC フローログの REJECT → CloudTrail で SG を変えた人を特定 → 復旧、の流れで追体験 (要 root / linux データプレーン) |
| `examples/scenario-visibility-timeout.sh` | SQS の可視性タイムアウト超過による二重処理と、古い ReceiptHandle での削除が効かない問題 |

EC2 / VPC / ALB を実体で動かすには root 権限が必要です (`sudo "$(command -v awsemu)" serve`、または `docker compose up -d awsemu`)。
root が無い環境では API と状態遷移だけを再現する simulated モードで動きます。詳細は [emulator/README.md](emulator/README.md#インフラ層-ec2--vpc--alb)。

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
docker compose up -d awsemu                            # awsemu (:4566、privileged で EC2/VPC/ALB を実体化、停止時に状態を保存)
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
