# 要件定義: ローカル AWS 障害再現環境

## 1. 目的

監視担当から上級クラウドエンジニアまでが **現場で見るもの** と **現場で行う作業** を、
8GB メモリのローカル PC 1 台で再現し、実業務の障害解析・訓練をプライベートで行えるようにする。

## 2. 利用者と業務

| ロール | 現場で見るもの | 現場で行う作業 |
| --- | --- | --- |
| 監視担当 | CloudWatch アラーム、メトリクスのグラフ | アラーム確認、一次切り分け、エスカレーション |
| 運用エンジニア | CloudWatch Logs / Logs Insights、CloudTrail | ログ検索、誰が何を変更したかの追跡、再実行・リドライブ |
| インフラエンジニア | VPC / サブネット / SG / ENI、EC2 の状態、ALB のターゲット状態、VPC Flow Logs | インスタンス作成・停止、SG やルートの修正、スケール |
| 上級 / SRE | X-Ray トレース、サービス間の依存、IAM の評価結果 | 根本原因分析、権限設計、容量設計、ゲームデイ |

## 3. 決定事項 (ヒアリング結果)

- 対象構成: サーバーレス、コンテナ/VM、ワークフロー、データ基盤の **すべて**
- 観測手段: CloudWatch メトリクス、CloudWatch Logs、CloudTrail、X-Ray の **すべて**
- 操作手段: **AWS CLI / SDK 互換** (現場と同じコマンドで確認できること)。Web コンソールは作らない
- IAM: **権限エラー (AccessDenied) を再現する**
- インフラ層: VPC・サブネット・ENI などのネットワーク境界を、Linux の仮想ネットワーク (network namespace / bridge / veth / iptables) とコンテナまたは VM で **実体として** 再現する
- 動作環境: **8GB メモリの PC 1 台** (Linux / WSL2 / macOS+Colima)

## 4. 基本方針

1. **API 互換**: 本物の AWS CLI / SDK が `--endpoint-url` だけで動くこと。エラーコード・メッセージも本物に合わせる
2. **観測の一貫性**: すべての API 呼び出しが CloudTrail に残り、各サービスが本物と同じ名前空間・ディメンションで CloudWatch メトリクスを出す。アラームが実際に発火する
3. **実体の再現**: EC2 は起動・SSH ログインできる実体 (コンテナ、必要なら軽量 VM)。VPC の境界は実際にパケットが通る/通らない形で再現する
4. **自然発生する障害**: 障害注入に頼らず、容量超過・権限不足・タイムアウトなど原因があれば本物と同じように障害が起きる
5. **軽量**: 制御プレーン (awsemu) は Python 標準ライブラリのみ。重いもの (VM、DB、k8s) は必要なときだけ起動する

## 5. 再現しない (できない) もの

- AWS マネジメントコンソールの GUI
- 物理障害 (AZ 障害、ハードウェア故障) そのもの。**影響の再現** (サブネット単位の遮断、インスタンス停止) で代替する
- 料金、Service Quotas の申請フロー、サポートケース
- AWS 内部の分散システムとしての挙動 (結果整合性の遅延などは、必要に応じて遅延注入で近似する)

## 6. メモリ予算 (8GB)

| 項目 | 目安 | 備考 |
| --- | --- | --- |
| OS + ブラウザ / エディタ | 3.0 GB | |
| Docker / WSL2 / Colima の VM | 0.8 GB | |
| awsemu 制御プレーン | 0.15 GB | 全サービスで 1 プロセス |
| EC2 インスタンス (コンテナ) | 0.05 GB × 10 | systemd + sshd の最小イメージ |
| EC2 インスタンス (本物の VM, 任意) | 0.5 GB × 2 | KVM が使える場合のみ |
| Lambda 実行環境 | 0.13 GB × 同時実行 4 | 同時実行数の上限を設定して抑える |
| RDS (MySQL/PostgreSQL コンテナ) | 0.3 GB × 1〜2 | |
| ALB (HAProxy / Envoy コンテナ) | 0.03 GB | |
| EKS (k3s, 任意) | 0.6 GB | 必要なときだけ |
| **合計** | **約 6〜7.5 GB** | 同時起動数を制限する設定を持つ |

## 7. フェーズ計画

| フェーズ | 内容 | 状態 |
| --- | --- | --- |
| 0 | S3 / SQS / DynamoDB / STS のデータプレーン、内部状態表示、障害注入、時計操作 | 完了 |
| 1 | **観測と権限の基盤**: IAM (認証・認可・AccessDenied)、CloudTrail、CloudWatch メトリクス/アラーム、CloudWatch Logs (+Logs Insights)、各サービスの標準メトリクス、DynamoDB の容量超過による自然なスロットリング、S3 バケットポリシー / SQS キューポリシー | **完了** |
| 2 | **サーバーレス**: Lambda (コンテナ実行、SQS/DynamoDB Streams のイベントソース、再試行・DLQ)、SNS、EventBridge、API Gateway、X-Ray (デーモン + API)、アラーム → SNS 通知 | 未着手 |
| 3a | **インフラ層 (ネットワークと計算)**: EC2 API、VPC / サブネット / ルートテーブル / IGW / NAT GW / EIP、ENI (veth)、セキュリティグループ (iptables, ステートフル)、NACL (ステートレス)、インスタンス (名前空間 + cgroup)、IMDSv2 とインスタンスプロファイル、VPC フローログ、EC2 メトリクスとステータスチェック、ALB / ターゲットグループ / ヘルスチェック (502/503/504)、ALB アクセスログ | **完了** |
| 3b | **インフラ層 (残り)**: Auto Scaling (アラーム連動のスケール)、RDS (MySQL/PostgreSQL コンテナ、フェイルオーバー)、EBS ボリューム、NLB、HTTPS リスナー (ACM)、VPC エンドポイント / ピアリング / Transit Gateway、Route 53、KVM による本物の VM (任意)、SSM Session Manager | 未着手 |
| 4 | **コンテナ・ワークフロー・データ**: ECS (Fargate 相当)、EKS (k3s)、Step Functions、EventBridge Scheduler、Batch、Kinesis、Firehose、Athena (DuckDB)、Glue カタログ | 未着手 |
| 5 | **訓練シナリオ**: ロール別のシナリオパック (アラーム対応 → ログ調査 → 原因特定 → 復旧)、ゲームデイ用スクリプト | 未着手 |

各フェーズは前のフェーズの基盤 (IAM 評価、CloudTrail 記録、メトリクス発行) の上に作るため、この順で進める。

## 8. フェーズ 1 の受け入れ基準 (すべて AWS CLI で確認済み。`emulator/tests` と `examples/scenario-throttling-incident.sh` に対応)

- [x] `aws iam create-user` / `create-access-key` で作ったキーで呼び出すと、ポリシーで許可されていない操作が本物と同じ `AccessDenied` になる (メッセージに principal・action・resource・理由を含む)
- [x] `aws sts assume-role` が信頼ポリシーを評価し、得た一時認証情報でロールの権限になる
- [x] `aws iam simulate-principal-policy` で評価結果を確認できる
- [x] S3 バケットポリシー、SQS キューポリシーの Allow / Deny が効く
- [x] `aws cloudtrail lookup-events` で管理イベントが本物の形式 (CloudTrailEvent JSON) で見える。証跡を作ればデータイベントを S3 / CloudWatch Logs に配信する
- [x] SQS / DynamoDB / S3 / Logs が `AWS/*` 名前空間の標準メトリクスを出し、`aws cloudwatch get-metric-data` / `get-metric-statistics` で取得できる
- [x] `aws cloudwatch put-metric-alarm` のアラームが時間経過で `ALARM` に遷移し、履歴が残る
- [x] `aws logs put-log-events` / `filter-log-events` / `tail` / `start-query` が動き、メトリクスフィルタでログからメトリクスを作れる
- [x] プロビジョンドモードの DynamoDB テーブルで、容量を超えると `ProvisionedThroughputExceededException` が自然に発生し、`ThrottledRequests` メトリクスに現れる

## 9. フェーズ 3a の受け入れ基準 (linux データプレーン、AWS CLI で確認済み。`emulator/tests/test_netplane.py` と `examples/scenario-alb-5xx-incident.sh` に対応)

- [x] `aws ec2 run-instances` のユーザーデータで起動した Web サーバーに、ホストからパブリック IP で HTTP アクセスできる
- [x] SG で許可していないポート、パブリック IP / NAT の無いプライベートサブネットからの外向き通信は届かない
- [x] SG 参照 (`--source-group`)、NAT ゲートウェイ経由の外向き通信、NACL のエフェメラルポート許可漏れが本物と同じ結果になる
- [x] IMDSv2 (トークン必須) とインスタンスロールの一時認証情報で、インスタンス内から API を呼ぶと IAM が評価される
- [x] `iam:PassRole` の不足が `UnauthorizedOperation` になり、`sts decode-authorization-message` で復号できる
- [x] ALB のヘルスチェックが `Target.Timeout` / `Target.FailedHealthChecks` になり、502 / 503 / 504 とフェイルオープンが再現される
- [x] `AWS/ApplicationELB`・`AWS/EC2` メトリクス、ALB アクセスログ (S3)、VPC フローログ (REJECT) で原因を追跡できる
