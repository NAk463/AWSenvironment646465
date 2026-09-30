# awsemu — 自作 AWS エミュレータ

LocalStack や Moto を使わずに、**AWS CLI / SDK からそのまま叩ける API** と、それに対応する **内部状態** をローカルで再現するエミュレータです。
Python 標準ライブラリだけで動き、外部依存はありません (Python 3.10+)。

現場のエンジニアが障害対応で見るもの (**CloudWatch アラーム・メトリクス、CloudWatch Logs、CloudTrail、IAM の権限エラー**) を、本物と同じ CLI コマンド・同じ形式で再現します。
要件と今後の計画は [docs/requirements.md](../docs/requirements.md) を参照してください。

## 起動

```bash
pipx install ./emulator            # リポジトリ直下の ./install.sh --only awsemu でも可
awsemu serve                       # http://127.0.0.1:4566
awsemu serve --state-file state.json   # 停止時に保存し、次回起動時に復元

cd emulator && python3 -m awsemu serve  # インストールせずに実行
docker compose up -d awsemu             # Docker (リポジトリ直下で実行)
```

```bash
aws --profile localstack s3 mb s3://demo          # install.sh が作るプロファイル (キー: test)
aws --endpoint-url http://localhost:4566 sqs create-queue --queue-name jobs
```

## 認証と権限 (IAM)

既定では **本物と同じように認証・認可を行います** (`AWSEMU_IAM=enforce`)。

- アクセスキー `test` は **root ユーザー** として扱われ、すべて許可されます (`AWSEMU_ROOT_ACCESS_KEYS` で変更可)
- `aws iam create-user` / `create-access-key` で作ったキーや、`aws sts assume-role` で得た一時認証情報で呼び出すと、ポリシーに従って評価されます
- 存在しないキー → `InvalidAccessKeyId` (S3) / `UnrecognizedClientException` (DynamoDB) / `InvalidClientTokenId` など、サービスごとに本物と同じエラー
- 期限切れの一時認証情報 → `ExpiredToken`
- すべて許可したい場合は `awsemu config --iam off` (または `AWSEMU_IAM=off`)

```bash
aws iam create-user --user-name alice
aws iam attach-user-policy --user-name alice --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam create-access-key --user-name alice      # このキーで呼び出すと…

# An error occurred (AccessDenied) when calling the PutObject operation: User: arn:aws:iam::000000000000:user/alice
# is not authorized to perform: s3:PutObject on resource: arn:aws:s3:::prod-data/b.txt
# because no identity-based policy allows the s3:PutObject action
```

評価するもの:
- ID ベースポリシー (ユーザー / グループ / ロールのインライン・管理ポリシー、ポリシーバージョン)
- リソースベースポリシー (S3 バケットポリシー、SQS キューポリシー、ロールの信頼ポリシー)
- `Allow` / 明示的 `Deny` / 暗黙的拒否、`Action`・`NotAction`・`Resource`・`NotResource`・`Principal`・`NotPrincipal`
- `Condition` (String / Numeric / Date / Bool / IpAddress / Arn / Null 系、`IfExists`、`ForAnyValue` / `ForAllValues`)、ポリシー変数 `${aws:username}`
- 条件キー: `aws:SourceIp`, `aws:username`, `aws:PrincipalArn`, `aws:CurrentTime`, `aws:RequestedRegion`, `s3:prefix`, `dynamodb:LeadingKeys` など
- `aws iam simulate-principal-policy` / `simulate-custom-policy` で評価結果を確認できます
- 主要な AWS 管理ポリシー (`AdministratorAccess`, `ReadOnlyAccess`, `AmazonS3ReadOnlyAccess` など) を収録 (内容は簡略版)

## 観測 (現場で見る画面)

### CloudTrail

- すべての API 呼び出しを本物と同じ形式 (`userIdentity`, `requestParameters`, `responseElements`, `errorCode` …) で記録
- `aws cloudtrail lookup-events` は本物と同じく **管理イベントのみ** を返します (S3 GetObject などのデータイベントは返らない)
- 証跡 (`create-trail` + `start-logging`) を作ると、イベントセレクタ (通常 / アドバンスド) に一致したイベントを **S3 (gzip JSON) と CloudWatch Logs に配信** します。バケットポリシーが不足していると本物と同じ `InsufficientS3BucketPolicyException`

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateTable
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=alice
```

### CloudWatch メトリクス / アラーム

各サービスが本物と同じ名前空間・メトリクス名・ディメンションでメトリクスを発行します。

| 名前空間 | 主なメトリクス |
| --- | --- |
| `AWS/SQS` | NumberOfMessagesSent / Received / Deleted, NumberOfEmptyReceives, SentMessageSize, ApproximateNumberOfMessagesVisible / NotVisible / Delayed, ApproximateAgeOfOldestMessage |
| `AWS/DynamoDB` | ConsumedRead/WriteCapacityUnits, ThrottledRequests, Read/WriteThrottleEvents, SuccessfulRequestLatency, ConditionalCheckFailedRequests, ReturnedItemCount, UserErrors, SystemErrors, ProvisionedRead/WriteCapacityUnits |
| `AWS/S3` | BucketSizeBytes, NumberOfObjects (日次)、リクエストメトリクス (AllRequests, 4xxErrors, 5xxErrors, FirstByteLatency … ※本物と同じく `put-bucket-metrics-configuration` で有効化したバケットのみ) |
| `AWS/Logs` | IncomingLogEvents, IncomingBytes |

- `put-metric-data`, `get-metric-data` (Metric Math: 四則演算, `METRICS()`, `SUM`/`AVG`/`MIN`/`MAX`, `FILL`, `ABS`)、`get-metric-statistics` (`p90` などのパーセンタイル)、`list-metrics`
- `put-metric-alarm` のアラームはエミュレータの時計に従って評価され、`OK` / `ALARM` / `INSUFFICIENT_DATA` に遷移します。`TreatMissingData`、`DatapointsToAlarm`、Metric Math アラームに対応。状態理由 (`StateReason`) と履歴 (`describe-alarm-history`) も本物と同じ形式
- アラームアクション (SNS 通知など) は次のフェーズで実装予定です。現在は履歴に「アクション失敗」として記録されます
- ゲージ系 (キューの滞留数など) は `AWSEMU_METRICS_INTERVAL` 秒 (既定 60) ごとにサンプリング。`awsemu time advance` で時計を進めると、その間のデータを 1 分間隔で補完します

### CloudWatch Logs

- ロググループ / ストリーム / `put-log-events` (時系列順・24 時間幅・古すぎ/新しすぎの検証)、保持期間
- `filter-log-events` と `aws logs tail` (`--follow` 含む)。フィルタパターンは用語 (`ERROR -DEBUG ?WARN`)、JSON (`{ $.level = "ERROR" && $.latency > 1000 }`)、スペース区切り (`[ip, ..., status = 5*, bytes]`)
- **メトリクスフィルタ**でログからメトリクスを作成 (`metricValue` に `1` / `$.latency` / `$bytes`、`defaultValue`、ディメンション)
- **Logs Insights** (`start-query` / `get-query-results`): `fields`, `filter`, `parse` (glob / 正規表現), `stats ... by bin(5m)`, `sort`, `limit`, `display`, `dedup`。JSON ログのフィールドは自動検出

## 自然に発生する障害

障害注入に頼らなくても、原因があれば本物と同じように障害が起きます。

- **DynamoDB のスロットリング**: プロビジョンドモードのテーブル / GSI はトークンバケットで容量を管理します (未使用分は最大 300 秒ぶんバースト)。超過すると `ProvisionedThroughputExceededException`。`BatchWriteItem` / `BatchGetItem` は不足分を `UnprocessedItems` / `UnprocessedKeys` で返します。GSI の容量不足によるテーブル書き込みのスロットリングも再現
- **権限不足**: ポリシーの付け忘れ、明示的 Deny、信頼ポリシーの不一致による `AccessDenied`
- **一時認証情報の期限切れ**: `ExpiredToken`
- **SQS**: 可視性タイムアウト切れによる二重処理、DLQ への移動、保持期間切れ
- **DynamoDB TTL**: 期限切れアイテムの削除 (`AWSEMU_DDB_TTL_DELAY` で削除遅延を再現)

## 対応 API

| サービス | 対応オペレーション |
| --- | --- |
| S3 | バケット / オブジェクト操作一式, マルチパート, ListObjectsV2, CopyObject, DeleteObjects, 条件付き書き込み, 署名付き URL, バケットポリシー, メトリクス設定 |
| SQS | キュー操作, Send/Receive/Delete (Batch), ChangeMessageVisibility, 属性, タグ, FIFO |
| DynamoDB | テーブル操作 (GSI/LSI, TTL, 削除保護), Put/Get/Update/DeleteItem, Query, Scan, Batch, Transact |
| IAM | ユーザー, グループ, ロール, 管理/インラインポリシー, ポリシーバージョン, アクセスキー (最終使用日時), Simulate |
| STS | GetCallerIdentity, AssumeRole, GetSessionToken |
| CloudTrail | LookupEvents, Create/Update/Delete/Describe/GetTrail, ListTrails, Start/StopLogging, GetTrailStatus, Put/GetEventSelectors |
| CloudWatch | PutMetricData, GetMetricData, GetMetricStatistics, ListMetrics, Put/Describe/DeleteAlarms, DescribeAlarmsForMetric, SetAlarmState, DescribeAlarmHistory, Enable/DisableAlarmActions, ダッシュボード |
| CloudWatch Logs | ロググループ / ストリーム, Put/Get/FilterLogEvents, 保持期間, メトリクスフィルタ, TestMetricFilter, StartQuery/GetQueryResults/StopQuery/DescribeQueries, タグ |

## 内部状態・履歴・障害注入・時計

```bash
awsemu state [s3|sqs|dynamodb|iam|cloudtrail|cloudwatch|logs]   # 内部状態
awsemu events --errors            # API 呼び出し履歴 (呼び出し元 principal 付き)
awsemu events -f                  # 追従表示
awsemu fault add --service dynamodb --operation PutItem --error InternalServerError --status 500 --probability 0.2
awsemu fault list | fault rm <id> | fault clear
awsemu time advance 300           # 時計を進める (アラーム評価・可視性タイムアウト・TTL・認証情報の期限)
awsemu snapshot save before.json / snapshot load before.json
awsemu config --iam off           # 認証・認可を無効化
awsemu reset
```

管理 API (`/_emulator`): `health`, `state[/<service>]`, `events`, `faults`, `time`, `snapshot`, `reset`, `config`, `tick`

## 環境変数

| 変数 | 既定値 | 内容 |
| --- | --- | --- |
| `AWSEMU_HOST` / `AWSEMU_PORT` | `127.0.0.1` / `4566` | 待ち受けアドレス |
| `AWSEMU_STATE_FILE` | なし | 状態ファイル |
| `AWSEMU_URL` | `http://localhost:4566` | CLI サブコマンドの接続先 |
| `AWSEMU_IAM` | `enforce` | `enforce`: 認証・認可を行う / `off`: すべて root 扱い |
| `AWSEMU_ROOT_ACCESS_KEYS` | `test` | root として扱うアクセスキー (カンマ区切り) |
| `AWSEMU_METRICS_INTERVAL` | `60` | ゲージ系メトリクスのサンプリングとアラーム評価の間隔 (秒) |
| `AWSEMU_DDB_INITIAL_BURST` | `60` | 新しいプロビジョンドテーブルが最初に持つバースト容量 (秒数) |
| `AWSEMU_DDB_TTL_DELAY` | `0` | TTL 期限切れから削除までの秒数 (本物は最大 48 時間程度) |
| `AWSEMU_HOSTNAME` | `localhost` | S3 仮想ホスト形式のベースドメイン |

## 制限事項

- 署名 (SigV4) の検証はしません (アクセスキー ID で呼び出し元を識別します)
- SCP、アクセス許可の境界、セッションポリシー、クロスアカウントは評価しません。AWS 管理ポリシーは簡略版です
- CloudTrail は本物より速く反映されます (本物は LookupEvents で数分、S3 配信で約 5 分の遅延)
- アラームアクション (SNS, Auto Scaling, EC2)、サブスクリプションフィルタ、X-Ray、Lambda、SNS、EventBridge、EC2/VPC は未実装 (フェーズ 2 以降)
- S3 のバージョニング・ライフサイクル・イベント通知、DynamoDB Streams / PartiQL、旧式パラメータ (`Expected` など) は未対応
- DynamoDB の 1MB ページ上限、パーティション単位のホットキー、テーブル作成中 (CREATING) の状態は再現しません
- SQS は JSON プロトコル、CloudWatch は JSON / CBOR プロトコルのみ (AWS CLI v2 / 最近の SDK が使う形式)
- データはメモリ上にあり、`--state-file` を指定したときだけ停止時に保存されます

## テスト

```bash
cd emulator
pip install -e '.[test]'
pytest
```
