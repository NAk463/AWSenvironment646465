# awsemu — 自作 AWS エミュレータ

LocalStack や Moto を使わずに、**AWS CLI / SDK からそのまま叩ける API** と、それに対応する **内部状態** をローカルで再現するエミュレータです。
Python 標準ライブラリだけで動き、外部依存はありません (Python 3.10+)。

障害解析向けに、次の機能を持っています。

- **内部状態の可視化**: バケット・キュー・テーブルの中身や、メッセージの状態 (可視 / 処理中 / 遅延) を JSON で確認
- **API 呼び出し履歴**: 全リクエストを CloudTrail のように記録 (エラーのみの絞り込み、`tail -f` 風の追従)
- **障害注入**: 特定の API にエラーや遅延を返す (スロットリング、5xx、タイムアウトなど)
- **時計の操作**: 可視性タイムアウト、遅延配信、TTL、保持期間を待たずに時間を進める
- **スナップショット**: 状態をファイルに保存・復元し、同じ状況を何度でも再現

## 起動

```bash
# pipx で導入 (リポジトリ直下の ./install.sh --only awsemu でも可)
pipx install ./emulator
awsemu serve                                   # http://127.0.0.1:4566
awsemu serve --state-file state.json           # 停止時に保存し、次回起動時に復元

# インストールせずに実行
cd emulator && python3 -m awsemu serve

# Docker
docker compose up -d awsemu                    # リポジトリ直下で実行
```

AWS CLI からは `--endpoint-url` を指定するか、install.sh が作る `localstack` プロファイル (endpoint_url=http://localhost:4566) を使います。

```bash
aws --profile localstack s3 mb s3://demo
aws --endpoint-url http://localhost:4566 sqs create-queue --queue-name jobs
```

SDK の場合も endpoint を向けるだけです (boto3: `boto3.client("s3", endpoint_url="http://localhost:4566")`)。
認証情報は何でも構いません (署名は検証しません)。

## 対応 API

| サービス | 対応オペレーション |
| --- | --- |
| S3 | CreateBucket, DeleteBucket, HeadBucket, ListBuckets, GetBucketLocation, GetBucketVersioning, PutObject, GetObject (Range / 条件付き), HeadObject, DeleteObject, DeleteObjects, CopyObject, ListObjects, ListObjectsV2, マルチパートアップロード一式, 署名付き URL |
| SQS | CreateQueue, DeleteQueue, GetQueueUrl, ListQueues, Get/SetQueueAttributes, PurgeQueue, SendMessage(Batch), ReceiveMessage, DeleteMessage(Batch), ChangeMessageVisibility(Batch), Tag/Untag/ListQueueTags |
| DynamoDB | Create/Describe/Update/Delete/ListTables, PutItem, GetItem, UpdateItem, DeleteItem, Query, Scan, BatchWriteItem, BatchGetItem, TransactWriteItems, TransactGetItems, Update/DescribeTimeToLive, Tag/Untag/ListTagsOfResource |
| STS | GetCallerIdentity, AssumeRole, GetSessionToken |

未対応のオペレーションは `NotImplemented` / `UnknownOperationException` を返します。

### 再現している挙動

**S3**
- バケット名のバリデーション、`BucketNotEmpty`、`NoSuchKey`、`NoSuchBucket`
- `If-None-Match: *` による条件付き書き込み (`PreconditionFailed`)
- ETag (MD5、マルチパートは `-N` 付き)、`Content-MD5` の検証 (`BadDigest`)
- ListObjectsV2 のページング、Delimiter による CommonPrefixes
- aws-chunked (CLI v2 のストリーミング署名 / チェックサムトレーラー) のデコード

**SQS**
- 可視性タイムアウト、`ChangeMessageVisibility`、遅延配信 (`DelaySeconds`)、ロングポーリング (`WaitTimeSeconds`)
- `RedrivePolicy` による DLQ への移動 (`maxReceiveCount` 超過時)
- 保持期間 (`MessageRetentionPeriod`) 切れによる削除
- 古い ReceiptHandle での `DeleteMessage` は「成功を返すが削除されない」
- FIFO キュー: 重複排除 (5 分)、同一メッセージグループの処理中ブロック
- SDK が検証する `MD5OfMessageBody` / `MD5OfMessageAttributes`
- エラーコードは AWS と同じ (`AWS.SimpleQueueService.NonExistentQueue` など)

**DynamoDB**
- 式: `ConditionExpression`、`FilterExpression`、`KeyConditionExpression`、`UpdateExpression` (SET/REMOVE/ADD/DELETE、`if_not_exists`、`list_append`、算術)、`ProjectionExpression`、ネストしたパス
- AWS と同じバリデーションエラー: **予約語** (`status`、`name`、`date` など)、未定義・未使用のプレースホルダ、キーの型不一致、キー属性の更新、400KB 超過、パスの重複
- `ConditionalCheckFailedException` (`ReturnValuesOnConditionCheckFailure` に対応)、`TransactionCanceledException` (`CancellationReasons` 付き)
- Query / Scan の `Limit` と `LastEvaluatedKey` によるページング (Limit はフィルタ前に適用)、GSI / LSI、射影 (KEYS_ONLY / INCLUDE)
- TTL (`AWSEMU_DDB_TTL_DELAY` 秒の削除遅延を設定可能)、削除保護

## 内部状態と履歴の確認

```bash
awsemu state                 # 全サービス
awsemu state sqs             # メッセージごとの state / receive_count / 再表示までの秒数
awsemu state dynamodb        # アイテムを素の JSON で表示
awsemu events                # 直近の API 呼び出し
awsemu events --errors       # エラーのみ
awsemu events -f             # 追従表示
awsemu events --service dynamodb --operation PutItem --json
```

HTTP でも取得できます: `curl localhost:4566/_emulator/state/sqs`

## 障害注入

```bash
# DynamoDB PutItem の 30% をスロットリングさせる
awsemu fault add --service dynamodb --operation PutItem \
  --error ProvisionedThroughputExceededException --status 400 --probability 0.3

# 特定バケットへの S3 アクセスを 3 回だけ 503 にする
awsemu fault add --service s3 --resource my-bucket --error SlowDown --status 503 --count 3

# SQS 全体に 2 秒の遅延 (エラーは返さない)
awsemu fault add --service sqs --latency-ms 2000

awsemu fault list
awsemu fault rm <id>
awsemu fault clear
```

SDK のリトライ設定やタイムアウトが意図どおり動くかを確認できます。
接続断など TCP レベルの障害は、リポジトリ直下の `examples/chaos.sh` (Toxiproxy) と組み合わせてください。

## 時計の操作とスナップショット

```bash
awsemu time advance 31       # 可視性タイムアウト切れや TTL 期限切れを即座に再現
awsemu time show

awsemu snapshot save before-incident.json
awsemu reset
awsemu snapshot load before-incident.json
```

## 管理 API (`/_emulator`)

| メソッド | パス | 内容 |
| --- | --- | --- |
| GET | `/_emulator/health` | 稼働確認 |
| GET | `/_emulator/state[/<service>]` | 内部状態 |
| GET / DELETE | `/_emulator/events?service=&operation=&errors=1&since=&limit=` | 呼び出し履歴 |
| GET / POST / DELETE | `/_emulator/faults[/<id>]` | 障害注入ルール |
| GET / POST | `/_emulator/time` (`{"advance_seconds": 30}`) | 時計 |
| GET / PUT | `/_emulator/snapshot` | 状態のダンプ / 復元 |
| POST | `/_emulator/reset[?service=s3]` | 初期化 (サービス指定なしなら履歴・障害・時計も初期化) |

## 環境変数

| 変数 | 既定値 | 内容 |
| --- | --- | --- |
| `AWSEMU_HOST` / `AWSEMU_PORT` | `127.0.0.1` / `4566` | 待ち受けアドレス |
| `AWSEMU_STATE_FILE` | なし | 状態ファイル |
| `AWSEMU_URL` | `http://localhost:4566` | CLI サブコマンドの接続先 |
| `AWSEMU_HOSTNAME` | `localhost` | S3 仮想ホスト形式のベースドメイン (`bucket.localhost`) |
| `AWSEMU_DDB_TTL_DELAY` | `0` | TTL 期限切れから削除までの秒数 (本番では最大 48 時間程度かかる) |

## 制限事項

- 署名 (SigV4)、IAM ポリシー、バケットポリシーは評価しません
- S3 のバージョニング・ライフサイクル・イベント通知、DynamoDB Streams、PartiQL、旧式パラメータ (`Expected`、`KeyConditions` など) は未対応
- SQS は JSON プロトコルのみ (AWS CLI v2 / 最近の SDK は JSON を使用)
- DynamoDB の 1MB ページ上限、キャパシティ計算、テーブル作成中 (CREATING) の状態は再現しません
- 結果整合性の遅延は再現しません (常に強い整合性で読める)
- データはメモリ上にあり、`--state-file` を指定したときだけ停止時に保存されます

## テスト

```bash
cd emulator
pip install -e '.[test]'
pytest
```
