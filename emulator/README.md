# awsemu — 自作 AWS エミュレータ

LocalStack や Moto を使わずに、**AWS CLI / SDK からそのまま叩ける API** と、それに対応する **内部状態** をローカルで再現するエミュレータです。
Python 標準ライブラリだけで動き、外部依存はありません (Python 3.10+)。

現場のエンジニアが障害対応で見るもの (**CloudWatch アラーム・メトリクス、CloudWatch Logs、CloudTrail、IAM の権限エラー**) を、本物と同じ CLI コマンド・同じ形式で再現します。
さらに **EC2 / VPC / ALB は Linux のネットワーク名前空間で実体として動き**、インスタンスの起動、SG・NACL・ルートテーブルによる通信の可否、ALB の 502/503/504 まで実際のパケットで再現します。
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

## インフラ層 (EC2 / VPC / ALB)

### データプレーン

| モード | 条件 | 内容 |
| --- | --- | --- |
| `linux` | Linux + root (または privileged コンテナ) + iproute2 / iptables | VPC・サブネット・インスタンス・ALB をネットワーク名前空間で作り、実際に通信する |
| `simulated` | それ以外 (macOS、非 root) | API と状態遷移だけを再現する (プロセスや通信は無い) |

`awsemu serve --network auto` (既定) は可能なら linux、無理なら simulated で起動します。

```bash
sudo "$(command -v awsemu)" serve          # pipx で入れた場合は sudo の PATH に無いのでフルパスで
docker compose up -d awsemu               # privileged コンテナ内で linux モード (macOS でも可)
```

ホストに加える変更は veth 1 本 (`awsemu0`, 100.64.0.1) と `198.19.0.0/16` (パブリック IP 用) へのルートだけです。
ほかはすべて `awsemu-*` という名前の名前空間に作られ、停止時に削除されます。`AWSEMU_INTERNET=1` のときだけホストで NAT し、インスタンスから実インターネットに出られます。

```
[ホスト] ── awsemu-core (インターネット / AWS バックボーン)
                └─ awsemu-vpc<N> (VPC ルーター: ルートテーブル、IGW の 1:1 NAT、NACL、IMDS)
                     ├─ サブネットのブリッジ
                     │    ├─ awsemu-i-xxxx   (EC2 インスタンス: ENI = veth、SG = iptables)
                     │    ├─ awsemu-elb-xxxx (ALB: サブネットごとの ENI、SG、HTTP プロキシ)
                     │    └─ awsemu-nat-xxxx (NAT ゲートウェイ)
```

### EC2 インスタンス

- `run-instances` で起動したインスタンスは、専用のネットワーク名前空間・PID 名前空間・UTS 名前空間で動き、**ユーザーデータを root で実行** します (ホストのファイルシステムを共有する軽量な「コンテナ」)。1 台あたり数 MB
- インスタンスタイプに応じて cgroup でメモリと CPU を制限 (t3.micro = 1GiB / 2vCPU)。メモリを使い切ると OOM で落ちる
- 状態遷移 pending → running → stopping → stopped / shutting-down → terminated。停止/起動で自動割り当てのパブリック IP が変わる、終了保護、vCPU 上限 (`VcpuLimitExceeded`) も再現
- **IMDSv2** (`169.254.169.254`): トークン必須 (AL2023 AMI の既定)、インスタンスプロファイルのロールの一時認証情報、ユーザーデータ、identity document。インスタンスのポートを消費せず、SG の影響も受けない (本物と同じ)
- インスタンス内のプログラムは `AWS_ENDPOINT_URL=http://100.64.0.1:<port>` で awsemu の API を呼べる。ただし **本物と同じく、パブリック IP も NAT ゲートウェイも無いサブネットからは API に届かない**
- `iam:PassRole` の権限が無いとロール付きで起動できない (`UnauthorizedOperation` + `aws sts decode-authorization-message` で復号できるメッセージ)
- ステータスチェック (`describe-instance-status`): 起動直後は initializing、プロセスが落ちると instance impaired、`awsemu impair` でホスト障害 (system impaired、通信断) を発生させられる
- `get-console-output` でユーザーデータの出力を確認できる

```bash
awsemu exec i-0123456789abcdef0              # インスタンスにログイン (SSH / Session Manager の代わり。要 root)
awsemu exec i-0123456789abcdef0 -- ps aux    # インスタンス内でコマンドを実行
awsemu impair i-0123456789abcdef0 system     # ハードウェア障害を起こす (recover で復旧)
```

### VPC

- VPC (デフォルト VPC 172.31.0.0/16 も自動作成)、サブネット、ルートテーブル (関連付け・メインルートテーブル・**ターゲットが消えたルートは blackhole**)、IGW、NAT ゲートウェイ、Elastic IP (上限 5)、ENI
- **セキュリティグループ**: ステートフル (戻りの通信は自動許可、既存の接続はルール削除後も続く)、SG 参照 (`--source-group`) は所属 ENI の IP に展開
- **ネットワーク ACL**: ステートレス、ルール番号順に評価、サブネット境界でのみ適用。新規 NACL は全拒否、エフェメラルポートの許可漏れで応答が返らない、も再現
- パブリック IP を持たないインスタンスの IGW 向け通信は破棄される
- **VPC フローログ**: SG / NACL で ACCEPT / REJECT されたパケットを ENI ごとに集計し、CloudWatch Logs (ロールの信頼ポリシーと権限を検証) または S3 に配信。カスタムフォーマット対応

### ALB (ELBv2)

- ロードバランサー (2 AZ 以上必須、internet-facing はパブリック IP、internal はプライベート IP)、ターゲットグループ (instance / ip)、リスナー (HTTP)、ルール (path-pattern / host-header / http-header、forward / fixed-response / redirect)
- ALB 自身が VPC 内に ENI と SG を持つ。**ターゲット側 SG が ALB の SG を許可していないとヘルスチェックが `Target.Timeout`** になる
- ヘルスチェックを ALB から実際に HTTP で実行: `Target.Timeout` / `Target.FailedHealthChecks` / `Target.ResponseCodeMismatch` / `Target.NotInUse` / `Target.InvalidState` / `Elb.InitialHealthChecking`、登録解除時の draining
- 応答: 全ターゲットが unhealthy なら**フェイルオープン**で振り分け、接続拒否は **502**、接続タイムアウト (10 秒) とアイドルタイムアウト超過は **504**、ターゲットが無ければ **503**
- メトリクス (`AWS/ApplicationELB`): RequestCount, HTTPCode_ELB_5XX/502/503/504_Count, HTTPCode_Target_2XX..5XX_Count, TargetResponseTime, TargetConnectionErrorCount, HealthyHostCount, UnHealthyHostCount など
- **アクセスログ** を本物と同じ形式で S3 に出力 (バケットポリシーが無いと `InvalidConfigurationRequest`)。X-Forwarded-For / X-Amzn-Trace-Id を付与
- ALB の DNS 名はインスタンス内の `/etc/hosts` で解決できる。ホストからは `describe-load-balancers` の `LoadBalancerAddresses` の IP に直接アクセスする

### EC2 メトリクス

`AWS/EC2` の CPUUtilization (cgroup の CPU 時間)、NetworkIn/Out・NetworkPackets (ENI の実測値)、StatusCheckFailed 系。
**基本モニタリングは 5 分粒度** で発行されるため、Period 60 のアラームはデータ不足になる (本物と同じ)。`--monitoring Enabled=true` で 1 分粒度。

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
| IAM | ユーザー, グループ, ロール, 管理/インラインポリシー, ポリシーバージョン, アクセスキー (最終使用日時), インスタンスプロファイル, Simulate |
| EC2 | Run/Describe/Start/Stop/Reboot/TerminateInstances, DescribeInstanceStatus, GetConsoleOutput, Modify/DescribeInstanceAttribute, ModifyInstanceMetadataOptions, AssociateIamInstanceProfile, キーペア, DescribeImages, DescribeInstanceTypes, VPC / サブネット / ルートテーブル / IGW / NAT GW / EIP / SG (ルール ID 含む) / NACL / ENI / フローログ, タグ, DescribeAvailabilityZones |
| ELBv2 | Create/Describe/DeleteLoadBalancer, SetSecurityGroups, 属性, ターゲットグループ (作成・変更・属性), Register/DeregisterTargets, DescribeTargetHealth, リスナー, ルール, タグ |
| STS | GetCallerIdentity, AssumeRole, GetSessionToken, DecodeAuthorizationMessage |
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
| `AWSEMU_NETWORK` | `auto` | データプレーン: `auto` / `linux` / `simulated` |
| `AWSEMU_INTERNET` | `0` | `1` でインスタンスから実インターネットへ出られるようにする (ホストで NAT) |
| `AWSEMU_EC2_BOOT_SECONDS` / `AWSEMU_EC2_STOP_SECONDS` | `3` / `3` | pending / stopping の所要時間 (エミュレータの時計) |
| `AWSEMU_EC2_STATUS_INIT_SECONDS` | `60` | ステータスチェックが initializing の時間 |
| `AWSEMU_EC2_VCPU_LIMIT` | `32` | vCPU の上限 (8GB PC を守るためにも使う) |
| `AWSEMU_FLOWLOG_FLUSH_SECONDS` | `10` | フローログの配信間隔 (本物は約 10 分。`time advance` でも即時配信) |
| `AWSEMU_ELB_LOG_FLUSH_SECONDS` | `60` | ALB アクセスログの配信間隔 (本物は 5 分。`time advance` でも即時配信) |

## 制限事項

- 署名 (SigV4) の検証はしません (アクセスキー ID で呼び出し元を識別します)
- SCP、アクセス許可の境界、セッションポリシー、クロスアカウントは評価しません。AWS 管理ポリシーは簡略版です
- CloudTrail は本物より速く反映されます (本物は LookupEvents で数分、S3 配信で約 5 分の遅延)
- アラームアクション (SNS, Auto Scaling, EC2)、サブスクリプションフィルタ、X-Ray、Lambda、SNS、EventBridge は未実装 (フェーズ 2)
- インフラ層の未実装: Auto Scaling、RDS、EBS ボリューム操作、NLB、HTTPS リスナー、VPC エンドポイント / ピアリング / Transit Gateway、Route 53 (フェーズ 3b)
- EC2 インスタンスはホストのファイルシステムを共有する (AMI ごとの OS の違いは無い)。SSH の代わりに `awsemu exec` を使う。KVM による本物の VM は未対応
- IMDS のホップ制限 (HttpPutResponseHopLimit) は評価しない。EC2 / ELBv2 の状態はスナップショットに保存されない
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
