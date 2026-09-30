※ LocalStack 用です。awsemu では `awsemu snapshot load` で初期状態を復元するか、起動後に aws コマンドで作成してください。

LocalStack 起動完了時 (ready 段階) にこのディレクトリ内の `*.sh` がアルファベット順に実行されます。
障害を再現したい構成 (S3 バケット、SQS キュー、DynamoDB テーブルなど) を作成するスクリプトを置いてください。
コンテナ内では `awslocal` がそのまま使えます。
