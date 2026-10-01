"""awsemu のコマンドラインインターフェース。

  python -m awsemu serve [--port 4566] [--state-file state.json]
  python -m awsemu state [s3|sqs|dynamodb]
  python -m awsemu events [--service sqs] [--errors] [--limit 50] [--follow]
  python -m awsemu fault add --service dynamodb --operation PutItem --error ProvisionedThroughputExceededException --status 400
  python -m awsemu fault list | fault rm <id> | fault clear
  python -m awsemu time advance 60
  python -m awsemu config [--iam enforce|off] [--root-keys test,admin]
  python -m awsemu exec i-xxxx -- ps aux          (インスタンス内でコマンド実行。引数なしでシェル)
  python -m awsemu impair i-xxxx system|instance|recover
  python -m awsemu reset [--service s3]
  python -m awsemu snapshot save FILE | snapshot load FILE
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from . import __version__

DEFAULT_URL = os.environ.get("AWSEMU_URL", "http://localhost:4566")


def call(url: str, method: str, path: str, body: Any = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{url.rstrip('/')}/_emulator/{path}", data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        sys.exit(f"error: {exc.code} {exc.read().decode()}")
    except urllib.error.URLError as exc:
        sys.exit(f"error: awsemu に接続できません ({url}): {exc.reason}")


def show(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def cmd_serve(args: argparse.Namespace) -> None:
    import threading

    from .netplane.linux import HOST_IP
    from .server import make_server

    server = make_server(args.host, args.port, verbose=not args.quiet, network=args.network)
    emu = server.emulator  # type: ignore[attr-defined]
    emu.api_port = args.port
    servers = [server]
    if emu.ec2.netplane.enabled and args.host not in ("0.0.0.0", HOST_IP):
        # インスタンス (VPC 内) から AWS API を呼べるよう、"インターネット側" のアドレスでも待ち受ける
        servers.append(make_server(HOST_IP, args.port, emulator=emu, verbose=not args.quiet, background=False))
    if args.state_file and os.path.exists(args.state_file):
        with open(args.state_file, encoding="utf-8") as f:
            emu.load(json.load(f))
        print(f"state loaded from {args.state_file}", file=sys.stderr)

    def shutdown(*_: Any) -> None:
        if args.state_file:
            tmp = args.state_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(emu.dump(), f, ensure_ascii=False)
            os.replace(tmp, args.state_file)
            print(f"state saved to {args.state_file}", file=sys.stderr)
        emu.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    np = emu.ec2.netplane
    print(f"awsemu listening on http://{args.host}:{args.port}  (services: {', '.join(sorted(emu.services))}, "
          f"iam={emu.iam_mode})", file=sys.stderr)
    print(f"data plane: {np.name}" + (f" ({np.reason})" if not np.enabled and getattr(np, 'reason', '') else
                                       f" (API for instances: http://{HOST_IP}:{args.port})" if np.enabled else ""),
          file=sys.stderr)
    for extra in servers[1:]:
        threading.Thread(target=extra.serve_forever, daemon=True).start()
    server.serve_forever()


def cmd_events(args: argparse.Namespace) -> None:
    query = f"events?limit={args.limit}"
    if args.service:
        query += f"&service={args.service}"
    if args.operation:
        query += f"&operation={args.operation}"
    if args.errors:
        query += "&errors=1"
    if not args.follow:
        events = call(args.url, "GET", query)
        if args.json:
            show(events)
        else:
            for e in events:
                print_event(e)
        return
    since = 0
    while True:
        for e in call(args.url, "GET", f"{query}&since={since}"):
            since = e["seq"]
            if args.json:
                print(json.dumps(e, ensure_ascii=False))
            else:
                print_event(e)
        time.sleep(0.5)


def print_event(e: dict[str, Any]) -> None:
    err = f"  {e['error']['code']}: {e['error']['message']}" if e.get("error") else ""
    fault = f"  [fault {e['fault_id']}]" if e.get("fault_id") else ""
    who = (e.get("principal") or "").split(":", 5)[-1]
    print(f"#{e['seq']:<5} {e['time'][11:23]} {e['service']:<10} {e['operation']:<26} "
          f"{e['resource'][:36]:<36} {who[:28]:<28} {e['status']}{err}{fault}")


def cmd_fault(args: argparse.Namespace) -> None:
    if args.action == "list":
        show(call(args.url, "GET", "faults"))
    elif args.action == "clear":
        show(call(args.url, "DELETE", "faults"))
    elif args.action == "rm":
        show(call(args.url, "DELETE", f"faults/{args.id}"))
    else:
        spec: dict[str, Any] = {"service": args.service, "operation": args.operation,
                                "probability": args.probability, "latency_ms": args.latency_ms,
                                "status": args.status}
        for key, value in (("resource", args.resource), ("error_code", args.error),
                           ("error_message", args.message), ("count", args.count)):
            if value is not None:
                spec[key] = value
        show(call(args.url, "POST", "faults", spec))


def cmd_snapshot(args: argparse.Namespace) -> None:
    if args.action == "save":
        with open(args.file, "w", encoding="utf-8") as f:
            json.dump(call(args.url, "GET", "snapshot"), f, ensure_ascii=False, indent=2)
        print(f"saved to {args.file}")
    else:
        with open(args.file, encoding="utf-8") as f:
            show(call(args.url, "PUT", "snapshot", json.load(f)))


def cmd_exec(args: argparse.Namespace) -> None:
    """インスタンスの中でコマンドを実行する (SSH / Session Manager の代わり)。ホストで root 権限が必要。"""
    pid = call(args.url, "GET", f"ec2/instances/{args.instance_id}/pid")["pid"]
    command = args.command or ["/bin/bash", "-l"]
    if command and command[0] == "--":
        command = command[1:] or ["/bin/bash", "-l"]
    root = os.path.join("/var/lib/awsemu/instances", args.instance_id)
    os.chdir(root if os.path.isdir(root) else "/")
    os.execvp("nsenter", ["nsenter", "-t", str(pid), "--pid", "--mount", "--uts", "--net", "--", *command])


def cmd_impair(args: argparse.Namespace) -> None:
    show(call(args.url, "POST", "ec2/impair", {"instance_id": args.instance_id, "kind": args.kind}))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="awsemu", description="自作 AWS エミュレータ")
    parser.add_argument("--version", action="version", version=f"awsemu {__version__}")
    parser.add_argument("--url", default=DEFAULT_URL, help="awsemu の URL (既定: $AWSEMU_URL or http://localhost:4566)")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("serve", help="サーバを起動する")
    p.add_argument("--host", default=os.environ.get("AWSEMU_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("AWSEMU_PORT", "4566")))
    p.add_argument("--state-file", default=os.environ.get("AWSEMU_STATE_FILE"),
                   help="起動時に読み込み、終了時に保存する状態ファイル")
    p.add_argument("--quiet", action="store_true", help="リクエストログを出力しない")
    p.add_argument("--network", choices=["auto", "linux", "simulated"], default=os.environ.get("AWSEMU_NETWORK", "auto"),
                   help="データプレーン。linux: 名前空間で実体を作る (要 root) / simulated: 状態のみ / auto: 可能なら linux")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("state", help="内部状態を表示する")
    p.add_argument("service", nargs="?")
    p.set_defaults(func=lambda a: show(call(a.url, "GET", f"state/{a.service}" if a.service else "state")))

    p = sub.add_parser("events", help="API 呼び出し履歴を表示する")
    p.add_argument("--service")
    p.add_argument("--operation")
    p.add_argument("--errors", action="store_true", help="エラーのみ")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--follow", "-f", action="store_true", help="tail -f のように追従する")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("fault", help="障害注入ルールを管理する")
    p.add_argument("action", choices=["add", "list", "rm", "clear"])
    p.add_argument("id", nargs="?")
    p.add_argument("--service", default="*")
    p.add_argument("--operation", default="*")
    p.add_argument("--resource", help="バケット/キュー/テーブル名などの部分一致")
    p.add_argument("--error", help="返すエラーコード (省略時は遅延のみ)")
    p.add_argument("--message")
    p.add_argument("--status", type=int, default=500)
    p.add_argument("--probability", type=float, default=1.0)
    p.add_argument("--latency-ms", type=int, default=0)
    p.add_argument("--count", type=int, help="発動回数の上限")
    p.set_defaults(func=cmd_fault)

    p = sub.add_parser("time", help="エミュレータ内の時計を操作する")
    p.add_argument("action", choices=["show", "advance"])
    p.add_argument("seconds", nargs="?", type=float, default=0)
    p.set_defaults(func=lambda a: show(call(a.url, "POST", "time", {"advance_seconds": a.seconds})
                                       if a.action == "advance" else call(a.url, "GET", "time")))

    p = sub.add_parser("config", help="IAM の強制モードなどの設定を表示/変更する")
    p.add_argument("--iam", choices=["enforce", "off"], help="enforce: 認証・認可を行う / off: すべて root 扱い")
    p.add_argument("--root-keys", help="root として扱うアクセスキー (カンマ区切り)")
    p.set_defaults(func=lambda a: show(call(a.url, "POST", "config", {
        **({"iam": a.iam} if a.iam else {}),
        **({"root_access_keys": a.root_keys.split(",")} if a.root_keys else {})})))

    p = sub.add_parser("exec", help="EC2 インスタンスの中でコマンドを実行する (引数なしならシェル)")
    p.add_argument("instance_id")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_exec)

    p = sub.add_parser("impair", help="EC2 インスタンスに障害を起こす (system / instance / recover)")
    p.add_argument("instance_id")
    p.add_argument("kind", choices=["system", "instance", "recover"])
    p.set_defaults(func=cmd_impair)

    p = sub.add_parser("reset", help="状態を初期化する")
    p.add_argument("--service")
    p.set_defaults(func=lambda a: show(call(a.url, "POST", f"reset?service={a.service}" if a.service else "reset")))

    p = sub.add_parser("snapshot", help="状態をファイルに保存/復元する")
    p.add_argument("action", choices=["save", "load"])
    p.add_argument("file")
    p.set_defaults(func=cmd_snapshot)

    args = parser.parse_args(argv)
    if not args.command:
        args = parser.parse_args(["serve", *(argv or sys.argv[1:])])
    args.func(args)


if __name__ == "__main__":
    main()
