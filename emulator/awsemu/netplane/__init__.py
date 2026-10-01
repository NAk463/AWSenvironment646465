"""データプレーン (VPC の実体)。

- linux:     ネットワーク名前空間・veth・ブリッジ・iptables で実際にパケットが流れる VPC を作る (要 root)
- simulated: API と状態だけを再現する (root 不要、macOS 可。インスタンスのプロセスや通信は無い)
"""
from __future__ import annotations

import os
import sys

from .simulated import SimulatedNetplane


def create(mode: str | None = None):
    mode = (mode or os.environ.get("AWSEMU_NETWORK", "auto")).lower()
    if mode in ("off", "simulated", "none"):
        return SimulatedNetplane("無効化されています (AWSEMU_NETWORK=simulated)")
    from .linux import LinuxNetplane, available
    ok, reason = available()
    if ok:
        return LinuxNetplane()
    if mode == "linux":
        print(f"[netplane] linux データプレーンを利用できません: {reason}", file=sys.stderr)
        raise SystemExit(1)
    return SimulatedNetplane(reason)
