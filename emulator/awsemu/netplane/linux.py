"""Linux のネットワーク名前空間で VPC を実体として再現するデータプレーン (要 root)。

トポロジ:

  [ホスト] awsemu0 (100.64.0.1) ──veth── core0 (100.64.0.2) [awsemu-core = インターネット/AWS バックボーン]
                                                │  v<N>c ──veth── up0 [awsemu-vpc<N> = VPC ルーター]
                                                │                    ├─ sb<M>  (サブネットのブリッジ, ゲートウェイ .1)
                                                │                    │    └─ ve<K> ──veth── eth0 [awsemu-i-xxxx = インスタンス]
                                                │                    └─ ...
  - ルートテーブル:      VPC ルーターの policy routing (サブネットのブリッジごとに ip rule → テーブル)
  - IGW / パブリック IP: VPC ルーターでの 1:1 NAT (パブリック IP を持たない送信元は IGW で破棄)
  - NAT ゲートウェイ:    パブリックサブネットに ENI を持つ名前空間で MASQUERADE
  - ネットワーク ACL:    VPC ルーターの FORWARD チェーン (ステートレス。サブネット内通信には効かない)
  - セキュリティグループ: 各 ENI の名前空間の INPUT/OUTPUT (conntrack によるステートフル)
  - フローログ:          NFLOG で ACCEPT/REJECT を収集

ホストに加える変更は veth 1 本 (awsemu0) と 198.19.0.0/16 へのルート 1 本だけ。AWSEMU_INTERNET=1 のときのみ
ホストで MASQUERADE を設定し、インスタンスから実インターネットへ出られるようにする。
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

PREFIX = os.environ.get("AWSEMU_NETNS_PREFIX", "awsemu")
CORE_NS = f"{PREFIX}-core"
HOST_IF = f"{PREFIX}0"
HOST_IP = "100.64.0.1"
CORE_IP = "100.64.0.2"
PUBLIC_POOL = ipaddress.ip_network("198.19.0.0/16")
NFLOG_GROUP = 33
CLONE_NEWNET = 0x40000000
INSTANCE_ROOT = os.environ.get("AWSEMU_INSTANCE_ROOT", "/var/lib/awsemu/instances")

_libc = ctypes.CDLL(None, use_errno=True)


def log(msg: str) -> None:
    print(f"[netplane] {msg}", file=sys.stderr, flush=True)


class NetplaneError(Exception):
    pass


def run(cmd: list[str], check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, input=input, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise NetplaneError(f"{' '.join(cmd)}: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def ip(*args: str, ns: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return run(["ip", *(["-n", ns] if ns else []), *args], check=check)


def nsexec(ns: str, *cmd: str, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
    return run(["ip", "netns", "exec", ns, *cmd], check=check, input=input)


def setns(ns: str) -> None:
    """呼び出したスレッドをネットワーク名前空間に移す (スレッド単位で有効)。"""
    fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
    try:
        if _libc.setns(fd, CLONE_NEWNET) != 0:
            err = ctypes.get_errno()
            raise NetplaneError(f"setns({ns}) failed: {os.strerror(err)}")
    finally:
        os.close(fd)


def run_in_netns(ns: str, fn: Callable[[], Any], name: str = "netns") -> threading.Thread:
    """名前空間内で fn を実行するデーモンスレッドを起動する (fn 内で作るソケット・スレッドもその名前空間に属する)。"""
    def target() -> None:
        setns(ns)
        fn()
    t = threading.Thread(target=target, name=f"{name}:{ns}", daemon=True)
    t.start()
    return t


def call_in_netns(ns: str, fn: Callable[[], Any]) -> Any:
    """名前空間内で fn を同期実行して結果を返す (ソケットの作成などに使う)。"""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            setns(ns)
            box["v"] = fn()
        except BaseException as exc:  # noqa: BLE001
            box["e"] = exc
    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join()
    if "e" in box:
        raise box["e"]
    return box.get("v")


def netns_exists(ns: str) -> bool:
    return os.path.exists(f"/run/netns/{ns}")


def available() -> tuple[bool, str]:
    if not sys.platform.startswith("linux"):
        return False, "Linux 以外では利用できません"
    if os.geteuid() != 0:
        return False, "root 権限が必要です (sudo awsemu serve または privileged コンテナで実行)"
    for tool in ("ip", "iptables-restore"):
        if shutil.which(tool) is None:
            return False, f"{tool} が見つかりません (iproute2 / iptables をインストールしてください)"
    return True, ""


# ============================================================================ rule specs
@dataclass
class SgRule:
    protocol: str            # "-1" | "tcp" | "udp" | "icmp" | 番号
    from_port: int | None
    to_port: int | None
    cidr: str


@dataclass
class NaclEntry:
    number: int
    protocol: str
    action: str              # allow | deny
    cidr: str
    from_port: int | None
    to_port: int | None


@dataclass
class RouterSpec:
    """VPC ルーターの完全な設定。変更のたびに作り直して丸ごと適用する。"""

    subnets: dict[int, str] = field(default_factory=dict)                 # subnet idx -> CIDR
    tables: dict[int, list[tuple[str, str, str | None]]] = field(default_factory=dict)
    # subnet idx -> [(destination, kind, nexthop)] kind: igw | via | blackhole
    nacl_in: dict[int, list[NaclEntry]] = field(default_factory=dict)
    nacl_out: dict[int, list[NaclEntry]] = field(default_factory=dict)
    public_map: dict[str, str] = field(default_factory=dict)              # private IP -> public IP
    flowlog: bool = False


PROTO_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "tcp": "tcp", "udp": "udp", "icmp": "icmp"}


def _match(protocol: str, from_port: int | None, to_port: int | None) -> str:
    proto = PROTO_NAMES.get(str(protocol).lower(), str(protocol))
    if proto in ("-1", "all"):
        return ""
    parts = f"-p {proto}"
    if proto in ("tcp", "udp") and from_port is not None and from_port >= 0:
        to = to_port if to_port is not None and to_port >= 0 else from_port
        if not (from_port == 0 and to == 65535):
            parts += f" --dport {from_port}" + (f":{to}" if to != from_port else "")
    return parts


# ============================================================================ driver
class LinuxNetplane:
    enabled = True
    name = "linux"

    def __init__(self, internet: bool | None = None) -> None:
        self.internet = internet if internet is not None else os.environ.get("AWSEMU_INTERNET") == "1"
        self.lock = threading.RLock()
        self.processes: dict[str, subprocess.Popen] = {}
        self.cgroups: dict[str, list[str]] = {}
        self._core_ready = False

    # ------------------------------------------------------------------ lifecycle
    def cleanup_all(self) -> None:
        """前回の実行で残った名前空間・インターフェースを削除する。"""
        with self.lock:
            for proc in list(self.processes.values()):
                self._kill(proc)
            self.processes.clear()
            listing = run(["ip", "netns", "list"], check=False).stdout
            for line in listing.splitlines():
                ns = line.split()[0] if line.split() else ""
                if ns.startswith(f"{PREFIX}-"):
                    for pid in run(["ip", "netns", "pids", ns], check=False).stdout.split():
                        try:
                            os.kill(int(pid), signal.SIGKILL)
                        except (ProcessLookupError, ValueError):
                            pass
                    run(["ip", "netns", "del", ns], check=False)
                    shutil.rmtree(f"/etc/netns/{ns}", ignore_errors=True)
            ip("link", "del", HOST_IF, check=False)
            ip("route", "del", str(PUBLIC_POOL), check=False)
            if self.internet:
                run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "100.64.0.0/10", "!", "-d", "100.64.0.0/10",
                     "-j", "MASQUERADE"], check=False)
            self._core_ready = False

    def ensure_core(self) -> None:
        with self.lock:
            if self._core_ready:
                return
            if not netns_exists(CORE_NS):
                ip("netns", "add", CORE_NS)
            ip("link", "set", "lo", "up", ns=CORE_NS)
            if ip("link", "show", HOST_IF, check=False).returncode != 0:
                ip("link", "add", HOST_IF, "type", "veth", "peer", "name", "core0", "netns", CORE_NS)
            ip("addr", "replace", f"{HOST_IP}/30", "dev", HOST_IF)
            ip("link", "set", HOST_IF, "up")
            ip("addr", "replace", f"{CORE_IP}/30", "dev", "core0", ns=CORE_NS)
            ip("link", "set", "core0", "up", ns=CORE_NS)
            ip("route", "replace", "default", "via", HOST_IP, ns=CORE_NS)
            nsexec(CORE_NS, "sysctl", "-qw", "net.ipv4.ip_forward=1")
            nsexec(CORE_NS, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
            ip("route", "replace", str(PUBLIC_POOL), "via", CORE_IP, "dev", HOST_IF)
            if self.internet:
                run(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
                rule = ["POSTROUTING", "-s", "100.64.0.0/10", "!", "-d", "100.64.0.0/10", "-j", "MASQUERADE"]
                if run(["iptables", "-t", "nat", "-C", *rule], check=False).returncode != 0:
                    run(["iptables", "-t", "nat", "-A", *rule])
            self._core_ready = True

    # ------------------------------------------------------------------ VPC router
    @staticmethod
    def vpc_ns(vpc_idx: int) -> str:
        return f"{PREFIX}-vpc{vpc_idx}"

    def ensure_vpc(self, vpc_idx: int) -> None:
        with self.lock:
            self.ensure_core()
            ns = self.vpc_ns(vpc_idx)
            if netns_exists(ns):
                return
            ip("netns", "add", ns)
            ip("link", "set", "lo", "up", ns=ns)
            for key in ("net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0",
                        "net.ipv4.conf.all.send_redirects=0", "net.ipv4.conf.default.send_redirects=0"):
                nsexec(ns, "sysctl", "-qw", key)
            nsexec(ns, "sysctl", "-qw", "net.bridge.bridge-nf-call-iptables=0", check=False)
            core_if = f"v{vpc_idx}c"
            ip("link", "add", core_if, "netns", CORE_NS, "type", "veth", "peer", "name", "up0", "netns", ns)
            ip("addr", "add", f"100.65.{vpc_idx}.1/30", "dev", core_if, ns=CORE_NS)
            ip("link", "set", core_if, "up", ns=CORE_NS)
            ip("addr", "add", f"100.65.{vpc_idx}.2/30", "dev", "up0", ns=ns)
            ip("link", "set", "up0", "up", ns=ns)

    def delete_vpc(self, vpc_idx: int) -> None:
        with self.lock:
            ip("link", "del", f"v{vpc_idx}c", ns=CORE_NS, check=False)
            ip("netns", "del", self.vpc_ns(vpc_idx), check=False)

    def ensure_subnet(self, vpc_idx: int, subnet_idx: int, cidr: str) -> None:
        with self.lock:
            ns = self.vpc_ns(vpc_idx)
            br = f"sb{subnet_idx}"
            if ip("link", "show", br, ns=ns, check=False).returncode == 0:
                return
            net = ipaddress.ip_network(cidr)
            ip("link", "add", br, "type", "bridge", ns=ns)
            ip("addr", "add", f"{net.network_address + 1}/{net.prefixlen}", "dev", br, ns=ns)
            ip("link", "set", br, "up", ns=ns)

    def delete_subnet(self, vpc_idx: int, subnet_idx: int) -> None:
        with self.lock:
            ip("link", "del", f"sb{subnet_idx}", ns=self.vpc_ns(vpc_idx), check=False)

    def set_public_routes(self, routes: dict[str, int]) -> None:
        """コアでのパブリック IP の経路 (public IP -> VPC index)。"""
        with self.lock:
            self.ensure_core()
            current = ip("route", "show", "proto", "static", ns=CORE_NS, check=False).stdout
            existing = {line.split()[0] for line in current.splitlines() if line.startswith("198.19.")}
            for pub in existing - set(routes):
                ip("route", "del", pub, ns=CORE_NS, check=False)
            for pub, vpc_idx in routes.items():
                ip("route", "replace", f"{pub}/32", "via", f"100.65.{vpc_idx}.2", "proto", "static", ns=CORE_NS)

    def apply_router(self, vpc_idx: int, spec: RouterSpec) -> None:
        with self.lock:
            ns = self.vpc_ns(vpc_idx)
            # ---- routing: サブネットごとのテーブル
            rules = ip("rule", "show", ns=ns).stdout
            for line in rules.splitlines():
                if "iif sb" in line:
                    pref = line.split(":", 1)[0]
                    ip("rule", "del", "pref", pref, ns=ns, check=False)
            for sidx, routes in spec.tables.items():
                table = str(1000 + sidx)
                ip("route", "flush", "table", table, ns=ns, check=False)
                for other_idx, other_cidr in spec.subnets.items():
                    ip("route", "add", other_cidr, "dev", f"sb{other_idx}", "table", table, ns=ns, check=False)
                for dest, kind, nexthop in routes:
                    if kind == "igw":
                        ip("route", "replace", dest, "via", f"100.65.{vpc_idx}.1", "dev", "up0", "table", table, ns=ns)
                    elif kind == "via" and nexthop:
                        dev_idx = next((i for i, c in spec.subnets.items()
                                        if ipaddress.ip_address(nexthop) in ipaddress.ip_network(c)), None)
                        if dev_idx is None:
                            ip("route", "replace", "blackhole", dest, "table", table, ns=ns)
                        else:
                            ip("route", "replace", dest, "via", nexthop, "dev", f"sb{dev_idx}", "table", table, ns=ns)
                    else:
                        ip("route", "replace", "blackhole", dest, "table", table, ns=ns)
                ip("rule", "add", "iif", f"sb{sidx}", "lookup", table, "pref", str(100 + sidx), ns=ns)
            # ---- iptables: NACL + IGW + 1:1 NAT
            lines = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
                     ":AWS-NOPUBLIC - [0:0]", ":AWS-NACL-DENY - [0:0]"]
            for sidx in spec.subnets:
                lines += [f":NACL-IN-{sidx} - [0:0]", f":NACL-OUT-{sidx} - [0:0]"]
            for sidx in spec.subnets:
                lines.append(f"-A FORWARD -i sb{sidx} -j NACL-OUT-{sidx}")
                lines.append(f"-A FORWARD -o sb{sidx} -j NACL-IN-{sidx}")
            for priv in spec.public_map:
                lines.append(f"-A FORWARD -o up0 -s {priv}/32 -j ACCEPT")
            lines.append("-A FORWARD -o up0 -j AWS-NOPUBLIC")
            lines.append("-A AWS-NOPUBLIC -j DROP")
            if spec.flowlog:
                lines.append(f"-A AWS-NACL-DENY -j NFLOG --nflog-group {NFLOG_GROUP} --nflog-prefix R")
            lines.append("-A AWS-NACL-DENY -j DROP")
            for direction, table in (("IN", spec.nacl_in), ("OUT", spec.nacl_out)):
                for sidx in spec.subnets:
                    for e in sorted(table.get(sidx, []), key=lambda x: x.number):
                        addr = f"-s {e.cidr}" if direction == "IN" else f"-d {e.cidr}"
                        target = "RETURN" if e.action == "allow" else "AWS-NACL-DENY"
                        lines.append(f"-A NACL-{direction}-{sidx} {_match(e.protocol, e.from_port, e.to_port)} "
                                     f"{addr} -j {target}".replace("  ", " "))
                    lines.append(f"-A NACL-{direction}-{sidx} -j AWS-NACL-DENY")
            lines.append("COMMIT")
            lines += ["*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
                      ":POSTROUTING ACCEPT [0:0]"]
            for priv, pub in spec.public_map.items():
                lines.append(f"-A PREROUTING -i up0 -d {pub}/32 -j DNAT --to-destination {priv}")
                lines.append(f"-A POSTROUTING -o up0 -s {priv}/32 -j SNAT --to-source {pub}")
            lines.append("COMMIT")
            nsexec(ns, "iptables-restore", input="\n".join(lines) + "\n")
            # パブリック IP 宛ての ARP/ルーティング: DNAT 後の宛先はブリッジ側の接続経路で届く

    # ------------------------------------------------------------------ hosts (instance / ALB / NAT GW)
    @staticmethod
    def host_ns(resource_id: str) -> str:
        return f"{PREFIX}-{resource_id}"

    def ensure_host(self, resource_id: str, hostname: str | None = None, hosts: str = "",
                    resolv: str = "") -> str:
        with self.lock:
            ns = self.host_ns(resource_id)
            if not netns_exists(ns):
                ip("netns", "add", ns)
                ip("link", "set", "lo", "up", ns=ns)
                nsexec(ns, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0", check=False)
            etc = f"/etc/netns/{ns}"
            os.makedirs(etc, exist_ok=True)
            if hostname is not None:
                with open(f"{etc}/hosts", "w") as f:
                    f.write(f"127.0.0.1 localhost\n{hosts}")
                with open(f"{etc}/hostname", "w") as f:
                    f.write(hostname + "\n")
                with open(f"{etc}/resolv.conf", "w") as f:
                    f.write(resolv or "nameserver 8.8.8.8\n")
            return ns

    def update_hosts_file(self, resource_id: str, hosts: str) -> None:
        path = f"/etc/netns/{self.host_ns(resource_id)}/hosts"
        if os.path.isdir(os.path.dirname(path)):
            with open(path, "w") as f:
                f.write(f"127.0.0.1 localhost\n{hosts}")

    def delete_host(self, resource_id: str) -> None:
        with self.lock:
            ns = self.host_ns(resource_id)
            proc = self.processes.pop(resource_id, None)
            if proc:
                self._kill(proc)
            for pid in run(["ip", "netns", "pids", ns], check=False).stdout.split():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except (ProcessLookupError, ValueError):
                    pass
            ip("netns", "del", ns, check=False)
            shutil.rmtree(f"/etc/netns/{ns}", ignore_errors=True)
            self._remove_cgroup(resource_id)

    def attach_eni(self, resource_id: str, dev: str, vpc_idx: int, eni_idx: int, subnet_idx: int, address: str,
                   prefix: int, gateway: str, mac: str, default_route: bool = True) -> None:
        with self.lock:
            ns = self.host_ns(resource_id)
            vns = self.vpc_ns(vpc_idx)
            router_if = f"ve{eni_idx}"
            if ip("link", "show", router_if, ns=vns, check=False).returncode != 0:
                ip("link", "add", router_if, "netns", vns, "type", "veth", "peer", "name", dev, "netns", ns)
            ip("link", "set", router_if, "master", f"sb{subnet_idx}", "up", ns=vns)
            ip("link", "set", dev, "address", mac, ns=ns)
            ip("addr", "replace", f"{address}/{prefix}", "dev", dev, ns=ns)
            ip("link", "set", dev, "up", ns=ns)
            if default_route:
                ip("route", "replace", "default", "via", gateway, "dev", dev, ns=ns)

    def source_route(self, resource_id: str, dev: str, address: str, gateway: str, cidr: str, table: int) -> None:
        ns = self.host_ns(resource_id)
        ip("route", "replace", cidr, "dev", dev, "table", str(table), ns=ns)
        ip("route", "replace", "default", "via", gateway, "dev", dev, "table", str(table), ns=ns)
        ip("rule", "del", "from", address, "lookup", str(table), ns=ns, check=False)
        ip("rule", "add", "from", address, "lookup", str(table), ns=ns)

    def detach_eni(self, vpc_idx: int, eni_idx: int) -> None:
        with self.lock:
            ip("link", "del", f"ve{eni_idx}", ns=self.vpc_ns(vpc_idx), check=False)

    def set_eni_link(self, vpc_idx: int, eni_idx: int, up: bool) -> None:
        ip("link", "set", f"ve{eni_idx}", "up" if up else "down", ns=self.vpc_ns(vpc_idx), check=False)

    def add_router_address(self, vpc_idx: int, address: str) -> None:
        ip("addr", "replace", f"{address}/32", "dev", "lo", ns=self.vpc_ns(vpc_idx))

    def apply_security(self, resource_id: str, ingress: list[SgRule], egress: list[SgRule], flowlog: bool,
                       forward: bool = False) -> None:
        """ENI のセキュリティグループ (ステートフル)。forward=True は NAT GW 用 (SG なし、転送を許可)。"""
        ns = self.host_ns(resource_id)
        lines = ["*filter", ":INPUT DROP [0:0]", ":OUTPUT DROP [0:0]",
                 f":FORWARD {'ACCEPT' if forward else 'DROP'} [0:0]",
                 ":SG-ACCEPT - [0:0]", ":SG-REJECT - [0:0]",
                 "-A INPUT -i lo -j ACCEPT", "-A OUTPUT -o lo -j ACCEPT"]
        if forward:
            lines += ["-A INPUT -j ACCEPT", "-A OUTPUT -j ACCEPT"]
        else:
            lines += ["-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j SG-ACCEPT",
                      "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j SG-ACCEPT",
                      # IMDS への通信はセキュリティグループの影響を受けない (AWS と同じ)
                      "-A OUTPUT -d 169.254.169.254/32 -p tcp --dport 80 -j ACCEPT"]
            for r in ingress:
                lines.append(f"-A INPUT {_match(r.protocol, r.from_port, r.to_port)} -s {r.cidr} -j SG-ACCEPT")
            for r in egress:
                lines.append(f"-A OUTPUT {_match(r.protocol, r.from_port, r.to_port)} -d {r.cidr} -j SG-ACCEPT")
            lines += ["-A INPUT -j SG-REJECT", "-A OUTPUT -j SG-REJECT"]
        if flowlog:
            lines += [f"-A SG-ACCEPT -j NFLOG --nflog-group {NFLOG_GROUP} --nflog-prefix A",
                      f"-A SG-REJECT -j NFLOG --nflog-group {NFLOG_GROUP} --nflog-prefix R"]
        lines += ["-A SG-ACCEPT -j ACCEPT", "-A SG-REJECT -j DROP", "COMMIT"]
        if forward:
            lines += ["*nat", ":PREROUTING ACCEPT [0:0]", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]",
                      ":POSTROUTING ACCEPT [0:0]", "-A POSTROUTING -o eth0 -j MASQUERADE", "COMMIT"]
            nsexec(ns, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        nsexec(ns, "iptables-restore", input="\n".join(line.replace("  ", " ") for line in lines) + "\n")

    def eni_stats(self, vpc_idx: int, eni_idx: int) -> dict[str, int] | None:
        """ENI のトラフィック量 (インスタンスから見た in/out)。ルーター側の veth のカウンタを読む。"""
        out = ip("-s", "-j", "link", "show", f"ve{eni_idx}", ns=self.vpc_ns(vpc_idx), check=False)
        if out.returncode != 0:
            return None
        try:
            stats = json.loads(out.stdout)[0]["stats64"]
        except (ValueError, KeyError, IndexError):
            return None
        # ルーター側の受信 = インスタンスの送信
        return {"out_bytes": stats["rx"]["bytes"], "out_packets": stats["rx"]["packets"],
                "in_bytes": stats["tx"]["bytes"], "in_packets": stats["tx"]["packets"]}

    # ------------------------------------------------------------------ instance processes
    def start_instance(self, instance_id: str, hostname: str, user_data: bytes, env: dict[str, str],
                       vcpus: int, memory_mib: int) -> None:
        with self.lock:
            ns = self.host_ns(instance_id)
            home = os.path.join(INSTANCE_ROOT, instance_id)
            os.makedirs(home, exist_ok=True)
            ud_path = os.path.join(home, "user-data")
            with open(ud_path, "wb") as f:
                f.write(user_data)
            os.chmod(ud_path, 0o755)
            console = open(os.path.join(home, "console.log"), "ab")
            cgroups = self._make_cgroup(instance_id, vcpus, memory_mib)

            def join_cgroup() -> None:
                for path in cgroups:
                    try:
                        with open(os.path.join(path, "cgroup.procs"), "w") as f:
                            f.write(str(os.getpid()))
                    except OSError:
                        pass
            init_path = os.path.join(os.path.dirname(INSTANCE_ROOT.rstrip("/")), "awsemu-init")
            with open(init_path, "w") as f:
                f.write(INIT_SCRIPT)
            cmd = ["ip", "netns", "exec", ns, "unshare", "--uts", "--pid", "--fork", "--mount-proc",
                   "--kill-child=SIGTERM", sys.executable, init_path, hostname, ud_path]
            proc = subprocess.Popen(cmd, cwd=home, env={**os.environ, **env}, stdout=console, stderr=console,
                                    stdin=subprocess.DEVNULL, preexec_fn=join_cgroup, start_new_session=True)
            console.close()
            self.processes[instance_id] = proc

    def stop_instance(self, instance_id: str, timeout: float = 8.0) -> None:
        with self.lock:
            proc = self.processes.pop(instance_id, None)
        if proc:
            self._kill(proc, timeout)

    def instance_alive(self, instance_id: str) -> bool:
        proc = self.processes.get(instance_id)
        return proc is not None and proc.poll() is None

    def instance_pid(self, instance_id: str) -> int | None:
        """インスタンスの init (PID 名前空間内の 1 番) のホスト側 PID。"""
        proc = self.processes.get(instance_id)
        if proc is None or proc.poll() is not None:
            return None
        # proc は `ip netns exec` が exec した unshare。その子が名前空間内の init
        children = run(["pgrep", "-P", str(proc.pid)], check=False).stdout.split()
        return int(children[0]) if children else None

    @staticmethod
    def _kill(proc: subprocess.Popen, timeout: float = 8.0) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(3)
        except ProcessLookupError:
            pass

    # ------------------------------------------------------------------ cgroups (ベストエフォート)
    def _make_cgroup(self, instance_id: str, vcpus: int, memory_mib: int) -> list[str]:
        paths = []
        mem = memory_mib * 1024 * 1024
        v2 = "/sys/fs/cgroup"
        if os.path.exists(f"{v2}/cgroup.controllers"):
            path = f"{v2}/{PREFIX}/{instance_id}"
            try:
                os.makedirs(path, exist_ok=True)
                with open(f"{v2}/{PREFIX}/cgroup.subtree_control", "w") as f:
                    f.write("+cpu +memory")
                with open(f"{path}/memory.max", "w") as f:
                    f.write(str(mem))
                with open(f"{path}/cpu.max", "w") as f:
                    f.write(f"{vcpus * 100000} 100000")
                paths.append(path)
            except OSError as exc:
                log(f"cgroup v2 の設定に失敗しました ({exc}); リソース制限なしで起動します")
        else:
            for ctrl, settings in (("memory", {"memory.limit_in_bytes": str(mem)}),
                                   ("cpu", {"cpu.cfs_period_us": "100000", "cpu.cfs_quota_us": str(vcpus * 100000)}),
                                   ("cpuacct", {})):
                base = f"/sys/fs/cgroup/{ctrl}"
                if not os.path.isdir(base):
                    continue
                path = f"{base}/{PREFIX}/{instance_id}"
                try:
                    os.makedirs(path, exist_ok=True)
                    for k, v in settings.items():
                        with open(f"{path}/{k}", "w") as f:
                            f.write(v)
                    paths.append(path)
                except OSError as exc:
                    log(f"cgroup {ctrl} の設定に失敗しました ({exc})")
        self.cgroups[instance_id] = paths
        return paths

    def cpu_usage_seconds(self, instance_id: str) -> float | None:
        for path in self.cgroups.get(instance_id, []):
            try:
                if os.path.exists(f"{path}/cpu.stat") and path.startswith("/sys/fs/cgroup/" + PREFIX):
                    with open(f"{path}/cpu.stat") as f:
                        for line in f:
                            if line.startswith("usage_usec"):
                                return int(line.split()[1]) / 1e6
                if os.path.exists(f"{path}/cpuacct.usage"):
                    with open(f"{path}/cpuacct.usage") as f:
                        return int(f.read()) / 1e9
            except (OSError, ValueError):
                continue
        return None

    def memory_usage_bytes(self, instance_id: str) -> int | None:
        for path in self.cgroups.get(instance_id, []):
            for name in ("memory.current", "memory.usage_in_bytes"):
                try:
                    with open(f"{path}/{name}") as f:
                        return int(f.read())
                except (OSError, ValueError):
                    continue
        return None

    def oom_killed(self, instance_id: str) -> int:
        for path in self.cgroups.get(instance_id, []):
            for name, key in (("memory.events", "oom_kill"), ("memory.oom_control", "oom_kill")):
                try:
                    with open(f"{path}/{name}") as f:
                        for line in f:
                            if line.startswith(key + " "):
                                return int(line.split()[1])
                except (OSError, ValueError):
                    continue
        return 0

    def _remove_cgroup(self, instance_id: str) -> None:
        for path in self.cgroups.pop(instance_id, []):
            try:
                os.rmdir(path)
            except OSError:
                pass


# インスタンスの PID 1。ホスト名を設定し、ユーザーデータを実行して、孤児プロセスを回収し続ける。
# SIGTERM (StopInstances) を受けたら全プロセスに SIGTERM → 猶予後 SIGKILL して終了する (OS のシャットダウン相当)。
INIT_SCRIPT = r"""
import os, signal, socket, subprocess, sys, time
hostname, user_data = sys.argv[1], sys.argv[2]
socket.sethostname(hostname)
def log(msg):
    print(time.strftime("[%Y-%m-%d %H:%M:%S]") + " awsemu-init: " + msg, flush=True)
log(f"booting {hostname}")
stopping = False
def shutdown(signum, frame):
    global stopping
    if stopping:
        return
    stopping = True
    log("received shutdown signal, stopping all processes")
    try:
        os.kill(-1, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            if os.waitpid(-1, os.WNOHANG) == (0, 0):
                time.sleep(0.1)
        except ChildProcessError:
            break
    try:
        os.kill(-1, signal.SIGKILL)
    except ProcessLookupError:
        pass
    log("halted")
    sys.exit(0)
signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)
if os.path.getsize(user_data) > 0:
    with open(user_data, "rb") as f:
        head = f.read(2)
    cmd = [user_data] if head == b"#!" else ["/bin/sh", user_data]
    log("running user data")
    ud = subprocess.Popen(cmd, cwd=os.getcwd())
else:
    ud = None
while True:
    try:
        pid, status = os.waitpid(-1, 0)
        if ud is not None and pid == ud.pid:
            log(f"user data finished with exit code {os.waitstatus_to_exitcode(status)}")
            ud = None
    except ChildProcessError:
        signal.pause()
    except InterruptedError:
        pass
"""
