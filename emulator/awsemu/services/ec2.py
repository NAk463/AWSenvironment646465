"""EC2 (EC2 プロトコル)。インスタンス・VPC 一式・IMDS を再現する。

データプレーン (netplane) が有効なら、インスタンスはネットワーク名前空間で動く実体 (ユーザーデータを実行し、
実際に通信できる) になる。無効 (simulated) なら状態遷移だけを再現する。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..core import ACCOUNT_ID, AwsError, Identity, Metric, Request
from ..iam_policy import base_context
from ..netplane import create as create_netplane
from ..netplane.simulated import SimulatedNetplane
from ._ec2proto import Ec2ProtocolService, apply_filters, iso, tag_filters, tag_list, tags_from_specs
from .ec2_network import AZS, NetworkMixin, new_id, not_found

BOOT_SECONDS = float(os.environ.get("AWSEMU_EC2_BOOT_SECONDS", "3"))
STOP_SECONDS = float(os.environ.get("AWSEMU_EC2_STOP_SECONDS", "3"))
STATUS_INIT_SECONDS = float(os.environ.get("AWSEMU_EC2_STATUS_INIT_SECONDS", "60"))
VCPU_LIMIT = int(os.environ.get("AWSEMU_EC2_VCPU_LIMIT", "32"))

INSTANCE_TYPES = {  # type: (vCPU, MiB)
    "t2.micro": (1, 1024), "t3.nano": (2, 512), "t3.micro": (2, 1024), "t3.small": (2, 2048),
    "t3.medium": (2, 4096), "t3.large": (2, 8192), "t3.xlarge": (4, 16384), "t4g.micro": (2, 1024),
    "m5.large": (2, 8192), "m5.xlarge": (4, 16384), "m6i.large": (2, 8192), "c5.large": (2, 4096),
    "c6i.large": (2, 4096), "r5.large": (2, 16384),
}
IMAGES = {
    "ami-0a2023a1b2c3d4e5f": {"name": "al2023-ami-2023.6.20260901.0-kernel-6.1-x86_64", "owner": "137112412989",
                              "alias": "amazon", "description": "Amazon Linux 2023 AMI", "imds": "v2.0"},
    "ami-0a2b3c4d5e6f24041": {"name": "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20260901",
                              "owner": "099720109477", "alias": None, "description": "Canonical, Ubuntu, 24.04",
                              "imds": None},
}
STATE_CODES = {"pending": 0, "running": 16, "shutting-down": 32, "terminated": 48, "stopping": 64, "stopped": 80}


@dataclass
class Instance:
    id: str
    image_id: str
    type: str
    subnet_id: str
    vpc_id: str
    eni_id: str
    reservation_id: str
    launch_time: float
    state: str = "pending"
    transition_at: float = 0.0
    state_reason: str = ""
    key_name: str | None = None
    user_data: bytes = b""
    profile_arn: str | None = None
    http_tokens: str = "required"
    hop_limit: int = 2
    http_endpoint: str = "enabled"
    monitoring: str = "disabled"
    tags: dict[str, str] = field(default_factory=dict)
    client_token: str = ""
    disable_api_termination: bool = False
    running_since: float | None = None
    impaired_system: bool = False
    impaired_instance: bool = False
    launch_index: int = 0
    cpu_sample: tuple[float, float] | None = None
    net_sample: dict[str, int] | None = None


class EC2(NetworkMixin, Ec2ProtocolService):
    name = "ec2"
    iam_prefix = "ec2"
    event_source = "ec2.amazonaws.com"
    access_denied_code = "UnauthorizedOperation"
    access_denied_status = 403
    invalid_token_code = "AuthFailure"
    invalid_token_status = 401
    invalid_token_message = "AWS was not able to validate the provided access credentials"

    def __init__(self, clock) -> None:
        super().__init__(clock)
        self.netplane: Any = SimulatedNetplane("未初期化")
        self.flowlogs_collector = None
        self.imds: dict[str, Any] = {}
        self.imds_tokens: dict[str, tuple[str, float]] = {}
        self.instance_creds: dict[str, Any] = {}
        self._initialized = False
        self.reset_state()

    # ================================================================== lifecycle
    def reset_state(self) -> None:
        self.reset_network()
        self.instances: dict[str, Instance] = {}
        self.key_pairs: dict[str, dict[str, Any]] = {}

    def reset(self) -> None:
        with self.lock:
            for iid in list(self.instances):
                self._halt(self.instances[iid], terminate=True)
            for vpc_id in list(self.imds):
                self.stop_imds(vpc_id)
            if self.netplane.enabled:
                self.netplane.cleanup_all()
            self.reset_state()
            self.create_default_vpc()

    def start(self, network: str | None = None) -> None:
        """エミュレータ起動時に一度だけ呼ばれる (データプレーンの初期化とデフォルト VPC の作成)。"""
        with self.lock:
            if self._initialized:
                return
            self.netplane = create_netplane(network)
            if self.netplane.enabled:
                from .ec2_flowlogs import FlowLogCollector
                self.flowlogs_collector = FlowLogCollector(self)
                self.flowlogs_collector.start_flusher()
            if self.netplane.enabled:
                self.netplane.cleanup_all()
                self.netplane.ensure_core()
            self.create_default_vpc()
            self._initialized = True

    def shutdown(self) -> None:
        with self.lock:
            for vpc_id in list(self.imds):
                self.stop_imds(vpc_id)
            if self.flowlogs_collector:
                self.flowlogs_collector.stop()
            if self.netplane.enabled:
                self.netplane.cleanup_all()

    # ================================================================== IAM 連携
    def authz(self, req: Request, op: str) -> list[tuple[str, str]]:
        p = self.params(req, op)
        base = f"arn:aws:ec2:{req.region}:{ACCOUNT_ID}"
        if p.get("InstanceIds") and op in ("StartInstances", "StopInstances", "RebootInstances", "TerminateInstances"):
            return [(f"ec2:{op}", f"{base}:instance/{i}") for i in p["InstanceIds"]]
        if p.get("InstanceId") and op in ("ModifyInstanceAttribute", "GetConsoleOutput",
                                          "ModifyInstanceMetadataOptions", "AssociateIamInstanceProfile"):
            return [(f"ec2:{op}", f"{base}:instance/{p['InstanceId']}")]
        if p.get("GroupId") and "SecurityGroup" in op:
            return [(f"ec2:{op}", f"{base}:security-group/{p['GroupId']}")]
        if op == "RunInstances":
            return [("ec2:RunInstances", f"{base}:instance/*")]
        return [(f"ec2:{op}", "*")]

    def format_denial(self, message: str, identity: Identity, action: str, resource: str, decision: Any) -> str:
        encoded = base64.b64encode(json.dumps({
            "allowed": False, "explicitDeny": decision.effect == "ExplicitDeny",
            "matchedStatements": {"items": decision.matched},
            "context": {"principal": {"arn": identity.arn}, "action": action, "resource": resource},
        }).encode()).decode()
        return (f"You are not authorized to perform this operation. {message}. "
                f"Encoded authorization failure message: {encoded}")

    def trail_resources(self, req: Request, op: str) -> list[dict[str, str]]:
        return []

    # ================================================================== helpers
    def _instance(self, iid: str | None) -> Instance:
        if not iid or not iid.startswith("i-"):
            raise AwsError("InvalidInstanceID.Malformed", f'Invalid id: "{iid}" (expecting "i-...")')
        inst = self.instances.get(iid)
        if inst is None:
            raise not_found("InvalidInstanceID.NotFound", f"The instance ID '{iid}' does not exist")
        self._refresh(inst)
        return inst

    def _refresh(self, inst: Instance) -> None:
        now = self.clock.now()
        if inst.state == "pending" and now >= inst.transition_at:
            inst.state, inst.running_since = "running", inst.transition_at
        elif inst.state == "stopping" and now >= inst.transition_at:
            inst.state = "stopped"
        elif inst.state == "shutting-down" and now >= inst.transition_at:
            inst.state = "terminated"

    def _refresh_all(self) -> None:
        now = self.clock.now()
        for inst in list(self.instances.values()):
            self._refresh(inst)
            if inst.state == "terminated" and now > inst.transition_at + 3600:
                del self.instances[inst.id]

    def _vcpus_in_use(self) -> int:
        return sum(INSTANCE_TYPES[i.type][0] for i in self.instances.values()
                   if i.state in ("pending", "running", "stopping"))

    def hostname(self, inst: Instance) -> str:
        eni = self.enis[inst.eni_id]
        return f"ip-{eni.private_ip.replace('.', '-')}"

    def _hosts_entries(self, vpc_id: str) -> str:
        lines = []
        for inst in self.instances.values():
            if inst.vpc_id == vpc_id and inst.eni_id in self.enis:
                ip_ = self.enis[inst.eni_id].private_ip
                lines.append(f"{ip_} {self.eni_hostname(ip_)} {self.hostname(inst)}")
        elb = self.emu.services.get("elbv2") if self.emu else None
        if elb is not None:
            for dns, ips in elb.dns_records(vpc_id).items():
                lines.extend(f"{a} {dns}" for a in ips[:1])
        return "\n".join(lines) + "\n"

    def refresh_dns(self) -> None:
        if not self.netplane.enabled:
            return
        for inst in self.instances.values():
            if inst.state in ("pending", "running"):
                self.netplane.update_hosts_file(inst.id, self._hosts_entries(inst.vpc_id))

    @staticmethod
    def _resolv() -> str:
        try:
            with open("/etc/resolv.conf") as f:
                servers = [line.split()[1] for line in f if line.startswith("nameserver")]
        except OSError:
            servers = []
        servers = [s for s in servers if not s.startswith("127.")] or ["8.8.8.8", "1.1.1.1"]
        return "".join(f"nameserver {s}\n" for s in servers)

    # ================================================================== data plane: instances
    def _launch(self, inst: Instance) -> None:
        np = self.netplane
        eni = self.enis[inst.eni_id]
        if np.enabled:
            np.ensure_host(inst.id, self.hostname(inst), self._hosts_entries(inst.vpc_id), self._resolv())
            self.attach_eni_dataplane(eni, inst.id)
        else:
            eni.owner = inst.id
        self.sync_security(inst.vpc_id)
        self.sync_vpc(self.vpcs[inst.vpc_id])
        if np.enabled:
            vcpus, mem = INSTANCE_TYPES[inst.type]
            port = getattr(self.emu, "api_port", 4566)
            env = {"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LANG": "C.UTF-8",
                   "HOME": "/root", "AWS_REGION": self.region(), "AWS_DEFAULT_REGION": self.region(),
                   "AWS_ENDPOINT_URL": f"http://100.64.0.1:{port}", "AWSEMU_INSTANCE_ID": inst.id}
            np.start_instance(inst.id, self.hostname(inst), inst.user_data, env, vcpus, mem)
        if self.flowlogs_collector:
            self.flowlogs_collector.refresh()
        self.refresh_dns()

    def _halt(self, inst: Instance, terminate: bool) -> None:
        np = self.netplane
        np.stop_instance(inst.id)
        eni = self.enis.get(inst.eni_id)
        if eni:
            self.release_public_ip(eni)
        if terminate:
            np.delete_host(inst.id)
            if eni:
                for a in self.addresses.values():
                    if a.eni_id == eni.id:
                        a.association_id, a.eni_id = None, None
                eni.public_ip, eni.allocation_id = None, None
                self.delete_eni(eni)
            if np.enabled:
                shutil.rmtree(os.path.join("/var/lib/awsemu/instances", inst.id), ignore_errors=True)
        if inst.vpc_id in self.vpcs:
            self.sync_vpc(self.vpcs[inst.vpc_id])
            self.sync_security(inst.vpc_id)
        if self.flowlogs_collector:
            self.flowlogs_collector.refresh()

    # ================================================================== IMDS
    def start_imds(self, vpc) -> None:
        """VPC ルーターで IMDS を待ち受ける (送信元 IP でインスタンスを特定)。"""
        from ..netplane.imds import IMDS_IP, ImdsServer
        if not self.netplane.enabled or vpc.id in self.imds:
            return
        self.netplane.add_router_address(vpc.idx, IMDS_IP)
        vpc_id = vpc.id

        def responder(method: str, path: str, headers: dict[str, str], client_ip: str):
            with self.lock:
                inst = next((i for i in self.instances.values() if i.vpc_id == vpc_id and i.eni_id in self.enis
                             and self.enis[i.eni_id].private_ip == client_ip), None)
                if inst is None:
                    return 404, b"", {}
                return self._imds(inst.id, method, path, {k.lower(): v for k, v in headers.items()})
        server = ImdsServer(self.netplane.vpc_ns(vpc.idx), responder)
        try:
            server.start()
            self.imds[vpc.id] = server
        except Exception as exc:  # noqa: BLE001
            print(f"[ec2] IMDS の起動に失敗しました ({vpc.id}): {exc}")

    def stop_imds(self, vpc_id: str) -> None:
        server = self.imds.pop(vpc_id, None)
        if server:
            server.stop()

    def _imds(self, iid: str, method: str, path: str, headers: dict[str, str]) -> tuple[int, bytes | None, dict]:
        inst = self.instances.get(iid)
        if inst is None or inst.state not in ("pending", "running"):
            return 404, b"", {}
        if inst.http_endpoint != "enabled":
            return 0, None, {}
        now = self.clock.now()
        path = path.split("?", 1)[0]
        if method == "PUT" and path == "/latest/api/token":
            if "x-forwarded-for" in headers:  # プロキシ経由のトークン取得は拒否される (SSRF 対策)
                return 403, b"", {}
            try:
                ttl = int(headers.get("x-aws-ec2-metadata-token-ttl-seconds", ""))
            except ValueError:
                return 400, b"", {}
            if not 1 <= ttl <= 21600:
                return 400, b"", {}
            token = base64.urlsafe_b64encode(secrets.token_bytes(42)).decode()
            self.imds_tokens[token] = (iid, now + ttl)
            return 200, token.encode(), {"X-Aws-Ec2-Metadata-Token-Ttl-Seconds": str(ttl)}
        if method != "GET":
            return 405, b"", {}
        token = headers.get("x-aws-ec2-metadata-token")
        if token:
            owner = self.imds_tokens.get(token)
            if owner is None or owner[0] != iid or owner[1] < now:
                return 401, b"", {}
        elif inst.http_tokens == "required":
            return 401, b"", {}
        body = self._imds_path(inst, path)
        if body is None:
            return 404, b"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?>\n<title>404 - Not Found</title>", \
                {"Content-Type": "text/html"}
        return 200, body.encode() if isinstance(body, str) else body, {}

    def _imds_path(self, inst: Instance, path: str) -> str | bytes | None:
        eni = self.enis.get(inst.eni_id)
        if eni is None:
            return None
        subnet = self.subnets[inst.subnet_id]
        role = self._instance_role(inst)
        md: dict[str, Any] = {
            "ami-id": inst.image_id, "ami-launch-index": str(inst.launch_index), "hostname": self.eni_hostname(eni.private_ip),
            "instance-id": inst.id, "instance-type": inst.type, "local-hostname": self.eni_hostname(eni.private_ip),
            "local-ipv4": eni.private_ip, "mac": eni.mac, "reservation-id": inst.reservation_id,
            "security-groups": "\n".join(self.sgs[g].name for g in eni.sg_ids if g in self.sgs),
            "placement/availability-zone": subnet.az, "placement/region": self.region(),
            "placement/availability-zone-id": f"apne1-az{AZS.index(subnet.az[-1]) + 1}",
            f"network/interfaces/macs/{eni.mac}/device-number": "0",
            f"network/interfaces/macs/{eni.mac}/interface-id": eni.id,
            f"network/interfaces/macs/{eni.mac}/local-ipv4s": eni.private_ip,
            f"network/interfaces/macs/{eni.mac}/subnet-id": subnet.id,
            f"network/interfaces/macs/{eni.mac}/subnet-ipv4-cidr-block": subnet.cidr,
            f"network/interfaces/macs/{eni.mac}/vpc-id": inst.vpc_id,
            f"network/interfaces/macs/{eni.mac}/vpc-ipv4-cidr-block": self.vpcs[inst.vpc_id].cidr,
            f"network/interfaces/macs/{eni.mac}/security-group-ids": "\n".join(eni.sg_ids),
            "services/domain": "amazonaws.com", "services/partition": "aws",
        }
        if eni.public_ip:
            md["public-ipv4"] = eni.public_ip
            md["public-hostname"] = f"ec2-{eni.public_ip.replace('.', '-')}.{self.region()}.compute.amazonaws.com"
            md[f"network/interfaces/macs/{eni.mac}/public-ipv4s"] = eni.public_ip
        if role:
            profile = self.emu.services["iam"].profile_by_arn_or_name(arn=inst.profile_arn)
            creds = self._instance_credentials(inst, role)
            md["iam/info"] = json.dumps({"Code": "Success", "LastUpdated": creds["LastUpdated"],
                                         "InstanceProfileArn": inst.profile_arn,
                                         "InstanceProfileId": profile.id if profile else ""}, indent=2)
            md[f"iam/security-credentials/{role}"] = json.dumps(creds, indent=2)
        if path == "/latest/user-data":
            return inst.user_data if inst.user_data else None
        if path in ("/latest/dynamic/instance-identity/document",):
            return json.dumps({"accountId": ACCOUNT_ID, "architecture": "x86_64", "availabilityZone": subnet.az,
                               "imageId": inst.image_id, "instanceId": inst.id, "instanceType": inst.type,
                               "pendingTime": datetime.fromtimestamp(inst.launch_time, timezone.utc).strftime(
                                   "%Y-%m-%dT%H:%M:%SZ"),
                               "privateIp": eni.private_ip, "region": self.region(), "version": "2017-09-30"},
                              indent=2)
        if path in ("/latest", "/latest/"):
            return "dynamic\nmeta-data\nuser-data" if inst.user_data else "dynamic\nmeta-data"
        prefix = "/latest/meta-data/"
        if not (path + "/").startswith(prefix):
            return None
        key = path[len(prefix):].strip("/")
        if key in md:
            return md[key]
        # ディレクトリ: 直下の項目を一覧表示する (サブディレクトリは末尾に /)
        base = key + "/" if key else ""
        children = set()
        for k in md:
            if k.startswith(base):
                head, sep, _ = k[len(base):].partition("/")
                children.add(head + ("/" if sep else ""))
        return "\n".join(sorted(children)) if children else None

    def _instance_role(self, inst: Instance) -> str | None:
        if not inst.profile_arn:
            return None
        iam = self.emu.services["iam"]
        profile = iam.profile_by_arn_or_name(arn=inst.profile_arn)
        if profile is None or not profile.roles:
            return None
        return profile.roles[0]

    def _instance_credentials(self, inst: Instance, role_name: str) -> dict[str, Any]:
        """インスタンスプロファイルのロールの一時認証情報。期限 6 時間、残り 15 分を切ると更新する。"""
        now = self.clock.now()
        cached = self.instance_creds.get(inst.id)
        if cached and cached[0] == role_name and cached[1].expiration - now > 900:
            session = cached[1]
        else:
            iam = self.emu.services["iam"]
            role = iam.roles.get(role_name)
            if role is None:
                return {"Code": "AssumeRoleUnauthorizedAccess", "Message": "EC2 cannot assume the role",
                        "LastUpdated": iso(now)}
            ident = Identity("AssumedRole", f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role.name}/{inst.id}",
                             f"{role.id}:{inst.id}", role_arn=role.arn, role_id=role.id, session_name=inst.id)
            with iam.lock:
                session = iam.create_session(ident, 6 * 3600, "role", role.name)
            self.instance_creds[inst.id] = (role_name, session)
        return {"Code": "Success", "LastUpdated": iso(now), "Type": "AWS-HMAC", "AccessKeyId": session.access_key,
                "SecretAccessKey": session.secret, "Token": session.token,
                "Expiration": iso(session.expiration).replace(".000", "")}

    # ================================================================== views
    def _instance_view(self, inst: Instance) -> dict[str, Any]:
        self._refresh(inst)
        eni = self.enis.get(inst.eni_id)
        subnet = self.subnets.get(inst.subnet_id)
        terminated = inst.state == "terminated"
        view: dict[str, Any] = {
            "InstanceId": inst.id, "ImageId": inst.image_id, "InstanceType": inst.type,
            "State": {"Code": STATE_CODES[inst.state], "Name": inst.state},
            "StateTransitionReason": inst.state_reason, "KeyName": inst.key_name, "AmiLaunchIndex": inst.launch_index,
            "LaunchTime": inst.launch_time, "Monitoring": {"State": inst.monitoring},
            "Placement": {"AvailabilityZone": subnet.az if subnet else "", "GroupName": "", "Tenancy": "default"},
            "Architecture": "x86_64", "Hypervisor": "xen", "VirtualizationType": "hvm", "RootDeviceType": "ebs",
            "RootDeviceName": "/dev/xvda", "ClientToken": inst.client_token, "EbsOptimized": True,
            "EnaSupport": True, "PlatformDetails": "Linux/UNIX", "UsageOperation": "RunInstances",
            "PrivateDnsName": "" if terminated or not eni else self.eni_hostname(eni.private_ip),
            "PublicDnsName": "", "Tags": tag_list(inst.tags), "SecurityGroups": [], "NetworkInterfaces": [],
            "BlockDeviceMappings": [] if terminated else [{"DeviceName": "/dev/xvda", "Ebs": {
                "VolumeId": "vol-" + inst.id[2:], "Status": "attached", "AttachTime": inst.launch_time,
                "DeleteOnTermination": True}}],
            "CpuOptions": {"CoreCount": max(1, INSTANCE_TYPES[inst.type][0] // 2), "ThreadsPerCore": 2 if
                           INSTANCE_TYPES[inst.type][0] > 1 else 1},
            "MetadataOptions": {"State": "applied", "HttpTokens": inst.http_tokens,
                                "HttpPutResponseHopLimit": inst.hop_limit, "HttpEndpoint": inst.http_endpoint,
                                "HttpProtocolIpv6": "disabled", "InstanceMetadataTags": "disabled"},
        }
        if inst.state in ("stopped", "stopping", "shutting-down", "terminated") and inst.state_reason:
            code = {"stopped": "Client.UserInitiatedShutdown", "stopping": "Client.UserInitiatedShutdown",
                    "shutting-down": "Client.UserInitiatedShutdown", "terminated": "Client.UserInitiatedShutdown"}
            view["StateReason"] = {"Code": code[inst.state], "Message": "Client.UserInitiatedShutdown: User initiated shutdown"}
        if inst.profile_arn:
            profile = self.emu.services["iam"].profile_by_arn_or_name(arn=inst.profile_arn)
            view["IamInstanceProfile"] = {"Arn": inst.profile_arn, "Id": profile.id if profile else ""}
        if eni and not terminated:
            groups = [{"GroupId": g, "GroupName": self.sgs[g].name} for g in eni.sg_ids if g in self.sgs]
            view.update(SubnetId=inst.subnet_id, VpcId=inst.vpc_id, PrivateIpAddress=eni.private_ip,
                        SecurityGroups=groups, SourceDestCheck=True)
            assoc = None
            if eni.public_ip:
                dns = f"ec2-{eni.public_ip.replace('.', '-')}.{self.region()}.compute.amazonaws.com"
                view.update(PublicIpAddress=eni.public_ip, PublicDnsName=dns)
                assoc = {"PublicIp": eni.public_ip, "PublicDnsName": dns,
                         "IpOwnerId": ACCOUNT_ID if eni.allocation_id else "amazon"}
            view["NetworkInterfaces"] = [{
                "NetworkInterfaceId": eni.id, "SubnetId": eni.subnet_id, "VpcId": eni.vpc_id, "OwnerId": ACCOUNT_ID,
                "Description": "", "MacAddress": eni.mac, "PrivateIpAddress": eni.private_ip,
                "PrivateDnsName": self.eni_hostname(eni.private_ip), "SourceDestCheck": True, "Status": "in-use",
                "InterfaceType": "interface", "Groups": groups, "Association": assoc,
                "Attachment": {"AttachmentId": eni.attach_id, "AttachTime": inst.launch_time, "DeleteOnTermination": True,
                               "DeviceIndex": 0, "Status": "attached", "NetworkCardIndex": 0},
                "PrivateIpAddresses": [{"Primary": True, "PrivateIpAddress": eni.private_ip, "Association": assoc,
                                        "PrivateDnsName": self.eni_hostname(eni.private_ip)}],
            }]
        return view

    def _instance_fields(self, inst: Instance) -> dict[str, Any]:
        eni = self.enis.get(inst.eni_id)
        return {
            "instance-id": inst.id, "instance-state-name": inst.state, "instance-state-code": STATE_CODES[inst.state],
            "instance-type": inst.type, "image-id": inst.image_id, "subnet-id": inst.subnet_id, "vpc-id": inst.vpc_id,
            "key-name": inst.key_name, "private-ip-address": eni.private_ip if eni else None,
            "ip-address": eni.public_ip if eni else None, "network-interface.network-interface-id": inst.eni_id,
            "instance.group-id": eni.sg_ids if eni else [], "group-id": eni.sg_ids if eni else [],
            "availability-zone": self.subnets[inst.subnet_id].az if inst.subnet_id in self.subnets else None,
            "iam-instance-profile.arn": inst.profile_arn, "reservation-id": inst.reservation_id,
            "private-dns-name": self.eni_hostname(eni.private_ip) if eni else None, **tag_filters(inst.tags)}

    # ================================================================== instances
    def op_RunInstances(self, p, req):
        image_id = p.get("ImageId")
        image = IMAGES.get(image_id or "")
        if image is None:
            raise not_found("InvalidAMIID.NotFound", f"The image id '[{image_id}]' does not exist")
        itype = p.get("InstanceType", "m1.small")
        if itype not in INSTANCE_TYPES:
            raise AwsError("InvalidParameterValue", f"Invalid value '{itype}' for InstanceType.")
        mn, mx = int(p.get("MinCount") or 1), int(p.get("MaxCount") or 1)
        if mn < 1 or mx < mn:
            raise AwsError("InvalidParameterValue", "Value for parameter MaxCount must be greater than or equal to MinCount")
        if p.get("KeyName") and p["KeyName"] not in self.key_pairs:
            raise not_found("InvalidKeyPair.NotFound", f"The key pair '{p['KeyName']}' does not exist")
        nics = p.get("NetworkInterfaces") or []
        nic = nics[0] if nics else {}
        if nic and (p.get("SecurityGroupIds") or p.get("SecurityGroups")):
            raise AwsError("InvalidParameterCombination", "Network interfaces and an instance-level security groups "
                           "may not be specified on the same request")
        subnet_id = p.get("SubnetId") or nic.get("SubnetId")
        if subnet_id:
            subnet = self._subnet(subnet_id)
        else:
            default_vpc = next((v for v in self.vpcs.values() if v.is_default), None)
            if default_vpc is None:
                raise AwsError("VPCIdNotSpecified", "No default VPC for this user. GroupName is only supported "
                               "for EC2-Classic and default VPC.")
            az = (p.get("Placement") or {}).get("AvailabilityZone")
            subnet = next(s for s in self.subnets.values() if s.vpc_id == default_vpc.id and s.default_for_az
                          and (not az or s.az == az))
        sg_ids = self._resolve_sgs(p.get("SecurityGroupIds") or nic.get("Groups"), p.get("SecurityGroups"),
                                   subnet.vpc_id)
        vcpus = INSTANCE_TYPES[itype][0]
        if self._vcpus_in_use() + vcpus * mn > VCPU_LIMIT:
            raise AwsError("VcpuLimitExceeded", f"You have requested more vCPU capacity than your current vCPU limit "
                           f"of {VCPU_LIMIT} allows for the instance bucket that the specified instance type belongs "
                           "to. Please visit http://aws.amazon.com/contact-us/ec2-request to request an adjustment "
                           "to this limit.")
        count = max(mn, min(mx, (VCPU_LIMIT - self._vcpus_in_use()) // vcpus))
        if subnet.free_count() < mn:
            raise AwsError("InsufficientFreeAddressesInSubnet", f"There are not enough free addresses in subnet "
                           f"'{subnet.id}' to satisfy the requested number of instances.")
        profile_arn = None
        if p.get("IamInstanceProfile"):
            spec = p["IamInstanceProfile"]
            iam = self.emu.services["iam"]
            profile = iam.profile_by_arn_or_name(arn=spec.get("Arn"), name=spec.get("Name"))
            if profile is None:
                field_name = "iamInstanceProfile.name" if spec.get("Name") else "iamInstanceProfile.arn"
                raise AwsError("InvalidParameterValue", f"Value ({spec.get('Name') or spec.get('Arn')}) for parameter "
                               f"{field_name} is invalid. Invalid IAM Instance Profile name" if spec.get("Name") else
                               f"Value ({spec.get('Arn')}) for parameter {field_name} is invalid. "
                               "Invalid IAM Instance Profile ARN")
            for role in profile.roles:
                role_arn = iam.roles[role].arn
                ctx = base_context(req.identity, req.region, req.client_ip, self.clock.now())
                with iam.lock:
                    decision = iam.authorize(req.identity, "iam:PassRole", role_arn, None, ctx)
                if not decision.allowed:
                    from ..iam_policy import denial_message
                    raise AwsError("UnauthorizedOperation", self.format_denial(
                        denial_message(req.identity, "iam:PassRole", role_arn, decision), req.identity,
                        "iam:PassRole", role_arn, decision), 403)
            profile_arn = profile.arn
        user_data = b""
        if p.get("UserData"):
            try:
                user_data = base64.b64decode(p["UserData"])
            except ValueError:
                raise AwsError("InvalidUserData.Malformed", "Invalid BASE64 encoding of user data.")
            if len(user_data) > 16384:
                raise AwsError("InvalidParameterValue", "User data is limited to 16384 bytes")
        md = p.get("MetadataOptions") or {}
        public = nic.get("AssociatePublicIpAddress", subnet.map_public_ip)
        tags = tags_from_specs(p.get("TagSpecifications"), "instance")
        reservation = new_id("r")
        now = self.clock.now()
        created = []
        for i in range(count):
            eni = self.create_eni(subnet, sg_ids, private_ip=(p.get("PrivateIpAddress") or nic.get("PrivateIpAddress"))
                                  if i == 0 else None)
            inst = Instance(new_id("i"), image_id, itype, subnet.id, subnet.vpc_id, eni.id, reservation, now,
                            transition_at=now + BOOT_SECONDS, key_name=p.get("KeyName"), user_data=user_data,
                            profile_arn=profile_arn,
                            http_tokens=md.get("HttpTokens") or ("required" if image["imds"] == "v2.0" else "optional"),
                            hop_limit=int(md.get("HttpPutResponseHopLimit") or 2),
                            http_endpoint=md.get("HttpEndpoint") or "enabled",
                            monitoring="enabled" if (p.get("Monitoring") or {}).get("Enabled") else "disabled",
                            tags=dict(tags), client_token=p.get("ClientToken") or "",
                            disable_api_termination=bool(p.get("DisableApiTermination")), launch_index=i)
            eni.instance_id, eni.attach_id = inst.id, new_id("eni-attach")
            if public:
                eni.auto_public = True
                self.assign_public_ip(eni)
            self.instances[inst.id] = inst
            self._launch(inst)
            created.append(inst)
        return {"ReservationId": reservation, "OwnerId": ACCOUNT_ID, "Groups": [],
                "Instances": [self._instance_view(i) for i in created]}

    def op_DescribeInstances(self, p, req):
        self._refresh_all()
        if p.get("InstanceIds"):
            items = [self._instance(i) for i in p["InstanceIds"]]
        else:
            items = list(self.instances.values())
        items = apply_filters(items, p.get("Filters"), self._instance_fields)
        reservations: dict[str, list[Instance]] = {}
        for inst in sorted(items, key=lambda x: x.launch_time):
            reservations.setdefault(inst.reservation_id, []).append(inst)
        return {"Reservations": [{"ReservationId": rid, "OwnerId": ACCOUNT_ID, "Groups": [],
                                  "Instances": [self._instance_view(i) for i in insts]}
                                 for rid, insts in reservations.items()]}

    def _state_change(self, inst: Instance, previous: str) -> dict[str, Any]:
        return {"InstanceId": inst.id, "CurrentState": {"Code": STATE_CODES[inst.state], "Name": inst.state},
                "PreviousState": {"Code": STATE_CODES[previous], "Name": previous}}

    def op_StopInstances(self, p, req):
        out = []
        for iid in p.get("InstanceIds") or []:
            inst = self._instance(iid)
            prev = inst.state
            if inst.state in ("terminated", "shutting-down"):
                raise AwsError("IncorrectInstanceState", f"This instance '{iid}' is not in a state from which it can be stopped.")
            if inst.state in ("pending", "running"):
                inst.state, inst.transition_at = "stopping", self.clock.now() + STOP_SECONDS
                inst.state_reason = f"User initiated ({datetime.fromtimestamp(self.clock.now(), timezone.utc):%Y-%m-%d %H:%M:%S GMT})"
                inst.impaired_instance = False
                self._halt(inst, terminate=False)
            out.append(self._state_change(inst, prev))
        return {"StoppingInstances": out}

    def op_StartInstances(self, p, req):
        out = []
        for iid in p.get("InstanceIds") or []:
            inst = self._instance(iid)
            prev = inst.state
            if inst.state in ("stopping",):
                raise AwsError("IncorrectInstanceState", f"The instance '{iid}' is not in a state from which it can be started.")
            if inst.state in ("terminated", "shutting-down"):
                raise AwsError("IncorrectInstanceState", f"The instance '{iid}' is not in a state from which it can be started.")
            if inst.state == "stopped":
                if self._vcpus_in_use() + INSTANCE_TYPES[inst.type][0] > VCPU_LIMIT:
                    raise AwsError("VcpuLimitExceeded", f"You have requested more vCPU capacity than your current "
                                   f"vCPU limit of {VCPU_LIMIT} allows.")
                inst.state, inst.transition_at, inst.state_reason = "pending", self.clock.now() + BOOT_SECONDS, ""
                inst.running_since = None
                eni = self.enis[inst.eni_id]
                if eni.auto_public and not eni.public_ip:
                    self.assign_public_ip(eni)
                self._launch(inst)
            out.append(self._state_change(inst, prev))
        return {"StartingInstances": out}

    def op_RebootInstances(self, p, req):
        for iid in p.get("InstanceIds") or []:
            inst = self._instance(iid)
            if inst.state not in ("running", "pending"):
                raise AwsError("IncorrectInstanceState", f"The instance '{iid}' is not in a state from which it can be rebooted.")
            if self.netplane.enabled:
                self.netplane.stop_instance(inst.id)
                vcpus, mem = INSTANCE_TYPES[inst.type]
                port = getattr(self.emu, "api_port", 4566)
                env = {"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8", "HOME": "/root",
                       "AWS_REGION": self.region(), "AWS_DEFAULT_REGION": self.region(),
                       "AWS_ENDPOINT_URL": f"http://100.64.0.1:{port}", "AWSEMU_INSTANCE_ID": inst.id}
                self.netplane.start_instance(inst.id, self.hostname(inst), inst.user_data, env, vcpus, mem)
            inst.running_since = self.clock.now()
            inst.impaired_instance = False
        return {}

    def op_TerminateInstances(self, p, req):
        out = []
        for iid in p.get("InstanceIds") or []:
            inst = self._instance(iid)
            if inst.disable_api_termination:
                raise AwsError("OperationNotPermitted", f"The instance '{iid}' may not be terminated. Modify its "
                               "'disableApiTermination' instance attribute and try again.")
            prev = inst.state
            if inst.state not in ("terminated", "shutting-down"):
                inst.state, inst.transition_at = "shutting-down", self.clock.now() + STOP_SECONDS
                inst.state_reason = "User initiated"
                self._halt(inst, terminate=True)
                self.instance_creds.pop(inst.id, None)
            out.append(self._state_change(inst, prev))
        self.refresh_dns()
        return {"TerminatingInstances": out}

    # ================================================================== status checks
    def _status(self, inst: Instance) -> tuple[str, str]:
        """(instance status, system status) を返す。ok / impaired / initializing / not-applicable。"""
        if inst.state != "running":
            return "not-applicable", "not-applicable"
        system = "impaired" if inst.impaired_system else "ok"
        crashed = self.netplane.enabled and not self.netplane.instance_alive(inst.id)
        instance = "impaired" if inst.impaired_instance or crashed else "ok"
        if inst.running_since is not None and self.clock.now() < inst.running_since + STATUS_INIT_SECONDS:
            instance = "initializing" if instance == "ok" else instance
            system = "initializing" if system == "ok" else system
        return instance, system

    def op_DescribeInstanceStatus(self, p, req):
        self._refresh_all()
        items = [self._instance(i) for i in p["InstanceIds"]] if p.get("InstanceIds") else list(self.instances.values())
        if not p.get("IncludeAllInstances"):
            items = [i for i in items if i.state == "running"]

        def detail(status: str) -> dict[str, Any]:
            passed = {"ok": "passed", "impaired": "failed", "initializing": "initializing"}.get(status)
            return {"Status": status, "Details": [{"Name": "reachability", "Status": passed}] if passed else []}
        out = []
        for inst in items:
            ist, sst = self._status(inst)
            fields = {"instance-state-name": inst.state, "instance-status.status": ist, "system-status.status": sst,
                      "availability-zone": self.subnets[inst.subnet_id].az, "instance-id": inst.id,
                      "instance-status.reachability": detail(ist)["Details"][0]["Status"] if ist in
                      ("ok", "impaired", "initializing") else None}
            if not apply_filters([inst], p.get("Filters"), lambda _: fields):
                continue
            out.append({"InstanceId": inst.id, "AvailabilityZone": self.subnets[inst.subnet_id].az,
                        "InstanceState": {"Code": STATE_CODES[inst.state], "Name": inst.state},
                        "InstanceStatus": detail(ist), "SystemStatus": detail(sst)})
        return {"InstanceStatuses": out}

    def impair(self, iid: str, kind: str) -> dict[str, Any]:
        """障害注入: system (ホスト障害 = ネットワーク断) / instance (OS ハング) / recover。"""
        with self.lock:
            inst = self._instance(iid)
            eni = self.enis[inst.eni_id]
            if kind == "system":
                inst.impaired_system = True
                self.netplane.set_eni_link(self.vpcs[inst.vpc_id].idx, eni.idx, False)
            elif kind == "instance":
                inst.impaired_instance = True
                self.netplane.set_eni_link(self.vpcs[inst.vpc_id].idx, eni.idx, False)
            elif kind == "recover":
                inst.impaired_system = inst.impaired_instance = False
                self.netplane.set_eni_link(self.vpcs[inst.vpc_id].idx, eni.idx, True)
            else:
                raise AwsError("InvalidParameterValue", "kind must be system, instance or recover")
            ist, sst = self._status(inst)
            return {"instance_id": iid, "instance_status": ist, "system_status": sst}

    def op_GetConsoleOutput(self, p, req):
        inst = self._instance(p.get("InstanceId"))
        path = os.path.join("/var/lib/awsemu/instances", inst.id, "console.log")
        data = b""
        if os.path.exists(path):
            with open(path, "rb") as f:
                f.seek(max(0, os.path.getsize(path) - 65536))
                data = f.read()
        return {"InstanceId": inst.id, "Timestamp": self.clock.now(),
                "Output": base64.b64encode(data).decode() if data else None}

    # ================================================================== attributes
    def op_ModifyInstanceAttribute(self, p, req):
        inst = self._instance(p.get("InstanceId"))
        eni = self.enis[inst.eni_id]
        if p.get("Groups"):
            eni.sg_ids = self._resolve_sgs(p["Groups"], None, inst.vpc_id)
            self.sync_security(inst.vpc_id)
        itype = (p.get("InstanceType") or {}).get("Value") or (p.get("Value") if p.get("Attribute") == "instanceType" else None)
        if itype:
            if inst.state != "stopped":
                raise AwsError("IncorrectInstanceState", f"The instance '{inst.id}' is not in the 'stopped' state.")
            if itype not in INSTANCE_TYPES:
                raise AwsError("InvalidParameterValue", f"Invalid value '{itype}' for InstanceType.")
            inst.type = itype
        if p.get("UserData"):
            if inst.state != "stopped":
                raise AwsError("IncorrectInstanceState", f"The instance '{inst.id}' is not in the 'stopped' state.")
            inst.user_data = base64.b64decode(p["UserData"]["Value"])
        if p.get("DisableApiTermination"):
            inst.disable_api_termination = p["DisableApiTermination"]["Value"]
        return {}

    def op_DescribeInstanceAttribute(self, p, req):
        inst = self._instance(p.get("InstanceId"))
        attr = p.get("Attribute")
        out: dict[str, Any] = {"InstanceId": inst.id}
        if attr == "instanceType":
            out["InstanceType"] = {"Value": inst.type}
        elif attr == "userData":
            out["UserData"] = {"Value": base64.b64encode(inst.user_data).decode()} if inst.user_data else {}
        elif attr == "groupSet":
            out["Groups"] = [{"GroupId": g, "GroupName": self.sgs[g].name} for g in self.enis[inst.eni_id].sg_ids]
        elif attr == "disableApiTermination":
            out["DisableApiTermination"] = {"Value": inst.disable_api_termination}
        else:
            raise AwsError("InvalidParameterValue", f"Value ({attr}) for parameter attribute is invalid.")
        return out

    def op_ModifyInstanceMetadataOptions(self, p, req):
        inst = self._instance(p.get("InstanceId"))
        if p.get("HttpTokens"):
            inst.http_tokens = p["HttpTokens"]
        if p.get("HttpPutResponseHopLimit"):
            inst.hop_limit = int(p["HttpPutResponseHopLimit"])
        if p.get("HttpEndpoint"):
            inst.http_endpoint = p["HttpEndpoint"]
        return {"InstanceId": inst.id, "InstanceMetadataOptions": {
            "State": "pending", "HttpTokens": inst.http_tokens, "HttpPutResponseHopLimit": inst.hop_limit,
            "HttpEndpoint": inst.http_endpoint, "HttpProtocolIpv6": "disabled", "InstanceMetadataTags": "disabled"}}

    def op_AssociateIamInstanceProfile(self, p, req):
        inst = self._instance(p.get("InstanceId"))
        if inst.profile_arn:
            raise AwsError("IncorrectState", f"There is an existing association for instance {inst.id}")
        spec = p.get("IamInstanceProfile") or {}
        profile = self.emu.services["iam"].profile_by_arn_or_name(arn=spec.get("Arn"), name=spec.get("Name"))
        if profile is None:
            raise AwsError("InvalidParameterValue", "Invalid IAM Instance Profile")
        inst.profile_arn = profile.arn
        self.instance_creds.pop(inst.id, None)
        return {"IamInstanceProfileAssociation": self._profile_assoc(inst)}

    def _profile_assoc(self, inst: Instance) -> dict[str, Any]:
        profile = self.emu.services["iam"].profile_by_arn_or_name(arn=inst.profile_arn)
        return {"AssociationId": f"iip-assoc-{inst.id[2:]}", "InstanceId": inst.id, "State": "associated",
                "IamInstanceProfile": {"Arn": inst.profile_arn, "Id": profile.id if profile else ""},
                "Timestamp": inst.launch_time}

    def op_DescribeIamInstanceProfileAssociations(self, p, req):
        return {"IamInstanceProfileAssociations": [self._profile_assoc(i) for i in self.instances.values()
                                                   if i.profile_arn and i.state != "terminated"]}

    # ================================================================== key pairs / images / types
    def op_CreateKeyPair(self, p, req):
        name = p.get("KeyName", "")
        if name in self.key_pairs:
            raise AwsError("InvalidKeyPair.Duplicate", f"The keypair '{name}' already exists.")
        material = self._generate_key(p.get("KeyType", "rsa"))
        kp = {"name": name, "id": new_id("key"), "type": p.get("KeyType", "rsa"), "created": self.clock.now(),
              "fingerprint": ":".join(f"{b:02x}" for b in hashlib.sha1(material.encode()).digest()),
              "tags": tags_from_specs(p.get("TagSpecifications"), "key-pair")}
        self.key_pairs[name] = kp
        return {"KeyName": name, "KeyPairId": kp["id"], "KeyFingerprint": kp["fingerprint"], "KeyMaterial": material,
                "Tags": tag_list(kp["tags"])}

    @staticmethod
    def _generate_key(kind: str) -> str:
        if shutil.which("ssh-keygen"):
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "k")
                ktype = "ed25519" if kind == "ed25519" else "rsa"
                proc = subprocess.run(["ssh-keygen", "-q", "-t", ktype, "-N", "", "-m", "PEM", "-f", path],
                                      capture_output=True)
                if proc.returncode == 0:
                    with open(path) as f:
                        return f.read()
        body = base64.encodebytes(secrets.token_bytes(1190)).decode()
        return f"-----BEGIN RSA PRIVATE KEY-----\n{body}-----END RSA PRIVATE KEY-----\n"

    def op_ImportKeyPair(self, p, req):
        name = p.get("KeyName", "")
        if name in self.key_pairs:
            raise AwsError("InvalidKeyPair.Duplicate", f"The keypair '{name}' already exists.")
        material = p.get("PublicKeyMaterial") or b""
        kp = {"name": name, "id": new_id("key"), "type": "rsa", "created": self.clock.now(),
              "fingerprint": ":".join(f"{b:02x}" for b in hashlib.md5(material).digest()),
              "tags": tags_from_specs(p.get("TagSpecifications"), "key-pair")}
        self.key_pairs[name] = kp
        return {"KeyName": name, "KeyPairId": kp["id"], "KeyFingerprint": kp["fingerprint"]}

    def op_DescribeKeyPairs(self, p, req):
        items = list(self.key_pairs.values())
        if p.get("KeyNames"):
            missing = [n for n in p["KeyNames"] if n not in self.key_pairs]
            if missing:
                raise not_found("InvalidKeyPair.NotFound", f"The key pair '{missing[0]}' does not exist")
            items = [self.key_pairs[n] for n in p["KeyNames"]]
        items = apply_filters(items, p.get("Filters"), lambda k: {"key-name": k["name"], "key-pair-id": k["id"],
                                                                  **tag_filters(k["tags"])})
        return {"KeyPairs": [{"KeyName": k["name"], "KeyPairId": k["id"], "KeyFingerprint": k["fingerprint"],
                              "KeyType": k["type"], "CreateTime": k["created"], "Tags": tag_list(k["tags"])}
                             for k in items]}

    def op_DeleteKeyPair(self, p, req):
        self.key_pairs.pop(p.get("KeyName") or "", None)
        return {"Return": True}

    def op_DescribeImages(self, p, req):
        items = list(IMAGES.items())
        if p.get("ImageIds"):
            missing = [i for i in p["ImageIds"] if i not in IMAGES]
            if missing:
                raise not_found("InvalidAMIID.NotFound", f"The image id '[{missing[0]}]' does not exist")
            items = [(i, IMAGES[i]) for i in p["ImageIds"]]
        owners = p.get("Owners")
        if owners:
            items = [(i, m) for i, m in items if m["owner"] in owners or m["alias"] in owners]
        items = apply_filters(items, p.get("Filters"), lambda x: {
            "name": x[1]["name"], "image-id": x[0], "owner-id": x[1]["owner"], "owner-alias": x[1]["alias"],
            "architecture": "x86_64", "state": "available", "virtualization-type": "hvm", "root-device-type": "ebs"})
        return {"Images": [{"ImageId": i, "Name": m["name"], "Description": m["description"], "OwnerId": m["owner"],
                            "ImageOwnerAlias": m["alias"], "State": "available", "Architecture": "x86_64",
                            "ImageType": "machine", "Public": True, "PlatformDetails": "Linux/UNIX",
                            "RootDeviceType": "ebs", "RootDeviceName": "/dev/xvda", "VirtualizationType": "hvm",
                            "Hypervisor": "xen", "EnaSupport": True, "ImdsSupport": m["imds"],
                            "CreationDate": "2026-09-01T00:00:00.000Z"} for i, m in items]}

    def op_DescribeInstanceTypes(self, p, req):
        names = p.get("InstanceTypes") or list(INSTANCE_TYPES)
        for n in names:
            if n not in INSTANCE_TYPES:
                raise AwsError("InvalidInstanceType", f"The following supplied instance types do not exist: [{n}]")
        return {"InstanceTypes": [{"InstanceType": n, "CurrentGeneration": True, "FreeTierEligible": n in
                                   ("t2.micro", "t3.micro"), "VCpuInfo": {"DefaultVCpus": INSTANCE_TYPES[n][0]},
                                   "MemoryInfo": {"SizeInMiB": INSTANCE_TYPES[n][1]}, "Hypervisor": "nitro",
                                   "ProcessorInfo": {"SupportedArchitectures": ["x86_64"]}} for n in names]}

    # ================================================================== region / tags
    def op_DescribeAvailabilityZones(self, p, req):
        return {"AvailabilityZones": [{"ZoneName": f"{self.region()}{z}", "ZoneId": f"apne1-az{i + 1}",
                                       "State": "available", "RegionName": self.region(), "ZoneType": "availability-zone",
                                       "GroupName": self.region(), "NetworkBorderGroup": self.region(),
                                       "OptInStatus": "opt-in-not-required", "Messages": []}
                                      for i, z in enumerate(AZS)]}

    def op_DescribeRegions(self, p, req):
        return {"Regions": [{"RegionName": r, "Endpoint": f"ec2.{r}.amazonaws.com", "OptInStatus": "opt-in-not-required"}
                            for r in ("ap-northeast-1", "us-east-1")]}

    def op_DescribeAccountAttributes(self, p, req):
        default = next((v.id for v in self.vpcs.values() if v.is_default), "none")
        attrs = {"default-vpc": default, "max-instances": str(VCPU_LIMIT), "supported-platforms": "VPC",
                 "vpc-max-security-groups-per-interface": "5", "max-elastic-ips": "5", "vpc-max-elastic-ips": "5"}
        return {"AccountAttributes": [{"AttributeName": k, "AttributeValues": [{"AttributeValue": v}]}
                                      for k, v in attrs.items()]}

    def _taggable(self, rid: str) -> dict[str, str] | None:
        for table in (self.instances, self.vpcs, self.subnets, self.sgs, self.route_tables, self.nacls, self.enis,
                      self.natgws, self.flow_logs):
            if rid in table:
                return table[rid].tags
        if rid in self.igws:
            return self.igws[rid]["tags"]
        if rid in self.addresses:
            return self.addresses[rid].tags
        return None

    def op_CreateTags(self, p, req):
        for rid in p.get("Resources") or []:
            tags = self._taggable(rid)
            if tags is None:
                raise not_found("InvalidID", f"The ID '{rid}' is not valid")
            for t in p.get("Tags") or []:
                tags[t["Key"]] = t.get("Value", "")
        return {}

    def op_DeleteTags(self, p, req):
        for rid in p.get("Resources") or []:
            tags = self._taggable(rid)
            if tags is None:
                raise not_found("InvalidID", f"The ID '{rid}' is not valid")
            for t in p.get("Tags") or [{"Key": k} for k in list(tags)]:
                if "Value" not in t or tags.get(t["Key"]) == t["Value"]:
                    tags.pop(t["Key"], None)
        return {}

    def op_DescribeTags(self, p, req):
        rows = []
        kinds = (("instance", self.instances), ("vpc", self.vpcs), ("subnet", self.subnets),
                 ("security-group", self.sgs), ("route-table", self.route_tables), ("network-acl", self.nacls),
                 ("network-interface", self.enis), ("natgateway", self.natgws))
        for kind, table in kinds:
            for rid, obj in table.items():
                rows += [(rid, kind, k, v) for k, v in obj.tags.items()]
        rows = apply_filters(rows, p.get("Filters"), lambda r: {"resource-id": r[0], "resource-type": r[1],
                                                                "key": r[2], "value": r[3]})
        return {"Tags": [{"ResourceId": r[0], "ResourceType": r[1], "Key": r[2], "Value": r[3]} for r in rows]}

    # ================================================================== metrics
    def gauges(self) -> list[Metric]:
        """AWS/EC2 メトリクス。基本モニタリングは 5 分粒度、詳細モニタリングは 1 分粒度で発行する (AWS と同じ)。"""
        with self.lock:
            self._refresh_all()
            now = self.clock.now()
            out = []
            for inst in self.instances.values():
                if inst.state != "running":
                    continue
                period = 60 if inst.monitoring == "enabled" else 300
                ts = float(int(now // period) * period)
                dims = {"InstanceId": inst.id}
                values: list[tuple[str, float, str]] = []
                ist, sst = self._status(inst)
                values += [("StatusCheckFailed_Instance", 1.0 if ist == "impaired" else 0.0, "Count"),
                           ("StatusCheckFailed_System", 1.0 if sst == "impaired" else 0.0, "Count"),
                           ("StatusCheckFailed", 1.0 if "impaired" in (ist, sst) else 0.0, "Count")]
                if self.netplane.enabled:
                    cpu = self.netplane.cpu_usage_seconds(inst.id)
                    if cpu is not None:
                        prev = inst.cpu_sample
                        inst.cpu_sample = (now, cpu)
                        if prev and now > prev[0]:
                            util = (cpu - prev[1]) / ((now - prev[0]) * INSTANCE_TYPES[inst.type][0]) * 100
                            values.append(("CPUUtilization", max(0.0, min(100.0, util)), "Percent"))
                    stats = self.netplane.eni_stats(self.vpcs[inst.vpc_id].idx, self.enis[inst.eni_id].idx)
                    if stats:
                        prev_stats, inst.net_sample = inst.net_sample, stats
                        if prev_stats:
                            for name, key in (("NetworkIn", "in_bytes"), ("NetworkOut", "out_bytes"),
                                              ("NetworkPacketsIn", "in_packets"), ("NetworkPacketsOut", "out_packets")):
                                unit = "Bytes" if "bytes" in key else "Count"
                                values.append((name, float(max(0, stats[key] - prev_stats[key])), unit))
                else:
                    values.append(("CPUUtilization", 0.0, "Percent"))
                out.extend(Metric("AWS/EC2", n, v, dims, u, ts) for n, v, u in values)
            return out

    # ================================================================== state
    def state(self) -> dict[str, Any]:
        with self.lock:
            self._refresh_all()
            return {
                "dataplane": {"driver": self.netplane.name, "note": getattr(self.netplane, "reason", "")},
                "vpcs": {v.id: {"cidr": v.cidr, "default": v.is_default, "igw": v.igw, "router_netns":
                                f"awsemu-vpc{v.idx}" if self.netplane.enabled else None,
                                "subnets": {s.id: {"cidr": s.cidr, "az": s.az, "route_table": self._subnet_rt(s).id,
                                                   "network_acl": self._subnet_nacl(s).id,
                                                   "public": any(r.target_type == "gateway" and r.dest == "0.0.0.0/0"
                                                                 for r in self._subnet_rt(s).routes)}
                                            for s in self.subnets.values() if s.vpc_id == v.id}}
                         for v in self.vpcs.values()},
                "instances": {i.id: {"state": i.state, "type": i.type, "private_ip": self.enis[i.eni_id].private_ip
                                     if i.eni_id in self.enis else None,
                                     "public_ip": self.enis[i.eni_id].public_ip if i.eni_id in self.enis else None,
                                     "status": dict(zip(("instance", "system"), self._status(i))),
                                     "process_alive": self.netplane.instance_alive(i.id) if i.state == "running" else None,
                                     "security_groups": self.enis[i.eni_id].sg_ids if i.eni_id in self.enis else [],
                                     "tags": i.tags}
                              for i in self.instances.values()},
                "security_groups": {g.id: {"name": g.name, "vpc": g.vpc_id,
                                           "ingress": [f"{x.protocol}:{x.from_port}-{x.to_port} from {x.cidr or x.group}"
                                                       for x in g.ingress],
                                           "egress": [f"{x.protocol}:{x.from_port}-{x.to_port} to {x.cidr or x.group}"
                                                      for x in g.egress]} for g in self.sgs.values()},
                "nat_gateways": {n.id: n.state for n in self.natgws.values()},
                "flow_logs": {f.id: {"resource": f.resource_id, "log_group": f.log_group} for f in self.flow_logs.values()},
            }

    def dump(self) -> dict[str, Any]:
        return {"note": "EC2 のスナップショットは未対応です (実体のプロセスを含むため)"}

    def load(self, data: dict[str, Any]) -> None:
        pass
