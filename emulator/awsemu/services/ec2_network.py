"""EC2 のネットワーク系リソース (VPC / サブネット / ルートテーブル / IGW / NAT GW / EIP / SG / NACL / ENI / フローログ)。

状態はここで管理し、変更のたびにデータプレーン (netplane) に反映する。
"""
from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field
from typing import Any

from ..core import ACCOUNT_ID, AwsError
from ..netplane.linux import NaclEntry, RouterSpec, SgRule
from ._ec2proto import apply_filters, tag_filters, tag_list, tags_from_specs

AZS = ("a", "c", "d")
PROTO_NUM = {"tcp": "6", "udp": "17", "icmp": "1", "-1": "-1", "all": "-1"}


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(9)[:17]}"


def not_found(code: str, msg: str) -> AwsError:
    return AwsError(code, msg)


def proto_str(p: str | int | None) -> str:
    p = str(p if p is not None else "-1").lower()
    return {"6": "tcp", "17": "udp", "1": "icmp", "all": "-1"}.get(p, p)


@dataclass
class Vpc:
    id: str
    cidr: str
    idx: int
    is_default: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    dns_support: bool = True
    dns_hostnames: bool = False
    main_rt: str = ""
    default_sg: str = ""
    default_nacl: str = ""
    igw: str | None = None


@dataclass
class Subnet:
    id: str
    vpc_id: str
    cidr: str
    az: str
    idx: int
    map_public_ip: bool = False
    default_for_az: bool = False
    tags: dict[str, str] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)

    @property
    def net(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.cidr)

    @property
    def gateway(self) -> str:
        return str(self.net.network_address + 1)

    def free_count(self) -> int:
        return self.net.num_addresses - 5 - len(self.used)

    def allocate(self, wanted: str | None = None) -> str:
        net = self.net
        reserved = {net.network_address + i for i in range(4)} | {net.broadcast_address}
        if wanted:
            addr = ipaddress.ip_address(wanted)
            if addr not in net or addr in reserved:
                raise AwsError("InvalidParameterValue", f"Address {wanted} does not fall within the subnet's address range")
            if wanted in self.used:
                raise AwsError("InvalidIPAddress.InUse", f"Address {wanted} is in use.")
            self.used.add(wanted)
            return wanted
        for host in net.hosts():
            if host not in reserved and str(host) not in self.used:
                self.used.add(str(host))
                return str(host)
        raise AwsError("InsufficientFreeAddressesInSubnet",
                       f"There are not enough free addresses in subnet '{self.id}' to satisfy the requested number of instances.")


@dataclass
class Route:
    dest: str
    target_type: str            # local | gateway | nat | instance | eni
    target_id: str
    origin: str = "CreateRoute"


@dataclass
class RouteTable:
    id: str
    vpc_id: str
    routes: list[Route] = field(default_factory=list)
    assoc: dict[str, str] = field(default_factory=dict)       # association id -> subnet id ("" = main)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class SgPerm:
    id: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str | None = None
    group: str | None = None
    description: str | None = None


@dataclass
class SecurityGroup:
    id: str
    name: str
    description: str
    vpc_id: str
    ingress: list[SgPerm] = field(default_factory=list)
    egress: list[SgPerm] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class AclEntry:
    number: int
    egress: bool
    protocol: str
    action: str
    cidr: str
    from_port: int | None = None
    to_port: int | None = None


@dataclass
class NetworkAcl:
    id: str
    vpc_id: str
    is_default: bool
    entries: list[AclEntry] = field(default_factory=list)
    assoc: dict[str, str] = field(default_factory=dict)       # association id -> subnet id
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Eni:
    id: str
    subnet_id: str
    vpc_id: str
    private_ip: str
    mac: str
    idx: int
    sg_ids: list[str]
    kind: str = "interface"           # interface | nat_gateway
    description: str = ""
    owner: str | None = None          # データプレーンのホスト (i-xxx / nat-xxx / lb id)
    device: str = "eth0"
    instance_id: str | None = None
    public_ip: str | None = None
    allocation_id: str | None = None
    requester_managed: bool = False
    attach_id: str | None = None
    auto_public: bool = False          # 起動時にパブリック IP を自動割り当てする (停止/起動で IP が変わる)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class Address:
    allocation_id: str
    public_ip: str
    association_id: str | None = None
    eni_id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class NatGateway:
    id: str
    subnet_id: str
    vpc_id: str
    allocation_id: str
    eni_id: str
    created: float
    state: str = "pending"
    deleted: float | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class FlowLog:
    id: str
    resource_id: str
    traffic_type: str
    destination_type: str
    log_group: str | None
    destination: str | None
    role_arn: str | None
    log_format: str
    max_aggregation: int
    created: float
    tags: dict[str, str] = field(default_factory=dict)
    deliver_status: str = "SUCCESS"
    deliver_error: str | None = None


DEFAULT_FLOW_FORMAT = ("${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} "
                       "${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}")


class NetworkMixin:
    """EC2 サービスのネットワーク部分。self は EC2 サービス。"""

    # ================================================================== state
    def reset_network(self) -> None:
        self.vpcs: dict[str, Vpc] = {}
        self.subnets: dict[str, Subnet] = {}
        self.route_tables: dict[str, RouteTable] = {}
        self.igws: dict[str, dict[str, Any]] = {}
        self.sgs: dict[str, SecurityGroup] = {}
        self.nacls: dict[str, NetworkAcl] = {}
        self.enis: dict[str, Eni] = {}
        self.addresses: dict[str, Address] = {}
        self.natgws: dict[str, NatGateway] = {}
        self.flow_logs: dict[str, FlowLog] = {}
        self.counters = {"vpc": 0, "subnet": 0, "eni": 0, "pub": 10}
        self.public_ips: set[str] = set()

    def _next(self, kind: str) -> int:
        self.counters[kind] += 1
        return self.counters[kind]

    def region(self) -> str:
        return getattr(self, "_region", "ap-northeast-1")

    # ================================================================== lookups
    def _vpc(self, vpc_id: str | None) -> Vpc:
        v = self.vpcs.get(vpc_id or "")
        if v is None:
            raise not_found("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
        return v

    def _subnet(self, subnet_id: str | None) -> Subnet:
        s = self.subnets.get(subnet_id or "")
        if s is None:
            raise not_found("InvalidSubnetID.NotFound", f"The subnet ID '{subnet_id}' does not exist")
        return s

    def _sg(self, sg_id: str | None) -> SecurityGroup:
        g = self.sgs.get(sg_id or "")
        if g is None:
            raise not_found("InvalidGroup.NotFound", f"The security group '{sg_id}' does not exist")
        return g

    def _rt(self, rt_id: str | None) -> RouteTable:
        r = self.route_tables.get(rt_id or "")
        if r is None:
            raise not_found("InvalidRouteTableID.NotFound", f"The routeTable ID '{rt_id}' does not exist")
        return r

    def _nacl(self, acl_id: str | None) -> NetworkAcl:
        a = self.nacls.get(acl_id or "")
        if a is None:
            raise not_found("InvalidNetworkAclID.NotFound", f"The networkAcl ID '{acl_id}' does not exist")
        return a

    def _subnet_rt(self, subnet: Subnet) -> RouteTable:
        for rt in self.route_tables.values():
            if subnet.id in rt.assoc.values():
                return rt
        return self.route_tables[self.vpcs[subnet.vpc_id].main_rt]

    def _subnet_nacl(self, subnet: Subnet) -> NetworkAcl:
        for acl in self.nacls.values():
            if subnet.id in acl.assoc.values():
                return acl
        return self.nacls[self.vpcs[subnet.vpc_id].default_nacl]

    def _resolve_sgs(self, ids: list[str] | None, names: list[str] | None, vpc_id: str) -> list[str]:
        out = []
        for gid in ids or []:
            g = self._sg(gid)
            if g.vpc_id != vpc_id:
                raise AwsError("InvalidParameter", f"Security group {gid} and subnet belong to different networks.")
            out.append(gid)
        for name in names or []:
            match = [g for g in self.sgs.values() if g.name == name and g.vpc_id == vpc_id]
            if not match:
                raise not_found("InvalidGroup.NotFound", f"The security group '{name}' does not exist in VPC '{vpc_id}'")
            out.append(match[0].id)
        return out or [self.vpcs[vpc_id].default_sg]

    # ================================================================== data plane sync
    def sync_vpc(self, vpc: Vpc) -> None:
        """VPC ルーターの設定 (ルート・NACL・NAT) を作り直す。"""
        np = self.netplane
        if not np.enabled:
            return
        spec = RouterSpec()
        subnets = [s for s in self.subnets.values() if s.vpc_id == vpc.id]
        spec.subnets = {s.idx: s.cidr for s in subnets}
        for s in subnets:
            routes = []
            for r in self._subnet_rt(s).routes:
                if r.target_type == "local":
                    continue
                state, nexthop = self._route_state(r, s.vpc_id)
                if state != "active":
                    routes.append((r.dest, "blackhole", None))
                elif r.target_type == "gateway":
                    routes.append((r.dest, "igw", None))
                else:
                    routes.append((r.dest, "via", nexthop))
            spec.tables[s.idx] = routes
            acl = self._subnet_nacl(s)
            for e in acl.entries:
                entry = NaclEntry(e.number, e.protocol, e.action, e.cidr, e.from_port, e.to_port)
                (spec.nacl_out if e.egress else spec.nacl_in).setdefault(s.idx, []).append(entry)
        for eni in self.enis.values():
            if eni.vpc_id == vpc.id and eni.public_ip and self._eni_active(eni):
                spec.public_map[eni.private_ip] = eni.public_ip
        spec.flowlog = any(self._flowlog_enabled(e) for e in self.enis.values() if e.vpc_id == vpc.id)
        np.apply_router(vpc.idx, spec)
        self.sync_public_routes()

    def sync_public_routes(self) -> None:
        if self.netplane.enabled:
            self.netplane.set_public_routes({e.public_ip: self.vpcs[e.vpc_id].idx for e in self.enis.values()
                                             if e.public_ip and self._eni_active(e)})

    def sync_security(self, vpc_id: str | None = None) -> None:
        """ENI ごとのセキュリティグループ (iptables) を作り直す。SG 参照は現在の IP に展開する。"""
        if not self.netplane.enabled:
            return
        for eni in self.enis.values():
            if (vpc_id and eni.vpc_id != vpc_id) or not eni.owner or not self._eni_active(eni):
                continue
            if eni.kind == "nat_gateway":
                self.netplane.apply_security(eni.owner, [], [], False, forward=True)
                continue
            # 同じ名前空間に複数 ENI (ALB) がある場合は SG の和集合をまとめて適用する
            siblings = [e for e in self.enis.values() if e.owner == eni.owner]
            if siblings[0] is not eni:
                continue
            ingress, egress = [], []
            for e in siblings:
                for gid in e.sg_ids:
                    g = self.sgs.get(gid)
                    if g:
                        ingress += self._expand(g.ingress)
                        egress += self._expand(g.egress)
            flow = any(self._flowlog_enabled(e) for e in siblings)
            self.netplane.apply_security(eni.owner, ingress, egress, flow)

    def _expand(self, perms: list[SgPerm]) -> list[SgRule]:
        out = []
        for p in perms:
            if p.cidr:
                out.append(SgRule(p.protocol, p.from_port, p.to_port, p.cidr))
            elif p.group:
                for e in self.enis.values():
                    if p.group in e.sg_ids:
                        out.append(SgRule(p.protocol, p.from_port, p.to_port, f"{e.private_ip}/32"))
        return out

    def _eni_active(self, eni: Eni) -> bool:
        if eni.instance_id:
            inst = self.instances.get(eni.instance_id)
            return inst is not None and inst.state in ("pending", "running", "stopping", "shutting-down")
        return True

    def _flowlog_enabled(self, eni: Eni) -> bool:
        return any(f.resource_id in (eni.id, eni.subnet_id, eni.vpc_id) for f in self.flow_logs.values())

    def _route_state(self, r: Route, vpc_id: str) -> tuple[str, str | None]:
        """ルートの状態 (active / blackhole) と次ホップ IP。ターゲットが消えたり外れたりすると blackhole。"""
        if r.target_type == "local":
            return "active", None
        if r.target_type == "gateway":
            igw = self.igws.get(r.target_id)
            return ("active", None) if igw and igw.get("vpc") == vpc_id else ("blackhole", None)
        if r.target_type == "nat":
            nat = self.natgws.get(r.target_id)
            if nat and nat.state == "available":
                return "active", self.enis[nat.eni_id].private_ip
            return "blackhole", None
        if r.target_type in ("instance", "eni"):
            eni = self.enis.get(r.target_id) if r.target_type == "eni" else next(
                (e for e in self.enis.values() if e.instance_id == r.target_id), None)
            if eni and self._eni_active(eni):
                return "active", eni.private_ip
        return "blackhole", None

    # ================================================================== ENI (他サービスからも使う)
    def create_eni(self, subnet: Subnet, sg_ids: list[str], description: str = "", kind: str = "interface",
                   private_ip: str | None = None, requester_managed: bool = False) -> Eni:
        idx = self._next("eni")
        mac = "06:" + ":".join(f"{b:02x}" for b in secrets.token_bytes(5))
        eni = Eni(new_id("eni"), subnet.id, subnet.vpc_id, subnet.allocate(private_ip), mac, idx, list(sg_ids),
                  kind=kind, description=description, requester_managed=requester_managed)
        self.enis[eni.id] = eni
        return eni

    def attach_eni_dataplane(self, eni: Eni, owner: str, device: str = "eth0", default_route: bool = True) -> None:
        eni.owner, eni.device = owner, device
        if self.netplane.enabled:
            subnet = self.subnets[eni.subnet_id]
            vpc = self.vpcs[eni.vpc_id]
            self.netplane.attach_eni(owner, device, vpc.idx, eni.idx, subnet.idx, eni.private_ip,
                                     subnet.net.prefixlen, subnet.gateway, eni.mac, default_route)

    def delete_eni(self, eni: Eni) -> None:
        if self.netplane.enabled:
            self.netplane.detach_eni(self.vpcs[eni.vpc_id].idx, eni.idx)
        self.subnets[eni.subnet_id].used.discard(eni.private_ip)
        self.release_public_ip(eni)
        self.enis.pop(eni.id, None)

    def assign_public_ip(self, eni: Eni) -> None:
        if eni.public_ip:
            return
        eni.public_ip = self._allocate_public()

    def release_public_ip(self, eni: Eni) -> None:
        if eni.public_ip and not eni.allocation_id:
            self.public_ips.discard(eni.public_ip)
            eni.public_ip = None

    def _allocate_public(self) -> str:
        pool = ipaddress.ip_network("198.19.0.0/16")
        while True:
            n = self.counters["pub"]
            self.counters["pub"] += 1
            if n >= pool.num_addresses - 1:
                self.counters["pub"] = 10
            addr = str(pool.network_address + n)
            if addr not in self.public_ips and not addr.endswith(".0") and not addr.endswith(".255"):
                self.public_ips.add(addr)
                return addr

    def eni_hostname(self, ip: str) -> str:
        return f"ip-{ip.replace('.', '-')}.{self.region()}.compute.internal"

    # ================================================================== default VPC
    def create_default_vpc(self) -> None:
        vpc = self._create_vpc("172.31.0.0/16", is_default=True)
        igw_id = new_id("igw")
        self.igws[igw_id] = {"id": igw_id, "vpc": vpc.id, "tags": {}}
        vpc.igw = igw_id
        self.route_tables[vpc.main_rt].routes.append(Route("0.0.0.0/0", "gateway", igw_id, "CreateRoute"))
        for i, az in enumerate(AZS):
            s = self._create_subnet(vpc, f"172.31.{i * 16}.0/20", f"{self.region()}{az}")
            s.map_public_ip = True
            s.default_for_az = True
        self.sync_vpc(vpc)

    # ================================================================== VPC
    def _create_vpc(self, cidr: str, is_default: bool = False, tags: dict[str, str] | None = None) -> Vpc:
        try:
            net = ipaddress.ip_network(cidr)
        except ValueError:
            raise AwsError("InvalidParameterValue", f"Value ({cidr}) for parameter cidrBlock is invalid. "
                           "This is not a valid CIDR block.")
        if not 16 <= net.prefixlen <= 28:
            raise AwsError("InvalidVpc.Range", f"The CIDR '{cidr}' is invalid.")
        idx = self._next("vpc")
        if idx > 250:
            raise AwsError("VpcLimitExceeded", "The maximum number of VPCs has been reached.")
        vpc = Vpc(new_id("vpc"), str(net), idx, is_default, tags or {})
        self.vpcs[vpc.id] = vpc
        rt = RouteTable(new_id("rtb"), vpc.id, [Route(str(net), "local", "local", "CreateRouteTable")],
                        {new_id("rtbassoc"): ""})
        self.route_tables[rt.id] = rt
        vpc.main_rt = rt.id
        sg = SecurityGroup(new_id("sg"), "default", "default VPC security group", vpc.id)
        sg.ingress.append(SgPerm(new_id("sgr"), "-1", None, None, group=sg.id))
        sg.egress.append(SgPerm(new_id("sgr"), "-1", None, None, cidr="0.0.0.0/0"))
        self.sgs[sg.id] = sg
        vpc.default_sg = sg.id
        acl = NetworkAcl(new_id("acl"), vpc.id, True, [
            AclEntry(100, False, "-1", "allow", "0.0.0.0/0"), AclEntry(32767, False, "-1", "deny", "0.0.0.0/0"),
            AclEntry(100, True, "-1", "allow", "0.0.0.0/0"), AclEntry(32767, True, "-1", "deny", "0.0.0.0/0")])
        self.nacls[acl.id] = acl
        vpc.default_nacl = acl.id
        if self.netplane.enabled:
            self.netplane.ensure_vpc(idx)
            self.start_imds(vpc)
        return vpc

    def _vpc_view(self, v: Vpc) -> dict[str, Any]:
        return {"VpcId": v.id, "CidrBlock": v.cidr, "State": "available", "DhcpOptionsId": "dopt-default",
                "InstanceTenancy": "default", "IsDefault": v.is_default, "OwnerId": ACCOUNT_ID,
                "CidrBlockAssociationSet": [{"AssociationId": f"vpc-cidr-assoc-{v.id[4:]}", "CidrBlock": v.cidr,
                                             "CidrBlockState": {"State": "associated"}}],
                "Tags": tag_list(v.tags)}

    def op_CreateVpc(self, p, req):
        vpc = self._create_vpc(p.get("CidrBlock", ""), tags=tags_from_specs(p.get("TagSpecifications"), "vpc"))
        self.sync_vpc(vpc)
        return {"Vpc": {**self._vpc_view(vpc), "State": "pending"}}

    def op_DescribeVpcs(self, p, req):
        items = self._by_ids(self.vpcs, p.get("VpcIds"), "InvalidVpcID.NotFound", "vpc")
        items = apply_filters(items, p.get("Filters"), lambda v: {
            "vpc-id": v.id, "cidr": v.cidr, "cidr-block": v.cidr, "cidr-block-association.cidr-block": v.cidr,
            "is-default": v.is_default, "state": "available", "owner-id": ACCOUNT_ID, **tag_filters(v.tags)})
        return {"Vpcs": [self._vpc_view(v) for v in items]}

    def op_DeleteVpc(self, p, req):
        vpc = self._vpc(p.get("VpcId"))
        deps = [s for s in self.subnets.values() if s.vpc_id == vpc.id] or \
            [g for g in self.igws.values() if g.get("vpc") == vpc.id] or \
            [g for g in self.sgs.values() if g.vpc_id == vpc.id and g.id != vpc.default_sg] or \
            [r for r in self.route_tables.values() if r.vpc_id == vpc.id and r.id != vpc.main_rt]
        if deps:
            raise AwsError("DependencyViolation", f"The vpc '{vpc.id}' has dependencies and cannot be deleted.")
        for table in (self.route_tables, self.sgs, self.nacls):
            for k in [k for k, v in table.items() if v.vpc_id == vpc.id]:
                del table[k]
        self.stop_imds(vpc.id)
        self.netplane.delete_vpc(vpc.idx)
        del self.vpcs[vpc.id]
        return {}

    def op_ModifyVpcAttribute(self, p, req):
        vpc = self._vpc(p.get("VpcId"))
        if "EnableDnsSupport" in p:
            vpc.dns_support = p["EnableDnsSupport"]["Value"]
        if "EnableDnsHostnames" in p:
            vpc.dns_hostnames = p["EnableDnsHostnames"]["Value"]
        return {}

    def op_DescribeVpcAttribute(self, p, req):
        vpc = self._vpc(p.get("VpcId"))
        attr = p.get("Attribute")
        out: dict[str, Any] = {"VpcId": vpc.id}
        if attr == "enableDnsSupport":
            out["EnableDnsSupport"] = {"Value": vpc.dns_support}
        elif attr == "enableDnsHostnames":
            out["EnableDnsHostnames"] = {"Value": vpc.dns_hostnames}
        else:
            raise AwsError("InvalidParameterValue", f"Value ({attr}) for parameter attribute is invalid.")
        return out

    # ================================================================== subnets
    def _create_subnet(self, vpc: Vpc, cidr: str, az: str, tags: dict[str, str] | None = None) -> Subnet:
        try:
            net = ipaddress.ip_network(cidr)
        except ValueError:
            raise AwsError("InvalidSubnet.Range", f"The CIDR '{cidr}' is invalid.")
        if not net.subnet_of(ipaddress.ip_network(vpc.cidr)) or not 16 <= net.prefixlen <= 28:
            raise AwsError("InvalidSubnet.Range", f"The CIDR '{cidr}' is invalid.")
        for s in self.subnets.values():
            if s.vpc_id == vpc.id and s.net.overlaps(net):
                raise AwsError("InvalidSubnet.Conflict", f"The CIDR '{cidr}' conflicts with another subnet")
        if az not in [f"{self.region()}{z}" for z in AZS]:
            raise AwsError("InvalidParameterValue", f"Value ({az}) for parameter availabilityZone is invalid. "
                           f"Subnets can currently only be created in the following availability zones: "
                           f"{', '.join(self.region() + z for z in AZS)}.")
        s = Subnet(new_id("subnet"), vpc.id, str(net), az, self._next("subnet"), tags=tags or {})
        self.subnets[s.id] = s
        if self.netplane.enabled:
            self.netplane.ensure_subnet(vpc.idx, s.idx, s.cidr)
        return s

    def _subnet_view(self, s: Subnet) -> dict[str, Any]:
        return {"SubnetId": s.id, "VpcId": s.vpc_id, "CidrBlock": s.cidr, "AvailabilityZone": s.az,
                "AvailabilityZoneId": f"apne1-az{AZS.index(s.az[-1]) + 1}", "State": "available",
                "AvailableIpAddressCount": s.free_count(), "DefaultForAz": s.default_for_az,
                "MapPublicIpOnLaunch": s.map_public_ip, "OwnerId": ACCOUNT_ID,
                "SubnetArn": f"arn:aws:ec2:{self.region()}:{ACCOUNT_ID}:subnet/{s.id}", "Tags": tag_list(s.tags)}

    def op_CreateSubnet(self, p, req):
        vpc = self._vpc(p.get("VpcId"))
        az = p.get("AvailabilityZone") or f"{self.region()}{AZS[len([s for s in self.subnets.values() if s.vpc_id == vpc.id]) % 3]}"
        s = self._create_subnet(vpc, p.get("CidrBlock", ""), az, tags_from_specs(p.get("TagSpecifications"), "subnet"))
        self.sync_vpc(vpc)
        return {"Subnet": self._subnet_view(s)}

    def op_DescribeSubnets(self, p, req):
        items = self._by_ids(self.subnets, p.get("SubnetIds"), "InvalidSubnetID.NotFound", "subnet")
        items = apply_filters(items, p.get("Filters"), lambda s: {
            "subnet-id": s.id, "vpc-id": s.vpc_id, "cidr-block": s.cidr, "cidr": s.cidr,
            "availability-zone": s.az, "default-for-az": s.default_for_az, "state": "available",
            "map-public-ip-on-launch": s.map_public_ip, **tag_filters(s.tags)})
        return {"Subnets": [self._subnet_view(s) for s in items]}

    def op_DeleteSubnet(self, p, req):
        s = self._subnet(p.get("SubnetId"))
        if any(e.subnet_id == s.id for e in self.enis.values()):
            raise AwsError("DependencyViolation", f"The subnet '{s.id}' has dependencies and cannot be deleted.")
        for table in (self.route_tables, self.nacls):
            for obj in table.values():
                for k in [k for k, v in obj.assoc.items() if v == s.id]:
                    del obj.assoc[k]
        del self.subnets[s.id]
        vpc = self.vpcs[s.vpc_id]
        self.netplane.delete_subnet(vpc.idx, s.idx)
        self.sync_vpc(vpc)
        return {}

    def op_ModifySubnetAttribute(self, p, req):
        s = self._subnet(p.get("SubnetId"))
        if "MapPublicIpOnLaunch" in p:
            s.map_public_ip = p["MapPublicIpOnLaunch"]["Value"]
        return {}

    # ================================================================== internet gateways
    def _igw(self, igw_id: str | None) -> dict[str, Any]:
        g = self.igws.get(igw_id or "")
        if g is None:
            raise not_found("InvalidInternetGatewayID.NotFound", f"The internetGateway ID '{igw_id}' does not exist")
        return g

    def _igw_view(self, g: dict[str, Any]) -> dict[str, Any]:
        return {"InternetGatewayId": g["id"], "OwnerId": ACCOUNT_ID, "Tags": tag_list(g["tags"]),
                "Attachments": [{"VpcId": g["vpc"], "State": "available"}] if g.get("vpc") else []}

    def op_CreateInternetGateway(self, p, req):
        g = {"id": new_id("igw"), "vpc": None, "tags": tags_from_specs(p.get("TagSpecifications"), "internet-gateway")}
        self.igws[g["id"]] = g
        return {"InternetGateway": self._igw_view(g)}

    def op_AttachInternetGateway(self, p, req):
        g, vpc = self._igw(p.get("InternetGatewayId")), self._vpc(p.get("VpcId"))
        if g.get("vpc"):
            raise AwsError("Resource.AlreadyAssociated", f"resource {g['id']} is already attached to network {g['vpc']}")
        if vpc.igw:
            raise AwsError("Resource.AlreadyAssociated", f"network {vpc.id} already has an internet gateway attached")
        g["vpc"], vpc.igw = vpc.id, g["id"]
        self.sync_vpc(vpc)
        return {}

    def op_DetachInternetGateway(self, p, req):
        g, vpc = self._igw(p.get("InternetGatewayId")), self._vpc(p.get("VpcId"))
        if g.get("vpc") != vpc.id:
            raise AwsError("Gateway.NotAttached", f"resource {g['id']} is not attached to network {vpc.id}")
        if any(e.public_ip and e.vpc_id == vpc.id and e.allocation_id for e in self.enis.values()):
            raise AwsError("DependencyViolation", f"Network {vpc.id} has some mapped public address(es). "
                           "Please unmap those public address(es) before detaching the gateway.")
        g["vpc"], vpc.igw = None, None
        self.sync_vpc(vpc)
        return {}

    def op_DeleteInternetGateway(self, p, req):
        g = self._igw(p.get("InternetGatewayId"))
        if g.get("vpc"):
            raise AwsError("DependencyViolation", f"The internetGateway '{g['id']}' has dependencies and cannot be deleted.")
        del self.igws[g["id"]]
        return {}

    def op_DescribeInternetGateways(self, p, req):
        items = self._by_ids(self.igws, p.get("InternetGatewayIds"), "InvalidInternetGatewayID.NotFound",
                             "internetGateway")
        items = apply_filters(items, p.get("Filters"), lambda g: {
            "internet-gateway-id": g["id"], "attachment.vpc-id": g.get("vpc"),
            "attachment.state": "available" if g.get("vpc") else None, **tag_filters(g["tags"])})
        return {"InternetGateways": [self._igw_view(g) for g in items]}

    # ================================================================== Elastic IP
    def _address(self, alloc_id: str | None = None, public_ip: str | None = None) -> Address:
        for a in self.addresses.values():
            if a.allocation_id == alloc_id or (public_ip and a.public_ip == public_ip):
                return a
        raise not_found("InvalidAllocationID.NotFound", f"The allocation ID '{alloc_id or public_ip}' does not exist")

    def _address_view(self, a: Address) -> dict[str, Any]:
        eni = self.enis.get(a.eni_id or "")
        return {"AllocationId": a.allocation_id, "PublicIp": a.public_ip, "Domain": "vpc",
                "AssociationId": a.association_id, "NetworkInterfaceId": a.eni_id,
                "PrivateIpAddress": eni.private_ip if eni else None,
                "InstanceId": eni.instance_id if eni else None, "NetworkBorderGroup": self.region(),
                "PublicIpv4Pool": "amazon", "Tags": tag_list(a.tags)}

    def op_AllocateAddress(self, p, req):
        if len(self.addresses) >= 5:
            raise AwsError("AddressLimitExceeded", "The maximum number of addresses has been reached.")
        a = Address(new_id("eipalloc"), self._allocate_public(), tags=tags_from_specs(p.get("TagSpecifications"),
                                                                                     "elastic-ip"))
        self.addresses[a.allocation_id] = a
        return {"AllocationId": a.allocation_id, "PublicIp": a.public_ip, "Domain": "vpc",
                "PublicIpv4Pool": "amazon", "NetworkBorderGroup": self.region()}

    def op_ReleaseAddress(self, p, req):
        a = self._address(p.get("AllocationId"), p.get("PublicIp"))
        if a.association_id:
            raise AwsError("InvalidIPAddress.InUse", f"Address {a.public_ip} is in use.")
        self.public_ips.discard(a.public_ip)
        del self.addresses[a.allocation_id]
        return {}

    def op_DescribeAddresses(self, p, req):
        items = list(self.addresses.values())
        if p.get("AllocationIds"):
            items = [self._address(i) for i in p["AllocationIds"]]
        items = apply_filters(items, p.get("Filters"), lambda a: {
            "allocation-id": a.allocation_id, "public-ip": a.public_ip, "association-id": a.association_id,
            "network-interface-id": a.eni_id, "domain": "vpc", **tag_filters(a.tags)})
        return {"Addresses": [self._address_view(a) for a in items]}

    def op_AssociateAddress(self, p, req):
        a = self._address(p.get("AllocationId"), p.get("PublicIp"))
        if p.get("NetworkInterfaceId"):
            eni = self.enis.get(p["NetworkInterfaceId"])
            if eni is None:
                raise not_found("InvalidNetworkInterfaceID.NotFound",
                                f"The networkInterface ID '{p['NetworkInterfaceId']}' does not exist")
        else:
            inst = self._instance(p.get("InstanceId"))
            eni = self.enis[inst.eni_id]
        if not self.vpcs[eni.vpc_id].igw:
            raise AwsError("Gateway.NotAttached", f"Network {eni.vpc_id} is not attached to any internet gateway")
        if a.association_id and not p.get("AllowReassociation", True):
            raise AwsError("Resource.AlreadyAssociated", f"resource {a.allocation_id} is already associated")
        self._disassociate(a)
        self.release_public_ip(eni)
        a.association_id, a.eni_id = new_id("eipassoc"), eni.id
        eni.public_ip, eni.allocation_id = a.public_ip, a.allocation_id
        self.sync_vpc(self.vpcs[eni.vpc_id])
        return {"AssociationId": a.association_id}

    def _disassociate(self, a: Address) -> None:
        eni = self.enis.get(a.eni_id or "")
        if eni:
            eni.public_ip, eni.allocation_id = None, None
            if eni.instance_id and eni.auto_public:
                inst = self.instances.get(eni.instance_id)
                if inst and inst.state in ("pending", "running"):
                    self.assign_public_ip(eni)
            self.sync_vpc(self.vpcs[eni.vpc_id])
        a.association_id, a.eni_id = None, None

    def op_DisassociateAddress(self, p, req):
        a = next((x for x in self.addresses.values() if x.association_id == p.get("AssociationId")
                  or (p.get("PublicIp") and x.public_ip == p.get("PublicIp"))), None)
        if a is None:
            raise not_found("InvalidAssociationID.NotFound",
                            f"The association ID '{p.get('AssociationId')}' does not exist")
        self._disassociate(a)
        return {}

    # ================================================================== NAT gateways
    def _natgw_view(self, n: NatGateway) -> dict[str, Any]:
        self._refresh_natgw(n)
        eni = self.enis.get(n.eni_id)
        addr = self.addresses.get(n.allocation_id)
        return {"NatGatewayId": n.id, "SubnetId": n.subnet_id, "VpcId": n.vpc_id, "State": n.state,
                "CreateTime": n.created, "DeleteTime": n.deleted, "ConnectivityType": "public",
                "NatGatewayAddresses": [{"AllocationId": n.allocation_id, "NetworkInterfaceId": n.eni_id,
                                         "PrivateIp": eni.private_ip if eni else None,
                                         "PublicIp": addr.public_ip if addr else None, "IsPrimary": True,
                                         "Status": "succeeded"}],
                "Tags": tag_list(n.tags)}

    def _refresh_natgw(self, n: NatGateway) -> None:
        if n.state == "pending" and self.clock.now() >= n.created + 3:
            n.state = "available"
            self.sync_vpc(self.vpcs[n.vpc_id])
        if n.state == "deleting" and self.clock.now() >= (n.deleted or 0) + 3:
            n.state = "deleted"

    def op_CreateNatGateway(self, p, req):
        subnet = self._subnet(p.get("SubnetId"))
        a = self._address(p.get("AllocationId"))
        if a.association_id:
            raise AwsError("Resource.AlreadyAssociated", f"Elastic IP address [{a.allocation_id}] is already associated")
        nat_id = new_id("nat")
        eni = self.create_eni(subnet, [], f"Interface for NAT Gateway {nat_id}", "nat_gateway", requester_managed=True)
        n = NatGateway(nat_id, subnet.id, subnet.vpc_id, a.allocation_id, eni.id, self.clock.now(),
                       tags=tags_from_specs(p.get("TagSpecifications"), "natgateway"))
        self.natgws[n.id] = n
        a.association_id, a.eni_id = new_id("eipassoc"), eni.id
        eni.public_ip, eni.allocation_id = a.public_ip, a.allocation_id
        if self.netplane.enabled:
            self.netplane.ensure_host(n.id)
            self.attach_eni_dataplane(eni, n.id)
            self.sync_security(subnet.vpc_id)
        self.sync_vpc(self.vpcs[subnet.vpc_id])
        return {"NatGateway": self._natgw_view(n), "ClientToken": p.get("ClientToken")}

    def op_DescribeNatGateways(self, p, req):
        items = self._by_ids(self.natgws, p.get("NatGatewayIds"), "NatGatewayNotFound", "NAT gateway")
        items = apply_filters(items, p.get("Filter"), lambda n: {
            "nat-gateway-id": n.id, "state": n.state, "subnet-id": n.subnet_id, "vpc-id": n.vpc_id,
            **tag_filters(n.tags)})
        return {"NatGateways": [self._natgw_view(n) for n in items]}

    def op_DeleteNatGateway(self, p, req):
        n = self.natgws.get(p.get("NatGatewayId") or "")
        if n is None:
            raise not_found("NatGatewayNotFound", f"The Nat Gateway {p.get('NatGatewayId')} was not found")
        if n.state in ("deleting", "deleted"):
            return {"NatGatewayId": n.id}
        n.state, n.deleted = "deleting", self.clock.now()
        eni = self.enis.get(n.eni_id)
        a = self.addresses.get(n.allocation_id)
        if a:
            a.association_id, a.eni_id = None, None
        if eni:
            eni.public_ip, eni.allocation_id = None, None
            self.delete_eni(eni)
        self.netplane.delete_host(n.id)
        self.sync_vpc(self.vpcs[n.vpc_id])
        return {"NatGatewayId": n.id}

    # ================================================================== route tables
    def _route_view(self, r: Route, vpc_id: str) -> dict[str, Any]:
        state, _ = self._route_state(r, vpc_id)
        out: dict[str, Any] = {"DestinationCidrBlock": r.dest, "Origin": r.origin, "State": state}
        if r.target_type in ("local", "gateway"):
            out["GatewayId"] = r.target_id
        elif r.target_type == "nat":
            out["NatGatewayId"] = r.target_id
        elif r.target_type == "instance":
            out["InstanceId"] = r.target_id
        elif r.target_type == "eni":
            out["NetworkInterfaceId"] = r.target_id
        return out

    def _rt_view(self, rt: RouteTable) -> dict[str, Any]:
        assocs = []
        for aid, sid in rt.assoc.items():
            a: dict[str, Any] = {"RouteTableAssociationId": aid, "RouteTableId": rt.id, "Main": sid == "",
                                 "AssociationState": {"State": "associated"}}
            if sid:
                a["SubnetId"] = sid
            assocs.append(a)
        return {"RouteTableId": rt.id, "VpcId": rt.vpc_id, "OwnerId": ACCOUNT_ID, "Associations": assocs,
                "Routes": [self._route_view(r, rt.vpc_id) for r in rt.routes], "PropagatingVgws": [],
                "Tags": tag_list(rt.tags)}

    def op_CreateRouteTable(self, p, req):
        vpc = self._vpc(p.get("VpcId"))
        rt = RouteTable(new_id("rtb"), vpc.id, [Route(vpc.cidr, "local", "local", "CreateRouteTable")],
                        tags=tags_from_specs(p.get("TagSpecifications"), "route-table"))
        self.route_tables[rt.id] = rt
        return {"RouteTable": self._rt_view(rt)}

    def op_DescribeRouteTables(self, p, req):
        items = self._by_ids(self.route_tables, p.get("RouteTableIds"), "InvalidRouteTableID.NotFound", "routeTable")
        items = apply_filters(items, p.get("Filters"), lambda rt: {
            "route-table-id": rt.id, "vpc-id": rt.vpc_id, "association.subnet-id": [s for s in rt.assoc.values() if s],
            "association.main": "" in rt.assoc.values(), "association.route-table-association-id": list(rt.assoc),
            "route.gateway-id": [r.target_id for r in rt.routes if r.target_type in ("gateway", "local")],
            "route.nat-gateway-id": [r.target_id for r in rt.routes if r.target_type == "nat"],
            "route.destination-cidr-block": [r.dest for r in rt.routes],
            "route.state": [self._route_state(r, rt.vpc_id)[0] for r in rt.routes], **tag_filters(rt.tags)})
        return {"RouteTables": [self._rt_view(rt) for rt in items]}

    def op_DeleteRouteTable(self, p, req):
        rt = self._rt(p.get("RouteTableId"))
        if rt.assoc:
            raise AwsError("DependencyViolation", f"The routeTable '{rt.id}' has dependencies and cannot be deleted.")
        del self.route_tables[rt.id]
        return {}

    def op_AssociateRouteTable(self, p, req):
        rt = self._rt(p.get("RouteTableId"))
        s = self._subnet(p.get("SubnetId"))
        if s.vpc_id != rt.vpc_id:
            raise AwsError("InvalidParameterValue", "Route table and subnet belong to different networks")
        for other in self.route_tables.values():
            if s.id in other.assoc.values():
                raise AwsError("Resource.AlreadyAssociated", f"the specified association for route table "
                               f"{other.id} conflicts with an existing association")
        aid = new_id("rtbassoc")
        rt.assoc[aid] = s.id
        self.sync_vpc(self.vpcs[rt.vpc_id])
        return {"AssociationId": aid, "AssociationState": {"State": "associated"}}

    def _find_assoc(self, aid: str | None) -> RouteTable:
        for rt in self.route_tables.values():
            if aid in rt.assoc:
                return rt
        raise not_found("InvalidAssociationID.NotFound", f"The association ID '{aid}' does not exist")

    def op_DisassociateRouteTable(self, p, req):
        rt = self._find_assoc(p.get("AssociationId"))
        if rt.assoc[p["AssociationId"]] == "":
            raise AwsError("InvalidParameterValue", "Cannot disassociate the main route table association")
        del rt.assoc[p["AssociationId"]]
        self.sync_vpc(self.vpcs[rt.vpc_id])
        return {}

    def op_ReplaceRouteTableAssociation(self, p, req):
        old = self._find_assoc(p.get("AssociationId"))
        new = self._rt(p.get("RouteTableId"))
        subnet = old.assoc.pop(p["AssociationId"])
        aid = new_id("rtbassoc")
        new.assoc[aid] = subnet
        if subnet == "":
            self.vpcs[new.vpc_id].main_rt = new.id
        self.sync_vpc(self.vpcs[new.vpc_id])
        return {"NewAssociationId": aid, "AssociationState": {"State": "associated"}}

    def _route_target(self, p: dict[str, Any], rt: RouteTable) -> tuple[str, str]:
        if p.get("GatewayId"):
            g = self._igw(p["GatewayId"])
            if g.get("vpc") != rt.vpc_id:
                raise AwsError("InvalidParameterValue", f"route table {rt.id} and network gateway {g['id']} "
                               "belong to different networks")
            return "gateway", g["id"]
        if p.get("NatGatewayId"):
            if p["NatGatewayId"] not in self.natgws:
                raise not_found("InvalidNatGatewayID.NotFound", f"The natGateway ID '{p['NatGatewayId']}' does not exist")
            return "nat", p["NatGatewayId"]
        if p.get("InstanceId"):
            self._instance(p["InstanceId"])
            return "instance", p["InstanceId"]
        if p.get("NetworkInterfaceId"):
            if p["NetworkInterfaceId"] not in self.enis:
                raise not_found("InvalidNetworkInterfaceID.NotFound",
                                f"The networkInterface ID '{p['NetworkInterfaceId']}' does not exist")
            return "eni", p["NetworkInterfaceId"]
        raise AwsError("MissingParameter", "The request must contain exactly one of gatewayId, natGatewayId, "
                       "networkInterfaceId, instanceId")

    def op_CreateRoute(self, p, req):
        rt = self._rt(p.get("RouteTableId"))
        dest = str(ipaddress.ip_network(p.get("DestinationCidrBlock", ""), strict=False))
        if any(r.dest == dest for r in rt.routes):
            raise AwsError("RouteAlreadyExists", f"The route identified by {dest} already exists.")
        kind, target = self._route_target(p, rt)
        rt.routes.append(Route(dest, kind, target))
        self.sync_vpc(self.vpcs[rt.vpc_id])
        return {"Return": True}

    def op_ReplaceRoute(self, p, req):
        rt = self._rt(p.get("RouteTableId"))
        dest = str(ipaddress.ip_network(p.get("DestinationCidrBlock", ""), strict=False))
        route = next((r for r in rt.routes if r.dest == dest), None)
        if route is None or route.target_type == "local":
            raise not_found("InvalidRoute.NotFound", f"There is no route defined for '{dest}' in the route table. "
                            "Use CreateRoute instead.")
        route.target_type, route.target_id = self._route_target(p, rt)
        self.sync_vpc(self.vpcs[rt.vpc_id])
        return {}

    def op_DeleteRoute(self, p, req):
        rt = self._rt(p.get("RouteTableId"))
        dest = p.get("DestinationCidrBlock")
        route = next((r for r in rt.routes if r.dest == dest), None)
        if route is None:
            raise not_found("InvalidRoute.NotFound", f"no route with destination-cidr-block {dest} in route table {rt.id}")
        if route.target_type == "local":
            raise AwsError("InvalidParameterValue", f"cannot remove local route {dest} in route table {rt.id}")
        rt.routes.remove(route)
        self.sync_vpc(self.vpcs[rt.vpc_id])
        return {}

    # ================================================================== security groups
    def _perm_views(self, perms: list[SgPerm]) -> list[dict[str, Any]]:
        grouped: dict[tuple, dict[str, Any]] = {}
        for perm in perms:
            key = (perm.protocol, perm.from_port, perm.to_port)
            view = grouped.setdefault(key, {"IpProtocol": perm.protocol, "FromPort": perm.from_port,
                                            "ToPort": perm.to_port, "IpRanges": [], "UserIdGroupPairs": [],
                                            "Ipv6Ranges": [], "PrefixListIds": []})
            if perm.cidr:
                view["IpRanges"].append({"CidrIp": perm.cidr, "Description": perm.description})
            else:
                view["UserIdGroupPairs"].append({"GroupId": perm.group, "UserId": ACCOUNT_ID,
                                                 "Description": perm.description})
        return list(grouped.values())

    def _sg_view(self, g: SecurityGroup) -> dict[str, Any]:
        return {"GroupId": g.id, "GroupName": g.name, "Description": g.description, "VpcId": g.vpc_id,
                "OwnerId": ACCOUNT_ID, "IpPermissions": self._perm_views(g.ingress),
                "IpPermissionsEgress": self._perm_views(g.egress),
                "SecurityGroupArn": f"arn:aws:ec2:{self.region()}:{ACCOUNT_ID}:security-group/{g.id}",
                "Tags": tag_list(g.tags)}

    def op_CreateSecurityGroup(self, p, req):
        vpc = self._vpc(p.get("VpcId")) if p.get("VpcId") else next(v for v in self.vpcs.values() if v.is_default)
        name = p.get("GroupName", "")
        if not name or name.startswith("sg-"):
            raise AwsError("InvalidParameterValue", "Group names may not be in the format sg-*.")
        if any(g.name == name and g.vpc_id == vpc.id for g in self.sgs.values()):
            raise AwsError("InvalidGroup.Duplicate", f"The security group '{name}' already exists for VPC '{vpc.id}'")
        g = SecurityGroup(new_id("sg"), name, p.get("Description", ""), vpc.id,
                          tags=tags_from_specs(p.get("TagSpecifications"), "security-group"))
        g.egress.append(SgPerm(new_id("sgr"), "-1", None, None, cidr="0.0.0.0/0"))
        self.sgs[g.id] = g
        return {"GroupId": g.id, "SecurityGroupArn": f"arn:aws:ec2:{self.region()}:{ACCOUNT_ID}:security-group/{g.id}",
                "Tags": tag_list(g.tags)}

    def _sg_from_params(self, p: dict[str, Any]) -> SecurityGroup:
        if p.get("GroupId"):
            return self._sg(p["GroupId"])
        name = p.get("GroupName")
        match = [g for g in self.sgs.values() if g.name == name and self.vpcs[g.vpc_id].is_default]
        if not match:
            raise not_found("InvalidGroup.NotFound", f"The security group '{name}' does not exist in default VPC")
        return match[0]

    def op_DescribeSecurityGroups(self, p, req):
        items = self._by_ids(self.sgs, p.get("GroupIds"), "InvalidGroup.NotFound", "security group")
        if p.get("GroupNames"):
            items = [g for g in items if g.name in p["GroupNames"]]
        items = apply_filters(items, p.get("Filters"), lambda g: {
            "group-id": g.id, "group-name": g.name, "vpc-id": g.vpc_id, "description": g.description,
            "ip-permission.from-port": [x.from_port for x in g.ingress],
            "ip-permission.to-port": [x.to_port for x in g.ingress],
            "ip-permission.cidr": [x.cidr for x in g.ingress if x.cidr],
            "ip-permission.group-id": [x.group for x in g.ingress if x.group],
            "ip-permission.protocol": [x.protocol for x in g.ingress], **tag_filters(g.tags)})
        return {"SecurityGroups": [self._sg_view(g) for g in items]}

    def op_DeleteSecurityGroup(self, p, req):
        g = self._sg_from_params(p)
        if g.id == self.vpcs[g.vpc_id].default_sg:
            raise AwsError("CannotDelete", f"the specified group: \"{g.id}\" name: \"default\" cannot be deleted by a user")
        if any(g.id in e.sg_ids for e in self.enis.values()):
            raise AwsError("DependencyViolation", f"resource {g.id} has a dependent object")
        if any(x.group == g.id for other in self.sgs.values() for x in other.ingress + other.egress if other is not g):
            raise AwsError("DependencyViolation", f"resource {g.id} has a dependent object")
        del self.sgs[g.id]
        return {"Return": True, "GroupId": g.id}

    def _perms_from_params(self, p: dict[str, Any], egress: bool) -> list[SgPerm]:
        perms = p.get("IpPermissions")
        if not perms:
            if p.get("IpProtocol") is None:
                raise AwsError("MissingParameter", "The request must contain the parameter ipPermissions")
            perms = [{"IpProtocol": p["IpProtocol"], "FromPort": p.get("FromPort"), "ToPort": p.get("ToPort"),
                      "IpRanges": [{"CidrIp": p["CidrIp"]}] if p.get("CidrIp") else [],
                      "UserIdGroupPairs": [{"GroupId": p["SourceSecurityGroupName"]}]
                      if p.get("SourceSecurityGroupName") else []}]
        out = []
        for perm in perms:
            proto = proto_str(perm.get("IpProtocol"))
            if proto not in ("-1", "tcp", "udp", "icmp") and not proto.isdigit():
                raise AwsError("InvalidParameterValue", f"Invalid value '{perm.get('IpProtocol')}' for IP protocol. "
                               "Unknown protocol.")
            fp, tp = perm.get("FromPort"), perm.get("ToPort")
            if proto in ("tcp", "udp") and (fp is None or tp is None):
                raise AwsError("InvalidParameterValue", "Invalid value for portRange. Must specify both from and to "
                               "ports with TCP/UDP.")
            if proto == "-1":
                fp = tp = None
            for r in perm.get("IpRanges") or []:
                try:
                    cidr = str(ipaddress.ip_network(r["CidrIp"], strict=False))
                except ValueError:
                    raise AwsError("InvalidParameterValue", f"CIDR block {r['CidrIp']} is malformed")
                out.append(SgPerm(new_id("sgr"), proto, fp, tp, cidr=cidr, description=r.get("Description")))
            for pair in perm.get("UserIdGroupPairs") or []:
                gid = pair.get("GroupId") or next((g.id for g in self.sgs.values()
                                                   if g.name == pair.get("GroupName")), None)
                self._sg(gid)
                out.append(SgPerm(new_id("sgr"), proto, fp, tp, group=gid, description=pair.get("Description")))
        return out

    @staticmethod
    def _same(a: SgPerm, b: SgPerm) -> bool:
        return (a.protocol, a.from_port, a.to_port, a.cidr, a.group) == (b.protocol, b.from_port, b.to_port, b.cidr, b.group)

    def _authorize(self, p: dict[str, Any], egress: bool) -> dict[str, Any]:
        g = self._sg_from_params(p)
        target = g.egress if egress else g.ingress
        new = self._perms_from_params(p, egress)
        for perm in new:
            if any(self._same(perm, x) for x in target):
                peer = perm.cidr or perm.group
                proto = perm.protocol.upper() if perm.protocol != "-1" else "ALL"
                raise AwsError("InvalidPermission.Duplicate",
                               f'the specified rule "peer: {peer}, {proto}, from port: {perm.from_port}, '
                               f'to port: {perm.to_port}, ALLOW" already exists')
        target.extend(new)
        self.sync_security(g.vpc_id)
        return {"Return": True, "SecurityGroupRules": [self._rule_view(g, x, egress) for x in new]}

    def _revoke(self, p: dict[str, Any], egress: bool) -> dict[str, Any]:
        g = self._sg_from_params(p)
        target = g.egress if egress else g.ingress
        unknown = []
        if p.get("SecurityGroupRuleIds"):
            ids = set(p["SecurityGroupRuleIds"])
            missing = ids - {x.id for x in target}
            if missing:
                raise not_found("InvalidSecurityGroupRuleId.NotFound",
                                f"The security group rule ID '{sorted(missing)[0]}' does not exist")
            target[:] = [x for x in target if x.id not in ids]
        else:
            for perm in self._perms_from_params(p, egress):
                match = [x for x in target if self._same(perm, x)]
                if match:
                    target.remove(match[0])
                else:
                    unknown.append(perm)
        self.sync_security(g.vpc_id)
        out: dict[str, Any] = {"Return": True}
        if unknown:
            out["UnknownIpPermissions"] = self._perm_views(unknown)
        return out

    def op_AuthorizeSecurityGroupIngress(self, p, req):
        return self._authorize(p, False)

    def op_AuthorizeSecurityGroupEgress(self, p, req):
        return self._authorize(p, True)

    def op_RevokeSecurityGroupIngress(self, p, req):
        return self._revoke(p, False)

    def op_RevokeSecurityGroupEgress(self, p, req):
        return self._revoke(p, True)

    def _rule_view(self, g: SecurityGroup, x: SgPerm, egress: bool) -> dict[str, Any]:
        out: dict[str, Any] = {"SecurityGroupRuleId": x.id, "GroupId": g.id, "GroupOwnerId": ACCOUNT_ID,
                               "IsEgress": egress, "IpProtocol": x.protocol,
                               "FromPort": x.from_port if x.from_port is not None else -1,
                               "ToPort": x.to_port if x.to_port is not None else -1, "Description": x.description,
                               "SecurityGroupRuleArn": f"arn:aws:ec2:{self.region()}:{ACCOUNT_ID}:security-group-rule/{x.id}"}
        if x.cidr:
            out["CidrIpv4"] = x.cidr
        else:
            out["ReferencedGroupInfo"] = {"GroupId": x.group, "UserId": ACCOUNT_ID}
        return out

    def op_DescribeSecurityGroupRules(self, p, req):
        rules = [(g, x, e) for g in self.sgs.values() for e, perms in ((False, g.ingress), (True, g.egress))
                 for x in perms]
        if p.get("SecurityGroupRuleIds"):
            rules = [r for r in rules if r[1].id in p["SecurityGroupRuleIds"]]
        rules = apply_filters(rules, p.get("Filters"), lambda r: {
            "group-id": r[0].id, "security-group-rule-id": r[1].id, **tag_filters(r[0].tags)})
        return {"SecurityGroupRules": [self._rule_view(g, x, e) for g, x, e in rules]}

    # ================================================================== network ACLs
    def _acl_assocs(self, a: NetworkAcl) -> list[tuple[str, str]]:
        """明示的な関連付けに加え、既定 NACL には関連付けのないサブネットも暗黙的に関連付けられる。"""
        out = list(a.assoc.items())
        if a.is_default:
            explicit = {sid for acl in self.nacls.values() for sid in acl.assoc.values()}
            out += [(f"aclassoc-{s.id[7:]}", s.id) for s in self.subnets.values()
                    if s.vpc_id == a.vpc_id and s.id not in explicit]
        return out

    def _acl_view(self, a: NetworkAcl) -> dict[str, Any]:
        entries = []
        for e in sorted(a.entries, key=lambda x: (x.egress, x.number)):
            v: dict[str, Any] = {"RuleNumber": e.number, "Protocol": PROTO_NUM.get(e.protocol, e.protocol),
                                 "RuleAction": e.action, "Egress": e.egress, "CidrBlock": e.cidr}
            if e.from_port is not None:
                v["PortRange"] = {"From": e.from_port, "To": e.to_port}
            entries.append(v)
        return {"NetworkAclId": a.id, "VpcId": a.vpc_id, "IsDefault": a.is_default, "OwnerId": ACCOUNT_ID,
                "Entries": entries, "Tags": tag_list(a.tags),
                "Associations": [{"NetworkAclAssociationId": aid, "NetworkAclId": a.id, "SubnetId": sid}
                                 for aid, sid in self._acl_assocs(a)]}

    def op_CreateNetworkAcl(self, p, req):
        vpc = self._vpc(p.get("VpcId"))
        a = NetworkAcl(new_id("acl"), vpc.id, False, [AclEntry(32767, False, "-1", "deny", "0.0.0.0/0"),
                                                       AclEntry(32767, True, "-1", "deny", "0.0.0.0/0")],
                       tags=tags_from_specs(p.get("TagSpecifications"), "network-acl"))
        self.nacls[a.id] = a
        return {"NetworkAcl": self._acl_view(a)}

    def op_DescribeNetworkAcls(self, p, req):
        items = self._by_ids(self.nacls, p.get("NetworkAclIds"), "InvalidNetworkAclID.NotFound", "networkAcl")
        items = apply_filters(items, p.get("Filters"), lambda a: {
            "network-acl-id": a.id, "vpc-id": a.vpc_id, "default": a.is_default,
            "association.subnet-id": [sid for _, sid in self._acl_assocs(a)],
            "association.association-id": [aid for aid, _ in self._acl_assocs(a)], **tag_filters(a.tags)})
        return {"NetworkAcls": [self._acl_view(a) for a in items]}

    def op_DeleteNetworkAcl(self, p, req):
        a = self._nacl(p.get("NetworkAclId"))
        if a.is_default:
            raise AwsError("InvalidParameterValue", f"cannot delete default network ACL {a.id}")
        if a.assoc:
            raise AwsError("DependencyViolation", f"The networkAcl '{a.id}' has dependencies and cannot be deleted.")
        del self.nacls[a.id]
        return {}

    def _acl_entry(self, p: dict[str, Any]) -> AclEntry:
        number = int(p.get("RuleNumber") or 0)
        if not 1 <= number <= 32766:
            raise AwsError("InvalidParameterValue", f"Value ({number}) for parameter ruleNumber is invalid.")
        proto = proto_str(p.get("Protocol"))
        pr = p.get("PortRange") or {}
        if proto in ("tcp", "udp") and not pr:
            raise AwsError("InvalidParameterValue", "TCP/UDP entries must specify a port range")
        return AclEntry(number, bool(p.get("Egress")), proto, p.get("RuleAction", "deny"),
                        str(ipaddress.ip_network(p.get("CidrBlock", "0.0.0.0/0"), strict=False)),
                        pr.get("From"), pr.get("To"))

    def op_CreateNetworkAclEntry(self, p, req):
        a = self._nacl(p.get("NetworkAclId"))
        e = self._acl_entry(p)
        if any(x.number == e.number and x.egress == e.egress for x in a.entries):
            raise AwsError("NetworkAclEntryAlreadyExists", f"The network acl entry identified by {e.number} already exists.")
        a.entries.append(e)
        self._sync_acl(a)
        return {}

    def op_ReplaceNetworkAclEntry(self, p, req):
        a = self._nacl(p.get("NetworkAclId"))
        e = self._acl_entry(p)
        old = next((x for x in a.entries if x.number == e.number and x.egress == e.egress), None)
        if old is None:
            raise not_found("InvalidNetworkAclEntry.NotFound", f"The network acl entry identified by {e.number} does not exist.")
        a.entries[a.entries.index(old)] = e
        self._sync_acl(a)
        return {}

    def op_DeleteNetworkAclEntry(self, p, req):
        a = self._nacl(p.get("NetworkAclId"))
        number, egress = int(p.get("RuleNumber") or 0), bool(p.get("Egress"))
        old = next((x for x in a.entries if x.number == number and x.egress == egress), None)
        if old is None:
            raise not_found("InvalidNetworkAclEntry.NotFound", f"The network acl entry identified by {number} does not exist.")
        a.entries.remove(old)
        self._sync_acl(a)
        return {}

    def op_ReplaceNetworkAclAssociation(self, p, req):
        new = self._nacl(p.get("NetworkAclId"))
        aid = p.get("AssociationId", "")
        subnet_id = None
        for acl in self.nacls.values():
            if aid in acl.assoc:
                subnet_id = acl.assoc.pop(aid)
        if subnet_id is None and aid.startswith("aclassoc-"):
            subnet_id = next((s.id for s in self.subnets.values() if s.id[7:] == aid[9:]), None)
        if subnet_id is None:
            raise not_found("InvalidAssociationID.NotFound", f"The association ID '{aid}' does not exist")
        new_aid = new_id("aclassoc")
        if not new.is_default:
            new.assoc[new_aid] = subnet_id
        self._sync_acl(new)
        return {"NewAssociationId": new_aid}

    def _sync_acl(self, a: NetworkAcl) -> None:
        self.sync_vpc(self.vpcs[a.vpc_id])

    # ================================================================== ENI / flow logs
    def eni_view(self, e: Eni) -> dict[str, Any]:
        subnet = self.subnets[e.subnet_id]
        out: dict[str, Any] = {
            "NetworkInterfaceId": e.id, "SubnetId": e.subnet_id, "VpcId": e.vpc_id, "AvailabilityZone": subnet.az,
            "Description": e.description, "InterfaceType": e.kind, "MacAddress": e.mac, "OwnerId": ACCOUNT_ID,
            "PrivateIpAddress": e.private_ip, "PrivateDnsName": self.eni_hostname(e.private_ip),
            "RequesterManaged": e.requester_managed, "SourceDestCheck": True,
            "Status": "in-use" if e.owner else "available",
            "Groups": [{"GroupId": g, "GroupName": self.sgs[g].name} for g in e.sg_ids if g in self.sgs],
            "PrivateIpAddresses": [{"Primary": True, "PrivateIpAddress": e.private_ip,
                                    "PrivateDnsName": self.eni_hostname(e.private_ip)}],
            "TagSet": tag_list(e.tags),
        }
        if e.public_ip:
            assoc = {"PublicIp": e.public_ip, "IpOwnerId": "amazon" if not e.allocation_id else ACCOUNT_ID,
                     "PublicDnsName": f"ec2-{e.public_ip.replace('.', '-')}.{self.region()}.compute.amazonaws.com"}
            if e.allocation_id:
                assoc["AllocationId"] = e.allocation_id
            out["Association"] = assoc
            out["PrivateIpAddresses"][0]["Association"] = assoc
        if e.instance_id:
            out["Attachment"] = {"AttachmentId": e.attach_id, "InstanceId": e.instance_id, "DeviceIndex": 0,
                                 "Status": "attached", "DeleteOnTermination": True, "InstanceOwnerId": ACCOUNT_ID}
        elif e.owner:
            out["Attachment"] = {"AttachmentId": e.attach_id or f"ela-attach-{e.id[4:]}", "Status": "attached",
                                 "InstanceOwnerId": "amazon-elb" if e.description.startswith("ELB") else "amazon-aws"}
        return out

    def op_DescribeNetworkInterfaces(self, p, req):
        items = self._by_ids(self.enis, p.get("NetworkInterfaceIds"), "InvalidNetworkInterfaceID.NotFound",
                             "networkInterface")
        items = apply_filters(items, p.get("Filters"), lambda e: {
            "network-interface-id": e.id, "subnet-id": e.subnet_id, "vpc-id": e.vpc_id, "description": e.description,
            "private-ip-address": e.private_ip, "addresses.private-ip-address": e.private_ip,
            "association.public-ip": e.public_ip, "attachment.instance-id": e.instance_id,
            "group-id": e.sg_ids, "interface-type": e.kind, "requester-managed": e.requester_managed,
            "status": "in-use" if e.owner else "available", **tag_filters(e.tags)})
        return {"NetworkInterfaces": [self.eni_view(e) for e in items]}

    def op_CreateFlowLogs(self, p, req):
        dest_type = p.get("LogDestinationType", "cloud-watch-logs")
        if dest_type == "cloud-watch-logs":
            if not p.get("LogGroupName") and not p.get("LogDestination"):
                raise AwsError("InvalidParameter", "LogGroupName or LogDestination is required")
            if not p.get("DeliverLogsPermissionArn"):
                raise AwsError("InvalidParameter", "DeliverLogsPermissionArn is required for cloud-watch-logs")
        elif dest_type != "s3":
            raise AwsError("InvalidParameter", f"Unsupported LogDestinationType {dest_type}")
        ids, failed = [], []
        for rid in p.get("ResourceIds") or []:
            if rid not in self.vpcs and rid not in self.subnets and rid not in self.enis:
                failed.append({"ResourceId": rid, "Error": {"Code": "InvalidParameter",
                                                            "Message": f"Unknown resource {rid}"}})
                continue
            group = p.get("LogGroupName") or (p.get("LogDestination", "").split(":log-group:", 1)[-1].removesuffix(":*")
                                              if dest_type == "cloud-watch-logs" else None)
            fl = FlowLog(new_id("fl"), rid, p.get("TrafficType", "ALL"), dest_type, group,
                         p.get("LogDestination"), p.get("DeliverLogsPermissionArn"),
                         p.get("LogFormat") or DEFAULT_FLOW_FORMAT, int(p.get("MaxAggregationInterval") or 600),
                         self.clock.now(), tags_from_specs(p.get("TagSpecifications"), "vpc-flow-log"))
            self.flow_logs[fl.id] = fl
            ids.append(fl.id)
        for vpc in {self._owner_vpc(r) for r in p.get("ResourceIds") or [] if self._owner_vpc(r)}:
            self.sync_vpc(self.vpcs[vpc])
            self.sync_security(vpc)
        if self.flowlogs_collector:
            self.flowlogs_collector.refresh()
        return {"FlowLogIds": ids, "Unsuccessful": failed, "ClientToken": p.get("ClientToken")}

    def _owner_vpc(self, rid: str) -> str | None:
        if rid in self.vpcs:
            return rid
        if rid in self.subnets:
            return self.subnets[rid].vpc_id
        if rid in self.enis:
            return self.enis[rid].vpc_id
        return None

    def op_DescribeFlowLogs(self, p, req):
        items = list(self.flow_logs.values())
        if p.get("FlowLogIds"):
            items = [f for f in items if f.id in p["FlowLogIds"]]
        items = apply_filters(items, p.get("Filter"), lambda f: {
            "flow-log-id": f.id, "resource-id": f.resource_id, "log-group-name": f.log_group,
            "traffic-type": f.traffic_type, "log-destination-type": f.destination_type, **tag_filters(f.tags)})
        return {"FlowLogs": [{
            "FlowLogId": f.id, "ResourceId": f.resource_id, "TrafficType": f.traffic_type,
            "LogDestinationType": f.destination_type, "LogGroupName": f.log_group, "LogDestination": f.destination,
            "DeliverLogsPermissionArn": f.role_arn, "LogFormat": f.log_format, "FlowLogStatus": "ACTIVE",
            "DeliverLogsStatus": f.deliver_status, "DeliverLogsErrorMessage": f.deliver_error,
            "MaxAggregationInterval": f.max_aggregation,
            "CreationTime": f.created, "Tags": tag_list(f.tags)} for f in items]}

    def op_DeleteFlowLogs(self, p, req):
        failed = []
        for fid in p.get("FlowLogIds") or []:
            fl = self.flow_logs.pop(fid, None)
            if fl is None:
                failed.append({"ResourceId": fid, "Error": {"Code": "InvalidFlowLogId.NotFound",
                                                            "Message": f"flow log {fid} does not exist"}})
            elif self._owner_vpc(fl.resource_id):
                self.sync_security(self._owner_vpc(fl.resource_id))
                self.sync_vpc(self.vpcs[self._owner_vpc(fl.resource_id)])
        if self.flowlogs_collector:
            self.flowlogs_collector.refresh()
        return {"Unsuccessful": failed}

    # ================================================================== helpers
    @staticmethod
    def _by_ids(table: dict[str, Any], ids: list[str] | None, code: str, label: str) -> list[Any]:
        if not ids:
            return list(table.values())
        missing = [i for i in ids if i not in table]
        if missing:
            raise not_found(code, f"The {label} ID '{missing[0]}' does not exist")
        return [table[i] for i in ids]
