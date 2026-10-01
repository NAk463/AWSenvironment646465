"""linux データプレーンの統合テスト (root が必要。他の awsemu serve が動いていないこと)。

    sudo python -m pytest tests/test_netplane.py
"""
import os
import shutil
import subprocess
import threading
import time
import urllib.request

import boto3
import pytest
from botocore.config import Config

from awsemu.server import make_server

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or shutil.which("ip") is None or os.path.exists("/run/netns/awsemu-core")
    or os.environ.get("AWSEMU_TEST_NETNS") == "0",
    reason="root 権限と iproute2 が必要 (かつ他の awsemu が動いていないこと)")

AMI = "ami-0a2023a1b2c3d4e5f"
# boto3 は UserData を自動で base64 エンコードするので生のスクリプトを渡す (二重エンコードは本物でも起動失敗になる)
WEB = "#!/bin/sh\nmkdir -p w && cd w && hostname > index.html\nexec python3 -m http.server 8080\n"


@pytest.fixture(scope="module")
def env():
    srv = make_server("127.0.0.1", 0, verbose=False, background=False, network="linux")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    emu = srv.emulator
    endpoint = f"http://127.0.0.1:{srv.server_address[1]}"

    def client(service):
        return boto3.client(service, endpoint_url=endpoint, region_name="ap-northeast-1", aws_access_key_id="test",
                            aws_secret_access_key="test", config=Config(retries={"total_max_attempts": 1}))
    yield emu, client
    srv.shutdown()
    emu.shutdown()


def http_get(url, timeout=3.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ""
    except OSError:
        return None, ""


def wait_for(fn, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.5)
    return fn()


def in_netns(ns, *cmd):
    return subprocess.run(["ip", "netns", "exec", ns, *cmd], capture_output=True, text=True, timeout=20)


def test_vpc_dataplane_end_to_end(env):
    emu, client = env
    ec2, elb = client("ec2"), client("elbv2")
    vpc = ec2.create_vpc(CidrBlock="10.50.0.0/16")["Vpc"]["VpcId"]
    s1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.50.1.0/24", AvailabilityZone="ap-northeast-1a")["Subnet"]["SubnetId"]
    s2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.50.2.0/24", AvailabilityZone="ap-northeast-1c")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    main_rt = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=main_rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    alb_sg = ec2.create_security_group(GroupName="alb", Description="alb", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=alb_sg, IpProtocol="tcp", FromPort=80, ToPort=80, CidrIp="0.0.0.0/0")
    web_sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=web_sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "UserIdGroupPairs": [{"GroupId": alb_sg}]}])
    inst = ec2.run_instances(
        ImageId=AMI, InstanceType="t3.micro", MinCount=1, MaxCount=1, UserData=WEB,
        NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": s1, "Groups": [web_sg], "AssociatePublicIpAddress": True}])
    iid = inst["Instances"][0]["InstanceId"]
    public_ip = inst["Instances"][0]["PublicIpAddress"]
    ns = f"awsemu-{iid}"

    # SG はインターネットからの 8080 を許可していないので、パブリック IP 直接では届かない
    time.sleep(1)
    assert http_get(f"http://{public_ip}:8080/", timeout=2)[0] is None

    # IMDSv2 (トークン必須) がインスタンスの中から使える
    token = in_netns(ns, "curl", "-s", "-m", "3", "-X", "PUT", "-H", "X-aws-ec2-metadata-token-ttl-seconds: 60",
                     "http://169.254.169.254/latest/api/token").stdout
    got = in_netns(ns, "curl", "-s", "-m", "3", "-H", f"X-aws-ec2-metadata-token: {token}",
                   "http://169.254.169.254/latest/meta-data/instance-id").stdout
    assert got == iid
    v1 = in_netns(ns, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "3",
                  "http://169.254.169.254/latest/meta-data/instance-id").stdout
    assert v1 == "401"

    # ALB 経由でターゲットに届き、ヘルスチェックが healthy になる
    lb = elb.create_load_balancer(Name="t-alb", Subnets=[s1, s2], SecurityGroups=[alb_sg])["LoadBalancers"][0]
    lb_ip = lb["AvailabilityZones"][0]["LoadBalancerAddresses"][0]["IpAddress"]
    tg = elb.create_target_group(Name="t-tg", Protocol="HTTP", Port=8080, VpcId=vpc, HealthCheckIntervalSeconds=5,
                                 HealthCheckTimeoutSeconds=2, HealthyThresholdCount=2,
                                 UnhealthyThresholdCount=2)["TargetGroups"][0]["TargetGroupArn"]
    elb.register_targets(TargetGroupArn=tg, Targets=[{"Id": iid}])
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])

    def state():
        emu.services["elbv2"].run_health_checks()
        return elb.describe_target_health(TargetGroupArn=tg)["TargetHealthDescriptions"][0]["TargetHealth"]

    emu.advance(30)
    assert wait_for(lambda: state()["State"] == "healthy"), state()
    status, body = http_get(f"http://{lb_ip}/")
    assert status == 200 and body.strip().startswith("ip-10-50-1-")

    # ターゲットのプロセスを止めると 502 (接続拒否) になり、ヘルスチェックも失敗する
    pid = emu.ec2.netplane.instance_pid(iid)
    subprocess.run(["nsenter", "-t", str(pid), "--pid", "--mount", "--", "pkill", "-f", "http.server"], check=False)
    time.sleep(0.5)
    assert http_get(f"http://{lb_ip}/")[0] == 502
    emu.advance(30)
    final = wait_for(lambda: state().get("Reason") == "Target.FailedHealthChecks")
    assert final, state()
