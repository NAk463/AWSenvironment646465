"""EC2 / VPC / ELBv2 の API と状態遷移 (simulated データプレーン。root 不要)。"""
import json

import pytest
from botocore.exceptions import ClientError

AMI = "ami-0a2023a1b2c3d4e5f"
ACCOUNT = "000000000000"


def code(e):
    return e.value.response["Error"]["Code"]


@pytest.fixture
def vpc(client):
    ec2 = client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    s1 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone="ap-northeast-1a")["Subnet"]["SubnetId"]
    s2 = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.2.0/24", AvailabilityZone="ap-northeast-1c")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    return {"vpc": vpc_id, "s1": s1, "s2": s2, "igw": igw}


def test_default_vpc_and_validation(client):
    ec2 = client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    assert vpcs[0]["CidrBlock"] == "172.31.0.0/16"
    assert len(ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}])["Subnets"]) == 3
    vpc_id = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.9.1.0/24")
    with pytest.raises(ClientError) as e:
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.9.1.128/25")
    assert code(e) == "InvalidSubnet.Conflict"
    with pytest.raises(ClientError) as e:
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.8.0.0/24")
    assert code(e) == "InvalidSubnet.Range"
    with pytest.raises(ClientError) as e:
        ec2.delete_vpc(VpcId=vpc_id)
    assert code(e) == "DependencyViolation"
    with pytest.raises(ClientError) as e:
        ec2.describe_instances(InstanceIds=["i-0123456789abcdef0"])
    assert code(e) == "InvalidInstanceID.NotFound"


def test_instance_lifecycle(client, emulator):
    ec2 = client("ec2")
    ud = "#!/bin/sh\necho hi\n"
    res = ec2.run_instances(ImageId=AMI, InstanceType="t3.micro", MinCount=2, MaxCount=2, UserData=ud,
                            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web"}]}])
    ids = [i["InstanceId"] for i in res["Instances"]]
    assert {i["State"]["Name"] for i in res["Instances"]} == {"pending"}
    assert all(i.get("PublicIpAddress") for i in res["Instances"])  # デフォルトサブネットはパブリック IP を自動割り当て
    emulator.advance(5)
    found = ec2.describe_instances(Filters=[{"Name": "tag:Name", "Values": ["web"]},
                                            {"Name": "instance-state-name", "Values": ["running"]}])
    assert sorted(i["InstanceId"] for r in found["Reservations"] for i in r["Instances"]) == sorted(ids)
    first_ip = found["Reservations"][0]["Instances"][0]["PublicIpAddress"]
    ec2.stop_instances(InstanceIds=[ids[0]])
    emulator.advance(5)
    with pytest.raises(ClientError) as e:
        ec2.modify_instance_attribute(InstanceId=ids[1], InstanceType={"Value": "t3.small"})
    assert code(e) == "IncorrectInstanceState"
    ec2.modify_instance_attribute(InstanceId=ids[0], InstanceType={"Value": "t3.small"})
    ec2.start_instances(InstanceIds=[ids[0]])
    emulator.advance(5)
    inst = ec2.describe_instances(InstanceIds=[ids[0]])["Reservations"][0]["Instances"][0]
    assert inst["InstanceType"] == "t3.small" and inst["State"]["Name"] == "running"
    assert inst["PublicIpAddress"] != first_ip   # 停止/起動でパブリック IP が変わる
    ec2.modify_instance_attribute(InstanceId=ids[1], DisableApiTermination={"Value": True})
    with pytest.raises(ClientError) as e:
        ec2.terminate_instances(InstanceIds=[ids[1]])
    assert code(e) == "OperationNotPermitted"
    ec2.terminate_instances(InstanceIds=[ids[0]])
    emulator.advance(5)
    assert ec2.describe_instances(InstanceIds=[ids[0]])["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated"


def test_run_instances_errors(client):
    ec2 = client("ec2")
    with pytest.raises(ClientError) as e:
        ec2.run_instances(ImageId="ami-00000000000000000", InstanceType="t3.micro", MinCount=1, MaxCount=1)
    assert code(e) == "InvalidAMIID.NotFound"
    with pytest.raises(ClientError) as e:
        ec2.run_instances(ImageId=AMI, InstanceType="x9.huge", MinCount=1, MaxCount=1)
    assert code(e) == "InvalidParameterValue"
    with pytest.raises(ClientError) as e:
        ec2.run_instances(ImageId=AMI, InstanceType="m5.xlarge", MinCount=9, MaxCount=9)
    assert code(e) == "VcpuLimitExceeded"
    with pytest.raises(ClientError) as e:
        ec2.run_instances(ImageId=AMI, InstanceType="t3.micro", MinCount=1, MaxCount=1, KeyName="nope")
    assert code(e) == "InvalidKeyPair.NotFound"
    with pytest.raises(ClientError) as e:
        ec2.run_instances(ImageId=AMI, InstanceType="t3.micro", MinCount=1, MaxCount=1, DryRun=True)
    assert code(e) == "DryRunOperation"


def test_security_groups_and_rules(client, vpc):
    ec2 = client("ec2")
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc["vpc"])["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                                                                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    with pytest.raises(ClientError) as e:
        ec2.authorize_security_group_ingress(GroupId=sg, IpProtocol="tcp", FromPort=80, ToPort=80, CidrIp="0.0.0.0/0")
    assert code(e) == "InvalidPermission.Duplicate"
    group = ec2.describe_security_groups(GroupIds=[sg])["SecurityGroups"][0]
    assert group["IpPermissions"][0]["FromPort"] == 80
    assert group["IpPermissionsEgress"][0]["IpProtocol"] == "-1"
    rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [sg]}])["SecurityGroupRules"]
    assert {r["IsEgress"] for r in rules} == {True, False}
    res = ec2.revoke_security_group_ingress(GroupId=sg, IpProtocol="tcp", FromPort=443, ToPort=443, CidrIp="0.0.0.0/0")
    assert res["UnknownIpPermissions"]
    with pytest.raises(ClientError) as e:
        ec2.create_security_group(GroupName="web", Description="dup", VpcId=vpc["vpc"])
    assert code(e) == "InvalidGroup.Duplicate"


def test_route_tables_nat_and_blackhole(client, vpc, emulator):
    ec2 = client("ec2")
    eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat = ec2.create_nat_gateway(SubnetId=vpc["s1"], AllocationId=eip)["NatGateway"]["NatGatewayId"]
    rt = ec2.create_route_table(VpcId=vpc["vpc"])["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat)
    ec2.associate_route_table(RouteTableId=rt, SubnetId=vpc["s2"])
    with pytest.raises(ClientError) as e:
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=vpc["igw"])
    assert code(e) == "RouteAlreadyExists"
    emulator.advance(5)
    state = lambda: [r["State"] for r in ec2.describe_route_tables(RouteTableIds=[rt])["RouteTables"][0]["Routes"]  # noqa: E731
                     if r["DestinationCidrBlock"] == "0.0.0.0/0"][0]
    assert ec2.describe_nat_gateways(NatGatewayIds=[nat])["NatGateways"][0]["State"] == "available"
    assert state() == "active"
    ec2.delete_nat_gateway(NatGatewayId=nat)
    assert state() == "blackhole"
    for _ in range(5):
        if len(ec2.describe_addresses()["Addresses"]) >= 5:
            break
        ec2.allocate_address(Domain="vpc")
    with pytest.raises(ClientError) as e:
        ec2.allocate_address(Domain="vpc")
    assert code(e) == "AddressLimitExceeded"


def test_network_acls(client, vpc):
    ec2 = client("ec2")
    default = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc["vpc"]]},
                                                 {"Name": "default", "Values": ["true"]}])["NetworkAcls"][0]
    assert {a["SubnetId"] for a in default["Associations"]} == {vpc["s1"], vpc["s2"]}
    acl = ec2.create_network_acl(VpcId=vpc["vpc"])["NetworkAcl"]
    assert [e["RuleAction"] for e in acl["Entries"]] == ["deny", "deny"]  # 新規 NACL は全拒否
    ec2.create_network_acl_entry(NetworkAclId=acl["NetworkAclId"], RuleNumber=100, Protocol="6", RuleAction="allow",
                                 Egress=False, CidrBlock="0.0.0.0/0", PortRange={"From": 80, "To": 80})
    assoc = next(a["NetworkAclAssociationId"] for a in default["Associations"] if a["SubnetId"] == vpc["s1"])
    ec2.replace_network_acl_association(AssociationId=assoc, NetworkAclId=acl["NetworkAclId"])
    acls = ec2.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": [vpc["s1"]]}])["NetworkAcls"]
    assert acls[0]["NetworkAclId"] == acl["NetworkAclId"]


def test_pass_role_is_required_for_instance_profile(client):
    iam = client("iam")
    iam.create_role(RoleName="app", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}))
    iam.create_instance_profile(InstanceProfileName="app")
    iam.add_role_to_instance_profile(InstanceProfileName="app", RoleName="app")
    iam.create_user(UserName="dev")
    iam.attach_user_policy(UserName="dev", PolicyArn="arn:aws:iam::aws:policy/PowerUserAccess")
    key = iam.create_access_key(UserName="dev")["AccessKey"]
    dev = client("ec2", key["AccessKeyId"], key["SecretAccessKey"])
    dev.run_instances(ImageId=AMI, InstanceType="t3.micro", MinCount=1, MaxCount=1)
    with pytest.raises(ClientError) as e:
        dev.run_instances(ImageId=AMI, InstanceType="t3.micro", MinCount=1, MaxCount=1,
                          IamInstanceProfile={"Name": "app"})
    assert code(e) == "UnauthorizedOperation"
    encoded = e.value.response["Error"]["Message"].split("Encoded authorization failure message: ")[1]
    decoded = json.loads(client("sts").decode_authorization_message(EncodedMessage=encoded)["DecodedMessage"])
    assert decoded["context"]["action"] == "iam:PassRole"


def test_alb_api_and_target_health(client, vpc, emulator):
    ec2, elb = client("ec2"), client("elbv2")
    with pytest.raises(ClientError) as e:
        elb.create_load_balancer(Name="one-az", Subnets=[vpc["s1"]])
    assert code(e) == "ValidationError"
    lb = elb.create_load_balancer(Name="web", Subnets=[vpc["s1"], vpc["s2"]])["LoadBalancers"][0]
    assert lb["DNSName"].endswith(".elb.amazonaws.com") and lb["State"]["Code"] == "provisioning"
    tg = elb.create_target_group(Name="web", Protocol="HTTP", Port=80, VpcId=vpc["vpc"], HealthCheckIntervalSeconds=10,
                                 HealthCheckTimeoutSeconds=5, HealthyThresholdCount=2)["TargetGroups"][0]["TargetGroupArn"]
    iid = ec2.run_instances(ImageId=AMI, InstanceType="t3.micro", MinCount=1, MaxCount=1,
                            SubnetId=vpc["s1"])["Instances"][0]["InstanceId"]
    emulator.advance(5)
    elb.register_targets(TargetGroupArn=tg, Targets=[{"Id": iid}])
    health = lambda: elb.describe_target_health(TargetGroupArn=tg)["TargetHealthDescriptions"][0]["TargetHealth"]  # noqa: E731
    assert health()["State"] == "unused" and health()["Reason"] == "Target.NotInUse"
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg}])
    assert health()["State"] == "initial"
    emulator.advance(30)
    assert health()["State"] == "healthy"
    ec2.stop_instances(InstanceIds=[iid])
    assert health()["Reason"] == "Target.InvalidState"
    with pytest.raises(ClientError) as e:
        elb.delete_target_group(TargetGroupArn=tg)
    assert code(e) == "ResourceInUse"
    elb.deregister_targets(TargetGroupArn=tg, Targets=[{"Id": iid}])
    assert health()["State"] == "draining"
    client("s3").create_bucket(Bucket="alb-logs")
    with pytest.raises(ClientError) as e:
        elb.modify_load_balancer_attributes(LoadBalancerArn=lb["LoadBalancerArn"], Attributes=[
            {"Key": "access_logs.s3.enabled", "Value": "true"}, {"Key": "access_logs.s3.bucket", "Value": "alb-logs"}])
    assert code(e) == "InvalidConfigurationRequest"
