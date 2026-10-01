"""botocore の API 定義から、awsemu が実装するオペレーションの入出力シェイプだけを抜き出す (開発時のみ使用)。

    pip install botocore && python tools/gen_models.py

生成物 awsemu/models/<service>.json は botocore (Apache License 2.0) のデータから派生したもの。
"""
from __future__ import annotations

import json
import pathlib

import botocore.session

OPS = {
    "ec2": """
        CreateVpc DescribeVpcs DeleteVpc ModifyVpcAttribute DescribeVpcAttribute
        CreateSubnet DescribeSubnets DeleteSubnet ModifySubnetAttribute
        CreateInternetGateway AttachInternetGateway DetachInternetGateway DeleteInternetGateway DescribeInternetGateways
        CreateNatGateway DescribeNatGateways DeleteNatGateway
        AllocateAddress ReleaseAddress DescribeAddresses AssociateAddress DisassociateAddress
        CreateRouteTable DescribeRouteTables DeleteRouteTable AssociateRouteTable DisassociateRouteTable
        ReplaceRouteTableAssociation CreateRoute ReplaceRoute DeleteRoute
        CreateSecurityGroup DescribeSecurityGroups DeleteSecurityGroup DescribeSecurityGroupRules
        AuthorizeSecurityGroupIngress AuthorizeSecurityGroupEgress RevokeSecurityGroupIngress RevokeSecurityGroupEgress
        CreateNetworkAcl DescribeNetworkAcls DeleteNetworkAcl CreateNetworkAclEntry ReplaceNetworkAclEntry
        DeleteNetworkAclEntry ReplaceNetworkAclAssociation
        DescribeNetworkInterfaces CreateFlowLogs DescribeFlowLogs DeleteFlowLogs
        DescribeAvailabilityZones DescribeRegions DescribeAccountAttributes CreateTags DeleteTags DescribeTags
        RunInstances DescribeInstances DescribeInstanceStatus StartInstances StopInstances RebootInstances
        TerminateInstances GetConsoleOutput ModifyInstanceAttribute DescribeInstanceAttribute
        ModifyInstanceMetadataOptions AssociateIamInstanceProfile DescribeIamInstanceProfileAssociations
        CreateKeyPair ImportKeyPair DescribeKeyPairs DeleteKeyPair DescribeImages DescribeInstanceTypes
    """,
}


def build(service: str, ops: list[str]) -> dict:
    model = botocore.session.get_session().get_service_model(service)
    shapes: dict[str, dict] = {}

    def visit(shape) -> str:
        name = shape.name
        if name in shapes:
            return name
        if shape.type_name == "structure":
            entry = {"t": "s", "m": {}}
            shapes[name] = entry
            for member, sub in shape.members.items():
                ser = sub.serialization
                query = ser.get("queryName") or (ser["name"][:1].upper() + ser["name"][1:] if "name" in ser else member)
                entry["m"][member] = [visit(sub), query, ser.get("name", member)]
        elif shape.type_name == "list":
            entry = {"t": "l"}
            shapes[name] = entry
            entry["m"] = visit(shape.member)
            entry["n"] = shape.member.serialization.get("name", "member")
        elif shape.type_name == "map":
            entry = {"t": "m"}
            shapes[name] = entry
            entry["k"] = visit(shape.key)
            entry["v"] = visit(shape.value)
        else:
            shapes[name] = {"t": shape.type_name}
        return name

    out_ops = {}
    for op in ops:
        om = model.operation_model(op)
        out_ops[op] = {"i": visit(om.input_shape) if om.input_shape else None,
                       "o": visit(om.output_shape) if om.output_shape else None}
    return {"metadata": {"apiVersion": model.metadata["apiVersion"],
                         "xmlNamespace": f"http://ec2.amazonaws.com/doc/{model.metadata['apiVersion']}/"},
            "operations": out_ops, "shapes": shapes}


if __name__ == "__main__":
    root = pathlib.Path(__file__).resolve().parent.parent / "awsemu" / "models"
    root.mkdir(exist_ok=True)
    for service, ops in OPS.items():
        data = build(service, ops.split())
        path = root / f"{service}.json"
        path.write_text(json.dumps(data, separators=(",", ":"), sort_keys=True))
        print(f"{path}: {len(data['operations'])} operations, {len(data['shapes'])} shapes, {path.stat().st_size} bytes")
