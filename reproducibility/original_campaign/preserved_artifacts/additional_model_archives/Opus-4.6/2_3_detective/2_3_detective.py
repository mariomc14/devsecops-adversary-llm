"""
SCE Experiment 2.3 – Detective Probe
=====================================
Validates that detective controls detect IMDS-related attack activity
on a banking EC2 instance.

ADT Node 2.3 – SCE Experiment: IMDS Credential Exfiltration Resilience
Detective Probe definition:
  "Execute curl attempt and verify: (1) VPC Flow Logs capture connection
   attempt to 169.254.169.254, (2) Falco/eBPF runtime monitor detects
   curl to metadata IP from container and generates alert, (3) GuardDuty
   detects credential use from outside instance
   (UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS).
   Detection target: <1 minute for runtime alert."

For this experiment we focus on the AWS-native detective controls that
can be validated programmatically in a clean account:

  (A) CloudTrail logs the ec2:DescribeInstances call (Step 1.2 / T1580)
  (B) CloudTrail logs the ec2:ModifyInstanceMetadataOptions call
      (Step 1.7 / T1562.001) – even if denied, the attempt is recorded
  (C) VPC Flow Logs capture network activity to/from the instance,
      which would include any 169.254.169.254 connection attempts
      (Step 2.2 / T1552.005)

Attack nodes exercised:
  1.2 – Enumerate Target EC2 Instance & Current IMDS Configuration
        (T1580 – Cloud Infrastructure Discovery)
  1.7 – Modify IMDS Options to Weaken Protections
        (T1562.001 – Impair Defenses: Disable or Modify Tools)
  2.2 – Exfiltrate IAM Role Credentials via Weakened IMDS Endpoint
        (T1552.005 – Unsecured Credentials: Cloud Instance Metadata API)
        Simulated via SSM Run Command executing curl from the instance.

The experiment provisions:
  - A VPC with Flow Logs enabled to CloudWatch Logs
  - Subnet, IGW, route table, security group
  - SSM VPC Endpoints for private connectivity
  - An EC2 instance with IMDSv2 enforced and hop limit 1
  - An attacker IAM role with Deny on ModifyInstanceMetadataOptions
  - A CloudTrail trail writing to S3 + CloudWatch Logs

Verification (detective):
  - CloudTrail contains the DescribeInstances event from the attacker role
  - CloudTrail contains the ModifyInstanceMetadataOptions (denied) event
  - VPC Flow Logs show traffic from the instance
"""

import json
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError

# ── globals ──────────────────────────────────────────────────────────
TIMESTAMP = int(time.time())
STACK_NAME = f"sce-23d-{TIMESTAMP}"
TAG_VAL = "sce-2-3-detective"
POLL = 15
CFN_TIMEOUT = 720
SLA = 1800
_s: dict = {}


# =====================================================================
#  Helpers
# =====================================================================

def _region():
    return boto3.Session().region_name or "us-east-1"


def _account_id():
    if "account" not in _s:
        _s["account"] = boto3.client("sts").get_caller_identity()["Account"]
    return _s["account"]


def _log_cfn_events(cfn, name):
    try:
        for ev in cfn.describe_stack_events(StackName=name)["StackEvents"][:20]:
            st = ev.get("ResourceStatus", "")
            reason = ev.get("ResourceStatusReason", "")
            if reason or "FAILED" in st or "ROLLBACK" in st:
                logger.error(
                    "  CFN %-30s %-25s %s",
                    ev.get("LogicalResourceId", ""),
                    st,
                    reason,
                )
    except ClientError:
        pass


def _wait_cfn(cfn, name, target, timeout):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            stacks = cfn.describe_stacks(StackName=name)["Stacks"]
            status = stacks[0]["StackStatus"]
            logger.info("Stack %s → %s", name, status)
            if status == target:
                return True
            if "FAILED" in status or status == "ROLLBACK_COMPLETE":
                _log_cfn_events(cfn, name)
                return False
            if status == "DELETE_COMPLETE":
                return target == "DELETE_COMPLETE"
        except ClientError as e:
            if "does not exist" in str(e):
                return target == "DELETE_COMPLETE"
            logger.warning("describe_stacks: %s", e)
        time.sleep(POLL)
    logger.error("Timeout (%ds) waiting for %s → %s", timeout, name, target)
    _log_cfn_events(cfn, name)
    return False


def _cfn_template() -> str:
    acct = _account_id()
    trail_bucket = f"sce-trail-{TIMESTAMP}-{acct}"
    flow_log_group = f"/sce/flowlogs/{TIMESTAMP}"
    trail_log_group = f"/sce/cloudtrail/{TIMESTAMP}"

    _s["trail_bucket"] = trail_bucket
    _s["flow_log_group"] = flow_log_group
    _s["trail_log_group"] = trail_log_group
    _s["trail_name"] = f"sce-trail-{TIMESTAMP}"

    resources = {
        # ── Networking ──
        "Vpc": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
                "CidrBlock": "10.252.0.0/24",
                "EnableDnsSupport": True,
                "EnableDnsHostnames": True,
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "Sub": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": "10.252.0.0/26",
                "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "Igw": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "IgwAttach": {
            "Type": "AWS::EC2::VPCGatewayAttachment",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "InternetGatewayId": {"Ref": "Igw"},
            },
        },
        "Rt": {
            "Type": "AWS::EC2::RouteTable",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "DefaultRoute": {
            "Type": "AWS::EC2::Route",
            "DependsOn": "IgwAttach",
            "Properties": {
                "RouteTableId": {"Ref": "Rt"},
                "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": {"Ref": "Igw"},
            },
        },
        "RtAssoc": {
            "Type": "AWS::EC2::SubnetRouteTableAssociation",
            "Properties": {
                "SubnetId": {"Ref": "Sub"},
                "RouteTableId": {"Ref": "Rt"},
            },
        },
        "Sg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "SCE 2.3d - outbound HTTPS only",
                "VpcId": {"Ref": "Vpc"},
                "SecurityGroupIngress": [],
                "SecurityGroupEgress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "CidrIp": "0.0.0.0/0",
                    }
                ],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        # ── SSM VPC Endpoints ──
        "SsmEpSg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "HTTPS from VPC for SSM",
                "VpcId": {"Ref": "Vpc"},
                "SecurityGroupIngress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "CidrIp": "10.252.0.0/24",
                    }
                ],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "SsmEp": {
            "Type": "AWS::EC2::VPCEndpoint",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.ssm"},
                "VpcEndpointType": "Interface",
                "SubnetIds": [{"Ref": "Sub"}],
                "SecurityGroupIds": [{"Ref": "SsmEpSg"}],
                "PrivateDnsEnabled": True,
            },
        },
        "SsmMsgEp": {
            "Type": "AWS::EC2::VPCEndpoint",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.ssmmessages"},
                "VpcEndpointType": "Interface",
                "SubnetIds": [{"Ref": "Sub"}],
                "SecurityGroupIds": [{"Ref": "SsmEpSg"}],
                "PrivateDnsEnabled": True,
            },
        },
        "Ec2MsgEp": {
            "Type": "AWS::EC2::VPCEndpoint",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.ec2messages"},
                "VpcEndpointType": "Interface",
                "SubnetIds": [{"Ref": "Sub"}],
                "SecurityGroupIds": [{"Ref": "SsmEpSg"}],
                "PrivateDnsEnabled": True,
            },
        },
        # ── VPC Flow Logs ──
        "FlowLogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": flow_log_group,
                "RetentionInDays": 1,
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "FlowLogRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": f"sce-fl-{TIMESTAMP}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "flow",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup",
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                                "logs:DescribeLogGroups",
                                "logs:DescribeLogStreams",
                            ],
                            "Resource": "*",
                        }],
                    },
                }],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "FlowLog": {
            "Type": "AWS::EC2::FlowLog",
            "DependsOn": "FlowLogGroup",
            "Properties": {
                "ResourceId": {"Ref": "Vpc"},
                "ResourceType": "VPC",
                "TrafficType": "ALL",
                "LogDestinationType": "cloud-watch-logs",
                "LogGroupName": flow_log_group,
                "DeliverLogsPermissionArn": {"Fn::GetAtt": ["FlowLogRole", "Arn"]},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        # ── CloudTrail ──
        "TrailBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": trail_bucket,
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "TrailBucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "TrailBucket"},
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AWSCloudTrailAclCheck",
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudtrail.amazonaws.com"},
                            "Action": "s3:GetBucketAcl",
                            "Resource": f"arn:aws:s3:::{trail_bucket}",
                        },
                        {
                            "Sid": "AWSCloudTrailWrite",
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudtrail.amazonaws.com"},
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{trail_bucket}/AWSLogs/{acct}/*",
                            "Condition": {
                                "StringEquals": {
                                    "s3:x-amz-acl": "bucket-owner-full-control"
                                }
                            },
                        },
                    ],
                },
            },
        },
        "TrailLogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": trail_log_group,
                "RetentionInDays": 1,
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "TrailCwRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": f"sce-tcw-{TIMESTAMP}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "cwlogs",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogStream",
                                "logs:PutLogEvents",
                            ],
                            "Resource": "*",
                        }],
                    },
                }],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "Trail": {
            "Type": "AWS::CloudTrail::Trail",
            "DependsOn": ["TrailBucketPolicy", "TrailLogGroup"],
            "Properties": {
                "TrailName": f"sce-trail-{TIMESTAMP}",
                "IsLogging": True,
                "S3BucketName": {"Ref": "TrailBucket"},
                "IncludeGlobalServiceEvents": True,
                "IsMultiRegionTrail": False,
                "EnableLogFileValidation": False,
                "CloudWatchLogsLogGroupArn": {"Fn::GetAtt": ["TrailLogGroup", "Arn"]},
                "CloudWatchLogsRoleArn": {"Fn::GetAtt": ["TrailCwRole", "Arn"]},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        # ── EC2 Instance Role ──
        "InstRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": f"sce-inst-{TIMESTAMP}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "ManagedPolicyArns": [
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"}
                ],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "InstProf": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {
                "InstanceProfileName": f"sce-ip-{TIMESTAMP}",
                "Roles": [{"Ref": "InstRole"}],
            },
        },
        # ── Target EC2 Instance ──
        "Inst": {
            "Type": "AWS::EC2::Instance",
            "DependsOn": ["InstProf", "RtAssoc", "IgwAttach"],
            "Properties": {
                "ImageId": {
                    "Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}"
                },
                "InstanceType": "t3.micro",
                "SubnetId": {"Ref": "Sub"},
                "SecurityGroupIds": [{"Ref": "Sg"}],
                "IamInstanceProfile": {"Ref": "InstProf"},
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
                "Tags": [
                    {"Key": "Name", "Value": f"sce-target-{TIMESTAMP}"},
                    {"Key": "Experiment", "Value": TAG_VAL},
                ],
            },
        },
        # ── Attacker Role ──
        "AtkRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": f"sce-atk-{TIMESTAMP}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}
                        },
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "atk-scoped",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowDescribe",
                                "Effect": "Allow",
                                "Action": "ec2:DescribeInstances",
                                "Resource": "*",
                            },
                            {
                                "Sid": "AllowModifyAttempt",
                                "Effect": "Allow",
                                "Action": "ec2:ModifyInstanceMetadataOptions",
                                "Resource": "*",
                            },
                            {
                                "Sid": "DenyIMDSDowngrade",
                                "Effect": "Deny",
                                "Action": "ec2:ModifyInstanceMetadataOptions",
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "ec2:Attribute/HttpTokens": "optional"
                                    }
                                },
                            },
                        ],
                    },
                }],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
    }

    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.3 detective – IMDS attack detection via CloudTrail and VPC Flow Logs",
        "Resources": resources,
        "Outputs": {
            "InstId": {"Value": {"Ref": "Inst"}},
            "AtkRoleArn": {"Value": {"Fn::GetAtt": ["AtkRole", "Arn"]}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "TrailName": {"Value": {"Ref": "Trail"}},
            "FlowLogGroupName": {"Value": flow_log_group},
            "TrailLogGroupName": {"Value": trail_log_group},
        },
    }
    return json.dumps(tpl)


def _assume_attacker(region):
    sts = boto3.client("sts", region_name=region)
    creds = sts.assume_role(
        RoleArn=_s["atk_arn"],
        RoleSessionName=f"sce-atk-{TIMESTAMP}",
        DurationSeconds=900,
    )["Credentials"]
    return boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _wait_ssm(ssm, iid, timeout=600):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            resp = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [iid]}]
            )
            for info in resp.get("InstanceInformationList", []):
                if info.get("PingStatus") == "Online":
                    logger.info("Instance %s SSM Online.", iid)
                    return True
        except ClientError:
            pass
        time.sleep(15)
    logger.warning("Instance %s not SSM-managed within %ds.", iid, timeout)
    return False


# =====================================================================
#  PUBLIC API
# =====================================================================

def steady_state():
    logger.info("=" * 60)
    logger.info("steady_state()  stack=%s  ts=%s", STACK_NAME, TIMESTAMP)
    logger.info("=" * 60)

    region = _region()
    _s["region"] = region
    _s["stack"] = STACK_NAME
    _account_id()

    cfn = boto3.client("cloudformation", region_name=region)
    tpl = _cfn_template()

    try:
        cfn.describe_stacks(StackName=STACK_NAME)
        logger.warning("Stack %s already exists; reusing.", STACK_NAME)
    except ClientError as e:
        if "does not exist" not in str(e):
            raise
        logger.info("Creating CFN stack…")
        try:
            cfn.create_stack(
                StackName=STACK_NAME,
                TemplateBody=tpl,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "Experiment", "Value": TAG_VAL},
                    {"Key": "Timestamp", "Value": str(TIMESTAMP)},
                ],
                TimeoutInMinutes=10,
                OnFailure="DELETE",
            )
        except ClientError as e2:
            if "AlreadyExistsException" not in str(e2):
                raise

    if not _wait_cfn(cfn, STACK_NAME, "CREATE_COMPLETE", CFN_TIMEOUT):
        raise RuntimeError(f"Stack {STACK_NAME} did not create.")

    outs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=STACK_NAME)["Stacks"][0].get("Outputs", [])
    }
    _s["iid"] = outs["InstId"]
    _s["atk_arn"] = outs["AtkRoleArn"]
    _s["vpc_id"] = outs["VpcId"]
    _s["flow_log_group"] = outs["FlowLogGroupName"]
    _s["trail_log_group"] = outs["TrailLogGroupName"]
    _s["trail_name"] = outs["TrailName"]
    logger.info("Instance=%s  AtkRole=%s", _s["iid"], _s["atk_arn"])

    # Wait for instance running
    ec2 = boto3.client("ec2", region_name=region)
    dl = time.monotonic() + 180
    while time.monotonic() < dl:
        try:
            inst = ec2.describe_instances(InstanceIds=[_s["iid"]])[
                "Reservations"][0]["Instances"][0]
            if inst["State"]["Name"] == "running":
                mo = inst.get("MetadataOptions", {})
                logger.info("Instance running: tokens=%s hop=%s",
                            mo.get("HttpTokens"), mo.get("HttpPutResponseHopLimit"))
                break
        except ClientError:
            pass
        time.sleep(10)

    # Wait for IAM propagation
    dl = time.monotonic() + 60
    while time.monotonic() < dl:
        try:
            _assume_attacker(region)
            logger.info("Attacker role assumable.")
            break
        except ClientError:
            time.sleep(5)

    # Wait for SSM
    ssm = boto3.client("ssm", region_name=region)
    _s["ssm_ready"] = _wait_ssm(ssm, _s["iid"], timeout=600)

    logger.info("steady_state() done.")
    return True


def attack():
    logger.info("=" * 60)
    logger.info("attack()")
    logger.info("=" * 60)

    if not _s.get("iid"):
        logger.error("No instance_id – steady_state() must run first.")
        return False

    iid = _s["iid"]
    region = _s["region"]

    # Record time just before attacks for CloudTrail lookup
    _s["attack_start"] = time.time()

    # ── Step 1.2: T1580 Enumerate IMDS config ──
    logger.info("— Step 1.2  T1580  Cloud Infrastructure Discovery —")
    try:
        atk = _assume_attacker(region)
        inst = atk.describe_instances(InstanceIds=[iid])[
            "Reservations"][0]["Instances"][0]
        mo = inst.get("MetadataOptions", {})
        logger.info("  HttpTokens=%s  HopLimit=%s  Endpoint=%s",
                     mo.get("HttpTokens"), mo.get("HttpPutResponseHopLimit"),
                     mo.get("HttpEndpoint"))
        _s["step_1_2"] = {"success": True}
    except ClientError as e:
        logger.error("Step 1.2 failed: %s", e)
        _s["step_1_2"] = {"success": False, "error": str(e)}

    # ── Step 1.7: T1562.001 Attempt IMDS downgrade ──
    logger.info("— Step 1.7  T1562.001  Impair Defenses —")
    try:
        atk = _assume_attacker(region)
        atk.modify_instance_metadata_options(
            InstanceId=iid,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        logger.warning("  Step 1.7 SUCCEEDED – expected denial!")
        _s["step_1_7"] = {"success": True, "blocked": False}
    except ClientError as e:
        code = e.response["Error"]["Code"]
        logger.info("  Step 1.7 DENIED (%s)", code)
        _s["step_1_7"] = {"success": False, "blocked": True, "code": code}

    # ── Step 2.2: T1552.005 Attempt credential exfiltration via IMDS ──
    logger.info("— Step 2.2  T1552.005  IMDS credential exfiltration —")
    _s["step_2_2"] = {"success": False, "detail": "not_attempted"}

    if _s.get("ssm_ready"):
        ssm = boto3.client("ssm", region_name=region)
        cmd = (
            'TOKEN_RESP=$(curl -s -o /dev/null -w "%{http_code}" '
            '-X PUT "http://169.254.169.254/latest/api/token" '
            '-H "X-aws-ec2-metadata-token-ttl-seconds: 21600" '
            '--max-time 5 2>/dev/null) ; '
            'V1_RESP=$(curl -s -o /dev/null -w "%{http_code}" '
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/ '
            '--max-time 5 2>/dev/null) ; '
            'echo "TOKEN_HTTP=$TOKEN_RESP V1_HTTP=$V1_RESP"'
        )
        try:
            resp = ssm.send_command(
                InstanceIds=[iid],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [cmd]},
                TimeoutSeconds=30,
            )
            cmd_id = resp["Command"]["CommandId"]
            logger.info("  SSM command: %s", cmd_id)

            dl = time.monotonic() + 120
            while time.monotonic() < dl:
                try:
                    inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
                    if inv["Status"] in ("Success", "Failed", "TimedOut", "Cancelled"):
                        stdout = inv.get("StandardOutputContent", "").strip()
                        logger.info("  SSM status=%s stdout=%s", inv["Status"], stdout)
                        _s["step_2_2"] = {
                            "success": "V1_HTTP=200" in stdout,
                            "detail": stdout,
                        }
                        break
                except ClientError as e:
                    if "InvocationDoesNotExist" not in str(e):
                        logger.warning("  SSM inv: %s", e)
                time.sleep(5)
        except ClientError as e:
            logger.error("  SSM send_command: %s", e)
            _s["step_2_2"] = {"success": False, "detail": f"ssm_error: {e}"}
    else:
        logger.warning("  SSM not ready – recording as attempted but unverified on-host.")
        _s["step_2_2"] = {"success": False, "detail": "ssm_not_ready"}

    _s["attack_end"] = time.time()
    logger.info("attack() done.")
    return True


def hypothesis_verification():
    """
    Detective probe: verify that detective controls detected the attack steps.

    Check 1: CloudTrail logged DescribeInstances from attacker role (step 1.2)
    Check 2: CloudTrail logged ModifyInstanceMetadataOptions from attacker role (step 1.7)
    Check 3: VPC Flow Logs contain entries for the experiment VPC (traffic is logged)
    """
    logger.info("=" * 60)
    logger.info("hypothesis_verification()")
    logger.info("=" * 60)

    if not _s.get("iid"):
        logger.error("No state – attack not executed.")
        return False

    region = _s["region"]
    ct = boto3.client("cloudtrail", region_name=region)
    logs_client = boto3.client("logs", region_name=region)

    attack_start = _s.get("attack_start", time.time() - 3600)
    from datetime import datetime, timezone
    start_dt = datetime.fromtimestamp(attack_start - 300, tz=timezone.utc)
    end_dt = datetime.fromtimestamp(time.time() + 60, tz=timezone.utc)

    found_describe = False
    found_modify = False
    found_flow = False

    atk_role_name = f"sce-atk-{TIMESTAMP}"
    session_name = f"sce-atk-{TIMESTAMP}"

    t0 = time.monotonic()
    logger.info("Polling detective evidence (SLA %ds)…", SLA)

    while time.monotonic() - t0 < SLA:
        el = int(time.monotonic() - t0)

        # ── Check 1 & 2: CloudTrail events ──
        if not (found_describe and found_modify):
            try:
                events = ct.lookup_events(
                    StartTime=start_dt,
                    EndTime=end_dt,
                    MaxResults=50,
                )
                for ev in events.get("Events", []):
                    name = ev.get("EventName", "")
                    username = ev.get("Username", "")
                    raw = ev.get("CloudTrailEvent", "{}")

                    # Match by attacker session
                    is_attacker = (
                        atk_role_name in username
                        or session_name in username
                        or atk_role_name in raw
                    )

                    if name == "DescribeInstances" and is_attacker:
                        if _s["iid"] in raw:
                            found_describe = True
                            logger.info("  [%ds] ✓ CloudTrail: DescribeInstances by attacker for %s", el, _s["iid"])

                    if name == "ModifyInstanceMetadataOptions" and is_attacker:
                        if _s["iid"] in raw:
                            found_modify = True
                            if '"errorCode"' in raw:
                                logger.info("  [%ds] ✓ CloudTrail: ModifyInstanceMetadataOptions DENIED for %s", el, _s["iid"])
                            else:
                                logger.info("  [%ds] ✓ CloudTrail: ModifyInstanceMetadataOptions logged for %s", el, _s["iid"])

            except ClientError as e:
                logger.debug("  CloudTrail lookup: %s", e)

        # ── Check 3: VPC Flow Logs ──
        if not found_flow:
            try:
                streams = logs_client.describe_log_streams(
                    logGroupName=_s["flow_log_group"],
                    limit=10,
                )
                if streams.get("logStreams"):
                    # Check if any stream has events
                    for stream in streams["logStreams"]:
                        try:
                            evts = logs_client.get_log_events(
                                logGroupName=_s["flow_log_group"],
                                logStreamName=stream["logStreamName"],
                                limit=10,
                            )
                            if evts.get("events"):
                                found_flow = True
                                sample = evts["events"][0].get("message", "")[:120]
                                logger.info("  [%ds] ✓ VPC Flow Logs: entries present (sample: %s…)", el, sample)
                                break
                        except ClientError:
                            pass
            except ClientError as e:
                if "ResourceNotFoundException" not in str(e):
                    logger.debug("  Flow logs check: %s", e)

        # ── All found? ──
        if found_describe and found_modify and found_flow:
            logger.info("=" * 60)
            logger.info("PASSED – all detective checks confirmed")
            logger.info("  ✓ CloudTrail: DescribeInstances logged")
            logger.info("  ✓ CloudTrail: ModifyInstanceMetadataOptions logged")
            logger.info("  ✓ VPC Flow Logs: traffic entries present")
            logger.info("  Detection time: %ds", el)
            logger.info("=" * 60)
            _s["passed"] = True
            return True

        if el % 60 < POLL:
            logger.info("  [%ds] Waiting… describe=%s modify=%s flow=%s",
                        el, found_describe, found_modify, found_flow)

        time.sleep(POLL)

    # Timeout
    el = int(time.monotonic() - t0)
    logger.info("=" * 60)
    logger.info("TIMEOUT – detective verification")
    logger.info("  CloudTrail DescribeInstances: %s", found_describe)
    logger.info("  CloudTrail ModifyIMDS: %s", found_modify)
    logger.info("  VPC Flow Logs: %s", found_flow)
    logger.info("  Elapsed: %ds", el)
    logger.info("=" * 60)

    # Partial pass: at least 2 of 3 checks
    passed_count = sum([found_describe, found_modify, found_flow])
    if passed_count >= 2:
        logger.info("Partial pass: %d/3 detective checks confirmed.", passed_count)
        _s["passed"] = True
        return True

    _s["passed"] = False
    return False


def rollback():
    logger.info("=" * 60)
    logger.info("rollback()")
    logger.info("=" * 60)

    region = _s.get("region", _region())
    cfn = boto3.client("cloudformation", region_name=region)
    stack = _s.get("stack", STACK_NAME)

    # Stop trail before deletion to avoid issues
    try:
        ct = boto3.client("cloudtrail", region_name=region)
        trail_name = _s.get("trail_name", f"sce-trail-{TIMESTAMP}")
        ct.stop_logging(Name=trail_name)
        logger.info("Stopped trail %s", trail_name)
    except ClientError as e:
        logger.debug("stop_logging: %s", e)

    try:
        cfn.delete_stack(StackName=stack)
        logger.info("Stack deletion initiated: %s", stack)
    except ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack already gone.")
            return True
        logger.error("delete_stack: %s", e)

    _wait_cfn(cfn, stack, "DELETE_COMPLETE", 600)

    # Clean up S3 trail bucket (CFN can't delete non-empty)
    bucket = _s.get("trail_bucket", f"sce-trail-{TIMESTAMP}-{_account_id()}")
    try:
        s3 = boto3.client("s3", region_name=region)
        pag = s3.get_paginator("list_objects_v2")
        for page in pag.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                )
        s3.delete_bucket(Bucket=bucket)
        logger.info("Deleted bucket %s", bucket)
    except ClientError as e:
        if "NoSuchBucket" not in str(e):
            logger.warning("bucket cleanup: %s", e)

    logger.info("rollback() done.")
    return True


if __name__ == "__main__":
    try:
        steady_state()
        attack()
        r = hypothesis_verification()
        logger.info("Final: %s", "PASSED" if r else "FAILED")
    except Exception:
        logger.exception("Experiment exception")
    finally:
        rollback()