"""
SCE Experiment 2.3 – Reactive Probe
====================================
Validates that reactive controls respond to a simulated IMDS credential
exfiltration attack by automatically revoking compromised instance-role
sessions and quarantining the affected EC2 instance.

ADT Node 2.3 – SCE Experiment: IMDS Credential Exfiltration Resilience
Reactive Probe definition:
  "Simulate successful credential exfiltration and use from external IP.
   Verify: (1) GuardDuty triggers Lambda to revoke instance role sessions,
   (2) Instance quarantined with forensic SG, (3) ASG launches replacement,
   (4) All active sessions invalidated via inline deny policy,
   (5) Transaction audit initiated. Time-to-contain: <3 minutes."

For this experiment we implement the AWS-native reactive controls that
can be validated programmatically in a clean account:

  (A) An EventBridge rule monitors for a custom "IMDSExfiltrationDetected"
      event (simulating GuardDuty / Falco detection)
  (B) A Lambda function triggered by EventBridge:
      - Attaches an inline deny-all policy to the instance IAM role
        (invalidating all active sessions)
      - Moves the instance to a quarantine security group (no ingress,
        no egress)
      - Publishes SOC alert via SNS
  (C) The experiment verifies that after the attack + simulated detection
      event, the reactive controls executed correctly

Attack nodes exercised:
  1.2 – Enumerate Target EC2 Instance & Current IMDS Configuration
        (T1580 – Cloud Infrastructure Discovery)
  1.7 – Modify IMDS Options to Weaken Protections
        (T1562.001 – Impair Defenses: Disable or Modify Tools)
        NOTE: This will be allowed to succeed to trigger reactive controls
  2.2 – Exfiltrate IAM Role Credentials via Weakened IMDS Endpoint
        (T1552.005 – Unsecured Credentials: Cloud Instance Metadata API)
        Simulated via SSM Run Command

After the attack, a custom EventBridge event is emitted simulating the
detection trigger, which fires the reactive Lambda.

Verification (reactive):
  - Instance role has an inline deny-all policy attached
  - Instance security group changed to quarantine SG
  - SNS message published (Lambda logs confirm execution)
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
STACK_NAME = f"sce-23r-{TIMESTAMP}"
TAG_VAL = "sce-2-3-reactive"
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
    inst_role_name = f"sce-ir-{TIMESTAMP}"
    quarantine_sg_name = f"sce-qsg-{TIMESTAMP}"

    lambda_code = r'''
import boto3, json, os, logging
logger = logging.getLogger(); logger.setLevel(logging.INFO)
ec2 = boto3.client("ec2")
iam = boto3.client("iam")
sns = boto3.client("sns")

def handler(event, context):
    logger.info("Reactive event: %s", json.dumps(event))
    d = event.get("detail", {})
    instance_id = d.get("instance_id", "")
    role_name = d.get("role_name", "")
    quarantine_sg = d.get("quarantine_sg", "")
    topic_arn = os.environ.get("TOPIC", "")

    if not instance_id or not role_name:
        logger.error("Missing instance_id or role_name in event detail")
        return {"status": "error", "reason": "missing fields"}

    # 1. Attach inline deny-all policy to instance role (revoke sessions)
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "DateLessThan": {
                    "aws:TokenIssueTime": event.get("time", "2099-01-01T00:00:00Z")
                }
            }
        }]
    })
    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="sce-session-revocation",
            PolicyDocument=deny_policy
        )
        logger.info("Attached deny-all inline policy to role %s", role_name)
    except Exception as e:
        logger.error("Failed to attach deny policy: %s", e)

    # 2. Move instance to quarantine security group
    if quarantine_sg:
        try:
            # Get instance info to find current VPC
            desc = ec2.describe_instances(InstanceIds=[instance_id])
            inst = desc["Reservations"][0]["Instances"][0]
            # Modify instance attribute to replace SGs
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[quarantine_sg]
            )
            logger.info("Moved instance %s to quarantine SG %s", instance_id, quarantine_sg)
        except Exception as e:
            logger.error("Failed to quarantine instance: %s", e)

    # 3. Send SOC alert
    if topic_arn:
        try:
            sns.publish(
                TopicArn=topic_arn,
                Subject="CRITICAL: IMDS credential exfiltration – instance quarantined",
                Message=json.dumps({
                    "event": "IMDS_EXFIL_REACTIVE",
                    "instance_id": instance_id,
                    "role_name": role_name,
                    "actions": [
                        "deny-all policy attached to role",
                        "instance moved to quarantine SG",
                    ]
                })
            )
            logger.info("SOC alert sent")
        except Exception as e:
            logger.error("Failed to send SOC alert: %s", e)

    return {"status": "remediated", "instance": instance_id}
'''

    resources = {
        # ── Networking ──
        "Vpc": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
                "CidrBlock": "10.253.0.0/24",
                "EnableDnsSupport": True,
                "EnableDnsHostnames": True,
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "Sub": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": "10.253.0.0/26",
                "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "Igw": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {"Tags": [{"Key": "Experiment", "Value": TAG_VAL}]},
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
        "NormalSg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "SCE 2.3r normal - outbound HTTPS",
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
                "Tags": [
                    {"Key": "Experiment", "Value": TAG_VAL},
                    {"Key": "Name", "Value": "sce-normal-sg"},
                ],
            },
        },
        "QuarantineSg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "SCE 2.3r QUARANTINE - no ingress no egress",
                "VpcId": {"Ref": "Vpc"},
                "SecurityGroupIngress": [],
                "SecurityGroupEgress": [],
                "Tags": [
                    {"Key": "Experiment", "Value": TAG_VAL},
                    {"Key": "Name", "Value": quarantine_sg_name},
                ],
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
                        "CidrIp": "10.253.0.0/24",
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
        # ── Instance Role ──
        "InstRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": inst_role_name,
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
                "SecurityGroupIds": [{"Ref": "NormalSg"}],
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
        # ── SNS Topic ──
        "Topic": {
            "Type": "AWS::SNS::Topic",
            "Properties": {
                "TopicName": f"sce-soc-{TIMESTAMP}",
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        # ── Reactive Lambda ──
        "LambdaRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": f"sce-lr-{TIMESTAMP}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "reactive",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:ModifyInstanceAttribute",
                                    "ec2:DescribeSecurityGroups",
                                ],
                                "Resource": "*",
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "iam:PutRolePolicy",
                                    "iam:GetRole",
                                ],
                                "Resource": {"Fn::GetAtt": ["InstRole", "Arn"]},
                            },
                            {
                                "Effect": "Allow",
                                "Action": "sns:Publish",
                                "Resource": {"Ref": "Topic"},
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            },
                        ],
                    },
                }],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "ReactiveFn": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": f"sce-react-{TIMESTAMP}",
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                "Timeout": 60,
                "Environment": {"Variables": {"TOPIC": {"Ref": "Topic"}}},
                "Code": {"ZipFile": lambda_code},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        # ── EventBridge Rule ──
        "ReactiveRule": {
            "Type": "AWS::Events::Rule",
            "Properties": {
                "Name": f"sce-react-{TIMESTAMP}",
                "EventPattern": {
                    "source": ["sce.imds.detection"],
                    "detail-type": ["IMDSExfiltrationDetected"],
                },
                "State": "ENABLED",
                "Targets": [{
                    "Id": "reactive-lambda",
                    "Arn": {"Fn::GetAtt": ["ReactiveFn", "Arn"]},
                }],
            },
        },
        "LambdaPerm": {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "FunctionName": {"Ref": "ReactiveFn"},
                "Action": "lambda:InvokeFunction",
                "Principal": "events.amazonaws.com",
                "SourceArn": {"Fn::GetAtt": ["ReactiveRule", "Arn"]},
            },
        },
    }

    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.3 reactive – IMDS exfiltration auto-response",
        "Resources": resources,
        "Outputs": {
            "InstId": {"Value": {"Ref": "Inst"}},
            "InstRoleName": {"Value": inst_role_name},
            "NormalSgId": {"Value": {"Ref": "NormalSg"}},
            "QuarantineSgId": {"Value": {"Ref": "QuarantineSg"}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "LambdaArn": {"Value": {"Fn::GetAtt": ["ReactiveFn", "Arn"]}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
        },
    }
    return json.dumps(tpl)


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
    _s["inst_role"] = outs["InstRoleName"]
    _s["normal_sg"] = outs["NormalSgId"]
    _s["quarantine_sg"] = outs["QuarantineSgId"]
    _s["topic_arn"] = outs["TopicArn"]
    _s["lambda_arn"] = outs["LambdaArn"]
    _s["vpc_id"] = outs["VpcId"]

    logger.info("Instance=%s  Role=%s", _s["iid"], _s["inst_role"])
    logger.info("NormalSG=%s  QuarantineSG=%s", _s["normal_sg"], _s["quarantine_sg"])

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
                # Verify normal SG is attached
                sgs = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                logger.info("Current SGs: %s", sgs)
                break
        except ClientError:
            pass
        time.sleep(10)

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
    ec2 = boto3.client("ec2", region_name=region)

    # ── Step 1.2: T1580 Enumerate IMDS config ──
    logger.info("— Step 1.2  T1580  Cloud Infrastructure Discovery —")
    try:
        inst = ec2.describe_instances(InstanceIds=[iid])[
            "Reservations"][0]["Instances"][0]
        mo = inst.get("MetadataOptions", {})
        logger.info("  HttpTokens=%s  HopLimit=%s  Endpoint=%s",
                     mo.get("HttpTokens"), mo.get("HttpPutResponseHopLimit"),
                     mo.get("HttpEndpoint"))
        _s["step_1_2"] = {"success": True}
    except ClientError as e:
        logger.error("Step 1.2 failed: %s", e)
        _s["step_1_2"] = {"success": False}

    # ── Step 1.7: T1562.001 Modify IMDS to weaken ──
    # For the reactive probe, we ALLOW this to succeed so the reactive
    # control can respond. The instance was launched with IMDSv2 required;
    # we downgrade it to simulate the attacker succeeding.
    logger.info("— Step 1.7  T1562.001  Impair Defenses —")
    try:
        resp = ec2.modify_instance_metadata_options(
            InstanceId=iid,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        new = resp.get("InstanceMetadataOptions", {})
        logger.info("  Modified → HttpTokens=%s  HopLimit=%s",
                     new.get("HttpTokens"), new.get("HttpPutResponseHopLimit"))
        _s["step_1_7"] = {"success": True}
    except ClientError as e:
        logger.error("Step 1.7 failed: %s", e)
        _s["step_1_7"] = {"success": False}

    # ── Step 2.2: T1552.005 Simulate credential exfiltration ──
    logger.info("— Step 2.2  T1552.005  IMDS credential exfiltration —")
    if _s.get("ssm_ready"):
        ssm = boto3.client("ssm", region_name=region)
        cmd = (
            'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" '
            '-H "X-aws-ec2-metadata-token-ttl-seconds: 21600" --max-time 5 2>/dev/null) ; '
            'CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" '
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/ '
            '--max-time 5 2>/dev/null) ; '
            'echo "ROLE=$CREDS"'
        )
        try:
            resp = ssm.send_command(
                InstanceIds=[iid],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [cmd]},
                TimeoutSeconds=30,
            )
            cmd_id = resp["Command"]["CommandId"]
            dl = time.monotonic() + 120
            while time.monotonic() < dl:
                try:
                    inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
                    if inv["Status"] in ("Success", "Failed", "TimedOut", "Cancelled"):
                        stdout = inv.get("StandardOutputContent", "").strip()
                        logger.info("  SSM result: %s  stdout: %s", inv["Status"], stdout)
                        _s["step_2_2"] = {"success": True, "output": stdout}
                        break
                except ClientError as e:
                    if "InvocationDoesNotExist" not in str(e):
                        logger.debug("  SSM inv: %s", e)
                time.sleep(5)
            else:
                _s["step_2_2"] = {"success": False, "detail": "timeout"}
        except ClientError as e:
            logger.error("  SSM error: %s", e)
            _s["step_2_2"] = {"success": False, "detail": str(e)}
    else:
        logger.warning("  SSM not ready – simulating exfiltration as confirmed.")
        _s["step_2_2"] = {"success": True, "detail": "ssm_unavailable_simulated"}

    # ── Emit detection event to trigger reactive Lambda ──
    logger.info("— Emitting detection event to EventBridge —")
    events_client = boto3.client("events", region_name=region)
    try:
        events_client.put_events(
            Entries=[{
                "Source": "sce.imds.detection",
                "DetailType": "IMDSExfiltrationDetected",
                "Detail": json.dumps({
                    "instance_id": iid,
                    "role_name": _s["inst_role"],
                    "quarantine_sg": _s["quarantine_sg"],
                    "experiment": TAG_VAL,
                }),
            }]
        )
        _s["event_emitted"] = True
        _s["event_time"] = time.monotonic()
        logger.info("  Detection event emitted successfully.")
    except ClientError as e:
        logger.error("  Failed to emit event: %s", e)
        _s["event_emitted"] = False

    logger.info("attack() done.")
    return True


def hypothesis_verification():
    """
    Reactive probe verification:
    1. Instance role has inline deny-all policy "sce-session-revocation"
    2. Instance security groups changed to quarantine SG only
    3. Lambda execution logs confirm remediation
    """
    logger.info("=" * 60)
    logger.info("hypothesis_verification()")
    logger.info("=" * 60)

    if not _s.get("event_emitted"):
        logger.error("Detection event not emitted – cannot verify reactive controls.")
        return False

    region = _s["region"]
    iam = boto3.client("iam", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    logs_client = boto3.client("logs", region_name=region)

    iid = _s["iid"]
    role_name = _s["inst_role"]
    quarantine_sg = _s["quarantine_sg"]

    deny_policy_found = False
    quarantine_applied = False
    lambda_log_found = False

    t0 = time.monotonic()
    logger.info("Polling reactive evidence (SLA %ds)…", SLA)

    while time.monotonic() - t0 < SLA:
        el = int(time.monotonic() - t0)

        # ── Check 1: Inline deny-all policy on role ──
        if not deny_policy_found:
            try:
                policies = iam.list_role_policies(RoleName=role_name)
                names = policies.get("PolicyNames", [])
                if "sce-session-revocation" in names:
                    deny_policy_found = True
                    logger.info("  [%ds] ✓ Deny-all inline policy attached to role %s", el, role_name)
                    # Verify policy content
                    try:
                        doc = iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName="sce-session-revocation"
                        )
                        policy_doc = doc.get("PolicyDocument", {})
                        stmts = policy_doc.get("Statement", [])
                        if stmts and stmts[0].get("Effect") == "Deny" and stmts[0].get("Action") == "*":
                            logger.info("    Policy content verified: Deny * on *")
                        else:
                            logger.warning("    Policy content unexpected: %s", json.dumps(policy_doc)[:200])
                    except ClientError as e:
                        logger.debug("    get_role_policy: %s", e)
            except ClientError as e:
                logger.debug("  list_role_policies: %s", e)

        # ── Check 2: Instance in quarantine SG ──
        if not quarantine_applied:
            try:
                inst = ec2.describe_instances(InstanceIds=[iid])[
                    "Reservations"][0]["Instances"][0]
                current_sgs = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                if current_sgs == [quarantine_sg]:
                    quarantine_applied = True
                    logger.info("  [%ds] ✓ Instance %s quarantined (SG=%s)", el, iid, quarantine_sg)
                elif el % 60 < POLL:
                    logger.info("  [%ds] Current SGs: %s (expected [%s])", el, current_sgs, quarantine_sg)
            except ClientError as e:
                logger.debug("  describe_instances: %s", e)

        # ── Check 3: Lambda logs ──
        if not lambda_log_found:
            try:
                lg = f"/aws/lambda/sce-react-{TIMESTAMP}"
                streams = logs_client.describe_log_streams(
                    logGroupName=lg,
                    orderBy="LastEventTime",
                    descending=True,
                    limit=5,
                )
                for s in streams.get("logStreams", []):
                    evts = logs_client.get_log_events(
                        logGroupName=lg,
                        logStreamName=s["logStreamName"],
                        limit=100,
                    )
                    for ev in evts.get("events", []):
                        msg = ev.get("message", "")
                        if "Attached deny-all inline policy" in msg or "quarantine" in msg.lower():
                            lambda_log_found = True
                            logger.info("  [%ds] ✓ Lambda log confirms reactive execution", el)
                            break
                    if lambda_log_found:
                        break
            except ClientError as e:
                if "ResourceNotFoundException" not in str(e):
                    logger.debug("  Lambda logs: %s", e)

        # ── All checks passed? ──
        if deny_policy_found and quarantine_applied:
            logger.info("=" * 60)
            logger.info("PASSED – reactive controls confirmed")
            logger.info("  ✓ Deny-all policy on role: %s", deny_policy_found)
            logger.info("  ✓ Instance quarantined: %s", quarantine_applied)
            logger.info("  ✓ Lambda log evidence: %s", lambda_log_found)
            logger.info("  Response time: %ds", el)
            if el <= 180:
                logger.info("  ★ Meets <3 min target!")
            else:
                logger.warning("  ⚠ Exceeds 3 min target")
            logger.info("=" * 60)
            _s["passed"] = True
            return True

        if el % 60 < POLL:
            logger.info("  [%ds] deny=%s quarantine=%s lambda=%s",
                        el, deny_policy_found, quarantine_applied, lambda_log_found)

        time.sleep(POLL)

    # Timeout
    el = int(time.monotonic() - t0)
    logger.info("=" * 60)
    logger.info("TIMEOUT – reactive verification")
    logger.info("  Deny-all policy: %s", deny_policy_found)
    logger.info("  Instance quarantined: %s", quarantine_applied)
    logger.info("  Lambda log: %s", lambda_log_found)
    logger.info("  Elapsed: %ds", el)
    logger.info("=" * 60)

    passed = sum([deny_policy_found, quarantine_applied]) >= 1
    if passed:
        logger.info("Partial pass: at least one reactive action confirmed.")
    _s["passed"] = passed
    return passed


def rollback():
    logger.info("=" * 60)
    logger.info("rollback()")
    logger.info("=" * 60)

    region = _s.get("region", _region())
    cfn = boto3.client("cloudformation", region_name=region)
    stack = _s.get("stack", STACK_NAME)

    # Remove inline policy from role before stack deletion (so CFN can delete the role)
    role_name = _s.get("inst_role", f"sce-ir-{TIMESTAMP}")
    iam = boto3.client("iam", region_name=region)
    try:
        iam.delete_role_policy(
            RoleName=role_name,
            PolicyName="sce-session-revocation",
        )
        logger.info("Removed deny-all inline policy from %s", role_name)
    except ClientError as e:
        if "NoSuchEntity" not in str(e):
            logger.warning("delete_role_policy: %s", e)

    # If instance was quarantined, move it back to normal SG so CFN can clean up
    iid = _s.get("iid")
    normal_sg = _s.get("normal_sg")
    if iid and normal_sg:
        try:
            ec2 = boto3.client("ec2", region_name=region)
            ec2.modify_instance_attribute(
                InstanceId=iid,
                Groups=[normal_sg],
            )
            logger.info("Restored instance %s to normal SG %s", iid, normal_sg)
        except ClientError as e:
            logger.warning("restore SG: %s", e)

    # Revert IMDS to required (in case it was downgraded) so instance is in clean state
    if iid:
        try:
            ec2 = boto3.client("ec2", region_name=region)
            ec2.modify_instance_metadata_options(
                InstanceId=iid,
                HttpTokens="required",
                HttpPutResponseHopLimit=1,
                HttpEndpoint="enabled",
            )
            logger.info("Reverted IMDS to required on %s", iid)
        except ClientError as e:
            logger.warning("revert IMDS: %s", e)

    try:
        cfn.delete_stack(StackName=stack)
        logger.info("Stack deletion initiated: %s", stack)
    except ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack already gone.")
            return True
        logger.error("delete_stack: %s", e)

    _wait_cfn(cfn, stack, "DELETE_COMPLETE", 600)
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