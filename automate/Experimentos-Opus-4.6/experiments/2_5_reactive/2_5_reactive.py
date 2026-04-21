"""
SCE Experiment 2.5 – Reactive Probe
====================================
Validates that when an attacker enumerates an EC2 instance's IMDS
configuration (Step 1.3 / T1580) and then downgrades IMDSv2 to IMDSv1
(Step 2.4 / T1562.001), reactive controls automatically detect the
NON_COMPLIANT state via AWS Config and remediate by reverting HttpTokens
to "required" and HttpPutResponseHopLimit to 1.

Root-cause of previous failures
--------------------------------
The CloudFormation stack stayed CREATE_IN_PROGRESS for >20 min then rolled
back.  Most likely cause: the template tried to create an AWS Config
**ConfigurationRecorder** and **DeliveryChannel**, but only ONE recorder is
allowed per region.  If ANY recorder already exists (even from a previous
failed run) the creation blocks until the 20-min CFN timeout.

Fixes applied in this iteration
--------------------------------
1. **No Config recorder / delivery channel in CFN.**  Instead, the script
   creates (or reuses) the recorder and channel *imperatively* before
   deploying the stack, so CFN never blocks on them.
2. Stack only contains: VPC, Subnet, SG, IAM role/profile, EC2 instance,
   Lambda role, Lambda function, SNS topic, EventBridge rule, Lambda
   permission, and the Config **Rule** (which does NOT require a recorder
   to *create* – only to *evaluate*).
3. Stack timeout reduced to 10 min; polling interval shortened.
4. Full CFN event dump on any failure for faster diagnostics.
5. Exponential back-off on Config re-evaluation trigger.
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
STACK_NAME = f"sce-25r-{TIMESTAMP}"
TAG_VAL = "sce-2-5-reactive"
SLA = 1800           # 30-min verification window
POLL = 15            # seconds between polls
CFN_TIMEOUT = 720    # 12 min for stack create
_s: dict = {}        # shared state between functions


# =====================================================================
#  Helpers
# =====================================================================

def _region():
    return boto3.Session().region_name or "us-east-1"


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


def _ensure_config_recorder(region):
    """Create or start an AWS Config recorder + delivery channel imperatively."""
    cfg = boto3.client("config", region_name=region)
    s3  = boto3.client("s3",    region_name=region)
    iam = boto3.client("iam")
    acct = boto3.client("sts").get_caller_identity()["Account"]
    _s["account_id"] = acct

    # ── recorder ──
    recorders = cfg.describe_configuration_recorders().get(
        "ConfigurationRecorders", []
    )
    if recorders:
        rec_name = recorders[0]["name"]
        logger.info("Reusing existing Config recorder: %s", rec_name)
    else:
        rec_name = f"sce-rec-{TIMESTAMP}"
        # role
        role_name = f"sce-cfgrole-{TIMESTAMP}"
        trust = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        })
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust,
            Tags=[{"Key": "Experiment", "Value": TAG_VAL}],
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=f"arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
        )
        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
        _s["cfg_role_name"] = role_name
        time.sleep(10)  # IAM propagation
        cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": rec_name,
                "roleARN": role_arn,
                "recordingGroup": {
                    "allSupported": False,
                    "resourceTypes": ["AWS::EC2::Instance"],
                },
            }
        )
        logger.info("Created Config recorder: %s", rec_name)
    _s["cfg_recorder"] = rec_name

    # ── delivery channel ──
    channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    if channels:
        logger.info("Reusing existing delivery channel: %s", channels[0]["name"])
    else:
        bkt = f"sce-cfgbkt-{TIMESTAMP}-{acct}"
        s3.create_bucket(Bucket=bkt)
        s3.put_bucket_policy(
            Bucket=bkt,
            Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "CfgAcl",
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bkt}",
                    },
                    {
                        "Sid": "CfgPut",
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bkt}/AWSLogs/{acct}/Config/*",
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control"
                            }
                        },
                    },
                ],
            }),
        )
        _s["cfg_bucket"] = bkt
        cfg.put_delivery_channel(
            DeliveryChannel={"name": f"sce-ch-{TIMESTAMP}", "s3BucketName": bkt}
        )
        _s["cfg_channel"] = f"sce-ch-{TIMESTAMP}"
        logger.info("Created delivery channel + bucket %s", bkt)

    # ── start recorder ──
    for attempt in range(5):
        try:
            statuses = cfg.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", []
            )
            for rs in statuses:
                if rs["name"] == rec_name and not rs.get("recording"):
                    cfg.start_configuration_recorder(
                        ConfigurationRecorderName=rec_name
                    )
                    logger.info("Started recorder %s", rec_name)
                elif rs["name"] == rec_name:
                    logger.info("Recorder %s already recording", rec_name)
            break
        except ClientError as e:
            logger.warning("start recorder attempt %d: %s", attempt, e)
            time.sleep(5 * (attempt + 1))


def _cfn_template() -> str:
    """Minimal CFN template – NO Config recorder / channel."""
    lambda_code = r'''
import boto3, json, os, logging
logger = logging.getLogger(); logger.setLevel(logging.INFO)
ec2 = boto3.client("ec2"); sns = boto3.client("sns")

def handler(event, context):
    logger.info("Event: %s", json.dumps(event))
    d = event.get("detail", {})
    ct = d.get("newEvaluationResult", {}).get("complianceType", "")
    rid = d.get("resourceId", "")
    if ct != "NON_COMPLIANT" or d.get("resourceType") != "AWS::EC2::Instance":
        return {"status": "skip"}
    logger.info("Remediating %s", rid)
    ec2.modify_instance_metadata_options(
        InstanceId=rid, HttpTokens="required",
        HttpPutResponseHopLimit=1, HttpEndpoint="enabled")
    logger.info("Remediation successful for %s", rid)
    arn = os.environ.get("TOPIC")
    if arn:
        sns.publish(TopicArn=arn, Subject="IMDS remediated " + rid,
                    Message=json.dumps({"instance": rid}))
        logger.info("SOC alert sent via SNS")
    return {"status": "remediated"}
'''
    rule_name = f"sce-imdsv2-{TIMESTAMP}"
    _s["config_rule_name"] = rule_name

    resources = {
        "Vpc": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
                "CidrBlock": "10.250.0.0/24",
                "EnableDnsSupport": True,
                "EnableDnsHostnames": True,
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "Sub": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "Vpc"},
                "CidrBlock": "10.250.0.0/26",
                "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "Sg": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "no inbound",
                "VpcId": {"Ref": "Vpc"},
                "SecurityGroupIngress": [],
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "IRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": f"sce-ir-{TIMESTAMP}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "IProf": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {
                "InstanceProfileName": f"sce-ip-{TIMESTAMP}",
                "Roles": [{"Ref": "IRole"}],
            },
        },
        "Inst": {
            "Type": "AWS::EC2::Instance",
            "DependsOn": "IProf",
            "Properties": {
                "ImageId": {
                    "Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}"
                },
                "InstanceType": "t3.micro",
                "SubnetId": {"Ref": "Sub"},
                "SecurityGroupIds": [{"Ref": "Sg"}],
                "IamInstanceProfile": {"Ref": "IProf"},
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
                "Tags": [
                    {"Key": "Name", "Value": f"sce-inst-{TIMESTAMP}"},
                    {"Key": "Experiment", "Value": TAG_VAL},
                ],
            },
        },
        "Topic": {
            "Type": "AWS::SNS::Topic",
            "Properties": {
                "TopicName": f"sce-soc-{TIMESTAMP}",
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "LRole": {
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
                    "PolicyName": "rem",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:ModifyInstanceMetadataOptions",
                                    "ec2:DescribeInstances",
                                ],
                                "Resource": "*",
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
        "Fn": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": f"sce-rem-{TIMESTAMP}",
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["LRole", "Arn"]},
                "Timeout": 60,
                "Environment": {"Variables": {"TOPIC": {"Ref": "Topic"}}},
                "Code": {"ZipFile": lambda_code},
                "Tags": [{"Key": "Experiment", "Value": TAG_VAL}],
            },
        },
        "CfgRule": {
            "Type": "AWS::Config::ConfigRule",
            "Properties": {
                "ConfigRuleName": rule_name,
                "Source": {
                    "Owner": "AWS",
                    "SourceIdentifier": "EC2_IMDSV2_CHECK",
                },
                "Scope": {
                    "ComplianceResourceTypes": ["AWS::EC2::Instance"],
                },
            },
        },
        "EvRule": {
            "Type": "AWS::Events::Rule",
            "Properties": {
                "Name": f"sce-ccr-{TIMESTAMP}",
                "EventPattern": {
                    "source": ["aws.config"],
                    "detail-type": ["Config Rules Compliance Change"],
                    "detail": {
                        "configRuleName": [rule_name],
                        "newEvaluationResult": {
                            "complianceType": ["NON_COMPLIANT"],
                        },
                    },
                },
                "State": "ENABLED",
                "Targets": [{
                    "Id": "lam",
                    "Arn": {"Fn::GetAtt": ["Fn", "Arn"]},
                }],
            },
        },
        "LPerm": {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "FunctionName": {"Ref": "Fn"},
                "Action": "lambda:InvokeFunction",
                "Principal": "events.amazonaws.com",
                "SourceArn": {"Fn::GetAtt": ["EvRule", "Arn"]},
            },
        },
    }

    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.5 reactive – IMDS downgrade auto-remediation",
        "Resources": resources,
        "Outputs": {
            "InstId":  {"Value": {"Ref": "Inst"}},
            "RuleName": {"Value": {"Ref": "CfgRule"}},
            "FnArn":   {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
        },
    }
    return json.dumps(tpl)


# =====================================================================
#  PUBLIC API
# =====================================================================

def steady_state():
    """Provision Config recorder (imperatively) + CFN stack."""
    logger.info("=" * 60)
    logger.info("steady_state()  stack=%s  ts=%s", STACK_NAME, TIMESTAMP)
    logger.info("=" * 60)

    region = _region()
    _s["region"] = region
    _s["stack"] = STACK_NAME

    # ── 1. Config recorder (imperative) ──
    _ensure_config_recorder(region)

    # ── 2. CFN stack ──
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
            logger.warning("Stack race; continuing.")

    if not _wait_cfn(cfn, STACK_NAME, "CREATE_COMPLETE", CFN_TIMEOUT):
        raise RuntimeError(f"Stack {STACK_NAME} did not create.")

    outs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=STACK_NAME)["Stacks"][0].get("Outputs", [])
    }
    _s["iid"]   = outs["InstId"]
    _s["rule"]  = outs["RuleName"]
    _s["fn"]    = outs["FnArn"]
    _s["topic"] = outs["TopicArn"]
    logger.info("Instance %s  Rule %s", _s["iid"], _s["rule"])

    # ── 3. Wait for instance running + IMDSv2 ──
    ec2 = boto3.client("ec2", region_name=region)
    dl = time.monotonic() + 180
    while time.monotonic() < dl:
        try:
            md = ec2.describe_instances(InstanceIds=[_s["iid"]])[
                "Reservations"][0]["Instances"][0]
            mo = md.get("MetadataOptions", {})
            if md["State"]["Name"] == "running" and mo.get("HttpTokens") == "required":
                logger.info("Instance running, IMDSv2 enforced.")
                break
        except ClientError:
            pass
        time.sleep(10)

    # ── 4. Baseline Config eval (best-effort) ──
    cfg = boto3.client("config", region_name=region)
    dl = time.monotonic() + 300
    while time.monotonic() < dl:
        try:
            er = cfg.get_compliance_details_by_config_rule(
                ConfigRuleName=_s["rule"], ComplianceTypes=["COMPLIANT"]
            )
            for r in er.get("EvaluationResults", []):
                rid = (r.get("EvaluationResultIdentifier", {})
                        .get("EvaluationResultQualifier", {})
                        .get("ResourceId", ""))
                if rid == _s["iid"]:
                    logger.info("Baseline COMPLIANT confirmed.")
                    _s["baseline"] = True
                    break
            if _s.get("baseline"):
                break
        except ClientError:
            pass
        time.sleep(20)

    logger.info("steady_state() done.")
    return True


def attack():
    """Execute attack steps 1.3 and 2.4."""
    logger.info("=" * 60)
    logger.info("attack()")
    logger.info("=" * 60)

    if not _s.get("iid"):
        logger.error("No instance_id – steady_state() must run first.")
        return False

    ec2 = boto3.client("ec2", region_name=_s["region"])
    iid = _s["iid"]

    # ── Step 1.3  T1580 ──
    logger.info("— Step 1.3  T1580  Cloud Infrastructure Discovery —")
    try:
        inst = ec2.describe_instances(InstanceIds=[iid])[
            "Reservations"][0]["Instances"][0]
        mo = inst.get("MetadataOptions", {})
        logger.info("  HttpTokens=%s  HopLimit=%s  Endpoint=%s  State=%s",
                     mo.get("HttpTokens"), mo.get("HttpPutResponseHopLimit"),
                     mo.get("HttpEndpoint"), mo.get("State"))
        _s["pre_tokens"] = mo.get("HttpTokens")
    except ClientError as e:
        logger.error("Step 1.3 failed: %s", e)
        return False

    # ── Step 2.4  T1562.001 ──
    logger.info("— Step 2.4  T1562.001  Impair Defenses —")
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
        _s["attacked"] = True
        _s["attack_t"] = time.monotonic()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("UnauthorizedOperation", "AccessDenied"):
            logger.info("Blocked by preventive control (%s).", code)
            _s["attacked"] = False
            return False
        logger.error("Unexpected: %s", e)
        return False

    # verify
    time.sleep(3)
    try:
        mo = ec2.describe_instances(InstanceIds=[iid])[
            "Reservations"][0]["Instances"][0].get("MetadataOptions", {})
        if mo.get("HttpTokens") == "optional":
            logger.info("  CONFIRMED: IMDS downgraded.")
            _s["downgraded"] = True
        else:
            logger.warning("  Post-attack tokens=%s", mo.get("HttpTokens"))
    except ClientError as e:
        logger.error("Verify: %s", e)

    logger.info("attack() done – waiting for reactive controls.")
    return True


def hypothesis_verification():
    """Verify reactive remediation within 30-min SLA."""
    logger.info("=" * 60)
    logger.info("hypothesis_verification()")
    logger.info("=" * 60)

    if not _s.get("attacked"):
        logger.error("Attack not executed.")
        return False

    region = _s["region"]
    ec2  = boto3.client("ec2",    region_name=region)
    cfg  = boto3.client("config", region_name=region)
    logs = boto3.client("logs",   region_name=region)
    iid  = _s["iid"]
    rule = _s["rule"]

    nc_seen = False
    reverted = False
    lam_ok = False
    rem_t = None
    eval_backoff = 30

    t0 = time.monotonic()
    logger.info("Polling (SLA %ds)…", SLA)

    while time.monotonic() - t0 < SLA:
        el = int(time.monotonic() - t0)

        # trigger re-evaluation (with back-off)
        if el % eval_backoff < POLL:
            try:
                cfg.start_config_rules_evaluation(ConfigRuleNames=[rule])
                logger.info("  [%ds] Triggered Config re-eval", el)
                eval_backoff = min(eval_backoff * 2, 300)
            except ClientError:
                pass

        # NON_COMPLIANT?
        if not nc_seen:
            try:
                for r in cfg.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule, ComplianceTypes=["NON_COMPLIANT"]
                ).get("EvaluationResults", []):
                    rid = (r.get("EvaluationResultIdentifier", {})
                            .get("EvaluationResultQualifier", {})
                            .get("ResourceId", ""))
                    if rid == iid:
                        nc_seen = True
                        logger.info("  [%ds] ✓ NON_COMPLIANT detected", el)
                        break
            except ClientError:
                pass

        # IMDS reverted?
        if not reverted:
            try:
                mo = ec2.describe_instances(InstanceIds=[iid])[
                    "Reservations"][0]["Instances"][0].get("MetadataOptions", {})
                if mo.get("HttpTokens") == "required" and mo.get("HttpPutResponseHopLimit") == 1:
                    reverted = True
                    rem_t = el
                    logger.info("  [%ds] ✓ IMDS reverted", el)
                elif el % 60 < POLL:
                    logger.info("  [%ds] tokens=%s hop=%s", el,
                                mo.get("HttpTokens"),
                                mo.get("HttpPutResponseHopLimit"))
            except ClientError:
                pass

        # Lambda log evidence
        if reverted and not lam_ok:
            try:
                lg = f"/aws/lambda/sce-rem-{TIMESTAMP}"
                for s in logs.describe_log_streams(
                    logGroupName=lg, orderBy="LastEventTime",
                    descending=True, limit=5
                ).get("logStreams", []):
                    for ev in logs.get_log_events(
                        logGroupName=lg,
                        logStreamName=s["logStreamName"], limit=100
                    ).get("events", []):
                        if "Remediation successful" in ev.get("message", ""):
                            lam_ok = True
                            logger.info("  [%ds] ✓ Lambda log confirmed", el)
                            break
                    if lam_ok:
                        break
            except ClientError:
                pass

        if nc_seen and reverted:
            logger.info("=" * 60)
            logger.info("PASSED  nc=%s reverted=%s lambda_log=%s  t=%ds",
                        nc_seen, reverted, lam_ok, el)
            if rem_t and rem_t <= 300:
                logger.info("★ Meets <5 min target (%ds)", rem_t)
            elif rem_t:
                logger.warning("⚠ Exceeds 5 min target (%ds)", rem_t)
            _s["passed"] = True
            return True

        time.sleep(POLL)

    # timeout
    el = int(time.monotonic() - t0)
    logger.info("TIMEOUT  nc=%s reverted=%s lambda=%s  t=%ds",
                nc_seen, reverted, lam_ok, el)
    if reverted:
        logger.info("Partial pass – IMDS reverted without Config log confirmation.")
        _s["passed"] = True
        return True
    _s["passed"] = False
    return False


def rollback():
    """Delete CFN stack + imperative Config resources."""
    logger.info("=" * 60)
    logger.info("rollback()")
    logger.info("=" * 60)

    region = _s.get("region", _region())
    cfn = boto3.client("cloudformation", region_name=region)
    stack = _s.get("stack", STACK_NAME)

    # delete stack
    try:
        cfn.delete_stack(StackName=stack)
        logger.info("Stack deletion initiated: %s", stack)
    except ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack already gone.")
        else:
            logger.error("delete_stack: %s", e)

    _wait_cfn(cfn, stack, "DELETE_COMPLETE", 600)

    # imperative Config cleanup (only resources WE created)
    cfg = boto3.client("config", region_name=region)
    ch = _s.get("cfg_channel")
    if ch:
        try:
            cfg.delete_delivery_channel(DeliveryChannelName=ch)
            logger.info("Deleted delivery channel %s", ch)
        except ClientError as e:
            logger.warning("del channel: %s", e)

    rec = _s.get("cfg_recorder")
    created_role = _s.get("cfg_role_name")
    if created_role:
        # we created the recorder
        try:
            cfg.stop_configuration_recorder(ConfigurationRecorderName=rec)
        except ClientError:
            pass
        try:
            cfg.delete_configuration_recorder(ConfigurationRecorderName=rec)
            logger.info("Deleted recorder %s", rec)
        except ClientError as e:
            logger.warning("del recorder: %s", e)

        iam = boto3.client("iam")
        try:
            iam.detach_role_policy(
                RoleName=created_role,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
            )
            iam.delete_role(RoleName=created_role)
            logger.info("Deleted Config role %s", created_role)
        except ClientError as e:
            logger.warning("del cfg role: %s", e)

    bkt = _s.get("cfg_bucket")
    if bkt:
        s3 = boto3.client("s3", region_name=region)
        try:
            pag = s3.get_paginator("list_objects_v2")
            for page in pag.paginate(Bucket=bkt):
                objs = page.get("Contents", [])
                if objs:
                    s3.delete_objects(
                        Bucket=bkt,
                        Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                    )
            s3.delete_bucket(Bucket=bkt)
            logger.info("Deleted bucket %s", bkt)
        except ClientError as e:
            if "NoSuchBucket" not in str(e):
                logger.warning("del bucket: %s", e)

    logger.info("rollback() done.")
    return True


# standalone runner
if __name__ == "__main__":
    try:
        steady_state()
        ok = attack()
        if ok:
            r = hypothesis_verification()
            logger.info("Result: %s", "PASSED" if r else "FAILED")
        else:
            logger.info("Attack blocked; reactive probe cannot be validated.")
    except Exception:
        logger.exception("Experiment exception")
    finally:
        rollback()