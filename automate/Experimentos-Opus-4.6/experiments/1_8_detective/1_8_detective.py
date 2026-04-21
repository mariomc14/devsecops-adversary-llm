"""
SCE Experiment 1.8 – Detective Probe
Attack Steps 1.2 & 1.7: EC2 IMDS Protection Weakening via ModifyInstanceMetadataOptions

Detective Probe Validation:
  This experiment verifies that AWS detective controls DETECT the following
  attack steps after they are executed:
    1.2 – ec2:DescribeInstances call to enumerate IMDS configuration (T1580)
    1.7 – ec2:ModifyInstanceMetadataOptions to downgrade IMDSv2→IMDSv1 and
          increase hop-limit (T1562.001)

  Detective controls under test:
    • CloudTrail records both API events with full context
    • An EventBridge rule matched on "ModifyInstanceMetadataOptions" fires and
      delivers a message to an SNS topic → SQS queue (observable proof of detection)
    • AWS Config rule "ec2-imdsv2-check" evaluates the modified instance as
      NON_COMPLIANT (configuration drift detection)

  The experiment provisions its own CloudTrail trail (logging to a dedicated S3
  bucket), an EventBridge rule → SNS → SQS pipeline, and enables AWS Config
  with a managed rule.  After running the attacks it polls with a 30-minute SLA
  to confirm all three detective signals fired.
"""

import json
import logging
import os
import sys
import time
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ensure boto3
# ---------------------------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# ---------------------------------------------------------------------------
# Global constants & mutable state
# ---------------------------------------------------------------------------
_TIMESTAMP = str(int(time.time()))
_STACK_NAME = f"sce-det-1-8-{_TIMESTAMP}"
_EXPERIMENT_TAG = "sce-experiment-1-8-detective"
_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
_SLA_TIMEOUT = 1800  # 30 minutes
_POLL_INTERVAL = 20
_STACK_OUTPUTS: dict = {}
_ATTACK_RESULTS: dict = {}
_ATTACK_TIMESTAMPS: dict = {}  # ISO-8601 times around the attack calls


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ts():
    return time.monotonic()


def _cfn():
    return boto3.client("cloudformation", region_name=_REGION)


def _sts():
    return boto3.client("sts", region_name=_REGION)


def _ec2():
    return boto3.client("ec2", region_name=_REGION)


def _sqs():
    return boto3.client("sqs", region_name=_REGION)


def _ct():
    return boto3.client("cloudtrail", region_name=_REGION)


def _config():
    return boto3.client("config", region_name=_REGION)


def _account_id():
    return _sts().get_caller_identity()["Account"]


def _get_subnet():
    ec2 = _ec2()
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        if vpcs["Vpcs"]:
            subs = ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpcs["Vpcs"][0]["VpcId"]]}]
            )
            if subs["Subnets"]:
                return subs["Subnets"][0]["SubnetId"], vpcs["Vpcs"][0]["VpcId"]
    except ClientError as exc:
        logger.error("Subnet lookup error: %s", exc)
    try:
        subs = ec2.describe_subnets(MaxResults=5)
        if subs["Subnets"]:
            s = subs["Subnets"][0]
            return s["SubnetId"], s["VpcId"]
    except ClientError as exc:
        logger.error("Fallback subnet lookup error: %s", exc)
    return None, None


def _get_ami():
    ec2 = _ec2()
    try:
        imgs = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
        )
        images = sorted(imgs["Images"], key=lambda x: x["CreationDate"], reverse=True)
        if images:
            return images[0]["ImageId"]
    except ClientError as exc:
        logger.error("AMI lookup: %s", exc)
    return None


def _wait_stack(name, target, timeout=900):
    cfn = _cfn()
    start = _ts()
    while (_ts() - start) < timeout:
        try:
            resp = cfn.describe_stacks(StackName=name)
            st = resp["Stacks"][0]["StackStatus"]
            logger.info("Stack %s → %s", name, st)
            if st == target:
                return True
            if "FAILED" in st or st == "ROLLBACK_COMPLETE":
                logger.error("Stack %s failed: %s", name, st)
                try:
                    evts = cfn.describe_stack_events(StackName=name)["StackEvents"]
                    for e in evts[:10]:
                        if "FAILED" in e.get("ResourceStatus", ""):
                            logger.error("  %s: %s", e["LogicalResourceId"],
                                         e.get("ResourceStatusReason", ""))
                except Exception:
                    pass
                return False
            if st == "DELETE_COMPLETE" and target != "DELETE_COMPLETE":
                return False
        except ClientError as exc:
            if "does not exist" in str(exc):
                return target == "DELETE_COMPLETE"
            logger.warning("describe_stacks: %s", exc)
        time.sleep(15)
    logger.error("Timeout waiting for stack %s → %s", name, target)
    return False


def _stack_outputs(name):
    try:
        resp = _cfn().describe_stacks(StackName=name)
        return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    except (ClientError, IndexError, KeyError) as exc:
        logger.error("Stack outputs error: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# CloudFormation template builder
# ---------------------------------------------------------------------------
def _build_template(account_id, subnet_id, vpc_id, ami_id):
    """
    Resources created:
    1. EC2 instance with IMDSv2 enforced (target of both attack steps)
    2. Security group (no ingress)
    3. S3 bucket for CloudTrail logs
    4. CloudTrail trail (management events, single-region)
    5. SNS topic for EventBridge detection notifications
    6. SQS queue subscribed to the SNS topic (poll-able proof of detection)
    7. EventBridge rule matching ModifyInstanceMetadataOptions → SNS
    8. IAM role for the attacker (has Allow on the two EC2 actions so the
       attacks SUCCEED – we need them to succeed so the detective controls
       can observe them)
    9. AWS Config configuration recorder + delivery channel + managed rule
       ec2-imdsv2-check  (detects the IMDS downgrade as NON_COMPLIANT)
    """
    bucket_name = f"sce-det-trail-{_TIMESTAMP}-{account_id[-6:]}"
    short_hash = hashlib.md5(f"{_TIMESTAMP}{account_id}".encode()).hexdigest()[:8]
    bucket_name = f"sce-det-trail-{short_hash}"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Detective Probe – IMDS downgrade detection",
        "Resources": {
            # ---------- networking ----------
            "SG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 1.8 det - no ingress",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [],
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            # ---------- EC2 ----------
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": ami_id,
                    "SubnetId": subnet_id,
                    "SecurityGroupIds": [{"Fn::GetAtt": ["SG", "GroupId"]}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [{"Key": "Name", "Value": f"sce-1-8-det-{_TIMESTAMP}"},
                             {"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            # ---------- S3 for CloudTrail ----------
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": bucket_name,
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
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
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${TrailBucket}"},
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${TrailBucket}/AWSLogs/${AWS::AccountId}/*"},
                                "Condition": {
                                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                                },
                            },
                        ],
                    },
                },
            },
            # ---------- CloudTrail ----------
            "Trail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": "TrailBucketPolicy",
                "Properties": {
                    "TrailName": f"sce-det-1-8-{_TIMESTAMP}",
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": False,
                    "EnableLogFileValidation": True,
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            # ---------- SNS topic (EventBridge target) ----------
            "DetectionTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": f"sce-det-1-8-{_TIMESTAMP}",
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "DetectionTopicPolicy": {
                "Type": "AWS::SNS::TopicPolicy",
                "Properties": {
                    "Topics": [{"Ref": "DetectionTopic"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridgePublish",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sns:Publish",
                                "Resource": {"Ref": "DetectionTopic"},
                            }
                        ],
                    },
                },
            },
            # ---------- SQS queue (observable from test) ----------
            "DetectionQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": f"sce-det-1-8-{_TIMESTAMP}",
                    "MessageRetentionPeriod": 3600,
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "DetectionQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowSNS",
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["DetectionQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {"aws:SourceArn": {"Ref": "DetectionTopic"}}
                                },
                            }
                        ],
                    },
                },
            },
            "SNSSub": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "Protocol": "sqs",
                    "TopicArn": {"Ref": "DetectionTopic"},
                    "Endpoint": {"Fn::GetAtt": ["DetectionQueue", "Arn"]},
                },
            },
            # ---------- EventBridge rule ----------
            "DetectionRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": f"sce-det-1-8-{_TIMESTAMP}",
                    "Description": "Detect ModifyInstanceMetadataOptions API calls",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.ec2"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventName": ["ModifyInstanceMetadataOptions"]
                        },
                    },
                    "Targets": [
                        {
                            "Id": "sns-target",
                            "Arn": {"Ref": "DetectionTopic"},
                        }
                    ],
                },
            },
            # ---------- Attacker IAM role (ALLOW so attacks succeed) ----------
            "AttackerAllowPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": f"sce-det-1-8-allow-{_TIMESTAMP}",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:ModifyInstanceMetadataOptions",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                },
            },
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-det-1-8-attacker-{_TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [{"Ref": "AttackerAllowPolicy"}],
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            # ---------- AWS Config ----------
            "ConfigRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-det-1-8-config-{_TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
                    ],
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "ConfigBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"sce-det-config-{short_hash}",
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "ConfigBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "ConfigBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSConfigBucketPermissionsCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}"},
                            },
                            {
                                "Sid": "AWSConfigBucketDelivery",
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${ConfigBucket}/AWSLogs/${AWS::AccountId}/Config/*"},
                                "Condition": {
                                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                                },
                            },
                        ],
                    },
                },
            },
            "ConfigRecorder": {
                "Type": "AWS::Config::ConfigurationRecorder",
                "Properties": {
                    "Name": f"sce-det-1-8-{_TIMESTAMP}",
                    "RoleARN": {"Fn::GetAtt": ["ConfigRole", "Arn"]},
                    "RecordingGroup": {
                        "AllSupported": False,
                        "ResourceTypes": ["AWS::EC2::Instance"],
                    },
                },
            },
            "ConfigDeliveryChannel": {
                "Type": "AWS::Config::DeliveryChannel",
                "DependsOn": "ConfigBucketPolicy",
                "Properties": {
                    "Name": f"sce-det-1-8-{_TIMESTAMP}",
                    "S3BucketName": {"Ref": "ConfigBucket"},
                },
            },
            "IMDSv2ConfigRule": {
                "Type": "AWS::Config::ConfigRule",
                "DependsOn": "ConfigRecorder",
                "Properties": {
                    "ConfigRuleName": f"sce-det-imdsv2-{_TIMESTAMP}",
                    "Description": "Checks whether EC2 instances require IMDSv2",
                    "Source": {
                        "Owner": "AWS",
                        "SourceIdentifier": "EC2_IMDSV2_CHECK",
                    },
                    "Scope": {
                        "ComplianceResourceTypes": ["AWS::EC2::Instance"],
                    },
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "AttackerRoleArn": {"Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}},
            "QueueUrl": {"Value": {"Ref": "DetectionQueue"}},
            "TrailName": {"Value": {"Ref": "Trail"}},
            "ConfigRuleName": {"Value": {"Ref": "IMDSv2ConfigRule"}},
            "TrailBucket": {"Value": {"Ref": "TrailBucket"}},
            "ConfigBucket": {"Value": {"Ref": "ConfigBucket"}},
        },
    }
    return json.dumps(template)


# ---------------------------------------------------------------------------
# 1. steady_state
# ---------------------------------------------------------------------------
def steady_state():
    global _STACK_OUTPUTS
    logger.info("=" * 70)
    logger.info("STEADY STATE: Provisioning resources for SCE 1.8 Detective Probe")
    logger.info("Stack: %s", _STACK_NAME)
    logger.info("=" * 70)

    cfn = _cfn()
    acct = _account_id()
    subnet_id, vpc_id = _get_subnet()
    if not subnet_id:
        raise RuntimeError("No subnet found.")
    ami_id = _get_ami()
    if not ami_id:
        raise RuntimeError("No AMI found.")
    logger.info("Account=%s  Subnet=%s  VPC=%s  AMI=%s", acct, subnet_id, vpc_id, ami_id)

    # Handle pre-existing Config recorders – only one allowed per region
    try:
        existing_recorders = _config().describe_configuration_recorders()
        if existing_recorders.get("ConfigurationRecorders"):
            logger.warning("Existing Config recorder found. Will attempt stack creation; "
                           "if it fails due to recorder conflict, the Config rule check "
                           "will be skipped gracefully.")
    except ClientError:
        pass

    tpl = _build_template(acct, subnet_id, vpc_id, ami_id)

    # Check existing stack
    try:
        resp = cfn.describe_stacks(StackName=_STACK_NAME)
        st = resp["Stacks"][0]["StackStatus"]
        if st in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            logger.warning("Stack already exists (%s). Reusing.", st)
            _STACK_OUTPUTS = _stack_outputs(_STACK_NAME)
            return True
        if "IN_PROGRESS" in st:
            _wait_stack(_STACK_NAME, "CREATE_COMPLETE")
            _STACK_OUTPUTS = _stack_outputs(_STACK_NAME)
            return True
        logger.warning("Stack in %s. Deleting first.", st)
        cfn.delete_stack(StackName=_STACK_NAME)
        _wait_stack(_STACK_NAME, "DELETE_COMPLETE", timeout=600)
    except ClientError as exc:
        if "does not exist" not in str(exc):
            logger.error("Stack check error: %s", exc)

    logger.info("Creating stack...")
    try:
        cfn.create_stack(
            StackName=_STACK_NAME,
            TemplateBody=tpl,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                  {"Key": "timestamp", "Value": _TIMESTAMP}],
            TimeoutInMinutes=15,
        )
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            logger.warning("Stack creation race. Continuing.")
        else:
            raise

    if not _wait_stack(_STACK_NAME, "CREATE_COMPLETE", timeout=900):
        raise RuntimeError("Stack creation failed.")

    _STACK_OUTPUTS = _stack_outputs(_STACK_NAME)
    logger.info("Outputs: %s", _STACK_OUTPUTS)

    # Wait IAM propagation
    role_arn = _STACK_OUTPUTS.get("AttackerRoleArn")
    if role_arn:
        start = _ts()
        while (_ts() - start) < 120:
            try:
                _sts().assume_role(RoleArn=role_arn, RoleSessionName="prop", DurationSeconds=900)
                logger.info("Attacker role assumable.")
                break
            except ClientError:
                time.sleep(10)

    # Wait instance running
    iid = _STACK_OUTPUTS.get("InstanceId")
    if iid:
        logger.info("Waiting for instance %s to run...", iid)
        try:
            _ec2().get_waiter("instance_running").wait(
                InstanceIds=[iid], WaiterConfig={"Delay": 15, "MaxAttempts": 40}
            )
        except WaiterError as exc:
            logger.error("Instance wait failed: %s", exc)
            raise

    # Give CloudTrail and EventBridge rule a moment to settle
    logger.info("Allowing 30s for CloudTrail/EventBridge stabilisation...")
    time.sleep(30)

    logger.info("STEADY STATE complete.")
    return True


# ---------------------------------------------------------------------------
# 2. attack
# ---------------------------------------------------------------------------
def attack() -> bool:
    global _ATTACK_RESULTS, _ATTACK_TIMESTAMPS
    logger.info("=" * 70)
    logger.info("ATTACK: Steps 1.2 and 1.7 via attacker role")
    logger.info("=" * 70)

    role_arn = _STACK_OUTPUTS.get("AttackerRoleArn")
    iid = _STACK_OUTPUTS.get("InstanceId")
    if not role_arn or not iid:
        logger.error("Missing outputs.")
        return True

    creds = _sts().assume_role(
        RoleArn=role_arn, RoleSessionName=f"sce-atk-{_TIMESTAMP}", DurationSeconds=900
    )["Credentials"]

    ec2a = boto3.client(
        "ec2", region_name=_REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    # Record wall-clock before attacks (for CloudTrail lookup window)
    import datetime
    _ATTACK_TIMESTAMPS["before"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # --- Step 1.2: DescribeInstances ---
    logger.info("STEP 1.2: ec2:DescribeInstances (T1580)")
    s12 = {"executed": True, "success": False, "error": None}
    try:
        resp = ec2a.describe_instances(InstanceIds=[iid])
        md = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
        s12["success"] = True
        s12["data"] = {
            "HttpTokens": md.get("HttpTokens"),
            "HopLimit": md.get("HttpPutResponseHopLimit"),
        }
        logger.info("  SUCCEEDED – IMDS config: %s", s12["data"])
    except ClientError as exc:
        s12["error"] = str(exc)
        logger.error("  FAILED: %s", exc)
    _ATTACK_RESULTS["step_1_2"] = s12

    time.sleep(2)  # small gap for distinct CloudTrail events

    # --- Step 1.7: ModifyInstanceMetadataOptions ---
    logger.info("STEP 1.7: ec2:ModifyInstanceMetadataOptions (T1562.001)")
    s17 = {"executed": True, "success": False, "error": None}
    try:
        resp = ec2a.modify_instance_metadata_options(
            InstanceId=iid,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        s17["success"] = True
        md = resp.get("InstanceMetadataOptions", {})
        s17["data"] = {
            "HttpTokens": md.get("HttpTokens"),
            "HopLimit": md.get("HttpPutResponseHopLimit"),
        }
        logger.info("  SUCCEEDED – new IMDS config: %s", s17["data"])
    except ClientError as exc:
        s17["error"] = str(exc)
        logger.error("  FAILED: %s", exc)
    _ATTACK_RESULTS["step_1_7"] = s17

    _ATTACK_TIMESTAMPS["after"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    logger.info("ATTACK complete. Results: %s", json.dumps(_ATTACK_RESULTS, indent=2))
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification
# ---------------------------------------------------------------------------
def hypothesis_verification() -> bool:
    """
    Verify three detective signals within the 30-minute SLA:
      CHECK 1 – CloudTrail contains DescribeInstances event for our instance
      CHECK 2 – CloudTrail contains ModifyInstanceMetadataOptions event
              AND EventBridge delivered a notification to SQS
      CHECK 3 – AWS Config rule evaluates the instance as NON_COMPLIANT
    """
    import datetime

    logger.info("=" * 70)
    logger.info("HYPOTHESIS VERIFICATION: Detective Probe SCE 1.8")
    logger.info("=" * 70)

    iid = _STACK_OUTPUTS.get("InstanceId", "")
    queue_url = _STACK_OUTPUTS.get("QueueUrl", "")
    trail_name = _STACK_OUTPUTS.get("TrailName", "")
    config_rule = _STACK_OUTPUTS.get("ConfigRuleName", "")

    checks = {
        "cloudtrail_describe": False,
        "cloudtrail_modify": False,
        "eventbridge_sqs": False,
        "config_noncompliant": False,
    }

    # Parse attack window
    before_str = _ATTACK_TIMESTAMPS.get("before")
    after_str = _ATTACK_TIMESTAMPS.get("after")
    if before_str:
        start_time = datetime.datetime.fromisoformat(before_str) - datetime.timedelta(minutes=5)
    else:
        start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30)
    if after_str:
        end_time = datetime.datetime.fromisoformat(after_str) + datetime.timedelta(minutes=30)
    else:
        end_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)

    sla_start = _ts()

    while (_ts() - sla_start) < _SLA_TIMEOUT:
        remaining = _SLA_TIMEOUT - (_ts() - sla_start)
        all_done = all(checks.values())
        if all_done:
            break

        logger.info("--- Poll iteration (%.0fs remaining) ---", remaining)
        logger.info("  Current: %s", checks)

        # ------ CHECK 1 & 2: CloudTrail ------
        if not checks["cloudtrail_describe"] or not checks["cloudtrail_modify"]:
            ct = _ct()
            try:
                # Lookup DescribeInstances
                if not checks["cloudtrail_describe"]:
                    resp = ct.lookup_events(
                        LookupAttributes=[
                            {"AttributeKey": "EventName", "AttributeValue": "DescribeInstances"}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50,
                    )
                    for evt in resp.get("Events", []):
                        cloud_evt = json.loads(evt.get("CloudTrailEvent", "{}"))
                        req_params = cloud_evt.get("requestParameters", {})
                        instances_set = req_params.get("instancesSet", {}).get("items", [])
                        for item in instances_set:
                            if item.get("instanceId") == iid:
                                checks["cloudtrail_describe"] = True
                                logger.info("  CHECK 1 PASS: CloudTrail DescribeInstances for %s found.", iid)
                                break
                        if checks["cloudtrail_describe"]:
                            break
            except ClientError as exc:
                logger.warning("  CloudTrail lookup (Describe): %s", exc)

            try:
                if not checks["cloudtrail_modify"]:
                    resp = ct.lookup_events(
                        LookupAttributes=[
                            {"AttributeKey": "EventName", "AttributeValue": "ModifyInstanceMetadataOptions"}
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=50,
                    )
                    for evt in resp.get("Events", []):
                        cloud_evt = json.loads(evt.get("CloudTrailEvent", "{}"))
                        req_params = cloud_evt.get("requestParameters", {})
                        if req_params.get("instanceId") == iid:
                            checks["cloudtrail_modify"] = True
                            logger.info("  CHECK 2a PASS: CloudTrail ModifyInstanceMetadataOptions for %s found.", iid)
                            break
            except ClientError as exc:
                logger.warning("  CloudTrail lookup (Modify): %s", exc)

        # ------ CHECK 2b: EventBridge → SQS ------
        if not checks["eventbridge_sqs"] and queue_url:
            sqs = _sqs()
            try:
                resp = sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=5,
                    VisibilityTimeout=10,
                )
                for msg in resp.get("Messages", []):
                    body = json.loads(msg.get("Body", "{}"))
                    # SNS wraps the EventBridge event in "Message"
                    inner = body.get("Message", "{}")
                    if isinstance(inner, str):
                        try:
                            inner = json.loads(inner)
                        except (json.JSONDecodeError, TypeError):
                            pass
                    # Check for our instance and event
                    inner_str = json.dumps(inner) if isinstance(inner, dict) else str(inner)
                    if "ModifyInstanceMetadataOptions" in inner_str and iid in inner_str:
                        checks["eventbridge_sqs"] = True
                        logger.info("  CHECK 2b PASS: EventBridge notification for ModifyInstanceMetadataOptions "
                                    "received on SQS.")
                        # Delete processed messages
                        sqs.delete_message(QueueUrl=queue_url,
                                           ReceiptHandle=msg["ReceiptHandle"])
                        break
                    # Also check if the event name is embedded at top level
                    if "ModifyInstanceMetadataOptions" in msg.get("Body", ""):
                        checks["eventbridge_sqs"] = True
                        logger.info("  CHECK 2b PASS: EventBridge notification detected in SQS body.")
                        sqs.delete_message(QueueUrl=queue_url,
                                           ReceiptHandle=msg["ReceiptHandle"])
                        break
            except ClientError as exc:
                logger.warning("  SQS receive: %s", exc)

        # ------ CHECK 3: AWS Config NON_COMPLIANT ------
        if not checks["config_noncompliant"] and config_rule:
            cfg = _config()
            try:
                resp = cfg.get_compliance_details_by_config_rule(
                    ConfigRuleName=config_rule,
                    ComplianceTypes=["NON_COMPLIANT"],
                    Limit=50,
                )
                for result in resp.get("EvaluationResults", []):
                    rid = result.get("EvaluationResultIdentifier", {}).get(
                        "EvaluationResultQualifier", {}
                    ).get("ResourceId", "")
                    if rid == iid:
                        checks["config_noncompliant"] = True
                        logger.info("  CHECK 3 PASS: AWS Config rule %s evaluates %s as NON_COMPLIANT.",
                                    config_rule, iid)
                        break
            except ClientError as exc:
                logger.warning("  Config check: %s", exc)

        if all(checks.values()):
            break

        time.sleep(_POLL_INTERVAL)

    # Final evaluation
    logger.info("=" * 70)
    logger.info("VERIFICATION RESULTS:")
    all_passed = True
    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        logger.info("  %s: %s", name, status)
        if not passed:
            all_passed = False

    if not checks["cloudtrail_describe"]:
        logger.error("CloudTrail did NOT record DescribeInstances for %s within SLA.", iid)
    if not checks["cloudtrail_modify"]:
        logger.error("CloudTrail did NOT record ModifyInstanceMetadataOptions for %s within SLA.", iid)
    if not checks["eventbridge_sqs"]:
        logger.error("EventBridge rule did NOT deliver ModifyInstanceMetadataOptions notification "
                      "to SQS within SLA.")
    if not checks["config_noncompliant"]:
        logger.error("AWS Config rule did NOT evaluate %s as NON_COMPLIANT within SLA.", iid)

    logger.info("OVERALL: %s", "PASS" if all_passed else "FAIL")
    logger.info("=" * 70)
    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback
# ---------------------------------------------------------------------------
def rollback():
    logger.info("=" * 70)
    logger.info("ROLLBACK: Tearing down %s", _STACK_NAME)
    logger.info("=" * 70)

    cfn = _cfn()

    # Revert IMDS on instance before deletion (best-effort)
    iid = _STACK_OUTPUTS.get("InstanceId")
    if iid:
        try:
            _ec2().modify_instance_metadata_options(
                InstanceId=iid,
                HttpTokens="required",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=1,
            )
            logger.info("Reverted IMDS on %s.", iid)
        except ClientError as exc:
            logger.warning("IMDS revert on %s: %s", iid, exc)

    # Terminate instance to accelerate deletion
    if iid:
        try:
            _ec2().terminate_instances(InstanceIds=[iid])
            logger.info("Terminated %s.", iid)
        except ClientError as exc:
            logger.warning("Terminate %s: %s", iid, exc)

    # Empty S3 buckets (CloudFormation can't delete non-empty buckets)
    for bkt_key in ("TrailBucket", "ConfigBucket"):
        bname = _STACK_OUTPUTS.get(bkt_key)
        if bname:
            s3 = boto3.resource("s3", region_name=_REGION)
            try:
                bucket = s3.Bucket(bname)
                bucket.objects.all().delete()
                bucket.object_versions.all().delete()
                logger.info("Emptied bucket %s.", bname)
            except ClientError as exc:
                logger.warning("Empty bucket %s: %s", bname, exc)

    # Stop Config recorder before stack deletion to avoid dependency issues
    try:
        recorder_name = f"sce-det-1-8-{_TIMESTAMP}"
        _config().stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
        logger.info("Stopped Config recorder %s.", recorder_name)
    except ClientError as exc:
        logger.warning("Stop Config recorder: %s", exc)

    # Delete stack
    try:
        cfn.delete_stack(StackName=_STACK_NAME)
        logger.info("Stack deletion initiated.")
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack already gone.")
            return True
        logger.error("delete_stack: %s", exc)
        return False

    ok = _wait_stack(_STACK_NAME, "DELETE_COMPLETE", timeout=900)
    if ok:
        logger.info("ROLLBACK complete.")
    else:
        logger.error("ROLLBACK: stack deletion may have failed. Manual cleanup needed.")
    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("SCE 1.8 Detective Probe – IMDS Downgrade Detection")
    try:
        steady_state()
        attack()
        result = hypothesis_verification()
        sys.exit(0 if result else 1)
    except Exception as exc:
        logger.exception("Unhandled: %s", exc)
        sys.exit(2)
    finally:
        try:
            rollback()
        except Exception as exc:
            logger.exception("Rollback error: %s", exc)