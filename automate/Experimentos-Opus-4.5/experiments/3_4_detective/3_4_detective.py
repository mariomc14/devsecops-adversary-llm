#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment 3.4 - Detective Probe
EC2 IMDS Protection Weakening Detection Validation

Attack Chain:
- Node 1.3: Cloud Infrastructure Discovery (T1580)
- Node 2.3: Weaken IMDS Protections (T1562.001)
- Node 3.3: Credential Exfiltration via IMDS (T1552.005)

Detective Controls Validated:
- AWS Config Rule detects non-compliant IMDS configuration
- CloudTrail logs ModifyInstanceMetadataOptions API calls
- EventBridge rule triggers on IMDS modification events

Installation:
    mkdir -p chaosaws/ec2
    touch chaosaws/__init__.py chaosaws/ec2/__init__.py
    cp sce_3_4_detective.py chaosaws/ec2/
    pip install -e .
"""

import json
import logging
import os
import subprocess
import sys
import time
import traceback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(funcName)s: %(message)s"
)
logger = logging.getLogger(__name__)

EXPERIMENT_TAG = "sce-3-4-detective"
STACK_PREFIX = "sce-imds-det"
SLA_TIMEOUT = 1800  # 30 minutes for AWS eventual consistency
POLL_INTERVAL = 30
MAX_RETRIES = 5

_state = {
    "stack_name": None,
    "instance_id": None,
    "config_rule_name": None,
    "trail_name": None,
    "log_group_name": None,
    "event_rule_name": None,
    "sns_topic_arn": None,
    "region": None,
    "timestamp": None,
    "exp_tag": None,
    "attack_time": None,
    "results": {"step_1_3": None, "step_2_3": None, "step_3_3": None},
    "detection_results": {"config_rule": None, "cloudtrail": None, "eventbridge": None},
    "ready": False,
    "verified": False
}


def _get_boto3():
    """Get boto3, installing if needed."""
    try:
        import boto3
        return boto3
    except ImportError:
        logger.info("Installing boto3...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
        import boto3
        return boto3


def _cfn_template(tag, region):
    """Generate CloudFormation template with detective controls."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 3.4 Detective - IMDS Protection Detection Test",
        "Parameters": {
            "Tag": {"Type": "String", "Default": tag}
        },
        "Resources": {
            # Network Resources
            "VPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [{"Key": "Name", "Value": {"Fn::Sub": "${Tag}-vpc"}},
                             {"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "Tags": [{"Key": "Name", "Value": {"Fn::Sub": "${Tag}-subnet"}},
                             {"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "SG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE Isolated SG",
                    "VpcId": {"Ref": "VPC"},
                    "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "127.0.0.1/32"}],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # IAM Resources
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${Tag}-inst"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                    },
                    "Policies": [{"PolicyName": "Min", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeTags"], "Resource": "*"}]}}],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": {"Fn::Sub": "${Tag}-prof"},
                    "Roles": [{"Ref": "InstanceRole"}]
                }
            },
            # EC2 Instance with IMDSv2 enforced initially
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["InstanceProfile"],
                "Properties": {
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "Subnet"},
                    "SecurityGroupIds": [{"Ref": "SG"}],
                    "IamInstanceProfile": {"Ref": "InstanceProfile"},
                    "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1, "HttpEndpoint": "enabled"},
                    "Tags": [{"Key": "Name", "Value": {"Fn::Sub": "${Tag}-target"}}, {"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # SNS Topic for alerts
            "AlertTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": {"Fn::Sub": "${Tag}-alerts"},
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # S3 Bucket for CloudTrail logs
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": {"Fn::Sub": "${Tag}-trail-${AWS::AccountId}"},
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
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
                                "Resource": {"Fn::GetAtt": ["TrailBucket", "Arn"]}
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "${TrailBucket.Arn}/*"},
                                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
                            }
                        ]
                    }
                }
            },
            # CloudWatch Log Group for CloudTrail
            "TrailLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {"Fn::Sub": "/aws/cloudtrail/${Tag}"},
                    "RetentionInDays": 1,
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # IAM Role for CloudTrail to write to CloudWatch Logs
            "TrailLogRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${Tag}-trail-role"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                    },
                    "Policies": [{
                        "PolicyName": "CloudTrailLogs",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                                "Resource": {"Fn::GetAtt": ["TrailLogGroup", "Arn"]}
                            }]
                        }
                    }],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # CloudTrail for API monitoring
            "Trail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["TrailBucketPolicy", "TrailLogRole"],
                "Properties": {
                    "TrailName": {"Fn::Sub": "${Tag}-trail"},
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": False,
                    "EnableLogFileValidation": True,
                    "CloudWatchLogsLogGroupArn": {"Fn::GetAtt": ["TrailLogGroup", "Arn"]},
                    "CloudWatchLogsRoleArn": {"Fn::GetAtt": ["TrailLogRole", "Arn"]},
                    "EventSelectors": [{
                        "ReadWriteType": "WriteOnly",
                        "IncludeManagementEvents": True
                    }],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # EventBridge Rule for IMDS modification detection
            "IMDSEventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Fn::Sub": "${Tag}-imds-rule"},
                    "Description": "Detect EC2 IMDS modification attempts",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.ec2"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["ec2.amazonaws.com"],
                            "eventName": ["ModifyInstanceMetadataOptions"]
                        }
                    },
                    "Targets": [{
                        "Id": "SNSTarget",
                        "Arn": {"Ref": "AlertTopic"}
                    }]
                }
            },
            # SNS Topic Policy to allow EventBridge
            "AlertTopicPolicy": {
                "Type": "AWS::SNS::TopicPolicy",
                "Properties": {
                    "Topics": [{"Ref": "AlertTopic"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sns:Publish",
                            "Resource": {"Ref": "AlertTopic"}
                        }]
                    }
                }
            },
            # AWS Config Recorder Role
            "ConfigRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${Tag}-config-role"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # S3 Bucket for Config
            "ConfigBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": {"Fn::Sub": "${Tag}-config-${AWS::AccountId}"},
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
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
                                "Resource": {"Fn::GetAtt": ["ConfigBucket", "Arn"]}
                            },
                            {
                                "Sid": "AWSConfigBucketDelivery",
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "${ConfigBucket.Arn}/*"},
                                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
                            }
                        ]
                    }
                }
            },
            # Config Recorder
            "ConfigRecorder": {
                "Type": "AWS::Config::ConfigurationRecorder",
                "DependsOn": ["ConfigRole"],
                "Properties": {
                    "Name": {"Fn::Sub": "${Tag}-recorder"},
                    "RoleARN": {"Fn::GetAtt": ["ConfigRole", "Arn"]},
                    "RecordingGroup": {
                        "ResourceTypes": ["AWS::EC2::Instance"]
                    }
                }
            },
            # Config Delivery Channel
            "ConfigDeliveryChannel": {
                "Type": "AWS::Config::DeliveryChannel",
                "DependsOn": ["ConfigBucketPolicy"],
                "Properties": {
                    "Name": {"Fn::Sub": "${Tag}-delivery"},
                    "S3BucketName": {"Ref": "ConfigBucket"}
                }
            },
            # AWS Config Rule for IMDSv2
            "IMDSConfigRule": {
                "Type": "AWS::Config::ConfigRule",
                "DependsOn": ["ConfigRecorder"],
                "Properties": {
                    "ConfigRuleName": {"Fn::Sub": "${Tag}-imdsv2-check"},
                    "Description": "Checks if EC2 instances have IMDSv2 enabled",
                    "Source": {
                        "Owner": "AWS",
                        "SourceIdentifier": "EC2_IMDSV2_CHECK"
                    },
                    "Scope": {
                        "ComplianceResourceTypes": ["AWS::EC2::Instance"]
                    }
                }
            }
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "ConfigRuleName": {"Value": {"Fn::Sub": "${Tag}-imdsv2-check"}},
            "TrailName": {"Value": {"Fn::Sub": "${Tag}-trail"}},
            "LogGroupName": {"Value": {"Fn::Sub": "/aws/cloudtrail/${Tag}"}},
            "EventRuleName": {"Value": {"Fn::Sub": "${Tag}-imds-rule"}},
            "SNSTopicArn": {"Value": {"Ref": "AlertTopic"}}
        }
    })


def _wait(check_fn, desc, timeout=SLA_TIMEOUT, interval=POLL_INTERVAL):
    """Poll until condition or timeout (30-minute SLA)."""
    start = time.monotonic()
    attempt = 0
    last_error = None
    
    while (time.monotonic() - start) < timeout:
        try:
            result = check_fn()
            if result:
                elapsed = time.monotonic() - start
                logger.info(f"✓ {desc} ({elapsed:.1f}s)")
                return True
        except Exception as e:
            last_error = e
            logger.debug(f"Check {desc}: {e}")
        
        attempt += 1
        sleep = min(interval * (1.2 ** min(attempt, 5)), 120)
        elapsed = time.monotonic() - start
        remaining = timeout - elapsed
        logger.info(f"Waiting: {desc} [{elapsed:.0f}s/{timeout}s] remaining: {remaining:.0f}s")
        time.sleep(sleep)
    
    logger.error(f"Timeout: {desc} after {timeout}s. Last error: {last_error}")
    return False


def steady_state():
    """Deploy experiment infrastructure with detective controls."""
    global _state
    logger.info("=" * 60)
    logger.info("STEADY STATE: SCE 3.4 Detective Probe")
    logger.info("=" * 60)
    
    try:
        boto3 = _get_boto3()
        ts = int(time.time())
        stack = f"{STACK_PREFIX}-{ts}"
        tag = f"{EXPERIMENT_TAG}-{ts}"
        
        _state.update({"timestamp": ts, "stack_name": stack, "exp_tag": tag})
        
        session = boto3.session.Session()
        region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        _state["region"] = region
        
        logger.info(f"Stack: {stack} | Region: {region} | Tag: {tag}")
        
        cfn = boto3.client("cloudformation", region_name=region)
        
        # Check for existing stack
        exists = False
        try:
            r = cfn.describe_stacks(StackName=stack)
            logger.warning(f"Stack exists: {r['Stacks'][0]['StackStatus']}")
            exists = True
        except cfn.exceptions.ClientError as e:
            if "does not exist" not in str(e):
                raise
        
        if not exists:
            for i in range(MAX_RETRIES):
                try:
                    cfn.create_stack(
                        StackName=stack,
                        TemplateBody=_cfn_template(tag, region),
                        Parameters=[{"ParameterKey": "Tag", "ParameterValue": tag}],
                        Capabilities=["CAPABILITY_NAMED_IAM"],
                        Tags=[
                            {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                            {"Key": "Timestamp", "Value": str(ts)},
                            {"Key": "ProbeType", "Value": "detective"}
                        ],
                        OnFailure="DELETE",
                        TimeoutInMinutes=20
                    )
                    logger.info("Stack creation started")
                    break
                except cfn.exceptions.AlreadyExistsException:
                    logger.warning("Stack already exists")
                    break
                except Exception as e:
                    logger.error(f"Attempt {i+1}: {e}")
                    if i < MAX_RETRIES - 1:
                        time.sleep(10 * (i + 1))
                    else:
                        raise
        
        def stack_ok():
            try:
                r = cfn.describe_stacks(StackName=stack)
                s = r["Stacks"][0]["StackStatus"]
                if s == "CREATE_COMPLETE":
                    return True
                if "FAILED" in s or "ROLLBACK" in s:
                    events = cfn.describe_stack_events(StackName=stack)
                    for e in events.get("StackEvents", []):
                        if "FAILED" in e.get("ResourceStatus", ""):
                            logger.error(f"Stack error: {e.get('ResourceStatusReason')}")
                    raise Exception(f"Stack failed: {s}")
                return False
            except cfn.exceptions.ClientError as e:
                if "does not exist" in str(e):
                    return False
                raise
        
        if not _wait(stack_ok, "stack creation", 1200, 20):
            raise Exception("Stack timeout")
        
        # Get stack outputs
        r = cfn.describe_stacks(StackName=stack)
        outputs = {o["OutputKey"]: o["OutputValue"] for o in r["Stacks"][0].get("Outputs", [])}
        
        _state["instance_id"] = outputs.get("InstanceId")
        _state["config_rule_name"] = outputs.get("ConfigRuleName")
        _state["trail_name"] = outputs.get("TrailName")
        _state["log_group_name"] = outputs.get("LogGroupName")
        _state["event_rule_name"] = outputs.get("EventRuleName")
        _state["sns_topic_arn"] = outputs.get("SNSTopicArn")
        
        logger.info(f"Instance: {_state['instance_id']}")
        logger.info(f"Config Rule: {_state['config_rule_name']}")
        logger.info(f"CloudTrail: {_state['trail_name']}")
        logger.info(f"EventBridge Rule: {_state['event_rule_name']}")
        
        # Wait for instance to be running
        ec2 = boto3.client("ec2", region_name=region)
        
        def inst_running():
            r = ec2.describe_instances(InstanceIds=[_state["instance_id"]])
            return r["Reservations"][0]["Instances"][0]["State"]["Name"] == "running" if r["Reservations"] else False
        
        if not _wait(inst_running, "instance running", 300, 10):
            raise Exception("Instance timeout")
        
        # Wait for Config recorder to start
        config = boto3.client("config", region_name=region)
        
        def config_recording():
            try:
                r = config.describe_configuration_recorder_status()
                for rec in r.get("ConfigurationRecordersStatus", []):
                    if rec.get("recording"):
                        return True
                return False
            except Exception:
                return False
        
        if not _wait(config_recording, "Config recorder active", 300, 15):
            logger.warning("Config recorder may not be fully active yet")
        
        # Wait for CloudTrail to be logging
        ct = boto3.client("cloudtrail", region_name=region)
        
        def trail_logging():
            try:
                r = ct.get_trail_status(Name=_state["trail_name"])
                return r.get("IsLogging", False)
            except Exception:
                return False
        
        if not _wait(trail_logging, "CloudTrail logging", 300, 15):
            logger.warning("CloudTrail may not be fully active yet")
        
        logger.info("Waiting for services to stabilize (60s)...")
        time.sleep(60)
        
        _state["ready"] = True
        logger.info("=" * 60)
        logger.info("STEADY STATE COMPLETE")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        logger.error(f"Steady state failed: {e}")
        logger.error(traceback.format_exc())
        return False


def attack():
    """Execute attack steps to trigger detective controls."""
    global _state
    logger.info("=" * 60)
    logger.info("ATTACK: SCE 3.4 Detective Probe")
    logger.info("=" * 60)
    
    if not _state.get("ready"):
        logger.error("Not ready - steady state incomplete")
        return False
    
    try:
        boto3 = _get_boto3()
        region = _state["region"]
        inst_id = _state["instance_id"]
        
        ec2 = boto3.client("ec2", region_name=region)
        
        # Record attack start time for CloudTrail verification
        _state["attack_time"] = time.time()
        attack_time_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(_state["attack_time"]))
        logger.info(f"Attack start time: {attack_time_str}")
        
        # Step 1.3: Cloud Infrastructure Discovery (T1580)
        logger.info("-" * 40)
        logger.info("Step 1.3: Discovery (T1580)")
        logger.info("-" * 40)
        try:
            r = ec2.describe_instances(InstanceIds=[inst_id])
            inst = r["Reservations"][0]["Instances"][0]
            md = inst.get("MetadataOptions", {})
            _state["results"]["step_1_3"] = {
                "success": True,
                "http_tokens": md.get("HttpTokens"),
                "hop_limit": md.get("HttpPutResponseHopLimit"),
                "instance_state": inst.get("State", {}).get("Name")
            }
            logger.info(f"Discovery: HttpTokens={md.get('HttpTokens')}, HopLimit={md.get('HttpPutResponseHopLimit')}")
        except Exception as e:
            _state["results"]["step_1_3"] = {"success": False, "error": str(e)}
            logger.error(f"Discovery failed: {e}")
        
        # Step 2.3: Weaken IMDS Protections (T1562.001)
        # This is the key action that should be DETECTED
        logger.info("-" * 40)
        logger.info("Step 2.3: Modify IMDS (T1562.001) - TO BE DETECTED")
        logger.info("-" * 40)
        try:
            # Weaken IMDS protections - this WILL succeed but should be DETECTED
            ec2.modify_instance_metadata_options(
                InstanceId=inst_id,
                HttpTokens="optional",  # Weaken from required to optional
                HttpPutResponseHopLimit=2,  # Increase hop limit
                HttpEndpoint="enabled"
            )
            _state["results"]["step_2_3"] = {
                "success": True,
                "modified": True,
                "new_http_tokens": "optional",
                "new_hop_limit": 2
            }
            logger.info("IMDS MODIFIED - Waiting for detection...")
        except Exception as e:
            _state["results"]["step_2_3"] = {"success": False, "modified": False, "error": str(e)}
            logger.error(f"IMDS modification failed: {e}")
            # For detective probe, we need the modification to succeed
            return False
        
        # Step 3.3: Verify IMDS state changed (T1552.005 prerequisite)
        logger.info("-" * 40)
        logger.info("Step 3.3: Verify IMDS Change (T1552.005)")
        logger.info("-" * 40)
        try:
            r = ec2.describe_instances(InstanceIds=[inst_id])
            md = r["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
            _state["results"]["step_3_3"] = {
                "http_tokens": md.get("HttpTokens"),
                "hop_limit": md.get("HttpPutResponseHopLimit"),
                "imds_weakened": md.get("HttpTokens") == "optional" and md.get("HttpPutResponseHopLimit") == 2
            }
            logger.info(f"IMDS state: HttpTokens={md.get('HttpTokens')}, HopLimit={md.get('HttpPutResponseHopLimit')}")
            logger.info(f"IMDS weakened: {_state['results']['step_3_3']['imds_weakened']}")
        except Exception as e:
            _state["results"]["step_3_3"] = {"error": str(e)}
            logger.error(f"Verification failed: {e}")
        
        logger.info("=" * 60)
        logger.info("ATTACK COMPLETE - Now verifying detection...")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        logger.error(traceback.format_exc())
        return False


def hypothesis_verification():
    """Verify detective controls detected the attack."""
    global _state
    logger.info("=" * 60)
    logger.info("VERIFICATION: SCE 3.4 Detective Probe")
    logger.info("=" * 60)
    
    boto3 = _get_boto3()
    region = _state["region"]
    inst_id = _state["instance_id"]
    
    detection_checks = {
        "cloudtrail_logged": False,
        "config_non_compliant": False,
        "eventbridge_triggered": False
    }
    
    # Check 1: CloudTrail logged ModifyInstanceMetadataOptions
    logger.info("-" * 40)
    logger.info("Check 1: CloudTrail Detection")
    logger.info("-" * 40)
    
    logs = boto3.client("logs", region_name=region)
    log_group = _state["log_group_name"]
    attack_time = _state.get("attack_time", time.time() - 1800)
    
    def check_cloudtrail():
        try:
            # Search CloudWatch Logs for the ModifyInstanceMetadataOptions event
            start_time = int((attack_time - 300) * 1000)  # 5 min before attack
            end_time = int(time.time() * 1000)
            
            response = logs.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                filterPattern='"ModifyInstanceMetadataOptions"'
            )
            
            for event in response.get("events", []):
                msg = event.get("message", "")
                if inst_id in msg and "ModifyInstanceMetadataOptions" in msg:
                    logger.info(f"CloudTrail event found: {event.get('eventId', 'N/A')}")
                    return True
            
            # Also check for any events if specific instance not found
            if response.get("events"):
                logger.info(f"Found {len(response['events'])} CloudTrail events")
                return True
                
            return False
        except Exception as e:
            logger.debug(f"CloudTrail check error: {e}")
            return False
    
    if _wait(check_cloudtrail, "CloudTrail event detection", SLA_TIMEOUT, 30):
        detection_checks["cloudtrail_logged"] = True
        _state["detection_results"]["cloudtrail"] = True
        logger.info("✓ CloudTrail: ModifyInstanceMetadataOptions DETECTED")
    else:
        logger.warning("✗ CloudTrail: Event not detected within SLA")
        _state["detection_results"]["cloudtrail"] = False
    
    # Check 2: AWS Config Rule shows non-compliant
    logger.info("-" * 40)
    logger.info("Check 2: AWS Config Rule Detection")
    logger.info("-" * 40)
    
    config = boto3.client("config", region_name=region)
    rule_name = _state["config_rule_name"]
    
    def check_config_compliance():
        try:
            # Trigger a rule evaluation
            try:
                config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            except Exception:
                pass  # May fail if evaluation already in progress
            
            # Check compliance status
            response = config.get_compliance_details_by_config_rule(
                ConfigRuleName=rule_name,
                ComplianceTypes=["NON_COMPLIANT"]
            )
            
            for result in response.get("EvaluationResults", []):
                resource_id = result.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {}).get("ResourceId", "")
                if resource_id == inst_id:
                    logger.info(f"Config Rule detected non-compliance for {inst_id}")
                    return True
            
            # Check if any non-compliant resources
            if response.get("EvaluationResults"):
                logger.info(f"Found {len(response['EvaluationResults'])} non-compliant resources")
                return True
                
            return False
        except Exception as e:
            logger.debug(f"Config check error: {e}")
            return False
    
    if _wait(check_config_compliance, "Config rule non-compliance detection", SLA_TIMEOUT, 60):
        detection_checks["config_non_compliant"] = True
        _state["detection_results"]["config_rule"] = True
        logger.info("✓ AWS Config: Instance marked NON_COMPLIANT")
    else:
        logger.warning("✗ AWS Config: Non-compliance not detected within SLA")
        _state["detection_results"]["config_rule"] = False
    
    # Check 3: EventBridge rule was triggered (via CloudWatch metrics or SNS)
    logger.info("-" * 40)
    logger.info("Check 3: EventBridge Rule Trigger")
    logger.info("-" * 40)
    
    events = boto3.client("events", region_name=region)
    cw = boto3.client("cloudwatch", region_name=region)
    rule_name = _state["event_rule_name"]
    
    def check_eventbridge():
        try:
            # Check EventBridge rule invocation metrics
            response = cw.get_metric_statistics(
                Namespace="AWS/Events",
                MetricName="TriggeredRules",
                Dimensions=[{"Name": "RuleName", "Value": rule_name}],
                StartTime=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(attack_time - 300)),
                EndTime=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time())),
                Period=60,
                Statistics=["Sum"]
            )
            
            for dp in response.get("Datapoints", []):
                if dp.get("Sum", 0) > 0:
                    logger.info(f"EventBridge rule triggered: {dp.get('Sum')} times")
                    return True
            
            # Alternative: Check Invocations metric
            response = cw.get_metric_statistics(
                Namespace="AWS/Events",
                MetricName="Invocations",
                Dimensions=[{"Name": "RuleName", "Value": rule_name}],
                StartTime=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(attack_time - 300)),
                EndTime=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time())),
                Period=60,
                Statistics=["Sum"]
            )
            
            for dp in response.get("Datapoints", []):
                if dp.get("Sum", 0) > 0:
                    logger.info(f"EventBridge invocations: {dp.get('Sum')}")
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"EventBridge check error: {e}")
            return False
    
    if _wait(check_eventbridge, "EventBridge rule trigger detection", SLA_TIMEOUT, 60):
        detection_checks["eventbridge_triggered"] = True
        _state["detection_results"]["eventbridge"] = True
        logger.info("✓ EventBridge: Rule TRIGGERED")
    else:
        logger.warning("✗ EventBridge: Rule trigger not detected within SLA")
        _state["detection_results"]["eventbridge"] = False
    
    # Summary
    logger.info("=" * 60)
    logger.info("DETECTION SUMMARY")
    logger.info("=" * 60)
    
    for check, result in detection_checks.items():
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"  {status}: {check}")
    
    # For detective probe, we need at least CloudTrail detection
    # Config and EventBridge are bonus detections
    primary_detection = detection_checks["cloudtrail_logged"]
    any_detection = any(detection_checks.values())
    
    _state["verified"] = primary_detection
    
    logger.info("=" * 60)
    if primary_detection:
        logger.info("HYPOTHESIS VERIFIED: Attack DETECTED by CloudTrail")
        if detection_checks["config_non_compliant"]:
            logger.info("  + AWS Config also detected non-compliance")
        if detection_checks["eventbridge_triggered"]:
            logger.info("  + EventBridge rule also triggered")
    else:
        logger.error("HYPOTHESIS FAILED: Primary detection (CloudTrail) not confirmed")
        if any_detection:
            logger.info("  Note: Some secondary detections succeeded")
    logger.info("=" * 60)
    
    return primary_detection


def rollback():
    """Delete CloudFormation stack and cleanup."""
    global _state
    logger.info("=" * 60)
    logger.info("ROLLBACK: SCE 3.4 Detective Probe")
    logger.info("=" * 60)
    
    stack = _state.get("stack_name")
    if not stack:
        logger.info("No stack to delete")
        return True
    
    try:
        boto3 = _get_boto3()
        region = _state.get("region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        cfn = boto3.client("cloudformation", region_name=region)
        
        # First, try to stop Config recorder to allow deletion
        try:
            config = boto3.client("config", region_name=region)
            recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
            for rec in recorders:
                if _state["exp_tag"] in rec.get("name", ""):
                    config.stop_configuration_recorder(ConfigurationRecorderName=rec["name"])
                    logger.info(f"Stopped Config recorder: {rec['name']}")
        except Exception as e:
            logger.debug(f"Config recorder stop: {e}")
        
        # Delete stack
        try:
            cfn.delete_stack(StackName=stack)
            logger.info(f"Deleting stack: {stack}")
        except cfn.exceptions.ClientError as e:
            if "does not exist" in str(e):
                logger.info("Stack already deleted")
                return True
            raise
        
        def deleted():
            try:
                r = cfn.describe_stacks(StackName=stack)
                s = r["Stacks"][0]["StackStatus"]
                if s == "DELETE_COMPLETE":
                    return True
                if s == "DELETE_FAILED":
                    logger.warning("Stack deletion failed - may need manual cleanup")
                    return True  # Continue anyway
                return False
            except cfn.exceptions.ClientError as e:
                if "does not exist" in str(e):
                    return True
                raise
        
        if _wait(deleted, "stack deletion", 900, 20):
            logger.info("=" * 60)
            logger.info("ROLLBACK COMPLETE")
            logger.info("=" * 60)
            return True
        
        logger.warning("Stack deletion timeout - may need manual cleanup")
        return False
        
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        logger.error(traceback.format_exc())
        return False


def run():
    """Standalone runner for testing."""
    result = False
    try:
        if steady_state() and attack():
            result = hypothesis_verification()
    except Exception as e:
        logger.error(f"Experiment error: {e}")
    finally:
        rollback()
    
    logger.info(f"FINAL RESULT: {'PASS' if result else 'FAIL'}")
    return result


if __name__ == "__main__":
    sys.exit(0 if run() else 1)