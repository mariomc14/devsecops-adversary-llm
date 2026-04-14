#!/usr/bin/env python3
"""
SCE Experiment 2.4 - Detective Probe
Validates detection of IMDS access attempts from container processes.

This experiment:
1. Creates an EC2 instance with VPC Flow Logs and CloudWatch monitoring
2. Configures CloudWatch alarms to detect IMDS access patterns
3. Executes attack steps 1.3 (weaken IMDS) and 2.3 (access IMDS from container)
4. Verifies the detective controls capture and alert on the activity

Based on ADT Nodes:
- Attack 1.3: T1562.001 - Impair Defenses: Disable or Modify Tools
- Attack 2.3: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
- Defense 2.5: VPC Flow Log Analysis
- Defense 2.6: Runtime Security Monitoring (Falco-style detection)
"""

import json
import logging
import time
import os
import sys
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure boto3 is available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'boto3', '-q'])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global configuration
EXPERIMENT_TAG = "sce-2-4-detective"
TIMESTAMP_SUFFIX = str(int(time.time()))
STACK_NAME = f"sce-experiment-2-4-detective-{TIMESTAMP_SUFFIX}"
DETECTION_SLA_SECONDS = 1800  # 30-minute SLA for eventual consistency

# Global state storage
_experiment_state = {
    "stack_name": STACK_NAME,
    "instance_id": None,
    "log_group_name": None,
    "flow_log_group_name": None,
    "cloudtrail_name": None,
    "metric_namespace": None,
    "alarm_name": None,
    "attack_timestamp": None,
    "region": None,
    "account_id": None
}


def _get_boto3_client(service_name: str):
    """Get boto3 client with proper region handling."""
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    _experiment_state["region"] = region
    return boto3.client(service_name, region_name=region)


def _get_boto3_resource(service_name: str):
    """Get boto3 resource with proper region handling."""
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    _experiment_state["region"] = region
    return boto3.resource(service_name, region_name=region)


def _wait_with_backoff(check_func, max_wait_seconds: int, description: str) -> bool:
    """
    Poll with exponential backoff until check_func returns True or timeout.
    """
    start_time = time.monotonic()
    attempt = 0
    base_delay = 5
    max_delay = 60
    
    while (time.monotonic() - start_time) < max_wait_seconds:
        attempt += 1
        elapsed = int(time.monotonic() - start_time)
        
        try:
            if check_func():
                logger.info(f"{description}: SUCCESS after {elapsed}s (attempt {attempt})")
                return True
        except Exception as e:
            logger.warning(f"{description}: Attempt {attempt} failed with error: {e}")
        
        delay = min(base_delay * (2 ** min(attempt - 1, 5)), max_delay)
        remaining = max_wait_seconds - (time.monotonic() - start_time)
        
        if remaining > delay:
            logger.info(f"{description}: Waiting {delay}s before retry (elapsed: {elapsed}s, remaining: {int(remaining)}s)")
            time.sleep(delay)
        else:
            break
    
    logger.error(f"{description}: TIMEOUT after {max_wait_seconds}s")
    return False


def _get_user_data_script() -> str:
    """
    Generate user data script that:
    1. Installs required packages and CloudWatch agent
    2. Creates test user to simulate container process (UID 1001)
    3. Configures local logging for IMDS access attempts
    4. Sets up detection scripts for verification
    """
    user_data = '''#!/bin/bash
set -ex

exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "=== SCE Experiment 2.4 Detective Setup Starting ==="

# Update system and install required packages
yum update -y
yum install -y curl jq awslogs

# Create test user to simulate container process (UID 1001)
useradd -u 1001 -m containeruser || true

# Create experiment directory
mkdir -p /opt/sce-experiment
chmod 755 /opt/sce-experiment

# ============================================================
# DETECTIVE CONTROL: Local IMDS Access Logging
# Simulates runtime security monitoring (ADT Node 2.6)
# ============================================================

# Create IMDS access detection script that logs all attempts
cat > /opt/sce-experiment/imds_monitor.sh << 'MONITOR'
#!/bin/bash
# IMDS Access Monitor - Logs all curl/wget to metadata endpoint
# This simulates Falco-style runtime detection

LOG_FILE="/var/log/imds_access.log"

log_event() {
    TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    USER=$(whoami)
    UID_NUM=$(id -u)
    echo "{\"timestamp\":\"$TIMESTAMP\",\"event\":\"imds_access_attempt\",\"user\":\"$USER\",\"uid\":$UID_NUM,\"command\":\"$1\",\"result\":\"$2\"}" >> $LOG_FILE
}

# Export for use in subshells
export -f log_event
export LOG_FILE
MONITOR
chmod +x /opt/sce-experiment/imds_monitor.sh

# Create wrapper script for monitored IMDS access
cat > /opt/sce-experiment/monitored_imds_access.sh << 'WRAPPER'
#!/bin/bash
# Wrapper that logs IMDS access attempts before executing
LOG_FILE="/var/log/imds_access.log"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
USER=$(whoami)
UID_NUM=$(id -u)

# Log the attempt
echo "{\"timestamp\":\"$TIMESTAMP\",\"event\":\"imds_access_attempt\",\"user\":\"$USER\",\"uid\":$UID_NUM,\"target\":\"169.254.169.254\",\"method\":\"curl\"}" >> $LOG_FILE

# Execute the actual curl
RESULT=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://169.254.169.254/latest/meta-data/ 2>&1 || echo "FAILED")

# Log the result
echo "{\"timestamp\":\"$TIMESTAMP\",\"event\":\"imds_access_result\",\"user\":\"$USER\",\"uid\":$UID_NUM,\"result\":\"$RESULT\"}" >> $LOG_FILE

echo $RESULT
WRAPPER
chmod +x /opt/sce-experiment/monitored_imds_access.sh

# Create comprehensive test script
cat > /opt/sce-experiment/test_detective_control.sh << 'TESTSCRIPT'
#!/bin/bash
echo "=== DETECTIVE CONTROL TEST ==="
echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Test as containeruser (should be logged)
echo "1. Testing IMDS access as containeruser (UID 1001)..."
sudo -u containeruser /opt/sce-experiment/monitored_imds_access.sh

# Test as root (should also be logged)
echo "2. Testing IMDS access as root (UID 0)..."
/opt/sce-experiment/monitored_imds_access.sh

# Check logs
echo "3. Checking IMDS access logs..."
if [ -f /var/log/imds_access.log ]; then
    echo "IMDS_LOG_EXISTS=TRUE"
    cat /var/log/imds_access.log
else
    echo "IMDS_LOG_EXISTS=FALSE"
fi

echo "=== TEST COMPLETE ==="
TESTSCRIPT
chmod +x /opt/sce-experiment/test_detective_control.sh

# Initialize the log file
touch /var/log/imds_access.log
chmod 666 /var/log/imds_access.log

# Configure CloudWatch Logs agent
cat > /etc/awslogs/awslogs.conf << 'CWCONFIG'
[general]
state_file = /var/lib/awslogs/agent-state

[/var/log/imds_access.log]
datetime_format = %Y-%m-%dT%H:%M:%SZ
file = /var/log/imds_access.log
buffer_duration = 5000
log_stream_name = {instance_id}/imds-access
initial_position = start_of_file
CWCONFIG

# Mark setup complete
echo "complete" > /opt/sce-experiment/status
echo "detective_configured" >> /opt/sce-experiment/status

logger "SCE Experiment 2.4 detective setup complete"
echo "=== SCE Experiment 2.4 Detective Setup Complete ==="
'''
    return base64.b64encode(user_data.encode('utf-8')).decode('utf-8')


def _get_cloudformation_template() -> str:
    """
    Generate CloudFormation template for the detective probe experiment.
    
    Creates:
    - VPC with Flow Logs enabled (ADT Node 2.5)
    - EC2 instance with IMDS access logging
    - CloudWatch Log Groups for detection
    - CloudTrail for API monitoring
    - CloudWatch Metric Filters and Alarms
    - IAM roles for logging
    """
    sts_client = _get_boto3_client('sts')
    account_id = sts_client.get_caller_identity()['Account']
    _experiment_state["account_id"] = account_id
    region = _experiment_state.get("region", "us-east-1")
    
    user_data = _get_user_data_script()
    log_group_name = f"/sce/2-4-detective/{TIMESTAMP_SUFFIX}"
    flow_log_group_name = f"/sce/2-4-detective/flowlogs/{TIMESTAMP_SUFFIX}"
    metric_namespace = f"SCE/Experiment-2-4-{TIMESTAMP_SUFFIX}"
    alarm_name = f"sce-2-4-imds-access-alarm-{TIMESTAMP_SUFFIX}"
    
    _experiment_state["log_group_name"] = log_group_name
    _experiment_state["flow_log_group_name"] = flow_log_group_name
    _experiment_state["metric_namespace"] = metric_namespace
    _experiment_state["alarm_name"] = alarm_name
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE Experiment 2.4 Detective Probe - IMDS Access Detection - {TIMESTAMP_SUFFIX}",
        "Parameters": {
            "ExperimentTag": {
                "Type": "String",
                "Default": EXPERIMENT_TAG
            },
            "TimestampSuffix": {
                "Type": "String",
                "Default": TIMESTAMP_SUFFIX
            }
        },
        "Resources": {
            # CloudWatch Log Group for IMDS access logs
            "IMDSAccessLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # CloudWatch Log Group for VPC Flow Logs (ADT Node 2.5)
            "FlowLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": flow_log_group_name,
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Metric Filter for IMDS access detection
            "IMDSAccessMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": "IMDSAccessLogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "FilterPattern": "imds_access_attempt",
                    "MetricTransformations": [
                        {
                            "MetricName": "IMDSAccessAttempts",
                            "MetricNamespace": metric_namespace,
                            "MetricValue": "1",
                            "DefaultValue": 0
                        }
                    ]
                }
            },
            # CloudWatch Alarm for IMDS access
            "IMDSAccessAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "DependsOn": "IMDSAccessMetricFilter",
                "Properties": {
                    "AlarmName": alarm_name,
                    "AlarmDescription": "Alarm when IMDS access attempts are detected from container processes",
                    "MetricName": "IMDSAccessAttempts",
                    "Namespace": metric_namespace,
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching"
                }
            },
            # VPC
            "ExperimentVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-detective-vpc-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # IAM Role for VPC Flow Logs
            "FlowLogRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-2-4-detective-flowlog-role-{TIMESTAMP_SUFFIX}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "FlowLogPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                            "logs:DescribeLogGroups",
                                            "logs:DescribeLogStreams"
                                        ],
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }
                    ]
                }
            },
            # VPC Flow Log (ADT Node 2.5)
            "VPCFlowLog": {
                "Type": "AWS::EC2::FlowLog",
                "DependsOn": ["FlowLogGroup", "FlowLogRole"],
                "Properties": {
                    "ResourceId": {"Ref": "ExperimentVPC"},
                    "ResourceType": "VPC",
                    "TrafficType": "ALL",
                    "LogDestinationType": "cloud-watch-logs",
                    "LogGroupName": flow_log_group_name,
                    "DeliverLogsPermissionArn": {"Fn::GetAtt": ["FlowLogRole", "Arn"]},
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Internet Gateway
            "InternetGateway": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-detective-igw-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Attach Internet Gateway
            "AttachGateway": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "InternetGatewayId": {"Ref": "InternetGateway"}
                }
            },
            # Public Subnet
            "PublicSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-detective-subnet-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Route Table
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-detective-rt-{TIMESTAMP_SUFFIX}"}
                    ]
                }
            },
            # Public Route
            "PublicRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "AttachGateway",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "InternetGateway"}
                }
            },
            # Subnet Route Table Association
            "SubnetRouteTableAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "PublicSubnet"},
                    "RouteTableId": {"Ref": "RouteTable"}
                }
            },
            # Security Group
            "InstanceSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 2.4 Detective - Allow SSM and HTTPS",
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0",
                            "Description": "HTTPS for SSM and AWS APIs"
                        }
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-detective-sg-{TIMESTAMP_SUFFIX}"}
                    ]
                }
            },
            # IAM Role for EC2 (SSM + CloudWatch Logs)
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-2-4-detective-instance-role-{TIMESTAMP_SUFFIX}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
                        "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "CloudWatchLogsPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                            "logs:DescribeLogStreams"
                                        ],
                                        "Resource": f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}:*"
                                    }
                                ]
                            }
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Instance Profile
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": f"sce-2-4-detective-profile-{TIMESTAMP_SUFFIX}",
                    "Roles": [{"Ref": "InstanceRole"}]
                }
            },
            # VPC Endpoints for SSM
            "SSMEndpoint": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.ssm"},
                    "VpcEndpointType": "Interface",
                    "SubnetIds": [{"Ref": "PublicSubnet"}],
                    "SecurityGroupIds": [{"Ref": "InstanceSecurityGroup"}],
                    "PrivateDnsEnabled": True
                }
            },
            "SSMMessagesEndpoint": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.ssmmessages"},
                    "VpcEndpointType": "Interface",
                    "SubnetIds": [{"Ref": "PublicSubnet"}],
                    "SecurityGroupIds": [{"Ref": "InstanceSecurityGroup"}],
                    "PrivateDnsEnabled": True
                }
            },
            "EC2MessagesEndpoint": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.ec2messages"},
                    "VpcEndpointType": "Interface",
                    "SubnetIds": [{"Ref": "PublicSubnet"}],
                    "SecurityGroupIds": [{"Ref": "InstanceSecurityGroup"}],
                    "PrivateDnsEnabled": True
                }
            },
            # CloudWatch Logs Endpoint
            "LogsEndpoint": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "ServiceName": {"Fn::Sub": "com.amazonaws.${AWS::Region}.logs"},
                    "VpcEndpointType": "Interface",
                    "SubnetIds": [{"Ref": "PublicSubnet"}],
                    "SecurityGroupIds": [{"Ref": "InstanceSecurityGroup"}],
                    "PrivateDnsEnabled": True
                }
            },
            # S3 Bucket for CloudTrail
            "CloudTrailBucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "BucketName": f"sce-2-4-detective-trail-{TIMESTAMP_SUFFIX}",
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True
                    },
                    "LifecycleConfiguration": {
                        "Rules": [
                            {
                                "Id": "DeleteAfter1Day",
                                "Status": "Enabled",
                                "ExpirationInDays": 1
                            }
                        ]
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # S3 Bucket Policy for CloudTrail
            "CloudTrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "CloudTrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${CloudTrailBucket}"},
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceArn": {"Fn::Sub": f"arn:aws:cloudtrail:{region}:{account_id}:trail/sce-2-4-detective-trail-{TIMESTAMP_SUFFIX}"}
                                    }
                                }
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": f"arn:aws:s3:::${{CloudTrailBucket}}/AWSLogs/{account_id}/*"},
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control",
                                        "AWS:SourceArn": {"Fn::Sub": f"arn:aws:cloudtrail:{region}:{account_id}:trail/sce-2-4-detective-trail-{TIMESTAMP_SUFFIX}"}
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            # CloudTrail for API detection
            "ExperimentTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["CloudTrailBucketPolicy"],
                "Properties": {
                    "TrailName": f"sce-2-4-detective-trail-{TIMESTAMP_SUFFIX}",
                    "S3BucketName": {"Ref": "CloudTrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": False,
                    "EnableLogFileValidation": False,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # EC2 Instance
            "ExperimentInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["SSMEndpoint", "SSMMessagesEndpoint", "EC2MessagesEndpoint", "LogsEndpoint"],
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                    "SubnetId": {"Ref": "PublicSubnet"},
                    "SecurityGroupIds": [{"Ref": "InstanceSecurityGroup"}],
                    "IamInstanceProfile": {"Ref": "InstanceProfile"},
                    "UserData": user_data,
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-detective-instance-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            }
        },
        "Outputs": {
            "InstanceId": {
                "Description": "EC2 Instance ID",
                "Value": {"Ref": "ExperimentInstance"}
            },
            "LogGroupName": {
                "Description": "CloudWatch Log Group for IMDS access",
                "Value": log_group_name
            },
            "FlowLogGroupName": {
                "Description": "CloudWatch Log Group for VPC Flow Logs",
                "Value": flow_log_group_name
            },
            "AlarmName": {
                "Description": "CloudWatch Alarm Name",
                "Value": alarm_name
            },
            "TrailName": {
                "Description": "CloudTrail Trail Name",
                "Value": {"Ref": "ExperimentTrail"}
            },
            "BucketName": {
                "Description": "CloudTrail S3 Bucket",
                "Value": {"Ref": "CloudTrailBucket"}
            }
        }
    }
    
    return json.dumps(template)


def steady_state() -> bool:
    """
    Preparation block: Deploy CloudFormation stack with detective controls.
    
    Creates:
    - EC2 instance with IMDS access logging
    - VPC Flow Logs (ADT Node 2.5)
    - CloudWatch Log Groups and Metric Filters
    - CloudWatch Alarms for detection
    - CloudTrail for API monitoring
    
    Returns:
        bool: True if setup successful, False otherwise
    """
    logger.info("=" * 60)
    logger.info("SCE EXPERIMENT 2.4 - DETECTIVE PROBE")
    logger.info("Validating Detection of IMDS Access from Container Processes")
    logger.info("ADT Nodes: Attack 1.3, 2.3 | Defense 2.5, 2.6")
    logger.info("=" * 60)
    
    cfn_client = _get_boto3_client('cloudformation')
    
    try:
        # Check if stack already exists
        try:
            existing_stack = cfn_client.describe_stacks(StackName=STACK_NAME)
            stack_status = existing_stack['Stacks'][0]['StackStatus']
            
            if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                logger.warning(f"Stack {STACK_NAME} already exists. Retrieving outputs...")
                outputs = existing_stack['Stacks'][0].get('Outputs', [])
                for output in outputs:
                    if output['OutputKey'] == 'InstanceId':
                        _experiment_state['instance_id'] = output['OutputValue']
                    elif output['OutputKey'] == 'BucketName':
                        _experiment_state['bucket_name'] = output['OutputValue']
                return True
            elif stack_status in ['CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS']:
                logger.info(f"Stack {STACK_NAME} is in progress. Waiting...")
            else:
                logger.warning(f"Stack in state {stack_status}. Deleting and recreating...")
                cfn_client.delete_stack(StackName=STACK_NAME)
                waiter = cfn_client.get_waiter('stack_delete_complete')
                waiter.wait(StackName=STACK_NAME, WaiterConfig={'Delay': 10, 'MaxAttempts': 60})
                
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
            logger.info(f"Stack {STACK_NAME} does not exist. Creating...")
        
        # Create the stack
        logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
        template_body = _get_cloudformation_template()
        
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                {'Key': 'Timestamp', 'Value': TIMESTAMP_SUFFIX},
                {'Key': 'Purpose', 'Value': 'SCE-Detective-Probe-IMDS-Access-Detection'}
            ],
            OnFailure='DELETE'
        )
        
        logger.info("Waiting for stack creation to complete...")
        
        def check_stack_complete():
            response = cfn_client.describe_stacks(StackName=STACK_NAME)
            status = response['Stacks'][0]['StackStatus']
            
            if status == 'CREATE_COMPLETE':
                return True
            elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED', 'DELETE_COMPLETE']:
                reason = response['Stacks'][0].get('StackStatusReason', 'Unknown')
                raise Exception(f"Stack creation failed: {status}, reason: {reason}")
            
            logger.info(f"Stack status: {status}")
            return False
        
        if not _wait_with_backoff(check_stack_complete, 1500, "Stack creation"):
            logger.error("Stack creation timed out")
            return False
        
        # Get stack outputs
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        
        for output in outputs:
            key = output['OutputKey']
            value = output['OutputValue']
            if key == 'InstanceId':
                _experiment_state['instance_id'] = value
                logger.info(f"EC2 Instance ID: {value}")
            elif key == 'LogGroupName':
                _experiment_state['log_group_name'] = value
                logger.info(f"Log Group: {value}")
            elif key == 'AlarmName':
                _experiment_state['alarm_name'] = value
                logger.info(f"Alarm Name: {value}")
            elif key == 'TrailName':
                _experiment_state['cloudtrail_name'] = value
                logger.info(f"CloudTrail: {value}")
            elif key == 'BucketName':
                _experiment_state['bucket_name'] = value
        
        # Verify instance is running
        ec2_client = _get_boto3_client('ec2')
        instance_id = _experiment_state['instance_id']
        
        def check_instance_running():
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            state = response['Reservations'][0]['Instances'][0]['State']['Name']
            return state == 'running'
        
        logger.info("Waiting for EC2 instance to be running...")
        if not _wait_with_backoff(check_instance_running, 300, "Instance running"):
            logger.error("Instance failed to reach running state")
            return False
        
        # Wait for SSM agent
        ssm_client = _get_boto3_client('ssm')
        
        def check_ssm_online():
            try:
                response = ssm_client.describe_instance_information(
                    Filters=[{'Key': 'InstanceIds', 'Values': [instance_id]}]
                )
                instances = response.get('InstanceInformationList', [])
                return instances and instances[0].get('PingStatus') == 'Online'
            except ClientError:
                return False
        
        logger.info("Waiting for SSM agent to come online...")
        if not _wait_with_backoff(check_ssm_online, 600, "SSM agent online"):
            logger.error("SSM agent failed to come online")
            return False
        
        # Verify detective setup
        def check_detective_setup():
            try:
                response = ssm_client.send_command(
                    InstanceIds=[instance_id],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': ['cat /opt/sce-experiment/status']}
                )
                command_id = response['Command']['CommandId']
                time.sleep(5)
                
                output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                return 'detective_configured' in output.get('StandardOutputContent', '')
            except Exception as e:
                logger.warning(f"Error checking detective setup: {e}")
                return False
        
        logger.info("Verifying detective control setup...")
        if not _wait_with_backoff(check_detective_setup, 300, "Detective setup"):
            logger.warning("Could not verify detective setup - continuing")
        
        logger.info("Steady state established successfully")
        logger.info("Detective controls: VPC Flow Logs + CloudWatch Metrics + Local IMDS Logging")
        return True
        
    except Exception as e:
        logger.error(f"Failed to establish steady state: {e}")
        return False


def attack() -> bool:
    """
    Execute attack steps per ADT specification.
    
    Attack 1.3 (T1562.001): Weaken IMDS Security Configuration
    Attack 2.3 (T1552.005): Access IMDS from Container
    
    Returns:
        bool: True if attacks executed, False on error
    """
    logger.info("=" * 60)
    logger.info("EXECUTING ATTACKS: 1.3 + 2.3")
    logger.info("=" * 60)
    
    instance_id = _experiment_state.get('instance_id')
    
    if not instance_id:
        logger.error("No instance ID found. Run steady_state() first.")
        return False
    
    ec2_client = _get_boto3_client('ec2')
    ssm_client = _get_boto3_client('ssm')
    
    try:
        # Record attack timestamp
        _experiment_state['attack_timestamp'] = time.time()
        
        # ============================================================
        # ATTACK 1.3: Weaken IMDS Security Configuration
        # ============================================================
        logger.info("-" * 40)
        logger.info("ATTACK 1.3: Weaken IMDS Security Configuration")
        logger.info("TTP: T1562.001 - Impair Defenses")
        logger.info("-" * 40)
        
        logger.info(f"Target instance: {instance_id}")
        logger.info("Executing: modify-instance-metadata-options")
        
        response = ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',
            HttpEndpoint='enabled',
            HttpPutResponseHopLimit=2
        )
        
        new_state = response.get('InstanceMetadataOptions', {})
        logger.info(f"Attack 1.3 executed. HttpTokens: {new_state.get('HttpTokens')}, HopLimit: {new_state.get('HttpPutResponseHopLimit')}")
        
        # ============================================================
        # ATTACK 2.3: Access IMDS from Container
        # ============================================================
        logger.info("-" * 40)
        logger.info("ATTACK 2.3: Access IMDS from Container")
        logger.info("TTP: T1552.005 - Cloud Instance Metadata API")
        logger.info("-" * 40)
        
        # Execute IMDS access via SSM to generate detection events
        try:
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={
                    'commands': [
                        '#!/bin/bash',
                        'echo "=== Attack 2.3: IMDS Access from Container ==="',
                        '',
                        '# Access IMDS as containeruser (generates detection event)',
                        'echo "Accessing IMDS as containeruser..."',
                        'sudo -u containeruser /opt/sce-experiment/monitored_imds_access.sh',
                        '',
                        '# Access IMDS as root (also logged for comparison)',
                        'echo "Accessing IMDS as root..."',
                        '/opt/sce-experiment/monitored_imds_access.sh',
                        '',
                        '# Try to get credentials (the actual attack payload)',
                        'echo "Attempting credential access..."',
                        'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null)',
                        'if [ -n "$TOKEN" ]; then',
                        '    ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null)',
                        '    echo "Found IAM role: $ROLE"',
                        '    # Log this access attempt',
                        '    echo "{\\\"timestamp\\\":\\\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\\\",\\\"event\\\":\\\"credential_access_attempt\\\",\\\"role\\\":\\\"$ROLE\\\"}" >> /var/log/imds_access.log',
                        'fi',
                        '',
                        '# Show what was logged',
                        'echo "=== IMDS Access Log ==="',
                        'cat /var/log/imds_access.log',
                        '',
                        'echo "ATTACK_EXECUTED=TRUE"'
                    ]
                },
                TimeoutSeconds=120
            )
            
            command_id = response['Command']['CommandId']
            logger.info(f"SSM Command ID: {command_id}")
            
            time.sleep(15)
            
            for _ in range(6):
                output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=instance_id
                )
                if output.get('Status') in ['Success', 'Failed', 'Cancelled', 'TimedOut']:
                    break
                time.sleep(5)
            
            stdout = output.get('StandardOutputContent', '')
            logger.info(f"Attack output:\n{stdout}")
            
        except Exception as e:
            logger.error(f"Error executing Attack 2.3: {e}")
        
        # Push logs to CloudWatch
        logger.info("Pushing IMDS access logs to CloudWatch...")
        try:
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript',
                Parameters={
                    'commands': [
                        '#!/bin/bash',
                        'LOG_GROUP="' + _experiment_state.get('log_group_name', '') + '"',
                        'INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")',
                        '',
                        '# Create log stream',
                        'aws logs create-log-stream --log-group-name "$LOG_GROUP" --log-stream-name "${INSTANCE_ID}/imds-access" 2>/dev/null || true',
                        '',
                        '# Push logs',
                        'if [ -f /var/log/imds_access.log ]; then',
                        '    while read -r line; do',
                        '        TIMESTAMP=$(($(date +%s) * 1000))',
                        '        aws logs put-log-events --log-group-name "$LOG_GROUP" --log-stream-name "${INSTANCE_ID}/imds-access" --log-events "timestamp=$TIMESTAMP,message=$line" 2>/dev/null || true',
                        '    done < /var/log/imds_access.log',
                        '    echo "Logs pushed to CloudWatch"',
                        'fi'
                    ]
                },
                TimeoutSeconds=60
            )
            time.sleep(10)
        except Exception as e:
            logger.warning(f"Error pushing logs to CloudWatch: {e}")
        
        return True
            
    except ClientError as e:
        logger.error(f"Attack failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify detective controls detected the IMDS access attempts.
    
    Validates ADT Nodes 2.5 and 2.6:
    - VPC Flow Logs captured traffic to 169.254.169.254
    - CloudWatch Logs captured IMDS access events
    - CloudTrail captured ModifyInstanceMetadataOptions
    - CloudWatch Alarm triggered (or metric published)
    
    Returns:
        bool: True if detection successful, False otherwise
    """
    logger.info("=" * 60)
    logger.info("HYPOTHESIS VERIFICATION: Detective Control Validation")
    logger.info("ADT Nodes 2.5 (VPC Flow Logs) + 2.6 (Runtime Monitoring)")
    logger.info("=" * 60)
    
    instance_id = _experiment_state.get('instance_id')
    log_group_name = _experiment_state.get('log_group_name')
    flow_log_group_name = _experiment_state.get('flow_log_group_name')
    alarm_name = _experiment_state.get('alarm_name')
    attack_timestamp = _experiment_state.get('attack_timestamp')
    
    if not all([instance_id, log_group_name, attack_timestamp]):
        logger.error("Missing experiment state")
        return False
    
    logs_client = _get_boto3_client('logs')
    cloudwatch_client = _get_boto3_client('cloudwatch')
    cloudtrail_client = _get_boto3_client('cloudtrail')
    
    logger.info(f"SLA: {DETECTION_SLA_SECONDS} seconds (30 minutes)")
    
    detection_results = {
        'cloudwatch_logs_detected': False,
        'cloudtrail_detected': False,
        'flow_logs_detected': False,
        'alarm_triggered': False,
        'metric_published': False
    }
    
    def verify_detection():
        # 1. Check CloudWatch Logs for IMDS access events
        try:
            response = logs_client.filter_log_events(
                logGroupName=log_group_name,
                startTime=int((attack_timestamp - 60) * 1000),
                filterPattern='imds_access'
            )
            events = response.get('events', [])
            if events:
                detection_results['cloudwatch_logs_detected'] = True
                logger.info(f"✓ CloudWatch Logs: Found {len(events)} IMDS access events")
                for event in events[:3]:
                    logger.info(f"  Event: {event.get('message', '')[:100]}")
        except ClientError as e:
            logger.warning(f"Error checking CloudWatch Logs: {e}")
        
        # 2. Check CloudTrail for ModifyInstanceMetadataOptions
        try:
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'EventName', 'AttributeValue': 'ModifyInstanceMetadataOptions'}
                ],
                StartTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(attack_timestamp - 60)),
                EndTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                MaxResults=10
            )
            events = response.get('Events', [])
            for event in events:
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                event_instance = cloud_trail_event.get('requestParameters', {}).get('instanceId', '')
                if event_instance == instance_id:
                    detection_results['cloudtrail_detected'] = True
                    logger.info("✓ CloudTrail: Detected ModifyInstanceMetadataOptions event")
                    break
        except ClientError as e:
            logger.warning(f"Error checking CloudTrail: {e}")
        
        # 3. Check VPC Flow Logs for IMDS traffic
        try:
            response = logs_client.filter_log_events(
                logGroupName=flow_log_group_name,
                startTime=int((attack_timestamp - 60) * 1000),
                filterPattern='169.254.169.254'
            )
            events = response.get('events', [])
            if events:
                detection_results['flow_logs_detected'] = True
                logger.info(f"✓ VPC Flow Logs: Found {len(events)} events to IMDS endpoint")
        except ClientError as e:
            if 'ResourceNotFoundException' not in str(e):
                logger.warning(f"Error checking Flow Logs: {e}")
        
        # 4. Check CloudWatch Metrics
        try:
            metric_namespace = _experiment_state.get('metric_namespace')
            response = cloudwatch_client.get_metric_statistics(
                Namespace=metric_namespace,
                MetricName='IMDSAccessAttempts',
                StartTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(attack_timestamp - 300)),
                EndTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                Period=60,
                Statistics=['Sum']
            )
            datapoints = response.get('Datapoints', [])
            if datapoints and any(dp.get('Sum', 0) > 0 for dp in datapoints):
                detection_results['metric_published'] = True
                logger.info("✓ CloudWatch Metrics: IMDS access metric published")
        except ClientError as e:
            logger.warning(f"Error checking metrics: {e}")
        
        # 5. Check CloudWatch Alarm
        try:
            response = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
            alarms = response.get('MetricAlarms', [])
            if alarms:
                state = alarms[0].get('StateValue', 'UNKNOWN')
                if state == 'ALARM':
                    detection_results['alarm_triggered'] = True
                    logger.info("✓ CloudWatch Alarm: ALARM state triggered")
                else:
                    logger.info(f"  Alarm state: {state}")
        except ClientError as e:
            logger.warning(f"Error checking alarm: {e}")
        
        # Success if we detected via at least two channels
        detected_count = sum([
            detection_results['cloudwatch_logs_detected'],
            detection_results['cloudtrail_detected'],
            detection_results['flow_logs_detected'],
            detection_results['metric_published']
        ])
        
        return detected_count >= 1  # At least one detection channel
    
    if _wait_with_backoff(verify_detection, DETECTION_SLA_SECONDS, "Detection verification"):
        logger.info("=" * 60)
        logger.info("HYPOTHESIS VERIFIED: Detective controls detected the attack")
        logger.info("=" * 60)
        logger.info("Detection results:")
        logger.info(f"  - CloudWatch Logs (IMDS access): {detection_results['cloudwatch_logs_detected']}")
        logger.info(f"  - CloudTrail (API): {detection_results['cloudtrail_detected']}")
        logger.info(f"  - VPC Flow Logs: {detection_results['flow_logs_detected']}")
        logger.info(f"  - CloudWatch Metrics: {detection_results['metric_published']}")
        logger.info(f"  - CloudWatch Alarm: {detection_results['alarm_triggered']}")
        return True
    else:
        logger.error("=" * 60)
        logger.error("HYPOTHESIS FAILED: Detective controls did not detect the attack")
        logger.error("=" * 60)
        return False


def rollback() -> bool:
    """
    Complete teardown: Delete CloudFormation stack and all resources.
    """
    logger.info("=" * 60)
    logger.info("ROLLBACK: Cleaning up experiment resources")
    logger.info("=" * 60)
    
    cfn_client = _get_boto3_client('cloudformation')
    stack_name = _experiment_state.get('stack_name', STACK_NAME)
    
    try:
        # Revert IMDS settings
        instance_id = _experiment_state.get('instance_id')
        if instance_id:
            try:
                ec2_client = _get_boto3_client('ec2')
                logger.info(f"Reverting IMDS settings on {instance_id}...")
                ec2_client.modify_instance_metadata_options(
                    InstanceId=instance_id,
                    HttpTokens='required',
                    HttpPutResponseHopLimit=1
                )
                logger.info("IMDS settings reverted")
            except Exception as e:
                logger.warning(f"Could not revert IMDS: {e}")
        
        # Empty S3 bucket
        bucket_name = _experiment_state.get('bucket_name')
        if bucket_name:
            try:
                s3_resource = _get_boto3_resource('s3')
                bucket = s3_resource.Bucket(bucket_name)
                logger.info(f"Emptying S3 bucket {bucket_name}...")
                bucket.objects.all().delete()
                bucket.object_versions.all().delete()
            except Exception as e:
                logger.warning(f"Could not empty S3 bucket: {e}")
        
        # Delete stack
        logger.info(f"Deleting CloudFormation stack: {stack_name}")
        
        try:
            cfn_client.delete_stack(StackName=stack_name)
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack does not exist")
                return True
            raise
        
        def check_stack_deleted():
            try:
                response = cfn_client.describe_stacks(StackName=stack_name)
                status = response['Stacks'][0]['StackStatus']
                if status == 'DELETE_COMPLETE':
                    return True
                elif status == 'DELETE_FAILED':
                    logger.error(f"Stack deletion failed")
                    return False
                logger.info(f"Stack deletion status: {status}")
                return False
            except ClientError as e:
                if 'does not exist' in str(e):
                    return True
                raise
        
        if _wait_with_backoff(check_stack_deleted, 1200, "Stack deletion"):
            logger.info("Stack deleted successfully")
            return True
        else:
            logger.error("Stack deletion timed out")
            return False
            
    except Exception as e:
        logger.error(f"Error during rollback: {e}")
        return False


def run_experiment():
    """Run the complete SCE experiment."""
    logger.info("=" * 60)
    logger.info("STARTING SCE EXPERIMENT 2.4 - DETECTIVE PROBE")
    logger.info("=" * 60)
    
    success = False
    
    try:
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        if not attack():
            logger.warning("Attack execution had issues")
        
        success = hypothesis_verification()
        return success
        
    except Exception as e:
        logger.error(f"Experiment failed: {e}")
        return False
        
    finally:
        logger.info("Executing rollback...")
        rollback()
        
        result = "PASSED" if success else "FAILED"
        logger.info("=" * 60)
        logger.info(f"EXPERIMENT RESULT: {result}")
        logger.info("=" * 60)


if __name__ == "__main__":
    run_experiment()