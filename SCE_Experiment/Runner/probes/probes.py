from typing import Any, Dict, List

from chaoslib.exceptions import FailedActivity
from chaoslib.types import Configuration, Secrets

from chaosaws import aws_client
from chaosaws.types import AWSResponse

from argparse import ArgumentParser, ArgumentTypeError
import random
import sys
import json

__all__ = [
    "describe_instances",
    "count_instances",
    "instance_state",
    "count_min_instances",
]


def describe_instances(
    filters: List[Dict[str, Any]],
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> AWSResponse:
    """
    Describe instances following the specified filters.

    Please refer to https://bit.ly/2Sv9lmU

    for details on said filters.
    """  # noqa: E501
    client = aws_client("ec2", configuration, secrets)

    return client.describe_instances(Filters=filters)


def count_instances(
    filters: List[Dict[str, Any]],
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> int:
    """
    Return count of instances matching the specified filters.

    Please refer to https://bit.ly/2Sv9lmU

    for details on said filters.
    """  # noqa: E501
    client = aws_client("ec2", configuration, secrets)
    result = client.describe_instances(Filters=filters)

    return len(result["Reservations"])


def instance_state(
    state: str,
    instance_ids: List[str] = None,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> bool:
    """
    Determines if EC2 instances match desired state

    For additional filter options, please refer to the documentation found:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    client = aws_client("ec2", configuration, secrets)

    if not any([instance_ids, filters]):
        raise FailedActivity(
            'Probe "instance_state" missing required '
            'parameter "instance_ids" or "filters"'
        )

    if instance_ids:
        instances = client.describe_instances(InstanceIds=instance_ids)
    else:
        instances = client.describe_instances(Filters=filters)

    for i in instances["Reservations"][0]["Instances"]:
        if i["State"]["Name"] != state:
            return False
    return True


def count_min_instances(
    filters: List[Dict[str, Any]],
    min_count: int = 0,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> bool:
    """
    Returns whether the number of instances matching the filters is superior to
    the min_count parameter

    """

    count = count_instances(
        filters=filters, configuration=configuration, secrets=secrets
    )
    return count >= min_count

def find_changes(input_file):
    file1 = open(input_file, 'r')

    buckets = json.load(file1)

    res = True
    message = "Steady State validated"
    for bucket in buckets:
        vals = buckets[bucket]
        if not vals["SS_Collectable"]:
            res = False
            message = "Failed validation"
        if not vals["SS_ACL_Collectable"]:
            res = False
            message = "Failed validation"

    print(f"Is Steady State validated?: {res}")
    print(message)
    return res

import boto3
from datetime import datetime
import time
import json
import os

def check_codeguru_vulnerabilities():
    
    client = boto3.client('codeguru-security')
    pipeline_client = boto3.client('codepipeline')
    
    print("Checking pipeline execution status")
    
    while True:
        time.sleep(5)
        # Get pipeline state
        pipeline_state = pipeline_client.get_pipeline_state(
            name='Experiment-5-CodeGuru'  # Replace with your pipeline name
        )
        
        source_stage = next(stage for stage in pipeline_state['stageStates'] 
                        if stage['stageName'] == 'Source')
        source_status = source_stage['latestExecution']['status']

        build_stage = next(stage for stage in pipeline_state['stageStates'] 
                        if stage['stageName'] == 'Build')
        build_status = build_stage['latestExecution']['status']
        
        sast_stage = next(stage for stage in pipeline_state['stageStates'] 
                        if stage['stageName'] == 'SAST')
        sast_status = sast_stage['latestExecution']['status']

        if build_status == 'Succeeded' and sast_status == 'Succeeded' and source_status == 'Succeeded':
            break
        elif build_status == 'Failed' or sast_status == 'Failed':
            print(f"Pipeline failed")
            break

    try:
        print("Starting code guru session")
        print("Creating Session")
    
        # Get last scan results 
        response = client.get_findings(
            scanName='codepipeline-Experiment-5-CodeGuru' 
        )
        
        metrics = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Count the vulnerabilities by severity
        for finding in response['findings']:
            severity = finding['severity'].lower()
            if severity in metrics:
                metrics[severity] += 1
        
        # Show last scan date
        last_scan_date = datetime.now() 
        print(f"Last scan created at: {last_scan_date}")

        metrics_text = "\nMetrics:\n"
        for severity, count in metrics.items():
            line = f"- '{severity}': {float(count)}\n"
            metrics_text += line
            print(line.rstrip())

        if os.path.exists('codeguru_results.json'):
            with open("codeguru_results.json", "r") as file:
                initial_state = json.load(file)
                if initial_state == metrics:
                    return False

        with open("codeguru_results.json", "w") as file:
            json.dump(metrics, file, indent=4)
        
        return True
        
    except Exception as e:
        print(f"Error getting results: {str(e)}")
        return False




def select_random_List(input_file, output_file, size):
    file = open(input_file, 'r')
    lines = file.readlines()
    res = random.sample(lines, size)
    final = {
        bucket.rstrip(): {
            "SS_Collectable": True,
            "SS_ACL_Collectable": True
        } for bucket in res}

    with open(output_file, 'w') as selected:
        json.dump(final, selected)


def print_help():
    print('No arguments received')


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-l",
                        dest="bucket_list",
                        required=True,
                        help="a list with bucket names.")
    parser.add_argument("-n",
                        dest="number",
                        type=int,
                        default=50,
                        required=False,
                        help="Number of buckets to be selected")
    parser.add_argument("-o",
                        dest="output",
                        type=str,
                        required=False,
                        default="output.txt",
                        help="output file.")

    if len(sys.argv) == 1:
        print_help()
        sys.exit()

    arguments = parser.parse_args()

    select_random_List(arguments.bucket_list, arguments.output, arguments.number)
