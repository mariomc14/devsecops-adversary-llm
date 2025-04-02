from argparse import ArgumentParser, ArgumentTypeError
import random
import sys
import json

import boto3
from datetime import datetime, timezone, timedelta

import subprocess
import os
import shutil
import time

def find_changes(finding_types, iam_instance_profile):
    
    max_attempts = 8
    check_interval = 300

    # Initialize clients
    guardduty_client = boto3.client('guardduty')

    # Get the detector ID
    try:
        detectors = guardduty_client.list_detectors()
        if not detectors['DetectorIds']:
            print("No GuardDuty detectors found in this region. Make sure GuardDuty is enabled.")
            return False
        
        detector_id = detectors['DetectorIds'][0]
    except Exception as e:
        print(f"Error getting GuardDuty detectors: {e}")
        return False

    for attempt in range(1, max_attempts + 1):

        print(f"\n--- Attempt {attempt}/{max_attempts} [{datetime.now().strftime('%H:%M:%S')}] ---")    
        # Define the time range for the last 5 minutes
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=10)

        # Convert to Unix timestamp in milliseconds
        start_time_ms = int(start_time.timestamp() * 1000)
        end_time_ms = int(end_time.timestamp() * 1000)

        # Define search criteria
        finding_criteria = {
            'Criterion': {
                'type': { 'Equals': finding_types },
                'resource.accessKeyDetails.userName' : { 'Equals' : iam_instance_profile},
                'updatedAt': {
                    'GreaterThanOrEqual': start_time_ms,
                    'LessThanOrEqual': end_time_ms
                }
            }
        }

        try:
            # Retrieve findings
            response = guardduty_client.list_findings(
                DetectorId=detector_id,
                FindingCriteria=finding_criteria
            )
            
            # Get the details of the findings found
            if 'FindingIds' in response and len(response['FindingIds']) > 0:
                findings_detail = guardduty_client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=response['FindingIds']
                )
                
                print(f"{len(response['FindingIds'])} alerts found:")
                for finding in findings_detail['Findings']:
                    print(f"ID: {finding['Id']}")
                    print(f"Type: {finding['Type']}")
                    print(f"User: {finding['Resource']['AccessKeyDetails']['UserName']}")
                    print(f"Severity: {finding['Severity']}")
                    print(f"Account: {finding['AccountId']}")
                    print(f"Region: {finding['Region']}")
                    print(f"Time: {finding['UpdatedAt']}")
                    print("-----------------------------------")
                    return True
            else:
                print("No alerts of the specified type were found in the given period. Waiting another 5 minutes...")
                if (attempt < max_attempts):
                    time.sleep(check_interval)
                else: return False
        except Exception as e:
            print(f"Error querying the findings: {e}")
            return False

