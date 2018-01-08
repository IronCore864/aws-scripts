import os
from time import sleep
import logging
import configparser

import boto3
from botocore.exceptions import ClientError

cfg = configparser.ConfigParser()
cfg.read(os.path.join(os.path.dirname(__file__), "../config/cfg.ini"))

VPC = cfg['AWS']['vpc']
REGION = cfg['AWS']['region']
ROUTE_53_ZONE_ID = cfg['AWS']['route_53_zone_id']
MS_SUBNET = cfg['AWS']['ms_subnet']

module_logger = logging.getLogger('main.utils.aws')


def _remove_default_existing_rules(sg):
    if sg.ip_permissions:
        sg.revoke_ingress(IpPermissions=sg.ip_permissions)
    if sg.ip_permissions_egress:
        sg.revoke_egress(IpPermissions=sg.ip_permissions_egress)


def create_security_group(group_name, ingress=None, egress=None):
    """
    :param group_name: the name of the security group to be created
    :return: security group id
    """
    try:
        ec2 = boto3.resource('ec2', region_name=REGION)
        sg = ec2.create_security_group(
            GroupName=group_name,
            Description=group_name,
            VpcId=VPC)
        sg.create_tags(
            Tags=[{
                'Key': 'Name',
                'Value': group_name,
            }])
        _remove_default_existing_rules(sg)
        if ingress:
            sg.authorize_ingress(IpPermissions=ingress)
        if egress:
            sg.authorize_egress(IpPermissions=egress)
        return sg.id
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
            module_logger.warning("Security group {} already exists!".format(group_name))
            client = boto3.client('ec2', region_name=REGION)
            response = client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-name',
                        'Values': [
                            group_name,
                        ]
                    }
                ]
            )
            return response['SecurityGroups'][0]['GroupId']
        else:
            module_logger.error("Unexpected error: %s" % e)
            exit(-1)


def create_auto_scaling_group_and_policy(group_name, tag_name, launch_config_name, policy_name):
    """
    :param group_name: the name of the auto scaling group to be created
    :param launch_config_name: which existing launch config to be used
    :return:
    """
    _create_asg_and_tag(group_name, tag_name, launch_config_name)
    # wait to make sure group is created
    sleep(3)
    _create_scaling_policy_for_group(group_name, policy_name)


def upsert_route53_cname(name, value):
    client = boto3.client('route53')
    try:
        r = client.change_resource_record_sets(
            HostedZoneId=ROUTE_53_ZONE_ID,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': name,
                            'Type': 'CNAME',
                            'TTL': 300,
                            'ResourceRecords': [
                                {
                                    'Value': value
                                },
                            ],
                        }
                    },
                ]
            }
        )
    except ClientError as e:
        module_logger.error("Unexpected error: %s" % e)
        exit(-1)


def _create_asg_and_tag(group, tag, launch_config):
    client = boto3.client('autoscaling', region_name=REGION)
    try:
        r = client.create_auto_scaling_group(
            AutoScalingGroupName=group,
            LaunchConfigurationName=launch_config,
            MaxSize=1,
            MinSize=1,
            VPCZoneIdentifier=MS_SUBNET,
            HealthCheckGracePeriod=300,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': tag,
                    'PropagateAtLaunch': True,
                },
            ]
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'AlreadyExists':
            module_logger.warning("Auto scaling group {} already exists!".format(group))
        else:
            module_logger.error("Unexpected error: %s" % e)
            exit(-1)


def _create_scaling_policy_for_group(group, policy):
    client = boto3.client('autoscaling', region_name=REGION)
    try:
        r = client.put_scaling_policy(
            AdjustmentType='ChangeInCapacity',
            AutoScalingGroupName=group,
            PolicyName=policy,
            ScalingAdjustment=1,
        )
    except ClientError as e:
        module_logger.error("Unexpected error: %s" % e)
        exit(-1)
