import argparse
import logging

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)


def parse_args():
    parser = argparse.ArgumentParser(description='Delete all security groups in a VPC.')
    parser.add_argument('--region',
                        required=True,
                        help='region')
    parser.add_argument('--vpc',
                        required=True,
                        help='vpc')
    return parser.parse_args()


def _revoke_access(security_group_iterator):
    for sg in security_group_iterator:
        try:
            if sg.ip_permissions:
                logging.info("Revoking ingress rules for security group {} {}".format(sg.id, sg.group_name))
                sg.revoke_ingress(IpPermissions=sg.ip_permissions)
            if sg.ip_permissions_egress:
                logging.info("Revoking egress rules for security group {} {}".format(sg.id, sg.group_name))
                sg.revoke_egress(IpPermissions=sg.ip_permissions_egress)
        except ClientError as e:
            logging.error(e)
            logging.error("Error code: {}".format(e.response['Error']['Code']))
            logging.error("Error message: {}".format(e.response['Error']['Message']))


def _delete_groups(security_group_iterator):
    for sg in security_group_iterator:
        try:
            if sg.group_name != 'default':
                logging.info("Deleting security group {} {}".format(sg.id, sg.group_name))
                sg.delete()
        except ClientError as e:
            if e.response['Error']['Code'] == 'DependencyViolation':
                logging.info(e.response['Error']['Message'])
            else:
                logging.error(e)
                logging.error("Error code: {}".format(e.response['Error']['Code']))
                logging.error("Error message: {}".format(e.response['Error']['Message']))


def delete_all_security_groups(region, vpc_id):
    ec2 = boto3.resource('ec2', region_name=region)
    security_group_iterator = ec2.security_groups.filter(
        Filters=[{
            'Name': 'vpc-id',
            'Values': [vpc_id]
        }])
    _revoke_access(security_group_iterator)
    _delete_groups(security_group_iterator)


if __name__ == "__main__":
    args = parse_args()
    region = args.region
    vpc_id = args.vpc
    delete_all_security_groups(region, vpc_id)
