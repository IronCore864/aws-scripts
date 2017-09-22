import logging
from time import sleep

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

ORIGIN_REGION = 'eu-west-2'
ORIGIN_VPC_ID = 'vpc-f21cc59b'

DESTINATION_REGION = 'eu-west-1'
DESTINATION_VPC_ID = 'vpc-e19eed86'

# if enabled, during the migration the name of the security groups are changed.
# for example, origin group name is ldn-test-1, destination prefix is 'irl'
# the new name will be 'irl-test-1'
REPLACE_SECURITY_GROUP_NAME_PREFIX = True
ORIGIN_SECURIGY_GROUP_NAME_PREFIX = 'ldn'
DESTINATION_SECURITY_GROUP_NAME_PREFIX = 'dub'

# if enabled, the ip addresses in the rules in the security groups will be updated
# for example, in origin region all your instances have IP like 10.100.*.*
# but in the destination region you want use 10.101.*.* to separate, this feature is useful
REPLACE_IP_ADDRESS = True
ORIGIN_IP = "10.100"
DESTINATION_IP = "10.102"

AWS_DEFAULT_ALLOW_ALL_OUTBOUND_RULE = [
    {
        "IpProtocol": "-1",
        "PrefixListIds": [],
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "UserIdGroupPairs": [],
        "Ipv6Ranges": []
    }]

logging.basicConfig(level=logging.INFO)


# exit code explanation:
# 2: security group not found
# 3: endpoint connection error

def _get_all_security_groups(region, vpc_id):
    """
    :param region: type str, name of the aws region, e.g., eu-west-1
    :return: array of all security groups
    """
    ec2_client = boto3.client('ec2', region)
    try:
        response = ec2_client.describe_security_groups(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            # security group not found
            logging.error("Err: security group not found!")
        else:
            # other errors like connection issue, etc
            logging.error("Unexpected error: %s" % e)
        exit(2)
    except EndpointConnectionError as e:
        logging.error("Unexpected error: %s" % e)
        exit(3)
    return response['SecurityGroups']


def _create_security_groups(security_groups, region, vpc_id):
    """
    Create security groups in region if not exists.
    In this step only groups themselves are created, not the rules in them, which will be created later.
    NB: by default there is a out bound rule which allows all ports to access all ips created by aws,
    but you probably don't want it so it will be deleted, which means after this function,
    the security group itself is completely empty, only with the name, description and tags defined in input param.
    :param security_groups: security_groups to be created
    :param region: type str, name of the aws region, e.g., eu-west-1
    :param vpc_id: type str, name of the vpc under which the groups will be created
    :return: None
    """
    existing_security_groups = _get_all_security_groups(region, vpc_id)
    # because newly created security groups are assigned random ids
    # we need to keep track of name-id pair, so that in the origin region if some group references another by id,
    # we know how to do it in the destination region
    sg_name_id_dict = {}
    # security groups that already exist in the destination region
    for sg in existing_security_groups:
        sg_name_id_dict[sg['GroupName']] = sg['GroupId']
    ec2 = boto3.resource('ec2', region_name=region)
    for osg in security_groups:
        logging.info("Migrating security group {}".format(osg['GroupName']))
        if osg['GroupName'] not in sg_name_id_dict:
            dsg = ec2.create_security_group(Description=osg['Description'], GroupName=osg['GroupName'], VpcId=vpc_id)
            sleep(1)
            logging.info("{} {} is created!".format(dsg.group_name, dsg.group_id))
            sg_name_id_dict[osg['GroupName']] = dsg.group_id
            logging.info("Revoking default outbound rule for {}:".format(osg['GroupName']))
            dsg.revoke_egress(IpPermissions=AWS_DEFAULT_ALLOW_ALL_OUTBOUND_RULE)
        else:
            dsg = ec2.SecurityGroup(sg_name_id_dict[osg['GroupName']])
            logging.info("Security group {} already exists, id {}".format(dsg.group_name, dsg.group_id))
        dsg.create_tags(Tags=osg['Tags'])
    return sg_name_id_dict


def _update_group_id(security_group, orig_sg_id_name_dict, dest_sg_name_id_dict):
    # replace rules with group ids in destination region
    for rule in security_group['IpPermissions'] + security_group['IpPermissionsEgress']:
        if rule['UserIdGroupPairs']:
            for pair in rule['UserIdGroupPairs']:
                pair['GroupId'] = dest_sg_name_id_dict[orig_sg_id_name_dict[pair['GroupId']]]
    return security_group


def _update_ip_address(security_group):
    # replace rules with group ids in destination region
    for rule in security_group['IpPermissions'] + security_group['IpPermissionsEgress']:
        if rule['IpRanges']:
            for ip_range in rule['IpRanges']:
                if ip_range['CidrIp'].startswith(ORIGIN_IP):
                    ip_range['CidrIp'] = DESTINATION_IP + ip_range['CidrIp'][len(ORIGIN_IP):]
    return security_group


def _process_rules(security_group, orig_sg_id_name_dict, dest_sg_name_id_dict):
    security_group = _update_group_id(security_group, orig_sg_id_name_dict, dest_sg_name_id_dict)
    if REPLACE_IP_ADDRESS:
        security_group = _update_ip_address(security_group)
    return security_group


def _generate_security_group_id_name_dict(security_groups):
    id_name_dict = {}
    for osg in security_groups:
        id_name_dict[osg['GroupId']] = osg['GroupName']
    return id_name_dict


def _set_ingress_egress_rules(origin_security_groups, dest_sg_name_id_dict, region):
    ec2 = boto3.resource('ec2', region_name=region)
    orig_sg_id_name_dict = _generate_security_group_id_name_dict(origin_security_groups)
    for osg in origin_security_groups:
        osg = _process_rules(osg, orig_sg_id_name_dict, dest_sg_name_id_dict)
        dsg = ec2.SecurityGroup(dest_sg_name_id_dict[osg['GroupName']])
        try:
            if osg['IpPermissions']:
                logging.info("Adding inbound rules to security group {}".format(dsg.group_name))
                dsg.authorize_ingress(IpPermissions=osg['IpPermissions'])
            if osg['IpPermissionsEgress']:
                logging.info("Adding outbound rules to security group {}".format(dsg.group_name))
                dsg.authorize_egress(IpPermissions=osg['IpPermissionsEgress'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                logging.info(e.response['Error']['Message'])
            else:
                logging.error(e)
                logging.error("Error code: {}".format(e.response['Error']['Code']))
                logging.error("Error message: {}".format(e.response['Error']['Message']))


def _replace_security_group_name_prefix(security_groups):
    for i in range(len(security_groups)):
        if security_groups[i]['GroupName'].startswith(ORIGIN_SECURIGY_GROUP_NAME_PREFIX):
            security_groups[i]['GroupName'] = DESTINATION_SECURITY_GROUP_NAME_PREFIX + \
                                              security_groups[i]['GroupName'][len(ORIGIN_SECURIGY_GROUP_NAME_PREFIX):]
        for tag in security_groups[i]['Tags']:
            if tag['Key'] == 'Name' and tag['Value'].startswith(ORIGIN_SECURIGY_GROUP_NAME_PREFIX):
                tag['Value'] = DESTINATION_SECURITY_GROUP_NAME_PREFIX + \
                               tag['Value'][len(ORIGIN_SECURIGY_GROUP_NAME_PREFIX):]
    return security_groups


def migrate_security_groups(origin_region, origin_vpc_id, destination_region, destination_vpc_id):
    """
    Create security groups in destination region if not exists.
    In this step only groups themselves are created, not the rules in them, which will be created later.
    NB: by default there is a out bound rule which allows all ports to access all ips created by aws,
    but you probably don't want it so it will be deleted, which means after this function,
    the security group itself is completely empty, only with the same name in the original region.
    :return: None
    """
    origin_region_security_groups = _get_all_security_groups(origin_region, origin_vpc_id)

    if REPLACE_SECURITY_GROUP_NAME_PREFIX:
        origin_region_security_groups = _replace_security_group_name_prefix(origin_region_security_groups)

    dest_sg_name_id_dict = _create_security_groups(
        origin_region_security_groups,
        destination_region,
        destination_vpc_id
    )

    _set_ingress_egress_rules(
        origin_region_security_groups,
        dest_sg_name_id_dict,
        destination_region
    )


if __name__ == "__main__":
    migrate_security_groups(ORIGIN_REGION, ORIGIN_VPC_ID, DESTINATION_REGION, DESTINATION_VPC_ID)
