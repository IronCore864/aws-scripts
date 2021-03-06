import argparse
import logging

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

logging.basicConfig(level=logging.INFO)


# exit code explanation:
# 2: security group not found
# 3: endpoint connection error

def parse_args():
    parser = argparse.ArgumentParser(description='AWS security groups comparison.')
    parser.add_argument('--from-region',
                        required=True,
                        help='source region')
    parser.add_argument('--from-vpc',
                        required=True,
                        help='source region')
    parser.add_argument('--from-ip-prefix',
                        help='source region/vpc ip address prefix')
    parser.add_argument('--from-sg-prefix',
                        help='source region/vpc group name prefix')
    parser.add_argument('--to-region',
                        required=True,
                        help='destination region')
    parser.add_argument('--to-vpc',
                        required=True,
                        help='destination region')
    parser.add_argument('--to-ip-prefix',
                        help='destination region/vpc ip address prefix')
    parser.add_argument('--to-sg-prefix',
                        help='destination region/vpc group name prefix')
    parser.add_argument('--replace-sg-prefix',
                        action='store_true',
                        help='If enabled, it means there is a prefix in the security group name. '
                             'Always used together with --from-sg-prefix and --to-sg-prefix. '
                             'For example, origin group name is ldn-test-1, destination name irl-test-1, '
                             'then the --from-sg-prefix would be ldn, and the --to-sg-prefix would be irl.')
    parser.add_argument('--replace-ip-prefix',
                        action='store_true',
                        help='If enabled, it means the ip address prefixes are different between vpcs'
                             '(normally it is the case). '
                             'Always used together with --from-ip-prefix and --to-ip-prefix. '
                             'For example, in origin region all your instances have IP like 10.100.*.*, '
                             'and in destination region ip is like 10.102.*.*, '
                             'the --from-ip-prefix would be 10.100. and --to-ip-prefix would be 10.102. '
                             'Make sure you include the last dot in the ip prefix because if not, '
                             'the prefix 10.10 may match 10.102.1.1 which is not what you may want.')
    return parser.parse_args()


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


def _generate_security_group_id_name_dict(security_groups):
    id_name_dict = {}
    for sg in security_groups:
        id_name_dict[sg['GroupId']] = sg['GroupName']
    return id_name_dict


def _handle_name(sg_groups, prefix):
    for sg in sg_groups:
        if sg['GroupName'].startswith(prefix):
            sg['GroupName'] = sg['GroupName'][len(prefix):]
        if 'Tags' in sg:
            for tag in sg['Tags']:
                if tag['Key'] == 'Name' and tag['Value'].startswith(prefix):
                    tag['Value'] = tag['Value'][len(prefix):]


def _handle_group_id(sg_groups):
    id_name_dict = _generate_security_group_id_name_dict(sg_groups)
    for sg in sg_groups:
        for rule in sg['IpPermissionsEgress'] + sg['IpPermissions']:
            if rule['UserIdGroupPairs']:
                for id_group_pair in rule['UserIdGroupPairs']:
                    id_group_pair['GroupId'] = id_name_dict[id_group_pair['GroupId']]


def _handle_vpc_group_id(sg_groups):
    id_name_dict = {}
    for sg in sg_groups:
        sg['VpcId'] = ''
        sg['GroupId'] = ''


def _hanlde_ip(sg_groups, ip_prefix):
    for sg in sg_groups:
        for rule in sg['IpPermissionsEgress'] + sg['IpPermissions']:
            if rule['IpRanges']:
                for ip_range in rule['IpRanges']:
                    if ip_range['CidrIp'].startswith(ip_prefix):
                        ip_range['CidrIp'] = ip_range['CidrIp'][len(ip_range['CidrIp']):]


def _handle_rule_order(sg_groups):
    for sg in sg_groups:
        def compare(a, b):
            if a['IpProtocol'] < b['IpProtocol']:
                return -1
            elif a['IpProtocol'] > b['IpProtocol']:
                return 1
            else:
                if not a['FromPort'] and b['FromPort']:
                    return -1
                elif a['FromPort'] and not b['FromPort']:
                    return 1
                else:
                    if a['FromPort'] < b['FromPort']:
                        return -1
                    elif a['FromPort'] == b['FromPort']:
                        return 0
                    else:
                        return 1

        sg['IpPermissions'] = sorted(sg['IpPermissions'], cmp=compare)
        sg['IpPermissionsEgress'] = sorted(sg['IpPermissionsEgress'], cmp=compare)

        for rule in sg['IpPermissionsEgress'] + sg['IpPermissions']:
            if rule['UserIdGroupPairs']:
                rule['UserIdGroupPairs'] = sorted(rule['UserIdGroupPairs'], key=lambda k: k['GroupId'])
            if rule['IpRanges']:
                rule['IpRanges'] = sorted(rule['IpRanges'], key=lambda k: k['CidrIp'])


def _compare_len(sgs_a, sgs_b, region_a, vpc_a, region_b, vpc_b):
    m, n = len(sgs_a), len(sgs_b)
    if m == n:
        logging.info("Region {} VPC {} and Region {} VPC {} both have {} security groups.".format(
            region_a, vpc_a, region_b, vpc_b, m
        ))
        return True
    else:
        logging.error("Region {} VPC {} has {} security groups but Region {} VPC {} has {} security groups.".format(
            region_a, vpc_a, m, region_b, vpc_b, n
        ))
        a, b = set(), set()
        for sg in sgs_a:
            a.add(sg['GroupName'])
        for sg in sgs_b:
            b.add(sg['GroupName'])
        if a - b:
            logging.error("Region {} VPC {} has {} but Region {} VPC {} doesn't".format(
                region_a, vpc_a, ",".join(list(a - b)), region_b, vpc_b
            ))
        if b - a:
            logging.error("Region {} VPC {} has {} but Region {} VPC {} doesn't".format(
                region_b, vpc_b, ",".join(list(b - a)), region_a, vpc_a
            ))


def _compare_rule(sgs_a, sgs_b, region_a, vpc_a, region_b, vpc_b):
    name_rules_dict_a, name_rules_dict_b = {}, {}
    for sg in sgs_a:
        name_rules_dict_a[sg['GroupName']] = {'Ingress': sg['IpPermissions'], 'Egress': sg['IpPermissionsEgress']}
    for sg in sgs_b:
        name_rules_dict_b[sg['GroupName']] = {'Ingress': sg['IpPermissions'], 'Egress': sg['IpPermissionsEgress']}
    res = True
    for sg_a, rules_a in name_rules_dict_a.iteritems():
        if sg_a not in name_rules_dict_b:
            # ignore non-existing groups
            continue
        rules_b = name_rules_dict_b[sg_a]
        if rules_a['Ingress'] != rules_b['Ingress']:
            res = False
            logging.error(
                "Security group {} in Region {} VPC {} has inbound rule {}, "
                "but in Region {} VPC {} the rule is different: {}".format(
                    sg_a, region_a, vpc_a, rules_a['Ingress'], region_b, vpc_b, rules_b['Ingress']
                ))
        if rules_a['Egress'] != rules_b['Egress']:
            res = False
            logging.error(
                "Security group {} in Region {} VPC {} has outbound rule {}, "
                "but in Region {} VPC {} the rule is different: {}".format(
                    sg_a, region_a, vpc_a, rules_a['Egress'], region_b, vpc_b, rules_b['Egress']
                ))
    if res:
        logging.info("Region {} VPC {} and Region {} VPC {} have same rules.".format(
            region_a, vpc_a, region_b, vpc_b
        ))
    return res


def compare_security_groups(region_a, vpc_a, region_b, vpc_b):
    sg_groups_a, sg_groups_b = _get_all_security_groups(region_a, vpc_a), \
                               _get_all_security_groups(region_b, vpc_b)

    if SECURITY_GROUP_NAME_PREFIX:
        _handle_name(sg_groups_a, SG_NAME_PREFIX_A)
        _handle_name(sg_groups_b, SG_NAME_PREFIX_B)
    _handle_group_id(sg_groups_a), _handle_group_id(sg_groups_b)
    _handle_vpc_group_id(sg_groups_a), _handle_vpc_group_id(sg_groups_b)
    if IP_PREFIX:
        _hanlde_ip(sg_groups_a, IP_PREFIX_A), _hanlde_ip(sg_groups_b, IP_PREFIX_B)
    _handle_rule_order(sg_groups_a)
    _handle_rule_order(sg_groups_b)

    res_len = _compare_len(sg_groups_a, sg_groups_b, region_a, vpc_a, region_b, vpc_b)
    res_rule = _compare_rule(sg_groups_a, sg_groups_b, region_a, vpc_a, region_b, vpc_b)
    return res_len and res_rule


if __name__ == "__main__":
    args = parse_args()
    REGION_A = args.from_region
    VPC_A = args.from_vpc
    REGION_B = args.to_region
    VPC_B = args.to_vpc
    SG_NAME_PREFIX_A = args.from_sg_prefix
    SG_NAME_PREFIX_B = args.to_sg_prefix
    IP_PREFIX_A = args.from_ip_prefix
    IP_PREFIX_B = args.to_ip_prefix
    SECURITY_GROUP_NAME_PREFIX = args.replace_sg_prefix
    IP_PREFIX = args.replace_ip_prefix

    compare_security_groups(REGION_A, VPC_A, REGION_B, VPC_B)
