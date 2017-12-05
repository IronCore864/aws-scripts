import argparse

import boto3
from botocore.exceptions import ClientError

# only describe rules of these types
FILTER = ['tcp', 'udp']


# exit code explanation:
# 1: security group not found

def parse_args():
    parser = argparse.ArgumentParser(description='AWS security groups comparison.')
    parser.add_argument('-r', '--region',
                        required=True,
                        help='Region')
    parser.add_argument('-g', '--sg',
                        required=True,
                        help='Security group id you want to describe')
    parser.add_argument('-f', '--full-desc',
                        action='store_true',
                        help='By default only output the first word of the description to keep it short'
                             'The idea is, for example, if the port is 3306, the description might be like:'
                             'MySQL of xxx xxx; so most of the time the first word is enough to describe it.'
                             'if --full-desc is specified, the full description will be used instead')
    return parser.parse_args()


def describe_security_group(security_group_id, region):
    ec2 = boto3.client('ec2', region_name=region)
    try:
        response = ec2.describe_security_groups(
            Filters=[
                {
                    'Name': 'ip-permission.protocol',
                    'Values': FILTER,
                },
            ],
            GroupIds=[
                str(security_group_id),
            ],
        )
    except ClientError as e:
        # cache security group not found exception
        if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
            print "Err: security group not found!"
        else:
            print "Unexpected error: %s" % e
        exit(1)
    return response


def parse_response(response, full_desc):
    res = []
    # json output parse
    for sg in response['SecurityGroups']:
        permissions = sg['IpPermissions']
        for perm in permissions:
            if perm['IpProtocol'] in FILTER:
                port = str(perm['FromPort'])
                protocol = perm['IpProtocol']
                description = ''
                # description could be in either IpRanges or UserIdGroupPairs section
                if 'IpRanges' in perm:
                    ip_ranges = perm['IpRanges']
                    for ip_range in ip_ranges:
                        if 'Description' in ip_range:
                            description = ip_range['Description']

                if 'UserIdGroupPairs' in perm and not description:
                    userid_group_pairs = perm['UserIdGroupPairs']
                    for userid_group_pair in userid_group_pairs:
                        if 'Description' in userid_group_pair:
                            description = userid_group_pair['Description']

                if not full_desc:
                    description = description.split(' ')[0]

                res.append([port, protocol, description])
    return res


def output(result):
    # sort by port as int, asc
    result = sorted(result, key=lambda x: int(x[0]))
    for rule in result:
        print ';'.join(rule)


if __name__ == "__main__":
    args = parse_args()

    region = args.region
    full_desc = args.full_desc
    sg = args.sg

    response = describe_security_group(sg, region)
    result = parse_response(response, full_desc)
    output(result)
    exit(0)
