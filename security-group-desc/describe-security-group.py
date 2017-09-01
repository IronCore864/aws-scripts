import boto3
from botocore.exceptions import ClientError

import sys

# aws region
REGION = 'eu-west-2'
# only describe rules of these types
FILTER = ['tcp', 'udp']


# exit code explanation:
# 1: security group id not provided
# 2: security group not found

def describe_security_group(security_group_id):
    ec2 = boto3.client('ec2', region_name=REGION)
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
        exit(2)
    return response


def parse_response(response):
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

                res.append([port, protocol, description])
    return res


def output(result):
    # sort by port as int, asc
    result = sorted(result, key=lambda x: int(x[0]))
    for rule in result:
        print ';'.join(rule)


if __name__ == "__main__":
    # at least one parameter is needed which is the security group id, like sg-12345
    if len(sys.argv) < 2:
        print "Please specify security group id."
        print "Usage:"
        print "\t{} {}".format(sys.argv[0], 'sg-xxxxx')
        exit(1)
    else:
        security_group_id = sys.argv[1]
        response = describe_security_group(security_group_id)
        result = parse_response(response)
        output(result)
        exit(0)
