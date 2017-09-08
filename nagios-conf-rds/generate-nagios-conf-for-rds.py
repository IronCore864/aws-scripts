import boto3
from botocore.exceptions import ClientError
import os, re, subprocess
from jinja2 import Environment, FileSystemLoader

# aws region
REGION = 'eu-west-2'
# nagios cfg dir
NAGIOS_CFG_DIR = '/usr/local/nagios/etc/cfgs/hosts'
# nagios cfg template filename
NAGIOS_CFG_TEMPLATE = 'example_host.cfg.j2'
# nagios cfg validation cmd
NAGIOS_VALIDATE_CMD = '/usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg'
# nagios restart cmd
NAGIOS_RESTART_CMD = 'service nagios restart'


def describe_db_instances():
    ec2 = boto3.client('rds', region_name=REGION)
    try:
        response = ec2.describe_db_instances()
    except ClientError as e:
        print "Unexpected error: %s" % e
        exit(1)
    return response


def parse_response(response):
    """
    :param response: output of boto3 rds client describe_db_instances
    :return: an array, each element is an 3-element array with DBInstanceIdentifier, Engine, and Endpoint Address
    Example:
        [
            ['devdb-ldn-test1', 'mysql', 'devdb-ldn-test.cjjimtutptto.eu-west-2.rds.amazonaws.com'],
            ['devdb-ldn-test2', 'postgres', 'devdb-ldn-test.cjjimtutptto.eu-west-2.rds.amazonaws.com'],
            ...
        ]
    """
    res = []
    # json output parse
    for db in response['DBInstances']:
        res.append([db['DBInstanceIdentifier'], db['Engine'], db['Endpoint']['Address']])
    return res


def purge(dir, pattern):
    """
    Delete files whose names match a specific pattern.
    Example: purge("/usr/local/nagios/etc/cfgs/hosts", "^i-.*\.cfg$") equals to rm -rf i-*.cfg
    :param dir: the directory under which to delete files
    :param pattern: regex pattern
    :return: None
    """
    for f in os.listdir(dir):
        if re.search(pattern, f):
            os.remove(os.path.join(dir, f))


def render(instances):
    """
    Using jinja to generate nagios cfg for all the instances collected
    :param instances: instance list, returned by get_ec2_instances()
    :return: None
    """
    j2_env = Environment(loader=FileSystemLoader(NAGIOS_CFG_DIR), trim_blocks=True)
    for inst in instances:
        filename = "{}/rds-{}_{}.cfg".format(NAGIOS_CFG_DIR, inst[0], inst[1])
        with open(filename, 'w') as f:
            f.write(
                j2_env.get_template(NAGIOS_CFG_TEMPLATE).render(
                    HOSTNAME='{}_{}'.format(inst[0], inst[1]),
                    IP=inst[2],
                    USE=inst[1]
                )
            )


def validate():
    process = subprocess.Popen(NAGIOS_VALIDATE_CMD, shell=True, stdout=subprocess.PIPE)
    process.wait()
    return process.returncode


def reboot():
    process = subprocess.Popen(NAGIOS_RESTART_CMD, shell=True, stdout=subprocess.PIPE)
    process.wait()
    return process.returncode


if __name__ == "__main__":
    # at least one parameter is needed which is the security group id, like sg-12345
    response = describe_db_instances()
    instances = parse_response(response)
    purge(NAGIOS_CFG_DIR, "^rds-.*\.cfg$")
    render(instances)
    if validate() == 0:
        print("Nagios cfg is valid!")
        reboot()
    exit(0)
