import argparse
import os, re, subprocess
from collections import defaultdict

from boto import ec2
from jinja2 import Environment, FileSystemLoader

# used to replace spaces, dot in name tags
CONCAT_CHAR = '_'
# nagios cfg dir
NAGIOS_CFG_DIR = '/usr/local/nagios/etc/cfgs/hosts'
# nagios cfg template filename
NAGIOS_CFG_TEMPLATE = 'example_host.cfg.j2'
# nagios cfg validation cmd
NAGIOS_VALIDATE_CMD = '/usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg'
# ignore instances that has 'test' in its name tag. default true.
# useful when someone else in your team wants to create an instance for test, whose name probably contains 'test', like
# haproxy-test, and you don't want to add it into nagios because it will probably be used only for a couple of days or even hours.
# if you want to include everything, just change it to False
IGNORE_TEST_INSTANCE = True
# ignore instances with a tag 'Nagios' = 'ignore'. default true.
# when set to true, ignore instances with a tag 'Nagios' of the value 'ignore'
# useful when you have certain instances that you don't want to include in nagios.
# if you want to include everything, just change it to False, or don't create this 'Nagios' tag at all.
IGNORE_NAGIOS_TAG_INSTANCE = True

USE = 'linux'


def parse_args():
    parser = argparse.ArgumentParser(description='Generate nagios configuration for aws ec2.')
    parser.add_argument('-r', '--region',
                        required=True,
                        help='Region')
    return parser.parse_args()


def get_ec2_instances(region):
    """
    Get all ec2 instances' id, name tag, and ip.
    :param region: the aws region 
    :return: instance list. Example:
    [
        ['id1', 'name1', '100.10.10.101'],
        ['id2', 'name2-102', '100.10.10.102'],
        ['id3', 'name2-103', '100.10.10.103'],
        ['id4', 'name3', '100.10.10.104'],
    ]
    """

    # get ec2 connection by region
    conn = ec2.connect_to_region(region)
    # get all instances
    reservations = conn.get_all_instances()

    ####
    # Getting a dictionary of all the isntances.
    # Key is instance name, value is an array, of which each element is a id, ip tuple
    #
    # Example:
    # {
    #     "name1": [
    #         ["id1", "ip1"],
    #         ["id2", "ip2"],
    #         ...
    #     ],
    #     "name2": [
    #         ["id3", "ip3"],
    #         ...
    #     ],
    # }
    ####
    instances_dict = defaultdict(lambda: [])

    for res in reservations:
        for inst in res.instances:

            # ignore terminated instances
            if inst.state == 'terminated':
                continue
            # key 'Nagios' value 'ignore' means do not add it into nagios
            if IGNORE_NAGIOS_TAG_INSTANCE and 'Nagios' in inst.tags and inst.tags['Nagios'] == 'ignore':
                continue
            # ignore instances that has 'test' as part of its name tag
            if IGNORE_TEST_INSTANCE and 'Name' in inst.tags and 'test' in inst.tags['Name'].lower():
                continue

            name = inst.tags['Name'] + CONCAT_CHAR + inst.id if 'Name' in inst.tags else inst.id
            name = name.replace(' ', CONCAT_CHAR)
            name = re.sub(r"[\(\)]", "", name)
            name = re.sub(r"[^-_a-zA-Z0-9]", CONCAT_CHAR, name)
            instances_dict[name].append([inst.id, inst.private_ip_address])

    ####
    # Solve duplicate instance names
    # The idea is adding the last section of IP as part of the name, if the name is duplicated.
    ####
    instance_list = []

    for name, id_ip_list in instances_dict.items():
        if len(id_ip_list) == 1:
            inst = id_ip_list[0]
            instance_list.append([inst[0], name, inst[1]])
        else:
            for id, ip in id_ip_list:
                instance_list.append([id, name + CONCAT_CHAR + ip.split('.')[-1], ip])

    return instance_list


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
        filename = NAGIOS_CFG_DIR + '/' + inst[0] + '.cfg'
        with open(filename, 'w') as f:
            f.write(
                j2_env.get_template(NAGIOS_CFG_TEMPLATE).render(
                    HOSTNAME=inst[1],
                    IP=inst[2],
                    USE=USE
                )
            )


def validate():
    process = subprocess.Popen(NAGIOS_VALIDATE_CMD, shell=True, stdout=subprocess.PIPE)
    process.wait()
    return process.returncode


if __name__ == "__main__":
    args = parse_args()
    REGION = args.region

    instances = get_ec2_instances(REGION)
    purge(NAGIOS_CFG_DIR, "^i-.*\.cfg$")
    render(instances)
    if validate() == 0:
        print("Nagios config files generated and are valid!")
    exit(0)
