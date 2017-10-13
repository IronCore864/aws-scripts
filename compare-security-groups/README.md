# Compare Security Groups between Two Regions/VPCs

### Background

After you migrate your security groups from one region/VPC to another using `migrate_security_groups.py`, you want to make sure if they are exactly the same.

### Usage

Install boto3 if you haven't done so: `pip install -r requirements.txt`

Then `python compare_security_groups.py -h` to see usage.

Example:

`python compare_security_groups.py --from-region eu-west-2 --from-vpc vpc-f21cc59b --replace-ip-prefix --from-ip-prefix 10.100. --replace-sg-prefix --from-sg-prefix ldn --to-region eu-west-1 --to-vpc vpc-81044be6 --to-ip-prefix 10.102. --to-sg-prefix dub`

### How it works

Use boto3 to query all security groups from origin region, sort security groups and rules and ips and compare.

### Dependencies

boto3

### Release Note

v0.1    20170925    First edition.

v0.2    20171013    Add argparse and help.
