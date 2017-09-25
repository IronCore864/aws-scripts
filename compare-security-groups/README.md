# Compare Security Groups between Two Regions/VPCs

### Background

After you migrate your security groups from one region/VPC to another using `migrate_security_groups.py`, you want to make sure if they are exactly the same.

### Usage

Install boto3 if you haven't done so: `pip install -r requirements.txt`

Update global vars as needed. Quite straightforward so no example here.

Then `python compare_security_groups.py`

### How it works

Use boto3 to query all security groups from origin region, sort security groups and rules and ips and compare.

### Dependencies

boto3

### Release Note

v0.1    20170925    First edition.
