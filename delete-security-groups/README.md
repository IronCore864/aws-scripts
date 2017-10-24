# Delete All Security Groups in a VPC

### Background

Sometimes for a certain reason (testing, most probably), you need to nuke all the security groups in your VPC,

which can be such a pain, because if you have a relatively complex network setup,

chances are there are a lot of security groups that are referring to each other,

i.e., sg-1 is in the ingress/egress rules of sg-2, and vice versa.

For security reasons AWS simply doesn't allow you to delete a security group which is still being referred,

you have to delete the referring rule first.

This script does it automatically for you: removing all rules so that security groups are not referring to each other,

then delete all the groups except the default one.

Note that at the end the VPC is not deleted automatically; you have to do it yourself, which is easy for manual or cli work.

### Usage

Install boto3 if you haven't done so, just run: `pip install -r requirements.txt`

Then `python delete_security_groups.py -h` to see usage.

Example:

`python delete_security_groups.py --region eu-west-1 --vpc vpc-652a7402`

You need two non-optional parameters in order to make it work, which are of course region and vpc id.

### Dependencies

boto3

### Release Note

v0.1    20171024    First edition.
