# Migrate Security Groups from One Region to Another

### Background

OK you are using amazon ec2.

In order to separate dev/staging/prod environments, you use different regions(or different vpcs inside the same region) for different purpose, say, eu-west-2(london) for dev, eu-west-1(ireland) for staging (or different vpc inside the same region).

After you went all the troubles to manually set up all the security groups, names, tags, rules, ip ranges, etc, you tested them, fixed issues, finally you want to move on to staging environment.

What are you gonna do, manually do the security groups again? It's such a pain in the a**.

AWS CLI doesn't provide a command to clone to another region; neither does boto.

In fact in boto2 there is a clone function but it doesn't work quite properly especially for security groups that has dependencies on others. And anyway you want to use boto3 instead of 2 because it's 3.

Even if there was a aws cli command to clone, you probably would still have some works to do, for example:

1. rename security groups. Because maybe in london your security group names are given like this: london-sg-xxx-1, but to move it to ireland, you want it to be like: ireland-sg-xxx-1

2. update ip ranges in the rules. Because maybe in london all your instances are using 10.10.*.* ip addresses, but to separate it, in ireland you want to use 10.11.*.*

Ideally, this script is meant to solve all the issues listed above.

### Usage

Install boto3 if you haven't done so: `pip install -r requirements.txt`

Update global vars as needed. Quite straightforward so no example here.

Then `python migrate_security_groups.py -h` to see usage.

Example:

`python migrate_security_groups.py --from-region eu-west-2 --from-vpc vpc-f21cc59b --replace-ip-prefix --from-ip-prefix 10.100. --replace-sg-prefix --from-sg-prefix ldn --to-region eu-west-1 --to-vpc vpc-81044be6 --to-ip-prefix 10.102. --to-sg-prefix dub`

If a security group already exists in the destination region, it won't be recreated. But if a rule is already in a group, it may throw an exception.

So the best way is to migrate it to a clean region.

### Known Issues

In between creating multiple security groups, I used sleep a bit.

Yeah I know it's ugly but for some reason if you create and use it right away there might be a chance that the group is not found.


### How it works

Use boto3 to query all security groups from origin region

Update name prefix ip addresses etc

Solve dependencies, for example one group may have a rule to allow access from/to another group

### Dependencies

boto3

### Release Note

v0.1    20170922    First edition.

v0.2    20171013    Add argparse and help.
