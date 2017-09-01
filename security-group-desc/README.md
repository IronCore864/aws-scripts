# Get Description for Each Rule/Port in a Security Group

### Usage

Update global vars as needed

Example:

```
REGION = 'eu-west-2'
# only describe tcp/udp ports
FILTER = ['tcp', 'udp']
```

Install dependencies `pip install -r requirements.txt`

Then `python describe-security-group.py sg-xxxxxx`

### How it works

Use boto3 to query security group by id

### Dependencies

boto3

### Release Note

v0.1    20170901    First edition.

