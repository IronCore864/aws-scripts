# Generate Nagios Configigurations for all AWS EC2 Instances

### Usage

Update global vars as needed

Example:

```
REGION = 'eu-west-2'
NAGIOS_CFG_DIR = '/usr/local/nagios/etc/cfgs/hosts'
NAGIOS_CFG_TEMPLATE = 'example_host.cfg.j2'
NAGIOS_VALIDATE_CMD = '/usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg'
IGNORE_TEST_INSTANCE = True
IGNORE_NAGIOS_TAG_INSTANCE = True
```

Install dependencies `pip install -r requirements.txt`

Then `python generate-nagios-conf-for-ec2.py`

### How it works

Use boto to query all ec2 instnaces, then use jinja2 to render nagios config files.

Each time you run it, all the old config files are removed from the nagios config directory, then generate all the new confg files. Note that nagios is not automatically restarted to enable the new config files.

### Parameters

```IGNORE_TEST_INSTANCE```

If set to True, instnaces that have 'test' as part of its name tag will be ignored.

Default True.

This is useful when someone in your team wants to create an instance for testing, whose name probably contains 'test', like 'haproxy-test', and you don't want to add it into nagios because it will probably be used only for a couple of days or even hours.

```IGNORE_NAGIOS_TAG_INSTANCE```

Ignore instances with a tag 'Nagios' = 'ignore'.

Default true.

When set to true, ignore instances with a tag 'Nagios' of the value 'ignore'

This is useful when you have certain instances that you don't want to include in nagios.

If you want to include everything, just set both of the two parameters above as False.

And by default, all terminated instances are ignored, because they will disappear sooner anyway.

### Dependencies

boto, jinja2

### Release Note

v0.1    20170823    First edition.
v0.2    20170908    Rename, update template, remove reboot nagios.
v0.3    20170913    Ignore terminated instances.
v0.4    20170913    Add a parameter to ignore instance with 'test' as part of its name.

