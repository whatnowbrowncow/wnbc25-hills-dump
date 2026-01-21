#!/usr/bin/python
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: asa_my_acl
version_added: "n/a"
author: "Anthony Gittins"
short_description: Manage access-lists on a Cisco ASA in a declaritive fashion
description:
  - This module allows you to work with access-lists on a Cisco ASA device.
extends_documentation_fragment: asa
options:
  acl_name:
    description:
      - The name of the ACL we are working on. Required.
  action:
    description:
      - The action for the ACE, either permit or deny. Default = 'permit'.
  line_num:
    description:
      - The line number of the ACL, to allow specification of where in the ACL the ACE is to be added. Required.
  src_ip:
    description:
      - The source IP address for the ACE. This must include the netmask in standard ASA netmask notation. Required.
  dst_ip:
    ddescription:
	  - The destination IP address for the ACE. This must include the netmask in standard ASA netmask notation. Required.
  protocol:
    description:
      - The protocol used in the ACE. The options match ASA available protocols. If 'ip' is selected no src/dst port can be defined. Default = 'ip'.
  src_port:
    description:
	  - The source port used in the ACE. Requires that protocol is defined, but is not 'ip'. Optional.
  dst_port:
    description:
	  - The destination port used in the ACE. Requires that protocol is defined, but is not 'ip'. Optional
  log_level:
    description:
	  - The logging level used on the ACE. Use either log level intergers [0-7] or names. Optional.
  time_range:
    description:
	  - The time-range applied to the ACE. The time-range object must already exist on the ASA. Optional.
"""

EXAMPLES = """
# Note: examples below use the following provider dict to handle
#       transport and authentication to the node.
---
vars:
  cli:
    host: "{{ inventory_hostname }}"
    username: cisco
    password: cisco
    transport: cli
    authorize: yes
    auth_pass: cisco

---
- asa_my_acl:
    acl_name: my_acl
	action: permit
	line_num: 1
	scr_ip: "192.168.1.1"
	dst_ip: "10.1.1.1"
	protocol: tcp
	dst_port: 22
    provider: "{{ cli }}"

- asa_my_acl:
    acl_name: my_acl
	action: deny
	line_num: 15
	scr_ip: "192.168.1.1"
	dst_ip: "10.1.1.1"
	protocol: udp
	src_port: 53
	dst_port: 53
    context: customer_a
    provider: "{{ cli }}"
"""

RETURN = """
updates:
  description: The set of commands that will be pushed to the remote device
  returned: always
  type: list
  sample: ['access-list ACL-OUTSIDE extended permit tcp any any eq www']
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.network.asa.asa import asa_argument_spec, check_args
from ansible.module_utils.network.asa.asa import get_config, load_config, run_commands

from ansible.module_utils.network.common.config import NetworkConfig, dumps


def get_acl_config(module):
    contents = module.params['config']
    if not contents:
        contents = get_config(module)

    filtered_config = list()
    for item in contents.split('\n'):
        if item.startswith('access-list %s ' % module.params['acl_name']):
            filtered_config.append(item)

    return NetworkConfig(indent=1, contents='\n'.join(filtered_config))

def build_ace(module):
    ace = list()
    
    #if module.params['state'] == "absent":
    #    ace.append('no access-list {acl_name} extended {action} {protocol} {src_ip} {dst_ip} eq {dst_port}'.format(**module.params))
    
    if module.params['src_port']:
        ace.append('access-list {acl_name} line {line_num} extended {action} {protocol} {src_ip} eq {src_port} {dst_ip} eq {dst_port}'.format(**module.params))
    
    else:
        ace.append('access-list {acl_name} line {line_num} extended {action} {protocol} {src_ip} {dst_ip} eq {dst_port}'.format(**module.params))
    
	return ace

    
def parse_ace(nc_instance):
    ace = nc_instance.items()
    
    return NetworkConfig(indent=1, contents=ace)
    
def main():

# Define the basic elements that are required to build an ACE as a dict
    argument_spec = dict(
        acl_name=dict(type='str'),
		action=dict(default='permit', choices=['permit', 'deny']),
        line_num=dict(type='int'),
        src_ip=dict(type='str'),
        dst_ip=dict(type='str'),
		protocol=dict(default='ip',
                      choices=[
                      'ah',
                      'eigrp',
                      'esp',
                      'gre',
                      'icmp',
                      'icmp6',
                      'igmp',
                      'igrp',
                      'ip,'
                      'ipinip',
                      'ipsec',
                      'nos',
                      # Objects need sorting so that the object name can be passed in
                      #'object',
                      #'object-group',
                      'ospf',
                      'pcp',
                      'pim',
                      'pptp',
                      'sctp',
                      'snp',
                      'tcp',
                      'udp']),
		src_port=dict(type='str'),
		dst_port=dict(type='str'),
        log_level=dict(type='str'),
        time_range=dict(type='str'),
        state=dict(default='present', choices=['present', 'absent']),
		force=dict(default=False, type='bool'),
        config=dict()
    )


    argument_spec.update(asa_argument_spec)
	
    required_together = [['acl_name', 'line_num', 'src_ip', 'dst_ip']]
    #required_if = [('dst_ip', ]

    module = AnsibleModule(argument_spec=argument_spec,
                           required_together=required_together
                           #supports_check_mode=True
						   )

    result = {'changed': False}

    candidate = NetworkConfig(indent=1)
    candidate.add(build_ace(module))


    if not module.params['force']:
        contents = get_acl_config(module)
        config = NetworkConfig(indent=1, contents=contents)

        commands = candidate.difference(config)
        commands = dumps(commands, 'commands').split('\n')
        commands = [str(c) for c in commands if c]
    else:
        commands = str(candidate).split('\n')

    if commands:
        if not module.check_mode:
            load_config(module, commands)            

        result['changed'] = True

    result['updates'] = commands

    module.exit_json(**result)
    #module.exit_json(changed=True, argument_spec=module.params)
    #print('##################')
    #print(module)

if __name__ == '__main__':
    main()
