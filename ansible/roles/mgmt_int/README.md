mgmt_int
=========

The purpose of this role is to identify and understand the management interface configuration on IOS, IOSXR and NXOS devices, parse that information into a JSON data structure and use it to report, document and configure the management interface. Additionally this role will also identify any remaining loopback intefaces and process them in the same way. This is carried out in three stages:

* parse the existing device configuration and generate a report in csv format.
* using the same parsed data generate a YAML file to document the existing relevant interface configuration.
* configure a management interface and any additional loopback interfaces on the device using variables contained in the YAML data structure.

It is necessary to carry out these steps on existing devices that already contain management / loopback interface configuration, for any new devices the YAML data will need to be populated manually and only the final configuration task run.

Requirements
------------

Any pre-requisites that may not be covered by Ansible itself or the role should be mentioned here. For instance, if the role uses the EC2 module, it may be a good idea to mention in this section that the boto package is required.

Tasks
-----

This role consists of ten separate tasks:  

main.yml
ios-report.yml  
ios-yaml.yml  
ios-config.yml  
iosxr-report.yml  
iosxr-yaml.yml  
iosxr-config.yml
nxos-report.yml  
nxos-yaml.yml  
nxos-config.yml

main.yml is executed first, the ansible-network.network-engine role containing the command_parser is imported at this stage. The remaining tasks are then only executed from within main.yml as a result of the `ansible_network_os` variable of the particular host matching:

```yaml
---
- name: Import network parser role
  include_role:
    name: ansible-network.network-engine

#- name: IOS - Management interface report task
#  include_tasks: ./ios-report.yml
#  when: ansible_network_os == "ios"

- name: IOS - Management interface YAML creation task
  include_tasks: ./ios-yaml.yml
  when: ansible_network_os == "ios"

#- name: IOS - Management interface config task
#  include_tasks: ./ios-config.yml
#  when: ansible_network_os == "ios"

#- name: NXOS - Management interface report task
#  include_tasks: ./nxos-report.yml
#  when: ansible_network_os == "nxos"

- name: NXOS - Management interface YAML creation task
  include_tasks: ./nxos-yaml.yml
  when: ansible_network_os == "nxos"

#- name: NXOS - Management interface config task
#  include_tasks: ./nxos-config.yml
#  when: ansible_network_os == "nxos"
#
#- name: IOS-XR - Management interface report task
#  include_tasks: ./iosxr-report.yml
#  when: ansible_network_os == "iosxr" 
#
- name: IOS-XR - Management interface YAML creation task
  include_tasks: ./iosxr-yaml.yml
  when: ansible_network_os == "iosxr"
#
#- name: IOS-XR - Management interface config task
#  include_tasks: ./iosxr-config.yml
#  when: ansible_network_os == "iosxr"

```

Role Variables
--------------

Example Variable Structures: 

Because management and loopback interface configurations are unique to each individual device the variables for this role are found in the respective host_var directory of each device.

#### IOS

Example IOS:  
`network_inventory/environments//prod/host_vars/gib-mpl-ar01/mgmt_interfaces.yml`

```yaml
---

mgmt_interface:
  
  interface: "GigabitEthernet0"
  description: "mgmt-vrf : management : gib-vcore1 Gi1/1/3"
  ip_addr: "10.180.129.248"
  mask: "255.255.255.0"
  vrf: ""

loopback_interfaces:

  - interface: "Loopback0"
    description: "BGP Router ID"
    ip_addr: "10.92.0.12"
    mask: "255.255.255.255"
    vrf: ""

  - interface: "Loopback20"
    description: "group-vrf : management"
    ip_addr: "10.99.253.32"
    mask: "255.255.255.255"
    vrf: "group-vrf"

```

Task: ios-config.yml makes reference to the "mgmt_interface" values as well as the "loopback_interfaces" list, and the values within.

***IMPORTANT***

At the time of writing it is the vrf variables that determine whether the 'vrf' tag is included within each interface. The jinja2 template used to generate the config uses if logic to determine whether the vrf variable is blank or not. If it is blank then the vrf tag is left off the config, if it is not blank then the vrf tag is used followed by the value of vrf.

E.g.

vrf blank:
`interface xxxxxx
  description xxxxxx
  ip address x.x.x.x x.x.x.x`


syslog_vrf defined:
`interface xxxxxx
  description xxxxxx
  ip address x.x.x.x x.x.x.x
  ip vrf forwarding "vrf"`

#### IOS-XR

Example IOS-XR:  
`network_inventory/environments//prod/host_vars/uk-ld6lcr01lnew/mgmt_interfaces.yml`

```yaml
---

mgmt_interface:
  
  interface: "MgmtEth0/RSP0/CPU0/0"
  description: "uk-ld6-os01 : management : Eth1/27"
  ip_addr: "10.112.129.210"
  mask: "255.255.255.0"
  vrf: "management"

loopback_interfaces:

  - interface: "Loopback0"
    description: "default-vrf : routing : router-id"
    ip_addr: "10.92.0.38"
    mask: "255.255.255.255"
    vrf: ""

  - interface: "Loopback20"
    description: "group-vrf : management : management interface"
    ip_addr: "10.99.253.59"
    mask: "255.255.255.255"
    vrf: "group-vrf"


```

Task: iosxr-config.yml makes makes reference to the "mgmt_interface" values as well as the "loopback_interfaces" list, and the values within.

***IMPORTANT***

At the time of writing it is the vrf variables that determine whether the 'vrf' tag is included within each interface. The jinja2 template used to generate the config uses if logic to determine whether the vrf variable is blank or not. If it is blank then the vrf tag is left off the config, if it is not blank then the vrf tag is used followed by the value of vrf.

E.g.

vrf blank:
```   
interface xxxxxx   
  description xxxxxx   
  ipv4 address x.x.x.x x.x.x.x
```


syslog_vrf defined:   
```
interface xxxxxx   
  description xxxxxx   
  ipv4 address x.x.x.x x.x.x.x   
  vrf "vrf"
```

Example NXOS:  
`network_inventory/environments//prod/host_vars/uk-sc1-ds03/mgmt_interfaces.yml`

```yaml
---

mgmt_interface:
  
  interface: "mgmt0"
  description: "uk-sc1-mgmt1 fa0/7"
  ip_addr: "10.120.129.83"
  cidr: "/24"
  vrf: "management"

loopback_interfaces:

mgmt129_interface:

  interface: "mgmt0"
  description: "uk-sc1-mgmt1 fa0/7"
  ip_addr: "10.120.129.83"
  cidr: "/24"
  vrf: "management"

mgmt0_interface:

  interface: "mgmt0"
  description: "uk-sc1-mgmt1 fa0/7"
  ip_addr: "10.120.129.83"
  cidr: "/24"
  vrf: "management"

vlan99_interface:

tacacs_source_interface:

```

Task: nxos-config.yml makes reference to the "mgmt_interface" values as well as the "loopback_interfaces" list, and the values within.

***IMPORTANT***

At the time of writing it is the vrf variables that determine whether the 'vrf' tag is included within each interface. The jinja2 template used to generate the config uses if logic to determine whether the vrf variable is blank or not. If it is blank then the vrf tag is left off the config, if it is not blank then the vrf tag is used followed by the value of vrf.

E.g.

vrf blank:
`interface xxxxxx
  description xxxxxx
  ip address x.x.x.x x.x.x.x`


syslog_vrf defined:
`interface xxxxxx
  description xxxxxx
  ip address x.x.x.x x.x.x.x
  vrf member "vrf"`

**NB.** notice that the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced. 

Command_Parser files
--------------------

#### IOS

Tasks: ios-report.yml and ios-yaml.yml use the following parser files to extract configutation data:  
`/ansible/parser_templates/ios/parser_ios_mgmt_int.yml`
`/ansible/parser_templates/ios/parser_ios_loopback_int.yml`

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml use the following parser files to extract configutation data:  
`/ansible/parser_templates/iosxr/parser_iosxr_mgmt_int.yml`
`/ansible/parser_templates/iosxr/parser_iosxr_loopback_int.yml`

#### NXOS

Tasks: nxos-report.yml and nxos-yaml.yml use the following parser files to extract configutation data:  
`/ansible/parser_templates/nxos/parser_nxos_mgmt_int.yml`
`/ansible/parser_templates/nxos/parser_nxos_loopback_int.yml`

Dependencies
------------

| **Module(s)** | **New in** | **Tested using** | **Python version tested**   | **Requirements**   |  
| ------- | ------- | ---- | --- | --- |  
| ios_config | version 2.1| version 2.8.3 | 3.6.8  | none  |  
| iosxr_config | version 2.1| version 2.8.3 | 3.6.8  | none  |  
| command_parser | version 2.7| version 2.8.3 | 3.6.8  | ansible-engine-network-engine role  |  

#### IOS

Tasks: ios-report.yml and ios-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: ios-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/mgmt_int/templates/ios/csv-template.j2`

Task: ios-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/mgmt_int/templates/ios/yml-template.j2`  

Task: ios-config.yml utilises the pre-written Ansible module "ios_config":  
    <https://docs.ansible.com/ansible/latest/modules/ios_config_module.html#ios-config-module>  

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/mgmt_int/templates/ios/config-template.j2`   

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: iosxr-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/mgmt_int/templates/iosxr/csv-template.j2`

Task: iosxr-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/mgmt_int/templates/iosxr/yml-template.j2`  

Task: iosxr-config.yml utilises the pre-written Ansible module "iosxr_config":  
    <https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html#iosxr-config-module>

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/mgmt_int/templates/iosxr/config-template.j2`   

#### NXOS

Tasks: nxos-report.yml and nxos-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: nxos-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/mgmt_int/templates/nxos/csv-template.j2`

Task: nxos-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/mgmt_int/templates/nxos/yml-template.j2`  

Task: nxos-config.yml utilises the pre-written Ansible module "nxos_config":  
    <https://docs.ansible.com/ansible/latest/modules/nxos_config_module.html#nxos-config-module>

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/mgmt_int/templates/nxos/config-template.j2`   

Example Playbook
----------------

Play: play_parser_mgmt_int.yml

```yaml
- name: PLAY - local user account parser 
  hosts: ios,iosxr,nxos
  gather_facts: no
  connection: network_cli

  roles:
    - mgmt_int
```
WH Standard
-----------

| Status:     | Approved |
|-------------|-----------|

[NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)   
[NET-STD042 - Base Build IOSXR](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Base+Build+IOS-XR)   

License
-------

BSD

Author Information
------------------

Role authors: Dave Burton 2019.  
README authors: Dave Burton 2020.