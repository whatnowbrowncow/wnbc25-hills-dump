local_user_accounts
===================

The purpose of this role is to understand the VTY configuration on IOS and IOSXR devices, parse that information into a JSON data structure and use it to report, document and configure VTY access. This is carried out in three stages:

* parse the existing device configuration and generate a report in csv format.
* using the same parsed data generate a YAML file to document the existing configuration.
* configure VTY access on the device using variables contained in the YAML file.   

It is necessary to carry out these steps on existing devices that already contain VTY configuration, for any new devices the YAML data will need to be populated manually and only the final configuration task run. 

Requirements
------------

None. (Although see dependencies.)  

Tasks
-----

This role consists of seven seperate tasks:  

main.yml  
ios-report.yml  
ios-yaml.yml  
ios-config.yml  
iosxr-report.yml  
iosxr-yaml.yml  
iosxr-config.yml 

main.yml is executed first, the ansible-network.network-engine role containing the command_parser is imported at this stage. Three of the remaining six tasks are then executed from within main.yml depending on the `ansible_network_os` variable of the particular host:

```yaml
---
- name: Import network parser role
  include_role:
    name: ansible-network.network-engine

- name: IOS - VTY report task
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: IOS - VTY YAML creation task
  include_tasks: ./ios-yaml.yml
  when: ansible_network_os == "ios"

- name: IOS - VTY config task
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

- name: IOS-XR - VTY report task
  include_tasks: ./iosxr-report.yml
  when: ansible_network_os == "iosxr" 

- name: IOS-XR - VTY YAML creation task
  include_tasks: ./iosxr-yaml.yml
  when: ansible_network_os == "iosxr"

- name: IOS-XR - VTY config task
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"
```


Role Variables
--------------

Example Variable Structures: 

This role currently references different variable files depending on the platform, an example of a variables file for each platform is documented below:

#### IOS

Example IOS:  
`network_inventory/environments//unautomated_prod/host_vars/uk-man-rr01/vty.yml`

```yaml
---
vty:
  - line_range: "0 4"
    access_class: "1"
    access_class_direction: "in"
    exec_timeout: "15 0"
    password: "1439475F0D451D3209"
    transport_input: "ssh"
    transport_output: "none"
    vrf: "vrf-also"
    logging: ""
  - line_range: "5 15"
    access_class: "1"
    access_class_direction: "in"
    exec_timeout: "15 0"
    password: "0525535B200D791034"
    transport_input: "ssh"
    transport_output: "none"
    vrf: "vrf-also"
    logging: ""
```

Task: ios-config.yml makes reference to the "vty" list, and the values within.

#### IOS-XR

Example IOS-XR:  
`network_inventory/environments//devnet/host_vars/uk-ld6-er01/vty.yml`

```yaml
---
vty:
  - line_template: "interactive-vty"
    access_class: "acl-management"
    access_class_direction: "ingress"
    exec_timeout: "15 0"
    transport_input: "ssh"
    transport_output: "telnet"
vty_pools:
  - pool_name: "default"
    line_range: "0 4"
    line_template: "interactive-vty"
  - pool_name: "extra-vtys"
    line_range: "5 15"
    line_template: "interactive-vty"
```

Task: iosxr-config.yml makes reference to the "vty" list, and the values within in order to configure a vty template. It then references the "vty_pools" list and the values within to link templates to VTY pools.

**NB.** notice that the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced. 

Command_Parser files
--------------------

#### IOS

Tasks: ios-report.yml and ios-yaml.yml use the following parser file to extract configutation data:  
`/ansible/parser_templates/ios/vty.yml`

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml use the following parser file to extract configutation data:  
`/ansible/parser_templates/iosxr/vty.yml`

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

Task: ios-report.yml uses a Jinja2 template to generate a csv report containing VTY configuration.  
    `/ansible/roles/vty/templates/ios/csv-template.j2`

Task: ios-yaml.yml uses a Jinja2 template to generate a csv report containing VTY configuration.  
    `/ansible/roles/vty/templates/ios/yml-template.j2`  

Task: ios-config.yml utilises the pre-written Ansible module "ios_config":  
    <https://docs.ansible.com/ansible/latest/modules/ios_config_module.html#ios-config-module> 

This task also uses a Jinja2 template to generate a VTY configuration file which is then applied to the device.  
    `/ansible/roles/vty/templates/ios/config-template.j2`  

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: iosxr-report.yml uses a Jinja2 template to generate a csv report containing VTY configuration.  
    `/ansible/roles/vty/templates/iosxr/csv-template.j2`

Task: iosxr-yaml.yml uses a Jinja2 template to generate a csv report containing VTY configuration.  
    `/ansible/roles/lvty/templates/iosxr/yml-template.j2`  

Task: iosxr-config.yml utilises the pre-written Ansible module "iosxr_config":  
    <https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html#iosxr-config-module>

This task also uses a Jinja2 template to generate a VTY configuration file which is then applied to the device.    
    `/ansible/roles/local-user-accounts/templates/iosxr/config-template.j2`   

Example Playbook
----------------

Play: play_parser_vty.yml

```yaml
- name: PLAY - Gather, report and configure VTY 
  hosts: ios,iosxr
  gather_facts: no
  connection: network_cli

  roles:
    - vty
```
WH Standard
-----------

| Status:     | Approved |
|-------------|-----------|

[NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)  
[NET-STD042 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Base+Build+IOS-XR) 

License
-------

BSD

Author Information
------------------

Role authors: Dave Burton 2019.  
README authors: Dave Burton 2019. 