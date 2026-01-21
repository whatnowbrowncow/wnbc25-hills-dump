ntp
===

The purpose of this role is to understand the ntp configuration on IOS and IOSXR devices, parse that information into a JSON data structure and use it to report, document and configure ntp. This is carried out in three stages:

* parse the existing device configuration and generate a report in csv format.
* using the same parsed data, generate a YAML file to document the existing configuration.
* configure ntp on the device using variables contained in the YAML file.   

It is necessary to carry out these steps on existing devices that already contain ntp configuration, for any new devices the YAML data will need to be populated manually and only the final configuration task run. 

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

- name: Import Network Parser role
  include_role:
    name: ansible-network.network-engine

- name: IOS - NTP CSV reporting task
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: IOS - NTP YAML creation task
  include_tasks: ./ios-yaml.yml
  when: ansible_network_os == "ios"

- name: IOS - NTP config task
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

- name: IOS-XR - NTP CSV reporting task
  include_tasks: ./iosxr-report.yml
  when: ansible_network_os == "iosxr"  

- name: IOS-XR - NTP YAML creation task
  include_tasks: ./iosxr-yaml.yml
  when: ansible_network_os == "iosxr"

- name: IOS-XR - NTP config task
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"
```


Role Variables
--------------

Example Variable Structures: 

This role currently references different variable files depending on the platform, an example of a variables file for each platform is documented below:

#### IOS

Example IOS:  
`network_inventory/environments//unautomated_prod/host_vars/uk-man-rr01/ntp.yml`

```yaml
---

ntp:
    source_interface: "Loopback20"
    ntp_servers:
    - ip_addr: "10.120.163.19"
      vrf: "group-vrf"
      preferred: "prefer"
    - ip_addr: "10.120.163.20"
      vrf: "group-vrf"
      preferred: ""
```

Task: ios-config.yml makes reference to the "ntp" list above, and the values within.

#### IOS-XR

Example IOS-XR:  
`network_inventory/environments//unautomated_prod/host_vars/uk-ld6-er01/ntp.yml`

```yaml
---

ntp:
    source_interface: "MgmtEth0/RSP0/CPU0/0"
    source_vrf: "management"   
    ntp_servers:
    - ip_addr: "10.120.163.19"
      vrf: "management"
      preferred: "prefer"
    - ip_addr: "10.120.163.20"
      vrf: "management"
      preferred: ""
```

Task: iosxr-config.yml makes reference to the "ntp" list above, and the values within.

**NB.** notice that the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced. 

Command_Parser files
--------------------

#### IOS

Tasks: ios-report.yml and ios-yaml.yml use the following parser file to extract configutation data:  
`/ansible/parser_templates/ios/ntp.yml`

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml use the following parser file to extract configutation data:  
`/ansible/parser_templates/iosxr/ntp.yml`

Dependencies
------------

| **Module(s)** | **New in** | **Tested using** | **Python version tested**   | **Requirements**   |  
| ------- | ------- | ---- | --- | --- |  
| ios_config | version 2.1| version 2.8.3 | 2.7.15+  | none  |  
| iosxr_config | version 2.1| version 2.8.3 | 2.7.15+  | none  |  
| command_parser | version 2.7| version 2.8.3 | 2.7.15+  | ansible-engine-network-engine role  |   

**NB.** If the ntp.yml files have not been created prior using the YAML creation tasks, the first run of the this role will fail on the final config tasks for IOS and IOS-XR but succeed on the second run. This is because Ansible checks the files are present at the start of the playbook run, but the ntp.yml files are not created and available to Ansible until midway through the first run of the role.

#### IOS

Tasks: ios-report.yml and ios-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: ios-report.yml uses a Jinja2 template to generate a csv report containing the ntp configuration.  
    `/ansible/roles/ntp/templates/ios/csv-template.j2`

Task: ios-yaml.yml uses a Jinja2 template to generate a csv report containing the ntp configuration.  
    `/ansible/roles/ntp/templates/ios/yml-template.j2`  

Task: ios-config.yml utilises the pre-written Ansible module "ios_config":  
    <https://docs.ansible.com/ansible/latest/modules/ios_config_module.html#ios-config-module>  

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: iosxr-report.yml uses a Jinja2 template to generate a csv report containing the ntp configuration.  
    `/ansible/roles/ntp/templates/iosxr/csv-template.j2`

Task: iosxr-yaml.yml uses a Jinja2 template to generate a csv report containing the ntp configuration.  
    `/ansible/roles/ntp/templates/iosxr/yml-template.j2`  

Task: iosxr-config.yml utilises the pre-written Ansible module "iosxr_config":  
    <https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html#iosxr-config-module>

Example Playbook
----------------

Play: play_parser_ntp.yml

```yaml
- name: PLAY - Gather, report and configure NTP
  hosts: ios,iosxr
  gather_facts: no
  connection: network_cli

  roles:
    - ntp
```
WH Standard
-----------

| Status:     | Approved |
|-------------|-----------|

[NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)
[NET-STD042 - Base Build IOS-XR](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Base+Build+IOS-XR)

License
-------

BSD

Author Information
------------------

Role authors: Chris Hannan 2019.  
README authors: Chris Hannan 2019. 