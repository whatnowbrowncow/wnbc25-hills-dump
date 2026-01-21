AAA
====

The purpose of this role is to understand the AAA configuration on IOS and IOSXR devices, parse that information into a JSON data structure and use it to report, document and configure AAA. This is carried out in three stages:

* parse the existing device configuration and generate a report in csv format.
* using the same parsed data, generate a YAML file to document the existing configuration (IOS only).
* configure AAA on the device using variables contained in the YAML files.   

Requirements
------------

None. (Although see dependencies.)  

Tasks
-----

This role consists of seven separate tasks:  

- main.yml  
- ios-report.yml  
- ios-yaml.yml  
- ios-config.yml | ios-config-legacy.yml | ios-config-private.yml
- iosxr-report.yml  
- iosxr-yaml.yml  
- iosxr-config.yml 

_main.yml_ is executed first and the ansible-network.network-engine role containing the command_parser is imported at this stage. Three of the remaining six tasks are then executed from within main.yml, depending on the `ansible_network_os` and `tacacs_style` variables of a particular host:


```yaml
---

- name: Import Network Parser role
  include_role:
    name: ansible-network.network-engine

- name: IOS - AAA CSV reporting task
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: IOS - AAA YAML creation task
  include_tasks: ./ios-yaml.yml
  when: ansible_network_os == "ios"
  
- name: IOS - AAA configuration (new-style tacacs) task
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios" and tacacs_style == "new"

- name: IOS - AAA configuration (legacy tacacs) task
  include_tasks: ./ios-config-legacy.yml
  when: ansible_network_os == "ios" and tacacs_style == "legacy"  
  
- name: IOS - AAA configuration (private tacacs) task
  include_tasks: ./ios-config-private.yml
  when: ansible_network_os == "ios" and tacacs_style == "private"  

- name: IOS-XR - AAA CSV reporting task
  include_tasks: ./iosxr-report.yml
  when: ansible_network_os == "iosxr"  

- name: IOS-XR - AAA configuration task
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"

```
*_The ios-config task executed on a host is determined by the TACACS+ configuration style for that particular host (New | Legacy | Private), which is a host variable collected during the ios-yaml.yml task._

Role Variables
--------------

Example Variable Structures: 

This role currently references different variable files depending on the platform, an example of the variable files for each platform is documented below:

#### IOS | IOS-XR Group Variables
**All hosts** will inherit the _aaa_all_ variables from _all.yml_. These variables define:

- The TACACS+ servers (hostnames and IP addresses).
- The TACACS+ server authentication key (encrypted using Ansible vault).
- The name of the TACACS+ server group, which will group the above TACACS+ servers.

Example aaa_all variables in all.yml:  
`network_inventory/environments//unautomated_prod/group_vars/all.yml`

```yaml
---

aaa_all:
  group_name: "WH-ISE-TACACS"
  key: !vault |
          <ansible-vault encrypted key>
  servers:
    - host: "uk-sc1-ise02"
      ip_addr: "10.120.194.211"
    - host: "uk-brs-ise02"
      ip_addr: "10.210.194.211"
    - host: "gi-mpl-ise01"
      ip_addr: "10.180.194.210"
```

*_Both the IOS and IOS-XR config tasks make reference to the "aaa_all" variables above._

#### IOS-XR Group Variables
**All IOS-XR hosts** will inherit the _aaa_iosxr_ variables from _iosxr.yml_. These variables define:

- The source interface, used for its source address in TACACS+ packets.
- The VRF for the source interface configuration above.
- The VRF to which the TACACS+ server group belongs to.

Example aaa_iosxr variables in iosxr.yml:  
`network_inventory/environments//unautomated_prod/group_vars/iosxr.yml`

```yaml
---

aaa_iosxr:
  source_interface: "MgmtEth0/RSP0/CPU0/0"
  source_vrf: "management"
  group_vrf: "management"
```

*_The IOS-XR config task makes reference to the "aaa_iosxr" variables above._

#### IOS Host Variables
**Each IOS host** will inherit their host-specific _aaa_ variables from their respective aaa.yml files. These variables define:

- The TACACS+ configuration style (New | Legacy | Private), used to determine which IOS config task to invoke.
- The source interface, used for its source address in TACACS+ packets.
- The VRF to which the TACACS+ server group belongs to.

Example aaa variables in aaa.yml:  
`network_inventory/environments//unautomated_prod/host_vars/it-ml2-cr01`

```yaml
---

tacacs_style: new
 
aaa:
  source_interface: "Loopback20"
  group_vrf: "group-vrf"
```

*_The IOS config tasks make reference to the "aaa" variables above. The IOS config task executed on a host is determined by the TACACS+ configuration style for that particular host (New | Legacy | Private), which is a host variable collected during the ios-yaml.yml task._

Command_Parser files
--------------------

#### IOS

Tasks: ios-report.yml and ios-yaml.yml use the following parser file to extract configuration data:  
`/ansible/parser_templates/ios/parser_ios_aaa.yml`

#### IOS-XR

Tasks: iosxr-report.yml uses the following parser file to extract configuration data:  
`/ansible/parser_templates/iosxr/parser_iosxr_aaa.yml`

Dependencies
------------

| **Module(s)** | **New in** | **Tested using** | **Python version tested**   | **Requirements**   |  
| ------- | ------- | ---- | --- | --- |  
| ios_config | version 2.1| version 2.8.6 | 2.7.15+  | none  |  
| iosxr_config | version 2.1| version 2.8.6 | 2.7.15+  | none  |  
| command_parser | version 2.7| version 2.8.6 | 2.7.15+  | ansible-engine-network-engine role  |   

**NB.** If the aaa.yml host variable files have not been created prior using the IOS YAML creation tasks, the first run of the this role will fail on the final config tasks for IOS and but succeed on the second run. This is because Ansible checks the files are present at the start of the playbook run, but the aaa.yml files are not created and available to Ansible until midway through the first run of the role.

#### IOS

Tasks: ios-report.yml and ios-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: ios-report.yml uses a Jinja2 template to generate a csv report containing the aaa configuration.  
    `/ansible/roles/aaa/templates/ios/csv-template.j2`

Task: ios-yaml.yml uses a Jinja2 template to generate a csv report containing the aaa configuration.  
    `/ansible/roles/aaa/templates/ios/yml-template.j2`  

Tasks: ios-config.yml, ios-config-legacy.yml and ios-config-private.yml utilise the pre-written Ansible module "ios_config":  
    <https://docs.ansible.com/ansible/latest/modules/ios_config_module.html#ios-config-module>  

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: iosxr-report.yml uses a Jinja2 template to generate a csv report containing the aaa configuration.  
    `/ansible/roles/aaa/templates/iosxr/csv-template.j2`

Task: iosxr-yaml.yml uses a Jinja2 template to generate a csv report containing the aaa configuration.  
    `/ansible/roles/aaa/templates/iosxr/yml-template.j2`  

Task: iosxr-config.yml utilises the pre-written Ansible module "iosxr_config":  
    <https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html#iosxr-config-module>

Example Playbook
----------------

Play: play_parser_aaa.yml

```yaml
---

- name: PLAY - Gather, report and configure AAA
  hosts: ios,iosxr
  gather_facts: no
  connection: network_cli

  roles:
    - aaa

```
WH Standard
-----------

| Status:     | Approved |
|-------------|-----------|

- [NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)
- [NET-STD042 - Base Build IOS-XR](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Base+Build+IOS-XR)

License
-------

BSD

Author Information
------------------

Role authors: Chris Hannan 2019.  
README authors: Chris Hannan 2019. 