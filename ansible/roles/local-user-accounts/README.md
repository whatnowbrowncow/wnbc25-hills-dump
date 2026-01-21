local_user_accounts
===================

The purpose of this role is to understand the local user account configuration on IOS, IOS-XR, NXOS and ASA devices, parse that information into a JSON data structure and use it to report, document and configure local user accounts. This is carried out in five stages:

* parse the existing device configuration and generate a report in csv format.
* using the same parsed data generate a YAML file to document the existing configuration.
* During the first run configure local user accounts on the device using variables contained in the YAML file.  After this is all confirmed ongoing this step will be removed
* If any account on a device are required that don’t appear in the master list then a variable to contain these accounts needs to be created
* configure the defined standard accounts on the devices 
It is necessary to carry out these steps on existing devices that already contain local user configuration, for any new devices the YAML data will need to be populated manually and only the final configuration task run. 

Requirements
------------

None. (Although see dependencies.)  

Tasks
-----

This role consists of 21 separate tasks:  

asa-multiple-config.yml
asa-multiple-report.yml  
asa-multiple-standardise.yml
asa-multiple-yaml.yml  
asa-single-config.yml
asa-single-report.yml  
asa-single-standardise.yml
asa-single-yaml.yml  
ios-config.yml  
ios-report.yml  
ios-standardise.yml
ios-yaml.yml  
iosxr-config.yml 
iosxr-report.yml  
iosxr-standardise.yml
iosxr-yaml.yml  
main.yml  
nxos-config.yml  
nxos-report.yml  
nxos-standardise.yml
nxos-yaml.yml  

main.yml is executed first, the ansible-network.network-engine role containing the command_parser is imported at this stage. The task are then executed in the following order
<os>-report.yml
<os>-yaml.yml
<os>-config.yml
<os>-standardise.yml

It will execute the relevant file depending on the `ansible_network_os` variable of the particular host:

```yaml

- name: Import network parser role
  include_role:
    name: ansible-network.network-engine

- name: IOS - local user account report task
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: NXOS - local user account report task
  include_tasks: ./nxos-report.yml
  when: ansible_network_os == "nxos"

- name: IOS-XR - local user account report task
  include_tasks: ./iosxr-report.yml
  when: ansible_network_os == "iosxr"

- name: ASA MULTIPLE - local user account report task 
  include_tasks: ./asa-multiple-report.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA single - local user account report task 
  include_tasks: ./asa-single-report.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: IOS - local user account YAML creation task
  include_tasks: ./ios-yaml.yml
  when: ansible_network_os == "ios"

- name: NXOS - local user account YAML creation task
  include_tasks: ./nxos-yaml.yml
  when: ansible_network_os == "nxos"

- name: IOS-XR - local user account YAML creation task
  include_tasks: ./iosxr-yaml.yml
  when: ansible_network_os == "iosxr"

- name: ASA MULTIPLE- local user account YAML creation task
  include_tasks: ./asa-multiple-yaml.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA SINGLE- local user account YAML creation task
  include_tasks: ./asa-single-yaml.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: IOS - local user account config task
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

- name: NXOS - local user account config task
  include_tasks: ./nxos-config.yml
  when: ansible_network_os == "nxos"

- name: IOS-XR - local user account config task
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"

- name: ASA MULTIPLE - local user account config task
  include_tasks: ./asa-multiple-config.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA SINGLE - local user account config task
  include_tasks: ./asa-single-config.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: IOS - standardise local user accounts
  include_tasks: ./ios-standardise.yml
  when: ansible_network_os == "ios"

- name: NXOS - standardise local user accounts
  include_tasks: ./nxos-standardise.yml
  when: ansible_network_os == "nxos"

- name: IOS-XR - standardise local user accounts
  include_tasks: ./iosxr-standardise.yml
  when: ansible_network_os == "iosxr"

- name: ASA MULTIPLE - standardise local user accounts
  include_tasks: ./asa-multiple-standardise.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA SINGLE - standardise local user accounts
  include_tasks: ./asa-single-standardise.yml
  when: ansible_network_os == "asa" and context_mode == "single"
```

Role Variables
--------------

Example Variable Structures: 

This role currently references different variable files depending on the platform, an example of a variables file for each platform is documented below:

#### IOS

Example IOS:  
`network_inventory/environments//unautomated_prod/host_vars/uk-man-rr01/local-user-accounts.yml`

```yaml
---
local_user_accounts:
  - username: "netsec"
    privilege: "15"
    password_type: "secret"
    encryption: "5"
    password_string: "$1$Suby$oHiLEl37ytDqxkqmcfSXP."
  - username: "nessus"
    privilege: "15"
    password_type: "password"
    encryption: "7"
    password_string: "032E7F4F540E32454103110B1143215F452B38"
  - username: "netadmin"
    privilege: "15"
    password_type: "secret"
    encryption: "5"
    password_string: "$1$cwn1$xwKutIjk2mPXp6psS.BMr1"

host_local_user_accounts:
  - "user1"
  - "user2"
  - "user3"

```

```yaml

---
```

#### IOS-XR

Example IOS-XR:  
`network_inventory/environments//devnet/host_vars/devnet-sandbox-rtr1/local-user-accounts.yml`

```yaml
---
local_user_accounts:
  - username: "admin"
    password_type: "secret"
    encryption: "5"
    password_string: "$1$A4C9$oaNorr6BXDruE4gDd086L."
    user_groups:
    - name: "root-lr"
    - name: "cisco-support"
  - username: "test"
    password_type: "secret"
    encryption: "5"
    password_string: "$1$A4C9$oaNorr6BXDruEsdfasfsf"
    user_groups:
    - name: "root-lr"
    - name: "cisco-support"


host_local_user_accounts:
  - "user1"
  - "user2"
  - "user3"

```


#### NXOS

```yaml
---
local_user_accounts:
  - username: "admin"
    password: "$5$N425n4C7$CPoUpUuHI3rOcUxq2G2jZ6oEhoiYTRZSP2fF211vkU9"
    encryption: "5"
    role: "network-admin"

host_local_user_accounts:
  - "user1"
  - "user2"
  - "user3"

```

#### ASA-<Type>

```yaml
---
local_user_accounts:
  - username: "netadmin"
    privilege: "15"
    encryption: "pbkdf2"
    password_string: "$1$cwn1$xwKutIjk2mPXp6psS.BMr1"

host_local_user_accounts:
  - "user1"
  - "user2"
  - "user3"

```

Within the all.yaml in the group vars there is also 
```yaml
---

master_local_user_accounts:
  - "netadmin"
  - "netsec"
  - "pipe_test"
  - "svcnetworkauto"
```
This specifies the master account list on all devices. Then within the host vars files, on some devices, within the <device>.yml there is the following appears.

```yaml
---
host_local_user_accounts:
  - "ddsupport"
```
This specifies were accounts are needed on individual devices, for example third party support accounts

**NB.** notice that the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced. 

Command_Parser files
--------------------

#### IOS

Tasks: ios-report.yml and ios-yaml.yml use the following parser file to extract configutation data:  
`{{ role_path }}/files/parser_templates/parser_ios_local_user_accounts.yml`

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml use the following parser file to extract configutation data:  
`{{ role_path }}/files/parser_templates/parser_iosxr_local_user_accounts.yml`

#### NXOS

Tasks: nxos-report.yml and nxos-yaml.yml use the following parser file to extract configutation data:  
`{{ role_path }}/files/parser_templates/parser_nxos_local_user_accounts.yml`

#### ASA-MULTIPLE

Tasks: asa-muliple-report.yml and asa-muliple-yaml-yaml.yml use the following parser file to extract configutation data:  
`{{ role_path }}/files/parser_templates/parser_asa_multiple_local_user_accounts.yml`


#### ASA-SINGLE

Tasks: asa-single-report.yml and asa-single-yaml.yml use the following parser file to extract configutation data:  
`{{ role_path }}/files/parser_templates/parser_asa_single_local_user_accounts.yml`

Dependencies
------------

| **Module(s)** | **New in** | **Tested using** | **Python version tested**   | **Requirements**   |  
| ------- | ------- | ---- | --- | --- |  
| ios_config | version 2.1| version 2.8.3 | 3.6.9  | none  |  
| ios_command | version 2.1 | version 2.8.6 | 3.6.9 | none |
| ios_user | version 2.5 | version 2.8.6 | 3.6.9 | none |
| iosxr_config | version 2.1| version 2.8.6 | 3.6.9  | none  |  
| iosxr_command | version 2.1 | version 2.8.6 | 3.6.9 | none |
| asa_config | version 2.5 | version 2.8.6 | 3.6.9 | none |
| asa_command | version 2.2 | version 2.8.6 | 3.6.9 | none |
| nxos_config | version 2.1 | version 2.8.6 | 3.6.9 | none |
| nxos_command | version 2.1 | version 2.8.6 | 3.6.9 | none |
| command_parser | version 2.7| version 2.8.3 | 3.6.9  | ansible-engine-network-engine role  |   

#### IOS

Tasks: ios-report.yml and ios-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: ios-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/ios/csv-template.j2`

Task: ios-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/ios/yml-template.j2`  

Task: ios-config.yml utilises the pre-written Ansible module "ios_config":  
    <https://docs.ansible.com/ansible/latest/modules/ios_config_module.html#ios-config-module>  

Task: ios-standardise.yml utilises the pre-written Ansible module "iosxr_comamnd":  
    <https://docs.ansible.com/ansible/latest/modules/ios_command_module.html#ios-comamnd-module>

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: iosxr-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/iosxr/csv-template.j2`

Task: iosxr-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/iosxr/yml-template.j2`  

Task: iosxr-config.yml utilises the pre-written Ansible module "iosxr_config":  
    <https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html#iosxr-config-module>

Task: iosxr-standardise.yml utilises the pre-written Ansible module "iosxr_comamnd":  
    <https://docs.ansible.com/ansible/latest/modules/iosxr_command_module.html#iosxr-comamnd-module>

#### NXOS

Tasks: nxos-report.yml and nxos-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: nxos-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/nxos/csv-template.j2`

Task: nxos-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/nxos/yml-template.j2`  

Task: nxos-config.yml utilises the pre-written Ansible module "nxos_config":  
    <https://docs.ansible.com/ansible/latest/modules/nsox_config_module.html#nxos-config-module>

Task: nxos-standardise.yml utilises the pre-written Ansible module "nxos_command":  
    <https://docs.ansible.com/ansible/latest/modules/nsox_command_module.html#nxos-command-module>

#### ASA

Tasks: asa-multiple/single-report.yml and asa-multiple/single-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: asa-multiple/single--report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/asa-multiple/csv-template.j2`
    `/ansible/roles/local-user-accounts/templates/asa-single/csv-template.j2`
Task: asa-multiple/single-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/local-user-accounts/templates/asa-multiple/yml-template.j2`  
    `/ansible/roles/local-user-accounts/templates/asa-single/yml-template.j2`  

Task: asa-multiple/single-config.yml utilises the pre-written Ansible module "asa_config":  
    <https://docs.ansible.com/ansible/latest/modules/asa_config_module.html#asa-config-module>

Task: asa-multiple/single-standardise.yml utilises the pre-written Ansible module "asa_command":  
    <https://docs.ansible.com/ansible/latest/modules/asa_command_module.html#asa-command-module>

Example Playbook
----------------

Play: play_parser_local_user_accounts.yml

```yaml
- name: PLAY - local user account parser 
  hosts: ios,iosxr,nxos,asa
  gather_facts: no
  connection: network_cli

  roles:
    - local-user-accounts
```
WH Standard
-----------

| Status:     | Approved |
|-------------|-----------|

[NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)  
[NET-STD042 - Cisco ASA Build Standard - DRAFT](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Cisco+ASA+Build+Standard+-+DRAFT)
License
-------

BSD

Author Information
------------------

Role authors: Dave Burton 2019, Chris Stafford 2020.
README authors: Dave Burton 2019, Chris Stafford 2020.
