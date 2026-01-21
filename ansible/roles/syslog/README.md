Syslog
=========

The purpose of this role is to understand the syslog configuration on IOS, IOSXR, NXOS and ASA devices, parse that information into a JSON data structure and use it to report, document and configure syslog. This is carried out in three stages:

* parse the existing device configuration and generate a report in csv format.
* configure syslog on the device using variables contained in the YAML data structure.
* standardise the syslog configuration by removing reference to syslog servers that are not listed in the centralised YAML data.   

Note that the above differs from other similar roles in that it doesn't produce any yaml data, this is because the yaml data used to configure syslog is contained in the group_vars directory and the mgmt_interfaces.yml file which is created under the separate, pre-requisite mgmt_int role.

Requirements
------------

***IMPORTANT***
The iosxr_user python module has been written incorrectly and therefore change is needed in order for the iosxr-config.yml task to execute properly. The file in question is iosxr_user.py. You will need to locate this file in the relevant python directory e.g.:

/home/dbu/.local/lib/python3.6/site-packages/ansible/modules/network/iosxr/iosxr_user.py

Once you have located the correct file you need to make a change to line 657, currently the elements in the 'groups' list are defined as 'dict', they need to be defined as 'str'

default line:

```python
        groups=dict(type='list', elements='dict'),
```  

changed line:

```python
        groups=dict(type='list', elements='str'),
```

Tasks
-----

This role consists of fifteen separate tasks:  

main.yml
ios-report.yml  
ios-config.yml
ios-standardise.yml  
iosxr-report.yml  
iosxr-config.yml
iosxr-standardise.yml  
nxos-report.yml  
nxos-config.yml
nxos-standardise.yml    
asa-single-report.yml  
asa-single-config.yml
asa-multiple-context.yml
asa-multiple-report.yml  
asa-multiple-config.yml  

***IMPORTANT***
This role also imports tasks from the contexts role in order to target the active ASA unit for multi context firewalls, more information on these tasks can be found in the README.md file for the contexts role. 

main.yml is executed first, the ansible-network.network-engine role containing the command_parser is imported at this stage. The context related tasks are then ran against any ASA firwalls included in the run and log_setup.yml is the executed to prepare the environment to write logs. Finally the remaining tasks are then only executed from within main.yml as a result of the `ansible_network_os` variable of the particular host matching:

```yaml
---
- name: Import network parser role
  include_role:
    name: ansible-network.network-engine

- name: "Interfaces - Performing logging preparation if 'log' is true"
  include_tasks: "./log_setup.yml"
  when: "log"

- name: ASA - CONTEXT - Running 'asa-contexts-yaml' task to update device contexts information
  include_role:
    name: asa-contexts
    tasks_from: asa-contexts-non-clustered.yml
  when: context_mode == "multiple" and cluster == false

- name: ASA - CONTEXT - Running 'asa-contexts-yaml' task to update device contexts information
  include_role:
    name: asa-contexts
    tasks_from: asa-contexts-clustered.yml
  when: context_mode == "multiple" and cluster == true

- name: IOS - Syslog report task
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: IOS - Syslog config standardisation task
  include_tasks: ./ios-standardise.yml
  when: ansible_network_os == "ios"

- name: IOS - Syslog config task
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

- name: IOS-XR - Syslog report task
  include_tasks: ./iosxr-report.yml
  when: ansible_network_os == "iosxr" 

- name: IOSXR - Syslog config standardisation task
  include_tasks: ./iosxr-standardise.yml
  when: ansible_network_os == "iosxr"

- name: IOS-XR - Syslog config task
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"

- name: NX-OS - Syslog report task
  include_tasks: ./nxos-report.yml
  when: ansible_network_os == "nxos"

- name: NXOS - Syslog config standardisation task
  include_tasks: ./nxos-standardise.yml
  when: ansible_network_os == "nxos"

- name: NX-OS - Syslog config task
  include_tasks: ./nxos-config.yml
  when: ansible_network_os == "nxos"

- name: ASA-SINGLE - Syslog report task
  include_tasks: ./asa-single-report.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-SINGLE - Syslog config task
  include_tasks: ./asa-single-config.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-MULTIPLE - Syslog report task
  include_tasks: ./asa-multiple-report.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA-MULTIPLE - Syslog config task
  include_tasks: ./asa-multiple-config.yml
  when: ansible_network_os == "asa" and context_mode == "multiple" and contexts.context is defined
  with_items:
    - "{{ contexts }}"
  loop_control:
    loop_var: "contexts"
```

#### Some specific notes on the standardise tasks:

At the time of writing there are standardisation tasks for IOS,IOSXR and NXOS. These tasks use parsers to understand the existing syslog servers configured on the device, if any of these IP addresses are not in the group_var YAML data they will be removed from the device. because of the way in which syslog is configured it is recomended to run the standardise tasks BEFORE running the configuration tasks. This is because the task checks the configuration for exact syntax including the vrf tag, not just the IP address. 

Consider the following configuration on a device:

_logging host 10.1.1.1_ (incorrect)
_logging host 10.1.1.1_ vrf syslog-vrf (correct)

The task will assess the first line and realising that it is incorrect will issue the following command:

_no logging host 10.1.1.1_

Unfortunately because of the way the command syntax works on Cisco devices, issuing this negated command would also remove the (correct) configuration containing the vrf tag. It is for that reason that the corresponding config task should be ran AFTER the standardise task.

#### Some specific notes on the asa config tasks:

The asa-single-config.yml and asa-multiple-config.yml tasks are unique in this role in that they don't rely solely on yaml data to build their config files, instead they use code to dynamically check the live routing table to establish the correct egress interface to use. This is done for each individual server and the result is then used as part of the config. What this means is that should a destination syslog IP change to one that is behind the Firewall in question, the Firewall will dynamically update it's config to use the correct egress interface.

The asa-multiple-config.yml task uses with_items to execute the task against each context, the {{ contexts }} variable in question is a list of contexts generated by the contexts. This role uses a parser to gather all contexts from a device and store them in contexts.yml within the relevant host_var directory. 

Role Variables
--------------

Example Variable Structures: 

This role currently references multiple variable files, the majority of syslog variables are global and contained within all.yml. Additional device specific variables are stored in host specific yaml files, an example of all.yml and a variables file for each platform is documented below:

#### Global syslog variables

Example all.yml file:

`network_inventory/environments//prod/group_vars/all.yml`

```yaml
---

syslog:  
  - ip_addr: "10.120.163.95"
  - ip_addr: "10.120.163.96"
```
Task: all config.yml tasks make reference to the "syslog" list, and the values within.

#### IOS

Example IOS:  
`network_inventory/environments//prod/host_vars/uk-wak-ar01/mgmt_interfaces.yml`

```yaml
---

mgmt_interface:
  interface: "Vlan152"
  description: "*** Wakefield - WH User ***"
  ip_addr: "10.1.152.2"
  mask: "255.255.254.0"
  vrf: ""

```

Task: ios-config.yml makes reference to the "vrf" variable.

***IMPORTANT***

At the time of writing it is the vrf variable that determines whether the 'vrf' tag is included at the end each config line to add a syslog server. The jinja2 template used to generate the config uses if logic to determine whether the vrf variable is blank or not. If it is blank then the vrf tag is left off the config, if it is not blank then the vrf tag is used followed by the value of vrf.

E.g.

vrf blank:
`vrf: "" = logging host x.x.x.x`

vrf defined:
`vrf: "group-vrf" = logging host x.x.x.x vrf group-vrf`

#### NXOS

Example IOS:  
`network_inventory/environments//prod/host_vars/uk-sc1-ds03/mgmt_interfaces.yml`

```yaml
---

mgmt_interface:
  
  interface: "mgmt0"
  description: "uk-sc1-mgmt1 fa0/7"
  ip_addr: "10.120.129.83"
  cidr: "/24"
  vrf: "management"
```

Task: nxos-config.yml makes reference to the "vrf" variable.

***IMPORTANT***

At the time of writing it is the vrf variable that determines whether the 'vrf' tag is included at the end each config line to add a syslog server. The jinja2 template used to generate the config uses if logic to determine whether the vrf variable is blank or not. If it is blank then the vrf tag is left off the config, if it is not blank then the vrf tag is used follwowed by the value of vrf.

E.g.

vrf blank:
`vrf: "" = logging server x.x.x.x`

vrf defined:
`vrf: "group-vrf" = logging server x.x.x.x use-vrf group-vrf`

#### IOS-XR

Example IOS-XR:  
`network_inventory/environments//prod/host_vars/uk-sc1-cr01/mgmt_interfaces.yml`

```yaml
---

mgmt_interface:
  
  interface: "MgmtEth0/RSP0/CPU0/0"
  description: "uk-sc1-cs01 : Gi1/1/42"
  ip_addr: "10.120.129.186"
  mask: "255.255.255.0"
  vrf: "management"
```

Task: iosxr-config.yml makes reference to the "vrf", "interface" variables.

#### ASA_MULTIPLE

Example ASA_MULTIPLE:  
`network_inventory/environments//prod/host_vars/uk-ld6-fw01-unit-1-1/contexts.yml`

```yaml
---

contexts:
  - context: "pte-n-mgt"
  - context: "dr-e-wan"
  - context: "pte-c-frontend"
  - context: "pte-c-mgt"
  - context: "pte-n-frontend"
  - context: "dr-n-frontend"
  - context: "dr-c-frontend"
  - context: "pr-c-fr-cx"
  - context: "pte-c-fr-cx"
  - context: "pte-r-frontend"
  - context: "dr-c-mgmt"
  - context: "dr-n-mgmt"
  - context: "production"
  - context: "corp"
  - context: "retail"
  - context: "cde-mgmt"
```

Task: asa-multiple-config.yml makes reference to the "contexts" list using the with_items argument in order to iterate through each context when applying the syslog config.

**NB1.** notice that asa-single and asa-multiple tasks do not generate or reference any host specific syslog variables. This is because there is dynamic logic built into the config tasks which works out the correct interface to use in the configuration based on live routing information, further information on this can be found in the Tasks section above.

**NB2.** notice that the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced. 

Command_Parser files
--------------------

#### IOS

Tasks: ios-report.yml and ios-yaml.yml use the following parser file to extract configuration data:  
`/ansible/parser_templates/ios/parser_ios_syslog.yml`

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml use the following parser file to extract configuration data:  
`/ansible/parser_templates/iosxr/parser_iosxr_syslog.yml`

#### NXOS

Tasks: nxos-report.yml and nxos-yaml.yml use the following parser file to extract configuration data:  
`/ansible/parser_templates/nxos/parser_nxos_syslog.yml`

#### ASA-SINGLE

Tasks: asa_single-report.yml and asa-single-yaml.yml use the following parser file to extract configuration data:  
`/ansible/parser_templates/asa_single/parser_asa_single_syslog.yml`

#### ASA-MULTIPLE

Tasks: asa-multiple-report.yml and asa-multiple-yaml.yml use the following parser file to extract configuration data:  
`/ansible/parser_templates/asa_multiple/parser_asa_multiple_syslog.yml`

Handlers
--------------------

This role uses handlers to log the configuration changes that are made to the ASA devices (development is required to do the same for IOS, IOSXR and NXOS devices), the handlers are defined in the following location:
`/ansible/roles/syslog/handlers/main.yml`

```yaml
---

- name: "ASA MULTIPLE LOG WRITE - Logging changes to disk"
  block:
    - name: "LOG WRITE - Printing updates written to device to stdout"
      listen: "asa multiple updates exist"
      debug:
        msg: 
        - "Updates applied to context {{ current_context }}......."
        - "{{ loggingUPDATE.updates }}"
        

    - name: "LOG WRITE - Building logging directory"
      listen: "asa multiple updates exist"
      file:
        path: "{{ LOG_PATH }}"
        state: "directory"
      changed_when: false

    - name: "LOG WRITE - Printing updates written to device to log file"
      listen: "asa multiple updates exist"
      template:
        src: "templates/sysloglog.j2"
        dest: "{{ LOG_PATH }}{{ inventory_hostname }}-{{ current_context }}.txt"
        newline_sequence: '\r\n'

  delegate_to: "localhost"

- name: "ASA SINGLE LOG WRITE - Logging changes to disk"
  block:
    - name: "LOG WRITE - Printing updates written to device to stdout"
      listen: "asa single updates exist"
      debug:
        msg: 
        - "Updates applied to {{ inventory_hostname }}......."
        - "{{ loggingUPDATE.updates }}"
        

    - name: "LOG WRITE - Building logging directory"
      listen: "asa single updates exist"
      file:
        path: "{{ LOG_PATH }}"
        state: "directory"
      changed_when: false

    - name: "LOG WRITE - Printing updates written to device to log file"
      listen: "asa single updates exist"
      template:
        src: "templates/sysloglog.j2"
        dest: "{{ LOG_PATH }}{{ inventory_hostname }}.txt"
        newline_sequence: '\r\n'

  delegate_to: "localhost"

```

Dependencies
------------

| **Module(s)** | **New in** | **Tested using** | **Python version tested**   | **Requirements**   |  
| ------- | ------- | ---- | --- | --- |  
| ios_config | version 2.1| version 2.8.3 | 3.6.8  | none  |  
| iosxr_config | version 2.1| version 2.8.3 | 3.6.8  | none  |
| nxos_config | version 2.1| version 2.8.3 | 3.6.8  | none  | 
| asa_config | version 2.1| version 2.8.3 | 3.6.8  | none  |   
| command_parser | version 2.7| version 2.8.3 | 3.6.8  | ansible-engine-network-engine role  |

This role is dependent on the following roles:

| **Role** | **State** | **platform** |
| ------- | ------- | -------- |
| asa-contexts | present | ASA |
| mgmt_int | mgmt_interfaces.yml present for host | IOS, IOS-XR, NXOS |


#### IOS

Tasks: ios-report.yml and ios-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: ios-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/ios/csv-template.j2`

Task: ios-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/ios/yml-template.j2`  

Task: ios-config.yml utilises the pre-written Ansible module "ios_config":  
    <https://docs.ansible.com/ansible/latest/modules/ios_config_module.html#ios-config-module>  

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: iosxr-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/iosxr/csv-template.j2`

Task: iosxr-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/iosxr/yml-template.j2`  

Task: iosxr-config.yml utilises the pre-written Ansible module "iosxr_config":  
    <https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html#iosxr-config-module>

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/syslog/templates/iosxr/config-template.j2`   


#### NXOS

Tasks: nxos-report.yml and nxos-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: nxos-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/nxos/csv-template.j2`

Task: nxos-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/nxos/yml-template.j2`  

Task: nxos-config.yml utilises the pre-written Ansible module "nxos_config":  
    <https://docs.ansible.com/ansible/latest/modules/nxos_config_module.html#nxos-config-module>

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/syslog/templates/nxos/config-template.j2`  

#### ASA-SINGLE

Tasks: asa-single-report.yml and asa-single-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: asa-single-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/asa-single/csv-template.j2`

Task: asa-single-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/asa-single/yml-template.j2`  

Task: asa-single-config.yml utilises the pre-written Ansible module "asa_config":  
    <https://docs.ansible.com/ansible/latest/modules/asa-single_config_module.html#asa-single-config-module>

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/syslog/templates/asa-single/config-template.j2`

#### ASA-MULTIPLE

Tasks: asa-multiple-report.yml and asa-multiple-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: asa-multiple-report.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/asa-multiple/csv-template.j2`

Task: asa-multiple-yaml.yml uses a Jinja2 template to generate a csv report containing local user account configuration.  
    `/ansible/roles/syslog/templates/asa-multiple/yml-template.j2`  

Task: asa-multiple-config.yml utilises the pre-written Ansible module "asa_config":  
    <https://docs.ansible.com/ansible/latest/modules/asa-multiple_config_module.html#asa-multiple-config-module>

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/syslog/templates/asa-multiple/config-template.j2`

Task: asa-multiple-context.yml utilises the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: asa-multiple-context.yml uses a Jinja2 template to generate a csv report containing context configuration.  
    `/ansible/roles/syslog/templates/asa-multiple/context-csv-template.j2`

Task: asa-multiple-context.yml uses a Jinja2 template to generate a YAML file containing context information.  
    `/ansible/roles/syslog/templates/asa-multiple/context-yml-template.j2`  


Example Playbook
----------------

Play: play_parser_syslog.yml

```yaml
---

- name: PLAY - Gather, report and configure syslog 
  hosts: ios,iosxr,nxos,asa
  gather_facts: no
  connection: network_cli

  roles:
    - syslog
```

WH Standard
-----------

| Status:     | Approved |
|-------------|-----------|

[NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)  
[NET-STD042 - Base Build IOS-XR](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Base+Build+IOS-XR) 

| Status:     | Draft |
|-------------|-----------| 
[NET-STD042 - Cisco ASA Build Standard - DRAFT](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Cisco+ASA+Build+Standard+-+DRAFT)  

License
-------

BSD

Author Information
------------------

Role authors: Dave Burton 2020.  
README authors: Dave Burton 2020. 