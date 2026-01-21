# snmp

The purpose of this role is to understand the snmp configuration on IOS, IOSXR, NXOS and ASA devices, parse that information into a JSON data structure and use it to report, document and configure snmp. This is carried out in three stages:

* parse the existing device configuration and generate a report in CSV format.
* using the same parsed data, generate a _host_var_ YAML file named `snmp.yml` to document the existing configuration.
* configure snmp on the device using variables contained in the _host_var_ `snmp.yml`.  

It is necessary to carry out these steps on existing devices that already contain snmp configuration, for any new devices the YAML data will need to be populated manually and only the final configuration task run.

## Requirements

None. (Although see dependencies.)  

## Tasks

This role consists of sixteen separate tasks:

* main.yml
* ios-report.yml
* ios-yaml.yml
* ios-config.yml
* iosxr-report.yml
* iosxr-yaml.yml
* iosxr-config.yml
* nxos-report.yml
* nxos-yaml.yml
* nxos-config.yml
* asa-single-report.yml
* asa-single-yaml.yml
* asa-single-config.yml
* asa-multiple-report.yml
* asa-multiple-yaml.yml
* asa-multiple-config.yml

**main.yml** is executed first, the **ansible-network.network-engine** role containing the `command_parser` is imported at this stage. Three of the remaining fifteen tasks are then executed from within main.yml depending on the `ansible_network_os` variable of the particular host:

```yaml
---

- name: Import Network Parser role
  include_role:
    name: ansible-network.network-engine

- name: IOS - SNMP CSV reporting task
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: IOS - SNMP YAML creation task
  include_tasks: ./ios-yaml.yml
  when: ansible_network_os == "ios"

- name: IOS - SNMP configuration task
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

- name: IOS-XR - SNMP CSV reporting task
  include_tasks: ./iosxr-report.yml
  when: ansible_network_os == "iosxr"  

- name: IOS-XR - SNMP YAML creation task
  include_tasks: ./iosxr-yaml.yml
  when: ansible_network_os == "iosxr"

- name: IOS-XR - SNMP configuration task
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"

- name: NX-OS - SNMP CSV reporting task
  include_tasks: ./nxos-report.yml
  when: ansible_network_os == "nxos"

- name: NX-OS - SNMP YAML creation task
  include_tasks: ./nxos-yaml.yml
  when: ansible_network_os == "nxos"

- name: NX-OS - SNMP configuration task
  include_tasks: ./nxos-config.yml
  when: ansible_network_os == "nxos"

- name: ASA-SINGLE - SNMP CSV reporting task
  include_tasks: ./asa-single-report.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-SINGLE - SNMP YAML creation task
  include_tasks: ./asa-single-yaml.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-SINGLE - SNMP configuration task
  include_tasks: ./asa-single-config.yml
  when: ansible_network_os == "asa" and context_mode == "single" 

- name: ASA-MULTIPLE - SNMP CSV reporting task
  include_tasks: ./asa-multiple-report.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA-MULTIPLE - SNMP YAML creation task
  include_tasks: ./asa-multiple-yaml.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA-MULTIPLE - SNMP configuration task
  include_tasks: ./asa-multiple-config.yml
  when: ansible_network_os == "asa" and context_mode == "multiple"
```

## Role Variables

Example Variable Structures:

This role currently references different variable files depending on the platform, an example of a variables file for each platform is documented below:

### IOS

Example snippet for IOS:
`network_inventory/environments//unautomated_prod/host_vars/uk-man-rr01/snmp.yml`

```yaml
---

snmp:
  community:
    - string: "m0squ1t0"
      access: "RO"
      access_list: "10"
    - string: "whM0n1T0r"
      access: "RO"
      access_list: "12"
```

Task: **ios-config.yml** makes reference to the "snmp" list above, and the values within.

#### IOS-XR

Example snippet for IOS-XR:
`network_inventory/environments//unautomated_prod/host_vars/uk-ld6-er01/snmp.yml`

```yaml
---

snmp:
  community:
    - string: "5wUxlDGU"
      access: "RO"
      type: "IPv4"
      access_list: "solarwinds-new"
    - string: "m0squ1t0"
      access: "RO"
      type: "IPv4"
      access_list: "acl-cacti"
```

Task: **iosxr-config.yml** makes reference to the "snmp" list above, and the values within.

#### NX-OS

Example snippet for NX-OS:
`network_inventory/environments//unautomated_prod/host_vars/gib-mpl-ds01/snmp.yml`

```yaml
---

snmp:
  community:
    - string: "wh1LLc0rp"
      role: "network-admin"
      access_list: "ncs"
    - string: "whM0n1T0r"
      role: "network-operator"
      access_list: "cacti"
```

Task: **nxos-config.yml** makes reference to the "snmp" list above, and the values within.

#### ASA (single context mode)

Example snippet for single context ASA::
`network_inventory/environments//unautomated_prod/host_vars/uk-sc1-fw04-pri/snmp.yml`

```yaml
---

snmp:
  host:
    - ip_address: "10.120.163.111"
      source_int: "group-vrf"
      community_string: "changeme"
      poll_trap: "both"
      version: "2c"
    - ip_address: "10.120.163.12"
      source_int: "group-vrf"
      community_string: "changeme"
      poll_trap: "both"
      version: "2c"
```

Task: **asa-single-config.yml** makes reference to the "snmp" list above, and the values within.

#### ASA (multiple context mode)

Example snippet for multiple context ASA::
`network_inventory/environments//unautomated_prod/host_vars/uk-ld6-lab-fw05-unit-1-1/snmp.yml`

```yaml
---

snmp:
- context: "lab-wan"
- context: "lab-production"
  host:
  - ip_address: "10.120.163.59"
    source_int: "internal-vrf"
    community_string: "m0squ1t0"
    poll_trap: "both"
    version: "2c"
  - ip_address: "10.120.136.15"
    source_int: "internal-vrf"
    community_string: "wh1LLc0rp"
    poll_trap: "both"
    version: "2c"
  - ip_address: "10.120.163.210"
    source_int: "internal-vrf"
    community_string: "n1m50ft"
    poll_trap: "both"
    version: "2c"
- context: "lab-corp"
  host:
  - ip_address: "10.120.163.59"
    source_int: "internal-vrf"
    community_string: "m0squ1t0"
    poll_trap: "both"
    version: "2c"
  - ip_address: "10.120.136.15"
    source_int: "internal-vrf"
    community_string: "wh1LLc0rp"
    poll_trap: "both"
    version: "2c"
  - ip_address: "10.120.163.210"
    source_int: "internal-vrf"
    community_string: "n1m50ft"
    poll_trap: "bo
```

>**Note:** snmp.yml for multiple-context ASAs will still list the context when no SNMP configuration is present.

Task: **asa-multiple-config.yml** makes reference to the "snmp" list above, and the values within.

**NB.** notice that the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced. 

## Command_Parser files

#### IOS

Tasks: ios-report.yml and ios-yaml.yml use the following parser file to extract configutarion data:
`/ansible/parser_templates/ios/parser_ios_snmp.yml`

#### IOS-XR

Tasks: iosxr-report.yml and iosxr-yaml.yml use the following parser file to extract configuration data:
`/ansible/parser_templates/iosxr/parser_iosxr_snmp.yml`

#### NX-OS

Tasks: nxos-report.yml and nxos-yaml.yml use the following parser file to extract configuration data:
`/ansible/parser_templates/nxos/parser_nxos_snmp.yml`

#### ASA (single context mode)

Tasks: asa-single-report.yml and asa-single-yaml.yml use the following parser file to extract configuration data:
`/ansible/parser_templates/asa_single/parser_asa_single_snmp`

#### ASA (multiple context mode)

Tasks: asa-multiple-report.yml and asa-multiple-yaml.yml use the following parser file to extract configuration data:
`/ansible/parser_templates/asa_multiple/parser_asa_multiple_snmp`

## Dependencies

| **Module(s)** | **New in** | **Tested using** | **Python version tested**   | **Requirements**   |
| ------- | ------- | ---- | --- | --- |  
| ios_command | version 2.1| version 2.8.3 | 3.6.9  | none  |
| ios_config | version 2.1| version 2.8.3 | 3.6.9  | none  |
| iosxr_command | version 2.1| version 2.8.3 | 3.6.9 | none  |
| iosxr_config | version 2.1| version 2.8.3 | 3.6.9 | none  |
| nxos_command | version 2.1| version 2.8.6 | 3.6.9  | none  |
| nxos_config | version 2.1| version 2.8.6 | 3.6.9  | none  |
| asa_command | version 2.2| version 2.8.6 | 3.6.9  | none  |
| asa_config | version 2.2| version 2.8.6 | 3.6.9  | none  |
| command_parser | version 2.7| version 2.8.3 | 3.6.9  | ansible-network.network-engine role  |

**NB.** If the snmp.yml _host_var_ YAML files have not been created prior using the YAML creation tasks, the first run of this role will fail on the final config tasks but succeed on the second run. This is because Ansible checks the files are present at the start of the playbook run, but the snmp.yml files are not created and available to Ansible until midway through the first run of the role.

#### All

* The CSV reporting and YAML creation tasks for **all** software types utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

#### IOS

* Task ios-report.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/ios/csv-template.j2`
* Task ios-yaml.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/ios/yml-template.j2`
* Tasks ios-report.yml and ios-yaml.yml utilise the pre-written Ansible module `ios_command`:
<https://docs.ansible.com/ansible/latest/modules/ios_command_module.html>  
* Task ios-config.yml utilises the pre-written Ansible module `ios_config`:  
<https://docs.ansible.com/ansible/latest/modules/ios_config_module.html>  

#### IOS-XR

* Task iosxr-report.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/iosxr/csv-template.j2`
* Task iosxr-yaml.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/iosxr/yml-template.j2`
* Tasks iosxr-report.yml and iosxr-yaml.yml utilise the pre-written Ansible module `iosxr_command`:
<https://docs.ansible.com/ansible/latest/modules/iosxr_command_module.html>  
* Task iosxr-config.yml utilises the pre-written Ansible module `iosxr_config`:  
<https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html>

#### NX-OS

* Task nxos-report.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/nxos/csv-template.j2`
* Task nxos-yaml.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/nxos/yml-template.j2`
* Tasks nxos-report.yml and nxos-yaml.yml utilise the pre-written Ansible module `nxos_command`:
<https://docs.ansible.com/ansible/latest/modules/nxos_command_module.html>  
* Task: nxos-config.yml utilises the pre-written Ansible module `nxos_config`:
<https://docs.ansible.com/ansible/latest/modules/nxos_config_module.html>

#### ASA (single context mode)

* Task asa-single-report.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/asa_single/csv-template.j2`
* Task asa-single-yaml.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/asa_single/yml-template.j2`
* Tasks asa-single-report.yml and asa-single-yaml.yml utilise the pre-written Ansible module `asa_command`:
<https://docs.ansible.com/ansible/latest/modules/asa_command_module.html>
* Task asa-single-config.yml utilises the pre-written Ansible module `asa_config`:
<https://docs.ansible.com/ansible/latest/modules/asa_config_module.html>

#### ASA (multiple context mode)

* Task asa-multiple-report.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/asa_multiple/csv-template.j2`
* Task asa-multiple-yaml.yml uses a Jinja2 template to generate a csv report containing the snmp configuration.
`/ansible/roles/snmp/templates/asa_multiple/yml-template.j2`
* Tasks asa-multiple-report.yml and asa-multiple-yaml.yml utilise the pre-written Ansible module `asa_command`:
<https://docs.ansible.com/ansible/latest/modules/asa_command_module.html>
* Task asa-multiple-config.yml utilises the pre-written Ansible module `asa_config`:
<https://docs.ansible.com/ansible/latest/modules/asa_config_module.html>

## Example Playbook

Play: play_parser_snmp.yml

```yaml
- name: PLAY - Gather, report and configure SNMP
  hosts: ios,iosxr,nxos,asa
  gather_facts: no
  connection: network_cli

  roles:
    - snmp
```

## WH Standard

| Status:     | Approved |
|-------------|-----------|

* [NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)
* [NET-STD042 - Base Build IOS-XR](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Base+Build+IOS-XR)

## License

BSD

## Author Information

Role authors: Chris Hannan 2020.
README authors: Chris Hannan 2020.
