# acl

The purpose of this role is to understand the access-list configuration on IOS, IOSXR, NXOS and ASA devices, parse that information into a JSON data structure and use it to report, document and configure access-lists. This is carried out in three stages:

* parse the existing device configuration and generate a report in CSV format.
* using the same parser, generate a YAML file to document the existing configuration.
* configure access-lists on the devices using variables contained in their _host_var_ YAML file.

It is necessary to carry out these steps on existing devices that already contain ACL configuration. For new devices the YAML data will need to be populated manually and only the final configuration task run.  

> **Note 1:** This role does not include the capability to parse the existing ACL config on IOS-XR devices. However ACL configuration from all IOS-XR devices in the estate has been pre-parsed into YAML format and verified. For any new devices the YAML data will need to be populated manually.  

> **Note 2:** This role does not yet include the capability to configure ASA firewalls. However it can be used to extract ACL lines into both YAML and CSV format.  

## Requirements

None. (Although see dependencies.)  

## Tasks

This role consists of 13 separate tasks:  

* main.yml
* ios-report.yml
* ios-yaml.yml
* ios-config.yml
* iosxr-report.yml
* iosxr-config.yml
* iosxr-yaml.yml
* nxos-report.yml
* nxos-yaml.yml
* nxos-config.yml
* asa-single-report.yml
* asa-single-yaml.yml
* asa-multiple-report.yml
* asa-multiple-yaml.yml

**main.yml** is executed first, the ansible-network.network-engine role containing the `command_parser` is imported at this stage. Two or three of the remaining twelve tasks are then executed from within main.yml depending on the `ansible_network_os` variable of the particular host:

```yaml
---

- name: Import Network Parser role
  include_role:
    name: ansible-network.network-engine

- name: IOS - ACL CSV reporting task
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: IOS - ACL YAML creation task
  include_tasks: ./ios-yaml.yml
  when: ansible_network_os == "ios"

- name: IOS - ACL configuration task
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

- name: IOS-XR - ACL CSV reporting task
  include_tasks: ./iosxr-report.yml
  when: ansible_network_os == "iosxr"  

- name: IOS-XR - ACL YAML creation task
  include_tasks: ./iosxr-yaml.yml
  when: ansible_network_os == "iosxr"

- name: IOS-XR - ACL configuration task
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"

- name: NX-OS - ACL CSV reporting task
  include_tasks: ./nxos-report.yml
  when: ansible_network_os == "nxos"

- name: NX-OS - ACL YAML creation task
  include_tasks: ./nxos-yaml.yml
  when: ansible_network_os == "nxos"

- name: NX-OS - ACL configuration task
  include_tasks: ./nxos-config.yml
  when: ansible_network_os == "nxos"

- name: ASA-SINGLE - ACL CSV reporting task
  include_tasks: ./asa-single-report.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-SINGLE - ACL YAML creation task
  include_tasks: ./asa-single-yaml.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-MULTIPLE -  ACL CSV reporting task
  include_tasks: ./asa-multiple-report.yml
  with_items:
    - "{{ contexts }}"
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA-MULTIPLE -  ACL YAML creation task
  include_tasks: ./asa-multiple-yaml.yml
  with_items:
    - "{{ contexts }}"
  when: ansible_network_os == "asa" and context_mode == "multiple"
```

## Role Variables

Example Variable Structures:

This role currently references different variable files depending on the platform, an example of a variables file for each platform is documented below:  
  
>**Note:** the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced.  
  
### IOS

Example IOS:
`environments/unautomated_prod/host_vars/uk-sc1-dmvpn01/acl.yml`

```yaml
access_lists:

  - name: "solarwinds-new"
    type: "Standard"
    rules:
    - line_no: "10"
      rule: "permit 10.112.12.126"
    - line_no: "20"
      rule: "permit 10.112.12.125"
 
  - name: "external"
    type: "Extended"
    rules:
    - line_no: "10"
      rule: "permit udp any any eq isakmp"
    - line_no: "20"
      rule: "permit udp any any eq non500-isakmp"
```  

Task: **ios-config.yml** makes reference to the _access_lists_ list above, and the _rules_ list nested within it. A Jinja2 template is then used to generate the required configuration.

Example IOS configuration generated using `templates/ios/config-template.j2`:

```yaml
- acl:
  name: solarwinds-new
  type: Standard
  lines:
    - 10 permit 10.112.12.126
    - 20 permit 10.112.12.125
- acl:
  name: external
  type: Extended
  lines:
    - 10 permit udp any any eq isakmp
    - 20 permit udp any any eq non500-isakmp
```

The ios-config.yml task then uses the dynamically generated configuration template above to apply the configuration.

### IOS-XR

Example IOS-XR:  
`environments/unautomated_prod/host_vars/uk-sov-cr01/acl.yml`

```yaml
access_lists:
  - name: "acl-ncs"
    rules:
    - line_no: "10"
      rule: "permit ipv4 host 10.112.12.126 any"
    - line_no: "20"
      rule: "permit ipv4 host 10.112.12.125 any"
    - line_no: "30"
      rule: "permit ipv4 host 10.120.136.140 any"
    - line_no: "40"
      rule: "permit ipv4 host 10.120.163.123 any"
    - line_no: "50"
      rule: "permit ipv4 host 10.120.163.122 any"
    - line_no: "60"
      rule: "permit ipv4 host 10.50.3.140 any"
    - line_no: "70"
      rule: "deny ipv4 any any log"
```

Task: iosxr-config.yml makes reference to the "access_lists" list above, and the "rules" list nested within.  

### NX-OS

Example NX-OS/IOSXR:
`environments/unautomated_prod/host_vars/uk-ld6-os01/acl.yml`

```yaml
---

access_lists:

  - name: "SNMP-CACTI-ACCESS"
    rules:
    - line_no: "10"
      rule: "permit udp 10.120.163.59/32 any eq snmp "
    - line_no: "15"
      rule: "permit udp 10.120.163.210/32 any eq snmp "

  - name: "SNMP-NCS-ACCESS"
    rules:
    - line_no: "10"
      rule: "permit udp 10.120.136.140/32 any eq snmp "
    - line_no: "20"
      rule: "permit udp 10.120.136.141/32 any eq snmp "
```  

Task: **nxos-config.yml** makes reference to the _access_lists_ list above, and the _rules_ list nested within it. A Jinja2 template is then used to generate the required configuration.

Example NX-OS configuration generated using `templates/nxos/config-template.j2`:

```yaml
- acl:
  name: SNMP-CACTI-ACCESS
  lines:
    - 10 permit udp 10.120.163.59/32 any eq snmp
    - 15 permit udp 10.120.163.210/32 any eq snmp
- acl:
  name: SNMP-NCS-ACCESS
  lines:
    - 10 permit udp 10.120.136.140/32 any eq snmp
    - 20 permit udp 10.120.136.141/32 any eq snmp
```

The nxos-config.yml task then uses the dynamically generated configuration template above to apply the configuration.

### ASA 

Both single and multiple context variants use the same varible structure within their acl.yml file. However the location of the acl.yml file differs depending on whether the ASA is a single or multiple context firewall. Multiple context firewalls have a sub-directory named `contexts/` in which there is a seperate directory for each context firewall.   

Example ASA (multiple context):
`environments/prod/host_vars/uk-sc1-fw01-sec/contexts/pr-c-frontend/acl.yml`

```yaml
---

access_groups:

  - interface: internal-vrf
    access_list: internal-vrf_access_in
    direction: in

access_lists:

  - name: "internal-vrf_access_in"
    type: extended
    version: 1
    rules:

    - line_no: "1"
      remark: "Deny Rule - CHG0115229"

    - line_no: "2"
      action: "deny"
      service:
        name: "ip"
        type: protocol
      source:
        name: "Corp-Wifi"
        type: net_obj_grp
      destination:
        name: "any"
        type: network
      logging:
        level: "informational"
        interval: "300"
      status: "inactive"
```  

## Command_Parser files

### IOS

Task: ios-report.yml uses the following parser file to extract configuration data:
`parser_templates/ios/parser_ios_acl.yml`

Task: ios-yaml.yml uses the following parser file to extract configuration data:
`parser_templates/ios/parser_ios_acl_yaml.yml`

>**Note:** The reason for a different parser for each task is to allow us to be more granular in the CSV task, creating columns for each attribute - but then maintain the whole access-list line as a single variable to be used in the yaml creation task.

### IOS-XR

No parser used.

### NX-OS

Task: nxos-report.yml uses the following parser file to extract configuration data:
`parser_templates/nxos/parser_nxos_acl.yml`

Task: nxos-yaml.yml uses the following parser file to extract configuration data:
`parser_templates/nxos/parser_nxos_acl_yaml.yml`

>**Note:** The reason for a different parser for each task is to allow us to be more granular in the CSV task, creating columns for each attribute - but then maintain the whole access-list line as a single variable to be used in the YAML creation task.

### ASA-SINGLE

Task: asa-single-report.yml and asa-single-yaml.yml use the following three parser files to extract configuration data to CSV and YAML format.  
`parser_templates/asa_single/parser_asa_single_acl_access_groups.yml`  
`parser_templates/asa_single/parser_asa_single_acl_extended.yml`  
`parser_templates/asa_single/parser_asa_single_acl_standard.yml`  
  
### ASA-MULTIPLE

Task: asa-multiple-report.yml and asa-multiple-yaml.yml use the following three parser files to extract configuration data to CSV and YAML format.  
`parser_templates/asa_multiple/parser_asa_multiple_acl_access_groups.yml`  
`parser_templates/asa_multiple/parser_asa_multiple_acl_extended.yml`  
`parser_templates/asa_multiple/parser_asa_multiple_acl_standard.yml`  

## Dependencies

NOTE: The Templates and some tasks within this role have a dependency within the asa-ras-object role and any changes made to the template must include testing of BOTH roles

| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements**                    |
| -------------- | ----------- | ---------------- | ------------------------- | ----------------------------------- |
| ios_command    | version 2.1 | version 2.8.3    | 3.6.8                     | none                                |
| ios_config     | version 2.1 | version 2.8.3    | 3.6.8                     | none                                |
| iosxr_command  | version 2.1 | version 2.8.3    | 3.6.8                     | none                                |
| iosxr_config   | version 2.1 | version 2.8.3    | 3.6.8                     | none                                |
| nxos_command   | version 2.1 | version 2.8.6    | 3.6.9                     | none                                |
| nxos_config    | version 2.1 | version 2.8.6    | 3.6.9                     | none                                |
| asa_command    | version 2.4 | version 2.9.2    | 3.6.9                     | none                                |
| command_parser | version 2.7 | version 2.8.6    | 3.6.9                     | ansible-network.network-engine role |

>**Note:** if the acl.yml files have not been created prior, using the YAML creation tasks, the first run of the this role will fail on the final config tasks for IOS but succeed on the second run. This is because Ansible checks the files are present at the start of the playbook run, but the acl.yml files are not created and available to Ansible until midway through the first run of the run of the role.  

### IOS

The IOS tasks utilise the below, pre-written Ansible modules:

* [ansible-network.network-engine](https://galaxy.ansible.com/ansible-network/network-engine)
* [ios_config](https://docs.ansible.com/ansible/latest/modules/ios_config_module.html)
* [ios_command](https://docs.ansible.com/ansible/latest/modules/ios_command_module.html)

**Task:** `ios-report.yml` uses a Jinja2 template to generate a csv report containing the acl configuration.
    `/ansible/roles/acl/templates/ios/csv-template.j2`

**Task:** `ios-yaml.yml` uses a Jinja2 template to generate a csv report containing the acl configuration.
    `/ansible/roles/acl/templates/ios/yml-template.j2`

**Task:** `ios-config.yml` uses a Jinja2 template to generate the acl configuration to apply.
    `/ansible/roles/acl/templates/ios/config-template.j2`

### IOS-XR

The IOS-XR tasks utilise the below, pre-written Ansible modules:

* [ansible-network.network-engine](https://galaxy.ansible.com/ansible-network/network-engine)
* [iosxr_config](https://docs.ansible.com/ansible/latest/modules/iosxr_config_module.html)
* [iosxr_command](https://docs.ansible.com/ansible/latest/modules/iosxr_command_module.html)

**Task:** `iosxr-report.yml` uses a Jinja2 template to generate a csv report containing the acl configuration.  
    `/ansible/roles/acl/templates/iosxr/csv-template.j2`

**Task:** `iosxr-config.yml` uses a Jinja2 template to generate the acl configuration to apply.
    `/ansible/roles/acl/templates/iosxr/config-template.j2`

### NX-OS

The NX-OS tasks utilise the below, pre-written Ansible modules:

* [ansible-network.network-engine](https://galaxy.ansible.com/ansible-network/network-engine)
* [nxos_config](https://docs.ansible.com/ansible/latest/modules/nxos_config_module.html)
* [nxos_command](https://docs.ansible.com/ansible/latest/modules/nxos_command_module.html)

**Task:** `nxos-report.yml` uses a Jinja2 template to generate a csv report containing the acl configuration.
    `/ansible/roles/acl/templates/nxos/csv-template.j2`

**Task:** `nxos-yaml.yml` uses a Jinja2 template to generate a csv report containing the acl configuration.
    `/ansible/roles/acl/templates/nxos/yml-template.j2`

**Task:** `nxos-config.yml` uses a Jinja2 template to generate the acl configuration to apply.
    `/ansible/roles/acl/templates/nxos/config-template.j2`

### ASA-SINGLE

The ASA-SINGLE tasks utilise the below, pre-written Ansible modules:

* [ansible-network.network-engine](https://galaxy.ansible.com/ansible-network/network-engine)
* [asa_command](https://docs.ansible.com/ansible/latest/modules/asa_command_module.html)

**Task:** `asa-single-report.yml` uses a Jinja2 template to generate a CSV report containing the acl configuration.
    `/ansible/roles/acl/templates/asa_single/csv-template.j2`

**Task:** `asa-single-yaml.yml` uses a Jinja2 template to generate a YAML data structure describing the acl configuration.
    `/ansible/roles/acl/templates/asa_single/yml-template.j2`

### ASA-MULTIPLE

The ASA-MULTIPLE tasks utilise the below, pre-written Ansible modules:

* [ansible-network.network-engine](https://galaxy.ansible.com/ansible-network/network-engine)
* [asa_command](https://docs.ansible.com/ansible/latest/modules/asa_command_module.html)

**Task:** `asa-multiple-report.yml` uses a Jinja2 template to generate a CSV report containing the acl configuration.
    `/ansible/roles/acl/templates/asa_multiple/csv-template.j2`

**Task:** `asa-multiple-yaml.yml` uses a Jinja2 template to generate a YAML data structure describing the acl configuration.
    `/ansible/roles/acl/templates/asa_multiple/yml-template.j2`

## Example Playbook

Play: play_parser_acl.yml  

```yaml
- name: PLAY - Gather, report and configure ACLs
  hosts: ios,iosxr,nxos,asa
  gather_facts: no
  connection: network_cli

  roles:
    - acl
```

## WH Standard

| Status:     | undefined |
|-------------|-----------|

## License

BSD

## Author Information

**Role authors**: Giles Falkingham (IOS-XR 2019), (ASA 2020) & Chris Hannan (IOS 2019), (NX-OS 2020), (ASA 2020).  
**README authors**: Giles Falkingham (IOS-XR 2019), (ASA 2020) & Chris Hannan (IOS 2019), (NX-OS 2020).  
