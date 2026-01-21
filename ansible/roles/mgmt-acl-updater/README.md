# mgmt-acl-updater

This role can be used to update the management access-list on network devices and is a temporary workaround until the [access-list](https://git.nonprod.williamhill.plc/networks/ansible/tree/master/roles/acl "access-list role") role is utilised and in production.

Specifically:

* IOS, IOS-XR and NXOS devices can be updated to **add** new entries.

* IOS, IOS-XR, NXOS and ASA devices can be updated to **remove** entries.

## Tasks

This role consists of nine separate tasks:  

* main.yml  
* ios-config.yml
* iosxr-config.yml
* nxos-config.yml
* ios-config-deletions.yml
* iosxr-config-deletions.yml
* nxos-config-deletions.yml
* asa-single-config-deletions.yml
* asa-multiple-config-deletions.yml

_**main.yml**_ is executed first, the remaining tasks executed thereafter depends on the whether you are wanting to add or remove entries from the management access-lists and the `ansible_network_os` variable of the particular host.

>**Note**: Make sure to comment out the tasks you **do not** want to execute from _main.yml_.

#### For access-entry additions:

```yaml
---

- name: IOS - Updates (additions) to the Management ACL
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

- name: IOS-XR - Updates (additions) to the Management ACL
  include_tasks: ./iosxr-config.yml
  when: ansible_network_os == "iosxr"

- name: NXOS - Updates (additions) to the Management ACL
  include_tasks: ./nxos-config.yml
  when: ansible_network_os == "nxos"

#- name: IOS - Updates (deletions) to the Management ACL
#  include_tasks: ./ios-config-deletions.yml
#  when: ansible_network_os == "ios"
#
#- name: IOS-XR - Updates (deletions) to the Management ACL
#  include_tasks: ./iosxr-config-deletions.yml
#  when: ansible_network_os == "iosxr"
#
#- name: NXOS - Updates (deletions) to the Management ACL
#  include_tasks: ./nxos-config-deletions.yml
#  when: ansible_network_os == "nxos"
#
#- name: ASA-SINGLE - Updates (deletions) to the Management Access
#  include_tasks: ./asa-single-config-deletions.yml
#  when: ansible_network_os == "asa" and context_mode == "single"
#
#- name: ASA-MULTIPLE - Updates (deletions) to the Management Access
#  include_tasks: ./asa-multiple-config-deletions.yml
#  with_items:
#    - "{{ contexts }}"
#  loop_control:
#    loop_var: context
#  when: ansible_network_os == "asa" and context_mode == "multiple" and contexts is iterable
```

These three configuration (additions) tasks are carried out as follows:

##### IOS (ios-config.yml)

* Retrieves the name of the management access-list applied to the VTY lines.
* Gracefully ends the play for any device with no access-list configured on the VTY lines.
* Retrieves the management access-list type (Standard | Extended) applied to the VTY lines.
* Uses a Jinja2 template to generate the access-list configuration specified in _**vars/main.yml**_
* Compares the generated configuration against each device's running-configuration to check if a change needs to be made.
* If a change does need to be made, it uses the `Before` parameter to enter the access-list configuration and remove the explicit deny statement (if present).
* Uses the configuration generated from the Jinja2 template to update the access-list with the new configuration.
* Uses the `After` parameter to re-add the explicit deny statement.
* If a change has been made to the device's access-list, the final task then resequences the management access-list and saves the configuration.

##### IOS-XR (iosxr-config.yml)

> **Note** _access-list name is standardised as 'acl-management'_

* Sets the terminal length to zero.
* Retrieves the management access-list (_acl-management_).
* Gracefully ends the play for any device with no access-list configured on the VTY lines.
* Uses Regex to parse the access-list and register the sequence number of the explicit Deny statement.
* Uses a Jinja2 template to generate the access-list configuration specified in _**vars/main.yml**_
* If a change does need to be made, it uses the `Before` parameter to enter the access-list configuration and remove the explicit deny statement (if present).
* Uses the configuration generated from the Jinja2 template to update the access-list with the new configuration.
* Uses the `After` parameter to re-add the explicit deny statement.
* If a change has been made to the device's access-list, the final task then resequences the management access-list and saves the configuration.

> **Note** _The iosxr_config Ansible module commits any changes made by the module with the default commit message "configured by iosxr_config"_

##### NX-OS (nxos-config.yml)

* Retrieves the name of the management access-list applied to the VTY lines.
* Gracefully ends the play for any device with no access-list configured on the VTY lines.
* Uses a Jinja2 template to generate the access-list configuration specified in _**vars/main.yml**_
* If a change does need to be made, it uses the `Before` parameter to enter the access-list configuration and remove the explicit deny statement (if present).
* Uses the configuration generated from the Jinja2 template to update the access-list with the new configuration.
* Uses the `After` parameter to re-add the explicit deny statement.
* If a change has been made to the device's access-list, the final task then resequences the management access-list and saves the configuration.

#### For access-entry deletions:

```yaml
---

#- name: IOS - Updates (additions) to the Management ACL
#  include_tasks: ./ios-config.yml
#  when: ansible_network_os == "ios"
#
#- name: IOS-XR - Updates (additions) to the Management ACL
#  include_tasks: ./iosxr-config.yml
#  when: ansible_network_os == "iosxr"
#
#- name: NXOS - Updates (additions) to the Management ACL
#  include_tasks: ./nxos-config.yml
#  when: ansible_network_os == "nxos"
#
- name: IOS - Updates (deletions) to the Management ACL
  include_tasks: ./ios-config-deletions.yml
  when: ansible_network_os == "ios"

- name: IOS-XR - Updates (deletions) to the Management ACL
  include_tasks: ./iosxr-config-deletions.yml
  when: ansible_network_os == "iosxr"

- name: NXOS - Updates (deletions) to the Management ACL
  include_tasks: ./nxos-config-deletions.yml
  when: ansible_network_os == "nxos"

- name: ASA-SINGLE - Updates (deletions) to the Management Access
  include_tasks: ./asa-single-config-deletions.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-MULTIPLE - Updates (deletions) to the Management Access
  include_tasks: ./asa-multiple-config-deletions.yml
  with_items:
    - "{{ contexts }}"
  loop_control:
    loop_var: context
  when: ansible_network_os == "asa" and context_mode == "multiple" and contexts is iterable
```

These four configuration (deletions) tasks are carried out as follows:

##### IOS (ios-config-deletions.yml)

* Retrieves the name of the management access-list applied to the VTY lines.
* Gracefully ends the play for any device with no access-list configured on the VTY lines.
* Retrieves the management access-list configuration.
* Uses Regex to search for the access-entries to be deleted, registering the access-list sequence number for each match.
* Uses a Jinja2 template to generate and apply the configuration that will delete the sequence numbers found above in the management access-list.
* If a change has been made to a device's management access-list, the final task then resequences the access-list and saves the configuration.

##### IOS-XR (iosxr-config-deletions.yml)

* Retrieves the name of the management access-list applied to the VTY lines.
* Gracefully ends the play for any device with no access-list configured on the VTY lines.
* Retrieves the management access-list configuration.
* Uses Regex to search for the access-entries to be deleted, registering the access-list sequence number for each match.
* Uses a Jinja2 template to generate and apply the configuration that will delete the sequence numbers found above in the management access-list.
* If a change has been made to a device's management access-list, the final task then resequences the access-list and saves the configuration.

##### NXOS (nxos-config-deletions.yml)

* Retrieves the name of the management access-list applied to the VTY lines.
* Gracefully ends the play for any device with no access-list configured on the VTY lines.
* Retrieves the management access-list configuration.
* Uses Regex to search for the access-entries to be deleted, registering the access-list sequence number for each match.
* Uses a Jinja2 template to generate and apply the configuration that will delete the sequence numbers found above in the management access-list.
* If a change has been made to a device's management access-list, the final task then resequences the access-list and saves the configuration.

##### ASA Single-Context Mode (asa-single-config-deletions.yml)

* Retrieves the ssh and https (ASDM) management access configuration
* Uses Regex to search for the entries to be deleted, registering each line of management access configuration as match.
* Uses a Jinja2 template to generate and apply the configuration that will delete each line found above in the management access configuration.

##### ASA Multiple-Context Mode (asa-multiple-config-deletions.yml)

* Retrieves the ssh and https (ASDM) management access configuration
* Uses Regex to search for the entries to be deleted, registering each line of management access configuration as match.
* Uses a Jinja2 template to generate and apply the configuration that will delete each line found above in the management access configuration.

## Idempotency

#### For access-entry additions:

It should be noted that of the three config (additions) tasks listed above, only the **IOS** (_**ios-config.yml**_) task is truly idempotent. This is because the running configuration of each device is used to do a diff against the generated configuration; and only IOS devices exclude access-list sequence numbers from the running-configuration. If no change needs to be made to the management access-list of an IOS device the subsequent task to resequence the access-list will abort.

The "PLAY RECAP" for an **IOS** device would show `changed=0`. 

The **IOS-XR** (_**iosxr-config.yml**_) and **NXOS** (_**nxos-config.yml**_) config tasks will always see a difference when comparing the configuration generated from the Jinja2 templates to that of the running-configuration because of the access-list sequence numbering.

The "PLAY RECAP" for an **IOS-XR** or **NXOS** device would always show `changed=2`, one for the task to update the access-list and one for the subsequent resequence.

> **Note** _It has been found through the testing of this role that, although the **IOS-XR** and **NXOS** configuration tasks are not idempotent and will always attempt to make two changes, only the **IOS-XR** devices accept the duplicate entries in the access-list. **NXOS** appears to have logic built in that recognises the access-list entries as duplicates and does not actually apply them to the running-configuration._

#### For access-entry deletions:

For the all of the deletion tasks, Ansible will always try to apply the configuration that removes the access-entries and management access configuration. This is because the running configuration of each device is used to do a diff against the generated configuration - and the generated confguration prepends a **'no'** to each line to negate the command.

However, the modules used for these deletions (referenced below in the dependencies section) will only report a change if the applied template has actually made a change to the configuration.

## Requirements

None. (Although see **Role Variables** and **Dependencies**.)

## Role Variables

#### For access-entry additions:

The network or host you want adding to the management access-list is currently stored in the role's _vars/main.yml_ file. The config tasks will then use these variables and the Jinja2 templates to generate the required configuration.

_**vars/main.yml: (example)**_

```yaml
--- 

mgmt_acl: 
  
  remark: "example-host-and-network"
  lines:
  -
    host: "192.168.0.10"
  -
    host: ""
  -
    host: ""
  -
    network: "192.168.12.0"
    wilcard: "0.0.3.255"
    cidr: "22"
  -
    network: ""
    wilcard: ""
    cidr: ""
  -
    network: ""
    wilcard: ""
    cidr: ""
```

#### For access-entry deletions:

Each deletion tasks file includes a task that uses Regex to search for the entries to be deleted. To remove entries from management access, simply update the Regex tasks highlighted below to find the entries that you want to remove.

>**Note**: Care should be taken to ensure the regex used is specific, only captures the entries you want to remove and **does not** capture any other entries.

For **IOS**, **IOS-XR** and **NXOS**, any matches are registered as `aclMATCH`.

_**tasks/iosxr-config-deletions.yml: (example)**_

```yaml
- name: IOS-XR - Registering the sequence numbers that are to be removed
  set_fact:
    aclMATCH: "{{ mgmtACL.stdout[0] | regex_findall('((\\d+) +permit +\\S+ +host +10.120.163.143.*)') }}"
```

For **ASA (both single and multiple context modes)**, any matches are registered as either `sshACC` or `httpACC`.

_**tasks/asa-single-config-deletions.yml: (example)**_

```yaml
- name: ASA-SINGLE - Registering the configuration lines that are to be removed
  set_fact:
    sshACC: "{{ mgmtACL.stdout[0] | regex_findall('(.*10.120.163.*)') }}"
    httpACC: "{{ mgmtACL.stdout[1] | regex_findall('(.*10.120.163.*)') }}"
```

## Dependencies

| **Module(s)** | **New in** | **Tested using** | **Python version tested** | **Requirements** |  
| ------- | ------- | ---- | --- | --- |  
| ios_config | version 2.1| version 2.8.6 | 3.6.9 | none  |
| ios_command | version 2.1| version 2.8.6 | 3.6.9 | none  |
| iosxr_config | version 2.1| version 2.8.6 | 3.6.9 | none  |
| iosxr_command | version 2.1| version 2.8.6 | 3.6.9 | none  |  
| nxos_config | version 2.1| version 2.8.6 | 3.6.9 | none  |
| nxos_command | version 2.1| version 2.8.6 | 3.6.9 | none  |
| asa_config | version 2.2 | version 2.8.6 | 3.6.9 | none |
| asa_command | version 2.2 | version 2.8.6 | 3.6.9 | none |
| meta: end_host | version 2.8| version 2.8.6 | 3.6.9  | none  |

## Example Playbook

_play_role-test.yml_

```yaml
---

- name: PLAY - Add or Remove Management-Access on IOS, IOS-XR, NXOS and ASA devices
  hosts: ios,iosxr,nxos,asa
  gather_facts: no
  connection: network_cli

  roles:
    - mgmt-acl-updater
```

## WH Standard

| Status:     | Approved |
|-------------|-----------|

- [NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)
- [NET-STD042 - Base Build IOS-XR](https://conf.willhillatlas.com/display/ARCH/NET-STD042+-+Base+Build+IOS-XR)

## License

BSD

## Author Information

Role authors: Chris Hannan 2020.  
README authors: Chris Hannan 2020.