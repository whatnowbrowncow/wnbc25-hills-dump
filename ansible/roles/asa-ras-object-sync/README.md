# asa-ras-object-sync

The purpose of this role is to take the existing master copy of the RAS object Yaml information (located in `/gitnet/network_inventory/environments/prod/group_var/ras`) and apply it to the secondary RAS Firewall, by doing it this way it allow us to still have an RAS firewall on a previous version to failover to if something should go wrong with a deployment.

This runs in several steps as follows:

* Confirm which device is the live device
* Crete a variable containing the name of the secondary device
(NOTE: the following tasks only run on the secondary device)
* Check the object YAML file for duplicate objects
* Take a snapshot of the current configuration
* Configure the objects in the secondary device

## Requirements

A development environment build to the standard in https://conf.willhillatlas.com/display/netsec/NetAuto+-+Dev+Environment+-+Windows+WSL+and+Microsoft+VS+Code or a gitlab-runner pipeline using image `nexus-aws.dtc.prod.williamhill.plc/networks/python-netauto:1.6.1`

## Tasks

This role consists of 3 separate tasks:

* main.yml
* pre-change-snapshot.yml
* asa-ras-object-config.yml

**main.yml** is executed first, a couple of tasks run to confirm, using a dig command, which is the secondary device. It then places this value adn place it in a fact called secondary_host, then the remaining tasks are then executed, in the order above from within main.yml on the device defined in the secondary_host fact.

After the playbook has finished the role calls a handler via the **  notify: "updates_exist_obj" ** command within the deployment tasks located within the ** asa-ras-object-config.yml ** file. These task compare the current configuration against the pre change snapshot and output the difference to a file located in ** ansible/roles/asa-ras-object/files/changes **

```yaml
---
- name: ASA-RAS-SYNC - Check Which Device is Live
  shell: dig +short vpn.williamhillplc.com
  register: vpn_nslookup
  delegate_to: localhost
  check_mode: no

- name: Point to secondary
  set_fact:
    secondary_host: "{% if (vpn_nslookup.stdout.startswith('10.120') or vpn_nslookup.stdout.startswith('141.138')) %}{{ groups[lookup('vars', 'ld6_sync_group')][0] }}{% else %}{{ groups[lookup('vars', 'sc1_sync_group')][0] }}{% endif %}"
  delegate_to: localhost

#This takes a snapshot of the ACLs and group policy and places in a temporary file. It is then used to compare against changed
- name: ASA-RAS - Taking pre-change snapshot
  include_tasks: pre-change-snapshot.yml
  when:
   - type == "ras" or type is defined

# Apply RAS configuration to the device where the device is a RAS device, then produces an output showing whats changed
- name: ASA-RAS - Apply configuration to device for RAS Objects (CFG files if enabled)
  include_tasks: asa-ras-object-config.yml
  when:
   - type == "ras" or type is defined

```

## Role Variables

Example Variable Structures:

>**Note:** the location of the variable files are nested within a directory called ras under the group_vars folder. This is to allow multiple YAML files to be created and allow only one source of truth for all RAS VPN devices, each one of the file contain variables for a specific element of the device configuration. It is important that **ALL** RAS specific YAML files are nested in this single location otherwise they will not be referenced.

### RAS VPN Group Vars structure example
```
📦gitnet
 ┣ 📂network_inventory
 ┃ ┣ 📂enviroments
 ┃ ┃ ┣ 📂prod
 ┃ ┃ ┃ ┣ 📂group_vars
 ┃ ┃ ┃ ┃ ┣ 📂ras
 ┃ ┃ ┃ ┃ ┃ ┣ 📜network_objects.yml
 ┃ ┃ ┃ ┃ ┃ ┣ 📜protocol_objects.yml
 ┃ ┃ ┃ ┃ ┃ ┣ 📜svc_objects.yml
 ┃ ┃ ┃ ┃ ┃ ┣ 📜...

```

Within the roles **vars/main.yml there are several defined variable that are used within the role. These are as follows

| **variable**  | **Use** |
| -------------- | ----------- |
| ras_cfg | Identify as this device is to run RAS configuration |
| yml_dir | Defines where the RAS ACL data is located |
| role_root | Defines the root directory of all the roles |
| date | Collates and stores the current date |
| time | Collates and stores the current time |
| backup_dir | Defines the directory to store a backup of the ACLs |
| changes_dir | Defines the directory to store changes |
| pre_conf_file | Defines filename for used to store pre change data |
| post_conf_file | Defines filename for used to store post change data |
| ld6_sync_group | collates the name to work out the device entry in the inventory for LD6 RAS Firewall|
|sc1_sync_group | collates the name to work out the device entry in the inventory for SCC RAS Firewall|

### network_objects
```yaml
---

network_objects:

  host_objects:
    - name: "mngz-aq1"
      description: ""
      ip_addr: "172.21.252.47"
      type: "host"
   - name: "net-obj-nyx-P34-6"
      description: ""
      network: "10.118.25.0"
      mask: "255.255.255.0"
      type: "subnet"

  range_objects:
    - name: "obj-172.31.96.129-172.31.96.254"
      description: ""
      start: "172.31.96.129"
      end: "172.31.96.254"
      type: "range"

network_object_groups:
  - name: "Alphameric"
    objects:
      - object_name: "uscxops01ops001.aws-us-east-1.usc.williamhill.plc"
      - object_name: "uspxops01ops001.aws-us-east-1.usp.williamhill.plc"
    hosts:
      - ip_addr: "10.208.192.53"
      - ip_addr: "10.208.7.11"
      - ip_addr: "10.208.7.12"
    networks:
      - ip_addr: "172.30.5.0"
        mask: "255.255.255.0"
      - ip_addr: "172.30.16.0"
        mask: "255.255.255.0"
    group_objects:
      - group_object_name: "RFC1918-nets"
```

### protocol_objects
```yaml
---

protocol_object_groups:
  - name: "TCPUDP"
    objects:
      - object_name: "udp"
      - object_name: "tcp"
    group_objects:
```

### svc_objects
```yaml
---

service_objects:

  - name: "infoblox-vpn-1"
    description: ""
    protocol: "udp"
    direction: "destination"
    port_type: "eq"
    port: "1194"
    range_start: ""
    range_end: ""

service_object_groups:
  - name: "HTTP8080"
    protocol: "tcp"
    objects:
    services:
    port_objects:
      - port_type: "eq"
        port: "8080"
        range_start: ""
        range_end: ""
      - port_type: "eq"
        port: "www"
        range_start: ""
        range_end: ""
    group_objects:
```
## Command_Parser files

All parser file details are located within the folder that is called **parser_templates**


## Dependencies
| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements**                    |
| -------------- | ----------- | ---------------- | ------------------------- | ----------------------------------- |
| asa_config | version 2.5 | version 2.16 | 3.11.5 | none |


>**Note:** There are extra dependencies required with the role called from this role. These are listed in the relevant role readme

>**Note:** On the asa-ras-object-config.yml if the \<object type\>.yml files have not been created prior to running the config tasks, the role will fail. You will need to make sure the YMLs are created

Example Playbook
----------------
Play: play_asa_ras_acl.yml
```yaml
---

- name: PLAY - Parse, report and deploy RAS Object configuration
  hosts: ras
  gather_facts: yes
  connection: network_cli

  roles:
    - asa-ras-object

```

Notes
-------
In order to reduce the amount of commits required we have added the cfg and pre/post change files to the **.gitingnore** located in ansible/roles/asa-ras-acl/.gitignore and ansible/.gitignore, an example of the configuration is all follows

**ansible/.gitignore**
```bash
*post_change.conf
*_changes
*pre_change.conf
```

**ansible/roles/asa-ras-acl/.gitignore**
```bash
files/changes/*
files/configs/*
```
License
-------

BSD

Author Information
------------------

**Role authors**: Chris Stafford (2024).
**README authors**: Chris Stafford (2024).


