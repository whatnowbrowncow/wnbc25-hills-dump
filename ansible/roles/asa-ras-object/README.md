# ASA RAS OBJECT YAML SCRIPT

The purpose of this role is to understand and configure the objects and groups on ASA RAS devices. Then parse the information into a JSON data structure and use it to report, document and then configure all the relevent devices at once. Production of a configuration (cfg) file can also be completed for testing purposes. The Role performs this in several stages:

**Building YML Infomation (this needs only to be ran the first time or if the ymls need matching to the device)**
* Calls the **asa-single-yaml** in the **asa-object-creator** role, parse the existing configuration and place them in a YML appropriate file (object,group) in the **\<env\>/group_var/ras ** folder.


**Applying Config**
* Run the ras-object-checks.py script in the `<role>/scripts/` folder to confirm that there are no duplicate objects defined within the yaml files, if duplicates are found them the role will fail.
* Create a snapshot of the current RAS objects and groups
* Run the ras-object-data-yaml.py script in the `<role>/scripts/` folder to create the data yaml files for changed objects and groups, with data complied into Ansible cisco asa_ogs module format
* Using a dig command workout which RAS Anyconnect is the active device
* Create config files containing the configuration to be applied to the primiary device
* Applies any new object and/or group configuration to the device
* Produces an output in the files/changes/\<inventory_hostname\>_acl/\<timestamp_changes\>/\<inventory_hostname\>_acl.conf containing all the changes made.

## Requirements

If an error is produced while running the asa_command saying that imp is not availible then add the following to the asa_command.py file located within the module directory

>**Note** The location module directory can be found by typing ansible --version in your development enviroment
```python
try:
   from importlib import import_module

except ImportError:
    import_module = __import__
    import imp
```
## Tasks

This role consists of 4 separate tasks:

* main.yml
* asa-ras-object-yaml.yml
* pre-change-snapshot.yml
* asa-ras-object-config.yml

**main.yml** is executed first, The first step of this is to, using a dig command, confirm with device is currently the primiary device and then set a fact called primary_host then add the name of the primary device in to it, using the first 2 octects of the IP address from the dig result to work ouit which one it is, after that the remaining tasks are then executed, in the order above from within main.yml depending on the `ansible_network_os` and `type` variable of the particular host.

The asa-ras-object-yaml.yml task is executed by calling the the asa-object-creator/tasks/asa-single-yaml.yml to collect the object information.

After the playbook has finished the role calls a handler via the **notify: "updates_exist"** command within the deployment tasks located within the ** asa-ras-object-config.yml ** file. These task compare the current configuration against the pre change snapshot and output the difference to a file located in ** ansible/roles/asa-ras-object/files/changes **

<details>
<summary> Main configuration </summary>

```yaml
---
- name: ASA-RAS-OBJECT - Starting Deployment of RAS Objects
  block:
    - name: ASA-RAS - Check Which Device is Live
      shell: dig +short vpn.williamhillplc.com
      register: vpn_nslookup
      check_mode: no

    - name: Point to primary:
      set_fact:
        primary_host: "{% if (vpn_nslookup.stdout.startswith('10.120') or vpn_nslookup.stdout.startswith('141.138')) %}{{ groups[lookup('vars', 'sc1_sync_group')][0] }}{% else %}{{ groups[lookup('vars', 'ld6_sync_group')][0] }}{% endif %}"


    # Import Network Parser Role Required for future tasks
    - name: Import Network Parser role
      include_role:
        name: ansible-network.network-engine

    # Call task to create Object and ACL yaml files where the deivice is a RAS device
    # - name: ASA-RAS - VPN YAML creation task
    #   include_tasks: asa-ras-object-yaml.yml
    #   when:
    #     - type == "ras"
    - name: Deploying data to device
      block:
    # Creates DATA YAMLs and updated version number, if a error occurs than this is passed to ansible and the role is stopped
        - name: ASA-RAS - Checking for Object Duplication
          shell: "python3 {{ role_path }}/scripts/ras-object-checks.py -i {{ inventory_dir }} -l info > /dev/tty"
          check_mode: no
          register: pythonoutput
          when:
            - type is defined and type == "ras" and inventory_hostname == primary_host

        #This takes a snapshot of the ACLs and group policy and places in a tempory file. It is then used to compare agaist changed
        - name: ASA-RAS - Taking pre-change snapshot
          include_tasks: pre-change-snapshot.yml
          when:
            - type is defined and type == "ras" and inventory_hostname == primary_host

        # Apply RAS configuration to the device where the device is a RAS device, then produces an ouput showing whats changed
        - name: ASA-RAS - Apply configuration to device for RAS Objects (CFG files if enabled)
          include_tasks: asa-ras-object-config.yml
          when:
            - type is defined and type == "ras" and inventory_hostname == primary_host
  rescue:
    - name: For Run of Cleanup after Failure
      shell: "echo '\e[1;32m############################################ \nStarting Failure Handling Process\n############################################ \e[0m'"
      notify: "fail_executed"
      check_mode: no
```
</details>

if the script fails the role calls a handler via the **notify: "fail_executed"** command. These task produce a zip file called  Ras_automation_logs.zip in the users home folder and contains all the logs from the ras-processed directory including but not limited to config, change list, ansible log, record of commit for the ansible and network_inventory directories and a copy of the /gitnet/network_inventory directory**. It then posts a message to the user says it has failed

## Role Variables

Example Variable Structures:

>**Note:** the location of the variable files are nested within a directory called ras under the group_vars folder. This is to allow multiple YAML files to be created and allow only one source of truth for all RAS VPN devices, each one of the file contain variables for a specific element of the device configuration. It is important that **ALL** RAS specific YAML files are nested in this single location otherwise they will not be referenced.

### RAS VPN Group Vars structure example
```
📦gitnet
 ┣ 📂network_inventory
 ┃ ┣ 📂environments
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
| wh_net_tools_path | Path to WH Network Python Toolset |
| date | Collects the Current Date |
| time | Collects the Current Time |
| backup_dir | Defines the directory to store a backup of the ACLs |
| log_dir | Defines the Directory where ansible logs are stored |
| changes_dir | Defines the directory to store changes |
| pre_conf_file | Defines filename for used to store pre change data |
| post_conf_file | Defines filename for used to store post change data |
| ld6_sync_group: | Defines LD6 RAS Devices |
| sc1_sync_group: | Defines SC1 RAS Devices
| config_file_object | Defines Object Config File name |
| channel_id | ID Of Channel to Send Notifications to |
| slack_message | Message to Send on Slack |

<details>

<summary> Example Network Object and Groups File </summary>

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
</details>

<details>
<summary> Example Protocol Object and Groups File </summary>

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

</details>

<details>
<summary> Example Service Object and Groups File </summary>

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

</details>

<details>

<summary>Example Ansible Cisco asa_orgs yaml file for network objects (Post ras-object-data-yaml.py script)</summary>

### Network Objects
```yaml
---
network_object_groups:
- name: Testing-Groups-Module-3
  object_items:
    address:
    - 192.168.192.0 255.255.255.0
  type: network
network_objects:
  fqdn_objects: {}
  host_objects: {}
  range_objects: {}
  subnet_objects: {}
```
</details>

<details>

<summary>Example Ansible Cisco asa_orgs yaml file for service objects (Post ras-object-data-yaml.py script)</summary>

### Service Objects
```yaml
---
service_object_groups:
  group_with_objects: []
  object_groups:
  - name: cs-test-service
    services_object:
    - destination_port:
        eq: '3389'
      protocol: tcp
service_objects: []
```

</details>


## Ansible Dependencies
| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements**                    |
| -------------- | ----------- | ---------------- | ------------------------- | ----------------------------------- |
| asa_config | version 2.5 | version 2.16.4 | 3.11.5 | none |

## Other Dependencies
| **Name** | **Version** | **Requirements** |
| -------------- | ----------- | ---------------- |
| Object Creator Role | N/A | Produce Configuration Files |
| WH NET Python Toolset | 1.14 | Slack Notifications <br> Log Zip File Creation |

>**Note:** On the asa-ras-object-config.yml if the \<object type\>.yml files have not been created prior to running the config tasks, the role will fail. You will need to make sure the YMLs are created

Example Playbook
----------------
Play: play_asa_ras_object.yml

<details>

```yaml
---

- name: PLAY - Parse, report and deploy RAS Object configuration
  hosts: ras
  gather_facts: yes
  connection: network_cli

  roles:
    - asa-ras-object

```
</details>

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

**Role authors**: Chris Stafford (2020,2021,2024).
**README authors**: Chris Stafford (2020,2021,2024).


