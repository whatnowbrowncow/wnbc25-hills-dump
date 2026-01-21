# asa-ras-dst
The purpose of this role is to understand and configure the dynamic split tunnel configuration on ASA RAS devices. 
This role extracts the DST information into a JSON data structure and uses it to report, document and then configure all RAS ASA devices at once. 
The Role performs this in several stages:

**Building YML Information (this needs only to be ran the first time or if the ymls need matching to the device)**
* sets the ras_cfg fact to true
* Extract the existing DST configuration and place them in a YML appropriate file ** \<dst\>\-include ** in the **{{ inventory_dir }}/group_vars/ras ** folder.
**Applying Config**
* Extracts the Group Policy Configuration from the devices
* Compiles the DST data using the dst-validation script in **/gitnet/ansible/roles/asa-ras-dst/scripts/dst-validation.py**
  * Confirms which DSTs have changed 
  * Extracts the data from the within the yaml files.
  * Checks if there are any duplicated data within the DST list
  * Sorts the Data into Alphabetical Order and if the deployment is not being performed from a release branch, writes it back to the file in the correct order
  * Confirms that each DST is no more than 5000 characters 
  * Segregates the entries up into groups containing no more than 421 characters
  * Writes the data to a yaml file located in **gitnet/ras-processed/data/ansible-data-<dst>-include.yml** using the segregated groups, allowing ansible to process the data
* Ansible then sets the data folder to **/gitnet/ras-processed/data**
* Extracts the currently applied DST names from the device group policy information.
* Extracts the version of each of the DST configured on the devices and checks which have changed or are a new DST
* Extracts all the DST data from the yamls located in **/gitnet/ras-processed/data**
* By comparing the device version with the yaml version, identifies the DSTs that have changed
* Produces a pre-change snapshot of the DST and Group Policy Configuration
* Confirms the folder **/gitnet/ras-processed/configs** exists
* Produces the configuration to update the DST and group policy and then deploy this configuration to the device,
* Then writes this configuration into CFG files and places them in **/gitnet/ras-processed/configs** 
* Saves the configuration on the device
* Create a post configuration snapshot
* Produces an ASA configuration output of all the changes, then places the information in the file **/gitnet/ras-processed/changes/\<inventory_hostname\>_dst/\<timestamp_changes\>/\<inventory_hostname\>_/changes.conf**, detailing which DSTs have been changed,the lines it effects and a complete list of changed config
* Performs a tidy up of the /gitnet/ras-processed directory
## Requirements
  * ras group to be defined within the inventory 
  * All python modules installed as detailed in the  **/gitnet/ansible/roles/asa-ras-dst/scripts/requirements.txt** file, using `pip3 install -r ansible/roles/asa-ras-dst/scripts/requirements.txt`

## Tasks

This role consists of 4 separate tasks:  

* main.yml
* asa-ras-dst-yaml.yml
* asa-ras-dst-validation.yml
* pre-change-snapshot.yml
* asa-ras-dst-config.yml

**main.yml** is executed first, then the remaining tasks are then executed in the order above from within main.yml depending on the `ansible_network_os`, 'ras_cfg' and 'type' variable of the particular host. 

```yaml
---

# Call task to create Object and DST yaml files where the deivice is a RAS device 
# (WARNING: Only run this in extreme circumstances as it will overwrite dependent data and prevent the role from running) 
- name: ASA-RAS - VPN YAML creation task
  include_tasks: asa-ras-dst-yaml.yml
  when: 
     - type == "ras"

## Identify all RAS DSTs and collate the information and places in a fact called changed_dst containing only the ACls that have changed
- name: ASA-RAS - Identifying DSTs version within YML and device
  include_tasks: dst-ras-dst-validation.yml
  when: 
   - type == "ras" or type is defined

#This takes a snapshot of the DSTs and group policy and places in a tempory file. It is then used to compare agaist changed 
- name: ASA-RAS - Taking pre-change snapshot
  include_tasks: pre-change-snapshot.yml
  when: 
   - type == "ras" or type is defined

# Apply RAS configuration to the device where the device is a RAS device, then produces an ouput showing whats changed
- name: ASA-RAS - Apply configuration to device for RAS DSTs (CFG files if enabled)
  include_tasks: asa-ras-dst-config.yml
  when: 
   - type == "ras" or type is defined
```
## Role Variables

Example Variable Structures:

>**Note:** the location of the variable files are nested within a directory called ras under the group_vars folder. This is to allow multiple YAML files to be created and allow only one source of truth for all RAS VPN devices, each one of the file contain variables for a specific element of the device configuration. It is important that **ALL** RAS specific YAML files are nested in this single location otherwise they will not be referenced. 

After the playbook has finished the role calls a handler via the **  notify: "updates_exist" ** command within the deployment tasks located within the ** asa-ras-dst-config.yml ** file. These task compare the current configuration against the pre change snapshot and output the difference to a file located in **  gitnet/ras-processed/changes/ **

if the script fails the role calls a handler via the **  notify: "fail_executed" ** command. These task produce a zip file called  Ras_automation_logs.zip in the users home folder and contains all the logs from the ras-processed directory including but not limited to config, change list, ansible log, record of commit for the ansible and network_inventory directories and a copy of the /gitnet/network_inventory directory**. It then posts a message to the user says it has failed

### RAS VPN Group Vars structure example
```
??gitnet
 ? ??network_inventory
 ? ? ??enviroments     
 ? ? ? ??prod
 ? ? ? ? ??group_vars
 ? ? ? ? ? ??ras
 ? ? ? ? ? ? ??<dst>-include.yml
 ? ? ? ? ? ? ...
```
Within the roles **vars/main.yml there are several defined variables that are used within the role. These are as follows

| **variable**  | **Use** |
| -------------- | ----------- |
| ras_cfg | Identify as this device is to run RAS configuration |
| yml_dir | Defines where the RAS DST data is located |
| role_root | Defines the root directory of all the roles |
| wh_net_tools_path | Path to WH Network Python Toolset |
| date | Collects the Current Date |
| time | Collects the Current Time |
| backup_dir | Defines the directory to store a backup of the DSTs |
| changes_dir | Defines the directory to store changes |
| log_dir | Defines the Directory where ansible logs are stored | 
| pre_conf_file | Defines filename for used to store pre change data |
| post_conf_file | Defines filename for used to store post change data |
| config_dir | Defines the directory to store .conf files |
| config_file_dst | Defines the location and name of the .conf files for the DST configuration |
| config_file_gp | Defines the location and name of the .conf files for the group policy configuration |
| ld6_sync_group: | Defines LD6 RAS Devices |
| sc1_sync_group: | Defines SC1 RAS Devices 
| channel_id | ID Of Channel to Send Notifications to |
| slack_message | Message to Send on Slack |

### \<dst\>.yml
```yaml
---
finance-include:
    name: "finance-include"
    policy: "finance_policy"
    dst_data:
        - "21nova.com"
        - "admin.gib.casinarena.com"
        - "admin.mraffiliate.com"
        - "amazonworkspaces.com"
        - "amswh.avature.net"
        - "app.onionsack.eu"
        - "blueprintgaming.com"
        - "bo-prod-gib.yggdrasilgaming.com"
        - "casinomodule.com"
        - "custhelp.com"
        ...
    version: 1  
```
### ras.yml
```yaml

ra_dst:
  - policy: "datamgmt_policy"
    name: "alluser-include"
  - policy: "dba_policy"
    name: "alluser-include"  
  - policy: "finance_policy"
    name: "alluser-include"
  - policy: "general_user_policy"
    name: "alluser-include"
  - policy: "itops_policy"
    name: "alluser-include"
  - policy: "mars_policy"
    name: "alluser-include"
  - policy: "retail-trading-tech_policy"
    name: "alluser-include"
  - policy: "retailuser_policy"
    name: "alluser-include"
  - policy: "serviceops_policy"
    name: "alluser-include"
  - policy: "traders_policy"
    name: "alluser-include"
  - policy: "whc_policy"
    name: "alluser-include"
keep_versions: 5
```
## Dependencies
| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements**                    |
| -------------- | ----------- | ---------------- | ------------------------- | ----------------------------------- |
| asa_config | version 2.5 | version 2.16.4 | 3.11.5 | none |

## Other Dependencies  
| **Name** | **Version** | **Requirements** |
| -------------- | ----------- | ---------------- | 
| WH NET Python Toolset | 1.14 | Slack Notifications <br> Log Zip File Creation |


Example Playbook
----------------
Play: play_asa_ras_dst.yml
```yaml
---

- name: PLAY - RAS ACL Deployment
  hosts: ras
  connection: network_cli
  gather_facts: yes

  roles:
     - asa-ras-dst

```

Notes
-------
In order to reduce the amount of commits required we have added several files to the  ** .gitignore ** file located in **/gitnet/ansible/roles/asa-ras-dst/scripts/**
```bash
roles/asa-ras-dst/scripts/log/ras_dst_constructor.log
```
If an error is produced while running the asa_command saying that imp is not available, then add the following to the asa_command.py file located within the module directory

>**Note** The location module directory can be found by typing ansible --version in your development environment
```python
try:
   from importlib import import_module
except ImportError:
    import_module = __import__
    import imp
```
License
-------

BSD
---

Author Information
------------------

**Role authors**: Chris Stafford (2021).  
**README authors**: Chris Stafford (2021).
