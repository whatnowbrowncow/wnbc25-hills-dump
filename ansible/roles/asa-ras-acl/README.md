# asa-vpn-acl

The purpose of this role is to understand and configure the objects, groups and ACL configuration on ASA RAS devices. Then parse the information into a JSON data structure and use it to report, document and then configure all RAS ASA devices at once. Production of a configuration (cfg) is also produced to allow an engineer to see the configuration that is to be deployed. The Role performs this in several stages:

**Building YML Infomation (this needs only to be ran the first time or if the ymls need matching to the device)**
1. Providing the ras_cfg fact is set to true (within the host file for the device), if this is not the case then ansible role will not run
2. Extracts the group_policy infomation using the `show run group_policy` command
3. Calls the parser_asa_single_ras_filters to extract the relevent infomation for the json varible to be used in the yml, using the information collected in step 2.
4. It then Extracts the appropriate ACL names using the same infomation.
5. Using the infomation collected in step 4, it extracts all the acl infomation from the device, using the command `show access_list <ACL> | exclude ^ `
5. Runs the infomation collected in step 5 through the parser parser_asa_single_acl_extended.yml, and places it in a json format.
6. The script then combines standard and extended acl into a single varible.
7. Taking the varible created in step 6 it runs the infomation through the templating file `yml-template.j2` to create YML files for the appropriate ACL and places them in the directory `<inventory_dir>/group_vars/ras/` under the name `<acl>.yml`

**Applying Config**
* Creates a snapshot of the current RAS and group policy infomation
* Compiles the ACL data using the ras_acl_constructor script in **/gitnet/ansible/roles/asa-ras-acl/scripts/ras_acl_constructor/ras_acl_constructor.py**
  * Confirms which ACLs have changed, and within these ACLs, that the yml and data integrity are correct.
    >**NOTE:** If this is in a release branch it highlights that the ACLs within the `release_update_acls` varible have changed, which in turn means all ACLs will be classed as changed)
  * Compiles all the ACLs together as per the hierarchy
  * Renumbers all the ACLs
  * Updates the version numbers on the relevent ACL yaml files, as per the hierarchy, unless the repo is in a release branch then this step is skipped
  * Outputs them in YAML format to the location gitnet/ras-processed/data
  * Updates the relevent yml file located within the inventory, that was passed to the script, with the new version and line numbers where applicable,unless the repo is in a release branch then this step is skipped
* Ansible then Retrieves the acl data from **/gitnet/ras-processed/data**
* Extracts the currently applied ACL names from the device group policy information.
* Confirms the ACLs that have changed, using the version number
* Check the Dependent ACL (Parent and Children) have been updated (using the version number)
* Applys the new configuration to the device
* Produces an output in the **/gitnet/ras-processed/changes/\<inventory_hostname\>_acl/\<timestamp_changes\>/\<inventory_hostname\>_acl/gp.conf** containing all the changes made.
* Performs a tidy up of data directories 
## Requirements

  * ras group to be defined within the inventory 
  * Only ACLs that have no dependencies within there hierarchy must be changed in the **/gitnet/network_inventory/\<env\>/group_vars/ras** folder
  * All ACLs must start with `ras-`
  * All python modules installed as detailed in the  **/gitnet/ansible/roles/asa-ras-acl/scripts/requirements.txt** files

## Tasks

This role consists of 4 separate tasks:  

* main.yml
* asa-ras-acl-yaml.yml
* acl-ras-version-checks.yml
* acl-ras-hierarchy-checks.yml
* pre-change-snapshot.yml
* asa-ras-acl-config.yml

**main.yml** is executed first, the ansible-network.network-engine role containing the `command_parser` is imported at this stage. Then the remaining tasks are then executed in the order above from within main.yml depending on the `ansible_network_os`, 'ras_cfg' and 'type' variable of the particular host. 

```yaml
---

# Import Network Parser Role Required for future tasks
- name: Import Network Parser role
  include_role:
    name: ansible-network.network-engine

# Call task to create Object and ACL yaml files where the deivice is a RAS device 
# (WARNING: Only run this in extreme circumstances as it will overwrite dependent data and prevent the role from running) 
- name: ASA-RAS - VPN YAML creation task
  include_tasks: asa-ras-acl-yaml.yml
  when: 
     - type == "ras"

## Identify all RAS ACLs and collate the information and places in a fact called changed_acl containing only the ACls that have changed
- name: ASA-RAS - Identifying ACLs version within YML and device
  include_tasks: acl-ras-version-checks.yml
  when: 
   - type == "ras" or type is defined
  
#This then takes each ACL defined in the changed_acl fact and extracts the names of each of the parent and child ACL confirm that they have been changed where relevent. If this check failes the whole playbook end with a error describing which ACLs are out of sync
- name: ASA-RAS - Identifying Dependent ACLs and check hierarchical changes  
  include_tasks: acl-ras-hierarchy-checks.yml
  loop: "{{ changed_acls }}" 
  loop_control:
   loop_var: loop_changed_acls
   label: "Collating Dependenct Rules for {{ loop_changed_acls }}"
  when: 
   - type == "ras" or type is defined

#This takes a snapshot of the ACLs and group policy and places in a tempory file. It is then used to compare agaist changed 
- name: ASA-RAS - Taking pre-change snapshot
  include_tasks: pre-change-snapshot.yml
  when: 
   - type == "ras" or type is defined

# Apply RAS configuration to the device where the device is a RAS device, then produces an ouput showing whats changed
- name: ASA-RAS - Apply configuration to device for RAS ACLs (CFG files if enabled)
  include_tasks: asa-ras-acl-config.yml
  when: 
   - type == "ras" or type is defined
  

```
## Role Variables

Example Variable Structures:

>**Note:** the location of the variable files are nested within a directory called ras under the group_vars folder. This is to allow multiple YAML files to be created and allow only one source of truth for all RAS VPN devices, each one of the file contain variables for a specific element of the device configuration. It is important that **ALL** RAS specific YAML files are nested in this single location otherwise they will not be referenced. 

>**Note:** This role will also cause the acl role to define the ACLs in a fact as the name of the ACL rather than **access_lists**. The relevent should have been defined in ras.yml under group_vars/ras. It will also extracts the vpn filters and place them under **ra_vpn_filters_\<acl\>:** rather than extracting the access group config. This is becuase of the configuration of the **type == ras** and the **ra_vpn_cfg == deploy** located in the **\<device\>.yml** and **/roles/asa-vpn-acl/vars/main.yml** respectivley.

After the playbook has finished the role calls a handler via the **  notify: "updates_exist" ** command within the deployment tasks located within the ** asa-ras-acl-config.yml ** file. These task comapre the current configration agaist the pre change snapshot and output the diffrence to a file located in ** ansible/roles/asa-ras-object/files/changes **

if the script fails the role calls a handler via the **  notify: "fail_executed" ** command. These task produce a zip file called  Ras_automation_logs.zip in the users home folder and contains all the logs from the ras-processed directory including but not limited to config, change list, ansible log, record of commit for the ansible and network_inventory directories and a copy of the /gitnet/network_inventory directory**. It then posts a message to the user says it has failed

### RAS VPN Group Vars structure example
```
📦gitnet
 ┣ 📂network_inventory
 ┃ ┣ 📂enviroments     
 ┃ ┃ ┣ 📂prod
 ┃ ┃ ┃ ┣ 📂group_vars
 ┃ ┃ ┃ ┃ ┣ 📂ras
 ┃ ┃ ┃ ┃ ┃ ┣ 📜<acl>.yml
 ┃ ┃ ┃ ┃ ┃ ┣ ...

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

### \<acl\>.yml
```yaml
---
ra_vpn_filters_ras_itops_filter:

  - group_policy: itops_policy
    ra_vpn_filter: ras-itops-filter
    split_tunnel_filter: itops-split-acl
    
ras_itops_filter:

  - name: "ras-itops-filter"
    type: extended
    version: 1
    parents:
      - "ras-whc-filter"
    children:
      - "ras-serviceops-filter"
    rules:
    
      - line_no: "1"
        action: "permit"
        service:
          name: "ip"
          type: protocol
        source:
          name: "ras-sc1-pool"
          type: net_obj_grp
        destination:
          name: "10.120.146.115"
          type: host
        logging:
          level: "informational"
          interval: "300"
        status: "active"
```
## Command_Parser files

All parser file details are located within the folder that is called **parser_templates**


## Dependencies
| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements**                    |
| -------------- | ----------- | ---------------- | ------------------------- | ----------------------------------- |
| asa_config | version 2.5 | version 2.16.4 | 3.11.5 | none |


## Other Dependencies  
| **Name** | **Version** | **Requirements** |
| -------------- | ----------- | ---------------- | 
| ACL Role | N/A | Produce Configuration Files |
| WH NET Python Toolset | 1.14 | Slack Notifications <br> Log Zip File Creation |

>**Note:** On the asa-single-config.yml if the \<object type\>.yml files have not been created prior to running the config tasks, the role will fail. You will need to make sure the YMLs are created

There is a dependency for the folders **/gitnet/ras-rule-update** and **/gitnet/ras-processed**.
* **/gitnet/ras-rule-update**  contains the ras script that is used to compile the RAS acls data. Details can be found in **https://gitlab.com/williamhillplc/technical-services/networks/ras-rule-update.git**
* **/gitnet/ras-processed** is where the RAS data this role is stored as well and any cfg and change files produced 

Example Playbook
----------------
Play: play_asa_ras_acl.yml
```yaml
---

- name: PLAY - Parse, report  VPN ACL configuration
  hosts: ras
  gather_facts: yes
  connection: network_cli

  roles:
    - asa-ras-acl

```

Notes
-------
In order to reduce the amount of commits required we have added the cfg and pre/post change files to the **.gitingnore** located in ansible/roles/asa-ras-acl/.gitignore and ansible/.gitignore, an example of the configration is all follows

**ansible/.gitignore**
```bash
*post_change.conf
*_changes
*pre_change.conf
```

**ansible/roles/asa-ras-acl/.gitignore**
```bash
files/changes/*


If an error is produced while running the asa_command saying that imp is not availible then add the following to the asa_command.py file located within the module directory

>**Note** The location module directory can be found by typing ansible --version in your development enviroment
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

Author Information
------------------

**Role authors**: Chris Stafford (2020,2021,2023).  
**README authors**: Chris Stafford (2020,2021,2023).


