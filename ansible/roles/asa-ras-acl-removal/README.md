# asa-ras-acl-removal

The purpose of this role is to automatically remove any unused old RAS ACL version up to a specified point (Currently 5 previous versions)

* The first step to run is to grab a pre-change snapshot of the acls before any changes are made
* The Next step is to start the clean-up process, This is done with the following tasks.
  * Collect all the deployed ACLs configured on each device
  * Collect the vpn filters (Group Policy) configuration on each device
  * Regex out all of the ACLs from the ACL configuration where it contains the word 'ras' 
  * It then calls some tasks to complete with each ACL
    * First step is to obtain the version recorded in the YML file related to the ACL it is looking at
    * It then checks the ACL YML version against the deployed ACL version on the FW, if they dont match it exits the playbook with an error message
    * The script then extracts the versions of each RAS ACL that is currently deployed on the FW and sorts them into numerical order
    * It then checks all the ACLs on the device to confirm that none of the ACLs are a greater version than what is deployed to the VPN Filter, if any are, then the playbook ends with an error message.
    * The script then loops through all the versions of each acl and adds the versions that are greater than the number of versions to keep and add them to a list
    * The last step in this section is to clear the working variables
  * The final few steps are to confirm the configuration directory exists, create the CFG files containing the configurations to remove the relevant ACLs, then run these commands on the FW and take a post change snapshot and produce a comparison report, the final step is to clear out any temporary files

## Requirements

  * **ras** group to be defined within the inventory 
  * **keep_version** variable needs to be populated with the number of versions to keep in the  **/gitnet/network_inventory/\<env\>/group_vars/ras/ras.yml** file


## Tasks

This role consists of 4 separate tasks:  

* main.yml
* pre-change-snapshot.yml
* asa-ras-acl-cleanup.yml
* asa-complie-old-acls.yml

**main.yml** is executed first, Then the asa-ras-acl-cleanup.yml tasks is called, within this at the relevant point the asa-compile-old-acls.yml is called on each ACL. Finally the handlers are called to create the post change snapshot

```yaml
---
- name: ASA-RAS - Pre-Change Snapshot
  include_tasks: ./pre-change-snapshot.yml
  when: 
    - type is defined and type == "ras"

- name: ASA-RAS - ACL Cleanup Task
  include_tasks: ./asa-ras-acl-cleanup.yml
  when: 
    - type is defined and type == "ras"

```

## Role Variables

Example Variable Structures:

### RAS VPN Group Vars structure example
```
📦gitnet
 ┣ 📂network_inventory
 ┃ ┣ 📂environments     
 ┃ ┃ ┣ 📂prod
 ┃ ┃ ┃ ┣ 📂group_vars
 ┃ ┃ ┃ ┃ ┣ 📂ras
 ┃ ┃ ┃ ┃ ┃ ┣ 📜<acl>.yml
 ┃ ┃ ┃ ┃ ┃ ┣ 📜ras.yml

```

Within the roles **vars/main.yml there are several defined variables that are used within the role. These are as follows

| **variable**  | **Use** |
| -------------- | ----------- |
| systime | Collates and converts the current time |
| date | Stores the current date and systime variable |
| backup_dir | Defines the directory to store a backup of the ACLs |
| changes_dir | Defines the directory to store changes |
| pre_conf_file | Defines filename for used to store pre change data |
| post_conf_file | Defines filename for used to store post change data |


## Dependencies
| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements** |
| -------------- | ----------- | -------------- | ----------- | -------------- |
| asa_config | version 2.5 | version 2.8.6 | 3.6.9 | none |


## Example Playbook
----------------
Play: play_asa_ras_acl_removal.yml

```yaml
---
- name: PLAY - RAS ACL Deployment
  hosts: ras
  connection: network_cli
  gather_facts: yes

  roles:
    - asa-ras-acl-removal

```


## Notes
-------
If an error is produced while running the asa_command saying that imp is not available then add the following to the asa_command.py file located within the module directory

>**Note** The location module directory can be found by typing ansible --version in your development environment
```python
try:
   from importlib import import_module

except ImportError:
    import_module = __import__
    import imp
```


## License
-------

## BSD



## Author Information
------------------

**Role authors**: Chris Stafford (2021).  
**README authors**: Chris Stafford (2021).


