# asa-ras-dst-removal

The purpose of this role is to automatically remove any unused old RAS DST versions, up to a specified point (Currently 5 previous versions)

* The first steps are to create any necessary folders and grab a pre-change snapshot of the DSTs before any changes are made
* The next step is to start the clean-up process, Using the data collected in the pre-change snapshot, it executes the following tasks.
  * Using the  DST entries and group policy, it collates the infomation, adds keys of `name` and `device_version` to it and then finally putting it all into a dictionary called `dst_device_info`
  * It then calls some tasks to complete with the dictionary infomation created above
    * First step is to obtain the version recorded in the YML file related to the DST it is looking at
    * It then checks the DST YML version against the deployed DST version located in the `device_version` key in the `dst_device_info` dictionary , if they dont match it exits the playbook with an error message
    * The script then extracts the versions of each RAS DST that is currently deployed on the FW, by using the infomation in the `dst_device_info` dictionary and sorts them into numerical order
    * It then checks all the DSTs to confirm that none of the DSTs are a greater version than what is in the `device_version` key , if any are, then the playbook ends with an error message.
    * The script then loops through all the versions of each DST, collating the versions that need removing, using the information in the `keep_versions` value and adds them to a list called `versions_to_remove`
    * The last step in this section is to clear the working variables
* The final few steps are to create the CFG files containing the configurations to remove the relevant DSTs, then run these commands on the FW and take a post change snapshot and produce a comparison report, the final step is to clear out any temporary files

## Requirements

  * **ras** group to be defined within the inventory 
  * **keep_versions** variable needs to be populated with the number of versions to keep in the  **/gitnet/network_inventory/\<env\>/group_vars/ras/ras.yml** file


## Tasks

This role consists of 4 separate tasks:  

* main.yml
* pre-change-snapshot.yml
* asa-ras-dst-cleanup.yml
* asa-complie-old-dsts.yml

**main.yml** is executed first, Then the asa-ras-dst-cleanup.yml tasks is called, within this at the relevant point the asa-compile-old-dsts.yml is called on each DST. Finally the handlers are called to create the post change snapshot

```yaml
---
- name: ASA-RAS - Pre-Change Snapshot
  include_tasks: ./pre-change-snapshot.yml
  when: 
    - type is defined and type == "ras"

- name: ASA-RAS - DST Cleanup Task
  include_tasks: ./asa-ras-dst-cleanup.yml
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
 ┃ ┃ ┃ ┃ ┃ ┣ 📜<DST>.yml
 ┃ ┃ ┃ ┃ ┃ ┣ 📜ras.yml

```

Within the roles **vars/main.yml there are several defined variables that are used within the role. These are as follows

| **variable**  | **Use** |
| -------------- | ----------- |
| systime | Collates and converts the current time |
| date | Stores the current date and systime variable |
| backup_dir | Defines the directory to store a backup of the DSTs |
| changes_dir | Defines the directory to store changes |
| pre_conf_file | Defines filename for used to store pre change data |
| post_conf_file | Defines filename for used to store post change data |
| configs_dir | Defines the directory to store cfg files |


## Dependencies
| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements** |
| -------------- | ----------- | -------------- | ----------- | -------------- |
| asa_config | version 2.5 | version 2.8.6 | 3.6.9 | none |


## Example Playbook
----------------
Play: play_asa_ras_dst_removal.yml

```yaml
---
- name: PLAY - RAS DST Deployment
  hosts: ras
  connection: network_cli
  gather_facts: yes

  roles:
    - asa-ras-DST-removal

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


