# asa-ras-dst-sync

The purpose of this role is to take the existing master copy of the RAS DST configuration (located in `/gitnet/network_inventory/environments/prod/group_var/ras`) and apply it to the secondary RAS Firewall, by doing it this way it allow us to still have an RAS firewall on a previous version to failover to if something should go wrong with a deployment. The Role performs this in several stages:


**Applying Config**
* Confirm which device is the live device
* Crete a variable containing the name of the secondary device
(NOTE: the following tasks only run on the secondary device)
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
* Produces a pre-change snapshot of the DST and Group Policy Configuration    * Produces the configuration to update the DST and group policy and then deploy this configuration to the device,
* Saves the configuration on the device
* Create a post configuration snapshot
* Performs a tidy up of the /gitnet/ras-processed directory

## Requirements

  * A development environment build to the standard in https://conf.willhillatlas.com/display/netsec/NetAuto+-+Dev+Environment+-+Windows+WSL+and+Microsoft+VS+Code or a gitlab-runner pipeline using image `nexus-aws.dtc.prod.williamhill.plc/networks/python-netauto:1.6.1`
  * ras group to be defined within the inventory

## Tasks

This role consists of 4 separate tasks:

* main.yml
* asa-ras-dst-validation.yml
* pre-change-snapshot.yml
* asa-ras-dst-config.yml


**main.yml** is executed first, a couple of tasks run to confirm, using a dig command, which is the secondary device. It then places this value adn place it in a fact called secondary_host, then the remaining tasks are then executed, in the order above from within main.yml on the device defined in the secondary_host fact.

After the playbook has finished the role calls a handler via the **  notify: "updates_exist_dst" ** command within the deployment tasks located within the ** asa-ras-object-config.yml ** file. These task compare the current configuration against the pre change snapshot and output the difference to a file located in ** ansible/roles/asa-ras-object/files/changes **

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

- name: ASA-RAS - Validate and deploy ansible data file for current DST
  include_tasks: asa-ras-dst-validation.yml
  when:
    - type is defined and type == "ras" and inventory_hostname == secondary_host

# This takes a snapshot of the ACLs and group policy configuration and places in a temporary file. It is then used to identify what has changed.
- name: ASA-RAS - Taking pre-change snapshot
  include_tasks: pre-change-snapshot.yml
  when:
    - type is defined and type == "ras" and inventory_hostname == secondary_host

# Apply new RAS configuration to the devices, then produces a text file output showing what has changed
- name: ASA-RAS - Apply configuration to device for RAS DST
  include_tasks: asa-ras-dst-config.yml
  when:
    - type is defined and type == "ras" and inventory_hostname == secondary_host

```
## Role Variables

Example Variable Structures:

>**Note:** the location of the variable files are nested within a directory called ras under the group_vars folder. This is to allow multiple YAML files to be created and allow only one source of truth for all RAS VPN devices, each one of the file contain variables for a specific element of the device configuration. It is important that **ALL** RAS specific YAML files are nested in this single location otherwise they will not be referenced.

After the playbook has finished the role calls a handler via the **  notify: "updates_exist_dst" ** command within the deployment tasks located within the ** asa-ras-dst-config.yml ** file. These task compare the current configuration against the pre change snapshot and output the difference to a file located in **  gitnet/ras-processed/changes/ **

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
| asa_config | version 2.5 | version 2.16.3 | 3.11.5 | none |


There is a dependency for the folders **/gitnet/ras-processed**. This is where the RAS ansible data is stored as well and any cfg and change files produced

Example Playbook
----------------
Play: play_asa_ras_dst.yml
```yaml
---

- name: PLAY - RAS ACL Deployment
  hosts: ras
  connection: network_cli

  roles:
     - asa-ras-dst-sync

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

**Role authors**: Chris Stafford (2024).
**README authors**: Chris Stafford (2024).
