# asa-ras-acl-sync

The purpose of this role is to take the existing master copy of the RAS ACL configuration (located in `/gitnet/network_inventory/environments/prod/group_var/ras`) and apply it to the secondary RAS Firewall, by doing it this way it allow us to still have an RAS firewall on a previous version to failover to if something should go wrong with a deployment. The Role performs this in several stages:

**Applying Config**
*
* Creates a snapshot of the current RAS and group policy information
* Compiles the ACL data using the ras_acl_constructor script in **/gitnet/ansible/roles/asa-ras-acl/scripts/ras_acl_constructor/ras_acl_constructor.py**
  * Marks all ACLs as changed
  * Compiles all the ACLs together as per the hierarchy
  * Renumbers all the ACLs
  * Outputs them in YAML format to the location gitnet/ras-processed/data
* Ansible then Retrieves the acl data from **/gitnet/ras-processed/data**
* Extracts the currently applied ACL names from the device group policy information.
* Confirms the ACLs that have changed, using the version number
* Check the Dependent ACL (Parent and Children) have been updated (using the version number)
* Apples the new configuration to the device
* Performs a tidy up of data directories
## Requirements

  * ras group to be defined within the inventory
  * Only ACLs that have no dependencies within there hierarchy must be changed in the **/gitnet/network_inventory/\<env\>/group_vars/ras** folder
  * All ACLs must start with `ras-`
  * All python modules installed as detailed in the  **/gitnet/ansible/roles/asa-ras-acl/scripts/requirements.txt** files

## Tasks

This role consists of 5 separate tasks:

* main.yml
* acl-ras-version-checks.yml
* acl-ras-hierarchy-checks.yml
* pre-change-snapshot.yml
* asa-ras-acl-config.yml

**main.yml** is executed first, a couple of tasks run to confirm, using a dig command, which is the secondary device. It then places this value adn place it in a fact called secondary_host, then the remaining tasks are then executed, in the order above from within main.yml on the device defined in the secondary_host fact.


After the playbook has finished the role calls a handler via the **  notify: "updates_exist_acl" ** command within the deployment tasks located within the ** asa-ras-object-config.yml ** file. These task compare the current configuration against the pre change snapshot and output the difference to a file located in ** ansible/roles/asa-ras-object/files/changes **


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

# Identify all RAS ACLs and collate the information. It then place all this in a fact called changed_acl. This will contain only the ACLs that have changed.
- name: ASA-RAS - Identifying ACLs version within YML and device
  include_tasks: acl-ras-version-checks.yml
  when:
    - type is defined and type == "ras" and inventory_hostname == secondary_host

# Takes each ACL defined in the changed_acl fact, extracts each of the required parent and children ACLs. Then it confirms that the relevant information has been updated. If this check fails, the whole playbook will end with an error describing which ACLs are out of sync.
- name: ASA-RAS - Identifying Dependent ACLs and check hierarchical changes
  include_tasks: acl-ras-hierarchy-checks.yml
  loop: "{{ changed_acls }}"
  loop_control:
   loop_var: loop_changed_acls
   label: "Collating Dependent Rules for {{ loop_changed_acls }}"
  when:
    - type is defined and type == "ras" and inventory_hostname == secondary_host and changed_acls is defined

# This takes a snapshot of the ACLs and group policy configuration and places in a temporary file. It is then used to identify what has changed.
- name: ASA-RAS - Taking pre-change snapshot
  include_tasks: pre-change-snapshot.yml
  when:
    - type is defined and type == "ras" and inventory_hostname == secondary_host and changed_acls is defined

# Apply new RAS configuration to the devices, then produces a text file output showing what has changed
- name: ASA-RAS - Apply configuration to device for RAS ACLs
  include_tasks: asa-ras-acl-config.yml
  when:
    - type is defined and type == "ras" and inventory_hostname == secondary_host and changed_acls is defined

```

## Role Variables

Example Variable Structures:

>**Note:** the location of the variable files are nested within a directory called ras under the group_vars folder. This is to allow multiple YAML files to be created and allow only one source of truth for all RAS VPN devices, each one of the file contain variables for a specific element of the device configuration. It is important that **ALL** RAS specific YAML files are nested in this single location otherwise they will not be referenced.

>**Note:** This role will also cause the acl role to define the ACLs in a fact as the name of the ACL rather than **access_lists**. The relevant should have been defined in ras.yml under group_vars/ras. It will also extracts the vpn filters and place them under **ra_vpn_filters_\<acl\>:** rather than extracting the access group config. This is because of the configuration of the **type == ras** and the **ra_vpn_cfg == deploy** located in the **\<device\>.yml** and **/roles/asa-vpn-acl/vars/main.yml** respectively.

After the playbook has finished the role calls a handler via the **  notify: "updates_exist_acl" ** command within the deployment tasks located within the ** asa-ras-acl-config.yml ** file. These task compare the current configuration against the pre change snapshot and output the difference to a file located in ** ansible/roles/asa-ras-object/files/changes **

### RAS VPN Group Vars structure example
```
📦gitnet
 ┣ 📂network_inventory
 ┃ ┣ 📂environments
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
| date | Collates and stores the current date |
| time | Collates and stores the current time |
| backup_dir | Defines the directory to store a backup of the ACLs |
| changes_dir | Defines the directory to store changes |
| pre_conf_file | Defines filename for used to store pre change data |
| post_conf_file | Defines filename for used to store post change data |
| ld6_sync_group | collates the name to work out the device entry in the inventory for LD6 RAS Firewall|
|sc1_sync_group | collates the name to work out the device entry in the inventory for SCC RAS Firewall|


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
| asa_config | version 2.5 | version 2.16.3 | 3.11.5 | none |


>**Note:** There are extra dependencies required with the role called from this role. These are listed in the relevant role readme


There is a dependency for the folders **/gitnet/ras-rule-update** and **/gitnet/ras-processed**.
* **/gitnet/ras-rule-update**  contains the ras script that is used to compile the RAS acls data. Details can be found in **https://gitlab.com/williamhillplc/technical-services/networks/ansible/-/tree/master/scripts**
* **/gitnet/ras-processed** is where the RAS data this role is stored as well and any cfg and change files produced

Example Playbook
----------------
Play: play_asa_ras_acl_sync.yml
```yaml
---

- name: PLAY - SYNC RAS ACL configuration
  hosts: ras
  gather_facts: now
  connection: network_cli

  roles:
    - asa-ras-acl-sync

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

**ansible/roles/asa-ras-acl-sync/.gitignore**
```bash
files/changes/*


If an error is produced while running the asa_command saying that imp is not available then add the following to the asa_command.py file located within the module directory

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

Author Information
------------------

**Role authors**: Chris Stafford (2024).
**README authors**: Chris Stafford (2024).
