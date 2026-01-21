aci-snapshot
============

Creates a new ACI Snapshot. 

Requirements
------------

None.

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-create-snapshot.yml  

Role Variables
--------------

Example Variable Structure: 

```yaml
  vars_prompt:
    - name: "snapshot_description"
      prompt: "Provide the change ref. This will be used for the slack message and/or snapshots:"
      default: "ansible pre-change backup"
      private: no
```

This role first references the group variables file(s) for the specified environment; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.

This role references "vars_prompt: > name" - the dynamic variable input by the user when the playbook is run. For an example playbook see: aci-role-build.yml  

Dependencies
------------

This role utilises the pre-written Ansible module "aci_config_snapshot":  
   https://docs.ansible.com/ansible/devel/modules/aci_config_snapshot_module.html#aci-config-snapshot-module

Example Playbook
----------------
```yaml
- name: PLAY - Full ACI Tenant build
  hosts: ld6
  connection: local
  gather_facts: no

  vars_prompt:
    - name: "snapshot_description"
      prompt: "Provide the change ref. This will be used for the slack message and/or snapshots:"
      default: "ansible pre-change backup"
      private: no

  roles:
    - aci-snapshot
```
WH Standard
-----------

| Status:     | approved |
|-------------|----------|

While there is no 'standard' necessary for the snapshot itself. There is a standard naming convention to include the Service Now change reference (CHG) in the snapshot name. 

License
-------

BSD

Author Information
------------------

Role author: Anthony Gittins, 2018.  
README author: Giles Falkingham, 2018. 