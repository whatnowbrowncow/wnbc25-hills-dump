aci-int-selector
================

This role creates Leaf Interface Profiles, and the Interface Selectors that are nested beneath. 

Requirements
------------

This role requires that the referenced ACI **Interface Policy Groups** and **Leaf Access Port Policy Groups** already exist. 

Either the seperate role responsible for creating a these: **aci-access-ifpolicies** should be invoked by the playbook before this role. Or, if this role in run independently, the Interface Policy Groups and/or Leaf Access Port Policy Groups must already be incumbent in the ACI fabric. 

Tasks
-----

This role consists of three seperate tasks that are executed in the following order:  

main.yml  
aci-leaf-interface-profile.yml  
aci-leaf-port-selector.yml  

Role Variables
--------------

Example Variable Structure:  

```yaml
if_selectors:
  - leaf_prof: "Switch103-104_Profile_ifselector"
    leaf_int_selection:
      - name: "uk-ld6-cr01-po1"
        port: "22"
        blk_no: "2"
        polgrp: "uk-ld6-cr01-po1_PolGrp"
        type: "bundle"
```

This role references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.

In group_vars/site_aci.yml this role will make reference to "if_selectors" for building Leaf Interface Profiles, and the Interface Selectors that are nested beneath. 

Dependencies
------------

This role utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module  

This role depends on the seperate role: "aci-access-ifpolicies" to build the Interface Policy Groups that are referenced by the Interface Selectors. 

This role depends upon the Leaf Switch Profiles being created seperately. The creation of Leaf Switch Profiles is not currently automated, so this must be done manually via the ACI GUI.  

Example Playbook
----------------
```yaml
- name: ACI interface policies / policy groups build
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-int-selector
```

WH Standard
-----------

| Status:     | undefined |
|-------------|-----------|

License
-------

BSD

Author Information
------------------

Role author: Giles Falkingham, 2020.  
README author: Giles Falkingham, 2020.  