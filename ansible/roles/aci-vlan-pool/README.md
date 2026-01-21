aci-l3out
=========

Creates a VLAN Pool and associated Encap Block(s) ACI.  
i.e. the VLAN Pool is created and blocks of one-or-more VLANs are allocated to the pool. 

Requirements
------------

None. However please note:

It is critical the pool_allocation_mode matches the current mode, otherwise the the task and play will fail. This could occur if the pool was originally created manually or if the host var was amended. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-vlan-pool.yml  

Role Variables
--------------

Example Variable Structure: 

```yaml
vlan_pools:
  - name: "vmware"
    pool_allocation_mode: "dynamic"
    vlans:
      - start: "1105"
        end: "1109"
        allocation_mode: "static"
      - start: "1110"
        end: "1119"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the host_vars file for the specified environment.

Example LD6 production: 
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml

Example LD6 Lab environment:  
   network_inventory/environments//dev/host_vars/lab-aci.yml

This role makes reference to the "vlan_pools" dictionary.  

VLAN Pools are created with reference to the first nested level of the "vlan_pools" dictionary. 

VLAN Encap Blocks are created and allocated to a VLAN Pool with reference to the "vlans" sub-dictionary under each VLAN Pool. 

Note that the "allocMode" variable is checked to see if it is set. Assuming it is set the value is used, if it is not set the default value of "dynamic" is used instead.

Dependencies
------------

This role (task: aci-build-epgs.yml) utilises the pre-written Ansible module "aci_rest":
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module

Example Playbook
----------------
```yaml
- name: ACI app profile build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-vlan-pool
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

Role author: Anthony Gittins, 2018.  
README author: Giles Falkingham, 2018. 