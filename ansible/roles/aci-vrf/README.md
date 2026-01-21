aci-vrf
===========

Creates a new VRF (aka. 'Context') in ACI. 

Requirements
------------

This role requires that the ACI Tenant referenced already exists. 

Either a seperate role responsible for creating a new Tenant: **aci-tenant** should be invoked by the playbook before this role. Or, if this role in run independently, the Tenant must already be incumbent in the ACI fabric. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-vrfs.yml  

Role Variables
--------------

Example Variable Structure: 

```yaml
tenants:
  - tenant: "common"
    vrfs:
      - vrf: "internal-vrf"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the host_vars file for the specified environment; for example LD6 production: 
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml

Specifically the "tenants" section of the variables file. 

Under the "tenants" section/tree this role makes reference to the "tenant" and the "vrf" variables. Creating the named Context/VRF under the specified Tenant. 

Dependencies
------------

This role utilises the pre-written Ansible module "aci_vrf":  
   https://docs.ansible.com/ansible/devel/modules/aci_vrf_module.html#aci-vrf-module

This role depends on the seperate role: "aci-tenant.yml" to build the ACI Tenant uder which the VRF will be created. 

Example Playbook
----------------
```yaml
- name: ACI vrf build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-vrf
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