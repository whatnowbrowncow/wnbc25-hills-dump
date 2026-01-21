aci-bd-subnet
=============

Creates the layer 3 / 'subnet' configuration for an L3 Bridge Domain (BD) in ACI. 

Requirements
------------

This role requires that the referenced ACI **BD**, **Tenant** and **VRF** already exist. 

Either the seperate roles responsible for creating a new BD: **aci-bd**, Tenant: **aci-tenant**, and VRF: **aci-vrf**, should be invoked by the playbook before this role. Or, if this role in run independently, the BD, Tenant and VRF must already be incumbent in the ACI fabric. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-bd-subnet.yml  

Role Variables
--------------

Example Variable Structure: 

```yaml
app_profs:
  - app_prof: "internal"
    tenant: "common"
    vrf: "internal-vrf"
    l3_ownership: aci
    bds:
      - bd: "infoblox"
        network: "10.2.0.0"
        gateway: "10.2.0.1"
        mask: "255.255.255.224"
        cidr_mask: "27"
        scope: "public"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.

This role then references the host_vars file for the specified environment; for example LD6 production:  
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml  
  
Specifically the "app_profs" section of the variables file. 

Under the "app_profs" list this role makes reference to the "tenant" variable and "bds" sub-list. 

Under the "bds" sub-list this role makes reference to the "bd", "network" and "cidr_mask" variables; concatenating these to determine the name of the Bridge Domain. 

Creating the L3 BD 'subnet' configuration under the specified Tenant+BD unique combination.

The L3 BD 'subnet' configuration is created with reference to the "gateway", "cidr_mask" and "scope" variables contained in the "bds" sub-list. 

**This role will only be invoked as part of the play if the variable "l3_ownership: aci" - thus specifying that the BD needs to be built as an L3 version.**

Dependencies
------------

This role utilises the following **Ansible** module:
- *[aci_bd_subnet](https://docs.ansible.com/ansible/devel/modules/aci_bd_subnet_module.html#aci-bd-subnet-module)*

| **Module(s)** | **New in** | **Tested using** | **Requirements**   |
| ------- | ------- | ---- | --- |
| aci_bd_subnet | version 2.4| tbc | none  |  

This role depends on the seperate role: "aci-tenant" to build the ACI Tenant under which the Bridge Domain will be created. 

This role depends on the seperate role: "aci-vrf" to build the VRF that the Bridge Domain will be associated with. 

This role depends on the seperate role: "aci-bd" to build the Bridge Domain (BD) that the L3 'subnet' configuration is for. 

Example Playbook
----------------
```yaml
- name: ACI app profile build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-bd-subnet
```
WH Standard
-----------

| Status:     | approved |
|-------------|----------|

[NET-STD050 - ACI Bridge Domain (BD)](https://conf.willhillatlas.com/pages/viewpage.action?pageId=237214867)  

License
-------

BSD

Author Information
------------------

Role author: Anthony Gittins, 2018.  
README author: Giles Falkingham, 2018.  