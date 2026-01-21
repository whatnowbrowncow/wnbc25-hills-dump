aci-bd
======

Creates a new Bridge Domain (BD) object in ACI. 

Requirements
------------

This role requires that the referenced ACI **Tenant** and **VRF** already exist. 

Either the seperate roles responsible for creating a new Tenant: **aci-tenant**, and VRF: **aci-vrf**, should be invoked by the playbook before this role. Or, if this role in run independently, the Tenant and VRF must already be incumbent in the ACI fabric. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-bds.yml  

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
        cidr_mask: "27"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the host_vars file for the specified environment; for example LD6 production:  
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml  
  
Specifically the "app_profs" section of the variables file. 

Under the "app_profs" list this role makes reference to the "tenant" and the "vrf" variables. Creating the named Bridge Domain (BD) under the specified Tenant and associated with the specified VRF. 

Under the "bds" sub-list this role makes reference to the "bd", "network" and "cidr_mask" variables to name the new Bridge Domain. 

**This role consists of two tasks and refers to the "l3_ownership" variable in the app_profs dictionary to determine whether the BD needs to be built as an L2 or L3 version.**

**Whereby the BD is built as L3 if "l3_ownership: aci". The BD is built as L2 if "l3_ownership: firewall" or "l3_ownership: none"**

Dependencies
------------

This role utilises the following **Ansible** module:
- *[aci_bd](https://docs.ansible.com/ansible/devel/modules/aci_bd_module.html#aci-bd-module)*

| **Module(s)** | **New in** | **Tested using** | **Requirements**   |
| ------- | ------- | ---- | --- |
| aci_bd | version 2.4| tbc | none  | 

This role depends on the seperate role: "aci-tenant" to build the ACI Tenant under which the Bridge Domain will be created. 

This role depends on the seperate role: "aci-vrf" to build the VRF that the Bridge Domain will be associated with. 

While not a dependency per-se, it is important to note that *this role does not create the BD subnet for L3 version BDs*. This is done by a seperate role: "aci-bd-subnet". Whether a BD is an L2 or L3 version is determined by the "l3_ownership" variable. 

Example Playbook
----------------
```yaml
- name: ACI app profile build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-bd
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