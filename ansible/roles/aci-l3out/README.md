aci-l3out
=========

**Beta** - This role is considered a work in progress.

Creates an L3out in ACI.   

Requirements
------------

This role requires that the referenced ACI **Tenant** and **VRF** (aka. Context) already exist. 

Either the seperate roles responsible for creating a new Tenant: **aci-tenant** and VRF: **aci-vrf**, should be invoked by the playbook before this role. Or, if this role in run independently, the Tenant and VRF must already be incumbent in the ACI fabric. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-l3out.yml  

A final task named aci-l3nodeprofile.yml may follow, but this is still in development. 

Role Variables
--------------

Example Variable Structure: 

```yaml
l3outs:
  - l3_domain: "network-devices"
    tenant: "ant-tenant"
    vrf: "ant-vrf"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the host_vars file for the specified environment.  

Example LD6 Lab environment:  
   network_inventory/environments//dev/host_vars/ld6-lab-aci.yml  
  
This role makes reference to the "l3outs" list. 
Note that the l3outs list is only in the lab veriables file at the time of writing. 

Dependencies
------------

This role (task: aci-build-epgs.yml) utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module

This role depends on the seperate role: "aci-tenant" to build the ACI Tenant under which the L3out will be created. 

This role depends on the seperate role: "aci-vrf" to build the VRF/Context that the L3out will be associated with. 

The role task **aci-l3out.yml** depends upon the following two Jinja2 templating scripts to dynamically build the relevant Json for the ACI rest API: 

l3out.j2  
l3extsubnet.j2  

Example Playbook
----------------
```yaml
- name: ACI app profile build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-l3out
```
WH Standard
-----------

| Status:     | draft |
|-------------|-------|

[NET-STD053 - ACI L3out](https://conf.willhillatlas.com/display/ARCH/NET-STD053+-+ACI+L3out)  

License
-------

BSD

Author Information
------------------

Role author: Anthony Gittins, 2018.  
README author: Giles Falkingham, 2018. 