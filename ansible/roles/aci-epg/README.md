aci-epg
=======

Creates an EPG (End Point Group) in ACI.  
Adds "vmware" VMM Domain to the EPG.  
Adds "enclosures" physical domain to the EPG.  
Adds "network-devices" physical domain to the EPG.  
Adds static port bindings for internal firewall vrfs to the EPG.  
Adds static port bindings for enclosures to the EPG. (Optional)  

Requirements
------------

This role requires that the referenced ACI **Tenant**, **App Profile** and **BD** already exist. 

Either the seperate roles responsible for creating a new Tenant: **aci-tenant**, Application Profile: **aci-app_prof**, and BD: **aci-bd**, should be invoked by the playbook before this role. Or, if this role in run independently, the Tenant, Application Profile and BD must already be incumbent in the ACI fabric. 

Tasks
-----

This role consists of six seperate tasks that are executed in the following order:

main.yml  
aci-epg-bds.yml  
aci-epg-epgs.yml  
aci-build-epgs.yml  
aci-epg_to_domain_loop.yml  
aci_static_binding_to_epg.yml  

The first three tasks in the list are necessary to pull the referenced variables from the heavily nested app_profs list in the variables file. 

Role Variables
--------------

Example Variable Structure: 

```yaml
pod_id: "1"

vmm_domain: "LD6PRDDvSRES02"

app_profs:
  - app_prof: "cde-mgmt"
    tenant: "common"
    vrf: "cde-mgmt-vrf"
    l3_ownership: firewall
    bds:
      - bd: "vsphere"
        network: "10.112.8.0"
        cidr_mask: "23"
        epgs:
          - epg: "vsphere"
            encap_id: "30"
            vcenter_dynamic_vlan: false
            vcenter_vlan_mode: "auto"
            vcenter_vlan: "1105"

static_interfaces:
  - description: "Data connection to uk-ld6-pp-fw05 firewalls"
    connected_device: "firewall"
    policy_group: "uk-ld6-fw05-data_polgrp"
    leafs: "101,102"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.

This role then references the host_vars file for the specified environment.

Example LD6 production:  
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml  
  
Example LD6 Lab environment:  
   network_inventory/environments//dev/host_vars/ld6-lab-aci.yml  
  
This role (task: aci-build-epgs.yml) makes reference to the "app_profs" list, and the "bds" and "epgs" sub-lists nested within. Creating the EPG under the specified Tenant+AppProfile unique combination.

This role (task: aci-epg_to_domain_loop.yml) makes reference to the "app_profs" list, and the "bds" and "epgs" sub-lists nested within. It also makes reference to the "vmm_domain" variable, which is in the site specific group_vars file. 

**The task: aci-epg_to_domain_loop.yml contains of two sub-tasks to create the EPG's VMM Domain association with either a dynamic or staic VLAN; it refers to the "vcenter_dynamic_vlan" variable in the "epgs" sub-list to determine whether the VMM Domain requires a static or dynamic VLAN.**

This role (task: aci_static_binding_to_epg.yml) makes reference to the "static_interfaces" list. The "static interfaces" list is in the site specific group_vars file; e.g. /prod/group_vars/ld6_aci.yml

Dependencies
------------

This role (task: aci-build-epgs.yml) utilises the pre-written Ansible module "aci_epg":  
   https://docs.ansible.com/ansible/devel/modules/aci_epg_module.html#aci-epg-module

This role (task: aci-epg_to_domain_loop.yml) utilises the pre-written Ansible module "aci_epg_to_domain":  
   https://docs.ansible.com/ansible/devel/modules/aci_epg_to_domain_module.html#aci-epg-to-domain-module

This role (task: aci_static_binding_to_epg.yml) utilises the pre-written Ansible module "aci_static_binding_to_epg":  
   https://docs.ansible.com/ansible/devel/modules/aci_static_binding_to_epg_module.html#aci-static-binding-to-epg-module

This role depends on the seperate role: "aci-tenant" to build the ACI Tenant under which the EPG will be created. 

This role depends on the seperate role: "aci-app_prof" to build the Application Profile under which the EPG will be created. 

This role depends on the seperate role: "aci-bd" to build the Bridge Domain (BD) that the EPG will be associated with.

Example Playbook
----------------
```yaml
- name: ACI app profile build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-epg
```
WH Standard
-----------

| Status:     | approved |
|-------------|----------|

[NET-STD051 - ACI End Point Group (EPG)](https://conf.willhillatlas.com/pages/viewpage.action?pageId=237214886)  

License
-------

BSD

Author Information
------------------

Role author: Anthony Gittins, 2018.  
README author: Giles Falkingham, 2018. 