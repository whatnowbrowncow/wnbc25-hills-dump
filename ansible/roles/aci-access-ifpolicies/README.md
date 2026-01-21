aci-access-ifpolicies
=====================

This role creates Interface Policies, and the Interface Policy Groups that reference them. 

Create link-level interface policies.
Create CDP interface policies.
Create LLDP interface policies.
Create LACP interface policies.
...
Create VPC interface policy groups.
Create access port interface policy groups.

Requirements
------------

None. However see dependencies. 

Tasks
-----

This role consists of three seperate tasks that are executed in the following order:  

main.yml  
aci-access-if-policies.yml  
aci-access-if-policy-groups.yml  

Role Variables
--------------

Example Variable Structure:  

```yaml
link_level_policy: 
  - name: "10gb"
    speed: "10G"   

cdp_policy:
  - name: "cdp_enabled"
    state: "enabled"

lldp_policy:
  - name: "lldp_enabled"
    rxstate: "enabled"
    txstate: "enabled"      

lacp_policy:
   - name: "lacp-active" 
     mode: "active"
     ctrl: "fast-sel-hot-stdby,graceful-conv,susp-individual"

if_policy_groups:
  - name: "gib-enc01-mod1_polgrp"
    speed: "10gb"
    aaep: "enclosures"
    linkagg: "lacp-active-nosuspend"
    cdp: "cdp_disabled"
    lldp: "lldp_enabled"
    type: "vpc"
```

This role references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.

In group_vars/aci.yml this role (task: aci-access-if-policies.yml) makes reference to "link_level_policy", "cdp_policy", "lldp_policy" and "lacp_policy" for building interface policies. 

In group_vars/site_aci.yml this role (task: aci-access-if-policy-groups.yml) will make reference to "if_policy_groups" for building interface policy groups, both VPC and access port types. 

Dependencies
------------

This role utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module  

This role depends upon the **Explicit VPC Protection Groups** being created seperately. The creation of Explicit VPC Protection Groups is not currently automated, so this must be done manually via the ACI GUI.  
In the ACI GUI go to: Fabric > Access Policies > Policies > Switch > Virtual Port Channel Default > Create VPC Explicit Protection Group
  
**Note: It is vital that Explicit VPC Protection Groups are configured before the Ansible tooling applies Interface Policy Groups to EPGs' Static Port Associations.**  
**!! Failure to configure Explicit VPC Protection Groups can cause a layer 2 loop. !!**  
  
Nb. This role is a dependency of aci-epg.  

Example Playbook
----------------
```yaml
- name: ACI interface policies / policy groups build
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-access-ifpolicies
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

Role authors: Nick Turner & Giles Falkingham, 2019.  
README author: Giles Falkingham, 2019. 