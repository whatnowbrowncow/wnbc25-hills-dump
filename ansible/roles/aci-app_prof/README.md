aci-app_prof
============

Creates a new Application Profile object in ACI. 

Requirements
------------

This role requires that the ACI **Tenant** referenced already exists. 

Either a seperate role responsible for creating a new Tenant: **aci-tenant** should be invoked by the playbook before this role. Or, if this role is run independently, the tenant must already be incumbent in the ACI fabric. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-app_profs.yml  

Role Variables
--------------

Example Variable Structure: 

```yaml
app_profs:
  - app_prof: "prod-cde"
    tenant: "production"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the host_vars file for the specified environment; for example LD6 production:  
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml  
  
Specifically the "app_profs" list in the variables file. 

Under the "app_profs" list this role makes reference to the "tenant" and the "app_prof" variables. Creating the named Application Profile under the specified tenant. 


Dependencies
------------

This role utilises the **Ansible** module *[aci_ap](https://docs.ansible.com/ansible/devel/modules/aci_ap_module.html#aci-ap-module)*:

| **New in** | **Tested using** | **Requirements**   |
| ------- | ---- | --- |
| version 2.4| tbc|  *none*    |

This role depends on the seperate role: "aci-tenant.yml" to build the ACI Tenant under which the App Profile will be created. 

Example Playbook
----------------
```yaml
- name: ACI app profile build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-app_prof
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