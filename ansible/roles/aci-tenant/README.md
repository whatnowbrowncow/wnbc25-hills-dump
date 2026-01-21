aci-tenant
==========

Creates a new Tenant in ACI. 

Requirements
------------

The _aci-syslog_ role configures the syslog servers to which all ACI syslog data will be forwarded. It also creates a 'default' tenant-level monitoring policy within the 'common' tenant and associates the syslog servers with this policy. This 'default' monitoring policy can then be associated with any other tenant rather than creating a new policy for each tenant. 

The second task in the _aci-tenant_ role associates the 'default' monitoring policy with each "user defined" tenant being configured (e.g. "production", "PTE")

The _aci-syslog_ role is part of the ACI Day Zero build. It must have been successfully executed at least once prior to execution of the _aci-tenant_ role so that the 'default' monitoring policy exists for association with each new tenant.


Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-tenant.yml  

aci-tenant.yml consists of 2x _sub-tasks_ run in the following order:  

- Configures user defined tenant (e.g. production, pte)
- Configures ACI SYSLOG Source: Tenant-level (Adds the default monitoring policy to all user defined tenants)

Role Variables
--------------

Example Variable Structure: 

```yaml
tenants:
  - tenant: "production"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the host_vars file for the specified environment; for example LD6 production:  
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml

Specifically the "tenants" list in the variables file. 

Under the "tenants" list this role makes reference to the "tenant" variable. 

Dependencies
------------

This role utilises the pre-written Ansible module "aci_tenant":  
   https://docs.ansible.com/ansible/devel/modules/aci_tenant_module.html#aci-tenant-module

Example Playbook
----------------
```yaml
- name: ACI app profile build
  hosts: all
  connection: local
  gather_facts: no

  roles:
    - aci-tenant
```
WH Standard
-----------

| Status:     | draft |
|-------------|-------|

[NET-STD054 - ACI Tenants](https://conf.willhillatlas.com/display/ARCH/NET-STD054+-+ACI+Tenants)  

License
-------

BSD

Author Information
------------------

Role author: Anthony Gittins, 2018.  
README author: Giles Falkingham, 2018.  