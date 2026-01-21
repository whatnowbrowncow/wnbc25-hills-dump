aci-syslog
==========

Configures SYSLOG in ACI by creating one or more SYSLOG destinations, plus the SYSLOG sources for Fabric, Access and the "Common" Tenant. The Syslog sources for the "user defined" tenants are configured by the _aci-tenant_ role.

Requirements
------------

This role depends upon **Out-Of-Band Management** of the ACI fabric, and the associated **Out-Of-Band Contracts**, configured by the _aci-oob-contract_ role. 

Tasks
-----

This role consists of two separate tasks that are executed in the following order:  

main.yml  
aci-syslog.yml  

aci-syslog.yml consists of 5x _sub-tasks_ run in the following order:  

- Configures a SYSLOG Destination Server
- Configures ACI SYSLOG Source: Fabric-level (common)
- Configures ACI SYSLOG Source: Fabric-level (default)
- Configures ACI SYSLOG Source: Access-level
- Configures ACI SYSLOG Source: Tenant-level (Sets up a default monitoring policy in common tenant)

Role Variables
--------------

Example Variable Structure:  

```yaml
syslog:
  - group: "splunk"
    name: "ld6uxpremn12.prod.williamhill.plc"
    ip_addr: "10.112.12.111"  
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the group_vars file for each site:  

Example LD6 Lab environment:  
   network_inventory/environments//dev/group_vars/lab.yml  

Example Gib environment:  
   network_inventory/environments//prod/group_vars/gib.yml

This role makes reference to the "syslog" list. Each entry in the list is a dictionary of three variables, which define the SYSLOG group, the SYSLOG server name and IP address. All servers defined in the "syslog" list will be configured.  


Dependencies
------------

This role utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module  

This role depends on the seperate role: "aci-oob-contract" to configure the **Out-Of-Band Contract** which permits SYSLOG connectivity. 

Example Playbook
----------------
```yaml
- name: PLAY - ACI Syslog Build
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-syslog
```
WH Standard
-----------

| Status:     | undefined |
|-------------|-----------|

Author Information
------------------

Role author: Giles Falkingham, 2019.  
README author: Giles Falkingham, 2019. 