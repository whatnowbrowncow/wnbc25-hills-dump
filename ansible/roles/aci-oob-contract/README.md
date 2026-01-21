aci-oob-contract
================

Configures the Out-Of-Band Contract in ACI to permit all necessary access including, but not limited to, HTTPS, SSH and SNMP. 

Requirements
------------

This role has no requirements.   
  
Tasks
-----

This role consists of two separate tasks that are executed in the following order:  

main.yml  
aci-oob-contract.yml  

aci-oob-contract.yml consists of 5x _sub-tasks_ run in the following order:  

- Creates a Filter (permit-all)
- Creates a Filter (permit-snmp)*
- Creates Out-Of-Band Contract (oob-mgmt) with subject (fabric_routed) and adds the filters to the subject
- Adds the Out-Of-Band Contract (oob-mgmt) to Out-of-Band EPG - default as 'provided'
- Creates an External Management Network Instance Profile (emnip) and adds the Out-of-Band Contract (oob-mgmt) as 'consumed'

\* Note that it is necessary to create a contract filter that explicitly specifies SNMP ports because of the way the APICs setup their internal iptables config based upon the oob-mgmt contract.

Role Variables
--------------

N/A - Values are hard coded in the the role task to avoid errors and enforce a standard configuration across all ACI fabrics.

Dependencies
------------

This role utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module  

_Nb. This role is a dependency of aci-snmp and aci-syslog._  

Example Playbook
----------------
```yaml
- name: PLAY - ACI Syslog Build
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-oob-contract
```
WH Standard
-----------

| Status:     | undefined |
|-------------|-----------|

Author Information
------------------

Role author: Giles Falkingham, 2019.  
README author: Giles Falkingham, 2019. 