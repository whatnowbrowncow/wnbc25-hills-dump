aci-user-cert-auth
==================

Configures the username, password and X.509 certificate for the automation user. 
This role is designed to be run first in the playbook: `play_aci-day-zero-build.yml` in order to enable certificate based authentication for all future ACI roles.  

Requirements
------------

ACI must be configured to use local user accounts (rather than TACACS). 


Tasks
-----

This role consists of two seperate task files that are executed in the following order:

main.yml  
aci-user-cert-auth.yml   

aci-user-cert-auth.yml consists of 4x _sub-tasks_ run in the following order:  

- Turn Off Password Strength Check
- Create Local Super-User for Automation
- Upload the Pre-existing X.509 Certificate for that Super-User
- Turn On Password Strength Check


Role Variables
--------------

Example Variable Structure: 

```yaml
aci_user: "svcnetworkauto"
aci_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32633...
aci_key: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          37356...
aci_cert: "-----BEGIN CERTIFICATE-----\n..."
```

This role references the main **aci.yml** group variables file:

Example production:  
   network_inventory/environments//prod/group_vars/aci.yml  

Example Lab environment:  
   network_inventory/environments//dev/group_vars/aci.yml  

In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication against ACI/APICs.  

Nb. Use `--ask-vault-pass` when running a playbook including this role in order to decrypt the user's password [aci_password] and the user's private key [aci_key]. 


Dependencies
------------

Minimum ansible version: 2.8 (necessary for Ansible Vault to decrypt the private key for cert based auth)
Tested with ansible version: 2.8.1
Tested with ACI 3.2(4e)

This role utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module  


Example Playbook
----------------
```yaml
---

- name: This configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-user-cert-auth

```
WH Standard
-----------

| Status:     | awaiting approval |
|-------------|-------------------|

TBC

License
-------

BSD

Author Information
------------------

Role author: Rick Twells, 2019.  
README author: Rick Twells, 2019. 