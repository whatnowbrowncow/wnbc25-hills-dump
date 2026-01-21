aci-disable-ep-learn
=====================

Disables the "Remote EP Learning" setting in System > System Settings "To disable remote endpoint learning in VRFs containing external bridged/routed domains". This is a Cisco recommended configuration to prevent stale MAC entries occurring on border leaf switches. 


Requirements
------------

None

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

**main.yml**
**aci-disable-ep-learn.yml**

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the **aci-disable-ep-learn.yml** task.

The **aci-disable-ep-learn.yml** task contains one task which uses the **rest_aci** Ansible module to set Remote EP Learning to disabled.  


Role Variables
--------------

No variables are defined for this role. 
 

Dependencies
------------

This role (task: aci-disable-ep-learn.yml) utilises the following pre-written Ansible module:

 "aci_rest":  
   <https://docs.ansible.com/ansible/2.4/aci_rest_module.html>


Example Playbook
----------------
```yaml
---

- name: This play performs switch discovery and configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-disable-ep-learn

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

Role author: Nick Turner, 2019.  
README author: Nick Turner, 2019. 