asa-remove-objects
==================

[Insert Role Overview here]

Requirements
------------

[Insert Role Requirements here]

Tasks
-----

This role consists of two separate task files that are executed in the following order:

+ **main.yml:** This task defines the ansible_network_os conditional statement and the _import_task/include_task_ statement for the **asa-remove-objects** task.
+ **asa-remove-objects:** This task contains 3 sub-tasks:
	- Removal of objects from contexts
	- Build objects removal commands
	- Remove objects from context

Role Variables
--------------

Example Variable Structure: 

```yaml
- name: Build objects removal commands
  template:
    src: objects.j2
    dest: ./roles/asa-remove-objects/configs/{{ inventory_hostname }}_objects.cfg

    
- name: Remove objects from context {{ contexts.context }}
  asa_config:
    src: ./roles/asa-remove-objects/configs/{{ inventory_hostname }}_objects.cfg
    context: "{{ item.context }}"
  with_items:
    - "{{ contexts }}"
```

Dependencies
------------

This role utilises the pre-written Ansible module *[_asa_config_](https://docs.ansible.com/ansible/latest/modules/asa_config_module.html)*:

| **New in** | **Tested using** | **Requirements**   |
| ------- | ---- | --- |
| 2.2| 2.8.1 |  none    |


Example Playbook
----------------
```yaml
---

- name: Removal of objects from contexts 
  include_tasks: ./asa-remove-objects.yml
```
WH Standard
-----------

| Status:     | undefined |
|-------------|-------------------|

Author Information
------------------

Role author: Anthony Gittins, 2018.  
README author: Chris Hannan, 2019. 