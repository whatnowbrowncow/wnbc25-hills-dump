asa-interfaces
==================

[Insert Role Overview here]

Requirements
------------

[Insert Role Requirements here]

Tasks
-----

This role consists of two separate task files that are executed in the following order:

+ **main.yml:** This task defines the ansible_network_os conditional statement and the _import_task/include_task_ statement for the **asa-interfaces** sub-tasks.
+ **asa-interfaces:** This task contains 3 tasks:
	- Setup interfaces on context firewalls using lines method
	- asa-interfaces_gather_vlans
	- asa-interface_builder

Role Variables
--------------

Example Variable Structure: 

```yaml
- name: Building interface on context {{ context_item.context }}
  asa_config:
    lines:
      - "mac-address {{ cluster_mac }}"
      - "nameif {{ item.nameif }}"
      - "security-level {{ item.sec_level}}"
      - "ip address {{ item.addr }} {{ item.netmask}}"
    parents: ["interface Port-channel1.{{ item.vlan }}"]
    match: line
    context: "{{ context_item.context }}"
  with_items:
    - "{{ context_interfaces_item }}"
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

- name: Setup interfaces on context firewalls using lines method
  include_tasks: ./asa-interfaces_gather_vlans.yml
  with_items:
    - "{{ contexts }}"
  loop_control:
    loop_var: context_item
```
WH Standard
-----------

| Status:     | undefined |
|-------------|-------------------|

Author Information
------------------

Role author: Anthony Gittins, 2018.  
README author: Chris Hannan, 2019. 