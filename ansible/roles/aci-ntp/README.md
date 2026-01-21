aci-ntp
=========

Generates and/or applies NTP configuration to ACI using the rest module.

Requirements
------------

The pod policy group for the relevant pod (in this case **POD1**) must exist within fabric policies before running this role otherwise sub-task 4 would fail.

Tasks
-----

This role consists of two seperate tasks that are executed in the following order: 

main.yml  
aci-ntp.yml 

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the aci_ntp task.

The **aci-ntp.yml** task contains four sub-tasks:  

(1/4) Configure time and date settings using the **aci_rest** Ansible module.  
(2/4) Create NTP pod policy using the **aci_rest** Ansible module.  
(3/4) Add NTP servers to pod policy using the **aci_rest** Ansible module.  
(4/4) Apply NTP pod policy to pod policy group using the **aci_rest** Ansible module.  

Role Variables
--------------

Example Variable Structure: 

```yaml
timezone: "p60_Europe-London"

ntp_servers:
  - name: "sc1ns01.williamhill.plc"
    description: "SCC Infoblox NTP"
    ip_addr: "10.120.193.235"
    preferred: "true"
  - name: "brsns01.williamhill.plc"
    description: "BRS Infoblox NTP"
    ip_addr: "10.210.193.235"
    preferred: "false"

pod_id: "1"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the main group variables file for the specified site.

Example GIB production:  
   network_inventory/environments//prod/group_vars/gib.yml  
  
Example LD6 production:  
   network_inventory/environments//prod/group_vars/ld6.yml  
  
This role (task: aci-ntp.yml - sub-task 1) makes reference to the **timezone** variable within group_vars/aci.yml

This role (task: aci-ntp.yml - sub-task 2) makes reference to the **pod_id** variable within group_vars/aci.yml

This role (task: aci-ntp.yml - sub-task 3) makes reference to the **ntp_servers** list in group variables which contains list items for each ntp server containing the variables for **description** , **ip_addr**, and **preferred**, a boolean variable to identify the primary ntp server to be used.

This role (task: aci-ntp.yml - sub-task 4) makes reference to the **pod_id** variable within group_vars/aci.yml

Dependencies
------------

This role (task: aci-ntp.yml) utilises the following pre-written Ansible module:

<https://docs.ansible.com/ansible/2.4/aci_rest_module.html>  

Minimum version ansible version 2.4
Tested using ansible version 2.8.1

Example Playbook
----------------
```yaml
---

- name: This play performs ACI NTP configuration.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-ntp
```
WH Standard
-----------

| Status:     | undefined |
|-------------|-----------|

[ARCH-008 - NTP](https://conf.willhillatlas.com/display/ARCH/ARCH-008+-+NTP)  

License
-------

BSD

Author Information
------------------

Role authors: Dave Burton 2019.  
README authors: Dave Burton 2019.  