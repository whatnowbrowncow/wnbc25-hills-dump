aci-fabric-membership
=====================

Updates the fabric membership list with fabric switches using the serial number as the device identifier. The user-determined values of node-id and switch hostname are associated with each serial number/switch. 

Uses rest module to update each fabric member with its physical geolocation.

Requirements
------------

The **aci-geolocation** role must always be run prior to the **aci-fabric-membership** role. 

The actual creation of each **geo_row** and **geo_rack** policy object is performed by the **aci-geolocation** role. Once these objects are created the second task in the **aci-fabric-membership** role will update each fabric switch with the relevant **geo_row** and **geo_rack** value from the **fabric_nodes** list. These objects must already exist otherwise this task will fail. 


Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-fabric-membership.yml   

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the aci_fabric_membership task.

The **aci-fabric-membership.yml** task contains two tasks:  

(1/2) Associate the fabric switches with ACI using the **aci_fabric_node** Ansible module.  
(2/2) Associate geolocation rack objects with each switch using the **aci_rest** Ansible module.  


Role Variables
--------------

Example Variable Structure: 

```yaml
fabric_nodes:
  - switch: "gi-mpl-ss03"
    node_id: "203"
    serial: "FDO22491X93"
    geo_row: "1"
    geo_rack: "c1a"
  - switch: "gi-mpl-ss04"
    node_id: "204"
    serial: "FDO22490X6L"
    geo_row: "2"
    geo_rack: "d1a"    
  - switch: "gi-mpl-ls01"
    node_id: "101"
    serial: "FDO22481WYX"
    geo_row: "1"
    geo_rack: "c1b"       

```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the main group variables file for the specified site.

Example GIB production:  
   network_inventory/environments//prod/group_vars/gib_aci.yml  
  
Example LD6 production:  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
This role (task: aci-fabric-membership.yml) makes reference to the **fabric_node** list in group variables which contains list items for each switch containing the variables for **node_id**, **switch**, **serial**, **geo_row** and **geo_rack**.


Dependencies
------------

This role (task: aci-fabric-membership.yml) utilises the following pre-written Ansible modules

 "aci_fabric_node":  
   <https://docs.ansible.com/ansible/latest/modules/aci_fabric_node_module.html#aci-fabric-node-module>

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
    - aci-fabric-membership

```
WH Standard
-----------

| Status:     | awaiting approval |
|-------------|-------------------|

https://conf.willhillatlas.com/display/ARCH/NET-STD052+-+ACI+Fabric+Membership

License
-------

BSD

Author Information
------------------

Role author: Nick Turner, 2019.  
README author: Nick Turner, 2019. 