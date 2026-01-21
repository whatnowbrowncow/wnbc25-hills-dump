aci-bgp-route-reflectors
========================

Sets the Autonomous System number for each ACI instance to the default BGP route reflector policy. Adds all spine switches to the RR policy. 

Requirements
------------

The completion of the **aci-fabric-membership** role is a prerequsite to running this role as the spine switches must be known to the fabric before they can be configured as active route reflectors. Any spine switches to be added to the fabric must be set up as fabric members first. 


Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

**main.yml**  
**aci-bgp-route-reflectors.yml**  

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the **aci-bgp-route-reflectors.yml** task.

The **aci-bgp-route-reflectors.yml** task contains two tasks:  

(1/2) Uses the **aci_rest** Ansible module to configure the default BGP route reflector policy Autonomous System Number (ASN) that is assigned to the infrastructure VRF of the ACI instance.  
(2/2) Uses the **aci_rest** Ansible module to add each spine switch to the default BGP route reflector policy so that all spine switches can perform the role of BGP route reflector.


Role Variables
--------------

Example Variable Structure: 

```yaml
asn: "65001"

fabric_nodes:
  - switch: "uk-ld6-ss01"
    node_id: "201"
    serial: "FOX2120P4BY"
    mgmt_ipv4_addr: "10.112.129.91/24"
    geo_row: "2"
    geo_rack: "d1a"
    role: "spine"      

```

This role  references the main group variables file for the specified site.

Example GIB production:  
   network_inventory/environments//prod/group_vars/gib_aci.yml  
  
Example LD6 production:  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
This role (task: aci-bgp-route-reflectors.yml) makes reference to the **asn** dict item to define the AS number variable. The role then uses the **fabric_nodes** list, and in particular the **node_id** and **role** key/values to ensure that ONLY spine switches are configured as BGP route reflectors and never leaf switches. 


Dependencies
------------


This role utilises the following **Ansible** module:
- *[aci_rest](https://docs.ansible.com/ansible/latest/modules/aci_rest_module.html#aci-rest-module)*

| **Module(s)** | **New in** | **Tested using** | **Requirements**   |
| ------- | ------- | ---- | --- |
| aci_rest | version 2.4| version 2.8.1| **lxml**, **xmljson**, **python 2.7+** (when using XML payload)  |


Example Playbook
----------------
```yaml
---

- name: This play performs switch discovery and configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-bgp-route-reflectors

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