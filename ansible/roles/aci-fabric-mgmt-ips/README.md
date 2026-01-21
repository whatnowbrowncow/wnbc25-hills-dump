aci-fabric-mgmt-ips
===================

Configures out-of-band management IPv4 addresses for all fabric nodes including APIC servers, spine and leaf switches. 

Requirements
------------

There are no pre-requisites for this role. The management IPv4 addresses can be configured for all nodes before they are even associated with the fabric. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:  

main.yml  
aci-fabric-membership.yml   

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the aci-fabric-mgmt-ips task.  

The **aci-fabric-mgmt-ips.yml** task contains a single task using the **aci_rest** Ansible module to provision the management IPv4 addresses for each node.  


Role Variables
--------------

Example Variable Structure: 

```yaml
fabric_nodes:
  - switch: "gi-mpl-ls02"
    node_id: "102"
    serial: "FDO22480P7V"
    mgmt_ipv4_addr: "10.180.129.102/24"
    geo_row: "4"
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
  
This role (task: aci-fabric-mgmt-ips.yml) makes reference to the **fabric_node** list in group_vars for the **mgmt_ipv4_addr** and **node_id** variable values. The **mgmt_ipv4_gway** variable is a dict item in group_vars. 


Dependencies
------------

This role (task: aci-fabric-mgmt-ips.yml) utilises the following pre-written Ansible module:

 "aci_rest":  
   <https://docs.ansible.com/ansible/2.4/aci_rest_module.html>


Example Playbook
----------------
```yaml
---

- name: Configure management IP addresses for all ACI fabric switches.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-fabric-mgmt-ips

```
WH Standard
-----------

| Status:     | awaiting approval |
|-------------|-------------------|

https://conf.willhillatlas.com/display/ARCH/NET-STD054+-+ACI+Fabric+Mgmt+IPs

License
-------

BSD

Author Information
------------------

Role author: Nick Turner, 2019.  
README author: Nick Turner, 2019. 