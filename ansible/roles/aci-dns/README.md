aci-dns
=======

Add IP addresses of Infoblox DNS servers across the estate to the default DNS profile for each ACI instance. The local name server to the data centre is set as 'preferred'. 

**NOTE** : ACI will only allow one name server to be configured as preferred. 

Requirements
------------

None

Tasks
-----

This role consists of two seperate task files that are executed in the following order:  

**main.yml**
**aci-dns.yml**   

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the **aci-dns.yml** task.  

The **aci-dns.yml** task uses the **aci_rest** module to configure the name servers and mark as preferred or not. 


Role Variables
--------------

Example Variable Structure: 

```yaml
dns_servers:
  - ip_addr: "10.112.208.11"    
    preferred: "true"  
  - ip_addr: "10.112.208.12"  
  - ip_addr: "10.120.193.235"
  - ip_addr: "10.210.193.235"
```

This role references the the group variables for each ACI instance:

Example GIB production:  
   network_inventory/environments//prod/group_vars/gib_aci.yml  

Example LD6 Lab environment:  
   network_inventory/environments//dev/group_vars/lab_aci.yml   

In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication against ACI/APICs.
  
This role (task: **aci-dns.yml**) makes reference to the **dns_servers** list which exists in the ACI group_vars per data centre (e.g ld6_aci, gib_aci). Note that this list is different for each site to reflect the preference of the local name server to that data centre. 

The **dns_servers** list contains the following key/values. There are four name servers configured for each site:

<pre>
**ip_addr**       Lists the DNS server IP addresses per data centre. 
**preferred**     Defines whether the name server is preferred (the 'default' value is 'false' so this variable is only present under the preferred name server).
</pre>

Dependencies
------------

This role (task: **aci-dns.yml**) utilises the **rest_aci** Ansible module.


Example Playbook
----------------
```yaml
---

- name: This play performs switch discovery and configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-dns

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