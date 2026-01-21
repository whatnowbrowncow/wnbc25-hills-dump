aci-snmp
=========

Enables and configures the _Default_ SNMP Policy to include the Solarwinds NMS nodes as ACI management stations and creates a Solarwinds specific SNMP community string. 

Requirements
------------

This role uses the _Default_, Management EPG  for the creation of the SNMP Policy. 

Also note that SNMP depends upon Out-Of-Band Management of the ACI fabric, and the associated Out-Of-Band Contracts.

This role does not configure **Out-Of-Band Management**, it assumes that Out-of-band Management for the ACI fabric is already configured. If you have not yet configured Out-Of-Band Management for the ACI Fabric, do that first. Ensure that your **Out-Of-Band Contracts** permit UDP Port 161.

Tasks
--------------
This role consists of two separate tasks that are executed in the following order:  

+ main.yml
	- **when the OS =** "aci"
+ aci-snmp
  - **Enable the _Default_ SNMP Policy:** Ensures that the _Default_ SNMP Policy is enabled.
	- **Create the SNMP Client Group Policy:** Creates a Client Group Profile named _Solarwinds_ in the _Default_ SNMP Policy, that contains the host names and IP addresses of the Solarwinds nodes.
	- **Create the SNMP Community Policy:** Creates a _Solarwinds_ SNMP Community string.
	- **Confirm the _POD1_ Policy Group:** Confirms that the _POD1_ Policy Group uses the _Default_ SNMP Policy.
	- **Create the SNMP Monitoring Destination Group** Creates a destination SNMP group named _Solarwinds_ for sending SNMP notifications that contains the IP addresses of the Solarwinds nodes.
	- **Create the Default SNMP Monitoring Policy** Creates the SNMP Source object in the Default policy and points to the Solarwinds Destination group for sending notifications.

Role Variables
--------------
Example Variable Structure:

```yaml
snmp:
  - name: "Solarwinds"
    comm_str: "S0larw1nd5"
    servers:
    - host: sc1wnpremn74
      ip_addr: "10.120.163.122"
    - host: sc1wnpremn75
      ip_addr: "10.120.163.123"
    - host: sc1wnpremn77
      ip_addr: "10.120.163.142"
    - host: sc1wnpremn78
      ip_addr: "10.120.163.143"
    - host: ld6wnpremn74
      ip_addr: "10.112.12.125"
    - host: ld6wnpremn75
      ip_addr: "10.112.12.126"
    - host: ld6wnpremn77
      ip_addr: "10.112.12.142"
    - host: ld6wnpremn78
      ip_addr: "10.112.12.143"
    - host: ld6wnpremn79
      ip_addr: "10.112.12.144"
```
This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role makes reference to the "snmp" dictionary. The dictionary is a list with one entry of three variables (_name, comm_str, servers_). 

**NB.** If an environment uses a `group_vars` variables file in addition to the `host-vars` variables file, the SNMP variables should be placed in the `group_vars`. For example, when SNMP servers have been determined for the LD6 prod environment they should be added to `environments/prod/group_vars/aci.yml`.

Dependencies
------------

This role utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module  

This role depends on the seperate role: "aci-oob-contract" to configure the **Out-Of-Band Contract** which permits SNMP connectivity. 

Example Playbook
----------------
```yaml
---

- name: PLAY - ACI SNMP Build
  hosts: aci
  connection: local
  gather_facts: no
  ignore_errors: yes

  roles:
    - aci-snmp
  ```
  WH Standard
-----------

| Status:     | undefined |
|-------------|-----------|

Author Information
------------------

Role author: Chris Hannan, 2019.  
README author: Chris Hannan, 2019.