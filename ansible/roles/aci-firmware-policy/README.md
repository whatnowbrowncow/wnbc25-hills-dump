aci-firmware-policy
===================

This role creates the below ACI objects required to perform a firmware upgrade of the fabric switches. The actual upgrade of the switches is not executed by this role. 

- firmware policy
- firmware group
- maintenance policy
- maintenance groups

A single firmware policy group is created called 'all' as we expect all fabric switches to be on the same firmware version. 

Two maintenance groups are created; 'odd' and 'even'. The switches are distributed across these two groups dependant on the switch's node ID. 

The schedule used by the maintenance group **maint_group_upgrade_manual_trigger** does not have an execution window configured. This means that the maintenance groups must be run manually by the ACI administrator. 

Requirements
------------

There are a number of pre-requisites prior to execution of the **aci-firmware-policy** role. 

**Pre-requisite 1**

The **aci-fabric-membership** role must have already been executed to associate all fabric switches with ACI. This role will add switches to the firmware and maintenance groups - the switches must be known to ACI before they can be added to these groups. 

**Pre-requisite 2**

The **aci-scheduler** role must have already been executed to pre-configure the upgrade schedule that will be referenced by the maintenance group created by this role. 

**Pre-requisite 3**

The relevant switch firmware must have been uploaded to the APIC firmware repository and the **firmware_version** variable updated to reflect this change before this role can be executed. This is a manual task by an ACI and Ansible administrator. 

At time of writing (July 2019) the **firmware_version** variable is defined as "n9000-13.2(4e)" which is the current ACI switch firmware version across all ACI instances on the WH estate.

**Pre-requisite 4**

The fabric switches must not already belong to an existing firmware or maintenance group. This will cause the aci_maintenance_group_node and aci_firmware_group_node modules to fail. Each switch/node can only belong to one firmware group and one maintenance group. 

Tasks
-----

This role consists of two separate tasks that are executed in the following order:

**main.yml**
**aci-firmware-policy.yml**

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the **aci-firmware-policy.yml** task.

The **aci-firmware-policy.yml** task contains the following 6 tasks:

(1/6) Creates the firmware policy and assigns the firmware version
(2/6) Creates the 'all' firmware group and associates the firmware policy
(3/6) Associates all fabric switches/nodes with the 'all' firmware group
(4/6) Creates the maintenance policy
(5/6) Creates the 'odd' and 'even' maintenance groups
(6/6) Associates the fabric switches with the maintenance groups based on their node-id number (e.g. odd or even). 

Role Variables
--------------

Example Variable Structure: 

```yaml
firmware_group: "all"
firmware_version: "n9000-13.2(4e)"

maint_groups:
  - name: "even"
    graceful: "true"
    sched: "maint_group_upgrade_manual_trigger"
  - name: "odd"
    graceful: "true"  
    sched: "maint_group_upgrade_manual_trigger"
```

This role references the main **aci.yml** group variables file **and** the group variables for each specified environment. 

Example GIB production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/gib_aci.yml  

Example LD6 Lab environment:  
   network_inventory/environments//dev/group_vars/aci.yml  
   network_inventory/environments//dev/group_vars/lab_aci.yml   

In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication against ACI/APICs.
  
This role (task: aci-backup.yml) makes reference to 4 sets of variables: 

<pre>
**firmware_group**              (dict item)  		(aci.yml)
**firmware_version**    	     	(dict_item)  		(aci.yml)
**maint_groups**	              (list)  			  (aci.yml)
**fabric_nodes**				        (list)				  ('environment'_aci.yml)   (eg. gib_aci.yml)
</pre>
 
The **maint_groups** list contains the '_name_', '_graceful_' and '_sched_' variable key/values used to define following:

<pre> 
'_name_', 						Name of the maintenance groups.
'_graceful_'					Defines whether the switches are taken down for upgrade gracefully. Default is no.
'_sched_'             Defines the schedule created by the **aci-scheduler** role. 
</pre>

The **fabric_nodes** list contains the '_maint_group_' and '_node_id_' variable key/values.  

These two values are used to determine which switch belongs to which maintenance group.  

<pre> 
'_maint_group_'  
'_node_id_'   
</pre>


Dependencies
------------

Minimum version ansible version 2.8  
Tested using ansible version 2.8.1  

This role (task: aci-firmware-policy.yml) utilises the following pre-written Ansible modules:

 "aci_firmware_policy":  
   <https://docs.ansible.com/ansible/latest/modules/aci_firmware_policy_module.html#aci-firmware-policy-module>

 "aci_firmware_group":  
   <https://docs.ansible.com/ansible/latest/modules/aci_firmware_group_module.html#aci-firmware-group-module>

 "aci_firmware_group_node":  
   <https://docs.ansible.com/ansible/latest/modules/aci_firmware_group_node_module.html#aci-firmware-group-node-module>

 "aci_maintenance_policy":  
   <https://docs.ansible.com/ansible/latest/modules/aci_maintenance_policy_module.html#aci-maintenance-policy-module>

 "aci_maintenance_group":  
   <https://docs.ansible.com/ansible/latest/modules/aci_maintenance_group_module.html#aci-maintenance-group-module>

 "aci_maintenance_group_node":  
   <https://docs.ansible.com/ansible/latest/modules/aci_maintenance_group_node_module.html#aci-maintenance-group-node-module>            

Example Playbook
----------------
```yaml
---

- name: This play performs switch discovery and configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-firmware-policy

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