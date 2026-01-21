aci-scheduler
=============

This role creates schedule objects such as the daily ACI configuration backup to NAS schedule and the maintenance schedules for upgrades/downgrades. The schedules are created here first to define the date/time of execution. The schedules are then later associated with other objects such as the backup/maintenance policies under a separate role. 

Requirements
------------

None


Tasks
-----

This role consists of two seperate task files that are executed in the following order:

main.yml  
aci-scheduler.yml   

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the aci-scheduler task.  

The **aci-scheduler.yml** task contains the actual task to configure the schedules policy objects utilising the **aci_fabric_scheduler** Ansible module. 


Role Variables
--------------


Example Variable Structure: 

```yaml
schedules:
  - maint_group_upgrade_manual_trigger
  - sched_name: "daily_aci_policy_backup_to_nas"
    window_name: "daily_8pm"
    hour: "20"
    minute: "00"
```

This role references the main **aci.yml** group variables file:

Example GIB production:  
   network_inventory/environments//prod/group_vars/aci.yml  

Example LD6 Lab environment:  
   network_inventory/environments//dev/group_vars/aci.yml  

In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication against ACI/APICs.
  
This role (task: **aci-scheduler.yml**) makes reference to the following list of variables: 

The **schedules** list exists inside the **aci.yml** group_vars file and contains the following key/values:

<pre>
sched_name:       Defines a name for the schedule object. (This object is referenced by other policies such as export policies etc.) 
window_name:      Defines a name for the schedule window.    
hour:             Defines the hour at which the schedule commences.  
minute:           Defines the minite at which the schedule commences. 
recur:            Boolean response 'yes' or 'no' to whether the schedule is set to be recurring. **Note - this variable is currently absent from the vars files as the default is 'yes' **

</pre>

Schedules such as the "daily_aci_policy_backup_to_nas" utilise a backup window for execution during a specific time window.  

The maintenance group schedule (used for firmware upgrade) does not require a window to be configured as the maintenance groups are triggered manually. 

The '_hour_', '_minute_', '_window_name' and '_recurring_' parameters are required for creation of schedule windows. When the variables for these parameters are not found this causes the module to fail. Therefore, the  **default(omit)** filter has been applied to these parameters so that if the variables are not present the parameters are ignored and the module does not attempt to configure a schedule window. See the example variable structure above for clarification. 

```yaml
hour: "{{ item.hour | default(omit) }}" 
minute: "{{ item.minute | default(omit) }}"
windowname: "{{ item.window_name | default(omit) }}"
recurring: "{{ item.recur | default(omit) }}"
```

Dependencies
------------

Minimum ansible version: 2.8.1
Tested with ansible version: 2.8.1

This role (task: **aci-scheduler.yml**) utilises the **aci_fabric_scheduler** Ansible module only.


Example Playbook
----------------
```yaml
---

- name: This play performs switch discovery and configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-scheduler

```
WH Standard
-----------

| Status:     | awaiting approval |
|-------------|-------------------|
1
TBC

License
-------

BSD

Author Information
------------------

Role author: Nick Turner, 2019.  
README author: Nick Turner, 2019. 