aci-backup
==========

Creates ACI configuration export/backup policy and remote location to enable export of the ACI configuration to an external source. 

Requirements
------------

**First Requirement**

The **aci-backup** role applies the required ACI configuration to perform a backup of the ACI configuration policy to each data centre's local NAS cluster. A "remote location" object is created within ACI instance for its local NAS cluster. The NAS cluster contains a number of hosts therefore we use DNS Hostname rather than IP addreses.  

The **aci-dns-providers** role add internal corporate DNS servers to the ACI policy so that the APICs can perform DNS lookups. 

While the **aci-backup** role will complete and successfully create all the necessary objects ACI will be unable to resolve the NAS cluster DNS hostname until the **aci-dns-providers** role has completed and the backups will fail. 


**Second Requirement**

The **aci-scheduler** role must be run prior to this role. This creates the backup _schedule_ that is then associated with the export policy configured under the **aci-backup** role. 

Tasks
-----

This role consists of two seperate task files that are executed in the following order:

main.yml  
aci-backup.yml   

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the aci-backup task.  

The **aci-backup.yml** task contains the actual tasks required to configure the backup policy. This is performed in 3 separate tasks:  

(1/3) Uses the **set_fact** module to perform a lookup in lastpass for password of the backup service account 'svcacibackup' and set as variable: **{{ location_passw }}**.
(2/3) Uses the **aci_rest** module to create a remote location for the NAS cluster in each data centre (calls **{{ location_passw }}** variable from step 1).  
(3/3) Uses the **aci_rest** module to create a parent export policy associating together the remotion location policy and the backup schedule created by the **aci-scheduler** role.

Role Variables
--------------

Example Variable Structure: 

```yaml
dc: "gib"

storage_locations:
  - dest: "{{ dc }}nasmgmt.williamhill.plc"
    path: "/ifs/home/WHGROUP/svcacibackup/"
    protocol: "scp"
    port: "22"
    user: "whgroup\\svcacibackup"
    lpass_entry: "Network Automation AD service account"
    export_name: "{{ dc }}_aci_backup"
    export_sched: "daily_8pm"  
```

This role references the main **aci.yml** group variables file **and** the group variables for each specified environment. 

Example GIB production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/gib_aci.yml  

Example LD6 Lab environment:  
   network_inventory/environments//dev/group_vars/aci.yml  
   network_inventory/environments//dev/group_vars/lab_aci.yml   

In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication against ACI/APICs.
  
This role (task: aci-backup.yml) makes reference to 2 sets of variables: 

<pre>
**dc**                   (dict item)  
**storage_locations**    (list)  
</pre>

The **dc** variable exists inside the group_vars file for each ACI instance (e.g. **gib_aci.yml**, **sc1_aci.yml**). This allows the **storage_locations** list to exist within the main **aci.yml** file as the names of the target NAS cluster and the filename of the backup are the only variables. 


The **storage_locations** list exists inside the **aci.yml** group_vars file and contains the following key/values:

<pre>
dest:             Configures the remote location hostname of IP address.  
path:             Configure the path location on the remote host.  
protocol:         Defines SCP, SFTP etc.  
port:             Defines the TCP port used.  
user:             Defines the user credential for authentication with the remote host.  
lpass_entry:      Defines the entry in lastpass from which Ansible should lookup the password and set as a variable within the playbook.  
export_name:      Defines the filename for the export.  
export_sched:     Associates the pre-configured schedule object with the export policy.  
</pre>

## Dependencies


This role utilises the following **Ansible** modules:
- *[aci_rest](https://docs.ansible.com/ansible/latest/modules/aci_rest_module.html#aci-rest-module)*

- *[set_fact](https://docs.ansible.com/ansible/latest/modules/set_fact_module.html#set-fact-module)*

| **Module(s)** | **New in** | **Tested using** | **Requirements**   |
| ------- | ------- | ---- | --- |
| aci_rest | version 2.4| version 2.8.1| **lxml**, **xmljson**, **python 2.7+** (when using XML payload)  |  
| set_fact | n/a [core] | n/a | n/a |


This role utilises the following pre-written Ansible 'lookup' plugin:

 "lastpass":  
   <https://docs.ansible.com/ansible/latest/plugins/lookup/lastpass.html>

The lastpass plugin performs a lookup in **lastpass** to retrieve the secure password for the **svcacibackup** AD service account required for authentication with each NAS cluster. This password is then stored as a variable within the playbook and used to create the remote location for each NAS cluster within ACI. This credential is stored within William Hill's corporate lastpass instance and specifically within the **Shared-Network** folder that is shared only amongst the Network Services team. 

To be able to successfully retrieve this credential the user running the **aci-backup** role must have the **lpass-cli** application installed on their control machine and have access to the aforementioned shared folder. The user has the option of pre-authenticating to lastpass from the CLI which means the lastpass lookup will occur without any further password prompt, otherwise lastpass will prompt for the user's lastpass credentials when this task is run. 



Example Playbook
----------------
```yaml
---

- name: This play performs switch discovery and configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-backup

```
WH Standard
-----------

| Status:     | awaiting approval |
|-------------|-------------------|

https://conf.willhillatlas.com/display/ARCH/NET-STD055+-+ACI+backup

License
-------

BSD

Author Information
------------------

Role author: Nick Turner, 2019.  
README author: Nick Turner, 2019. 