Device-Hardening
=========

The purpose of this role is to check and implement service and process hardening to confirm that devices comply with [NET-STD041 - Base Build IOS, IOS-XE and NX-OS][1]. Where a device doesn’t comply it is updated with the relevant configuration. This was organised under Jira ticket: [NETAUTO-256][2].

Each OS configuration is separated into five sections of checks and configuration:  
* Checks if IP Helper/DHCP relay/dhcp pool commands are configured and if not removes the DHCP service
* Check for OS/Version specific changes and configures where necessary 
* Implemented the default configuration across all devices where required 
* Records what changes have been made in /configs/
* Saves the configuration to startup-config

Requirements
------------

None. (Although see dependencies.)

Tasks
-----

This role consists of nine separate tasks:

main.yml

ios-config.yml
ios-individual-commands.yml
ios-report-output.yml
ios-save.yml

nxos-config.yml
nxos-individual-commands.yml
nxos-report-output.yml
nxos-save.yml

main.yml is executed first, Then two of the remaining eight tasks are executed from within main.yml depending on the `ansible_network_os` variable of the particular host. Within ios/nxos-individual-commands.yml there is a call to the relevant ios/nxos-report-output.yml various times to record the configurations applied. Next ios/nxos-config.yml is run. At the end of the play, ios/nxos-config.yml calls ios/nxos-save.yml to save any changed configuration.

NOTE: The ios/nxos-report-output.yml will save a file to the `roles/device-hardening/files/` directory. The role checks if this directory exists first if not creates it. These tasks will run even in check mode is specified due to the check_mode: no configuration.

```yaml
---
# Applies Deploying Router Specific Hardening on IOS
- name: IOS - Deploying Hardening Configuration if individual device configuration
  include_tasks: ./ios-individual-commands.yml
  when: ansible_network_os == "ios"

# Applies global Configuration on IOS
- name: IOS - Deploying Service Hardening Configuration
  include_tasks: ./ios-config.yml
  when: ansible_network_os == "ios"

# Applies Deploying Router Specific Hardening on NXOS
- name: NXOS - Deploying Hardening Configuration if individual device configuration
  include_tasks: ./nxos-individual-commands.yml
  when: ansible_network_os == "nxos"

# Applies relevent Configuration on NXOS
- name: NXOS - Deploying Service Hardening Configuration
  include_tasks: ./nxos-config.yml
  when: ansible_network_os == "nxos"
```

Role Variables
--------------

There are no specific role variables used within this

Dependencies
------------

| **Module(s)** | **New in**  | **Tested using** | **Python version tested** | **Requirements** |
| ------------- | ----------- | ---------------- | ------------------------- | ---------------- |
| ios_config    | version 2.1 | version 2.8.5    | 2.7.12                    | none             |
| nxos_config   | version 2.1 | version 2.8.5    | 2.7.12                    | none             |


Example Playbook
----------------
``` yaml
Play: play_device_hardening.yml
---
- name: "IOS - NXOS - Check and Deploy Service Hardening on IOS and NX-OS"
  hosts: ios,nxos
  gather_facts: no
  connection: network_cli

  # This applies all device hardening configuration to IOS and NX-OS 

  roles:
    - role: device-hardening
```

WH Standard
-----------

| Status:     |           |
|-------------|-----------|

[NET-STD041 - Base Build IOS, IOS-XE and NX-OS](https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS)  

License
-------

BSD

Author Information
------------------

Role authors: Chris Stafford 2020.  
README authors: Chris Stafford 2020.  

[1]: https://conf.willhillatlas.com/display/ARCH/NET-STD041+-+Base+Build+IOS%2C+IOS-XE+and+NX-OS#NET-STD041-BaseBuildIOS,IOS-XEandNX-OS-3.2SystemServices&Processes
[2]: https://jira.willhillatlas.com/browse/NETAUTO-256
