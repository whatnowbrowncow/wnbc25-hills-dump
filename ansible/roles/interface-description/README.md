Interface Descriptions
======================

There are two purposes of this role: 

- 1) AUDIT -- Audit the IOS and NXOS estate, collect the UP interfaces, check if the UP interface has a interface description, if empty check the CDP database for a known entry, if there is a CDP entry (matching on interface IDs e.g. ethernet1/1) collect the data and register it in YAML, else if there's no entry mark the interface as no_cdp_data. 

- 2) CONFIGURE -- Push out the suggested configuration from the second YAML dataset and update the interface descriptions.


Requirements
------------

None. (Although see dependencies.) 


Tasks
-----

This role consists of five separate tasks:  

main.yml
ios-report.yml  
ios-standardise.yml  
nxos-report.yml  
nxos-standardise.yml    

```yaml
---

- name: Import Network Parser role
  include_role:
    name: ansible-network.network-engine

- name: IOS - Gather Interface Status For all UP Interfaces with No Description
  include_tasks: ./ios-report.yml
  when: ansible_network_os == "ios"

- name: IOS - Config Task - Build Interface Descriptions
  include_tasks: ./ios-standardise.yml
  when: ansible_network_os == "ios"

- name: NX0S - Gather Interface Status For all UP Interfaces with No Description
  include_tasks: ./nxos-report.yml
  when: ansible_network_os == "nxos"

- name: NXOS - Config Task - Build Interface Descriptions
  include_tasks: ./nxos-standardise.yml
  when: ansible_network_os == "nxos"
```

#### Some specific notes on the playbook and report tasks:

This role is more of a utility to audit interface descriptions, provide a CSV report and suggest a valid configuration if there is a match in the CDP database. I've used YAML structured datasets as staging files to manipulate and hold data which are consumed for the CSV generation and pushing configuration back out to the estate.

The reporting tasks have a dependency on the Genie Parser (role called - clay584.parse_genie) to collect facts from the network estate. In this case for IOS we collect configuration state for 'interface description' and 'cdp neighbour'. For NXOS we collect configuration state for 'interface description', 'cdp neighbour' and 'interface status'.

Each time the report tasks are run all staging files are removed. Only the config-dataset is retained which is consumed by the config tasks ios-standardise.yml for pushing suggested configuration out to our estate. Once ios-standardise.yml is executed the config-dataset YAML is deleted.

At this point the play can be run on demand to check the estate again.


Role Variables
--------------

YAML datasets for this role are transient; they are created and then removed during the playbook run by design.  
While present, the variable files are nested within a directory named after the relevant host.

Example vars files:
```
environments/prod/host_vars/uk-brs-er01/final-dataset.yml
environments/prod/host_vars/uk-brs-er01/config-dataset.yml
```

final-dataset.yml  - dataset for reporting state only
config-dataset.yml - dataset for configuration deployment

Both YAML datasets use exactly the same structure.

Example Variable Structure:  
```yaml
final_state:
  - interface: "GigabitEthernet0/0"
    interface_description: "uk-cwk-vacc01.network.williamhill.plc-GigabitEthernet2/0/2"
  - interface: "GigabitEthernet0/1"
    interface_description: "no_cdp_data" 
```


Dependencies
------------

Install pyats and genie by issuing:

```
pip install pyats
pip install genie
```

NOTE - genie will not work with Python 3.9 and above.

| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements** |  
| -------------- | ----------- | ---------------- | ------------------------- | ---------------- |  
| ios_config     | version 2.1 | version 2.8.6    | 3.8.5                     | none             |  
| nxos_config    | version 2.1 | version 2.8.6    | 3.8.5                     | none             | 
| pyats          | version 2.7 | version 2.8.6    | 3.8.5 pyats 20.12         | none             |
| genie          | version 2.7 | version 2.8.6    | 3.8.5 genie 20.12.2       | none             |


This role is dependent on the following roles:

The role will be part of master, you will see a role called - clay584.parse_genie

| **Role**            | **Version** | **Requirements** |
| ------------------- | ----------- | ---------------- |
| clay584.parse_genie | 1.5.2+      | pyats + genie    |

See documentation for parse_genie here: <https://github.com/clay584/parse_genie>

There is also a dependency on enabling Jinja2 extensions in `ansible.cfg`. This enabled loop controls such as break and continue in the Jinja2 templates. Again, these changes will be part of master in ansible.cfg.

```
jinja2_extensions = jinja2.ext.do,jinja2.ext.i18n,jinja2.ext.loopcontrols
```

#### IOS

Tasks: ios-report.yml and utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: ios-report.yml uses a Jinja2 template to generate a staging file for interface descriptions and UP only interfaces.  
    `{{ role_path }}/templates/ios/int-desc-template.j2`

Task: ios-report.yml uses a Jinja2 template to generate a staging file for the cdp database.  
    `{{ role_path }}/templates/ios/cdp-template.j2`

Task: ios-report.yml uses a Jinja2 template to generate a staging to combine UP Interfaces with no descriptions and ties in a CDP entry (matching on interface ID's) if present, if not add no_cdp_data.   
    `{{ role_path }}/templates/ios/final-template.j2`

Task: ios-report.yml uses a Jinja2 template to generate a staging file for UP Interfaces with no description with a valid interface match from the CDP database. This staging file will be used for pushing configuration out to the estate  
    `{{ role_path }}/templates/ios/config-template.j2`

Task: ios-report.yml uses a Jinja2 template to generate a csv report containing data from the final-template.j2 which can be consumed to report on and identify interfaces that need attention either via automation or manual attention
    `{{ role_path }}/templates/ios/csv-template.j2`


Task: ios-config.yml utilises the pre-written Ansible module "ios_config":  
    <https://docs.ansible.com/ansible/latest/modules/ios_config_module.html#ios-config-module>  

#### NXOS

Tasks: nxos-report.yml and nxos-yaml.yml utilise the pre-written Ansible module "command_parser" contained within the role "ansible-network.network-engine":  
    <https://galaxy.ansible.com/ansible-network/network-engine>  

Task: nxos-report.yml uses a Jinja2 template to generate a staging file for interface status for UP interfaces.  
    `{{ role_path }}/templates/nxos/int-status-template.j2`

Task: nxos-report.yml uses a Jinja2 template to generate a staging file for interface descriptions.  
    `{{ role_path }}/templates/nxos/int-desc-template.j2`

Task: nxos-report.yml uses a Jinja2 template to generate a staging file for the cdp database.  
    `{{ role_path }}/templates/nxos/cdp-template.j2`

Task: nxos-report.yml uses a Jinja2 template to generate a staging to combine UP Interfaces with no descriptions and ties in a CDP entry (matching on internet ID's) if present, if not add no_cdp_data.   
    `{{ role_path }}/templates/nxos/final-template.j2`

Task: nxos-report.yml uses a Jinja2 template to generate a staging file for UP Interfaces with no description with a valid interface match from the CDP database. This staging file will be used for pushing configuration out to the estate  
    `{{ role_path }}/templates/nxos/config-template.j2`

Task: nxos-report.yml uses a Jinja2 template to generate a csv report containing data from the final-template.j2 which can be consumed to report on and identify interfaces that need attention either via automation or manual attention
    `{{ role_path }}/templates/nxos/csv-template.j2`

Task: nxos-config.yml utilises the pre-written Ansible module "nxos_config":  
    <https://docs.ansible.com/ansible/latest/modules/nxos_config_module.html#nxos-config-module>

This task also uses a Jinja2 template to generate the local user account configuration.  
    `/ansible/roles/syslog/templates/nxos/config-template.j2`  


Example Playbook
----------------

Play: play_interface_description.yml

```yaml
---
- name: "IOS - NXOS - Check and Deploy Service Hardening on IOS and NX-OS"
  hosts: nxos, ios
  gather_facts: no
  connection: network_cli

  # This applies all device hardening configuration to IOS and NX-OS 

  roles:
    - role: interface-description
```


WH Standard
-----------

| Status:     | Approved  |
|-------------|-----------|

 

| Status:     | Draft     |
|-------------|-----------| 


License
-------

BSD


Author Information
------------------

Role authors: Garry Richardson 2021.  
README authors: Garry Richardson 2021. 
