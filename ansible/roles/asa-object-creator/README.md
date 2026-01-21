# asa-object-creator
## version: 1.0

The purpose of this role is to understand the objects and group configuration on ASA devices. Then parse the information into a JSON data structure and use it to report, document and produce a configuration (cfg) file of the objects and groups. This is carried out in three stages:

* parse the existing device configuration 
* using the parser, generate a YAML file to document the existing configuration.
* create cfg file with the object and group configurtion in it, using the varibles defined in the YAML file

It is necessary to carry out these steps on existing devices that already contain object configuration. For new devices the YAML data will need to be populated manually and only the final configuration task run. 

## Requirements

If an error is produced while running the asa_command saying that imp is not avaible then add the following to the asa_command.py file located within the module directory

>**Note** The location module directory can be found by typing ansible --version in your developemnt enviroment
```python
try:
   from importlib import import_module

except ImportError:
    import_module = __import__
    import imp
```

## Role Variables

This role consists of 5 separate tasks:  

* main.yml
* asa-single-yaml.yml
* asa-single-config.yml
* asa-multiple-yaml.yml
* asa-multiple-config.yml

**main.yml** is executed first, the ansible-network.network-engine role containing the `command_parser` is imported at this stage. Two of the remaining four tasks are then executed from within main.yml depending on the `ansible_network_os` variable of the particular host:


```yaml
---
- name: Import network parser role
  include_role:
    name: ansible-network.network-engine
    
- name: ASA-SINGLE - object parser YAML creation task.
  include_tasks: ./asa-single-yaml.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-SINGLE - network object creation task.
  include_tasks: ./asa-single-config.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-MULTIPLE -  object parser YAML creation task.
  include_tasks: ./asa-multiple-yaml.yml
  with_items:
    - "{{ contexts }}"
  when: ansible_network_os == "asa" and context_mode == "multiple"

- name: ASA-MULTIPLE - network object creation task.
  include_tasks: ./asa-multiple-config.yml
  with_items:
    - "{{ contexts }}"
  when: ansible_network_os == "asa" and context_mode == "multiple"
```

>**Note:** The *asa-\<type\>-config.yml* tasks do not configure the device but instead produce a cfg stored in the /file/\<context\>/ within the roles/asa-object-creator directory. The files contain config for use by an experianced engineer and should be used with the same considrations as if it was to be done manually. Features to automatically add the rules will be in future versions of this code.

## Role Variables

Example Variable Structures:

This role currently references different variable file locations depending on the platform

Within the single asa the folder layout is 

### ASA Single
```
📦environments
 ┣ 📂prod
 ┃ ┣ 📂host_vars
 ┃ ┃ ┣ 📂uk-brs-vpn-fw01-pri
 ┃ ┃ ┃ ┣ 📜network_objects.yml
 ┃ ┃ ┃ ┣ 📜protocol_objects.yml
 ┃ ┃ ┃ ┣ 📜snmp.yml
 ┃ ┃ ┃ ┣ 📜svc_objects.yml
 ┃ ┃ ┃ ┗ 📜uk-brs-vpn-fw01-pri.yml
```
>**Note:** the location of the variable files are nested within a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced.  
Within the multiple asa the folder layout will be

### ASA Multiple
📦environments
 ┣ 📂prod
 ┃ ┣ 📂host_vars
 ┃ ┃ ┣ 📂uk-brs-vpn-fw01-pri
 ┃ ┃ ┃ ┣ 📂context
 ┃ ┃ ┃ ┃ ┣ 📜network_objects.yml
 ┃ ┃ ┃ ┃ ┣ 📜protocol_objects.yml
 ┃ ┃ ┃ ┃ ┣ 📜snmp.yml
 ┃ ┃ ┃ ┃ ┣ 📜svc_objects.yml
 ┃ ┃ ┃ ┃ ┗ 📜uk-brs-vpn-fw01-pri.yml

>**Note:** the location of the variable files are nested within a context directory in a directory named after the relevant host. This is to allow multiple YAML files to be created for each host, each one containing variables for a specific element of the device configuration. It is important that **ALL** host specific YAML files are nested in this single location otherwise they will not be referenced, as these are imported in the start of a role and placed into specfic varibles

The varible yaml files are the same regardless of the asa type and theses are as follows

### network_objects
```yaml
---

network_objects:

  host_objects:
    - name: "mngz-aq1"
      description: ""
      ip_addr: "172.21.252.47"
      type: "host"
   - name: "net-obj-nyx-P34-6"
      description: ""
      network: "10.118.25.0"
      mask: "255.255.255.0"
      type: "subnet"

  range_objects:
    - name: "obj-172.31.96.129-172.31.96.254"
      description: ""
      start: "172.31.96.129"
      end: "172.31.96.254"
      type: "range"  

network_object_groups:
  - name: "Alphameric"
    objects:
      - object_name: "uscxops01ops001.aws-us-east-1.usc.williamhill.plc"
      - object_name: "uspxops01ops001.aws-us-east-1.usp.williamhill.plc"
    hosts:
      - ip_addr: "10.208.192.53"
      - ip_addr: "10.208.7.11"
      - ip_addr: "10.208.7.12"    
    networks:
      - ip_addr: "172.30.5.0"
        mask: "255.255.255.0"
      - ip_addr: "172.30.16.0"
        mask: "255.255.255.0"
    group_objects:
      - group_object_name: "RFC1918-nets"
```

### protocol_objects
```yaml
---

protocol_object_groups:
  - name: "TCPUDP"
    objects:
      - object_name: "udp"
      - object_name: "tcp"
    group_objects:
```

### svc_objects
```yaml
---

service_objects:

  - name: "infoblox-vpn-1"
    description: ""
    protocol: "udp"
    direction: "destination"
    port_type: "eq"
    port: "1194"
    range_start: ""
    range_end: ""

service_object_groups:
  - name: "HTTP8080"
    protocol: "tcp"
    objects:
    services:
    port_objects:
      - port_type: "eq"
        port: "8080"
        range_start: ""
        range_end: ""
      - port_type: "eq"
        port: "www"
        range_start: ""
        range_end: ""
    group_objects:
```
## Command_Parser files

### ASA Single and Multiple

Task: asa-\<type\>-yaml.yml uses the following parser files to extract configuration data:\
`parser_templates/asa_<type>/parser_asa_<type>_objects_network.yml`\
`parser_templates/asa_<type>/parser_asa_<type>_object_groups_network_split.yml`\
`parser_templates/asa_<type>/parser_asa_<type>_object_groups_network.yml`\
`parser_templates/asa_<type>/parser_asa_<type>_objects_service.yml`\
`parser_templates/asa_<type>/parser_asa_<type>_object_groups_service_split.yml`\
`parser_templates/asa_<type>/parser_asa_<type>_object_groups_service.yml`\
`parser_templates/asa_<type>/parser_asa_<type>_object_groups_protocol_split.yml`\
`parser_templates/asa_<type>/parser_asa_<type>_object_groups_protocol.yml`

## Dependencies

NOTE: The Templates and some tasks within this role have a dependency within the asa-ras-object role and any changes made to the template must include testing of BOTH roles

| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements**                    |
| -------------- | ----------- | ---------------- | ------------------------- | ----------------------------------- |
| asa_command    | version 2.4 | version 2.8.6    | 3.6.9                     | none                                |
| command_parser | version 2.7 | version 2.8.6    | 3.6.9                     | ansible-network.network-engine role |

>**Note:** on the asa-single-config.yml if the \<object type\>.yml files have not been created prior, using the YAML creation tasks, the first run of the this role will fail on the first run but succeed on the second. This is because Ansible checks the files are present at the start of the playbook run, but the \<object type\>.yml files are not created and available to Ansible until midway through the first run of the run of the role.  

Example Playbook
----------------
Play: play_asa-object-parser.yml
```yaml
---

- name: PLAY - Parse, report  object and group configuration
  hosts: asa
  gather_facts: no
  connection: network_cli

  roles:
    - asa-object-creator
```

License
-------

BSD

Author Information
------------------

**Role authors**: David Burton (ASA-single 2020), Chris Stafford (ASA-Single 2020), (ASA-Multiple 2020) & Giles Falkingham (ASA-Single 2020), (ASA-Multiple 2020).\
**README authors**: Chris Stafford (2020)


