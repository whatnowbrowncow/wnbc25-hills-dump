asa-base
========
This role builds a base, best practice configuration on the ASA context firewalls.

Items configured by running this role:

- Syslog
- Custom global_policy map (inspect ftp, tftp, icmp, icmp error and DCD)
- Antispoofing
- Custom ICMP configuration (rate-limiting, ACLs)
- SNMP

## Dependencies


This role utilises the **Ansible** module *[asa_config](https://docs.ansible.com/ansible/latest/modules/asa_config_module.html#asa-config-module)*:

| **New in** | **Tested using** | **Requirements**   |
| ------- | ---- | --- |
| version 2.2| version 2.8.1|  *none*    |