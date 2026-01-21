# vmc-conversions

The purpose of this role is to parse Cisco ASA firewalls of their access-list configuration and transpose it to YAML and Terraform configuration files. Storing ASA access-list configuration in YAML allows for a vendor neutral format, offline backup and source of truth. Storing ASA access-list configuration in Terraform format will allow us to redeploy a complete ASA ruleset to a VMC distributed firewall (DFW). 

Not only do the access-lists need to be parsed, but all objects and object-groups, for both networks and services, that are referenced in an access-entry also need to be parsed and transposed to YAML and Terraform configuration files.

YAML configuration files:

* **_dfw_sddc_specific_groups.yml:_** Contains the network-objects and network-object-groups found on the ASA transposed into YAML format. 
* **_dfw_sddc_specific_ports.yml:_** Contains the service-objects and service-object-groups found on the ASA transposed into YAML format. 
* **_dfw_sddc_specific_rules.yml:_** Contains the access-lists found on the ASA transposed into YAML format. 

Terraform configuration files:

* **_dfw_sddc_specific_groups.tf:_** Contains the `nsxt_policy_group` resource, used to define IP address and network objects in VMC.
* **_dfw_sddc_specific_ports.tf:_** Contains the `nsxt_policy_service` resource, used to define Protocol/Port objects in VMC.
* **_dfw_sddc_specific_rules.tf:_** Contains the `nsxt_policy_security_policy` resource, used to define rules in VMC.

The ASA configuration parsing and YAML / Terraform file generation is carried out in following stages

1. Parse the existing ASA configuration for all access-lists, network objects/object-groups and service objects/object-groups. 
2. Generate a 'human-readable' **YAML** file to document the existing configuration.
3. Convert the **YAML** file to generate a **Terraform** configuration file.

Due to the size and complexity of this role, additional information can be found on the following Confluence page:  
[Role - vmc-conversions - Instructions for use](https://conf.willhillatlas.com/pages/viewpage.action?pageId=856031717)

## Requirements

None. (Although see dependencies.)

## Tasks

This role consists of 10 separate tasks:

```bash
roles/vmc-conversions/tasks/
├── main.yml                       # Executed first and imports the `command_parser` role
├── asa-multiple-vmc-all-yaml.yml  # Runs the parser against a multi-context ASA; uses Jinja2 templates to create 3x YAML files; 'groups', 'ports', and 'rules'
├── asa-multiple-vmc-all-tf.yml    # References YAML files created by this role; uses Jinja2 templates to create 3x Terraform files; 'groups', 'ports', and 'rules'
├── asa-single-vmc-groups-yaml.yml # Runs the parser against a single-context ASA; uses a Jinja2 template to create 1x YAML file; 'groups'
├── asa-single-vmc-groups-tf.yml   # References the 'groups' YAML file already created by this role; uses a Jinja2 template to create 1x Terraform file; 'groups'
├── asa-single-vmc-ports-yaml.yml  # Runs the parser against a single-context ASA; uses a Jinja2 template to create 1x YAML file; 'ports'
├── asa-single-vmc-ports-tf.yml    # References the 'ports' YAML file already created by this role; uses a Jinja2 template to create 1x Terraform file; 'ports'
├── asa-single-vmc-rules-yaml.yml  # Runs the parser against a single-context ASA; uses a Jinja2 template to create 1x YAML file; 'rules'
├── asa-single-vmc-rules-tf.yml    # References the 'rules' YAML file already created by this role; uses a Jinja2 template to create 1x Terraform file; 'rules'
└── asa-multiple-config-count.yml  # Optional; can be run seperately to count the number of relevant objects on the ASA
```

#### nsxt_policy_group (ASA network objects and object-groups)

**Source:** https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_group

This VMC resource provides a method for the management of an inventory Group and its members. Groups are used as sources and destinations within the rules of the Security Policy.

> **Note:** Unlike Cisco ASA, the VMC DFW does not differentiate between network objects/object-groups and everything is a **policy group**.

* A group consisting of a single member that is an individual IP Address, ranges of IP Addresses or subnets would be a network object on Cisco ASA.
* A group consisting of a list of members, each one a group in it's own right, would be a network object-group on Cisco ASA.

All groups include the following fields:

* `resource` - Name of the resource type (`nsxt_policy_group`) followed by the name of the network object.
* `display_name` - Display name of the resource. Set to be identical to the `resource`.
* `domain` - The domain to use for the Group. Set to `cgw` for VMware Cloud on AWS.
* `criteria` - A repeatable block to specify criteria for members of this Group.

##### Single member groups (ASA Network Object)

Includes the following fields:

* `description` - Description of the resource. Must contain the "role" and "ip" keys (this format is to aid later computer based extraction):
  * `role:` - Set to the parsed object description or if none, that of the `display_name`.
  * `ip:` - Lists the IP addresses/networks (CIDR) defined in the object in a comma separated format
* `criteria`
  * `ipaddress_expression` - An expression block to specify individual IP Addresses, ranges of IP Addresses or subnets for this Group.
    * `ip_addresses` - List of a single IP address, IP address range or a subnet.

**Example network object and criteria block:**

```json
resource "nsxt_policy_group" "pr-r-frontend_rt2_till_range_1" {
   display_name = "pr-r-frontend_rt2_till_range_1"
   description = "role: CHG0141028, ip: [10.93.137.112/28]"
   domain       = "cgw"
   criteria {
     ipaddress_expression {
       ip_addresses = ["10.93.137.112/28"]
     }
   }
}
```

##### List of member groups (ASA Network Object-Group)

Includes the following fields:

* `description` - Set to the parsed object description or if none, that of the `display_name`.
* `criteria`
  * `member_paths`
    * `path_expression` - List of policy paths for group members of this Group.

**Example network object-group and criteria block:**

```json
resource "nsxt_policy_group" "pr-r-frontend_rt2_tills" {
   display_name = "pr-r-frontend_rt2_tills"
   description = "role: CHG0141028"
   domain       = "cgw"
    criteria {
      member_paths {
        path_expression = ["nsxt_policy_group.pr-r-frontend_rt2_till_range_1.path", "nsxt_policy_group.pr-r-frontend_rt2_till_range_2.path", "nsxt_policy_group.pr-r-frontend_rt2_till_range_3.path", "nsxt_policy_group.pr-r-frontend_rt2_till_range_4.path"]
     }
   }
}
```

#### nsxt_policy_service

**Source:** https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_service  

This VMC resource provides a way to configure a networking and security service which can be used within the rules of the Security Policy.  

> **Note:** Unlike Cisco ASA, the VMC DFW does not differentiate between service objects/object-groups and everything is a **policy service**.  


**Example service object-group and criteria block:**

```json
resource "nsxt_policy_service" "service_l4port" {
  description  = "L4 ports service provisioned by Terraform"
  display_name = "S1"
 
  l4_port_set_entry {
    display_name      = "TCP_80"
    description       = "TCP port 80 entry"
    protocol          = "TCP"
    destination_ports = [ "80" ]
  }
}
```

### nsxt_policy_security_policy (ASA access-lists)

**Source:** https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_security_policy

This VMC resource provides a method for the management of a Security Policy and the repeatable block of rules under it.

Each rule includes the following fields:

* `display_name` - Display name of the rule resource.
* `description` - Description of the rule resource.
* `action` - Rule action, one of `ALLOW` or `DROP`.
* `logged` - Set to `true` to enable packet logging.
* `ip_version` - Version of IP protocol, set to `IPV4`.
* `direction` - Traffic direction, set to `IN_OUT`.
* `source_groups` - List of group paths that serve as the source for this rule.
* `destination_groups` - List of group paths that serve as the destination for this rule.
* `services` - List of service paths to match.

**Example rule block:**

```json
resource "nsxt_policy_service" "pr-r-frontend_21299" {
  display_name = "pr-r-frontend_21299"
  description  = "description: 21299, services: [tcp21299]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = [21299]
  }
}
```

For further information please refer to our Confluence page detailing VMC Terraform standards:  
[NetAuto VMC - Terraform - Standards](https://conf.willhillatlas.com/display/netsec/NetAuto+VMC+-+Terraform+-+Standards)  

Role Variables
--------------

The variable structure for multiple-context ASAs must include a `contexts.yml` file that contains a simple list of contexts.  
(This is not required for single mode ASAs as they  do not have 'contexts'.)  
This needs to be in the directory: host_vars/device_name  

Example contexts.yml:  

```yaml
contexts:
#  - context: "admin"
  - context: "prod-frontend"
  - context: "prod-mgt"
  - context: "prod-internal"
```

The variable structure for multiple-context ASAs must include a `vmc_acls.yml` file that contains a simple list of access-lists on the ASA to parse.  
(Single mode ASA  does not currently support this list; all access-lists on the single mode ASA will be parsed.)  
This needs to be in the directory: host_vars/device_name/context_name  

Example vmc_acls.yml:
```yaml
vmc_migrate_acls:
  - internal-vrf_access_in
  - monitoring-int_access_in
  - global_access
```

After running this role successfully against a multi-context ASA, the variable 

Example variables directory structure:  

```
environments/prod/host_vars/asa-fw-name/
├── contexts
│   ├── prod-frontend
│   │   ├── dfw_pr-c-frontend_groups.tf
│   │   ├── dfw_pr-c-frontend_groups.yml
│   │   ├── dfw_pr-c-frontend_ports.tf
│   │   ├── dfw_pr-c-frontend_ports.yml
│   │   ├── dfw_pr-c-frontend_rules.tf
│   │   ├── dfw_pr-c-frontend_rules.yml
│   │   └── vmc_acls.yml
│   ├── prod-mgt
│   │   ├── dfw_pr-c-mgt_groups.tf
│   │   ├── dfw_pr-c-mgt_groups.yml
│   │   ├── dfw_pr-c-mgt_ports.tf
│   │   ├── dfw_pr-c-mgt_ports.yml
│   │   ├── dfw_pr-c-mgt_rules.tf
│   │   ├── dfw_pr-c-mgt_rules.yml
│   │   └── vmc_acls.yml
│   └── prod-internal
│       ├── dfw_pr-e-internal_groups.tf
│       ├── dfw_pr-e-internal_groups.yml
│       ├── dfw_pr-e-internal_ports.tf
│       ├── dfw_pr-e-internal_ports.yml
│       ├── dfw_pr-e-internal_rules.tf
│       ├── dfw_pr-e-internal_rules.yml
│       └── vmc_acls.yml
└── contexts.yml
```

Dependencies
------------

This role imports and utilises the role: `ansible-network.network-engine`. This must be present and available in the list of local roles.  

This role uses the python3 script: `roles/vmc-conversions/files/asa2vmc-port-converter.py` to convert ASA named ports to port numbers. This python script makes use of the following non-standard python module that should be installed with pip (pip3) if it is not already available in your environment:

- ruamel.yaml

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yaml
---

- name: PLAY - ASA to VMC objects and rules conversion 
  hosts: asa
  gather_facts: no
  connection: network_cli

  roles:
    - vmc-conversions
```

License
-------

BSD

Author Information
------------------

Role authors: Chris Hannan, David Burton, Giles Falkingham, 2020.  
README authors: Chris Hannan, David Burton, Giles Falkingham, 2020-2021.  
