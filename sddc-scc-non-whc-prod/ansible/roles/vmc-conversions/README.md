# vmc-conversions

The purpose of this role is to parse Cisco ASA firewalls of their access-list configuration and transpose it to a Terraform configuration file that will be used by VMC for the distributed firewall (DFW) configuration. 

Not only do the access-lists need to be parsed, but all objects and object-groups for both networks and services that are referenced in an access-entry also need to be parsed and transposed to the Terraform configuration files below:

* **_dfw_sddc_specific_groups.tf:_** Contains the `nsxt_policy_group` resource, used to define IP address and network objects in VMC.
* **_dfw_sddc_specific_ports.tf:_** Contains the `nsxt_policy_service` resource, used to define Protocol/Port objects in VMC.
* **_dfw_sddc_specific_rules.tf:_** Contains the `nsxt_policy_security_policy` resource, used to define rules in VMC.

The ASA configuration parsing and Terraform file generation is carried out in following stages

1. Parse the existing ASA configuration for all access-lists, network objects/object-groups and service objects/object-groups. Generate a 'human-readable' **YAML** file to document the existing configuration.
2. Convert the **YAML** file to generate a **Terraform** configuration file.

## Requirements

None. (Although see dependencies.)

## Tasks

This role consists of 7 separate tasks:

```bash
roles/vmc-conversions/
├── tasks
│   ├── main.yml                          # executed first and imports the `command_parser` role
│   ├── asa-multiple-vmc-groups-yaml.yml  # parses ASA network objects/object-groups and generates a host_var YAML file named "dfw_sddc_specific_groups.yml"
│   ├── asa-multiple-vmc-groups-tf.yml    # converts "dfw_sddc_specific_groups.yml" to a Terraform file named "dfw_sddc_specific_groups.tf"
│   ├── asa-multiple-vmc-ports-yaml.yml   # parses ASA service objects/object-groups and generates a host_var YAML file named "dfw_sddc_specific_ports.yml"
│   ├── asa-multiple-vmc-ports-tf.yml     # converts "dfw_sddc_specific_ports.yml" to a Terraform file named "dfw_sddc_specific_ports.tf"
│   ├── asa-multiple-vmc-rules-yaml.yml   # parses ASA access-lists and generates a host_var YAML file named "dfw_sddc_specific_rules.yml"
│   └── asa-multiple-vmc-rules-tf.yml     # converts "dfw_sddc_specific_rules.yml" to a Terraform file named "dfw_sddc_specific_ports.tf
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

Role Variables
--------------

A description of the settable variables for this role should go here, including any variables that are in defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role. Any variables that are read from other roles and/or the global scope (ie. hostvars, group vars, etc.) should be mentioned here as well.

Dependencies
------------

A list of other roles hosted on Galaxy should go here, plus any details in regards to parameters that may need to be set for other roles, or variables that are used from other roles.

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

An optional section for the role authors to include contact information, or a website (HTML is not allowed).
