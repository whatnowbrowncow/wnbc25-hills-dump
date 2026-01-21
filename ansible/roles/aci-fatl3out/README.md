aci-fatl3out
============

Creates 'fatl3out' in ACI.  

One 'External Routed Network' per VRF with multiple 'Logical Node Profiles' nested within is known as a 'fatl3out'.
This role will configure the top level 'External Routed Network' and all of the sub-components thereof for functioning layer 3 connectivity in/out of the ACI fabric. 

Creates Routed Outside (fatl3out task 1)  
Creates External Networks (fatl3out task 2)  
Creates Logical Node Profiles (fatl3out task 3)  
Creates Logical Interface Profiles (fatl3out task 4)  
Selects Nodes (fatl3out task 5)   
Adds Static Route(s) to Selected Nodes (fatl3out task 6) (Optional)  

Requirements
------------

This role requires that the ACI **Tenant** referenced already exists.  

Either a seperate role responsible for creating a new Tenant: **aci-tenant** should be invoked by the playbook before this role. Or, if this role is run independently, the tenant must already be incumbent in the ACI fabric.  

This role requires that the ACI **External Routed Domain** referenced already exists.  

Either a seperate role responsible for creating a new External Routed Domain should be invoked by the playbook before this role. Or, if this role is run independently, the External Routed Domain must already be incumbent in the ACI fabric. Nb. At the time of writing there is no role responsible for creating a new External Routed Domain.  

This role requires that the ACI **VPC Interface Policy Group** or **Leaf Access Port Policy Group** referenced already exists.  

Either a seperate role responsible for creating the Interface Policy Group(s) should be invoked by the playbook before this role. Or, if this role is run independently, the Interface Policy Group(s) must already be incumbent in the ACI fabric. Nb. At the time of writing there is no role responsible for creating new Interface Policy Groups.  

Tasks
-----

This role consists of seven seperate tasks that are executed in the following order:

main.yml  
aci-fatl3out-routed-outside.yml  
aci-fatl3out-networks.yml  
aci-fatl3out-node-profiles.yml  
aci-fatl3out-interface-profiles.yml  
aci-fatl3out-select-nodes.yml  
aci-fatl3out-static-routes.yml  

Role Variables
--------------

Example Variable Structure:  

```yaml
fatl3outs: 
  - l3out_name: "group-vrf_fatl3out"
    l3_domain: "network-devices"
    tenant: "common"
    vrf: "group-vrf"
    ext_networks:
      - ext_subnet: "0.0.0.0/0"
        scope: "export-rtctrl,import-security"
        aggregate: "export-rtctrl"

node_profiles:
  - np: "group-vrf_dr-e-wan"
    fatl3out: "group-vrf_fatl3out"
    tenant: "common"
    svi_nodes: "101-102"
    svi_path: "FW01-Data_PolGrp"
    svi_vlan: "571"
    svi_side_a: "10.19.0.129"
    svi_side_b: "10.19.0.130"
    svi_shared: "10.19.0.131"
    svi_cidr: "27"
    bgp:
      - bgp_peer: "10.19.0.132"
        bgp_local_as: "64559"
        bgp_remote_as: "64603"
    nodes:
      - node_id: "101"
        sr_subnet: "3.8.37.0/28"
        sr_nexthop: "10.19.0.132"
      - node_id: "102"
        sr_subnet: "3.8.37.0/28"
        sr_nexthop: "10.19.0.132"
  - np: "group-vrf_uk-ld6-cr01"
    fatl3out: "group-vrf_fatl3out"
    tenant: "common"
    svi_nodes: "103-104"
    svi_path: "uk-ld6-cr01-po1_PolGrp"
    svi_vlan: "500"
    svi_side_a: "10.19.0.2"
    svi_side_b: "10.19.0.3"
    svi_shared: "10.19.0.4"
    svi_cidr: "27"
    bfd_policy: "core-l3outs"
    bgp:
      - bgp_peerctrl: "bfd"
        bgp_peer: "10.19.0.1"
        bgp_local_as: "64559"
        bgp_remote_as: "57002"
    nodes:
      - node_id: "103"
      - node_id: "104"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.  

This role then references the host_vars file for the specified environment.  

Example LD6 production:  
   network_inventory/environments//prod/host_vars/ld6-prod-aci.yml  
  
Example LD6 Lab environment:  
   network_inventory/environments//dev/host_vars/ld6-lab-aci.yml  

The following two tasks make reference to the "fatl3outs" list.  
- aci-fatl3out-routed-outside.yml
- aci-fatl3out-networks.yml
  
The following four tasks make reference to the "node_profiles" list.  
- aci-fatl3out-node-profiles.yml
- aci-fatl3out-interface-profiles.yml
- aci-fatl3out-select-nodes.yml
- aci-fatl3out-static-routes.yml

The following task makes reference to the "bgp" nested list when it is present.  
- aci-fatl3out-interface-profiles.yml

The following two tasks make reference to the "nodes" nested list.  
- aci-fatl3out-select-nodes.yml  
- aci-fatl3out-static-routes.yml  
  
The "fatl3outs" list describes the top level 'External Routed Networks' along with their assocciated 'External Network Instance Profile'. Our standard configuration is to have one 'External Routed Network' per VRF with multiple 'Logical Node Profiles' nested within. This type of l3out configuration is known as a 'fatl3out'. The 'Logical Node Profiles' are described seperately in the "node_profiles" list.  
  
The "node_profiles" list describes the 'Logical Node Profiles' and all their associated configuration. Including the 'Logical Interface Profile' with their SVI configuration, plus BGP configuration and static routes as appropriate. Each 'Logical Node Profile' is nested within a fatl3out 'External Routed Network'.  
  
The task "aci-fatl3out-interface-profiles.yml" is capable of bulding 'Logical Interface Profiles' to three differing specifications based upon the variables defined for that node profile in the "node_profiles" list.  
  
Sub-task **Create Logical Interface Profiles that use BGP (SINGLE profile)** will run when both the 'bgp' and 'svi_path' variables are defined for that node profile.  
Sub-task **Create Logical Interface Profiles that use BGP (DUAL profile)** will run when both the 'bgp' and 'svi_interface' variables are defined for that node profile.  
Sub-task **Create Logical Interface Profiles that do NOT use BGP** will run when both the 'bgp' variable is not defined for that node profile.  
  
The task "aci-fatl3out-select-nodes.yml" is capable of creating the 'Configured Nodes' with either standard or non-standard Router IDs. To configure a non-standard Node Router ID, it is necessary to declare an extra "router_id" variable in the "nodes" dictionary.  
  
Sub-task **Select Nodes (With Standard Router IDs)** will run when there is no "router_id" variable defined in the "nodes" dictionary.  
Sub-task **Select Nodes (With Non-standard Router IDs)** will run when a "router_id" variable is defined in the "nodes" dictionary.  
  
Dependencies
------------

This role utilises the pre-written Ansible module "aci_rest":  
   https://docs.ansible.com/ansible/devel/modules/aci_rest_module.html#aci-rest-module  
  
This role depends on the seperate role: "aci-tenant" to build the ACI Tenant under which the fatl3out will be created.  
  
While not a dependency per-se, it is important to note that *this role does not configure the 'External Routed Domain'* referred by the "fatl3outs" list, *nor the 'VPC Interface Policy Groups' or 'Leaf Access Port Policy Groups'* referred by by the "node_profiles" list. The creation of these ACI components is not currently automated and must, therefore, be undertaken manually until such time as the roles exist to create them programmatically.  

Example Playbook
----------------
```yaml
- name: ACI fatl3out build
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-fatl3out
```

WH Standard
-----------

| Status:     | draft    |
|-------------|----------|

[NET-STD053 - ACI L3out (DRAFT)](https://conf.willhillatlas.com/display/ARCH/NET-STD053+-+ACI+L3out)  

License
-------

BSD

Author Information
------------------

Role author: Giles Falkingham, 2019.  
README author: Giles Falkingham, 2019. 
