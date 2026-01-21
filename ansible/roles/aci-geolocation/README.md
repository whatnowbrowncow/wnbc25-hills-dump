aci-geolocation
===============

Creates 'site', 'building', 'floor', 'room', 'row(s)' and 'rack(s)' geolocation policy objects withiin Fabric > Fabric Policies > Policies > Geolocation.

Requirements
------------

There are no pre-requisites to running this role. 

Tasks
-----

This role consists of two seperate tasks that are executed in the following order:

main.yml  
aci-geolocation.yml   

The **main.yml** task merely defines the ansible_network_os conditional statement and the import_task statement for the aci-geolocation task.  

The **aci-geolocation.yml** task contains the actual tasks required to create all the geolocation objects. This is performed in 6 separate tasks:  

Create geolocation object for the site                (1/6)  
Create geolocation object for site building           (2/6)  
Create geolocation object for floor                   (3/6)  
Create geolocation object for each room               (4/6)  
Create geolocation objects for each row of racks      (5/6)  
Create geolocation objects for each rack              (6/6)  

Role Variables
--------------

Example Variable Structure: 

```yaml
geo_site: "gib"
geo_building: "mount_pleasant"
geo_floor: "ground"
geo_room: "dc5" 

geo_rows:
  - row: "unassigned"
    racks:
      - rack: "unassigned"
  - row: "3"
    racks:
      - rack: "h1a"
      - rack: "s1b"
      - rack: "s1c"
      - rack: "d1a"
```

This role first references the group variables file(s) for the specified environment and specific site; for example LD6 production:  
   network_inventory/environments//prod/group_vars/aci.yml  
  
In group_vars/aci.yml this role will make reference to "aci_user" and "aci_key" for certificate based authentication.
  
This role then references the main group variables file for the specified site.

Example GIB production:  
   network_inventory/environments//prod/group_vars/gib_aci.yml  
  
Example LD6 production:  
   network_inventory/environments//prod/group_vars/ld6_aci.yml  
  
This role (task: aci-geolocation.yml) makes reference to the following dict items contained within the group_vars files for the ACI instance:

'geo_site'
'geo_building'
'geo_floor'
'geo_room'

The 'row' and 'rack' variables are found within the 'geo_rows' list also contained within the group_vars files for the ACI instance.


Dependencies
------------

This role (task: aci-geolocation.yml) utilises the Ansible module "aci_rest" which has been tailored to target each of the ACI geolocation policy objects.


Example Playbook
----------------
```yaml
---

- name: This play performs switch discovery and configures basic management functions.
  hosts: aci
  connection: local
  gather_facts: no

  roles:
    - aci-geolocation
```
WH Standard
-----------

| Status:     | awaiting approval |
|-------------|-------------------|

https://conf.willhillatlas.com/display/ARCH/NET-STD053+-+ACI+Geolocation

License
-------

BSD

Author Information
------------------

Role author: Nick Turner, 2019.  
README author: Nick Turner, 2019. 