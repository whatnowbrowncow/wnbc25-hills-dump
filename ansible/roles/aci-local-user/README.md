aci-local-user
==============

This role creates a local ACI user account for administrative access to the ACI Fabric. It was decided for this role to use the ACI's Rest Module for account creation, rather than the Ansible Core Module *aci_aaa_user* due to the limitations, python bugs and additional dependencies within the module.

Requirements
------------

The role requires that its variables are passed in via either:
- the accompanying playbook "play_aci-role-local-user"
- a list of dictionaries stored in *group_vars* for *aci.yml*
- a Jinja2 template

Tasks
-----

This role consists of two separate task files that are executed in the following order:

+ **main.yml:** This task defines the ansible_network_os conditional statement and the _import_task/include_task_ statement for the **aci-local-user** task.
+ **aci-local-user:** This task contains 2 sub-tasks:
	- Creating your ACI local user account
	- Configuring your new account's Security Domains

Role Variables
--------------

**Example Variable Structures:**

The role can be passed its required variables using one of the below methods:

**Method 1: Dynamically** 

The role has an accompanying playbook "*play_aci-role-local-user*" that can be used to prompt a user and dynamically pass in the variables required to create a local ACI user account.

`ansible-playbook play_aci-role-local-user.yml -i <environment> --ask-vault-pass `

**Method 2: Dynamically**

The role variables can be passed in at the command line when running a playbook that includes the role, using the `--extra-vars` (or `-e`) argument and replacing *var* for the user's details.

` -e "user_username=var first_name=var last_name=var email_address=var local_password=var" -i <environment> --ask-vault-pass`

**Method 3: Statically**

The variables could be a list of dictionaries stored in a vars_file, such as *group_vars* for *aci.yml*:

```yaml
---
#Used to define the local users to be created on the ACI Fabric:
local_users:
  - first_name: "Joe"
    last_name: "Bloggs"
    email_address: "Joe.Bloggs@example.com"
    user_username: "jbloggs"
    local_password: "secret_key"
  - first_name: "Bob"
    last_name: "Smith"
    email_address: "Bob.Smith@example.com"
    user_username: "bsmith"
    local_password: "secret_key"
```

The above list would then need to be appended to each task within the role:

```yaml
 ---

- name: Creating your ACI local user account
  ...    
    validate_certs: no
  with_items:
     - "{{ local_users }}"

- name: Configuring your new account's Security Domains
  ...    
    validate_certs: no
  with_items:
     - "{{ local_users }}"     
```


Dependencies
------------

This role utilises the pre-written Ansible module *[_aci_rest_](https://docs.ansible.com/ansible/latest/modules/aci_rest_module.html)*:

| **New in** | **Tested using** | **Requirements**   |
| ------- | ---- | --- |
| 2.4| 2.8.1 |  **lxml**, **xmljson**, **python 2.7+** (when using XML payload)    |


Example Playbook
----------------
```yaml
---

- name: PLAY - Create a local user account
  hosts: aci
  connection: local
  remote_user: "{{ user_username }}"
  gather_facts: no
     
  roles:
    - aci-local-user
```

Accompanying Playbook "*play_aci-role-local-user*"
--------------------------------------------------
```yaml
---

- name: PLAY - Create a local user account
  hosts: aci
  connection: local
  gather_facts: no
  
  vars_prompt:
    - name: "snapshot_description"
      prompt: "Provide the change ref. This will be used for the slack message and/or snapshots:"
      default: "ansible pre-change backup"
      private: no
    - name: 'first_name'
      prompt: 'Please enter your first name'
      private: no
    - name: 'last_name'
      prompt: 'Please enter your last name'
      private: no
    - name: 'user_username'
      prompt: 'Please enter your AD username'
      private: no
    - name: 'email_address'
      prompt: 'Please enter your email address'
      private: no      
    - name: 'local_password'
      prompt: 'Please create a password (8 character minimum, include 3 of the following classes: upper, lower, digits and special characters)'
      private: yes
      confirm: yes

  pre_tasks:
    - name: Confirm your details are correct
      vars:
        msg: |
            First Name: {{ first_name }}
            Last Name: {{ last_name }}
            Email Address: {{ email_address }}
            AD Username: {{ user_username }}
      debug: 
        msg: "{{ msg.split('\n') }}"
    - name:      
      pause: prompt='Confirm the information you entered above is correct. Press return to continue or Ctrl+c and then "a" to abort.'    

  roles:
    - aci-local-user

  post_tasks:
    - debug:
        msg:
        - Your ACI username is '{{ user_username }}-local'
        
```
WH Standard
-----------

| Status:     | undefined |
|-------------|-------------------|

Author Information
------------------

Role author: Chris Hannan, 2019.  
README author: Chris Hannan, 2019. 