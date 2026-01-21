# asa-contexts

The purpose of this role is to interrogate Cisco ASA firewalls for their security context mode (single|multiple), cluster mode (true|false) and failover state (active|standby) configurations and document it in a `<hostname>.yml` host variable YAML file.

>**Note:** If a host already has a `<hostname>.yml` host variable file, the role will simply add/update the dictionary key/values in that file.

Additionally, if an ASA is configured in multiple context mode, the role will parse the configured contexts and document them in a host variable YAML file named `contexts.yml`.

>**Note:** If a host already has a `contexts.yml` host variable file, the role will simply add/update the list of contexts in that file.

## Tasks

This role consists of six separate tasks:  

* main.yml  
* asa-context-mode.yml
* asa-cluster-mode.yml
* asa-failover-state.yml
* asa-contexts-non-clustered.yml
* asa-contexts-clustered.yml

`main.yml` is executed first, the _ansible-network.network-engine_ role containing the _command_parser_ is imported at this stage. The remaining tasks are then executed from within `main.yml`.

**All ASA's** will be targeted by the following tasks:

* `asa-context-mode.yml`: documents an ASA's security context mode (single|multiple) configuration
* `asa-cluster-mode.yml`: documents an ASA's cluster mode (true|false) configuration

After the two tasks above have been processed, ASA's will now have their context mode and cluster configuration documented in their `<hostname>.yml` host variable file. This file is used to evaluate which one of the remaining three tasks are processed.

**Single-context mode ASA's** will be targeted by the below task:

* `asa-failover-state.yml`: documents an ASA's failover state (active|standby) configuration

After the task above have been processed, ASA's will now have their failover state configuration documented in their `<hostname>.yml` host variable file.

**Non-clustered, multiple-context mode ASA's** will be targeted by the below task:

* `asa-contexts-non-clustered.yml`: documents a non-clustered ASA's **active** contexts

After the task above have been processed, single unit ASA's and ASA's in an _active/active_ | _active/standby_ high-availability configuration will now have an up-to-date host variable YAML file named `contexts.yml` which lists the active contexts for each unit. 

**Clustered, multiple-context mode ASA's** will be targeted by the below task:

* `asa-contexts-clustered.yml`: documents a clustered ASA's configured contexts 

After the task above have been processed, clustered ASA's in an _active/active_ high-availability configuration will now have an up-to-date host variable YAML file named `contexts.yml` which lists the active contexts for the cluster.

**main.yml**

```yaml
---

- name: Import Network Parser role
  include_role:
    name: ansible-network.network-engine

- name: ASA - YAML Context Mode (single|multiple) Creation
  include_tasks: ./asa-context-mode.yml
  when: ansible_network_os == "asa"

- name: ASA - YAML Cluster Mode (true|false) Creation
  include_tasks: ./asa-cluster-mode.yml
  when: ansible_network_os == "asa"

- name: ASA SINGLE - YAML Failover State (active|standby) Creation
  include_tasks: ./asa-failover-state.yml
  when:
    - ansible_network_os == "asa"
    - context_mode == "single"
    - cluster == false

- name: ASA MULTIPLE (Active|Standby) - YAML Contexts List Creation
  include_tasks: ./asa-contexts-non-clustered.yml
  when:
    - ansible_network_os == "asa"
    - context_mode == "multiple"
    - cluster == false

- name: ASA MULTIPLE (Clustered) - YAML Contexts List Creation
  include_tasks: ./asa-contexts-clustered.yml
  when:
    - ansible_network_os == "asa"
    - context_mode == "multiple"
    - cluster == true
```

## Requirements

None. (Although see **Role Variables** and **Dependencies**.)

## Role Variables

Example `<hostname>.yml` YAML file for a non-clustered ASA:

```yaml
---

context_mode: single
cluster: false
failover_state: active
```

Example `<hostname>.yml` YAML file for a clustered ASA:

```yaml
---

context_mode: multiple
cluster: true
```

Example `contexts.yml` YAML file:

```yaml
---

contexts:
  - context: "admin"
  - context: "pte-n-mgt"
  - context: "dr-e-wan"
  - context: "pte-c-frontend"
  - context: "pte-c-mgt"
  - context: "pte-n-frontend"
  - context: "dr-n-frontend"
  - context: "dr-c-frontend"
  - context: "pr-c-fr-cx"
  - context: "pte-c-fr-cx"
  - context: "pte-r-frontend"
  - context: "dr-c-mgmt"
  - context: "dr-n-mgmt"
  - context: "production"
  - context: "corp"
  - context: "retail"
  - context: "cde-mgmt"
```

## Dependencies

| **Module(s)**  | **New in**  | **Tested using** | **Python version tested** | **Requirements**                    |
| -------------- | ----------- | ---------------- | ------------------------- | ----------------------------------- |
| asa_command    | version 2.2 | version 2.8.6    | 3.6.9                     | none                                |
| command_parser | version 2.5 | version 2.8.6    | 3.6.9                     | ansible-network.network-engine role |

## Example Usage

>**Note:** When executing a playbook/role that includes any tasks to configure Cisco ASA firewalls, this role must be executed first to refresh the host variables and ensure that the active unit and/or active contexts for each firewall is correctly targeted.

**Example 1:** used as a standalone role

```yaml
---

- name: PLAY - ASA Security Context/Failover Discovery
  hosts: asa
  gather_facts: no
  connection: network_cli

  roles:
    - asa-contexts
```

**Example 2:** used as a standalone role with additional ASA roles (syslog in this case)

```yaml
---

- name: PLAY - ASA Security Context/Failover Discovery
  hosts: asa
  gather_facts: no
  connection: network_cli

  roles:
    - asa-contexts
    - syslog
```

**Example 3:** imported into another ASA role (syslog in this case)

```yaml
---

- name: Import network parser role
  include_role:
    name: ansible-network.network-engine

- name: Import ASA contexts/failover role
  include_role:
    name: asa-contexts

- name: ASA-SINGLE - Syslog config task
  include_tasks: ./asa-single-config.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-MULTIPLE - Syslog config task
  include_tasks: ./asa-multiple-config.yml
  when: ansible_network_os == "asa" and context_mode == "multiple" and contexts is iterable
  with_items:
    - "{{ contexts }}"
  loop_control:
    loop_var: loop_contexts
```

**Example 4:** tasks from the role imported into another ASA role (syslog in this case)

```yaml
---

- name: Import network parser role
  include_role:
    name: ansible-network.network-engine

- name: ASA - CONTEXT - Running 'asa-contexts-yaml' task to update device contexts information
  include_role:
    name: asa-contexts
    tasks_from: asa-contexts-non-clustered.yml
  when: context_mode == "multiple" and cluster == false

- name: ASA - CONTEXT - Running 'asa-contexts-yaml' task to update device contexts information
  include_role:
    name: asa-contexts
    tasks_from: asa-contexts-clustered.yml
  when: context_mode == "multiple" and cluster == true

- name: ASA-SINGLE - Syslog config task
  include_tasks: ./asa-single-config.yml
  when: ansible_network_os == "asa" and context_mode == "single"

- name: ASA-MULTIPLE - Syslog config task
  include_tasks: ./asa-multiple-config.yml
  when: ansible_network_os == "asa" and context_mode == "multiple" and contexts is iterable
  with_items:
    - "{{ contexts }}"
  loop_control:
    loop_var: loop_contexts

```

## WH Standard

| Status:     | Approved |
|-------------|-----------|

## License

BSD

## Author Information

Role authors: Chris Hannan 2020, Chris Stafford 2020, Dave Burton 2020.
README authors: Chris Hannan 2020, Chris Stafford 2020, Dave Burton 2020.
