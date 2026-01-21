# logging

This role has been created to remove the requirement for duplicated logging tasks in each role. Instead, the logging tasks within this role can be automatically pulled in to other roles that list this role as a dependency.

## Tasks

The role consists of four separate tasks, two in `tasks/` directory and two in the `handlers/` directory.

```bash
roles/logging/
├── tasks
│   ├── main.yml         # executed first and lists the tasks the role will execute
│   └── log_setup.yml    # performs the initial log setup tasks
└── handlers
    ├── main.yml         # lists the handler tasks the role make available to the play
    └── log_write.yml    # tasks that write logs to disk if notified
```

**log_setup.yml:** This task is execute once, regardless of how many hosts are targeted, and executed against the local host. It performs the initial setup tasks required to log any changes to disk. Steps include:

1. Retrieving the date and time.
2. Registering the date and time in the timestamp format _**iso8601_basic_short**_ as the variable `{{ DTG }}`. 
3. Ensuring the `logs/` directory exists and if not, creating one.
4. Sets the variable `{{ LOG_PATH }}`, which is a directory path of `logs/{{ role }}_{{ DTG }}/`

**log_write.yml:** This task is made available to the play and listens for notifications of `"updates exist"`. If notified, the task will execute at the end of the play and perform the tasks that write any changes to a log file. Steps include:

1. Creating the logging directory, utilising the `{{ LOG_PATH }}` variable created from _**log_setup.yml**_.
2. Calling a **role-specific** Jinja2 template that prints any changes made to a log file with the name `"{{ LOG_PATH }}{{ inventory_hostname }}.txt"`.

**Example of _ansible/logs/:_**

```bash
logs/
├── mgmt-acl-updater_20201006T092551
    ├── uk-cwk-lab-sw01.txt
    └── uk-cwk-lab-sw02.txt
```

## Role Variables

None. (Although see **Requirements** and **Dependencies**.)

## Requirements

For this role to be listed as a dependency by another role and to be called successfully, the below requirements need to be met:

1. If you want to log any configuration changes that a task in the parent role makes, the task needs to register the output and notify `"updates exist"`. This will notify the handler tasks within _**log_write.yml**_ to execute, using the variable registered to render the log file.

**Example task from _ansible/roles/mgmt-acl-updater/tasks/ios-config-deletions.yml:_**

```yaml
- name: IOS - Building and applying the configuration
  ios_config:
    src: "{{ role_path }}/templates/ios-deletions.j2"
  register: aclUPDATED
  notify: "updates exist"
  when: aclMATCH
```

2. In the templates directory of this role, a Jinja2 template file specific to the parent role needs to be created and named `"{{ role_name }}-logging.j2"`.

**Example template name in _ansible/roles/logging/templates/:_**

```yaml
roles/logging/templates/
└── mgmt-acl-updater-logging.j2
```

**Example template _ansible/roles/logging/templates/mgmt-acl-updater-logging.j2:_**

```yaml
!--- User <{{ lookup('env','USER') }}> executing the Ansible role <{{ role_name }}> ---!
!--- BEGIN UPDATES: {{ inventory_hostname }} @ {{ DTG }} ---!
!
{% if aclUPDATED.updates is defined %}
{% for item in aclUPDATED.updates -%}
{{ item }}
{% endfor %}
{% endif %}
!
!--- END UPDATES: {{ inventory_hostname }} @ {{ DTG }} ---!
```

3. In the parent role a dependency for this role needs to be created in `meta/main.yml` with the following dependency variables:

    * **role:** the name of the parent role, used to create the `{{ LOG_PATH }}` variable in Step 4 of _**log_setup.yml**_.
    * **LOG_TEMPLATE:** the name of the parent role with **"-logging.j2"** appended. This variable will then match the name of the role-specific Jinja2 template created in Requirement 2 and will be called by _**log_write.yml**_ to render the log file.

**Example dependency listed in _ansible/roles/mgmt-acl-updater/meta/main.yml:_**

```yaml
dependencies:
  - role: logging
    vars:
      role: "mgmt-acl-updater"
      LOG_TEMPLATE: "mgmt-acl-updater-logging.j2"
```

## Dependencies

| **Module(s)** | **New in** | **Tested using** | **Python version tested** | **Requirements** |
| ------------- | ---------- | ---------------- | ------------------------- | ---------------- |
| setup: _gather_subset_ | version 2.1 | version 2.8.6 | 3.6.9 | none |
| template: _newline_sequence_ | version 2.4 | version 2.8.6 | 3.6.9 | none |

## WH Standard

| Status:     | Approved |
|-------------|-----------|

## License

BSD

## Author Information

Role authors: Chris Hannan 2020.
README authors: Chris Hannan 2020.