# Evoke Cloud Network Deployment Script

This Ansible playbook automates the process of adding a new network to the Evoke Cloud infrastructure. It retrieves necessary variables, converts host ranges, interacts with Infoblox to create networks, and deploys network configurations on Cisco Nexus switches via DCNM.

---

## Features
- Sets and passes environment-specific variables
- Converts host ranges to CIDR notation
- Retrieves container network details
- Creates new networks in Infoblox
- Queries and configures Cisco Nexus switches
- Deploys network configurations to the fabric
- Sends Slack notifications on success or failure

---

## Prerequisites
- Ansible 2.9+ installed
- Access to Infoblox API with appropriate credentials
- Access to Cisco DCNM API with necessary permissions
- Python environment with `slack-message.py` script
- The relevant environment variables set:
  - `hosts`
  - `site`
  - `environment`
  - `network_name`
  - `ticket_ref`
  - `cde`
  - `security_group`
  - `summary`
  - `NS_SLACK_BOTTOKEN`
  - `NOTIFICATION_CHANNEL`

---

## Variables

Majority of static variables for this role are defined in [`vars/main.yml`](vars/main.yml).
Review and update this file as needed to match your environment and logging requirements.

---

## Usage

### Variables
The script retrieves key variables from environment variables, such as:
- `hosts`: Host range or network segment
- `site`: Site name (e.g., "IE-DB2 - Ireland Dublin DB2 (Equinix)")
- `environment`: Deployment environment (e.g., dev, prod)
- `network_name`: Owner of the network
- `ticket_ref`: Change ticket reference
- `cde`: Configuration Data Element
- `security_group`: Security context
- `summary`: Summary string

### Command to Execute
To Execute the Script use the following steps
Make sure the following are set as a enviroment varible in the relevent area
export hosts='<Number of hosts in the format ###-### (##)>' #Note this must be the same as on the Jira form
export environment='<Relevent Value As Defined In the Estate>'
export ticket_ref=<String Varibile>
export security_group='<Relevent String Value As Defined In the Estate>'
export summary=<String Varibile>
export network_name=<String Varibile>
export cde='<Yes/NO>'
export site=<Relevent String Value As Defined In the Estate>
export NS_SLACK_BOTTOKEN=<Token as per Password Vault>
export NOTIFICATION_CHANNEL=<Slack Channel ID >

eg
```bash
export hosts='1-9 (28)' #Note this must be the same as on the Jira form
export environment='Devlopment'
export ticket_ref='UAT-5242'
export security_group='Web'
export summary='Testing'
export network_name='Network'
export cde='Yes'
export site='IE-DB2 - Ireland Dublin DB2 (Equinix)'
export NS_SLACK_BOTTOKEN=<Token as per Password Vault>
export NOTIFICATION_CHANNEL=C06JHGK9YDT
```

Ensure the repo https://gitlab.com/williamhillplc/technical-services/networks/automation-tools/wh_net_python_toolset is in the location `ansible_development/ansible/roles/deploy_evoke_cloud_network/scripts`:
```bash
cd /gitnet/evoke_cloud/ansible_development/ansible/roles/deploy_evoke_cloud_network/scripts
ln -s /gitnet/automation-tools/wh_net_python_toolset/
```
** REMOVE THIS WHEN YOU HAVE FINISHED TESTING, BEFORE DOING A GIT PUSH OF THE EVOKE CLOUD CODE **
```bash
cd /gitnet/evoke_cloud/ansible_development/ansible/roles/deploy_evoke_cloud_network/scripts
rm -rf wh_net_python_toolset
```

Make sure there is access to:
* Evoke Cisco Nexus Dashboard
* Evoke Jira Service Management
* Evoke Infoblox

To Run, please execute the following:
```bash
cd /gitnet/evoke_cloud/ansible_development
ANSIBLE_CONFIG=ansible/ansible.cfg ansible-playbook -i inventory/inventory.yml ansible/play_evoke_cloud_deploy.yml --vault-id evokecloud@prompt -e @evoke_vault.yml
```

---

## Workflow

1. Sets variables based on environment inputs
2. Converts host ranges to CIDR notation
3. Retrieves container network details
4. Calls Infoblox API to create a new network
5. Retrieves network details and prepares deployment
6. Queries Cisco DCNM for switches
7. Deploys network configuration to switches
8. Sends Slack notifications upon success or failure

---

## Tasks Breakdown

### 1. Setting Variables
Collects environment variables using `set_fact`:
```yaml
- name: Set Varibles
  ansible.builtin.set_fact:
    address_range: "{{ lookup('env', 'hosts') }}"
    site: "{{ lookup('env', 'site') }}"
    environment_name: "{{ lookup('env', 'environment') }}"
    owner: "{{ lookup('env', 'network_name') }}"
    change_reference: "{{ lookup('env', 'ticket_ref') }}"
    cde: "{{ lookup('env', 'cde') }}"
    security_group: "{{ lookup('env', 'security_group') }}"
    summary: "{{ lookup('env', 'summary') }}"
```

### 2. Convert Hosts to CIDR
Maps host range to CIDR notation:
```yaml
- name: Convert Hosts to CIDR
  ansible.builtin.set_fact:
    cidr: "{{ subnet_cidr.cidr }}"
  loop: "{{ subnet_converstion }}"
  loop_control:
    loop_var: subnet_cidr
  when: subnet_cidr.range == address_range
```

### 3. Retrieve Container Network
Fetches network information for the site and environment:
```yaml
- name: EVOKE CLOUD - Retrieve Container Network
  set_fact:
    container_network: "{{ container_network_group[site][environment_name]['network'] }}"
```

### 4. Create New Network in Infoblox
Calls the Infoblox API to provision the new network:
```yaml
- name: EVOKE CLOUD - Implement New Network in Infoblox
  ansible.builtin.uri:
    url: "{{ infoblox_api_url}}/{{ib_retrieve_next_network['url']}}"
    user: "{{ username }}"
    password: "{{ password }}"
    method: "{{ ib_retrieve_next_network['request_type'] }}"
    body_format: json
    body:  "{{ ib_retrieve_next_network['data'] }}"
    return_content: true
    force_basic_auth: true
    validate_certs: false
    status_code: 201
```

### 5. Set Network Details
Stores network info for deployment:
```yaml
- name: EVOKE CLOUD - Retrieve New Network Subnet and Owner
  set_fact:
    network_data: {
      network_subnet: "{{ network_details.json[0].result.network | ansible.utils.ipaddr('net') }}",
      owner: "{{ owner }}",
      vrf: "{{ container_network_group[site][environment_name]['vrf'] }}",
      cidr: "{{ cidr }}",
    }
```

### 6. Query and Configure Switches
Queries switches and builds the deployment list:
```yaml
- name: Find Switches to Deploy to
  dcnm_rest:
    method: GET
    path: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/{{ ndfc.fabric_name }}/inventory/switchesByFabric"
  register: allSwitches
  delegate_to: nexusdashboard.williamhill.plc

- name: Initialise Switch List
  ansible.builtin.set_fact:
    switches: []

- name: Find Logical Names for Leafs
  set_fact:
    switches: "{{ switches + [{'ip_address': switch ,'ports': ['Ethernet1/11']}] }}"
  loop: "{{ allSwitches.response.DATA | selectattr('switchRole', 'equalto', 'leaf') | map(attribute='ipAddress') | list }}"
  loop_control:
    loop_var: switch
```

### 7. Deploy Network
Deploys the network to the fabric:
```yaml
- name: Deploy Network
  cisco.dcnm.dcnm_network:
    state: merged
    fabric: Evoke_Cloud
    config:
      - net_name: "{{ environment_name }}-{{ subnet_name }}"
        vlan_name: "{{ network_data.vrf }}:{{ subnet_name }}"
        vrf_vlan_name: "{{ network_data.vrf }}:{{ subnet_name }}"
        vrf_name: "{{ network_data.vrf }}"
        gw_ip_subnet: '{{ network_data.network_subnet |  ansible.utils.ipaddr("net") | ansible.utils.ipaddr("1") }}'
        attach: "{{ switches }}"
        deploy: true
  register: deployed_network
  delegate_to: nexusdashboard.williamhill.plc
```

### 8. Notifications
Sends a Slack message on success or failure:
```yaml
- name: Send Slack Message on Success
  shell: python {{ role_path }}/scripts/slack-message.py
    -l {{ python_log_level }}
    -lp {{ slack_log_location }}
    --forcefail
    --message_detail '{{ success_message }}'
  check_mode: no
  delegate_to: localhost
  notify: "evoke_cloud:network_depolyed"

# In rescue block:
- name: EVOKE CLOUD - Send Slack Message to Network Team on Failure
  shell: python {{ role_path }}/scripts/slack-message.py
    -l {{ python_log_level }}
    -lp {{ slack_log_location }}
    --forcefail
    --message
      "Deployment of Evoke Cloud Network has failed
      on task {{ ansible_failed_task.name }}
      while deploying request for {{ change_reference }}"
  register: pythonoutput
  check_mode: no
  changed_when: true
  notify: "evoke_cloud:network_depoly_failed"
```

---

## License
This project is licensed under the BSD License.

---

## Author
Chris Stafford, Dave Burton (2025)
