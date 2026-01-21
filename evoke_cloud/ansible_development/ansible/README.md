# Evoke Cloud Ansible Automation

This directory contains Ansible playbooks, roles, and supporting files for automating network deployment and management in the Evoke Cloud environment.

## Structure

- **play_evoke_cloud_deploy.yml**
  Main playbook to deploy a network using the `deploy_evoke_cloud_network` role.

- **roles/deploy_evoke_cloud_network/**
  Contains the role for network deployment, including tasks, handlers, variables, scripts, and documentation.

- **inventory/**
  Inventory files for specifying target hosts and groups.

## Key Role Documentation

- **[Evoke Cloud Network Role README](roles/deploy_evoke_cloud_network/README.md)**
  Details and usage for the Evoke Cloud network deployment role.

- **[Python Toolset README](roles/deploy_evoke_cloud_network/scripts/wh_net_python_toolset/README.md)**
  Documentation for the supporting Python toolset (if present as a submodule or symlink).

## Usage

1. Review and set required variables in `roles/deploy_evoke_cloud_network/vars/main.yml`.
2. Set necessary environment variables as described in the role README.
3. Run the main playbook:
   ```bash
   ANSIBLE_CONFIG=ansible.cfg ansible-playbook -i inventory/inventory.yml play_evoke_cloud_deploy.yml --vault-id evokecloud@prompt -e @evoke_vault.yml
   ```

## Related Documentation

- **[Project Root README](../../README.md)**
- **[Evoke Cloud Network Role README](roles/deploy_evoke_cloud_network/README.md)**
- **[Python Toolset README](roles/deploy_evoke_cloud_network/scripts/wh_net_python_toolset/README.md)**

Refer to these files for setup, usage, and module-specific instructions.
