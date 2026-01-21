# NSX

## Overview

Creates and maintains the networking rules for the SDDC.

## Usage

CHANNEL, REGION and ENV Makefile vars are being handled using the Makefile.env file for this repo.

To be deployed in VMC Sidecar Prod account in EU West 1

 ```bash
    APPROVAL=RTSK00000 aws-okta exec <Prod Delegated Write Profile> -- make onetime
    APPROVAL=RTSK00000 aws-okta exec <Prod Delegated Write Profile> -- make plan
    APPROVAL=RTSK00000 aws-okta exec <Prod Delegated Write Profile> -- make apply
 ```

## Prerequisites

* Ensure an AWS sidecar has been created and VPCs setup
* CloudFormation run in that account as root user to allow it to be paired to VMC org
* Check against the requirements laid out [here](https://conf.willhillatlas.com/display/IE/Creating+An+SDDC+Process+Flow)

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| terraform | 0.13.4 |
| aws | ~> 2.0 |
| nsxt | ~> 3.1.1 |

## Providers

| Name | Version |
|------|---------|
| nsxt | ~> 3.1.1 |
| terraform | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| dfw_core | git::https://gitlab.com/williamhillplc/technical-services/infrastructure-and-engineering/vmc/modules/tf-vmc-dfw?ref=feature/SCCEXIT-0000_post-migration-fixes |  |

## Resources

| Name |
|------|
| [nsxt_policy_gateway_policy](https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_gateway_policy) |
| [nsxt_policy_group](https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_group) |
| [nsxt_policy_security_policy](https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_security_policy) |
| [nsxt_policy_service](https://registry.terraform.io/providers/vmware/nsxt/latest/docs/resources/policy_service) |
| [nsxt_policy_tier0_gateway](https://registry.terraform.io/providers/vmware/nsxt/latest/docs/data-sources/policy_tier0_gateway) |
| [terraform_remote_state](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/data-sources/remote_state) |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| api\_token | n/a | `any` | n/a | yes |
| aws\_role | ########## only used by make here for clean output ################# | `string` | `""` | no |
| category | Catagory within DFW | `string` | `"Application"` | no |
| channel | n/a | `string` | `"it-ops"` | no |
| channel\_account\_id | n/a | `string` | `""` | no |
| env | n/a | `string` | `"prod"` | no |
| org | ########## below are for the remote state bucket and key ######### | `string` | `"wh"` | no |
| policy\_description | Policy Desciption | `string` | `"Core connectivity rules"` | no |
| policy\_name | Name of the Policy | `string` | `"Core_Management"` | no |
| product | n/a | `string` | `"scc-prod-nonwhc"` | no |
| region | n/a | `string` | `"eu-west-1"` | no |
| segment\_policy\_description | Policy Desciption | `string` | `"ANY-ANY rule within a segment"` | no |
| segment\_policy\_name | Name of the Policy | `string` | `"Segment-Segment-Any"` | no |
| segments | n/a | `list` | `[]` | no |
| service\_management\_cidr | CIDR assigned to the SDDC for our management infrastructure | `string` | `"10.156.4.0/25"` | no |
| specific\_policy\_description | Policy Desciption | `string` | `"Rules specific to this SDDC"` | no |
| specific\_policy\_name | Name of the Policy | `string` | `"SDDC_Specific"` | no |
| stateful | boolean value to determine if the section is stateful or not. | `bool` | `true` | no |
| vrops\_env\_master\_node | IP of the env master vrops node | `string` | `"10.120.134.250"` | no |
| vrops\_env\_master\_node\_name | name of the env master vrops node | `string` | `"sc1prapvro01"` | no |

## Outputs

No output.
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->