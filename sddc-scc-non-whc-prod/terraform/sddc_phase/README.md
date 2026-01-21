# SDDC

## Overview

Creates the initial SDDC and the associated compute clusters.

## Usage

CHANNEL, REGION and ENV Makefile vars are being handled using the Makefile.env file for this repo.

To be deployed in VMC Sidecar Prod account in EU West 1

You will need to create a VMC API token with deploy permissions and pass it through on plan and apply invocations.

 ```bash
    APPROVAL=RTSK00000 aws-okta exec <Prod Delegated Write Profile> -- make onetime
    APPROVAL=RTSK00000 aws-okta exec <Prod Delegated Write Profile> -- make plan OPTIONS="-var-file='~/edp.tfvars'"
    APPROVAL=RTSK00000 aws-okta exec <Prod Delegated Write Profile> -- make apply OPTIONS="-var-file='~/edp.tfvars'"

 ```

### Known Deployment Issues

* If, when running a plan or apply, you get the following error:

```module.sddc.vmc_sddc.sddc1: Refreshing state... [id=210eec68-1a9f-4706-b78e-7a7b111c80c0]

Error: Failed to read VMC Organization  (Error converting the object to byte stream: 'vapi.data.structure.getfield.unknown provider')

  on .terraform/it-ops/eu-west-1/dev/modules/sddc/sddc.tf line 3, in data "vmc_org" "my_org":
   3: data "vmc_org" "my_org" {


make: *** [tfplan] Error 1
exit status 2
```

Just run the plan/apply again. This is a known issue with the `vmc_org` data lookup.
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
| vmc | ~> 1.5.1 |

## Providers

No provider.

## Modules

| Name | Source | Version |
|------|--------|---------|
| sddc | git::https://gitlab.com/williamhillplc/technical-services/infrastructure-and-engineering/vmc/modules/tf-vmc-sddc.git?ref=2.1.0 |  |

## Resources

No resources.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| api\_token | n/a | `string` | `""` | no |
| aws\_account\_number | n/a | `string` | n/a | yes |
| aws\_role | n/a | `string` | `""` | no |
| channel\_account\_id | n/a | `string` | `""` | no |
| clusters | Used if creating more than 1 cluster in the SDDC the first cluster here will use be cluster 2 on the SDDC if having single cluster default = {} | `list(any)` | `[]` | no |
| deployment\_type | Denotes if request is for a SingleAZ or a MultiAZ SDDC. | `string` | `"SingleAZ"` | no |
| edrs\_policy\_type | The EDRS policy type. This can either be 'cost', 'performance', 'storage-scaleup' or 'rapid-scaleup'. Default : storage-scaleup. | `string` | `"storage-scaleup"` | no |
| enable\_edrs | True if EDRS is enabled. | `bool` | `true` | no |
| host\_instance\_type | The instance type for the ESX hosts in the primary cluster of the SDDC. Possible values: I3\_METAL, R5\_METAL. | `string` | `"I3_METAL"` | no |
| max\_hosts | The maximum number of hosts that the cluster can scale out to. | `number` | n/a | yes |
| min\_hosts | The minimum number of hosts that the cluster can scale in to. | `number` | n/a | yes |
| num\_hosts | The number of hosts. | `number` | `1` | no |
| org | Organisation descriptor for resource naming. | `string` | `"wh"` | no |
| org\_id | VMC Organisation ID | `string` | n/a | yes |
| provider\_type | Determines what additional properties are available based on cloud provider. Default value : AWS | `string` | `"AWS"` | no |
| public\_ip\_displayname | Display name for public IP. | `string` | `""` | no |
| sddc\_name | Name of SDDC. | `string` | n/a | yes |
| sddc\_region | The AWS  or VMC specific region. | `string` | `"eu-west-1"` | no |
| sddc\_type | Denotes the sddc type, if the value is null or empty, the type is considered as default. Possible values : '1NODE', 'DEFAULT'. | `string` | `"1NODE"` | no |
| size | The size of the vCenter and NSX appliances. | `string` | `"medium"` | no |
| storage\_capacity | The storage capacity value to be requested for the SDDC primary cluster. This variable is only for R5.METAL. Possible values are 15TB, 20TB, 25TB, 30TB, 35TB per host. | `string` | `""` | no |
| subnet\_1 | array number for the subnet you want to deploy the SDDC on | `number` | `0` | no |
| subnet\_2 | array number of the second subnet if deploying a stretched SDDC | `number` | `1` | no |
| vpc\_cidr | SDDC management network CIDR. Only prefix of 16, 20 and 23 are supported. | `string` | n/a | yes |
| vxlan\_subnet | A logical network segment that will be created with the SDDC under the compute gateway. | `string` | `""` | no |

## Outputs

| Name | Description |
|------|-------------|
| cloud\_password | n/a |
| cloud\_username | n/a |
| nsxt\_reverse\_proxy | n/a |
| vc\_url | n/a |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->