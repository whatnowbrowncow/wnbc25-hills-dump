variable "api_token" {
  type    = string
  default = ""
}

variable "aws_account_number" {
  type = string
}

variable "aws_role" {
  type    = string
  default = ""
}

variable "channel_account_id" {
  type    = string
  default = ""
}

/* ####### Example format for adding clusters replace {} with .... #######
[
    {
      cluster            = "2"
      num_hosts          = "6"
      host_instance_type = "I3_METAL"
    },
    {
      cluster            = "3"
      num_hosts          = "6"
      host_instance_type = "I3_METAL"
    }, 
  ]  
##########################################################################
*/

variable "clusters" {
  type        = list(any)
  description = "Used if creating more than 1 cluster in the SDDC the first cluster here will use be cluster 2 on the SDDC if having single cluster default = {}"
  default     = []
}

variable "deployment_type" {
  type        = string
  description = "Denotes if request is for a SingleAZ or a MultiAZ SDDC."
  default     = "SingleAZ"
}

variable "edrs_policy_type" {
  type        = string
  description = "The EDRS policy type. This can either be 'cost', 'performance', 'storage-scaleup' or 'rapid-scaleup'. Default : storage-scaleup."
  default     = "storage-scaleup"
}

variable "enable_edrs" {
  type        = bool
  description = "True if EDRS is enabled."
  default     = true
}

variable "host_instance_type" {
  type        = string
  description = "The instance type for the ESX hosts in the primary cluster of the SDDC. Possible values: I3_METAL, R5_METAL."
  default     = "I3_METAL"
}

variable "max_hosts" {
  type        = number
  description = "The maximum number of hosts that the cluster can scale out to."
}

variable "min_hosts" {
  type        = number
  description = "The minimum number of hosts that the cluster can scale in to."
}

variable "num_hosts" {
  type        = number
  description = "The number of hosts."
  default     = 1
}

variable "org" {
  type        = string
  description = "Organisation descriptor for resource naming."
  default     = "wh"
}

variable "org_id" {
  type        = string
  description = "VMC Organisation ID"
}

variable "provider_type" {
  type        = string
  description = "Determines what additional properties are available based on cloud provider. Default value : AWS"
  default     = "AWS"
}

variable "public_ip_displayname" {
  type        = string
  description = "Display name for public IP."
  default     = ""
}

variable "sddc_name" {
  type        = string
  description = "Name of SDDC."
}

variable "sddc_region" {
  type        = string
  description = "The AWS  or VMC specific region."
  default     = "eu-west-1"
}

variable "sddc_type" {
  type        = string
  description = "Denotes the sddc type, if the value is null or empty, the type is considered as default. Possible values : '1NODE', 'DEFAULT'. "
  default     = "1NODE"
}

variable "size" {
  type        = string
  description = "The size of the vCenter and NSX appliances."
  default     = "medium"
}

variable "storage_capacity" {
  type        = string
  description = "The storage capacity value to be requested for the SDDC primary cluster. This variable is only for R5.METAL. Possible values are 15TB, 20TB, 25TB, 30TB, 35TB per host."
  default     = ""
}

variable "subnet_1" {
  type        = number
  description = "array number for the subnet you want to deploy the SDDC on "
  default     = 0
}

variable "subnet_2" {
  type        = number
  description = "array number of the second subnet if deploying a stretched SDDC"
  default     = 1
}

variable "vpc_cidr" {
  type        = string
  description = "SDDC management network CIDR. Only prefix of 16, 20 and 23 are supported."
}

variable "vxlan_subnet" {
  type        = string
  description = "A logical network segment that will be created with the SDDC under the compute gateway."
  default     = ""
}