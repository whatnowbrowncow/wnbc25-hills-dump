variable "api_token" {

}

variable "policy_name" {
  description = "Name of the Policy"
  default     = "Core_Management"
}

variable "policy_description" {
  description = "Policy Desciption"
  default     = "Core connectivity rules"
}

variable "specific_policy_name" {
  description = "Name of the Policy"
  default     = "SDDC_Specific"
}

variable "specific_policy_description" {
  description = "Policy Desciption"
  default     = "Rules specific to this SDDC"
}

variable "segment_policy_name" {
  description = "Name of the Policy"
  default     = "Segment-Segment-Any"
}

variable "segment_policy_description" {
  description = "Policy Desciption"
  default     = "ANY-ANY rule within a segment"
}

variable "category" {
  description = "Catagory within DFW"
  default     = "Application"
}

variable "stateful" {
  description = "boolean value to determine if the section is stateful or not."
  default     = true
}

variable "segments" {
  default = [
    /*
    {
      name         = "10.156.4.0S25"
      network      = "10.156.4.0/25"
      gw_cidr      = "10.156.4.1/25"
      connectivity = "ON"
    },
    {
      name         = "10.120.139.0S27"
      network      = "10.120.139.0/27"
      gw_cidr      = "10.120.139.1/27"
      connectivity = "ON"
    },
    {
      name         = "10.120.36.0S24"
      network      = "10.120.36.0/24"
      gw_cidr      = "10.120.36.1/24"
      connectivity = "ON"
    },
    {
      name         = "10.120.71.0S24"
      network      = "10.120.71.0/24"
      gw_cidr      = "10.120.71.1/24"
      connectivity = "ON"
    },
    {
      name         = "10.120.192.128S27"
      network      = "10.120.192.128/27"
      gw_cidr      = "10.120.192.129/27"
      connectivity = "ON"
    },
    {
      name         = "10.156.5.128S27"
      network      = "10.156.5.128/27"
      gw_cidr      = "10.156.5.129/27"
      connectivity = "ON"
    },
    {
      name         = "10.120.163.0S24V309"
      network      = "10.120.163.0/24"
      gw_cidr      = "10.120.163.1/24"
      connectivity = "ON"
    },
    {
      name         = "10.120.141.0S24V321"
      network      = "10.120.141.0/24"
      gw_cidr      = "10.120.141.1/24"
      connectivity = "ON"
    },
    {
      name         = "10.120.143.64S27V334"
      network      = "10.120.143.64/27"
      gw_cidr      = "10.120.143.65/27"
      connectivity = "ON"
    },
    {
      name         = "10.120.151.0S24V347"
      network      = "10.120.151.0/24"
      gw_cidr      = "10.120.151.1/24"
      connectivity = "ON"
    },
    */
  ]
}

variable "service_management_cidr" {
  description = "CIDR assigned to the SDDC for our management infrastructure"
  default     = "10.156.4.0/25"
}

########### below are for VROPS master node that the collector will connect to  #########

variable "vrops_env_master_node" {
  description = "IP of the env master vrops node"
  default     = "10.120.134.250"
}

variable "vrops_env_master_node_name" {
  description = "name of the env master vrops node"
  default     = "sc1prapvro01"
}

########### below are for the remote state bucket and key #########
variable org {
  default = "wh"
}

variable channel {
  default = "it-ops"
}

variable product {
  default = "scc-prod-nonwhc"
}

variable env {
  default = "prod"
}

variable region {
  default = "eu-west-1"
}

########### only used by make here for clean output #################
variable aws_role {
  default = ""
}

variable channel_account_id {
  default = ""
}
