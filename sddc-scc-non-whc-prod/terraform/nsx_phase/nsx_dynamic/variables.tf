variable "api_token" {
}

variable "nsx_password_ssm_parameter" {
  type        = string
  description = "The name of the SSM parameter that holds the actual password string"
  default     = "non_whc_prod_nsx_admin_pw" #tfsec:ignore:GEN001
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
    {
      name         = "10.120.100.0S24V262"
      network      = "10.120.100.0/24"
      gw_cidr      = "10.120.100.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.101.0S27V263"
      network      = "10.120.101.0/27"
      gw_cidr      = "10.120.101.1/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.102.0S24V264"
      network      = "10.120.102.0/24"
      gw_cidr      = "10.120.102.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.103.0S29"
      network      = "10.120.103.0/29"
      gw_cidr      = "10.120.103.1/29"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.129.0S24V301"
      network      = "10.120.129.0/24"
      gw_cidr      = "10.120.129.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.131.0S24V303"
      network      = "10.120.131.0/24"
      gw_cidr      = "10.120.131.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.132.0S24V304"
      network      = "10.120.132.0/24"
      gw_cidr      = "10.120.132.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.136.0S24V309"
      network      = "10.120.136.0/24"
      gw_cidr      = "10.120.136.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.137.0S24V310"
      network      = "10.120.137.0/24"
      gw_cidr      = "10.120.137.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.139.0S27"
      network      = "10.120.139.0/27"
      gw_cidr      = "10.120.139.1/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.140.0S24V320"
      network      = "10.120.140.0/24"
      gw_cidr      = "10.120.140.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.141.0S24V321"
      network      = "10.120.141.0/24"
      gw_cidr      = "10.120.141.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.143.64S27V334"
      network      = "10.120.143.64/27"
      gw_cidr      = "10.120.143.65/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.145.0S24V341"
      network      = "10.120.145.0/24"
      gw_cidr      = "10.120.145.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.146.0S24V342"
      network      = "10.120.146.0/24"
      gw_cidr      = "10.120.146.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.148.0S24V344"
      network      = "10.120.148.0/24"
      gw_cidr      = "10.120.148.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.149.0S24V345"
      network      = "10.120.149.0/24"
      gw_cidr      = "10.120.149.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.151.0S24V347"
      network      = "10.120.151.0/24"
      gw_cidr      = "10.120.151.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.152.0S24V348"
      network      = "10.120.152.0/24"
      gw_cidr      = "10.120.152.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.153.0S24V349"
      network      = "10.120.153.0/24"
      gw_cidr      = "10.120.153.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.159.96S27V365"
      network      = "10.120.159.96/27"
      gw_cidr      = "10.120.159.97/27"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.161.224S27V385"
      network      = "10.120.161.224/27"
      gw_cidr      = "10.120.161.225/27"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.162.0S24V398"
      network      = "10.120.162.0/24"
      gw_cidr      = "10.120.162.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.163.0S24V399"
      network      = "10.120.163.0/24"
      gw_cidr      = "10.120.163.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.170.0S25V450"
      network      = "10.120.170.0/25"
      gw_cidr      = "10.120.170.1/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.170.128S25V451"
      network      = "10.120.170.128/25"
      gw_cidr      = "10.120.170.129/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.172.0S24V453"
      network      = "10.120.172.0/24"
      gw_cidr      = "10.120.172.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.173.0S25V460"
      network      = "10.120.173.0/25"
      gw_cidr      = "10.120.173.1/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.173.128S25V461"
      network      = "10.120.173.128/25"
      gw_cidr      = "10.120.173.129/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.177.0S25V480"
      network      = "10.120.177.0/25"
      gw_cidr      = "10.120.177.1/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.180.0S25V485"
      network      = "10.120.180.0/25"
      gw_cidr      = "10.120.180.1/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.180.128S25V486"
      network      = "10.120.180.128/25"
      gw_cidr      = "10.120.180.129/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.192.160S29V565"
      network      = "10.120.192.160/29"
      gw_cidr      = "10.120.192.161/29"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.192.168S29"
      network      = "10.120.192.168/29"
      gw_cidr      = "10.120.192.169/29"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.192.192S27"
      network      = "10.120.192.192/27"
      gw_cidr      = "10.120.192.193/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.193.224S27V575"
      network      = "10.120.193.224/27"
      gw_cidr      = "10.120.193.225/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.194.0S26V576"
      network      = "10.120.194.0/26"
      gw_cidr      = "10.120.194.1/26"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.194.192S26V579"
      network      = "10.120.194.192/26"
      gw_cidr      = "10.120.194.193/26"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.194.64S26V577"
      network      = "10.120.194.64/26"
      gw_cidr      = "10.120.194.65/26"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.195.0S24V580"
      network      = "10.120.195.0/24"
      gw_cidr      = "10.120.195.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.196.0S24V581"
      network      = "10.120.196.0/24"
      gw_cidr      = "10.120.196.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.208.0S24V650"
      network      = "10.120.208.0/24"
      gw_cidr      = "10.120.208.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.216.0S21V397"
      network      = "10.120.216.0/21"
      gw_cidr      = "10.120.216.1/21"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.254.208S29V989"
      network      = "10.120.254.208/29"
      gw_cidr      = "10.120.254.209/29"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.32.128S27V104"
      network      = "10.120.32.128/27"
      gw_cidr      = "10.120.32.129/27"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.32.96S27V103"
      network      = "10.120.32.96/27"
      gw_cidr      = "10.120.32.97/27"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.33.160S27V115"
      network      = "10.120.33.160/27"
      gw_cidr      = "10.120.33.161/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.33.192S26"
      network      = "10.120.33.192/26"
      gw_cidr      = "10.120.33.193/26"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.36.0S24"
      network      = "10.120.36.0/24"
      gw_cidr      = "10.120.36.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.37.0S24V121"
      network      = "10.120.37.0/24"
      gw_cidr      = "10.120.37.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.39.0S24V123"
      network      = "10.120.39.0/24"
      gw_cidr      = "10.120.39.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "/infra/dhcp-relay-configs/WH_DHCP"
    },
    {
      name         = "10.120.43.0S24V124"
      network      = "10.120.43.0/24"
      gw_cidr      = "10.120.43.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.44.0S23V134"
      network      = "10.120.44.0/23"
      gw_cidr      = "10.120.44.1/23"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.46.0S25V140"
      network      = "10.120.46.0/25"
      gw_cidr      = "10.120.46.1/25"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.65.128S27V235"
      network      = "10.120.65.128/27"
      gw_cidr      = "10.120.65.129/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.65.64S27V232"
      network      = "10.120.65.64/27"
      gw_cidr      = "10.120.65.65/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.65.96S27V234"
      network      = "10.120.65.96/27"
      gw_cidr      = "10.120.65.97/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.66.0S24V210"
      network      = "10.120.66.0/24"
      gw_cidr      = "10.120.66.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.67.0S24V211"
      network      = "10.120.67.0/24"
      gw_cidr      = "10.120.67.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.69.96S27V216"
      network      = "10.120.69.96/27"
      gw_cidr      = "10.120.69.97/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.69.192S27V219"
      network      = "10.120.69.192/27"
      gw_cidr      = "10.120.69.193/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.69.224S27V218"
      network      = "10.120.69.224/27"
      gw_cidr      = "10.120.69.225/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.70.0S27V223"
      network      = "10.120.70.0/27"
      gw_cidr      = "10.120.70.1/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.71.0S24"
      network      = "10.120.71.0/24"
      gw_cidr      = "10.120.71.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.72.0S24V222"
      network      = "10.120.72.0/24"
      gw_cidr      = "10.120.72.1/24"
      connectivity = "OFF"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.74.0S23V231"
      network      = "10.120.74.0/23"
      gw_cidr      = "10.120.74.1/23"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.76.0S24V233"
      network      = "10.120.76.0/24"
      gw_cidr      = "10.120.76.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.98.0S24V260"
      network      = "10.120.98.0/24"
      gw_cidr      = "10.120.98.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.99.0S24V261"
      network      = "10.120.99.0/24"
      gw_cidr      = "10.120.99.1/24"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.156.4.0S25"
      network      = "10.156.4.0/25"
      gw_cidr      = "10.156.4.1/25"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.156.5.128S27"
      network      = "10.156.5.128/27"
      gw_cidr      = "10.156.5.129/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    },
    {
      name         = "10.120.194.128S27"
      network      = "10.120.194.128/27"
      gw_cidr      = "10.120.194.129/27"
      connectivity = "ON"
      local_egress = "false"
      dhcp_relay   = "false"
    }
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
