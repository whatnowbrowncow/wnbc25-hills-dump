# ==================================================
# CLIENT VPC MODULE - Variables
# ==================================================

# ==================================================
# BASIC CONFIGURATION
# ==================================================
variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "account_name" {
  description = "Account name for resource identification"
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., prod, nonprod, dev, staging)"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones to use"
  type        = list(string)
  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones are required for high availability."
  }
}

# ==================================================
# NETWORK CONFIGURATION
# ==================================================
variable "vpc_cidr" {
  description = "VPC CIDR block allocated from Infoblox"
  type        = string
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "workload_subnets" {
  description = "Workload subnet CIDR blocks from Infoblox (one per AZ)"
  type        = list(string)
  validation {
    condition     = alltrue([for cidr in var.workload_subnets : can(cidrhost(cidr, 0))])
    error_message = "All workload subnet CIDRs must be valid IPv4 CIDR blocks."
  }
}

variable "tgw_subnets" {
  description = "Transit Gateway attachment subnet CIDR blocks from Infoblox (one per AZ)"
  type        = list(string)
  validation {
    condition     = alltrue([for cidr in var.tgw_subnets : can(cidrhost(cidr, 0))])
    error_message = "All TGW subnet CIDRs must be valid IPv4 CIDR blocks."
  }
}

# ==================================================
# TRANSIT GATEWAY CONFIGURATION
# ==================================================
variable "transit_gateway_id" {
  description = "ID of the Transit Gateway to attach to"
  type        = string
}

variable "tgw_default_route_table_association" {
  description = "Whether to associate with the default TGW route table"
  type        = bool
  default     = true
}

variable "tgw_default_route_table_propagation" {
  description = "Whether to propagate routes to the default TGW route table"
  type        = bool
  default     = true
}

variable "appliance_mode_support" {
  description = "Enable appliance mode support for TGW attachment (for stateful appliances)"
  type        = bool
  default     = false
}

variable "create_default_tgw_route" {
  description = "Create a default route (0.0.0.0/0 or custom) pointing to TGW in workload route table"
  type        = bool
  default     = true
}

variable "default_route_cidr" {
  description = "CIDR block for default route to TGW (typically 0.0.0.0/0 or 10.0.0.0/8)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "additional_workload_routes" {
  description = "Additional routes to add to workload route table (CIDR -> TGW)"
  type        = map(string)
  default     = {}
  # Example:
  # {
  #   "10.0.0.0/8"    = "Transit Gateway"
  #   "172.16.0.0/12" = "Transit Gateway"
  # }
}

# ==================================================
# VPC FLOW LOGS
# ==================================================
variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_logs_traffic_type" {
  description = "Type of traffic to log (ACCEPT, REJECT, or ALL)"
  type        = string
  default     = "ALL"
  validation {
    condition     = contains(["ACCEPT", "REJECT", "ALL"], var.flow_logs_traffic_type)
    error_message = "Flow logs traffic type must be ACCEPT, REJECT, or ALL."
  }
}

variable "flow_logs_retention_days" {
  description = "Number of days to retain flow logs in CloudWatch"
  type        = number
  default     = 7
}

variable "flow_logs_destination_arn" {
  description = "ARN of existing CloudWatch Log Group for flow logs (optional, will create if not provided)"
  type        = string
  default     = ""
}

variable "flow_logs_role_arn" {
  description = "ARN of existing IAM role for flow logs (optional, will create if not provided)"
  type        = string
  default     = ""
}

# ==================================================
# TEST INSTANCE CONFIGURATION
# ==================================================
variable "enable_test_instance" {
  description = "Enable creation of a test instance in workload subnet"
  type        = bool
  default     = false
}

variable "test_instance_type" {
  description = "EC2 instance type for test instance"
  type        = string
  default     = "t3.micro"
}

variable "ssh_key_name" {
  description = "Name of the SSH key pair for test instance"
  type        = string
  default     = ""
}

variable "test_instance_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH to test instance"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

# ==================================================
# TAGS
# ==================================================
variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
