# ==================================================
# variables.tf
# ==================================================

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "network-services"
}

variable "account_name" {
  description = "Account name for resource identification"
  type        = string
  default     = "network-services-account"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-1"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
}

# Network configuration from Infoblox
variable "vpc_cidr" {
  description = "VPC CIDR block allocated from Infoblox"
  type        = string
  default     = "100.108.64.0/19"
}

variable "workload_subnets" {
  description = "CDE subnet CIDR blocks from Infoblox"
  type        = list(string)
  default = [
    "100.108.64.0/21",  # 1a
    "100.108.72.0/21",  # 1b
    "100.108.80.0/21"   # 1c
  ]
}

variable "tgw_subnets" {
  description = "Transit Gateway attachment subnet CIDR blocks from Infoblox"
  type        = list(string)
  default = [
    "100.108.95.208/28", # 1a
    "100.108.95.224/28", # 1b
    "100.108.95.240/28"  # 1c
  ]
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Environment    = "prod"
    Project        = "network-services"
    AccountName    = "network-services-account"
    ManagedBy      = "OpenTofu"
    Classification = "nonpublic"
    CardData       = "cde"
    Tier           = "client"
  }
}

variable "enable_test_instance" {
  description = "Enable creation of a test instance in NCDE subnet"
  type        = bool
  default     = true
}

variable "test_instance_type" {
  description = "EC2 instance type for test instance"
  type        = string
  default     = "t3.micro"
}

variable "ssh_key_name" {
  description = "Name of the SSH key pair for test instance"
  type        = string
  default     = "eu_west_1_prod_network_services.pem"
}

variable "transit_gateway_id" {
  description = "Transit gateway ID"
  type        = string
  default     = "tgw-064572ba47d22fb2a"
}
