terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.87.0"
    }
    nsxt = {
      source  = "vmware/nsxt"
      version = "~> 3.8.0"
    }
  }
  required_version = "~> 1.10.5"
}
