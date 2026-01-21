terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 2.0"
    }
    nsxt = {
      source  = "vmware/nsxt"
      version = "~> 3.2.2"
    }
  }
  required_version = "0.13.4"
}
