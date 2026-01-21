terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 2.0"
    }
    vmc = {
      source  = "vmware/vmc"
      version = "~> 1.5.1"
    }
  }
  required_version = "0.13.4"
}

