# environments/eu-west-1/nonprod/provider.tf

terraform {
  required_version = ">= 1.10.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.3.0"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = "~> 1.49.0"
    }
  }
}

provider "aws" {
  region = var.region
}