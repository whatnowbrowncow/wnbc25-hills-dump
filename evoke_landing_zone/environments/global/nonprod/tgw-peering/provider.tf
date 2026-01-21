terraform {
  required_version = ">= 1.10.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.3"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = "~> 1.49.0"
    }
  }
}

provider "aws" {
  region = var.local_region
}

# Your existing aliased providers
provider "aws" {
  alias  = "local"
  region = var.local_region
}

provider "aws" {
  alias  = "peer"
  region = var.peer_region
}