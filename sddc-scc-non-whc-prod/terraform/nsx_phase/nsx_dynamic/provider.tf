provider "nsxt" {
  host                 = "10.126.236.3"
  vmc_token            = var.api_token
  vmc_auth_mode        = "Bearer"
  allow_unverified_ssl = true
  enforcement_point    = "vmc-enforcementpoint"
}

provider "aws" {
  region = "eu-west-1"
}

