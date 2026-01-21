provider "vmc" {
  refresh_token = var.api_token
  org_id        = var.org_id
}

provider "aws" {
  region = var.sddc_region
}
