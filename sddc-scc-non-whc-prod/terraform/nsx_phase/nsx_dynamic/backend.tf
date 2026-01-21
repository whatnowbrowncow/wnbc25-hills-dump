terraform {
  backend "s3" {
    bucket = "wh-it-ops-scc-prod-nonwhc-prod-eu-west-1-tfstate"
    key = "prod-nsx-dynamic.tfstate"
    region = "eu-west-1"
  }
}
