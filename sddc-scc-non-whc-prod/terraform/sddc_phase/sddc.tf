
##### Build the SDDC ######
module "sddc" {
  source = "git::https://gitlab.com/williamhillplc/technical-services/infrastructure-and-engineering/vmc/modules/tf-vmc-sddc.git?ref=2.1.0"

  aws_account_number = var.aws_account_number
  clusters           = var.clusters
  deployment_type    = var.deployment_type
  host_instance_type = var.host_instance_type
  num_hosts          = var.num_hosts
  provider_type      = var.provider_type
  sddc_name          = var.sddc_name
  sddc_region        = var.sddc_region
  sddc_type          = var.sddc_type
  size               = var.size
  subnet_1           = var.subnet_1
  subnet_2           = var.subnet_2
  vpc_cidr           = var.vpc_cidr
  vxlan_subnet       = var.vxlan_subnet
  edrs_policy_type   = var.edrs_policy_type
  enable_edrs        = var.enable_edrs
  min_hosts          = var.min_hosts
  max_hosts          = var.max_hosts

}