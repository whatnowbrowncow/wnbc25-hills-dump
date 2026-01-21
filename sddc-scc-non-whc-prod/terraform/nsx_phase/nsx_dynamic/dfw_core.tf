module "dfw_core" {
  source                  = "git::https://gitlab.com/williamhillplc/technical-services/infrastructure-and-engineering/vmc/modules/tf-vmc-dfw?ref=3.0.23"
  policy_name             = var.policy_name
  category                = var.category
  policy_description      = var.policy_description
  stateful                = var.stateful
  service_management_cidr = var.service_management_cidr
}
