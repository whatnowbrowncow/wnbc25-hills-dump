module "segments" {
  source   = "git::https://gitlab.com/williamhillplc/technical-services/infrastructure-and-engineering/vmc/modules/tf-vmc-segments?ref=3.2.7"
  segments = var.segments
}
