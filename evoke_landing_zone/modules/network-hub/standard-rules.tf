# ==================================================
# Standard IP-based Rules Configuration
# ==================================================

locals {
  # Global IP-based rules that apply to ALL environments
  global_ip_rules = [
    {
      name        = "block-metadata-service"
      action      = "DROP"
      protocol    = "TCP"
      source      = "ANY"
      destination = "169.254.169.254"
      port        = "ANY"
      description = "GLOBAL: Block access to AWS metadata service"
    },
  ]
}