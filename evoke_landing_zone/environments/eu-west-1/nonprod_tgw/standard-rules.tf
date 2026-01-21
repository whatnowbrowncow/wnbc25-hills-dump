# ========================================
# ENVIRONMENT IP RULES
# ========================================
locals {
  environment_ip_rules = [
    {
      name        = "ping-cloudflare-dns"
      action      = "PASS"
      protocol    = "ICMP"
      source      = "ANY"
      destination = "1.0.0.1"
      port        = "ANY"
      description = "TEST RULE: Allows ICMP pings to Cloudflare DNS (1.1.1.1) for firewall testing"
    },
  ]
}