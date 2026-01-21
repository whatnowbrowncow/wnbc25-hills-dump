# ========================================
# ENVIRONMENT IP RULES
# ========================================
locals {
  environment_ip_rules = [
    {
      name        = "ping-cloudflare-dns" # Rule name
      action      = "PASS" # PASS / DROP
      protocol    = "ICMP" # ICMP / TCP / UDP 
      source      = "ANY" # ANY / IP (1.1.1.1) / Network (10.0.0.0/8)
      destination = "1.0.0.1" # ANY / IP (1.1.1.1) / Network (10.0.0.0/8)
      port        = "ANY" # ANY / Port number 53 / Port range 48000-48030
      description = "TEST RULE: Allows ICMP pings to Cloudflare DNS (1.1.1.1) for firewall testing" # Rule Description
    },
  ]
}