# ========================================
# ENVIRONMENT DOMAIN RULES
# ========================================

#locals {
#  environment_domain_rules = {
#    allowed_domains = [
#      ".ifconfig.me", # .<some_domain> Whitelists all subdomains from parent
#      "bbc.co.uk", # Whitelists a specific domain
#    ]
#  }
#}

# If/When we use a seperate repo to manage endpoints
locals {
  # Read environment-specific domains from file
  env_domains = split("\n", trimspace(file("/gitnet/channels-team/evoke_landing_zone/modules/https_whitelist/prod_allowed_endpoints")))
  
  environment_domain_rules = {
    allowed_domains = [
      for domain in local.env_domains : trimspace(domain)
      if trimspace(domain) != "" && !startswith(trimspace(domain), "#")
    ]
  }
}