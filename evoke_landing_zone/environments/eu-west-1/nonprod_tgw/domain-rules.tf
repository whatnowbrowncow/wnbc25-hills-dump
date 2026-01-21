# ========================================
# ENVIRONMENT DOMAIN RULES
# ========================================
locals {
  environment_domain_rules = {
    allowed_domains = [
      ".ifconfig.me"
    ]
  }
}

# If/When we use a seperate repo to manage endpoints
#locals {
#  # Read environment-specific domains from file
#  env_domains = split("\n", trimspace(file("${path.root}/modules/https_whitelist/nonprod_allowed_endpoints")))
#  
#  environment_domain_rules = {
#    allowed_domains = [
#      for domain in local.env_domains : trimspace(domain)
#      if trimspace(domain) != "" && !startswith(trimspace(domain), "#")
#    ]
#  }
#}