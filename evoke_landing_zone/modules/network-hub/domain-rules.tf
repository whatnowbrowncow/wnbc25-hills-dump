# ==================================================
# Domain Rules Configuration
# ==================================================

locals {
  # Global domain-based rules for all environments
  global_domain_rules = {
    allowed_domains = [
      ".amazon.com",
      "example.com",
    ]
  }
}

# If/When we use a seperate repo to manage endpoints
#locals {
#  raw_domains = split("\n", file("${path.module}/../../config/global_allowed_endpoints.txt"))
#  # Filter out comments and empty lines
#  external_domains = [
#    for domain in local.raw_domains : trimspace(domain)
#    if trimspace(domain) != "" && !startswith(trimspace(domain), "#")
#  ]
#}