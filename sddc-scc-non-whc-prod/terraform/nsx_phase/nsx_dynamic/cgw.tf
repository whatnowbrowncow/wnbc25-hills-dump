/*======================================
terraform import nsxt_policy_gateway_policy.cgw cgw/default

Scope for CGW (applied to:) are:
  INTERNET: "/infra/labels/cgw-public"
  DX:       "/infra/labels/cgw-direct-connect"  
  VPN:      "/infra/labels/cgw-vpn"  
  VPC:      "/infra/labels/cgw-cross-vpc"  
  ALL:      "/infra/labels/cgw-all"  
  
========================================*/

resource "nsxt_policy_group" "N-0-0-0-0S0" {
  lifecycle {
    create_before_destroy = true
  }
  description  = "WH_ANY - 0.0.0.0/0"
  display_name = "WH_ANY"
  domain       = "cgw"
  criteria {
    ipaddress_expression {

      ip_addresses = ["0.0.0.0/0"]

    }
  }
}

/*======================================
DO NOT ALTER OR REMOVE THE SEQUENCE NUMBER
ON THE DEFAULT POLICY RESOURCE BELOW!
========================================*/

resource "nsxt_policy_gateway_policy" "cgw" {

  category        = "LocalGatewayRules"
  description     = "Terraform provisioned Gateway Policy"
  display_name    = "default"
  sequence_number = "20"
  domain          = "cgw"

  # New rules below . . 
  # Order in code below is order in GUI  
  rule {
    action = "ALLOW"
    destination_groups = [
      "/infra/tier-0s/vmc/groups/s3_prefixes",
    "/infra/tier-0s/vmc/groups/connected_vpc"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "Any to AWS"
    ip_version            = "IPV4_IPV6"
    logged                = false
    profiles              = []
    scope                 = ["/infra/labels/cgw-cross-vpc"]
    services              = []
    source_groups         = []
    sources_excluded      = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = []
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "AWS to Any"
    ip_version            = "IPV4_IPV6"
    logged                = false
    profiles              = []
    scope                 = ["/infra/labels/cgw-cross-vpc"]
    services              = []
    source_groups = [
      "/infra/tier-0s/vmc/groups/s3_prefixes",
    "/infra/tier-0s/vmc/groups/connected_vpc"]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = [nsxt_policy_group.N-0-0-0-0S0.path]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = true
    display_name          = "Any - ANY to VPN"
    ip_version            = "IPV4_IPV6"
    logged                = false
    profiles              = []
    scope                 = ["/infra/labels/cgw-vpn"]
    services              = []
    source_groups         = [nsxt_policy_group.N-0-0-0-0S0.path]
    sources_excluded      = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = [nsxt_policy_group.N-0-0-0-0S0.path]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "Any - ANY to DFW"
    ip_version            = "IPV4_IPV6"
    logged                = false
    profiles              = []
    scope                 = ["/infra/labels/cgw-all"]
    services              = []
    source_groups         = [nsxt_policy_group.N-0-0-0-0S0.path]
    sources_excluded      = false
  }
}
