/*======================================
terraform import nsxt_policy_gateway_policy.mgw mgw/default

Scope for MGW is "/infra/labels/mgw"
========================================*/
data "nsxt_policy_tier0_gateway" "vmc" {
  display_name = "vmc"
}

resource "nsxt_policy_gateway_policy" "mgw" {

  category     = "LocalGatewayRules"
  description  = "Terraform provisioned Gateway Policy"
  display_name = "default"
  domain       = "mgw"

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/VCENTER"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "vCenter Inbound"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services = [
      "/infra/services/HTTPS",
      "/infra/services/ICMP-ALL",
      "/infra/services/SSO"
    ]
    source_groups = [
      nsxt_policy_group.SCC_vCentre_Mgmt.path,
      nsxt_policy_group.Bomgar.path,
      nsxt_policy_group.service_management_cidr.path,
      nsxt_policy_group.vrops_env_master_node.path,
      nsxt_policy_group.New_Relic.path,
      nsxt_policy_group.scc_oracle_prod_vc.path,
      nsxt_policy_group.scc_whc_prod_vc.path,
      nsxt_policy_group.commvault.path,
      nsxt_policy_group.ld6wnprxync01.path
    ]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = []
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "vCenter Outbound Rule"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services              = []
    source_groups         = ["/infra/domains/mgw/groups/VCENTER"]
    sources_excluded      = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/ESXI"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "ESXi Inbound"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services = [
      "/infra/services/HTTPS",
      "/infra/services/ICMP-ALL",
      "/infra/services/VMware_Remote_Console"
    ]
    source_groups    = [nsxt_policy_group.Bomgar.path]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = []
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "ESXi Outbound Rule"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services              = []
    source_groups         = ["/infra/domains/mgw/groups/ESXI"]
    sources_excluded      = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/VCENTER"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "Snow Asset Collector to vCentre"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services = [
      #"/infra/services/VMware-SRM-VAMI",
      #"/infra/services/Vmware-VC-VC-Internal",
      "/infra/services/HTTPS",
      "/infra/services/ICMP-ALL"
    ]
    source_groups    = [nsxt_policy_group.snow_asset_collector.path]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/VCENTER"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "VMC Citrix Controllers to vCentre"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services = [
      "/infra/services/HTTPS",
      "/infra/services/ICMP-ALL"
    ]
    source_groups    = [nsxt_policy_group.vmc_citrix_controllers.path]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/ESXI"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "ESXi Inbound"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services = [
      "/infra/services/HTTPS",
      "/infra/services/ICMP-ALL",
      "/infra/services/VMware_Remote_Console"
    ]
    source_groups    = [nsxt_policy_group.commvault.path]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/NSX-MANAGER"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "NSX Manager Inbound"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services = [
      "/infra/services/HTTPS"
    ]
    source_groups    = [nsxt_policy_group.anyconnect_vpn_ranges.path]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/NSX-MANAGER"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "NSX Manager Inbound Rule"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services              = ["/infra/services/HTTPS"]
    source_groups = [
      nsxt_policy_group.vrni_appliance.path
    ]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/VCENTER"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "vROps to vCentre"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services = [
      "/infra/services/HTTPS"
    ]
    source_groups    = [nsxt_policy_group.vrops_proxy.path]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = ["/infra/domains/mgw/groups/NSX-MANAGER"]
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "NSX Manager Inbound Rule"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services              = ["/infra/services/HTTPS"]
    source_groups = [
      nsxt_policy_group.aws_techops_prod.path
    ]
    sources_excluded = false
  }

  rule {
    action                = "ALLOW"
    destination_groups    = []
    destinations_excluded = false
    direction             = "IN_OUT"
    disabled              = false
    display_name          = "NSX_Outbound_Rule"
    ip_version            = "IPV4_IPV6"
    logged                = true
    profiles              = []
    scope                 = ["/infra/labels/mgw"]
    services              = []
    source_groups = [     
      "/infra/domains/mgw/groups/NSX-MANAGER"
    ]
    sources_excluded = false
  }

}
