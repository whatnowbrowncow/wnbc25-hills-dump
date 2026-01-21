/*======================================

############ Example Format ############

resource "nsxt_policy_security_policy" "policy1" {
  display_name = "policy1"
  description = "Terraform provisioned Security Policy"
  category = "Application"
  locked = false
  stateful = true
  tcp_strict = false
  scope = [nsxt_policy_group.pets.path]
 
  rule {
    display_name = "block_icmp"
    destination_groups = [nsxt_policy_group.cats.path, nsxt_policy_group.dogs.path]
    action = "DROP"
    services = [nsxt_policy_service.icmp.path]
    logged = true
  }
 
  rule {
    display_name = "allow_udp"
    source_groups = [nsxt_policy_group.fish.path]
    sources_excluded = true
    scope = [nsxt_policy_group.aquarium.path]
    action = "ALLOW"
    services = [nsxt_policy_service.udp.path]
    logged = true
    disabled = true
    notes = "Disabled by starfish for debugging"
  }
}


How we will format and standardise this:

- The policy_security_policy on initial build is split into 2 sections: "Core_Management" and "SDDC_Specific"
  - "Core_Management" section holds the base rules for the SDDC, deployed when the SDDC is     instantiated and fully managed based on the Infra CoE team "dfw_core" TF module
  - "SDDC_Specific" section holds all channel specific rules for the SDDC. This is the section into which channel rules are deployed and is managed by Network Services
  
- The intial Security Policy resource names, display_names, descriptions, category, and stateful variables are fixed by the Infa CoE team TF code

- Additional Security Policy sections can be defined to allow for splitting up of the DFW rules into logical sections. E.g. for the SCC migration we will create a section for each ASA firewall context
- Each rule is defined in a "rule" section in the main nsxt_policy_security_policy TF resource:
  - "display_name" is optional, but would be useful to help identify a rule's purpose in the VMC GUI
  - "description" is a required element and must contain the ServiceNow FAR reference(s) for this rule


resource "nsxt_policy_security_policy" "( section_name )" {
  display_name = "( section_name )"
  description  = "Firewall section for ( section_name ) - ${var.specific_policy_description}"
  category     = var.category
  stateful     = var.stateful
  domain       = "cgw"
  rule {
    display_name       = "( rule_description | leave blank )"
    description        = "Change ref: ( list_of_far_refs )"
    action             = "( ALLOW | DROP )"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    source_groups      = [( list_of_source_groups )]
    destination_groups = [( list_of_destination_groups )]
    services           = [( list_of_service_groups )]
  }
  rule {
    display_name       = "( rule_description )"
    description        = "Change ref: ( list_of_far_refs )"
    action             = "( ALLOW | DROP )"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    source_groups      = [( list_of_source_groups )]
    destination_groups = [( list_of_destination_groups )]
    services           = [( list_of_service_groups )]
  }
}

======================================*/

resource "nsxt_policy_security_policy" "pr-n-mgt" {
  display_name    = "pr-n-mgt"
  description     = "Firewall section for pr-n-mgt"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "40"
  domain          = "cgw"
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_1"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_inv-cde-mgmt-lan.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_14.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_3"
    description        = "Change ref: CHG0079131"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_238.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_4"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_inv-cde-mgmt-lan.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-9977_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_6"
    description        = "Change ref: CHG0067660"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxpremg02.path]
    services           = [nsxt_policy_service.pr-n-mgt_katello-tcp.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_8"
    description        = "Change ref: CHG0067823 - NCDE Jumpnet to NTP"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_wh-ntp-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_ntp-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_10"
    description        = "Change ref: CHG0068990 - NCDE Jumpnet to Cell Mon (CX Prod)"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_pr-cde-front-cx-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_cellmon-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_12"
    description        = "Change ref: CHG0068990 - NCDE Jumpnet to Puppet Master (CX Prod), CHG0071650,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_pr-cde-stingray-dest-nets.path]
    services           = [nsxt_policy_service.pr-n-mgt_stingray-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_14"
    description        = "Change ref: CHG0071650"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_pr-cde-stingray-dest-nets.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_56.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_16"
    description        = "Change ref: CHG0075762, PCI Q4 2018"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_git-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_18"
    description        = "Change ref: CHG0076315"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_pr-cde-front-cx-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_puppet-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_22"
    description        = "Change ref: CHG0114418, PCI-Q4-2017"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-sc1-bomgar-appliances.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-syslog-svrs.path]
    services           = [nsxt_policy_service.pr-n-mgt_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_24"
    description        = "Change ref: CHG0114956"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-sc1-bomgar-appliances.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-rsa-svrs.path]
    services           = [nsxt_policy_service.pr-n-mgt_udp-1812_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_26"
    description        = "Change ref: CHG0115563"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-151-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_invxpup06mst001-inv-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp_8140.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_access_in_28"
    description        = "Change ref: CHG0120024"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-non-cde-jump.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_group-shop-network.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_sc1-noncde-jumphost-lan_to_any_deny"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-mgt_any_to_sc1-noncde-jumphost-lan_permit"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
  }
  rule {
    display_name       = "pr-n-mgt_web-tier_access_in_2"
    description        = "Change ref: CHG0020856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-mgt_web-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sccuxstnmg01.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_22.path]
  }
  rule {
    display_name       = "pr-n-mgt_web-tier_access_in_4"
    description        = "Change ref: CHG0100330, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-145-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_47.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_16.path]
  }
  rule {
    display_name       = "pr-n-mgt_web-tier_access_in_6"
    description        = "Change ref: CHG0017824, CHG0018398"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_web-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-ldap.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8275_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_web-tier_access_in_9"
    description        = "Change ref: CHG0024637, CHG0027079 ,CHG0024637, CHG0027079"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_122.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_web-tier_access_in_11"
    description        = "Change ref: CHG0030474"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1apprnwb91.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_93.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_web-tier_access_in_13"
    description        = "Change ref: CHG0077536, CHG0077975 - IRS do not disable"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_web-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_hp-irs-server.path]
    services           = [nsxt_policy_service.pr-n-mgt_hp-irs-target-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_web-tier_access_in_15"
    description        = "Change ref: CHG0125694"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-145-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_10-120-214-40-59.path]
    services           = [nsxt_policy_service.pr-n-mgt_nas-access-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_2"
    description        = "Change ref: CHG0018398"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-mgt_app-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-ad-dc.path]
    services           = [nsxt_policy_service.pr-n-mgt_grp-pr-c-ad-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_4"
    description        = "Change ref: CHG0020856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_app-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sccuxstnmg01.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_20.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_6"
    description        = "Change ref: CHG0137956"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1uxprgdb05.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ld6-ncde_db-general-db.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_76.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_10"
    description        = "Change ref: CHG0075769"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_oracle-db-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-201-9-248.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_12"
    description        = "Change ref: CHG0051845"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-redhat-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_cde-server-ilo-network-24.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcpudp-623.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_14"
    description        = "Change ref: CHG0063608"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_trs_db_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_185.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_75.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_16"
    description        = "Change ref: CHG0065871"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprncp002-mgmt-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_uk-scc-wsus.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc_wsus_ports_tcp.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_18"
    description        = "Change ref: CHG0077536, CHG0077975 - IRS do not disable"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-mgt_app-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_hp-irs-server.path]
    services           = [nsxt_policy_service.pr-n-mgt_hp-irs-target-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_20"
    description        = "Change ref: CHG0076656"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_qlickview_app_mgt.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnpremg001-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_rds_udp_tcp.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_22"
    description        = "Change ref: CHG0079620, PCI Q4 2018"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprndb019.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-100-9-230.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_40.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_24"
    description        = "Change ref: CHG0080407, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_spin2win-sql-svrs.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_sc1uxprndb037-38_ilo.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcpudp-623.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_26"
    description        = "Change ref: CHG0095011, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_trs_db_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1-enc02-ilo4.path]
    services           = [nsxt_policy_service.pr-n-mgt_udp-623_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_28"
    description        = "Change ref: CHG0095011, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_trs_db_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1-enc04-ilo9.path]
    services           = [nsxt_policy_service.pr-n-mgt_udp-623_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_30"
    description        = "Change ref: CHG0111088"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_commvault-backup-networks.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-46-0s25.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_63.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_32"
    description        = "Change ref: CHG0112168"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-trading-oracle-cluster.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-enc-ilo-nodes.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-udp-623.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_34"
    description        = "Change ref: CHG0125459"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-trading-oracle-cluster.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_brsuxoemapp01.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-4903_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_36"
    description        = "Change ref: CHG0119471"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_124.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_126.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_38"
    description        = "Change ref: CHG0120138"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_scc-nas-ip-range.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcpudp_1.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_40"
    description        = "Change ref: CHG0124796"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_147.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_brsuxoemapp01.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-4903.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_42"
    description        = "Change ref: CHG0125493"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_10-120-214-40-59.path]
    services           = [nsxt_policy_service.pr-n-mgt_nas-access-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_44"
    description        = "Change ref: CHG0126301, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_154.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ld6-ncde_db-general-db.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_46"
    description        = "Change ref: CHG0134947"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-trading-oracle-cluster.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-201-9-248.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_48"
    description        = "Change ref: CHG0145480"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1uxprgdb05_clone.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ld6-ncde_db-general-db.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_app-tier_access_in_52"
    description        = "Change ref: test"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-115.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_4"
    description        = "Change ref: CHG0020856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-mgt_backoffice-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sccuxstnmg01.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_21.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_6"
    description        = "Change ref: CHG002645"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_117.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_118.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_23.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_7"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb11.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_8"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb12.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_10"
    description        = "Change ref: CHG0051856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb05.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_11"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb06.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_13"
    description        = "Change ref: CHG0057127"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-148-10.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-194-15.path]
    services           = [nsxt_policy_service.pr-n-mgt_ad_auth_ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_15"
    description        = "Change ref: CHG0057127"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-148-10.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-194-15.path]
    services           = [nsxt_policy_service.pr-n-mgt_ad_auth_ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_17"
    description        = "Change ref: CHG0065871"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprncp001-mgmt-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_uk-scc-wsus.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc_wsus_ports_tcp.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_19"
    description        = "Change ref: CHG0078799"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprncp001.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-3-20-45.path]
    services           = [nsxt_policy_service.pr-n-mgt_hp-laserjet-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_21"
    description        = "Change ref: CHG0086757"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-mgt_prod-misvr1.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_prod-misvr1-brs.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-873_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_23"
    description        = "Change ref: CHG0120037,CHG0132114"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprncp001-mgmt-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_171.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_41.path]
  }
  rule {
    display_name       = "pr-n-mgt_backoffice-tier_access_in_25"
    description        = "Change ref: CHG0125694"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-mgt_backoffice-tier-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_10-120-214-40-59.path]
    services           = [nsxt_policy_service.pr-n-mgt_nas-access-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_2"
    description        = "Change ref: CHG0146120"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc_mrr_db.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_voip-infrastructure.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-1504_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_5"
    description        = "Change ref: CHG0144335 ,CHG0020856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ods-mgmt-network-24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sccuxstnmg01.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_19.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_7"
    description        = "Change ref: CHG0018415,CHG0026456"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_116.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-ad-dc.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_22.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_9"
    description        = "Change ref: CHG0040354, CHG0041623"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_92.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_82.path]
    services           = [nsxt_policy_service.pr-n-mgt_mrr-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_11"
    description        = "Change ref: CHG0060685"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_ods-ad-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_ad-controllers-brs-scc.path]
    services           = [nsxt_policy_service.pr-n-mgt_active-directory-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_13"
    description        = "Change ref: CHG0067748"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-dr-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_cluster-ports-tcp.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_14"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-dr-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_cluster-ports-udp.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_16"
    description        = "Change ref: CHG0087898"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1nsml01.path]
    services           = [nsxt_policy_service.pr-n-mgt_dns.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_20"
    description        = "Change ref: CHG0130146, CHG0145624"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_78.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_22"
    description        = "Change ref: CHG0130146"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_gibwnprefs01-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_24"
    description        = "Change ref: CHG0087149, PCI Q4 2018"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-mgt_dmtestbench-prod.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnpremg001-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_rds_udp_tcp.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_26"
    description        = "Change ref: CHG0077536, CHG0077975 - IRS do not disable"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-149-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_hp-irs-server.path]
    services           = [nsxt_policy_service.pr-n-mgt_hp-irs-target-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_ods-mgmt_access_in_28"
    description        = "Change ref: CHG0141618, temporal rule with duration 90 days starting on 03/06/2020"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-180-139-145.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-1526_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_noncde-cf-app-mgmt_access_in_2"
    description        = "Change ref: CHG0059032, CHG0073258, CHG0080779"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_172.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-nap-wily.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_noncde-cf-app-mgmt_access_in_4"
    description        = "Change ref: CHG0080020"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_net-10-120-153-0_24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_noncde-cf-app-mgmt_access_in_6"
    description        = "Change ref: CHG0080075"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-scc-spin-mgt.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-nap-wily.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_noncde-cf-app-mgmt_access_in_8"
    description        = "Change ref: CHG0072188"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_market-services-server.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-nap-wily.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_noncde-cf-app-mgmt_access_in_10"
    description        = "Change ref: CHG0074773"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_220.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_gibux208-williamhill-remote.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_noncde-cf-app-mgmt_access_in_12"
    description        = "Change ref: CHG0078186"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_231.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-nap-wily.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_noncde-cf-app-mgmt_access_in_14"
    description        = "Change ref: CHG0081799"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-153-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-wily.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_8"
    description        = "Change ref: chg0033456,CHG0058571 ,chg0033456, CHG0058571, CHG0140904, CHG0139389, CHG0139430, CHG0141789 ,CHG0140904"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-idam-sftp-access.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprein14-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_10"
    description        = "Change ref: CHG0137956"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ld6-ncde_db-general-db.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_54.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_45.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_11"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_168.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_169.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_12"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_sailpoint-group.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprein14-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_14"
    description        = "Change ref: CHG0132959"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_gibux950.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_9.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_16"
    description        = "Change ref: CHG0132959"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ob-vpn-range.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_177.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_20"
    description        = "Change ref: CHG0065642, CHG0089931, CHG0092047, CHG0092666, CHG0093640, CHG0096830, CHG0097522, CHG0100390, ,CHG0104868, CHG0105337, CHG0106532, CHG0106972, CHG0108637, CHG0113574,RITM0091779,TASK0175697, ,TASK0177655"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_201.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb81.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_80.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_22"
    description        = "Change ref: CHG0131075, CHG0136900"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_sdp-intergation-access.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprnap024-mgmt-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_24"
    description        = "Change ref: CHG0065642"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_193.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_uk-dr-in-an.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_26"
    description        = "Change ref: CHG0065642, PCI Q4 2018"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_197.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_sas-prod-crm-analytics.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_28"
    description        = "Change ref: CHG0065642, CHG0078738,CHG0118447,CHG0118139, RITM0100229,TASK0192509,TASK0195603"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_206.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    services           = [nsxt_policy_service.pr-n-mgt_sas-admin-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_31"
    description        = "Change ref: CHG0065642, CHG0086510, CHG0086808, CHG0113948, TASK0225279 ,CHG0065642, CHG0086510, CHG0086808, CHG0113948, TASK0225279"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_235.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_71.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_33"
    description        = "Change ref: CHG0112916, CHG0112277, CHG0112268  CHG0113350"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-trading-r-and-d.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_69.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_35"
    description        = "Change ref: CHG0134318, CHG0134516, CHG0135124, CHG0135513, TASK0224888, CHG0136186"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_malta-bi-users.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_4.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_38"
    description        = "Change ref: CHG0134318, CHG0134516, CHG0135124, CHG0135513, TASK0224888,CHG0136186 ,CHG0134318, CHG0134516, CHG0135124, CHG0135513, TASK0224888,CHG0136186, RITM0123628"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_malta-bi-users.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprnmg020.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_40"
    description        = "Change ref: CHG0023206, CHG0021275, CHG0071526"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_orbis.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_37.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_42"
    description        = "Change ref: CHG0076619, CHG0077863"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-ta-gsh-testers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-scc-ta-db-2.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_85.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_44"
    description        = "Change ref: CHG0020368, CHG0021040"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-c-nms-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_rfc-1918.path]
    services           = [nsxt_policy_service.pr-n-mgt_nms.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_46"
    description        = "Change ref: CHG0035636"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_sc1-networkmonitoring.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-159-0s27.path]
    services           = [nsxt_policy_service.pr-n-mgt_udp-snmp_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_49"
    description        = "Change ref: CHG0018415"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_2.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-mgmt-vlans.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_9.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_53"
    description        = "Change ref: CHG0018415"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-n-mgt_uk-scc-wsus.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-mgmt-vlans.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-kms-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_56"
    description        = "Change ref: CHG0018398 ,CHG0017824, CHG0018398"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-ad-dc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-mgmt-vlans.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_5.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_58"
    description        = "Change ref: CHG0019830, CHG0020211, CHG0022219, CHG0022372, CHG0026654,CHG0085414"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-moni-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_119.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_23.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_63"
    description        = "Change ref: CHG0017758, CHG0036853,CHG0036855, CHG0036892, CHG0058264, ,CHG0058588, CHG0060471, CHG0115369"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_7.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_6.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_20.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_67"
    description        = "Change ref: CHG0138643"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-orion-app-srvs.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_net-obj-g-solarwinds-destinations.path]
    services           = [nsxt_policy_service.pr-n-mgt_svc-obj-g-solarwinds.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_69"
    description        = "Change ref: CHG0013113, Administration to Cisco VCS, CHG0024220, CHG0113778"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_81.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_80.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_3.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_72"
    description        = "Change ref: CHG0013113, CHG0113778 ,Administration to Cisco VCS"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_3.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_84.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_2.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_74"
    description        = "Change ref: CHG0020353,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_29.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1apprnwb91.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_4.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_76"
    description        = "Change ref: CHG0020675, CHG0027079, CHG0076434, CHG0097943,CHG0116922,CHG0126849"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_121.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_78"
    description        = "Change ref: CHG0034224, CHG0079227"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-n-mgt_scc-nessus.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_noncde-mgmt-nets.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_80"
    description        = "Change ref: CHG0021663, CHG0019396"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-n-mgt_scc-nessus.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_82"
    description        = "Change ref: CHG0027133, CHG0012357"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_192-168-2-0s23.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_86"
    description        = "Change ref: CHG0027711, CHG0033734, CHG0050904, CHG0094578"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_143.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprecp01.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_90"
    description        = "Change ref: CHG0028336"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_125.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_92"
    description        = "Change ref: CHG0030409, CHG0056009, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-n-mgt_brsuxprein02.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_130.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_94"
    description        = "Change ref: CHG0031336, CHG0083614"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_83.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-149-40.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_57.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_96"
    description        = "Change ref: CHG0035043"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_infrastructure_architects.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_20.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_25.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_98"
    description        = "Change ref: CHG0034356,CHG0036667"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1uxprein12.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_21.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_100"
    description        = "Change ref: CHG0034683,CHG0035050"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_symantec-workflow-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1-wn-prg-db01.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_25.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_102"
    description        = "Change ref: CHG0035851"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-moni-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_trafalgar_servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_wily_ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_110"
    description        = "Change ref: CHG0069279, CHG0070175, CHG0070577, CHG0071916, CHG0076040, CHG0076080, CHG0080236, CHG0081759, ,CHG0090666, CHG0090927, CHG0090943, CHG0092571, CHG0097155, CHG0097132, CHG0097321, CHG0098923 ,CHG0099595, CHG0099859, CHG0100080, CHG0100390, CHG0102562, CHG0103279, CHG0104360, CHG0104633 ,CHG0104821, CHG0105282, CHG0105415, CHG0105229, CHG0106351, CHG0106605, CHG0111757, CHG0112244 ,CHG0115434,CHG0119019, CHG0119700, TASK0169407, CHG0122728, RITM0093681, RITM0094092, RITM0095819, ,RITM0097790, CHG0126190,RITM0100318, CHG0109711, CHG0082152, RITM0097099, INC0349272, CHG0081474, ,CHG0081537, CHG0114368, CHG0116429, CHG0129506, TASK0225809, CHG0139968"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_214.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_trs_vip.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_112"
    description        = "Change ref: CHG0039235"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_liability-viewer-pds-apps.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_114"
    description        = "Change ref: CHG0039235"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_liability-viewer-euthenia-apps.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_116"
    description        = "Change ref: CHG0034065, CHG0039590, CHG0087900"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_239.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-135.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_121"
    description        = "Change ref: CHG0077634 ,CHG0081799"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-n-mgt_net-10-1-74-0_24.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-noncde-cf-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_123"
    description        = "Change ref: CHG0058444, CHG0107321"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_234.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_166.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_44.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_125"
    description        = "Change ref: CHG0058535"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-n-mgt_rod-merrick-pc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-25.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_67.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_127"
    description        = "Change ref: CHG0081692"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-nap-wily.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap100.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_131"
    description        = "Change ref: CHG0101313, CHG0128086,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_165.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-34.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_133"
    description        = "Change ref: CHG0059232"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnpresc13.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_70.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_135"
    description        = "Change ref: CHG0059653"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-nap-wily.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_cf_proxy.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_138"
    description        = "Change ref: CHG0060656,CHG0060656,CHG0071346, CHG0076921, CHG0083037, CHG0091339, PCI-Q4-2017,TASK0176964, ,PCI Q2 2018, CHG0124290, PCI Q4 2018, CHG0129845,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_212.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprgdb01.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_140"
    description        = "Change ref: CHG0063280, CHG0124290, CHG0124657"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_182.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_184.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_74.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_143"
    description        = "Change ref: CHG0064217, CHG0064276, CHG0064594, CHG0069768, CHG0071116, ,CHG0112268, CHG0112277, CHG0113350"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_trs-users.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_trs_db_servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_145"
    description        = "Change ref: CHG0067329"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_cxb41-0-corp-lans.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_149"
    description        = "Change ref: CHG0065586,CHG0065703,CHG0067453,CHG0068832,CHG0068834,CHG0071025,CHG0073762 ,CHG0075615,CHG0076691,CHG0076789,CHG0077276,CHG0077634,CHG0078082,CHG0079224 ,CHG0079240,CHG0080058,CHG0080326,CHG0080743,CHG0082856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_wh-user-networks-01.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_90.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_151"
    description        = "Change ref: CHG0067748"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-dr-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-prod-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_cluster-ports-tcp.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_152"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "58"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-dr-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-prod-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_cluster-ports-udp.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_156"
    description        = "Change ref: CHG0065703, CHG0068834, CHG0068832, CHG0071025, CHG0073762, CHG0075615, CHG0076789 ,CHG0076691, CHG0077276, CHG0078082, CHG0079224, CHG0079240, CHG0080058, CHG0080326, ,CHG0084655, CHG0112696"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "59"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_76.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb81.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_158"
    description        = "Change ref: PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "60"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_213.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_gtp-stream-servers-mgmt.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_160"
    description        = "Change ref: CHG0073125"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "61"
    source_groups      = [nsxt_policy_group.pr-n-mgt_stjux073.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_162"
    description        = "Change ref: CHG0073387, CHG0085465"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "62"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_229.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_164"
    description        = "Change ref: AND_CHG0088102, CHG0119306, CHG0119343, CHG0119370, CHG0120759,RITM0093036"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "63"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_101.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-non-cde-jump-hosts.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_166"
    description        = "Change ref: CHG0097787"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "64"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_hp-oneview-backups.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_168"
    description        = "Change ref: CHG0082052, PCI Q4 2018"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "65"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-apm-enterprise-manager.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_cf_proxy.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_170"
    description        = "Change ref: CHG0082905, CHG0083742"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "66"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_sql-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_31.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_172"
    description        = "Change ref: CHG0088645"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "67"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_corp_sql_servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-49152-65535_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_174"
    description        = "Change ref: CHG0089523, CHG0100626"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "68"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_8.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_5.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_179"
    description        = "Change ref: CHG0091410, CHG0113948, CHG0116423,CHG0118447,TASK0170797, CHG0131603 ,CHG0091410, CHG0113948, CHG0116423,CHG0118447,TASK0170797, CHG0131603 ,TASK0226806 ,TASK0226806"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "69"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_86.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprnmg020.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_183"
    description        = "Change ref: CHG0100262"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "70"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_db-sql.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_35.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_17.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_185"
    description        = "Change ref: CHG0099396 CHG0117513"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "71"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_113.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1-noncde-jumphost-lan.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_2.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_187"
    description        = "Change ref: CHG0111088"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "72"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_75.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_77.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp_8400-8403.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_193"
    description        = "Change ref: CHG0125459"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "73"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-trading-oracle-cluster.path]
    services           = [nsxt_policy_service.pr-n-mgt_grp-oracle-monitoring-svcs.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_195"
    description        = "Change ref: CHG0115233 CHG0117209"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "74"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_87.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_94.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_197"
    description        = "Change ref: CHG0115728,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "75"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_97.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_98.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_98.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_199"
    description        = "Change ref: CHG0116620"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "76"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-po-kr-mars-db-users.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnap62.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_202"
    description        = "Change ref: CHG0116707 ,CHG0117647,CHG0118935, CHG0125636, TASK0202904, TASK0202903,TASK0202921-27,TASK0203016-17"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "77"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_114.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnft001.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_204"
    description        = "Change ref: CHG0119660"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "78"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_eoc-devices.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_prdxjmp27jmp001-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_206"
    description        = "Change ref: CHG0119649"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "79"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-po-kra-mars-master-users.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_129.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_208"
    description        = "Change ref: CHG0120563,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "80"
    source_groups      = [nsxt_policy_group.pr-n-mgt_st_johns_finance_team.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_210"
    description        = "Change ref: CHG0124796"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "81"
    source_groups      = [nsxt_policy_group.pr-n-mgt_brsuxoemapp01.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_148.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_83.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_212"
    description        = "Change ref: CHG0125763"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "82"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_149.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-scc-ta-db-2.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_150.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_216"
    description        = "Change ref: CHG0127851 CHG0127893"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "83"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_163.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-non-cde-jump.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_218"
    description        = "Change ref: CHG0133141, CHG0132583"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "84"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_malta-users.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_trs_vip.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_220"
    description        = "Change ref: CHG0132148"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "85"
    source_groups      = [nsxt_policy_group.pr-n-mgt_jabber-brs-vcse-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_jabber-scc-vcse-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_46.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_223"
    description        = "Change ref: CHG0135151 ,CHG0135151, CHG0137276"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "86"
    source_groups      = [nsxt_policy_group.pr-n-mgt_gibux998.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_25.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_6.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_225"
    description        = "Change ref: CHG0136821"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "87"
    source_groups      = [nsxt_policy_group.pr-n-mgt_brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_49.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_13.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_229"
    description        = "Change ref: CHG0138102"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "88"
    source_groups      = [nsxt_policy_group.pr-n-mgt_wh5002156.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_trs_vip.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_230"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "89"
    source_groups      = [nsxt_policy_group.pr-n-mgt_javier-luna-labrador-pc1.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_21.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_232"
    description        = "Change ref: CHG0138734"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "90"
    source_groups      = [nsxt_policy_group.pr-n-mgt_krk-michalsadowski.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_data-mgt-dpe-prod-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_18.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_234"
    description        = "Change ref: CHG0141345"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "91"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-210-194-83.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_jabber-scc-vcse-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_udp_4.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_236"
    description        = "Change ref: CHG0141345"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "92"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-210-194-83.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_jabber-scc-vcse-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_86.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_238"
    description        = "Change ref: CHG0143329"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "93"
    source_groups      = [nsxt_policy_group.pr-n-mgt_sofwnprefs01-group-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb046.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_242"
    description        = "Change ref: CHG0145480"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "94"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ld6-ncde_db-general-db.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-165.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_244"
    description        = "Change ref: CHG0145622"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "95"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_73.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprgdb05.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_246"
    description        = "Change ref: CHG0145706"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "96"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_5.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-120-146-27.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_248"
    description        = "Change ref: CHG0145835"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "97"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_manila-subnets.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_trs_vip.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_250"
    description        = "Change ref: CHG0146337"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "98"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ntt-vpn-nat-range.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_jabber-uc-vcse-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_6.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_252"
    description        = "Change ref: CHG0146622"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "99"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_dm-aws-prod-vpc.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1wnprndb002.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_1.path]
  }
  rule {
    display_name       = "pr-n-mgt_internal-vrf_access_in_254"
    description        = "Change ref: CHG0149101"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "100"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_10.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxprnwb046.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_5"
    description        = "Change ref: CHG0144834"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_whgroup_ad_servers-chg0144834.path]
    services           = [nsxt_policy_service.pr-n-mgt_whgroup_ad_ports-chg0144834.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_7"
    description        = "Change ref: CHG0142765"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_euc_mgmt_server-group-chg0142765.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_on_premise_datacentre_vlans-group-chg0142765.path]
    services           = [nsxt_policy_service.pr-n-mgt_euc_mgmt_port-group-chg0142765.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_11"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_splunk_deployment_server-chg0143200.path]
    services           = [nsxt_policy_service.pr-n-mgt_splunk_mgmt_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_15"
    description        = "Change ref: CHG0142763"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_wh_nets-chg0142763.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_splunk_deployment_server-chg0142763.path]
    services           = [nsxt_policy_service.pr-n-mgt_splunk_mgmt_port-chg0142763.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_17"
    description        = "Change ref: RAS-VPN"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_ras-vpn-pool.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_19"
    description        = "Change ref: CHG0137261,CHG0137484,CHG0145266"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_rfc-1918.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_ise-psn.path]
    services           = [nsxt_policy_service.pr-n-mgt_ise-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_26"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-scc-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_28"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-ld6-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_30"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_grp-gib-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_32"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-scc-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_34"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-ld6-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_36"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-gib-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_39"
    description        = "Change ref: CHG0087656"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_splunkhfcluster.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-9997_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_42"
    description        = "Change ref: CHG0106526"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_rundeck-servers.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-mgt_rundeck-winrm-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_44"
    description        = "Change ref: Wily global access - CHG0081701"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_wily-svrs_all.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_wily-access-group.path]
    services           = [nsxt_policy_service.pr-n-mgt_wily-outbound-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_45"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_wily-access-group.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_wily-svrs_all.path]
    services           = [nsxt_policy_service.pr-n-mgt_wily-inbound-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_47"
    description        = "Change ref: CHG0078639"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_webproxies-cx-scc.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_50"
    description        = "Change ref: CHG0100330"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-120-0-0s16.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_48.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_17.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_52"
    description        = "Change ref: CHG0116053"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_100.path]
    services           = [nsxt_policy_service.pr-n-mgt_ldap-services.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_54"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_mailhosts.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_58"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_ossec-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_ossec-client-services.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_61"
    description        = "Change ref: Standard rule - CHG0083747"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_whgroup-ad-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_whgroup-ad-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_72"
    description        = "Change ref: Standard rule - CHG0083506"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_infoblox-all-dns-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_infoblox-standard-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_77"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-wsus-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_58.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_79"
    description        = "Change ref: CHG0095744"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_sc1uxpromn012.path]
    services           = [nsxt_policy_service.pr-n-mgt_splunk-ports.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_81"
    description        = "Change ref: CHG0081848 "
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_scc_snow_collector.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_89"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-syslog-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcpudp-514.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_93"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-nms-mgmt.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_95"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-openview.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-383_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_97"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-ntp.path]
    services           = [nsxt_policy_service.pr-n-mgt_udp-ntp_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_99"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-status-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-60606_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_101"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-kms-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-1688_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_103"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-pr-n-katello-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_tcp_31.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_105"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_mail-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_113"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_uim-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_ip_10-0-0-0s8.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_115"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.pr-n-mgt_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_uim-servers.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_121"
    description        = "Change ref: CHG0055146"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_nexus.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-8082_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_125"
    description        = "Change ref: CHG0067511 - allow Splunk Heavy Forwarder secure access to management protocols and SNMP agent"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_18.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_14.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_128"
    description        = "Change ref: CHG0114418"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_grp-sc1-bomgar-appliances.path]
    services           = [nsxt_policy_service.pr-n-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_134"
    description        = "Change ref: CHG0109764"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_rfc-1918.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_scc-migrated_network_59.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_138"
    description        = "Change ref: CHG0109028"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_rfc-1918.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_grp_rds-kms-server.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_140"
    description        = "Change ref: Standard Rule - CHG0083593"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-mgt_global_access_147"
    description        = "Change ref: Standard Rule ,CHG0122435, CHG0133580"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-n-mgt_grp_skybox-appliances.path]
    destination_groups = [nsxt_policy_group.pr-n-mgt_classa-8.path]
    services           = [nsxt_policy_service.pr-n-mgt_scc-migrated_service_12.path]
  }
}
