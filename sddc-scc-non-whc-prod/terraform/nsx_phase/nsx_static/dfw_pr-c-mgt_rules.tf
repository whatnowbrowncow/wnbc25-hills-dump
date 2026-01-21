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

resource "nsxt_policy_security_policy" "pr-c-mgt" {
  display_name    = "pr-c-mgt"
  description     = "Firewall section for pr-c-mgt"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "30"
  domain          = "cgw"
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_2"
    description        = "Change ref: CHG0079131"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-cx-cde-nets.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_4"
    description        = "Change ref: CHG0067823 - CDE Jumpnet to Katello"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_sc1-katello-prod.path]
    services           = [nsxt_policy_service.pr-c-mgt_katello-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_6"
    description        = "Change ref: CHG0140052"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_stingray-mgt.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9090_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_8"
    description        = "Change ref: CHG0120371"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_sc1-bomgar-clients.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-prd-ncde-sports-app-lan.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_10"
    description        = "Change ref: CHG0128017"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_sc1-bomgar-clients.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_310.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_14"
    description        = "Change ref: CHG0067329 - CDE Jumpnet to Puppet Master (Inv Prod)"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-inv-cde-nets.path]
    services           = [nsxt_policy_service.pr-c-mgt_cellmgmt-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_16"
    description        = "Change ref: CHG0067329 - CDE Jumpnet to Cell Mgmt (Inv Prod), CHG0115965"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_inv-cde-mgmt-lan.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_38.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_18"
    description        = "Change ref: CHG0067823 - CDE Jumpnet to Stingray Mgmt (Inv Prod)"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_inv-pr-stingray-subnets.path]
    services           = [nsxt_policy_service.pr-c-mgt_stingray-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_20"
    description        = "Change ref: CHG0076594"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_qlickview_app.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_22"
    description        = "Change ref: CHG0076594"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_qlickview_web.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_24"
    description        = "Change ref: CHG0111495, CHG0127143"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_vsphere_mgmt_nets.path]
    services           = [nsxt_policy_service.pr-c-mgt_vmware-access-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_26"
    description        = "Change ref: CHG0114077, CHG0114418"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-scc-bomgar-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-bomgar-appliances.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_28"
    description        = "Change ref: CHG0120144"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-scc-bomgar-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_device-management-networks.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_30"
    description        = "Change ref: CHG0114077"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-scc-bomgar-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-0-0s16.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-22-3389.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_32"
    description        = "Change ref: CHG0115563"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-141-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_invxpup06mst001-inv-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp_8140.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_34"
    description        = "Change ref: CHG0120025"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-141-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_aws-ddos-big-ip-net.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_36"
    description        = "Change ref: CHG0121057,CHG0121362,CHG0121632,CHG0121634"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_rds-servers-scc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_skybox-appliances.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_42.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_38"
    description        = "Change ref: CHG0120877"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_rds-servers-scc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_bomgar_asdm_access_brs_gib.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_40"
    description        = "Change ref: CHG0127129"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-141-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_cde-ilo-range.path]
    services           = [nsxt_policy_service.pr-c-mgt_ilo-access-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_42"
    description        = "Change ref: CHG0127129,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-141-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_oneview.path]
    services           = [nsxt_policy_service.pr-c-mgt_hp-oneview-access.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_44"
    description        = "Change ref: CHG0123657,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-scc-bomgar-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_checkpoint-mds-cmas.path]
    services           = [nsxt_policy_service.pr-c-mgt_checkpoint-user-mgmt-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_46"
    description        = "Change ref: CHG0123808"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-cx-cde-jump-hosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprtdb001.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8080-1521.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_48"
    description        = "Change ref: CHG0123933, CHG0127332"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-c-mgt_10-120-141-40s29.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_295.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_73.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_50"
    description        = "Change ref: CHG0126265"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_sc1-bomgar-clients.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_us-njp-ddos-platform.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_52"
    description        = "Change ref: CHG0126949"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_300.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-0s24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_301.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_54"
    description        = "Change ref: CHG0127332, CHG0127524, CHG0127798,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_304.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_306.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_305.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_56"
    description        = "Change ref: CHG0130995"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-scc-bomgar-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_317.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_58"
    description        = "Change ref: CHG0133434"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_aws-supernets.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_60"
    description        = "Change ref: CHG0140039"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_26.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_29.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_30.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_62"
    description        = "Change ref: CHG0140344"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_36.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_aws-dcs-ire-nva.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_40.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_64"
    description        = "Change ref: CHG0140523"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_39.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_40.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_44.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_66"
    description        = "Change ref: CHG0141002"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_51.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_71.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_68"
    description        = "Change ref: CHG0142117, CHG0144147, CHG0144126, CHG0143326, CHG0143327"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_55.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_15.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_70"
    description        = "Change ref: CHG0142705"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_53.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_aws-ddos-dev-100-78-80-0s20.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_54.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_72"
    description        = "Change ref: CHG0144793"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_service-mgmt-scc-whc-prod-sddc.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_74"
    description        = "Change ref: CHG0144732"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_57.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_58.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-7778_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_access_in_76"
    description        = "Change ref: CHG0145168"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-bomgar-grp.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_69.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_37.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_2"
    description        = "Change ref: CHG0020856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-mgt_web-mgmt-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sccuxstnmg01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_24.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_4"
    description        = "Change ref: CHG0070831,CHG0116922"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-moni-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_6"
    description        = "Change ref: CHG82531"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-layer7new-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-moni-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_8"
    description        = "Change ref: CHG0020675, CHG0027079, CHG0107140,CHG0116922,CHG0126849"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_117.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_10"
    description        = "Change ref: CHG0104113,CHG0116922"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpromn012.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8089_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_12"
    description        = "Change ref: CHG0104113"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-layer7new-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpromn012.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8089_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_14"
    description        = "Change ref: PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxprcwb41.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_16"
    description        = "Change ref: CHG0105871,CHG0116922"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_ob-web-app-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_67.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcpudp-514.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_18"
    description        = "Change ref: CHG0107212"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-mgmt-3.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_83.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcpudp-514.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_20"
    description        = "Change ref: CHG0107212"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-mgmt-3.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-136-181.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_29.path]
  }
  rule {
    display_name       = "pr-c-mgt_web-mgt_access_in_22"
    description        = "Change ref: CHG0122003"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-mgt_web-mgmt-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-nas-ip-range.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-nas-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_app-mgt_access_in_2"
    description        = "Change ref: CHG0020856"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-mgt_app-mgt-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sccuxstnmg01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_42.path]
  }
  rule {
    display_name       = "pr-c-mgt_app-mgt_access_in_3"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxprcap45.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_app-mgt_access_in_4"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxprcap46.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_app-mgt_access_in_6"
    description        = "Change ref: CHG0124318"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_298.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_app-mgt_access_in_8"
    description        = "Change ref: CHG0122003"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-mgt_app-mgt-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-nas-ip-range.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-nas-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_cde-backoffice-mgt_in_2"
    description        = "Change ref: CHG0028339"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-mgt_cde-backoffice-mgt-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sccuxstnmg01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_cde-backoffice-mgt_in_3"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-137-11.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_cde-backoffice-mgt_in_4"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-137-12.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_cde-backoffice-mgt_in_6"
    description        = "Change ref: CHG0122003"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-mgt_cde-backoffice-mgt-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-nas-ip-range.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-nas-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_2"
    description        = "Change ref: CHG0030985"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-140-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_289.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_udp_8.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_4"
    description        = "Change ref: CHG0060912,CHG0083349"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_f5-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1wnpredc03.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ldap_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_6"
    description        = "Change ref: CHG0061479, CHG0078266, CHG0083349"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-f5-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_f5-splunk-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_49.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_8"
    description        = "Change ref: CHG0074843, CHG0078266,CHG0083441, CHG0084296,CHG0094547, CHG0094606"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_stingray-group.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_235.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_48.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_9"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-140-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_27.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_17.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_11"
    description        = "Change ref: CHG0066638,CHG0083441"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_stingray_prod.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-ldap-group-scc.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ldap_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_13"
    description        = "Change ref: CHG0086708"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_wh-f5-devices.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_292.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_15"
    description        = "Change ref: CHG0113225"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_stingray-group.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_clp-heavyforwarders.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8088_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_17"
    description        = "Change ref: CHG0114594"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1bigiq01-mgmt-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_278.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_19"
    description        = "Change ref: CHG0123860"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-140-14.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_9.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_21"
    description        = "Change ref: CHG0125663, CHG0132492"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_321.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_23"
    description        = "Change ref: CHG0142649"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_aws-ddos-dev-100-78-80-0s20.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_25.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_25"
    description        = "Change ref: CHG0125909"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1bigiq04-mgmt-prod-williamhill.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_njp-dev-ddos-subnet.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_Stingray-Mgt_access_in_27"
    description        = "Change ref: CHG0141617"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_45.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-194-58.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_1"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_8.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-xiv-array-1.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-7778_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_3"
    description        = "Change ref: CHG0143999"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_cp-vpn-cde-mgmt-nets.path]
    services           = [nsxt_policy_service.pr-c-mgt_cde-mgmt-nets-services.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_6"
    description        = "Change ref: CHG0143999 ,CHG0143999"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prappsc02-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_7"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_uk-sc1-network-mgmt-24.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_9"
    description        = "Change ref: CHG0143999"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_web-mgmt-network-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_32.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_11"
    description        = "Change ref: CHG0143999"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_bladelogic-dmz-network-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_33.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_13"
    description        = "Change ref: CHG0143999"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_net-10-120-140-0_24-sccstringray.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_35.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_15"
    description        = "Change ref: CHG0143999"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_36.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_17"
    description        = "Change ref: CHG0143999"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-143-64s27.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_18"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-134-253.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_29.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_21"
    description        = "Change ref: ** Temp Access for migration work - Monday 25th Jan 2021 ** ,** Temp Access for migration work - Monday 25th Jan 2021 **"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_vmhost-mgt-network-24.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_24"
    description        = "Change ref: CHG0125201 - ILO ACCESS IS ALLOWED IN THE CDE"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_ilo-access.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_hp-ilo-subnets.path]
    services           = [nsxt_policy_service.pr-c-mgt_ilo-access-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_26"
    description        = "Change ref: CHG0141104"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-c-mgt_us-esxi-hosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9084_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_28"
    description        = "Change ref: CHG0141104"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-c-mgt_us-esxi-hosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_7.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_31"
    description        = "Change ref: CHG0140599 ,CHG0140759"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-commvault-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpremg30.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-60606_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_33"
    description        = "Change ref: CHG0140599"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-c-mgt_copxbld16api001-co1-cop-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_43"
    description        = "Change ref: CHG0123928"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_networkteam-vpn-range.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_cde-direct-access-nets.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-22-3389.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_47"
    description        = "Change ref: Deny Rule - CHG0123928"
    action             = "DROP"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_cde-direct-access-nets.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-22-3389.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_49"
    description        = "Change ref: controlled on BRS CP"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_cde-direct-access-nets.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_51"
    description        = "Change ref: CHG0064699"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_tufincollectors.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-internal-asa.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_53"
    description        = "Change ref: CHG0090616"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-c-mgt_pr-cde-front-cx-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-internal-asa.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_55"
    description        = "Change ref: TBC"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_tufincollectors.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_tufiniosdevices.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_57"
    description        = "Change ref: CHG0065974"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_149.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_tufincheckpointmds.path]
    services           = [nsxt_policy_service.pr-c-mgt_tufincheckpointports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_60"
    description        = "Change ref: OPSEC LEA connection from SCC Splunk HF to SCC CMA-1 server - CHG0084220 ,OPSEC LEA connection from SCC Splunk HF to SCC CMA-1 server - CHG0084220"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxpremn79.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_54.path]
    services           = [nsxt_policy_service.pr-c-mgt_checkpointmanagmentports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_61"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxpremn79.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-pr-ext-cma1.path]
    services           = [nsxt_policy_service.pr-c-mgt_checkpointmanagmentports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_63"
    description        = "Change ref: CHG0065471, CHG0070895"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-c-mgt_uk-scc-wsus.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_225.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_65"
    description        = "Change ref: CHG0066166"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-c-mgt_uk-scc-wsus.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpremg30.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_67"
    description        = "Change ref: CHG0131534"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ld6wnprwsus01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpremg30.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_69"
    description        = "Change ref: CHG0131534"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brswnprwsus01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpremg30.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_71"
    description        = "Change ref: CHG0060632, INC0349198"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_211.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_rsa-scc-new.path]
    services           = [nsxt_policy_service.pr-c-mgt_rsa-new-services.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_73"
    description        = "Change ref: CHG0132892"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gibux950-02.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_323.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_75"
    description        = "Change ref: CHG0035636"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-solarwinds.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_173.path]
    services           = [nsxt_policy_service.pr-c-mgt_sc1-solarwindsports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_77"
    description        = "Change ref: CHG0056829"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-c-mgt_uk-sc1-netbrain01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_uk-sc1-network-mgmt-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_45.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_78"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cacti.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_293.path]
    services           = [nsxt_policy_service.pr-c-mgt_udp-snmp_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_80"
    description        = "Change ref: CHG0021260"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_rfc-1918.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_43.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_21.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_82"
    description        = "Change ref: CHG0085234, CHG0035934, CHG0086479, CHG0111816"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_athene-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_287.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_84"
    description        = "Change ref: CHG0015230, CHG0021040"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-nms-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_rfc-1918.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_19.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_86"
    description        = "Change ref: CHG0015319, CHG0017396"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_104.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-0-0s16.path]
    services           = [nsxt_policy_service.pr-c-mgt_grp-pr-c-altris-task-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_88"
    description        = "Change ref: CHG0018025, CHG0018188"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_110.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_116.path]
    services           = [nsxt_policy_service.pr-c-mgt_grp-pr-c-ad-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_92"
    description        = "Change ref: CHG0015230, CHG0118320"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_215.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-ncs1.path]
    services           = [nsxt_policy_service.pr-c-mgt_udp-tftp_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_94"
    description        = "Change ref: CHG0076486, CHG0077496 - IRS do not disable"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_hp-irs-server.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_hp-irs-destinations.path]
    services           = [nsxt_policy_service.pr-c-mgt_hp-irs-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_95"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-gib-whapi-portal-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-layer7new-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_97"
    description        = "Change ref: CHG82531, CHG0084117, INC0604535, CHG0135991"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_1.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_uk-sc1-network-mgmt-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_1.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_99"
    description        = "Change ref: CHG0075512,CHG0076346,CHG0076483, CHG0083049,CHG0082670,CHG0081582,CHG0083446,CHG0083821,CHG0083088"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_whapi-gateway-access.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_whapi-gateway-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_whapi-access-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_102"
    description        = "Change ref: CHG0053652 ,CHG0116257 - SDenham removed as part of CDE lockdown,CHG0116922"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_191.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_192.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_97.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_104"
    description        = "Change ref: CHG0019196"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-136-30.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-60606_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_106"
    description        = "Change ref: Infosec approved web-ports"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_15.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_vmhost-mgt-network-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_99.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_110"
    description        = "Change ref: CHG0013387 ,CHG0015230 ,CHG0116257 - Removed SSH as part of CDE lockdown"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_network_services_team.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_48.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_113"
    description        = "Change ref: CHG0020650,CHG0023838, CHG0023913, CHG0024220 CHG0036165 ,CHG0117503 - SSH removed as part of CDE lockdown"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_47.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_48.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_115"
    description        = "Change ref: CHG0022219, CHG0022372, INC0442316,CHG0116922"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-moni-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_ob-web-app-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_58.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_119"
    description        = "Change ref: CHG0029253,CHG0031299,CHG0052001, CHG0073744,CHG0083441, CHG0110894, CHG0114039"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_stingray-mgt-tcp-9070-9090-access.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_stingray-mgt.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_72.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_121"
    description        = "Change ref: CHG0029349, CHG0033991"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_gib-checkpoint.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_gib-pr-ext-cma1.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_66.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_123"
    description        = "Change ref: CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_birstall_checkpointfirewalls.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_35.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_92.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_125"
    description        = "Change ref: CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_birstall_checkpointfirewalls.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_222.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_127"
    description        = "Change ref: CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_brs-checkpoint-firewalls.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_brs-pp-ext-cma1.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_93.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_129"
    description        = "Change ref: CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.pr-c-mgt_scc-pr-ext-cma2.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc_checkpointfirewalls.path]
    services           = [nsxt_policy_service.pr-c-mgt_checkpoint-mgmt.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_131"
    description        = "Change ref: CHG0033991, CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gi-mpl-fm01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-smart-1.path]
    services           = [nsxt_policy_service.pr-c-mgt_provider-1-mgt.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_133"
    description        = "Change ref: CHG0033991"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "58"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gib-pr-ext-cma2.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_gib-pr-ext-cma1.path]
    services           = [nsxt_policy_service.pr-c-mgt_provider-1-mgt.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_135"
    description        = "Change ref: CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "59"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-dr-ext-cma2.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_brs-dr-ext-cma1.path]
    services           = [nsxt_policy_service.pr-c-mgt_provider-1-mgt.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_137"
    description        = "Change ref: CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "60"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-pp-ext-cma2.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_brs-pp-ext-cma1.path]
    services           = [nsxt_policy_service.pr-c-mgt_provider-1-mgt.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_139"
    description        = "Change ref: CHG0052271"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "61"
    source_groups      = [nsxt_policy_group.pr-c-mgt_scc-pr-ext-cma2.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-pr-ext-cma1.path]
    services           = [nsxt_policy_service.pr-c-mgt_provider-1-mgt.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_141"
    description        = "Change ref: CHG0027354, CHG0028018, CHG0056990,CHG0029349"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "62"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_gib-smart-1.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-smart-1.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_143"
    description        = "Change ref: CHG0029400, CHG0071526"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "63"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_orbis.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-wn-pre-mg01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_145"
    description        = "Change ref: CHG0032746 , CHG0035670,CHG0083441, CHG0101073"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "64"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_152.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_279.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_128.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_147"
    description        = "Change ref: CHG0066839,CHG0083441,PCI-Q4-2017,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "65"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brsuxprein02.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-stingrays-batch2.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9090-9070.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_150"
    description        = "Change ref: CHG0033689, CHG0034017 CHG0036165,CHG0039270, CHG0038627, CHG0052441,CHG0083441, CHG0090196, ,CHG0110251,CHG0118303,TASK0238453"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "66"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_282.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_stingray-mgt.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9090_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_152"
    description        = "Change ref: CHG0034356"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "67"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxprein12.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_284.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_154"
    description        = "Change ref: CHG0034492"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "68"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_infoblox-grid-masters.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprenw01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_156"
    description        = "Change ref: CHG0126802"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "69"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_291.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprenw01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_158"
    description        = "Change ref: CHG0125582"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "70"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_299.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprenw01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_160"
    description        = "Change ref: CHG0066438"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "71"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-moni-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_218.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-1526_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_165"
    description        = "Change ref: CHG0079889,CHG0083441 ,CHG0079889,CHG0083441 ,CHG0079889,CHG0083441 ,CHG0092703,CHG0094547,CHG0094606"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "72"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_2.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_stingray-group.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_170"
    description        = "Change ref: CHG0039188, CHG0040157, CHG0065418, CHG0067336,CHG0074856, CHG0081123, CHG0095211 ,CHG0113088,CHG0115204, CHG0116788, TASK0234868,TASK0240023"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "73"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_160.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-tpam.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_172"
    description        = "Change ref: CHG0040158"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "74"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brs-tpam.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-tpam.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_85.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_174"
    description        = "Change ref: CHG0040756,CHG0116922"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "75"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gib-c-web-mg-net.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-layer7-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_177"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "76"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-n-redhat-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-n-redhat-servers-ilo.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcpudp-623.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_179"
    description        = "Change ref: CHG0054123"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "77"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sccappresc01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-fw-bk-svr.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_181"
    description        = "Change ref: RITM0113292,TASK0213814"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "78"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_krk-f5-admin-users.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_322.path]
    services           = [nsxt_policy_service.pr-c-mgt_networkmanagementports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_182"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "79"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-180-163-140.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-140-0s24.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_183"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "80"
    source_groups      = [nsxt_policy_group.pr-c-mgt_pr-cde-front-cx-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-140-0s24.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_185"
    description        = "Change ref: CHG0068574"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "81"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gibwnprcmg003.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_storage-mgt-vlans.path]
    services           = [nsxt_policy_service.pr-c-mgt_storage-mgt-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_187"
    description        = "Change ref: CHG0069498"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "82"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxprein001.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-xiv-array.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-7778_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_189"
    description        = "Change ref: CHG0069500"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "83"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gibux9002.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-xiv-array.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-7778_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_190"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "84"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxpremg001.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-xiv-array.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-7778_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_191"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "85"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brsuxpremg001.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-xiv-array.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-7778_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_193"
    description        = "Change ref: CHG0133739"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "86"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_3.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvro01.path]
    services           = [nsxt_policy_service.pr-c-mgt_vr-ops.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_195"
    description        = "Change ref: CHG0076518"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "87"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brsdatafabman01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc_nas_mgmt.path]
    services           = [nsxt_policy_service.pr-c-mgt_brsdatafabman01_ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_196"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "88"
    source_groups      = [nsxt_policy_group.pr-c-mgt_brsdatafabman01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc_nas_mgmt.path]
    services           = [nsxt_policy_service.pr-c-mgt_brsdatafabman01_ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_197"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "89"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_cisco_dcmn_access.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1dcnm01.path]
    services           = [nsxt_policy_service.pr-c-mgt_cisco_dcmn_ports_monitoring.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_199"
    description        = "Change ref: CHG0075038, CHG0079579"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "90"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_237.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-xiv-array.path]
    services           = [nsxt_policy_service.pr-c-mgt_splunk-xiv-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_201"
    description        = "Change ref: CHG0089260"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "91"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_5.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_203"
    description        = "Change ref: CHG0085802"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "92"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxpremn74.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-143-185.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_206"
    description        = "Change ref: Snow monitoring to all vCenter 6.0 ,CHG0087219"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "93"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1wnpremg44.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_208"
    description        = "Change ref: CHG0131065"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "94"
    source_groups      = [nsxt_policy_group.pr-c-mgt_nj2-whc-build-server.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_210"
    description        = "Change ref: CHG0135767"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "95"
    source_groups      = [nsxt_policy_group.pr-c-mgt_inpxbld16api001-in1-inp-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_212"
    description        = "Change ref: CHG0087137"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "96"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpresc002-mgmt-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_214"
    description        = "Change ref: CHG0087628 - Performance related metrics collection from device over ssh or APIs"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "97"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxcpemn001.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-129-0s24.path]
    services           = [nsxt_policy_service.pr-c-mgt_perf_metrics_ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_216"
    description        = "Change ref: CHG0095011"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "98"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_trs_db_servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-enc02-ilo4.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcpudp-623.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_217"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "99"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_trs_db_servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-enc04-ilo9.path]
    services           = [nsxt_policy_service.pr-c-mgt_udp-623_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_218"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "100"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-sc1-uxprrdb.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-sc1-uxprrdb-ilo.path]
    services           = [nsxt_policy_service.pr-c-mgt_udp-623_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_220"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "101"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_mailhosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1apprcmg001.path]
    services           = [nsxt_policy_service.pr-c-mgt_mailhostports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_222"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "102"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_proofpoint_admins.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1apprcmg001.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_223"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "103"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_proofpoint_admins.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1apprcmg001.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-10000_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_225"
    description        = "Change ref: CHG0101840, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "104"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-gib-layer7-srv-cluster3.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprcmg01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp_8182_8675.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_227"
    description        = "Change ref: CHG0107579, CHG0115760"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "105"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_188.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_89.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_38.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_229"
    description        = "Change ref: CHG0108784"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "106"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-118.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sccstorageprocesserb.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_231"
    description        = "Change ref: CHG0110901"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "107"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_137.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-134-253.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_30.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_233"
    description        = "Change ref: CHG0111326"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "108"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_139.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-134-0s24.path]
    services           = [nsxt_policy_service.pr-c-mgt_comm_vault_service.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_235"
    description        = "Change ref: CHG0112168"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "109"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-trading-oracle-cluster.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-enc-ilo-nodes.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-udp-623.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_237"
    description        = "Change ref: CHG0114426"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "110"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-134.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_179.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_239"
    description        = "Change ref: CHG0114383"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "111"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_192-168-2-0s23.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-131-0s24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_63.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_241"
    description        = "Change ref: CHG0115599"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "112"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-brs-bomgar-wn-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-134-0s24.path]
    services           = [nsxt_policy_service.pr-c-mgt_vmware-tcp-groups.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_244"
    description        = "Change ref: CHG0116321 ,CHG0137633"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "113"
    source_groups      = [nsxt_policy_group.pr-c-mgt_us-10-178-0-0s15.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_246"
    description        = "Change ref: CHG0116654, PCI Q4 2018"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "114"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-po-kr-tpam-access.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_scc-tpam.path]
    services           = [nsxt_policy_service.pr-c-mgt_web-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_248"
    description        = "Change ref: CHG0116778,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "115"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-apm-cluster.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_203.path]
    services           = [nsxt_policy_service.pr-c-mgt_udp-snmp_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_249"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "116"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_241.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sccstorageprocesserb.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_251"
    description        = "Change ref: CHG0118285"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "117"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_210.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-cluster-ilo-fencing-srvs.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_211.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_253"
    description        = "Change ref: CHG0119666,PCI-Q2-2019"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "118"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_242.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_243.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9070.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_255"
    description        = "Change ref: CHG0139085"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "119"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-orion-app-srvs.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_net-10-120-129-0_24-scc-networkmanagement.path]
    services           = [nsxt_policy_service.pr-c-mgt_solarwinds-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_259"
    description        = "Change ref: CHG0135695"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "120"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-orion-app-srvs.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_uk-sc1-network-mgmt-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_2.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_261"
    description        = "Change ref: CHG0121232 CHG0164785"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "121"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_zabbix-monitoring.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_252.path]
    services           = [nsxt_policy_service.pr-c-mgt_zabbix-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_263"
    description        = "Change ref: CHG0126163, CHG0126733"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "122"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_storage-labm.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_82.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_265"
    description        = "Change ref: CHG0133938"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "123"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_us-las-it-team.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_4.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_267"
    description        = "Change ref: CHG0133938"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "124"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_us-las-it-team.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prappsc02-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_6.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_269"
    description        = "Change ref: CHG0134210,CHG0134346"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "125"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxpremn81.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvro01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_9.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_271"
    description        = "Change ref: CHG0135451"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "126"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-wh-us-team.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvro01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_10.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_273"
    description        = "Change ref: CHG0135151, CHG0135607"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "127"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gibux998.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_7.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_14.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_275"
    description        = "Change ref: CHG0137053"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "128"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxpremn17.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sccstorageprocesserb.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_277"
    description        = "Change ref: CHG0141421"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "129"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-89.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_44.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_281"
    description        = "Change ref: CHG0142676"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "130"
    source_groups      = [nsxt_policy_group.pr-c-mgt_aws-ddos-dev-100-78-80-0s20.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_26.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_284"
    description        = "Change ref: CHG0144380 CHG0144383 ,CHG0144380, CHG0144383, CHG0144490"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "131"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-scc-vmc-service-mgmt.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_vmhost-mgt-network-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_23.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_286"
    description        = "Change ref: CHG0144597"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "132"
    source_groups      = [nsxt_policy_group.pr-c-mgt_vmcprapvro01-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvro01.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-whc-prod-vmc-service-grp.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_288"
    description        = "Change ref: CHG0144732"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "133"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_59.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_62.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-7778_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_290"
    description        = "Change ref: CHG0145092"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "134"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_68.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_vmhost-mgt-network-24.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-31031_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_292"
    description        = "Change ref: CHG0145248"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "135"
    source_groups      = [nsxt_policy_group.pr-c-mgt_gibwnprndcnm01.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_san-switches.path]
    services           = [nsxt_policy_service.pr-c-mgt_cisco_dcmn_ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_294"
    description        = "Change ref: VMC migration rule - to allow connectivity between migrated and yet to be migrated subnets."
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "136"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_pr_c_mgt_local_subnets.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_pr_c_mgt_local_subnets.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_296"
    description        = "Change ref: CHG0145252"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "137"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_ise-psn.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxprenw01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_298"
    description        = "Change ref: CHG0146753"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "138"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_brs_citrix_controllers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1prapvc01.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_300"
    description        = "Change ref: CHG0146853"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "139"
    source_groups      = [nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_ld6.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_scc.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_11.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_304"
    description        = "Change ref: CHG0147160"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "140"
    source_groups      = [nsxt_policy_group.pr-c-mgt_10-125-4-0s22.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1bigiq01-mgmt-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_307"
    description        = "Change ref: CHG0148000 ,CHG0148000, CHG0148066"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "141"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-33-11.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_6.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_internal-vrf_access_in_309"
    description        = "Change ref: CHG0150097"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "142"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-aws-ddos-nonprod.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1bigiq03-mgmt-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_5"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_ras-vpn-pool.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-0-0s16.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_7"
    description        = "Change ref: CHG0144834"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_whgroup_ad_servers-chg0144834.path]
    services           = [nsxt_policy_service.pr-c-mgt_whgroup_ad_ports-chg0144834.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_9"
    description        = "Change ref: CHG0142765"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_euc_mgmt_server-group-chg0142765.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_on_premise_datacentre_vlans-group-chg0142765.path]
    services           = [nsxt_policy_service.pr-c-mgt_euc_mgmt_port-group-chg0142765.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_11"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_splunk_heavy_forwarders-chg0143200.path]
    services           = [nsxt_policy_service.pr-c-mgt_splunk_indexing_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_13"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_splunk_deployment_server-chg0143200.path]
    services           = [nsxt_policy_service.pr-c-mgt_splunk_mgmt_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_15"
    description        = "Change ref: CHG0142763"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_wh_nets-chg0142763.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_splunk_heavy_forwarders-chg0142763.path]
    services           = [nsxt_policy_service.pr-c-mgt_splunk_indexing_port-chg0142763.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_17"
    description        = "Change ref: CHG0142763"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_wh_nets-chg0142763.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_splunk_deployment_server-chg0142763.path]
    services           = [nsxt_policy_service.pr-c-mgt_splunk_mgmt_port-chg0142763.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_19"
    description        = "Change ref: CHG0137261,CHG0137484,CHG0145266"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_rfc-1918.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_ise-psn.path]
    services           = [nsxt_policy_service.pr-c-mgt_ise-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_34"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp8400-8403.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_36"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-gib-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp8400-8403.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_38"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp8400-8403.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_40"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_grp-ld6-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp8400-8403.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_42"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-ld6-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp8400-8403.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_44"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-gib-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp8400-8403.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_48"
    description        = "Change ref: CHG0112231 ,CHG0110997 ,CHG0112231"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-134-246.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-134.path]
    services           = [nsxt_policy_service.pr-c-mgt_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_53"
    description        = "Change ref: CHG0087656,  PCI Q2 2016"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_splunkhfcluster.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_4.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_55"
    description        = "Change ref: CHG0106526"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_rundeck-servers.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-mgt_rundeck-winrm-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_59"
    description        = "Change ref: CHG0100330"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-120-0-0s16.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_50.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_27.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_61"
    description        = "Change ref: Global Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1uxpromn012.path]
    services           = [nsxt_policy_service.pr-c-mgt_8089.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_63"
    description        = "Change ref: CHG0116053"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_200.path]
    services           = [nsxt_policy_service.pr-c-mgt_ldap-services.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_67"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_wily-svrs_all.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_wily-access-group.path]
    services           = [nsxt_policy_service.pr-c-mgt_wily-outbound-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_69"
    description        = "Change ref: PCI Q2 2016"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_wily-access-group.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_wily-svrs_all.path]
    services           = [nsxt_policy_service.pr-c-mgt_wily-inbound-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_71"
    description        = "Change ref: CHG0078639"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_webproxies-cx-scc.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_75"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_mailhosts.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_77"
    description        = "Change ref: CHG0079439 - HP Oneview do not disable"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_hp-ilo-subnets.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_hp-oneview-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_hp-oneview-client-services.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_79"
    description        = "Change ref: CHG0079439 - HP Oneview do not disable"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_hp-oneview-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_hp-ilo-subnets.path]
    services           = [nsxt_policy_service.pr-c-mgt_hp-oneview-server-services.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_80"
    description        = ""
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_ossec-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_ossec-client-services.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_84"
    description        = "Change ref: Standard rule - CHG0083747, CHG0128153"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_wh-group-ad-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_5.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_86"
    description        = "Change ref: CHG0111493"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_145.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_vsphere_mgmt_net_scc.path]
    services           = [nsxt_policy_service.pr-c-mgt_vcenteruseraccess.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_96"
    description        = "Change ref: CHG0111495, CHG0121216,CHG0128563, CHG0133793, CHG0135610"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_vsphere_access.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_vsphere_mgmt_nets.path]
    services           = [nsxt_policy_service.pr-c-mgt_vmware-access-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_108"
    description        = "Change ref: Standard rile - CHG0083506"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_infoblox-all-dns-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_infoblox-standard-ports.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_112"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-dns-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcpudp-domain.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_114"
    description        = "Change ref: CHG0081848 "
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1wnpremg44.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_116"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-wsus-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_120.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_120"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-trendav-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_121.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_124"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-syslog-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcpudp-514.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_132"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-ntp-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_udp-ntp_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_134"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-status-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_90.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_138"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_grp-pr-c-katello-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_tcp_91.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_140"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_mail-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_148"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_uim-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-0-0-0s8.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_150"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-c-mgt_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_uim-servers.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_158"
    description        = "Change ref: CHG0109764"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_rfc-1918.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_105.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_164"
    description        = "Change ref: CHG0067511 - allow Splunk Heavy Forwarder secure access to management protocols and SNMP agent"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1uxpremn74.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_8.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_166"
    description        = "Change ref: CHG0109028"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_rfc-1918.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_grp_rds-kms-server.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_168"
    description        = "Change ref: Standard Rule - CHG0083593"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_172"
    description        = "Change ref: CHG0119053"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_scc-migrated_network_221.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_ip_10-120-163-33.path]
    services           = [nsxt_policy_service.pr-c-mgt_tcp-8083_eq.path]
  }
  rule {
    display_name       = "pr-c-mgt_global_access_175"
    description        = "Change ref: Standard Rule ,CHG0122435, CHG0133580"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-c-mgt_grp_skybox-appliances.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_10-0-0-0_8_range.path]
    services           = [nsxt_policy_service.pr-c-mgt_scc-migrated_service_1.path]
  }
  rule {
    display_name       = "pr-c-mgt_sc1-cde-jumphost-lan_to_any_deny"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-c-mgt_any_to_sc1-cde-jumphost-lan_permit"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_sc1-cde-jumphost-lan.path]
  }
  rule {
    display_name       = "pr-c-mgt_allow_any_to_all_management_networks"
    description        = "Change ref: CHG0146123"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-mgt_all_networks.path]
  }
  rule {
    display_name       = "pr-c-mgt_allow_all_management_networks_to_any"
    description        = "Change ref: CHG0146123"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-mgt_all_networks.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
}
