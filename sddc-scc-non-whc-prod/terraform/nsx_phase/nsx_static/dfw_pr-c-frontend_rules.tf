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

resource "nsxt_policy_security_policy" "pr-c-frontend" {
  display_name    = "pr-c-frontend"
  description     = "Firewall section for pr-c-frontend"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "50"
  domain          = "cgw"
  rule {
    display_name       = "pr-c-frontend_cde-web_access_in_2"
    description        = "Change ref: CHG0100449-CHG86354,CHG0116922"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_whapi-gateway-srvs.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_gibux1023.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8081_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-web_access_in_4"
    description        = "Change ref: CHG0144060"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_whapi-gateways.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_int-api-bonus-proxy-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-7331_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-web_access_in_6"
    description        = "Change ref: CHG0100449-CHG96558,CHG96693,CHG0116922"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_int-api-sports-pds-cmapi-whapi.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-9191_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-web_access_in_10"
    description        = "Change ref: internal_rules_above_this_line ,external_rules_above_this_line ,CHG0100449-filted on scc-fw01-02"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_outbound-ext-web-access.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_internet-all-subnets.path]
    services           = [nsxt_policy_service.pr-c-frontend_web.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-web_access_in_12"
    description        = "Change ref: CHG0100449-CHG32140,CHG82531,CHG011692"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_outbound-any-web-access.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-frontend_web.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-web_access_in_14"
    description        = "Change ref: CHG0100449-filted on scc-fw01-02"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_outbound-3rdparty-access.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_internet-all-subnets.path]
    services           = [nsxt_policy_service.pr-c-frontend_3rdparties.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-web_access_in_16"
    description        = "Change ref: CHG0137419"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-sports-pds-cmapi-whapi.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-9191_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-app_in_2"
    description        = "Change ref: CHG0023174"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_26.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_27.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-app_in_3"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1uxprcap31.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_informix-db-vip.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1540_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-app_in_4"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1uxprcap32.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_informix-db-vip.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1540_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-app_in_6"
    description        = "Change ref: CHG0030481,CHG0032128,CHG0134084"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_50.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_6.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_21.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-app_in_8"
    description        = "Change ref: CHG0035108, CHG0035320, CHG0134381, CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_57.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_59.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-app_in_10"
    description        = "Change ref: CHG0040300"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_cde_backoffice_app_servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_oxi_application_servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-10300_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-app_in_12"
    description        = "Change ref: CHG0141205"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_146.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_int-lb-cde-cp-aws-noncde-proxy-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_mailhosts_access_in_2"
    description        = "Change ref: CHG0097030, PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_mailhosts.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1apprcmg001.path]
    services           = [nsxt_policy_service.pr-c-frontend_mailhostports.path]
  }
  rule {
    display_name       = "pr-c-frontend_mailhosts_access_in_4"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_mailhosts.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_mailhosts_access_in_6"
    description        = "Change ref: CHG0123744,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_116.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_splunk-group.path]
    services           = [nsxt_policy_service.pr-c-frontend_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_2"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-oracle-db.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_6"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-accurate-batch-srvs.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_8"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-accurate-web-srvs.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_12"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-propman-db.path]
    services           = [nsxt_policy_service.pr-c-frontend_grp-dr-svc-propman.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_16"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-tanda-svr.path]
    services           = [nsxt_policy_service.pr-c-frontend_grp-dr-svc-tanda.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_18"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-jde-svr.path]
    services           = [nsxt_policy_service.pr-c-frontend_jde.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_20"
    description        = "Change ref: CHG0143146, INC1090824"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-jde-app-svr.path]
    services           = [nsxt_policy_service.pr-c-frontend_grp-dr-svc-jde-app.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_22"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-onshore.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-web.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_24"
    description        = "Change ref: CHG0134913"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-onshore.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_int-lb-cdebackoffice-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-web.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_26"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1uxprtdb001.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_30"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-qlikview-web.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-web.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_35"
    description        = "Change ref: CHG0143146, INC1090824 ,CHG0143146, INC1090824"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-sap-routers.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-3299_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_37"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_was01n-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-frontend_jde.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_39"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-offshore.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_svr-openbet-offshore-cde.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-web.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_41"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-dr-noncde-citrix-dvs-offshore.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_int-lb-cdeproxy.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-web.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_43"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprefs04.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_brswnprefs04.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-5722_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_45"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_brswnprefs04.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-citrix-fs.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_47"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprein01.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_49"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_brswnpredb005.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-citrix-fs.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_53"
    description        = "Change ref: CHG0143146,CHG0145624"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_149.path]
    services           = [nsxt_policy_service.pr-c-frontend_svc-citrix-fs.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_55"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_splunk-group.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-9997_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_57"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_splunkdeployment-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8089_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_59"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprens01-bovip.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-81_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_citrix_access_in_v2_61"
    description        = "Change ref: CHG0143146"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_brsapprcmg002.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp_udp_rdp.path]
  }
  rule {
    display_name       = "pr-c-frontend_int-lb_access_in_3"
    description        = "Change ref: CHG0091814 ,CHG0134295"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_4.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_8.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_7.path]
  }
  rule {
    display_name       = "pr-c-frontend_int-lb_access_in_4"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-int-lb-cde-stingray.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-brocade-svc-control.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8100-8101_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_int-lb_access_in_6"
    description        = "Change ref: CHG0134368"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_15.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_22.path]
  }
  rule {
    display_name       = "pr-c-frontend_int-lb_access_in_8"
    description        = "Change ref: CHG0100330"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_30.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_25.path]
    services           = [nsxt_policy_service.pr-c-frontend_puppet-services.path]
  }
  rule {
    display_name       = "pr-c-frontend_int-lb_access_in_10"
    description        = "Change ref: CHG0102733, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-int-lb-cde-stingray.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_rundeck-application-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_6.path]
  }
  rule {
    display_name       = "pr-c-frontend_int-lb_access_in_12"
    description        = "Change ref: CHG0130251"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-int-lb-cde-stingray.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1uxpremn77.path]
    services           = [nsxt_policy_service.pr-c-frontend_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_int-lb_access_in_14"
    description        = "Change ref: CHG0143705"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-44-0s23.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_aws-central-product-prod.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_2"
    description        = "Change ref: CHG0136121"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-brs-media-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp_8400-8403.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_4"
    description        = "Change ref: CHG0146120"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-0s24.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_6"
    description        = "Change ref: CHG0110428, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-media-server-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_8"
    description        = "Change ref: CHG0110428, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-commcell-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_10"
    description        = "Change ref: CHG0110614, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-media-server-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_12"
    description        = "Change ref: CHG0110614, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-media-server-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_14"
    description        = "Change ref: CHG0110901"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-vsa-proxy-servers-scc.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-proxy-server-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_16"
    description        = "Change ref: CHG0111049"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_70.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-73.path]
    services           = [nsxt_policy_service.pr-c-frontend_udp-snmptrap_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_18"
    description        = "Change ref: CHG0110901, PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell-scc.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_72.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_16.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_20"
    description        = "Change ref: CHG0110901"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_74.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-134-253.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_14.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_22"
    description        = "Change ref: CHG0110901"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_77.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_19.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_24"
    description        = "Change ref: CHG0124417"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-73.path]
    services           = [nsxt_policy_service.pr-c-frontend_udp-snmptrap_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_26"
    description        = "Change ref: CHG0111088"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_78.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_87.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_28.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_28"
    description        = "Change ref: CHG0111287, CHG0111353"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_82.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-180-142-164.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_39.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_30"
    description        = "Change ref: CHG0111326"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_84.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-134-0s24.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_17.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_32"
    description        = "Change ref: CHG0112804"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_90.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-134.path]
    services           = [nsxt_policy_service.pr-c-frontend_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_34"
    description        = "Change ref: CHG0115825"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_insightiq-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_isilon-clusters.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_36"
    description        = "Change ref: CHG0122987"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_111.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_115.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_112.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_38"
    description        = "Change ref: CHG0124578"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-70.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_118.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_40"
    description        = "Change ref: CHG0133364"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_2.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8404-8407.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_42"
    description        = "Change ref: CHG0137980"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_45.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8404-8423_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_storage_data_access_in_44"
    description        = "Change ref: CHG0141258"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-114-135-221.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_24.path]
  }
  rule {
    display_name       = "pr-c-frontend_hdr-db_access_in_2"
    description        = "Change ref: CHG0139243"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_55.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_56.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_hdr-db_access_in_4"
    description        = "Change ref: CHG0032040"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_openbet-hdr-reporting-dbs.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_52.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_hdr-db_access_in_6"
    description        = "Change ref: CHG0032569"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_openbet-hdr-reporting-dbs.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_informix-db-vip.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_hdr-db_access_in_8"
    description        = "Change ref: CHG0040696"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_openbet-hdr-reporting-dbs.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_64.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_26.path]
  }
  rule {
    display_name       = "pr-c-frontend_hdr-db_access_in_10"
    description        = "Change ref: CHG0040987"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_openbet-hdr-reporting-dbs.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_prodjde.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_hdr-db_access_in_12"
    description        = "Change ref: CHG0095962"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_openbet-hdr-reporting-dbs.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-99-10.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_database_access_in_2"
    description        = "Change ref: CHG0023174"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_informix-db-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_informix-hdr-vip.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_14.path]
  }
  rule {
    display_name       = "pr-c-frontend_database_access_in_3"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_informix-db-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_archive-db.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1530_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_database_access_in_4"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_informix-db-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_brsux311.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1560_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_2"
    description        = "Change ref: CHG0034224"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_scc-nessus.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_3"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-brs-media-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp_8400-8403.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_4"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnpremn20.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-nas-ip-range40-49.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_68.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_10"
    description        = "Change ref: CHG0018357, CHG0019810, CHG0021073, CHG0021327, CHG0002234, CHG0023308,CHG0059082"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_16.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_17.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_8.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_14"
    description        = "Change ref: CHG0023174"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_oxi_application_servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_29.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_17"
    description        = "Change ref: *** Locked on BRS CP *** ,*** Locked on BRS CP ***"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_vpn-uk-24.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_19"
    description        = "Change ref: CHG0029533, CHG0071526, CHG0134381"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_openbet-live-dr.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_13.path]
    services           = [nsxt_policy_service.pr-c-frontend_web.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_21"
    description        = "Change ref: CHG0032682, CHG0032663"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_54.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_informix-hdr-vip.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1528_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_23"
    description        = "Change ref: CHG0074086"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sccuxstnmg03.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_25"
    description        = "Change ref: CHG0125763, CHG0134381"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_125.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_18.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_69.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_27"
    description        = "Change ref: CHG0040975"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-101-10.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_informix-hdr-vip.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1528_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_29"
    description        = "Change ref: CHG0091814"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_7.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-int-lb-cde-stingray.path]
    services           = [nsxt_policy_service.pr-c-frontend_grp-vtm-svc.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_31"
    description        = "Change ref: CHG0091814,CHG0118303,CHG0120322, CHG0123895"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-brocade-vtm-admin.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-int-lb-cde-stingray.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_2.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_33"
    description        = "Change ref: CHG0094883"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-c-frontend_brsux311.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_informix-db-vip.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_37"
    description        = "Change ref: Proofpoint Rule - CHG0100580"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1apprcmg001.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_mailhosts.path]
    services           = [nsxt_policy_service.pr-c-frontend_mailhostports.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_39"
    description        = "Change ref: Proofpoint Rule - CHG0100580"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1apprcmg001.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_mailhosts.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_41"
    description        = "Change ref: Proofpoint Rule - CHG0097030, PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_rfc1918.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_emailhost02.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_43"
    description        = "Change ref: Proofpoint Rule - CHG0097030"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_rfc1918.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_emailhost01.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_45"
    description        = "Change ref: CHG0101535"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_34.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_35.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_15.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_49"
    description        = "Change ref: CHG0100330"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_32.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_33.path]
    services           = [nsxt_policy_service.pr-c-frontend_puppet-services.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_51"
    description        = "Change ref: CHG0100449-CHG91757, CHG0094722,CHG0116922,CHG0120588"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_102.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-scc-pr-cwb-layer7.path]
    services           = [nsxt_policy_service.pr-c-frontend_web-proxy-ports.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_53"
    description        = "Change ref: CHG0100449-CHG71475"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_cde-web-any-access.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_net_10-120-37-0m24.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_59"
    description        = "Change ref: CHG0106968"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_euc-team-.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-0s24.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_61"
    description        = "Change ref: CHG0107904, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_46.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-48-122.path]
    services           = [nsxt_policy_service.pr-c-frontend_informix_replication.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_63"
    description        = "Change ref: CHG0109619,TASK0238453"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_53.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-0s25.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_7.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_65"
    description        = "Change ref: CHG0110147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_infoblox-all-dns-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1isilon-ssip.path]
    services           = [nsxt_policy_service.udp-any.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_67"
    description        = "Change ref: CHG0110428, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-media-server-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_69"
    description        = "Change ref: CHG0110428, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-commcell-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_71"
    description        = "Change ref: CHG0110614, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-media-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-media-server-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_73"
    description        = "Change ref: CHG0110901, CHG0111187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_73.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_commvault-commcell.path]
    services           = [nsxt_policy_service.pr-c-frontend_commvault-proxy-server-service.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_75"
    description        = "Change ref: CHG0111028 CHG0118198"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_101.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-0s25.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_77"
    description        = "Change ref: CHG0111088"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_commvault-backup-networks.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_79.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8400-8403_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_79"
    description        = "Change ref: CHG0111287,CHG0117589"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_97.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_81.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_34.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_81"
    description        = "Change ref: CHG0112804, CHG0114385"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-134.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_89.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_43.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_83"
    description        = "Change ref: CHG0113167"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-210-143-170.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_91.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_22.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_85"
    description        = "Change ref: CHG0114967 CHG0115147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_scc-nas-ip-range.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_23.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_87"
    description        = "Change ref: CHG0117834"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_whc-nexus.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_isilon-cluster-scc.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_42.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_91"
    description        = "Change ref: CHG0125642,PCI-Q2-2019 ,CHG0125642,PCI-Q2-2019 ,CHG0125642,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1uxprnap71.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_archive-db.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1530.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_93"
    description        = "Change ref: CHG0122987"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-118-0-0s16.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_112.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_49.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_97"
    description        = "Change ref: CHG0122369 ,CHG0122735, PCI Q4 2018,PCI-Q2-2019 ,CHG0123406,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_113.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_100"
    description        = "Change ref: CHG0124172"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-141-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-0s25.path]
    services           = [nsxt_policy_service.pr-c-frontend_rdp.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_102"
    description        = "Change ref: CHG0124953 CHG0125133"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_122.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-108.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_54.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_104"
    description        = "Change ref: CHG0124975"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-69-200.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_120.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_53.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_107"
    description        = "Change ref: CHG0124975, PCI Q4 2018,PCI-Q2-2019 ,CHG0124975"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-69-200.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-39-0s24.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcpudp_1.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_109"
    description        = "Change ref: CHG0126133"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-c-frontend_brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_citrix-network-24.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_29.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_111"
    description        = "Change ref: CHG0125763"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.pr-c-frontend_net_10-210-39-0m24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprefs04.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_56.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_114"
    description        = "Change ref: CHG0125763 ,CHG0126775,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-c-frontend_net_10-210-39-0m24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnpredb005.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_57.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_117"
    description        = "Change ref: CHG0126550 ,CHG0128520,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-69-200.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_133.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-81.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_122"
    description        = "Change ref: CHG0127113"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_142.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1-whapi-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_66.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_124"
    description        = "Change ref: CHG0130058"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1uxpremg22-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_137.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_125"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_sc1-apic-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_isilon-cluster-scc.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_127"
    description        = "Change ref: CHG0137245"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.pr-c-frontend_gibux998.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_int-lb-cdebackoffice-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_9.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_129"
    description        = "Change ref: CHG0141258"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-114-135-221.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprbkcs01.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_33.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_131"
    description        = "Change ref: CHG0141421"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-89.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_88.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_133"
    description        = "Change ref: CHG0144610"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_100-74-144-0s23.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_emailhost02.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_137"
    description        = "Change ref: CHG0145088"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.pr-c-frontend_gibprcap01.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_isilon-cluster-scc.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_internal-vrf_access_in_139"
    description        = "Change ref: CHG0146699"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.pr-c-frontend_sc1wnprepvs05.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprelic01.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-citrix-pvs.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-backoffice_in_2"
    description        = "Change ref: CHG0021821"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_cde-backoffice-web-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_cde_backoffice_app_servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-10201-10600_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-backoffice_in_4"
    description        = "Change ref: CHG0021821, CHG0020771"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_cde-backoffice-web-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_cde_crypto_app_servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-10201-10600_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_cde-backoffice_in_6"
    description        = "Change ref: CHG0041229, CHG0135748"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_cde-backoffice-web-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_141.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_3"
    description        = "Change ref: CHG0141979 -  wide access on prem due to specific rules in sddc ,CHG0145426"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_vmc-sddcs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_4"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_vmc-sddcs.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_6"
    description        = "Change ref: CHG0144834"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_whgroup_ad_servers-chg0144834.path]
    services           = [nsxt_policy_service.pr-c-frontend_whgroup_ad_ports-chg0144834.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_8"
    description        = "Change ref: CHG0142765"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_euc_mgmt_server-group-chg0142765.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_on_premise_datacentre_vlans-group-chg0142765.path]
    services           = [nsxt_policy_service.pr-c-frontend_euc_mgmt_port-group-chg0142765.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_10"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_splunk_heavy_forwarders-chg0143200.path]
    services           = [nsxt_policy_service.pr-c-frontend_splunk_indexing_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_12"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_splunk_deployment_server-chg0143200.path]
    services           = [nsxt_policy_service.pr-c-frontend_splunk_mgmt_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_14"
    description        = "Change ref: CHG0142763"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_wh_nets-chg0142763.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_splunk_heavy_forwarders-chg0142763.path]
    services           = [nsxt_policy_service.pr-c-frontend_splunk_indexing_port-chg0142763.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_16"
    description        = "Change ref: CHG0142763"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_wh_nets-chg0142763.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_splunk_deployment_server-chg0142763.path]
    services           = [nsxt_policy_service.pr-c-frontend_splunk_mgmt_port-chg0142763.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_19"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_ras-vpn-pool.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_22"
    description        = "Change ref: CHG0101535"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-66-0s24.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_43.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_18.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_25"
    description        = "Change ref: CHG0106526"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_rundeck-servers.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-frontend_rundeck-winrm-ports.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_27"
    description        = "Change ref: Wily global access - CHG0081701, PCI Q2 2016"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_wily-svrs_all.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_wily-access-group.path]
    services           = [nsxt_policy_service.pr-c-frontend_wily-outbound-ports.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_29"
    description        = "Change ref: CHG0101535"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_42.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_39.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_17.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_31"
    description        = "Change ref: CHG0116053"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-c-frontend_classa-8.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_93.path]
    services           = [nsxt_policy_service.pr-c-frontend_ldap-services.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_37"
    description        = "Change ref: Global Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_katello.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_tcp_25.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_39"
    description        = "Change ref: Global Rules"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_wsus.path]
    services           = [nsxt_policy_service.pr-c-frontend_grp-pr-c-wsus-ports.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_47"
    description        = "Change ref: CHG0114133"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_scc-nas-ip-range.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-nas-ports.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_53"
    description        = "Change ref: Global Rules"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_splunk-logger.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_63"
    description        = "Change ref: CHG0078639, PCI Q2 2016"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_webproxies-cx-scc.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_65"
    description        = "Change ref: Standard rule - CHG0083506"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_infoblox-all-dns-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_infoblox-standard-ports.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_67"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_mailhosts.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_69"
    description        = "Change ref: Standard rule - CHG0083747"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_67.path]
    services           = [nsxt_policy_service.pr-c-frontend_whgroup-ad-ports.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_71"
    description        = "Change ref: CHG0031243"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnprein12.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-1688_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_77"
    description        = "Change ref: CHG0081848 "
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_scc_snow_collector.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_79"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_uim-servers.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_classa-8.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_81"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-c-frontend_classa-8.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_uim-servers.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_85"
    description        = "Change ref: CHG0109028"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_rfc1918.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_rds-kms-server.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_87"
    description        = "Change ref: CHG0109764"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_rfc1918.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_61.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_89"
    description        = "Change ref: Standard rule - CHG0083593"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_91"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_grp_grp-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_97"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_grp-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_107"
    description        = "Change ref: CHG0118423"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-c-frontend_ip_10-120-46-0s25.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_sc1wnpremg30.path]
    services           = [nsxt_policy_service.pr-c-frontend_60606.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_109"
    description        = "Change ref: CHG0119053"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_scc-migrated_network_103.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_ip_10-120-163-33.path]
    services           = [nsxt_policy_service.pr-c-frontend_tcp-8083_eq.path]
  }
  rule {
    display_name       = "pr-c-frontend_global_access_113"
    description        = "Change ref: CHG0122435, CHG0133580"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-c-frontend_grp_skybox-appliances.path]
    destination_groups = [nsxt_policy_group.pr-c-frontend_classa-8.path]
    services           = [nsxt_policy_service.pr-c-frontend_scc-migrated_service_1.path]
  }
}
