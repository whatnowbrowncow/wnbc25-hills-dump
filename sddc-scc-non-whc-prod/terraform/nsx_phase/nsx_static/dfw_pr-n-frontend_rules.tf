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

resource "nsxt_policy_security_policy" "pr-n-frontend" {
  display_name    = "pr-n-frontend"
  description     = "Firewall section for pr-n-frontend"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "60"
  domain          = "cgw"
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_2"
    description        = "Change ref: CHG0100450-CHG33775, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sccnsc01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_infoblox-grid-masters.path]
    services           = [nsxt_policy_service.pr-n-frontend_infoblox-vpn.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_4"
    description        = "Change ref: CHG0100450-CHG34874, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sccnsc01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_nms-nimsoft-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-snmptrap_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_6"
    description        = "Change ref: CHG0100450-CHG41280"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sccnsc01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_gibnsr01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9997_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_8"
    description        = "Change ref: CHG0100450-CHG97624"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb040.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ext-api-forwardproxy-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-2222_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_10"
    description        = "Change ref: CHG0100450-CHG0019941,CHG0020750,CHG0021390"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_scc_internal_02.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_brs-server-10-1-29-235.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_12"
    description        = "Change ref: CHG0100450-CHG33547"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_net_10-120-67-0slash24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_bg-sof-infoblox.path]
    services           = [nsxt_policy_service.pr-n-frontend_infoblox-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_16"
    description        = "Change ref: *** internal_rules_above_this_line *** ,*** external_rules_below_this_line *** ,CHG0100450-CHG34207"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_outbound-ext-dns-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    services           = [nsxt_policy_service.pr-n-frontend_dns.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_18"
    description        = "Change ref: CHG0100450-filted on uk-sc1-fw01-02"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_outbound-ext-web-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_23"
    description        = "Change ref: CHG0100450-CHG30350,CHG37668,CHG52108,CHG61551,CHG68039,CHG94732,CHG87837,CHG43088,CHG55401,CHG60964 ,CHG71948,CHG78606,CHG61814,CHG84300"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    services           = [nsxt_policy_service.pr-n-frontend_ftp-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_36"
    description        = "Change ref: CHG0100450-filted on uk-sc1-fw01-02"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_outbound-3rdparty-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    services           = [nsxt_policy_service.pr-n-frontend_3rdparties.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_38"
    description        = "Change ref: CHG0100450-INC16595,CHG91239, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_outbound-3rdparty-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-ntp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_40"
    description        = "Change ref: CHG0116580, PCI-Q4-2017, CHG0121388, CHG0122284, CHG0123200, CHG0123422,CHG0127348,CHG0128366"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnft001.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_329.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_42"
    description        = "Change ref: CHG0122164"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnft001.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_163-156-208-187.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-2222_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_44"
    description        = "Change ref: CHG0134228, CHG0138522"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb040.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_413.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_46"
    description        = "Change ref: CHG0134229, CHG0134230,CHG0145624"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb040.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_21.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_24.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-web_access_in_48"
    description        = "Change ref: CHG0137039"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnft001.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sftp-alexmann-com.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_41.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_2"
    description        = "Change ref: CHG0142918"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-bo-gib-prod.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_171.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_4"
    description        = "Change ref: CHG0137912,CHG0145624"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_404.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_95.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_6"
    description        = "Change ref: CHG0144123"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_mnlfile01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_176.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_8"
    description        = "Change ref: CHG0025821,CHG0036667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_backoffice_web_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_3.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10201-10500_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_11"
    description        = "Change ref: CHG0026112 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-mi-web.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_14"
    description        = "Change ref: CHG0146032 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wncpgap12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wncpgdb12.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_17"
    description        = "Change ref: CHG0122368 ,CHG0035689"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wncpgap12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_bacs-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_48.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_19"
    description        = "Change ref: CHG0042659"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_crm-php.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_vip-10-120-99-91.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_21"
    description        = "Change ref: CHG0016931"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_24"
    description        = "Change ref: CHG0052077 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-mi-web.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-mi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_25"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mars-internal-proxies.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_mars--phys-tc-cluster.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_31"
    description        = "Change ref: CHG0064960"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnap95.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_brsux595.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_33"
    description        = "Change ref: CHG0067874"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wncpgap12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_35"
    description        = "Change ref: CHG006556"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wncpgap12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1apprnsc001-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-5001-5003_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_37"
    description        = "Change ref: CHG0074936, CHG0074942, CHG0074955"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_bacs-server.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod1.path]
    services           = [nsxt_policy_service.pr-n-frontend_bacs-transfer.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_39"
    description        = "Change ref: CHG0076656"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_qlickview_web.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_qlickview_app.path]
    services           = [nsxt_policy_service.pr-n-frontend_qlickview_ports_udp_tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_41"
    description        = "Change ref: CHG0082356"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wncpgap12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_stj-proofpoint.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_45"
    description        = "Change ref: CHG0101250"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_internal_proxyusers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_int-lb-gib-prd.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_48"
    description        = "Change ref: CHG0134302, CHG0134423 ,CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprewb10.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-99-155.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_50"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprewb10.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_278.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9997.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_52"
    description        = "Change ref: CHG0138285"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_416.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_54"
    description        = "Change ref: CHG0137733, CHG0138285, CHG0138277"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_415.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_105.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_56"
    description        = "Change ref: CHG0142064"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap002.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_449.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_58"
    description        = "Change ref: CHG0143131"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxpremn21.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_43.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_60"
    description        = "Change ref: CHG0143239"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_nyxbodk-mrgreen-services.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_172.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_63"
    description        = "Change ref: CHG0146032 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap013.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_64"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-mi-web.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprrmiap01_ip_10-120-99-120.path]
    services           = [nsxt_policy_service.pr-n-frontend_mi-app-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-backoffice_access_in_66"
    description        = "Change ref: CHG0144728"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uipath_robot.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_486.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_486.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_2"
    description        = "Change ref: CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-etl.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_aws-retail-db.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_6"
    description        = "Change ref: CHG0146960"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mars-tc-cluster.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_ld6-informix-rss-server.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1522_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_9"
    description        = "Change ref: CHG0139808 ,CHG0023174, CHG0032663,CHG0036667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_77.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_28.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_36.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_11"
    description        = "Change ref: CHG0076019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-scc-ta-db-13-14.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_brs-proofpoint.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_13"
    description        = "Change ref: CHG0075108 CHG0075369"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-scc-ta-db.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-scc-as400.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_15"
    description        = "Change ref: CHG0032669,CHG0036667,CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_oxi_application_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_122.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_34.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_17"
    description        = "Change ref: CHG0016931"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_18"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mars-tc-cluster.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_19"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mars-tc-cluster.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_rss-gib_openbetrep_top.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1528_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_21"
    description        = "Change ref: CHG0103332"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_sag-php-svrs.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-sa-generics-php.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_22"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprndb01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_2.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_24"
    description        = "Change ref: CHG0054167"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_56.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_23.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_27"
    description        = "Change ref: CHG0054167 ,CHG0054167"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprndb01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_20.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_32"
    description        = "Change ref: CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-etl.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_33"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_380.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-100-50-5.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_37"
    description        = "Change ref: CHG0057619, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019 ,CHG0083338 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-etl.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_226.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_106.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_39"
    description        = "Change ref: CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-etl.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_436.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_127.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_41"
    description        = "Change ref: CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-etl.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_dfwsftp-cadency-trintech-com.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_42"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-etl.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-mi-web.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_46"
    description        = "Change ref: CHG0146032 ,CHG0146032 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-mi.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-sftp-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_53"
    description        = "Change ref: CHG0078585 ,CHG0057897 ,CHG0140054 ,CHG0140054 ,CHG0057897 ,CHG0069073"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wncpgdb12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_brswnprncp002-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_bacs_sql.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_55"
    description        = "Change ref: CHG0068310"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_olmf-php-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-dcs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ldap_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_57"
    description        = "Change ref: CHG0068310"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_olmf-php-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ldap-adgency-brs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ldap_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_60"
    description        = "Change ref: CHG0070655 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_retail-gamcon.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ces-sql-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_61"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_olmf-php-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_olmf-hazelcast-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5701_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_63"
    description        = "Change ref: CHG0076656"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_qlickview_app.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_qlickview_web.path]
    services           = [nsxt_policy_service.pr-n-frontend_qlickview_ports_udp_tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_65"
    description        = "Change ref: CHG0076656"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_qlickview_app.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prodjde-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_jde_ports_tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_69"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnap019.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_71"
    description        = "Change ref: CHG0082151"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_fct-perl-app-srvs.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_feeds-db-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3307_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_74"
    description        = "Change ref: CHG0086206 ,CHG0093492, PCI-Q4-2017,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnap71.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_onshorearchive_db.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1530_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_77"
    description        = "Change ref: CHG0096923 ,CHG0097917"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_41.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_59.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_79"
    description        = "Change ref: CHG0101630"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_oxi_application_servers71-71.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_gib-oxirepserver-tig.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10287_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_81"
    description        = "Change ref: CHG0101912"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_110.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb040.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_83"
    description        = "Change ref: CHG0103084, PCI-Q4-2017, PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mi-server-group.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_mi-mig-srvs.path]
    services           = [nsxt_policy_service.pr-n-frontend_mi-app-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_85"
    description        = "Change ref: CHG0107499"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp-pr-n-svrs-mars.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-mars-gib-prod.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_87"
    description        = "Change ref: CHG0111088"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_commvault-backup-networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-46-0s25.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_97.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_89"
    description        = "Change ref: CHG0123808"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-qlikview-app-svrs.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprtdb001.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1521.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_91"
    description        = "Change ref: CHG0134301 CHG0134334"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-qlikview-app-svrs.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-isilon-nodes.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_19.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_93"
    description        = "Change ref: CHG0125749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_343.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ld6-ncde_db-general-db.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_95"
    description        = "Change ref: CHG0126301"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_357.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ld6-ncde_db-general-db.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_97"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprewb10.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_101"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_273.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9997.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_105"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ld6wnpreap10.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_56.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_107"
    description        = "Change ref: CHG0143191"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_qlikview-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_pte_informix.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1526_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_109"
    description        = "Change ref: CHG0144814"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_488.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_80-45-145-130.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_111"
    description        = "Change ref: CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_qlikview-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_489.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_45.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_113"
    description        = "Change ref: CHG0146862"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprgdb01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_stfp-servers-vmc-retail.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app_access_in_115"
    description        = "Change ref: CHG0146931"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_19.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_11.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_2"
    description        = "Change ref: CHG0140490"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_prod1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_429.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_1.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_4"
    description        = "Change ref: CHG0033974,CHG0034582"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_95.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnmg01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_32.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_6"
    description        = "Change ref: CHG0036204"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_115.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_116.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_54.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_8"
    description        = "Change ref: CHG0041231,CHG0041426, CHG0042175 , CHG0063165, CHG0066380, CHG0038891, CHG0041434, Q2-2017"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-120-64-152-154.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_10-210-64-152-154.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_70.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_10"
    description        = "Change ref: CHG0038841"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_140.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_141.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_63.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_12"
    description        = "Change ref: CHG0038841"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_142.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_143.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_65.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_14"
    description        = "Change ref: CHG0035735"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-64-146.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_155.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_72.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_16"
    description        = "Change ref: CHG0035767"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_prod1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod_epos_bai.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-exec_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_18"
    description        = "Change ref: CHG0040362"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-120-64-152-154.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_10-210-64-152-154.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3777_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_20"
    description        = "Change ref: CHG0040362"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_pr-prodjde-range.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_dr-prodjde-range.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3777_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_22"
    description        = "Change ref: CHG0040657"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_172.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_173.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_24"
    description        = "Change ref: CHG0039172"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_prod1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_178.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_26"
    description        = "Change ref: CHG0041478, Q2-2017, PCI-Q4-2017,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_scc-prodjde.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_devjde.path]
    services           = [nsxt_policy_service.pr-n-frontend_jde-enterprise-service.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_28"
    description        = "Change ref: CHG0076656, Q2-2017, PCI-Q4-2017,PCI Q2 2018,PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_iseries-printer.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_gs-1fl-kyocera01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-lpd_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_30"
    description        = "Change ref: CHG0095962"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_prod1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap001.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_32"
    description        = "Change ref: CHG0120392"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_prod1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_emailhost01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_148.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_34"
    description        = "Change ref: CHG0139557"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-frontend_prod1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-210-64-147.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-prod_access_in_36"
    description        = "Change ref: CHG0143713"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-frontend_iseries-jde-new.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod-jde-new.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_175.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_2"
    description        = "Change ref: CHG0031336, CHG0033671"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_64.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_61.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_25.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_4"
    description        = "Change ref: CHG0032005,CHG0032926"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_92.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_wg-wrproxy-com.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3128_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_6"
    description        = "Change ref: CHG0036002"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_112.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prodjde-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-6016_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_8"
    description        = "Change ref: CHG0036002"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_117.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prodjde-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_10.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_10"
    description        = "Change ref: CHG0041478"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_devjde.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_scc-prodjde.path]
    services           = [nsxt_policy_service.pr-n-frontend_jde-enterprise-service.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_12"
    description        = "Change ref: CHG0137152"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_248.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_251.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_249.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_14"
    description        = "Change ref: CHG0137730,CHG0137423,CHG0137536,CHG0137853"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_419.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_420.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_420.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_16"
    description        = "Change ref: CHG0137730,CHG0137423,CHG0137536,CHG0137853"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpredp1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_394.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_40.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_18"
    description        = "Change ref: CHG0138439"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpredp1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-210-64-151.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_118.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_20"
    description        = "Change ref: CHG0139263"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpredp1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_425.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-14502-14520_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_22"
    description        = "Change ref: CHG0139557 CHG0139618"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_431.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-210-64-142.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_24"
    description        = "Change ref: CHG0139629, CHG0139770"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpredp1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-210-64-151.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_124.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_26"
    description        = "Change ref: CHG0141562"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_dev2.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-210-64-147.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ftp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_28"
    description        = "Change ref: CHG0141766"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpredp1.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-210-64-151.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_136.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_30"
    description        = "Change ref: CHG0142833"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_450.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_451.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_451.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_32"
    description        = "Change ref: CHG0142840"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_452.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_453.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_453.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_34"
    description        = "Change ref: CHG0142840"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_454.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_455.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_455.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_38"
    description        = "Change ref: CHG0142840"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_458.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_459.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_459.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_40"
    description        = "Change ref: CHG0142840"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_460.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_461.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-finance-test_access_in_42"
    description        = "Change ref: CHG0142836"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_465.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_466.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_466.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-app2_access_in_2"
    description        = "Change ref: CHG0060854"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_payment-card-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-frontend_whcard-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_non-cde-app2_access_in_4"
    description        = "Change ref: CHG0061024"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_payment-card-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_gateway-proxy-srvs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3151_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_cobain-iptv-access-in_2"
    description        = "Change ref: CHG0035253, CHG0122265"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cobain-local-media-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_cobain-distribution-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_cobain-distribution.path]
  }
  rule {
    display_name       = "pr-n-frontend_cobain-iptv-access-in_3"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-sccm-in_2"
    description        = "Change ref: CHG0093007"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp001-group-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreap003.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sccm.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-sccm-in_4"
    description        = "Change ref: CHG0093007"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp001-group-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_group-ad-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_ad_ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-sccm-in_6"
    description        = "Change ref: CHG0101376"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-69-227.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-163-99.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8089_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-sccm-in_10"
    description        = "Change ref: CHG0101376"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp001-group-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_80.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9997_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_citrix_netscaler_in_5"
    description        = "Change ref: CHG0124975"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-69-200.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_342.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_153.path]
  }
  rule {
    display_name       = "pr-n-frontend_citrix_netscaler_in_7"
    description        = "Change ref: CHG0124975"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-69-200.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-39-0s24.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcpudp_4.path]
  }
  rule {
    display_name       = "pr-n-frontend_citrix_netscaler_in_9"
    description        = "Change ref: CHG0125710"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-69-200.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_335.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_citrix_netscaler_in_11"
    description        = "Change ref: CHG0126550"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-69-200.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_361.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-81.path]
  }
  rule {
    display_name       = "pr-n-frontend_citrix_netscaler_in_13"
    description        = "Change ref: CHG0137794"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_408.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxpremn003-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_citrix_netscaler_in_15"
    description        = "Change ref: TEMP while getting all relevant destinations"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpredc15-prod.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_1"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_3"
    description        = "Change ref: CHG0054675"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf_proxy_array.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_cf_api_servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-7141_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_5"
    description        = "Change ref: CHG0054675,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf_proxy_array.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_tennis_c_pricing.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_7"
    description        = "Change ref: CHG0070519"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf_proxy_array.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_market-services-app-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_9"
    description        = "Change ref: CHG0079801,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf_proxy_array.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-int-api-trd-icehockey-brs-scc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_11"
    description        = "Change ref: CHG0076631"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf_proxy_array.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_liabilitesbrokers-b.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_13"
    description        = "Change ref: CHG0078384"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf_proxy_array.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-scc-proxy-gtp.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_15"
    description        = "Change ref: CHG0081130,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf_proxy_array.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_rabbit_message_queue.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_17"
    description        = "Change ref: CHG0070758"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_gtp-stream-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_rabbit_message_queue.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5672_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_19"
    description        = "Change ref: CHG0076819,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-gtp-live-stream.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_rabbit_message_queue.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5672_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_21"
    description        = "Change ref: CHG0084321, CHG0084168"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_263.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_10-120-102-0.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_23"
    description        = "Change ref: CHG0084437, CHG0100889"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_265.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_75.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_25"
    description        = "Change ref: CHG0106159"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_central_feeds_vip.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-gtp-endpoint-filter-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8081-8084_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_27"
    description        = "Change ref: CHG0134024"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_noncde-cf-web-net.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-74-46.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-web_access_in_29"
    description        = "Change ref: RAS-VPN"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-72-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_ras-vpn-pool.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_1"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_3"
    description        = "Change ref: CHG0140307"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_438.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprein14-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_5"
    description        = "Change ref: CHG0112912, CHG0127391"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_365.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_uk-scc-wsus.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_7"
    description        = "Change ref: CHG0112912, CHG0127391"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_366.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_ad-kms-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_ad-kms.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_8"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreap005.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_303.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_142.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_10"
    description        = "Change ref: CHG0123404"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprokt01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ext-api-forwardproxy-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3128-3129_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_12"
    description        = "Change ref: CHG0123383"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprokt01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_okta-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_151.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_14"
    description        = "Change ref: CHG0127391, CHG0131841"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_5.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_sailpoint-secure-tunnels.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_16"
    description        = "Change ref: CHG0131841"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxpreap01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ld6uxpreap01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5050-5051_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_18"
    description        = "Change ref: CHG0131841,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_7.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_390.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5050-5051_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_22"
    description        = "Change ref: CHG0137627"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_397.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_398.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_398.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_24"
    description        = "Change ref: CHG0139692"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreap008.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_432.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_26"
    description        = "Change ref: CHG0141042,CHG0141594, CHG0141918,CHG0142524,CHG0142952"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreap008.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_442.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcpudp_6.path]
  }
  rule {
    display_name       = "pr-n-frontend_vmware-esc_access_in_28"
    description        = "Change ref: CHG0142324"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_449.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sofwnprefs01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_1"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-brocade-svc-control.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8100-8101_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_4"
    description        = "Change ref: CHG0091900 CHG0092205 CHG0096957 CHG0096966 ,CHG0134368"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_12.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_5"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_36.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_7"
    description        = "Change ref: CHG0098341"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_mds_app_servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_9"
    description        = "Change ref: CHG0100334"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservicestb-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-2383_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_12"
    description        = "Change ref: INC0628826, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019 ,CHG0104552"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-asdi-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-7011_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_15"
    description        = "Change ref: CHG0114404 ,CHG0130251"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxpremn77.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_17"
    description        = "Change ref: CHG0116274, PCI-Q4-2017, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap010-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_8080.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_19"
    description        = "Change ref: CHG0116274"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_scc-int-lb-n-stingray01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_21"
    description        = "Change ref: CHG0116394"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_scc-int-lb-n-stingray01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ssrs-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_23"
    description        = "Change ref: CHG0124804"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-163-95.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_25"
    description        = "Change ref: CHG0126092, CHG0139061"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_424.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_27"
    description        = "Change ref: CHG0128784,CHG0128741"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_uno-sandbox.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_int-lb_access_in_29"
    description        = "Change ref: RAS-VPN"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-74-0s23.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_ras-vpn-pool.path]
  }
  rule {
    display_name       = "pr-n-frontend_property-prod_access_in_2"
    description        = "Change ref: CHG0108186"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpredb003.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_brswndredb003.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_75.path]
  }
  rule {
    display_name       = "pr-n-frontend_property-prod_access_in_4"
    description        = "Change ref: CHG0109076"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-65-64s27.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_219.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_82.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_2"
    description        = "Change ref: PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_6"
    description        = "Change ref: CHG0130336 ,CHG0130336 ,CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_371.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_147.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_8"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_373.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_10"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_sns-group.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcpudp-domain.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_12"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreap003.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_163.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_14"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_374.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_164.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_16"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_377.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcpudp_5.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_18"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_376.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_165.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_20"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_predc-group.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-ntp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_22"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprecp002.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_168.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_24"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ld6wnpreda01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_166.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_26"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_375.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_28"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_372.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcpudp-49152-65535.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_30"
    description        = "Change ref: CHG0131443,CHG0137184, CHG0145624"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_414.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_corporate-web_access_in_32"
    description        = "Change ref: CHG0140485"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-194-51.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_hr-sap_access_in_2"
    description        = "Change ref: CHG0124930"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprsap01-sc1-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sap-se-nat.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3299_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_hr-sap_access_in_4"
    description        = "Change ref: CHG0125495"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprsap01-sc1-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxpremg32-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_katello-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_aspect-stunnel_access_in_2"
    description        = "Change ref: CHG0129567"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_aspect-stunnel-slash28.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxpremg32-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_162.path]
  }
  rule {
    display_name       = "pr-n-frontend_aspect-stunnel_access_in_4"
    description        = "Change ref: CHG0133344"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_net-10-120-65-128-27-stunnel-re.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_net-3-8-37-0-28-aspect-ext.path]
    services           = [nsxt_policy_service.pr-n-frontend_grp-aspect-stunnel-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_aspect-stunnel_access_in_5"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_2"
    description        = "Change ref: CHG0147013"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mds_app_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ld6ux351.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1522_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_4"
    description        = "Change ref: CHG0129101"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-powerbi-datagateway.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svr-uno-sandbox.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_7"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-powerbi-datagateway.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_10"
    description        = "Change ref: CHG0144615 ,CHG0143323"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_481.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_aws-retail-db.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_12"
    description        = "Change ref: CHG0138849"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_sc1nasncde-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_121.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_14"
    description        = "Change ref: CHG0066342"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_cluster-ports-tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_15"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_cluster-ports-udp.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_16"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_18"
    description        = "Change ref: CHG0072383"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_dr-sql-whdp-listeners.path]
    services           = [nsxt_policy_service.pr-n-frontend_135_5985.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_20"
    description        = "Change ref: CHG0068129, CHG0068244"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_dpe-replication-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_22"
    description        = "Change ref: CHG0071386"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnap004.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_pte_informix.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1526_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_24"
    description        = "Change ref: CHG0080971"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_252.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_pte_informix.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1526_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_26"
    description        = "Change ref: CHG0100164"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ext-api-uno-netrefer-sc1.path]
    services           = [nsxt_policy_service.pr-n-frontend_49430.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_28"
    description        = "Change ref: CHG0100627, CHG0100657"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-oxi-proxy-gib-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_30"
    description        = "Change ref: CHG0109195, CHG0112666"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_32"
    description        = "Change ref: CHG0110900"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-omni-databases.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_34"
    description        = "Change ref: CHG0123351"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_laswncpedb03.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_37"
    description        = "Change ref: CHG0111088 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_38"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_commvault-backup-networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-46-0s25.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_92.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_41"
    description        = "Change ref: CHG0119389 ,CHG0125169"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_gaming-scan1_2_3-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_43"
    description        = "Change ref: CHG0125169,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_bonus_wallet_live_vips.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_45"
    description        = "Change ref: CHG0125169"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_bonus-wallet-rac-43.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_47"
    description        = "Change ref: CHG0128910"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mds_app_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb040.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_49"
    description        = "Change ref: CHG0130222"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_mds_app_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_10-121-77-0s24.path]
    services           = [nsxt_policy_service.pr-n-frontend_dm_redis_ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_51"
    description        = "Change ref: CHG0127981"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-powerbi-datagateway.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_53"
    description        = "Change ref: CHG0127981"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-powerbi-datagateway.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-ssas-tab-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-2383_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_55"
    description        = "Change ref: CHG0130504"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-n-frontend_uno-sandbox.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_git-nonprod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_mgmt-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_57"
    description        = "Change ref: CHG0141618"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-n-frontend_uno-sandbox.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-180-139-145.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1526_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_59"
    description        = "Change ref: CHG0142071"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-nap-uno-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_447.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_61"
    description        = "Change ref: CHG0146547"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-powerbi-datagateway.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_14.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-ods_access_in_63"
    description        = "Change ref: CHG0146954"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-n-frontend_uno-sandbox.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprefs03-new.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_11.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_2"
    description        = "Change ref: CHG0034654"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_100.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_14.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_4"
    description        = "Change ref: CHG0034654"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_268.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_pte_informix.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1526_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_6"
    description        = "Change ref: CHG0116056"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-trs-feed-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-api-seneca-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_8"
    description        = "Change ref: CHG0112135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-101-12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_brswndrrcl02-mgmt-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_31.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_10"
    description        = "Change ref: CHG0112669"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-101-12.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ob-ahdi-svr.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-7011_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_12"
    description        = "Change ref: 10.120.67.25"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_161.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_14"
    description        = "Change ref: CHG0029762"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_54.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_7.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_16"
    description        = "Change ref: CHG0034302, CHG0035130, CHG0064339"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_231.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_liability-db-vips.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_111.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_18"
    description        = "Change ref: CHG0040975"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_informix-hdr-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1528_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_23"
    description        = "Change ref: CHG0064379 ,CHG0066143, CHG0066407, CHG0066420, CHG0134811, CHG0135436"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprecp01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_235.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_27"
    description        = "Change ref: CHG0108326"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreap001.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-tradingreports-3rdparties.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_trading-dmz_access_in_31"
    description        = "Change ref: CHG0119468"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_327.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxpremn12.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8082.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-app_access_in_1"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-app_access_in_3"
    description        = "Change ref: CHG0079735"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxpremn13.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5001_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-app_access_in_5"
    description        = "Change ref: CHG0078639"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_net-10-121-7-0.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-app_access_in_7"
    description        = "Change ref: CHG0087900"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-gtp-outbound-adapters.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnap70.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-app_access_in_9"
    description        = "Change ref: CHG0104282"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cf-prod-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_cbs-gtp-endpoint.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-app_access_in_11"
    description        = "Change ref: CHG0101250"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1uxprnmq35b.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_int-lb-gib-prd.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-cf-app_access_in_13"
    description        = "Change ref: CHG0134024"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-74-46.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_4"
    description        = "Change ref: CHG0147029"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_gibux353-354-fe.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_finance-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_7"
    description        = "Change ref: CHG0034224, CHG0139968 ,CHG0144948"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_aws-dm-prod-vpc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_9"
    description        = "Change ref: CHG0144948"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_aws-dm-prod-vpc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpops01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-22000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_11"
    description        = "Change ref: CHG0142875"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_aws_prd_central_product.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svc-int-lb-mars-backofficeadmin-sc1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_13"
    description        = "Change ref: CHG0141674"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_aws-trading-prod-vpc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_trading-db-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_15"
    description        = "Change ref: See Mike Dawson"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_433.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap002.path]
    services           = [nsxt_policy_service.pr-n-frontend_ms_filesharing_ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_16"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_scc-nessus.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_19"
    description        = "Change ref: new group for access to whdppresent01 ,CHG0139243, CHG0140490"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_accurate_project_aftp_access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_128.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_21"
    description        = "Change ref: CHG0139243"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_accurate_project_aftp_access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_22"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_dreamfactory-uno-api.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_24"
    description        = "Change ref: CHG0139462"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-119-77-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpops01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-22000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_26"
    description        = "Change ref: CHG0138952"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_245.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_42.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_28"
    description        = "Change ref: CHG0137525"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-n-frontend_dreamfactory-uno-api.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_29"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-uno-whdppresent01-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_30"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-uno-dpe-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_dpe-monitoring.path]
    services           = [nsxt_policy_service.pr-n-frontend_dpe-mon-tcp-srv.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_33"
    description        = "Change ref: CHG0135493 ,Group acces to uno cubes"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-uno-cube-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-ssas-tab-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-2383_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_35"
    description        = "Change ref: CHG0128743,CHG0129320"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-uno-sandbox-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svr-uno-sandbox.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_36"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreap008.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_39.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_39"
    description        = "Change ref: CHG0091814 ,CHG0134283"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_27.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_scc-cfweb-tig.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_41"
    description        = "Change ref: CHG0135182, CHG0135202, CHG0135230, CHG0135340, CHG0137508"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_171.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_scc-cfweb-tig.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_14.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_43"
    description        = "Change ref: CHG0135133"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_170.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_scc-cfweb-tig.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_45"
    description        = "Change ref: CHG0059232"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sep-williamhill-plc-uk.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8014_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_47"
    description        = "Change ref: CHG0082282, CHG0082282, CHG0110460"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_stj-trading-dev.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_237.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_53"
    description        = "Change ref: CHG0097668,CHG0101735, CHG0102403, CHG0103017, CHG0103279, ,CHG0103255, CHG0103186, CHG0105469,CHG0105464, CHG0112768, ,CHG0112845, CHG0115434, CHG0116429, CHG0128248"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_304.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreap001.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_55"
    description        = "Change ref: CHG0091814"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-brocade-svc-control.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    services           = [nsxt_policy_service.pr-n-frontend_grp-svc-vtm.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_57"
    description        = "Change ref: CHG0091814"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-brocade-vtm-admin.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    services           = [nsxt_policy_service.pr-n-frontend_grp-svc-vtm-admin.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_59"
    description        = "Change ref: CHG0115537"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-n-frontend_bfa-vegas_users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-ssas-tab-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_32.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_61"
    description        = "Change ref: CHG0065642, CHG0069955, CHG0077636 , CHG81839,  CHG0082041, CHG0082042, CHG0116858,TASK0204207"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_315.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpops01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-22000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_69"
    description        = "Change ref: CHG0065642, CHG0021577,CHG0022166, CHG0024441, CHG0032328, CHG0033499,CHG0036181, ,CHG0036389,CHG0039572, CHG0040689,CHG0040080,CHG0041272, CHG0041700,CHG0042227, ,CHG0043041, CHG0050816, CHG0051701,CHG0051909,CHG0050376,CHG0053671,CHG0054132, ,CHG0059198, CHG0070827,CHG0069595,CHG0071164, CHG0073291,CHG0072861,CHG0076787, ,CHG0076548, CHG0076892, CHG0077307, CHG0077328, CHG0079445, CHG0080142,CHG0082555, ,CHG83346, CHG0085050, CHG0069955, CHG0077636, CHG81839,  CHG0082041, ,CHG0082042, CHG0111280, CHG0116858,TASK0210511"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_238.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_71"
    description        = "Change ref: CHG0123364"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-n-frontend_who-fernandolago.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-29000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_73"
    description        = "Change ref: CHG0065642, CHG0077636, CHG81839, CHG0082041, CHG0111280, CHG0082042,"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_249.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_75"
    description        = "Change ref: CHG0021438,CHG0025888"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_33.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_4.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_77"
    description        = "Change ref: CHG0026112, CHG0071526, RITM0093321, RITM0093284, RITM0098239, RITM0098588,TASK0187868, CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_332.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_164.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_80"
    description        = "Change ref: CHG0019665 *** Locked on BRS CP ***, CHG0027122 ,CHG0029596"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brs-vpn-pool.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_82"
    description        = "Change ref: CHG0019665 *** Locked on GIB SSLVPN ***,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_43.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_84"
    description        = "Change ref: CHG0026112, CHG0107877"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_finance-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wncpgap12.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_7.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_86"
    description        = "Change ref: CHG0034890"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_20.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_42.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_88"
    description        = "Change ref: CHG0030302"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_48.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_49.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_93"
    description        = "Change ref: CHG0090536, CHG0114082, CHG0030418,CHG0034121, ,CHG0041231, CHG0041426, CHG0042175, CHG0063165, ,CHG0066380, CHG0108846, CHG0124102, CHG0124147, ,CHG0125731, CHG0139968"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_354.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_oxi-application-servers-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10301_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_95"
    description        = "Change ref: CHG0034121, CHG0041434,"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_96.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_97.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10302_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_97"
    description        = "Change ref: CHG0029533,CHG0042175, CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_204.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_132.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_18.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_99"
    description        = "Change ref: CHG0031357, CHG0112217, CHG0112476"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_70.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_60.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_24.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_101"
    description        = "Change ref: CHG0122749, CHG0133118,CHG0114382, CHG0118223"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-n-frontend_dev-ics-agent.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_devjde.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_35.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_103"
    description        = "Change ref: CHG0031547"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-n-frontend_serveroperations.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_68.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_105"
    description        = "Change ref: CHG0069003,TASK0238011"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_239.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_30.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_22.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_108"
    description        = "Change ref: CHG0055861, CHG0056706 ,CHG0059761, CHG0112268, CHG0112277 ,CHG0113350, CHG0113584, PCI-Q4-2017"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_trs-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_trs-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_110"
    description        = "Change ref: CHG0105186, PCI-Q4-2017, CHG0126845"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_363.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprrdb04.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_112"
    description        = "Change ref: CHG0034654, CHG0038666, CHG0105843, RITM0102946"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_101.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_233.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_45.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_114"
    description        = "Change ref: CHG0032787,CHG0032889, CHG0052911"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_83.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_84.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_116"
    description        = "Change ref: CHG0032787"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_89.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_90.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_41.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_118"
    description        = "Change ref: CHG0034856"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_jde-web-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_devjde.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9401-9405_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_120"
    description        = "Change ref: CHG0032794, CHG0059213, PCI-Q4-2017, CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_93.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_127.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_124"
    description        = "Change ref: CHG0033008, CHG0033694,CHG0033758,CHG0035348, CHG0041657, CHG0051374, CHG0056272, CHG0068950, ,CHG0085513, CHG0090099, CHG0092323, CHG0092657, CHG0093341, CHG0096615, CHG0100037, CHG0102403, ,CHG0111485, CHG0111851, CHG0115126,CHG0111371, CHG0134721,RITM0121772"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_94.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_123.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_42.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_126"
    description        = "Change ref: CHG0035366"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.pr-n-frontend_net_10-120-39-0m24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_devjde.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9401-9405_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_128"
    description        = "Change ref: CHG0100433, CHG0134222, CHG0139968"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_434.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_cobain-local-media-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_cobain-client.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_130"
    description        = "Change ref: CHG0035253, Q2-2017, PCI-Q4-2017"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_cobain-distribution-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_cobain-local-media-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5118_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_132"
    description        = "Change ref: CHG0036265"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_118.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_119.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_55.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_135"
    description        = "Change ref: CHG0035608, CHG0041496, CHG0041613, CHG0042024, CHG0042246, CHG0051175 ,CHG0051188, CHG0066504, CHG0077069, CHG0082778,CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "58"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_openbet-backoffice-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_168.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_137"
    description        = "Change ref: CHG0052038"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "59"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_bis-team-greenside.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_devjde.path]
    services           = [nsxt_policy_service.pr-n-frontend_bis-devjde.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_139"
    description        = "Change ref: CHG0052038"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "60"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_bis-team-greenside.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prodjde-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_bis-prodjde.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_141"
    description        = "Change ref: CHG0052038"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "61"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_bis-team-greenside.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_was1.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_100.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_143"
    description        = "Change ref: CHG0052038, CHG0112217"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "62"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_289.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod1.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_99.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_145"
    description        = "Change ref: CHG0052038"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "63"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_bis-team-greenside.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-64-171.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_101.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_147"
    description        = "Change ref: CHG0052038, PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "64"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_bis-team-greenside.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-66-112.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_102.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_150"
    description        = "Change ref: CHG0037110, CHG0037649, CHG0037659 ,CHG0037511, CHG0038870"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "65"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_159.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_was1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9645_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_154"
    description        = "Change ref: CHG0053156"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "66"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_222.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnmg01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_17.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_156"
    description        = "Change ref: CHG0038268, CHG0038546"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "67"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_133.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_135.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_16.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_158"
    description        = "Change ref: CHG0037577"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "68"
    source_groups      = [nsxt_policy_group.pr-n-frontend_net_10-120-39-0m24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_was1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9645_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_160"
    description        = "Change ref: CHG0038411, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "69"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_139.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_mimix.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_64.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_162"
    description        = "Change ref: CHG0038841"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "70"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_146.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_147.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_67.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_165"
    description        = "Change ref: CHG0038841 ,CHG0139263"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "71"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_428.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpredp1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_166"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "72"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_148.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_149.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_68.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_168"
    description        = "Change ref: CHG0038841"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "73"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_150.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_151.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_69.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_169"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "74"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_171"
    description        = "Change ref: CHG0054543,CHG0057897"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "75"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_228.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod1.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_104.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_173"
    description        = "Change ref: CHG0040300"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "76"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_openbet-app-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_oxi_application_servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10300_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_175"
    description        = "Change ref: CHG0040362, Q2-2017,PCI Q2 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "77"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-210-64-152-154.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_10-120-64-152-154.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3777_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_177"
    description        = "Change ref: CHG0040362"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "78"
    source_groups      = [nsxt_policy_group.pr-n-frontend_dr-prodjde-range.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_pr-prodjde-range.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3777_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_179"
    description        = "Change ref: CHG0040696 CHG0117314"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "79"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_167.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod1.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_88.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_181"
    description        = "Change ref: CHG0039172"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "80"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-100-50-5.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_177.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_183"
    description        = "Change ref: CHG0040796"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "81"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gibux100.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_prod1.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_79.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_186"
    description        = "Change ref: CHG0038891 ,CHG0041231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "82"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-210-64-140-145.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_10-120-64-140-145.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_84.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_189"
    description        = "Change ref: CHG0041231,CHG0041426, CHG0042175 , CHG0063165, CHG0066380, CHG0038891, ,CHG0041434, Q2-2017, PCI-Q4-2017,PCI Q2 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "83"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-210-64-152-154.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_10-120-64-152-154.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_86.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_191"
    description        = "Change ref: CHG0041231, CHG0041434, CHG0042175,"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "84"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_201.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_202.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10302_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_193"
    description        = "Change ref: CHG0052066"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "85"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_iana-privatenets.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnwb86.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_110.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_195"
    description        = "Change ref: CHG0116321, RITM0098185, TASK0225143"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "86"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_312.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svc-int-lb-mars-backofficeadmin-sc1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_197"
    description        = "Change ref: CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "87"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_10.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_105.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_205"
    description        = "Change ref: CHG0080161, CHG0091125 ,BCP Rule - Do Not Remove ,CHG0054675"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "88"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_gib_openbet_adaptors.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_rabbit_message_queue.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5672_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_213"
    description        = "Change ref: CHG0075445"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "89"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-rd-gib-traders.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-gtp-streaming.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_215"
    description        = "Change ref: CHG0058556, CHG0080232,CHG0081234, CHG0139968"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "90"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_255.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-99-10.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_217"
    description        = "Change ref: CHG0058556,CHG0125763"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "91"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_346.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-99-155.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_219"
    description        = "Change ref: CHG0125763"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "92"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_345.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_iseries_dr_stack.path]
    services           = [nsxt_policy_service.pr-n-frontend_jde.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_221"
    description        = "Change ref: CHG0077468, CHG0080746"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "93"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_stingray-topend.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_sag-php-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_224"
    description        = "Change ref: CHG0061115, CHG0081233, Data-mgt-Channel CHG0060796,CHG0060798,CHG0060799, ,CHG0060801, CHG0060804, CHG0060807,CHG0060810,CHG0060808"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "94"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_accurate_user.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-99-10.path]
    services           = [nsxt_policy_service.pr-n-frontend_accurate_ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_226"
    description        = "Change ref: CHG0058556, CHG0081234 CHG0129521"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "95"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_257.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-66-23.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_228"
    description        = "Change ref: CHG0063740, CHG0096522,INC0922913"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "96"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_240.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-10.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_230"
    description        = "Change ref: CHG0063740, CHG0096522"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "97"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_241.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-10.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_236"
    description        = "Change ref: CHG0064379, CHG0085367, CHG0085878, CHG0091555, CHG0098380,CHG0099042,CHG0099848, CHG0100501, ,CHG0064379, CHG0085367, CHG0085878, CHG0091555, CHG0098380,CHG0099042,CHG0099848, CHG0100501, ,CHG0105293, CHG0109478, CHG0111072, CHG0119833,TASK0165788, RITM0095469, CHG0123842 TASK0177054 ,TASK0246334 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "98"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_272.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-mi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_240"
    description        = "Change ref: CHG0105293, CHG0109478, CHG0111072, CHG0119833,TASK0165788, RITM0095469, CHG0123842 TASK0177054 ,CHG0099557, CHG0124759 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "99"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_corporate_networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-mi-web.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_241"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "100"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_337.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprecp01.path]
    services           = [nsxt_policy_service.pr-n-frontend_nevada-trs-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_243"
    description        = "Change ref: CHG0064781,CHG0127850"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "101"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc_tape_drives_access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc_tape_drives.path]
    services           = [nsxt_policy_service.pr-n-frontend_tape_drive_acces_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_245"
    description        = "Change ref: CHG0066342"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "102"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_cluster-ports-tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_246"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "103"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_cluster-ports-udp.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_248"
    description        = "Change ref: CHG0072383"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "104"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_dpe-monitoring.path]
    services           = [nsxt_policy_service.pr-n-frontend_135_5985.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_250"
    description        = "Change ref: CHG0068129, CHG0068244"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "105"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-prod-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_dpe-replication-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_252"
    description        = "Change ref: CHG0071382, CHG0071550"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "106"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dpe-dr-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_scc-whdp.path]
    services           = [nsxt_policy_service.pr-n-frontend_cluster-query-tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_254"
    description        = "Change ref: CHG0069700"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "107"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brs_business_continuity_suit.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-10.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_256"
    description        = "Change ref: CHG0069789"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "108"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-1-86-0s23.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-10.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_258"
    description        = "Change ref: CHG0069789"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "109"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-1-86-0s23.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-102-10.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_260"
    description        = "Change ref: CHG0069466, CHG0124609,CHG0125287"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "110"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_corporate_networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grouplan-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_262"
    description        = "Change ref: Citrix access, CHG0144201"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "111"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_418.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_groupras-williamhill-plc-uk.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_419.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_265"
    description        = "Change ref: CHG0069484 ,CHG0069484"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "112"
    source_groups      = [nsxt_policy_group.pr-n-frontend_aws-ddos-irl-ext.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_groupras-williamhill-plc-uk.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_116.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_267"
    description        = "Change ref: CHG0072685, CHG0072932,CHG0098693, CHG0124140, CHG0139968"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "113"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_57.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_gtp-stream-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_269"
    description        = "Change ref: CHg0070758, CHG0098229"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "114"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_244.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_gtp-stream-servers.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_271"
    description        = "Change ref: CHG0071475"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "115"
    source_groups      = [nsxt_policy_group.pr-n-frontend_net-pr-cde-api-integration.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-0-0s16.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_276"
    description        = "Change ref: BCP Rule - Do Not Remove ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "116"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brswndvncp004-dev-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-mi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_280"
    description        = "Change ref: CHG0076594 ,CHG0078585, PCI-Q4-2017"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "117"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_gsh-nets.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnap019.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_282"
    description        = "Change ref: CHG0079847"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "118"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_capita_citrix_range.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grouplan-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_284"
    description        = "Change ref: CHG0100377,CHG0122460"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "119"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_71.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-qlikview-sc1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_287"
    description        = "Change ref: CHG0107729,CHG0125763,PCI-Q2-2019 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "120"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_277.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_288"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "121"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_347.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-qlikview-sc1.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_290"
    description        = "Change ref: CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "122"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-gsh-sql-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_297"
    description        = "Change ref: CHG0082717,CHG0085810,CHG0116839,CHG0118409,CHG0118565,TASK0169361,CHG0129845,PCI-Q2-2019 ,TASK0216435 ,CHG0081483 ,CHG0083109, CHG0088818,CHG0118893 ,CHG0076594 ,CHG0076594, TASK0258297"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "123"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_482.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_qlickview_app.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_298"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "124"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_sc1-cde-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_qlickview_app.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_300"
    description        = "Change ref: CHG0076594"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "125"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_sc1-cde-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_qlickview_web.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_304"
    description        = "Change ref: CHG0084897,CHG0085409,CHG0088286,CHG0088912, CHG0109904,CHG0120244"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "126"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-payroll-app-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svr-sc1wnprndb007-top.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-13211_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_306"
    description        = "Change ref: CHG0112268,CHG0112277,CHG0113350,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "127"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uno-uat-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_presentation-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_ssas-listeners.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_308"
    description        = "Change ref: CHG0119393"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "128"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uno-uat-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_ssas-listeners.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_314"
    description        = "Change ref: CHG0118771, RITM0090701, CHG0124906"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "129"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_321.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_318"
    description        = "Change ref: CHG0116456, CHG0124609,CHG0125287"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "130"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_corporate_networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp_1433_8080.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_320"
    description        = "Change ref: CHG0086848, Q2-2017,CHG0115537"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "131"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_305.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_308.path]
    services           = [nsxt_policy_service.pr-n-frontend_ssas-listeners.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_324"
    description        = "Change ref: CHG0100334, CHG0100478, CHG0124609,CHG0125287"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "132"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_corporate_networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-ssas-tab-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_66.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_326"
    description        = "Change ref: CHG0118949"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "133"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_bfa-data-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-ssas-tab-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-2383_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_328"
    description        = "Change ref: CHG0098314, CHG0124609,CHG0125287"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "134"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_corporate_networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-uno-mds-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_330"
    description        = "Change ref: CHG0121975"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "135"
    source_groups      = [nsxt_policy_group.pr-n-frontend_whc-10-121-67-0-24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_dqs-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-29000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_332"
    description        = "Change ref: CHG0122040"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "136"
    source_groups      = [nsxt_policy_group.pr-n-frontend_whc-10-121-67-0-24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ssas-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-4445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_334"
    description        = "Change ref: CHG0122040, PCI Q4 2018,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "137"
    source_groups      = [nsxt_policy_group.pr-n-frontend_whc-10-121-67-0-24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ssas-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-44445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_336"
    description        = "Change ref: CHG0082151"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "138"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_stingray-topend.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_fct-php-app-srvs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_339"
    description        = "Change ref: CHG0083175 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "139"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_35.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_340"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "140"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_spotlight-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_corp-sql-cluster.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_25.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_342"
    description        = "Change ref: CHG0085571"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "141"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brswndvncp004-dev-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1qlikviewstore.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_346"
    description        = "Change ref: CHG0085545, CHG0096927, CHG0116599, CHG0117785, CHG0119236, RITM0094634 TASK0177054, RITM0100254 ,TASK0188203, RITM0102429 ,Q2-2017, PCI-Q4-2017,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "142"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brsux090.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnap019.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_348"
    description        = "Change ref: CHG0087779"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "143"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_service-now-ext.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpredc15-prod.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_139.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_350"
    description        = "Change ref: CHG0089097"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "144"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpops01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-22000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_353"
    description        = "Change ref: CHG0089097 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "145"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_2.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_354"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "146"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_356"
    description        = "Change ref: CHG0089097"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "147"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-29000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_358"
    description        = "Change ref: CHG0089097"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "148"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_1.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_361"
    description        = "Change ref: CHG0089523 ,CHG0091147,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "149"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gib-traders_net_10-180-18-0_255-255-254-0.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb26.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_363"
    description        = "Change ref: PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "150"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gib-traders_net_10-180-18-0_255-255-254-0.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb27.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_367"
    description        = "Change ref: CHG0093007"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "151"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1wnpreap003.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprecp001-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sccm.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_369"
    description        = "Change ref: CHG0095962"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "152"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_33.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap001.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_370"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "153"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_48.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap001.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_372"
    description        = "Change ref: CHG0094921"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "154"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-prn-sccmoni-mg.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-int-lb-n-stingray.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_374"
    description        = "Change ref: CHG0097162, CHG0124609,CHG0125287"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "155"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_corporate_networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_dashboards-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_377"
    description        = "Change ref: CHG0097542 ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "156"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_appservergroup.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_10.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_378"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "157"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_368.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_380"
    description        = "Change ref: CHG0095363"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "158"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-163-73.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_53.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_5.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_381"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "159"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_58.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svr-omt-db-prod.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3308_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_391"
    description        = "Change ref: CHG0132038 ,CHG0100450-CHG33775,CHG35912,CHG89995"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "160"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_infoblox-dns-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sccnsc01.path]
    services           = [nsxt_policy_service.pr-n-frontend_dns.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_393"
    description        = "Change ref: CHG0100450-CHG0020750"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "161"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brs-server-10-1-29-235.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_scc_internal_02.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_399"
    description        = "Change ref: CHG0100450-CHG0030350,CHG41594,CHG80992,CHG90119,CHG96549,CHG96560,CHG0065454,CHG66366,CHG86377 ,CHG0100450-CHG20750,CHG34902,CHG52431,CHG59265,CHG61572,CHG73291,CHG73756,CHG89762,CHG89762 ,CHG30350,CHG40234,CHG42365,CHG55114,CHG56578,CHG59508,CHG61487,CHG64899,CHG80176,CHG82033,CHG85568 ,CHG86197,CHG88797,CHG88673,CHG91735,CHG95441,CHG21723,CHG22166,CHG30302,CHG30350,CHG33274 ,CHG24441,CHG37668,CHG52874,CHG24441,CHG37668,CHG52874,CHG58959,CHG84199,CHG0103594"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "162"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_299.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_401"
    description        = "Change ref: CHG0100450"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "163"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-f5-top.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svr-pr-csc1wnprnwb002-top.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_402"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "164"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_inbound-any-web-access.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_404"
    description        = "Change ref: CHG0100450-CHG0079046"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "165"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb040.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_406"
    description        = "Change ref: CHG0100450-CHG0030350,CHG0041594,CHG0080992,CHG0090119,CHG0096549,CHG0096560"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "166"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_408"
    description        = "Change ref: CHG0101101, CHG0101098, CHG0101168,CHG0118105,TASK0167173"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "167"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_74.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreap001.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_16.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_410"
    description        = "Change ref: CHG0088659"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "168"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_rss-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb51.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_412"
    description        = "Change ref: CHG0101674"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "169"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprecp001-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_414"
    description        = "Change ref: CHG0101674, CHG0108435"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "170"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprecp001-group-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8531_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_416"
    description        = "Change ref: CHG0101287"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "171"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_bi-tableau-migration.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_418"
    description        = "Change ref: CHG0102580"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "172"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gib-cx-adc-internal-api-tier.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdppresent01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_420"
    description        = "Change ref: CHG0106764"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "173"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gib-cx-adc-internal-api-tier.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpops01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-22000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_422"
    description        = "Change ref: CHG0106764"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "174"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gib-cx-adc-internal-api-tier.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-29000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_425"
    description        = "Change ref: CHG0102177, CHG0139968 ,CHG0102177"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "175"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_435.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svc-int-lb-mars-backofficeadmin-sc1.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_427"
    description        = "Change ref: CHG0108063"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "176"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gsh-johnwoods.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_179.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_30.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_429"
    description        = "Change ref: CHG0108186"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "177"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brswndredb003.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpredb003.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_77.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_431"
    description        = "Change ref: CHG0108186"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "178"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_224.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpredb003.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_78.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_435"
    description        = "Change ref: CHG0135588"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "179"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-tfs-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_437"
    description        = "Change ref: CHG0121823"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "180"
    source_groups      = [nsxt_policy_group.pr-n-frontend_whc-10-121-67-0-24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_439"
    description        = "Change ref: CHG0112107, CHG0114518, CHG0114578"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "181"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_302.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_trading-db-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_441"
    description        = "Change ref: CHG0111088, PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "182"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_287.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-100-0s24.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_112.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_443"
    description        = "Change ref: CHG0112325, CHG0112691"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "183"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_290.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_trading-db-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_445"
    description        = "Change ref: CHG0113634, CHG0114433"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "184"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-121-77-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-29000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_447"
    description        = "Change ref: CHG0128957"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "185"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-121-77-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnwb040.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_449"
    description        = "Change ref: CHG0126334"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "186"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-119-77-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_whdpservices01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-29000_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_451"
    description        = "Change ref: CHG0116300"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "187"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_sc1apprein04-09.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_309.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_144.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_453"
    description        = "Change ref: CHG0116721 CHG0116988"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "188"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-po-kr-mars-db-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_317.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_455"
    description        = "Change ref: PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "189"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-163-13.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_326.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_456"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "190"
    source_groups      = [nsxt_policy_group.pr-n-frontend_st_johns_finance_team.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnwb001.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_3.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_457"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "191"
    source_groups      = [nsxt_policy_group.pr-n-frontend_st_johns_finance_team.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnap019.path]
    services           = [nsxt_policy_service.pr-n-frontend_ftp-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_459"
    description        = "Change ref: CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "192"
    source_groups      = [nsxt_policy_group.pr-n-frontend_st_johns_finance_team.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_106.path]
    services           = [nsxt_policy_service.pr-n-frontend_web-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_461"
    description        = "Change ref: CHG0120634"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "193"
    source_groups      = [nsxt_policy_group.pr-n-frontend_st_johns_finance_team.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnap41.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_462"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "194"
    source_groups      = [nsxt_policy_group.pr-n-frontend_st_johns_finance_team.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap001.path]
    services           = [nsxt_policy_service.pr-n-frontend_windows_file_services.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_464"
    description        = "Change ref: CHG0120736, CHG0123895"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "195"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_333.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-101-12.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_466"
    description        = "Change ref: CHG0121510"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "196"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-cx-ppx-ncde-app1-lan.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8080_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_468"
    description        = "Change ref: CHG0122538,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "197"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_data-mgt-dba.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap013.path]
    services           = [nsxt_policy_service.pr-n-frontend_er-studio.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_470"
    description        = "Change ref: CHG0134310"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "198"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_er-studio-access.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap013.path]
    services           = [nsxt_policy_service.pr-n-frontend_er-studio-access-tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_472"
    description        = "Change ref: TASK0173855,CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "199"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_339.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_108.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_475"
    description        = "Change ref: CHG0124975, PCI Q4 2018 ,CHG0124975, PCI Q4 2018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "200"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_341.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-69-201.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_476"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "201"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_355.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprsap01-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3299_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_478"
    description        = "Change ref: CHG0124930,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "202"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sap-se-nat.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprsap01-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3299_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_480"
    description        = "Change ref: CHG0125495"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "203"
    source_groups      = [nsxt_policy_group.pr-n-frontend_svr-pr-sc1uxrdk.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprsap01-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_482"
    description        = "Change ref: CHG0125712,CHG0136018"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "204"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_405.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap002.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_155.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_484"
    description        = "Change ref: CHG0125749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "205"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ld6-ncde_db-general-db.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_344.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_486"
    description        = "Change ref: CHG0125763,PCI-Q2-2019,CHG0134721"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "206"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_351.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_114.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_488"
    description        = "Change ref: RITM0099554, RITM0100881, RITM0117711, RITM0117713,TASK0234173,TASK0240025"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "207"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_362.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_dpe-monitoring.path]
    services           = [nsxt_policy_service.pr-n-frontend_dpe-mon-tcp-srv.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_498"
    description        = "Change ref: CHG0126550"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "208"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-39-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprens01-bovip.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-81.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_500"
    description        = "Change ref: CHG0129603"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "209"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc_bomgar_jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_qlikview.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_502"
    description        = "Change ref: CHG0127391, CHG0127694"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "210"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprefed99.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_161.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_504"
    description        = "Change ref: CHG0130013"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "211"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ld6ux341.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnap41.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_506"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "212"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ld6wnpreda01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_167.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_508"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "213"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_378.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcpudp-3389.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_510"
    description        = "Change ref: CHG0130230"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "214"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-121-73-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprrdb04.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_512"
    description        = "Change ref: CHG0130336"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "215"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_internet-all-subnets.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreda01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_514"
    description        = "Change ref: CHG0130651"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "216"
    source_groups      = [nsxt_policy_group.pr-n-frontend_sc1-whc-noncde-lan03.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprnst01.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_169.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_516"
    description        = "Change ref: CHG0131933,CHG0132808"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "217"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_392.path]
    services           = [nsxt_policy_service.pr-n-frontend_euc_brokers_ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_518"
    description        = "Change ref: CHG0131627"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "218"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_384.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_svc-int-lb-mars-backofficeadmin-sc1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_520"
    description        = "Change ref: CHG0131841,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "219"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_387.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_388.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_522"
    description        = "Change ref: CHG0131841,PCI-Q2-2019"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "220"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_391.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpreiam01.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5050-5051_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_524"
    description        = "Change ref: CHG0132235, CHG0133141, CHG0132583, CHG0133836, CHG0134318"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "221"
    source_groups      = [nsxt_policy_group.pr-n-frontend_malta-wifi-10-40-10_s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_8.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_525"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "222"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ld6wnppeap01.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_6.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5050-5051_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_527"
    description        = "Change ref: CHG0133787"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "223"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_infoblox-all-dns-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_6.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-5050_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_533"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "224"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_malta-finance-team.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap001.path]
    services           = [nsxt_policy_service.pr-n-frontend_accurate_ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_535"
    description        = "Change ref: CHG0134121, CHG0135763, CHG0136186"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "225"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_malta-uno-users.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-ssas-tab-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-2383_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_539"
    description        = "Change ref: CHG0134364,CHG0134950 ,CHG0134455 ,CHG0134556"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "226"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_81.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1uxprsap01-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_542"
    description        = "Change ref: TASK0225149 ,TASK0225149,TASK0233942"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "227"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_395.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_175.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_544"
    description        = "Change ref: CHG0136821"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "228"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_194.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_38.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_546"
    description        = "Change ref: CHG0137162,CHG0137152"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "229"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_234.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpredp1.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_549"
    description        = "Change ref: CHG0137152 ,CHG0137152"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "230"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_242.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_243.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcpudp-3389.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_551"
    description        = "Change ref: CHG0117943"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "231"
    source_groups      = [nsxt_policy_group.pr-n-frontend_brsux084.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-99-155.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_40.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_553"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "232"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_253.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_259.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3389_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_555"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "233"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_267.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcpudp-445.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_557"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "234"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ld6wnpreap10.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_43.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_561"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "235"
    source_groups      = [nsxt_policy_group.pr-n-frontend_gibux998.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_tig-backoffice-williamhill-local.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_61.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_564"
    description        = "Change ref: CHG0137396,CHG0137819 ,CHG0137396,CHG0137819,CHG0137853"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "236"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_409.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_410.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_410.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_566"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "237"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_rfc1918-networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-99-155.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_570"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "238"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_411.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprewb10.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8443_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_576"
    description        = "Change ref: BCP Rule - Do Not Remove ,CHG0146032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "239"
    source_groups      = [nsxt_policy_group.pr-n-frontend_10-1-53-42.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-mi.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-sqlnet_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_578"
    description        = "Change ref: CHG0139243"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "240"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_427.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_581"
    description        = "Change ref: RITM0128074 ,CHG0140237"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "241"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_437.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_int-lb-dm-analytics-tig-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_583"
    description        = "Change ref: CHG0141421"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "242"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-163-89.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_444.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_585"
    description        = "Change ref: CHG0141573"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "243"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-123-13-118.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_446.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_44.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_589"
    description        = "Change ref: CHG0143484"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "244"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_manila-desktops-sports-admin.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_oxi-application-servers-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10301_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_591"
    description        = "Change ref: CHG0143498"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "245"
    source_groups      = [nsxt_policy_group.pr-n-frontend_prod-jde-new.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_iseries-jde-new.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_174.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_593"
    description        = "Change ref: CHG0144786"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "246"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_487.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_oxi-application-servers-vip.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-10301_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_595"
    description        = "Change ref: CHG0145499"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "247"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_490.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap002.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_491.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_597"
    description        = "Change ref: TEMP while getting all relevant sources"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "248"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpredc15-prod.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_599"
    description        = "Change ref: VMC migration rule - to allow connectivity between migrated and yet to be migrated subnets."
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "249"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_pr_n_frontend_local_subnets.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_pr_n_frontend_local_subnets.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_605"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "250"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_8.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-101-27.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_607"
    description        = "Change ref: CHG0146305"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "251"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-120-71-0s24.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap002.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_4.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_615"
    description        = "Change ref: CHG0146194 ,CHG0146194 ,temp-to-remove"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "252"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_15.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_16.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-4445_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_617"
    description        = "Change ref: CHG0146863"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "253"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_aws-dm-prod-vpc.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_uno-sandbox.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_9.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_619"
    description        = "Change ref: CHG0146779"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "254"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_ld6-uno-db-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_17.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_8.path]
  }
  rule {
    display_name       = "pr-n-frontend_internal-vrf_access_in_621"
    description        = "Change ref: CHG0146931"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "255"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_18.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_19.path]
  }
  rule {
    display_name       = "pr-n-frontend_noncde-app-new2_access_in_2"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_qlickview_web.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_retail-bi.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_6.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_2"
    description        = "Change ref: CHG0141979 -  wide access on prem due to specific rules in sddc CHG0145387"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_vmc-sddcs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_3"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_vmc-sddcs.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_5"
    description        = "Change ref: CHG0144834"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_whgroup_ad_servers-chg0144834.path]
    services           = [nsxt_policy_service.pr-n-frontend_whgroup_ad_ports-chg0144834.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_7"
    description        = "Change ref: CHG0142765"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_euc_mgmt_server-group-chg0142765.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_on_premise_datacentre_vlans-group-chg0142765.path]
    services           = [nsxt_policy_service.pr-n-frontend_euc_mgmt_port-group-chg0142765.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_9"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_splunk_heavy_forwarders-chg0143200.path]
    services           = [nsxt_policy_service.pr-n-frontend_splunk_indexing_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_11"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_splunk_deployment_server-chg0143200.path]
    services           = [nsxt_policy_service.pr-n-frontend_splunk_mgmt_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_13"
    description        = "Change ref: CHG0142763"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_wh_nets-chg0142763.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_splunk_heavy_forwarders-chg0142763.path]
    services           = [nsxt_policy_service.pr-n-frontend_splunk_indexing_port-chg0142763.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_15"
    description        = "Change ref: RAS-VPN"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_ras-vpn-pool.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_23"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_25"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-ld6-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_27"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_grp-gib-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_29"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-scc-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_31"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-ld6-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_33"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-gib-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_35"
    description        = "Change ref: and_CHG0131679, CHG0135664"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_282.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_382.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_90.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_38"
    description        = "Change ref: CHG0101535"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_103.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_102.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_37.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_40"
    description        = "Change ref: CHG0116053"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-n-frontend_net-10-0-0-0.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_307.path]
    services           = [nsxt_policy_service.pr-n-frontend_ldap-services.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_45"
    description        = "Change ref: CHG0106526"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_rundeck-servers.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-n-frontend_rundeck-winrm-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_47"
    description        = "Change ref: Wily global access - CHG0081701,"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_wily-svrs_all.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_wily-access-group.path]
    services           = [nsxt_policy_service.pr-n-frontend_wily-outbound-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_50"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_wily-access-group.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_wily-svrs_all.path]
    services           = [nsxt_policy_service.pr-n-frontend_wily-inbound-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_54"
    description        = "Change ref: Global Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-163-99.path]
    services           = [nsxt_policy_service.pr-n-frontend_8089.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_59"
    description        = "Change ref: CHG0078639 ,Global Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_webproxies-cx-scc.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_61"
    description        = "Change ref: Standard rule - CHG0083747"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_whgroup-ad-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_ad-global-rule-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_66"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_mailhosts.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_68"
    description        = "Change ref: Standard rule - CHG0083506"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_infoblox-all-dns-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_infoblox-standard-ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_70"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-wsus-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_27.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_79"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-syslog-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcpudp-514.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_81"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-altris-notification-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_tcp_29.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_85"
    description        = "Change ref: CHG0081848 "
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_scc_snow_collector.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_89"
    description        = "Change ref: Standard Rule,"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-ntp-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_udp-ntp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_91"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-status-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-60606_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_93"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_grp-pr-kms-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-1688_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_95"
    description        = "Change ref: Standard Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_mail-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_103"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_uim-servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-0-0-0s8.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_105"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_uim-servers.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-48000-48030_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_111"
    description        = "Change ref: Standard Rule - CHG0083593"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_143"
    description        = "Change ref: Standard Rule ,Standard Rule ,CHG0057892, CHG0058224, CHG0069697, CHG0086982,CHG0133639"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_webroot_ldap_servers.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnpredc15-prod.path]
    services           = [nsxt_policy_service.pr-n-frontend_ad_ports.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_145"
    description        = "Change ref: CHG0109764"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_rfc1918-networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_229.path]
    services           = [nsxt_policy_service.pr-n-frontend_cluster-ports-tcp.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_150"
    description        = "Change ref: CHG0109028"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_rfc1918-networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_rds-kms-server.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_154"
    description        = "Change ref: CHG0119053"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_324.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_ip_10-120-163-33.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-8083_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_157"
    description        = "Change ref: Standard Rule ,CHG0122435, CHG0133580"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_skybox-appliances.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_net-10-0-0-0.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_9.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_161"
    description        = "Change ref: CHG0125718"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-n-frontend_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_infosecsplunk-sc1-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_165"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_291.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_grp_scc-migrated_network_297.path]
    services           = [nsxt_policy_service.pr-n-frontend_scc-migrated_service_292.path]
  }
  rule {
    display_name       = "pr-n-frontend_global_access_171"
    description        = "Change ref: CHG0137135"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-n-frontend_grp_rfc1918-networks.path]
    destination_groups = [nsxt_policy_group.pr-n-frontend_sc1wnprnap81.path]
    services           = [nsxt_policy_service.pr-n-frontend_tcp-445_eq.path]
  }
}
