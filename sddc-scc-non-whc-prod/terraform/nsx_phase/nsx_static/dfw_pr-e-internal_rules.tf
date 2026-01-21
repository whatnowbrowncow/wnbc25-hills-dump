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

resource "nsxt_policy_security_policy" "pr-e-internal" {
  display_name    = "pr-e-internal"
  description     = "Firewall section for pr-e-internal"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "70"
  domain          = "cgw"
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_4"
    description        = "Change ref: CHG0138766,CHG0140021,CHG0143922"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_net-obj-g-solarwinds-destinations.path]
    services           = [nsxt_policy_service.pr-e-internal_svc-obj-g-solarwinds.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_6"
    description        = "Change ref: CHG0111088"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-0s24.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_26.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_9.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_8"
    description        = "Change ref: CHG0075847"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-0s24.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_brs-git-nonprod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_10"
    description        = "Change ref: CHG0019196"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-0s24.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_sc1uxpremg30.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-60606_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_12"
    description        = "Change ref: CHG0141604"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_rundeck-app-servers.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_aws-retail-prod-vpc.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_14"
    description        = "Change ref: CHG0112330"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_27.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_28.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-3306_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_16"
    description        = "Change ref: CHG0112691"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremn73.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-99-85.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-1523_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_18"
    description        = "Change ref: CHG0101781 / CHG0114923"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_rundeck-primary-cluster.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_14.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9977.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_20"
    description        = "Change ref: CHG0054123"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-26.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-129-151.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_22"
    description        = "Change ref: CHG0134971"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_skybox-appliances.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_skybox-clients.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_25"
    description        = "Change ref: CHG0117835, CHG0118067, CHG0118070, CHG0118072, CHG0118074, CHG0118080, CHG0118083, ,CHG0119313"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnmem01.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_36.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-3306.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_27"
    description        = "Change ref: CHG0130058"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremg22.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_isilon-storage-svrs.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_29"
    description        = "Change ref: CHG0114426"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-134.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_pure-storage-svrs.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_31"
    description        = "Change ref: CHG0064699, CHG0143874"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-e-internal_tufin.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_tufin-endpoints.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_33"
    description        = "Change ref: CHG0033465"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxrdk.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_retail-liability-svrs.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_35"
    description        = "Change ref: CHG0122369,CHG0127976"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn006.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_41.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_37"
    description        = "Change ref: CHG0115562"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremg31.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_puppet-master-db.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8081_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_39"
    description        = "Change ref: CHG0063703, CHG0143875"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-e-internal_netbrain.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_netbrain-destinations.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_37.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_41"
    description        = "Change ref: Cacti - CHG0015230"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-e-internal_gib-internal-traffic-mon.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
    services           = [nsxt_policy_service.pr-e-internal_udp-snmp_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_43"
    description        = "Change ref: CHG0123307, CHG0123640"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_ca-hub-servers-scc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_ca-hub-clients-aws.path]
    services           = [nsxt_policy_service.pr-e-internal_ca-hub-services-group.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_45"
    description        = "Change ref: CHG0125390, CHG0125510"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-e-internal_prdxclo25srv001-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_51.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_47"
    description        = "Change ref: CHG0124683"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremg60.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_cran-r-project-org.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-873_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_49"
    description        = "Change ref: CHG0125713"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_54.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_55.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8089_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_51"
    description        = "Change ref: CHG0033465"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_88.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_apache-servers.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_89.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_53"
    description        = "Change ref: CHG0143884"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_91.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_92.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_55"
    description        = "Change ref: CHG0127786"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpreap242.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_brs-git-nonprod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_56"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_wh-border-devices.path]
    services           = [nsxt_policy_service.pr-e-internal_udp-snmp_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_58"
    description        = "Change ref: CHG0129308"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremg26.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_us-subnets.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_21.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_60"
    description        = "Change ref: CHG0131597"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_69.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_malta_pure_array.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_70.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_62"
    description        = "Change ref: CHG0135223"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpredb11-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ld6wnpredb11-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_25.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_64"
    description        = "Change ref: CHG0135457"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremg26.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_in1-ilo-net.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_27.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_66"
    description        = "Change ref: CHG0136426"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnprcdb30.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ld6wnprcdb30.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_29.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_68"
    description        = "Change ref: CHG0111816"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_athene-servers.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_sc1prapvc01-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_70"
    description        = "Change ref: CHG0137053"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn17.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-143-171.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_72"
    description        = "Change ref: CHG0141421"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-89.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-121-10-109.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_74"
    description        = "Change ref: CHG0141421"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-89.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_107.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_76"
    description        = "Change ref: CHG0141736"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-89.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_106.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_78"
    description        = "Change ref: CHG0143826"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_130.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_84.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_132.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_80"
    description        = "Change ref: CHG0065974, CHG0143829"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_131.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_checkpoint-cma.path]
    services           = [nsxt_policy_service.pr-e-internal_tufincheckpointports.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_82"
    description        = "Change ref: CHG0079889,CHG0083441,CHG0092703,CHG0094547,CHG0094606"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxrdk.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_stingrays.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_84"
    description        = "Change ref: CHG0089097"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_whdpops01.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-22000_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_86"
    description        = "Change ref: CHG0089097"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_whdppresent01.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-23000_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_88"
    description        = "Change ref: CHG0089097"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_whdpservices01.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-29000_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_90"
    description        = "Change ref: CHG0089097"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_whdpservices.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_3.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_93"
    description        = "Change ref: CHG0082905 ,CHG0083742"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_sql-monitored-servers.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_4.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_95"
    description        = "Change ref: CHG0082905"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnprcmn250-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_sql-servers.path]
    services           = [nsxt_policy_service.pr-e-internal_sql-monitoring.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_97"
    description        = "Change ref: CHG0143828"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremn57.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_76.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_5.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_99"
    description        = "Change ref: CHG0143830"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremg32.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-112-13-33.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-www_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_101"
    description        = "Change ref: CHG0135695, CHG0143840"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_77.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_78.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_83.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_103"
    description        = "Change ref: CHG0079439"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremg26.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_80.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_105"
    description        = "Change ref: CHG0034356, CHG0143923"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.pr-e-internal_obmon-onshore.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_81.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_107"
    description        = "Change ref: CHG0108784"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn006.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_95.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_109"
    description        = "Change ref: CHG0065471, CHG0070895, CHG0066166"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.pr-e-internal_scc_wsus.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_139.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_111"
    description        = "Change ref: CHG0134210, CHG0134346"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn81.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-134-250.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_25.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_113"
    description        = "Change ref: CHG0143841"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn21.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_82.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8089_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_115"
    description        = "Change ref: CHG0143842"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn21.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-100-9-73.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_6.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_117"
    description        = "Change ref: CHG0098476, CHG0101521, CHG0115562"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_93.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-201-230-17.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_119"
    description        = "Change ref: CHG0085802"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "58"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn74.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_138.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_121"
    description        = "Change ref: CHG0112804, CHG0114385, CHG0143887, CHG0143888"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "59"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-134.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_isilon-storage-svrs.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_26.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_123"
    description        = "Change ref: CHG0076486, CHG0077496,CHG0077496"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "60"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremn01-prod-williamhill-plc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_134.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_125"
    description        = "Change ref: CHG0097787"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "61"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_140.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-146-135.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-ssh_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_127"
    description        = "Change ref: CHG0143974"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "62"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_wily_svrs_scc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_consul-hosts.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8500_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_130"
    description        = "Change ref: Snow monitoring to all vCenter 6.0 ,CHG0087219,CHG0134053"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "63"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremg44.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_vcenter.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_132"
    description        = "Change ref: CHG0144405"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "64"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_master-rundeck-app-nodes.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_134"
    description        = "Change ref: CHG0144444"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "65"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_master-rundeck-app-nodes.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ext-api-forwardproxy-gib-prod-williamhill-plc-nic2.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9070_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_monitoring-int_access_in_136"
    description        = "Change ref: CHG0144134"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "66"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-163-89.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-oracle-instances.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-oracle-instances-services.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_2"
    description        = "Change ref: CHG0141979 -  wide access on prem due to specific rules in sddc"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_vmc-sddcs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_3"
    description        = ""
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_vmc-sddcs.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_5"
    description        = "Change ref: CHG0144834"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_whgroup_ad_servers-chg0144834.path]
    services           = [nsxt_policy_service.pr-e-internal_whgroup_ad_ports-chg0144834.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_7"
    description        = "Change ref: CHG0015788"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.pr-e-internal_scc-nessus.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_9"
    description        = "Change ref: CHG0067421, CHG0090267"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_sc1uxpremn74.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_udp_1.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_11"
    description        = "Change ref: CHG0094805 CHG0117584"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_wily_svrs_scc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_sccbrs-stingray.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9070.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_13"
    description        = "Change ref: CHG0109028"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rds-kms-server.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-1688_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_15"
    description        = "Change ref: CHG0115147 CHG0118220"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_31.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_15.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_17"
    description        = "Change ref: CHG0144215"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.pr-e-internal_net-10-120-163-0_255-255-255-0.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-121-10-0s24.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-9996_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_19"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.pr-e-internal_net-10-0-0-0_255-0-0-0.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_135.path]
    services           = [nsxt_policy_service.pr-e-internal_nimsoft-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_21"
    description        = "Change ref: CHG0079749"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_136.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_net-10-0-0-0_255-0-0-0.path]
    services           = [nsxt_policy_service.pr-e-internal_nimsoft-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_23"
    description        = "Change ref: CHG0089523"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_6.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_7.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_36.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_25"
    description        = "Change ref: CHG0102733"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_18.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rundeck-primary-cluster.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_35.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_27"
    description        = "Change ref: CHG0094015"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_splunk-heavy-forwarders.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_splunk-deploy-server.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8089.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_29"
    description        = "Change ref: CHG0067421"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1uxpremn74.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-e-internal_splunk_mgmt.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_31"
    description        = "Change ref: CHG0143973"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs-ld6.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs-scc.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_120.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_33"
    description        = "Change ref: CHG0143973"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs-scc.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs-ld6.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_27.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_35"
    description        = "Change ref: CHG0144184"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs-ld6.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_sc1wnpredb11-prod-williamhill-plc.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_12.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_39"
    description        = "Change ref: Katello - Generic"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-0-0s16.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-163-130.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_125.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_41"
    description        = "Change ref: Katello - Generic"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-121-0-0s16.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-163-136.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_22.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_43"
    description        = "Change ref: CHG0144190"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-121-10-0s24.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-163-0s24.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8089_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_45"
    description        = "Change ref: CHG0144188"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-180-163-234.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-163-234.path]
    services           = [nsxt_policy_service.pr-e-internal_maria-db-services.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_47"
    description        = "Change ref: CHG0142765"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_euc_mgmt_server-group-chg0142765.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_on_premise_datacentre_vlans-group-chg0142765.path]
    services           = [nsxt_policy_service.pr-e-internal_euc_mgmt_port-group-chg0142765.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_49"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_splunk_heavy_forwarders-chg0143200.path]
    services           = [nsxt_policy_service.pr-e-internal_splunk_indexing_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_51"
    description        = "Change ref: CHG0143200"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_wh_nets-chg0143200.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_splunk_deployment_server-chg0143200.path]
    services           = [nsxt_policy_service.pr-e-internal_splunk_mgmt_port-chg0143200.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_57"
    description        = "Change ref: RAS-VPN"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_ras-vpn-pool.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_63"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-scc-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_65"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-ld6-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_67"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-gib-commvault-svrs.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_71"
    description        = "Change ref: CHG0112231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_grp-ld6-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_73"
    description        = "Change ref: Standard rule - CHG0083747"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_whgroup-ad-servers.path]
    services           = [nsxt_policy_service.pr-e-internal_ad-global-rule-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_75"
    description        = "Change ref: CHG0121600"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_grp-gib-commvault-svrs.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-8400-8403.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_78"
    description        = "Change ref: Wily global access - CHG0081701, CHG0092588"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_wily-svrs_all.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_wily-access-group.path]
    services           = [nsxt_policy_service.pr-e-internal_wily-outbound-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_80"
    description        = "Change ref: PCI Q2 2016"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_wily-access-group.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_wily-svrs_all.path]
    services           = [nsxt_policy_service.pr-e-internal_wily-inbound-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_82"
    description        = "Change ref: CHG0106526"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_rundeck-servers.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-e-internal_rundeck-winrm-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_84"
    description        = "Change ref: CHG0078639"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_webproxies-cx-scc.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_86"
    description        = "Change ref: Standard rule - CHG0083593"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.icmp-any.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_88"
    description        = "Change ref: Standard rule - CHG0083506"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_infoblox-servers.path]
    services           = [nsxt_policy_service.pr-e-internal_infoblox-standard-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_90"
    description        = "Change ref: CHG0097030"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_mailhosts.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-smtp_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_92"
    description        = "Change ref: CHG0095595, CHG0095744"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-0-0s16.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_10.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_6.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_94"
    description        = "Change ref: CHG0101535"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_17.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_16.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_4.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_96"
    description        = "Change ref: CHG0116053"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-0-0-0s8.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_33.path]
    services           = [nsxt_policy_service.pr-e-internal_ldap-service.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_98"
    description        = "Change ref: Global Rule"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_sc1uxpromn012.path]
    services           = [nsxt_policy_service.pr-e-internal_8089.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_104"
    description        = "Change ref: CHG0060667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
    services           = [nsxt_policy_service.pr-e-internal_udp-snmp_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_106"
    description        = "Change ref: CHG0060667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_108"
    description        = "Change ref: CHG0060667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-1433_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_111"
    description        = "Change ref: CHG0060667 ,logging disabled to stop double logging"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_11.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_113"
    description        = "Change ref: CHG0095363"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremn73.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_scc-migrated_network_11.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_8.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_115"
    description        = "Change ref: CHG0060667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_117"
    description        = "Change ref: CHG0060667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_aws-100-64-0-0slash10.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_121"
    description        = "Change ref: CHG0110997"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.pr-e-internal_ip_10-120-134-246.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_ip_10-120-163-134.path]
    services           = [nsxt_policy_service.pr-e-internal_udp-syslog_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_124"
    description        = "Change ref: CHG0060667 ,logging disabled to reduce double logging"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_service_10.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_126"
    description        = "Change ref: CHG0123314"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_grp-bomgar-cde-jumphosts.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_grp-orion-app-srvs.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-3389.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_130"
    description        = "Change ref: CHG0060667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_rfc1918networks.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_132"
    description        = "Change ref: CHG0060667"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.pr-e-internal_aws-100-64-0-0slash10.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_internal-nets.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_136"
    description        = "Change ref: CHG0014573"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_direct-internet-access.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
    services           = [nsxt_policy_service.pr-e-internal_scc-migrated_tcp_1.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_183"
    description        = "Change ref: CHG0069736, CHG0072222"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.pr-e-internal_scc_nimsoft_mgmt.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_rackspace_nimsoft_ch.path]
    services           = [nsxt_policy_service.pr-e-internal_nimsoft-ports.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_224"
    description        = "Change ref: CHG0077138"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "58"
    source_groups      = [nsxt_policy_group.pr-e-internal_grp_external-netflow-sources.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_grp-swinds-polling-svrs.path]
    services           = [nsxt_policy_service.pr-e-internal_solarwinds-netflow.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_226"
    description        = "Change ref: CHG0077138"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "59"
    source_groups      = [nsxt_policy_group.pr-e-internal_scc-ca-nfa-harvester.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_uk-sc1-border-routers.path]
    services           = [nsxt_policy_service.pr-e-internal_udp-snmp_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_228"
    description        = "Change ref: CHG0080518"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "60"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremg44.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_williamhillssl-cloudsoftcat-com.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_232"
    description        = "Change ref: CHG0081562"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "61"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremg45.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_grp_snow_public.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-https_eq.path]
  }
  rule {
    display_name       = "pr-e-internal_global_access_242"
    description        = "Change ref: CHG0086912"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "62"
    source_groups      = [nsxt_policy_group.pr-e-internal_sc1wnpremg45.path]
    destination_groups = [nsxt_policy_group.pr-e-internal_williamhillssl-cloudsoftcat-com-secondary.path]
    services           = [nsxt_policy_service.pr-e-internal_tcp-1433_eq.path]
  }
}
