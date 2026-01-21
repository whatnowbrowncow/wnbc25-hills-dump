/*========================================

###########################################################################
###########################################################################
###                                                                     ###
###                DYNAMIC RULES - NOT MIGRATED FROM SCC                ###
###                                                                     ###
###########################################################################
###########################################################################

========================================*/

resource "nsxt_policy_security_policy" "dynamic" {
  display_name    = "dynamic"
  description     = "Firewall section for dynamic"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "20"
  domain          = "cgw"
  rule {
    display_name       = "deny scc openbet citrix to ma3wnprfs08"
    description        = "Change ref: NETAR-7228"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.citrix_ob_scc.path]
    destination_groups = [nsxt_policy_group.ma3wnprfs08-group-williamhill-plc.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "VMC corp networks to all RFC-1918 and RFC-6598 subnets"
    description        = "Change ref: CHG0145252"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.vmc_corp_subnets.path]
    destination_groups = [nsxt_policy_group.rfc_1918.path, nsxt_policy_group.rfc_6598.path]
  }
  rule {
    display_name       = "All RFC-1918 and RFC-6598 subnets to VMC corp networks"
    description        = "Change ref: CHG0145252"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.rfc_1918.path, nsxt_policy_group.rfc_6598.path]
    destination_groups = [nsxt_policy_group.vmc_corp_subnets.path]
  }
  rule {
    display_name       = "VMC corp networks to all internet"
    description        = "Change ref: User Internet access rules - InfoSec approved"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.vmc_corp_subnets.path]
    destination_groups = [nsxt_policy_group.internet_minus_rfc1918.path]
    services           = [nsxt_policy_service.general_internet_ports.path]
  }
  rule {
    display_name       = "OpenDNS Access"
    description        = "Change ref: OpenDNS access - InfoSec approved"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.opendns_virtual_appliances.path]
    destination_groups = [nsxt_policy_group.opendns_ntp_service.path, nsxt_policy_group.opendns_dns_service.path]
    services           = [nsxt_policy_service.opendns_ports.path]
  }
  rule {
    display_name       = "OpenDNS Access"
    description        = "Change ref: OpenDNS access - InfoSec approved"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.sc1uxpregw01.path]
    destination_groups = [nsxt_policy_group.wh_apogee_external_site.path]
    services           = [nsxt_policy_service.wh_apogee_external_site_services.path]
  }
  rule {
    display_name       = "scc dc nets and brs trs to aws storage gateway"
    description        = "Change ref: CHG0145578-CHG0146480"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.scc_dc_networks.path, nsxt_policy_group.brsuxdrrdb04.path]
    destination_groups = [nsxt_policy_group.aws_storage_gateway.path]
    services           = [nsxt_policy_service.aws_storage_gatweway_ports.path]
  }
  rule {
    display_name       = "aws storage gateway to scc dc nets and brs trs"
    description        = "Change ref: CHG0145578-CHG0146480"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.aws_storage_gateway.path]
    destination_groups = [nsxt_policy_group.scc_dc_networks.path, nsxt_policy_group.brsuxdrrdb04.path]
    services           = [nsxt_policy_service.aws_storage_gatweway_ports.path]
  }
  rule {
    display_name       = "dm_uno_presentation_access_in"
    description        = "Change ref: NA"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "9"
    source_groups      = [nsxt_policy_group.uno_presentation_access_group.path]
    destination_groups = [nsxt_policy_group.uno_presentation_lb_vip.path]
    services           = [nsxt_policy_service.uno_presentation_ports.path]
  }
  rule {
    display_name       = "dm_uno_sandbox_access_in"
    description        = "Change ref: NA"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "10"
    source_groups      = [nsxt_policy_group.uno_sandbox_access_group.path]
    destination_groups = [nsxt_policy_group.uno_sandbox_lb_vip.path]
    services           = [nsxt_policy_service.uno_sandbox_ports.path]
  }
  rule {
    display_name       = "dm_uno_cube_access_in"
    description        = "Change ref: NA"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "11"
    source_groups      = [nsxt_policy_group.uno_cube_access_group.path]
    destination_groups = [nsxt_policy_group.uno_cube_lb_vip.path]
    services           = [nsxt_policy_service.uno_cube_ports.path]
  }
  rule {
    display_name       = "dm_uno_dpe_access_in"
    description        = "Change ref: NA"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "12"
    source_groups      = [nsxt_policy_group.uno_dpe_access_group.path]
    destination_groups = [nsxt_policy_group.uno_dpe_servers.path]
    services           = [nsxt_policy_service.uno_dpe_ports.path]
  }
  rule {
    display_name       = "vmcprapvrli02 to sc1uxpremn126"
    description        = "Change ref: CHG0146817"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "13"
    source_groups      = [nsxt_policy_group.vmcprapvrli02.path]
    destination_groups = [nsxt_policy_group.sc1uxpremn126.path]
    services           = [nsxt_policy_service.tcp8088.path]
  }
  rule {
    display_name       = "accurate batch dfs to accurate batch dfs scc legacy to scc"
    description        = "Change ref: CHG0146931"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "14"
    source_groups      = [nsxt_policy_group.sc1wnpreap10.path]
    destination_groups = [nsxt_policy_group.irewnpreap10.path]
    services           = [nsxt_policy_service.accurate_batch_dfs.path]
  }
  rule {
    display_name       = "accurate batch dfs to accurate batch dfs scc to legacy scc"
    description        = "Change ref: CHG0146931"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "15"
    source_groups      = [nsxt_policy_group.irewnpreap10.path]
    destination_groups = [nsxt_policy_group.sc1wnpreap10.path]
    services           = [nsxt_policy_service.accurate_batch_dfs.path]
  }
  rule {
    display_name       = "snow mid servers to williamhillssl-cloudsoftcat-com-secondary"
    description        = "Change ref: CHG0146988"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "16"
    source_groups      = [nsxt_policy_group.snow_mid_servers.path]
    destination_groups = [nsxt_policy_group.williamhillssl-cloudsoftcat-com-secondary.path]
    services           = [nsxt_policy_service.tcp1433.path]
  }
  rule {
    display_name       = "allow access to new gib rss servers"
    description        = "Change ref: CHG0147001"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "17"
    source_groups      = [nsxt_policy_group.trs_servers.path, nsxt_policy_group.sc1wnprndb002.path]
    destination_groups = [nsxt_policy_group.gib_rss_server.path]
    services           = [nsxt_policy_service.tcp1576.path]
  }
  rule {
    display_name       = "Spotlight monitoring servers to ld6 uno db servers"
    description        = "Change ref: CHG0147215"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "18"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.spotlight_monitoring_servers.path]
    services           = [nsxt_policy_service.uno_db_ports.path]
  }
  rule {
    display_name       = "Spotlight access to monitor retail vmc db servers"
    description        = "Change ref: CHG0147260"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "19"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.retail_vmc_retail_db_servers.path]
    services           = [nsxt_policy_service.retail_db_ports.path]
  }
  rule {
    display_name       = "sc1wnprcmn250 access to ld6_uno_db_servers"
    description        = "Change ref: CHG0147209"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "20"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.ld6_uno_db_servers.path]
    services           = [nsxt_policy_service.ld6_uno_db_ports.path]
  }
  rule {
    display_name       = "UI Robot Path to MRG NYX Services"
    description        = "Change ref: CHG0147311"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "21"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.mrg_nyx_services_for_uipath.path]
    services           = [nsxt_policy_service.tcp-http-https.path]
  }
  rule {
    display_name       = "UI Robot Path to MRG Jira"
    description        = "Change ref: CHG0147284"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "22"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.jira_mrgreen_zone.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "Citrix controllers to vsphere"
    description        = "Change ref: CHG0147368"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "23"
    source_groups      = [nsxt_policy_group.citrix_controllers.path]
    destination_groups = [nsxt_policy_group.scc_non_whc_prod_vcentre.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "SCC-NON-WHC SDDC vSphere network to port mirror server"
    description        = "Change ref: CHG0147444"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "24"
    source_groups      = [nsxt_policy_group.scc_non_whc_prod_vsphere_net.path]
    destination_groups = [nsxt_policy_group.irepraptcp02.path]
  }
  rule {
    display_name       = "rpa robots vmc to mrg fileshare"
    description        = "Change ref: CHG0147919"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "25"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.mrg-fileshare.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "rpa robots vmc to ld6 fileserver"
    description        = "Change ref: CHG0152337"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "26"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.ld6-fileshare.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "gibux353 & gibux354 to sc1uxprnwb51"
    description        = "Change ref: CHG0147891"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "27"
    source_groups      = [nsxt_policy_group.gibux353-354-mgt.path]
    destination_groups = [nsxt_policy_group.sc1uxprnwb51.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "STJWN561 sftp access to sc1uxprnwb51"
    description        = "Change ref: AWSMIG-253"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "28"
    source_groups      = [nsxt_policy_group.stjwn561.path]
    destination_groups = [nsxt_policy_group.sc1uxprnwb51.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "rpa robots to featurespace ui"
    description        = "Change ref: CHG0148052"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "29"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.featurespace_ui.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "scc citrix to jde meridian"
    description        = "Change ref: CHG0148470"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "30"
    source_groups      = [nsxt_policy_group.scc_citrix.path]
    destination_groups = [nsxt_policy_group.jde_meridian_svrs.path]
    services           = [nsxt_policy_service.jde_meridian_ports.path]
  }
  rule {
    display_name       = "rpa robots to int-lb-backoffice"
    description        = "Change ref: CHG0148498"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "31"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.int-lb-backoffice.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "rpa robots to int-api-bonuswallet"
    description        = "Change ref: CHG0148632"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "32"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.gib-int-api-bonuswallet.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "scc uno load balancers to ld6 presentation"
    description        = "Change ref: CHG0148856"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "33"
    source_groups      = [nsxt_policy_group.scc_uno_load_balancers.path]
    destination_groups = [nsxt_policy_group.whdppresent02.path]
    services           = [nsxt_policy_service.tcp23000.path]
  }
  rule {
    display_name       = "sftp server to new as400"
    description        = "Change ref: CHG0148876"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "34"
    source_groups      = [nsxt_policy_group.sc1uxprnwb040.path]
    destination_groups = [nsxt_policy_group.prodjden.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "sc1uxprnft001 to prodjden"
    description        = "Change ref: CHG0122284"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "35"
    source_groups      = [nsxt_policy_group.sc1uxprnft001.path]
    destination_groups = [nsxt_policy_group.prodjden.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "sc1uxprnap019 to as400"
    description        = "Change ref: CHG0122284"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "36"
    source_groups      = [nsxt_policy_group.sc1uxprnap019.path]
    destination_groups = [nsxt_policy_group.grp_prod1_dev1.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "ld6 uno db to sc1uxprnwb040"
    description        = "Change ref: CHG0148614"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "37"
    source_groups      = [nsxt_policy_group.ld6_uno_db_servers.path]
    destination_groups = [nsxt_policy_group.sc1uxprnwb040.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "scc uno load balancers connection to whdp02tabular."
    description        = "Change ref: CHG0148971"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "38"
    source_groups      = [nsxt_policy_group.scc_uno_load_balancers.path]
    destination_groups = [nsxt_policy_group.whdp02tabular.path]
    services           = [nsxt_policy_service.uno_cube_ports.path]
  }
  rule {
    display_name       = "scc uno load balancers connection to uno mds."
    description        = "Change ref: CHG0148971"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "39"
    source_groups      = [nsxt_policy_group.scc_uno_load_balancers.path]
    destination_groups = [nsxt_policy_group.uno_mds.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "scc uno load balancers connection to uno ssrs."
    description        = "Change ref: CHG0148976"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "40"
    source_groups      = [nsxt_policy_group.scc_uno_load_balancers.path]
    destination_groups = [nsxt_policy_group.uno_ssrs.path]
    services           = [nsxt_policy_service.tcp-http-https.path]
  }
  rule {
    display_name       = "rpa robots access to nyx spain"
    description        = "Change ref: CHG0148928"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "41"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.nyx-spain.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "hp oneview to aws tss vpcs"
    description        = "Change ref: CHG0149147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "42"
    source_groups      = [nsxt_policy_group.sc1uxpremg26.path]
    destination_groups = [nsxt_policy_group.aws-tss-vpc-prod.path, nsxt_policy_group.aws-tss-vpc-dev.path]
    services           = [nsxt_policy_service.snmp-traps.path]
  }
  rule {
    display_name       = "ld6 uno to whdp"
    description        = "Change ref: CHG0147981"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "43"
    source_groups      = [nsxt_policy_group.ld6wnprndb005.path]
    destination_groups = [nsxt_policy_group.whdpservices01.path]
    services           = [nsxt_policy_service.tcp5022.path, nsxt_policy_service.tcp29000.path]
  }
  rule {
    display_name       = "uno jumphost to uno presentation"
    description        = "Change ref: CHG0149220"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "44"
    source_groups      = [nsxt_policy_group.uno-remote-access.path]
    destination_groups = [nsxt_policy_group.uno-presentation-ld6.path]
    services           = [nsxt_policy_service.uno_presentation_ports.path]
  }
  rule {
    display_name       = "uno jumphost to uno presentation"
    description        = "Change ref: CHG0149094"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "45"
    source_groups      = [nsxt_policy_group.ld6-ncde-stingray.path]
    destination_groups = [nsxt_policy_group.uno-dmtfs.path]
    services           = [nsxt_policy_service.tcp8080.path]
  }
  rule {
    display_name       = "bacs to jde"
    description        = "Change ref: CHG0149277"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "46"
    source_groups      = [nsxt_policy_group.sc1wnprncp001.path]
    destination_groups = [nsxt_policy_group.prodjden.path, nsxt_policy_group.prod1.path]
    services           = [nsxt_policy_service.tcp21.path, nsxt_policy_service.tcp22.path, nsxt_policy_service.tcp139.path, nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "uno hosts to sftp"
    description        = "Change ref: CHG0149285"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "47"
    source_groups      = [nsxt_policy_group.ld6_uno_db_servers.path]
    destination_groups = [nsxt_policy_group.sc1uxprnwb51.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "UI Robot Path to int pres clp"
    description        = "Change ref: CHG0149127"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "48"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.int-pres-clp-sc1.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "Sofia to SCC Commvault"
    description        = "Change ref: CHG0149455"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "49"
    source_groups      = [nsxt_policy_group.sofia-commvault-server.path]
    destination_groups = [nsxt_policy_group.sc1wnprbkcs01.path]
    services           = [nsxt_policy_service.commvault_server_ports.path]
  }
  rule {
    display_name       = "SCC to Sofia Commvault"
    description        = "Change ref: CHG0149455"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "50"
    source_groups      = [nsxt_policy_group.sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.sofia-commvault-server.path]
    services           = [nsxt_policy_service.commvault_server_ports.path]
  }
  rule {
    display_name       = "cde jumphost to ld6 lab esxi hosts"
    description        = "Change ref: CHG0149246"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "51"
    source_groups      = [nsxt_policy_group.cde_jumphosts.path]
    destination_groups = [nsxt_policy_group.ld6_lab_esxi_hosts.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "rpa robots to have access to bonus engine"
    description        = "Change ref: CHG0149626"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "52"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.bonusadmin_mrgreen_services.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "ping federate aws to ad autopilot poc"
    description        = "Change ref: CHG0149589"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "53"
    source_groups      = [nsxt_policy_group.ping_federate_aws_subnets.path]
    destination_groups = [nsxt_policy_group.ad_autopilot_poc.path]
    services           = [nsxt_policy_service.ping_to_ad_autopilot_ports.path]
  }
  rule {
    display_name       = "rpa robots to have access to campaign manager mrgreen"
    description        = "Change ref: CHG0149628"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "54"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.campaignmanager_mrgreen_zone.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "com_vault_to_vsa"
    description        = "Change ref: CHG0149801"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "55"
    source_groups      = [nsxt_policy_group.comm_vault_servers_group.path]
    destination_groups = [nsxt_policy_group.vsa_proxy_vmc.path]
    services           = [nsxt_policy_service.commvault_server_ports.path]
  }
  rule {
    display_name       = "vsa_to_com_vault"
    description        = "Change ref: CHG0149801"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "56"
    source_groups      = [nsxt_policy_group.vsa_proxy_vmc.path]
    destination_groups = [nsxt_policy_group.comm_vault_servers_group.path]
    services           = [nsxt_policy_service.commvault_server_ports.path]
  }
  rule {
    display_name       = "vsa_to_esx_hosts_vmc_scc_non-whc"
    description        = "Change ref: CHG0149801"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "57"
    source_groups      = [nsxt_policy_group.vsa_proxy_vmc.path]
    destination_groups = [nsxt_policy_group.esx_hosts_vmc_scc_non-whc.path]
    services           = [nsxt_policy_service.commvault_backup_ports.path]
  }
  rule {
    display_name       = "ld6 ncde lbs to erportal"
    description        = "Change ref: CHG0149972"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "58"
    source_groups      = [nsxt_policy_group.ld6-ncde-stingray.path]
    destination_groups = [nsxt_policy_group.sc1wnprnap013.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "sc1 cde jumphosts to sc1 cx lans"
    description        = "Change ref: CHG0079131"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "59"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.sc1_cx_nets.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "commvault servers connectivity"
    description        = "Change ref: CHG0150040"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "60"
    source_groups      = [nsxt_policy_group.grp_commvault.path]
    destination_groups = [nsxt_policy_group.grp_commvault.path]
    services           = [nsxt_policy_service.commvault_server_ports.path]
  }
  rule {
    display_name       = "mars backofficeadmin access"
    description        = "Change ref: RITM0148509"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "61"
    source_groups      = [nsxt_policy_group.mars-backofficeadmin-users.path]
    destination_groups = [nsxt_policy_group.mars-backofficeadmin.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "bacs to jde"
    description        = "Change ref: CHG0150049"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "62"
    source_groups      = [nsxt_policy_group.sc1wnprncp001.path]
    destination_groups = [nsxt_policy_group.prodjden.path]
    services           = [nsxt_policy_service.tcp139.path, nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "commvault servers to sc1 vcenter on prem"
    description        = "Change ref: CHG0150040"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "63"
    source_groups      = [nsxt_policy_group.grp_commvault.path]
    destination_groups = [nsxt_policy_group.sc1-vcenter.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "sc1 jumphosts to f5 big iq caesars"
    description        = "Change ref: CHG0150343"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "64"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.f5_big-iq_nonprod_caesars.path]
    services           = [nsxt_policy_service.tcp_8443_tcp_443.path]
  }
  rule {
    display_name       = "sc1 jumphosts to vmc preprod and dev vropss appliances"
    description        = "Change ref: CHG0150362"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "65"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.vmc_preprod_and_dev_vropss_appliances.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "Bulgaria Sec ISP to Citrix"
    description        = "Change ref: CHG0125710"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "66"
    source_groups      = [nsxt_policy_group.bulgaria_sec_isp.path]
    destination_groups = [nsxt_policy_group.groupras-williamhill-plc-uk.path]
    services           = [nsxt_policy_service.groupras_ports.path]
  }
  rule {
    display_name       = "scc bomgar to vmc prod vrops appliances"
    description        = "Change ref: CHG0150584"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "67"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.vmc_prod_vrops_appliances.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "Bulgaria LAN to Citrix"
    description        = "Change ref: CHG0125710"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "68"
    source_groups      = [nsxt_policy_group.bulgaria_lan.path]
    destination_groups = [nsxt_policy_group.groupras-williamhill-plc-uk.path]
    services           = [nsxt_policy_service.groupras_ports.path]
  }
  rule {
    display_name       = "rpa robots to int-api-bonuswallet"
    description        = "Change ref: CHG0148632"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "69"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.gib-int-api-bonuswallet-2.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "citrix accurate to file server"
    description        = "Change ref: CHG0150752"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "70"
    source_groups      = [nsxt_policy_group.scc_accurate_citrix.path]
    destination_groups = [nsxt_policy_group.sc1wnprefs04.path]
    services           = [nsxt_policy_service.tcp445.path, nsxt_policy_service.tcp135.path]
  }
  rule {
    display_name       = "citrix accurate to xenapp 7 licensing"
    description        = "Change ref: CHG0150752"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "71"
    source_groups      = [nsxt_policy_group.scc_accurate_citrix.path]
    destination_groups = [nsxt_policy_group.sc1wnprelic01.path]
    services           = [nsxt_policy_service.citrix_licensing_ports.path]
  }
  rule {
    display_name       = "citrix delivery controller to vda"
    description        = "Change ref: CHG0150752"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "72"
    source_groups      = [nsxt_policy_group.citrix_controllers.path]
    destination_groups = [nsxt_policy_group.scc_accurate_citrix.path]
    services           = [nsxt_policy_service.citrix_to_vda_ports.path, nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "citrix delivery controller to vda"
    description        = "Change ref: CHG0150752, NETAR-7000"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "73"
    source_groups      = [nsxt_policy_group.scc_accurate_citrix.path]
    destination_groups = [nsxt_policy_group.citrix_controllers.path]
    services           = [nsxt_policy_service.tcp-http-https.path]
  }
  rule {
    display_name       = "vmc citrix to vmc hids Server"
    description        = "Change ref: CHG0150752"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "74"
    source_groups      = [nsxt_policy_group.scc_citrix.path]
    destination_groups = [nsxt_policy_group.sc1uxprcmn001.path]
    services           = [nsxt_policy_service.udp1514.path]
  }
  rule {
    display_name       = "citrix accurate to sc1wnprens01-bo-vip"
    description        = "Change ref: CHG0150911"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "75"
    source_groups      = [nsxt_policy_group.scc_accurate_citrix.path]
    destination_groups = [nsxt_policy_group.sc1wnprens01_bo_vip.path]
    services           = [nsxt_policy_service.tcp81.path]
  }
  rule {
    display_name       = "trading eks to trs db"
    description        = "Change ref: CHG0150798"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "76"
    source_groups      = [nsxt_policy_group.trading_aws_subnets.path]
    destination_groups = [nsxt_policy_group.trs_mysql.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "netscaler snip access"
    description        = "Change ref: CHG0150752"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "77"
    source_groups      = [nsxt_policy_group.sc1wnprens01_snip.path]
    destination_groups = [nsxt_policy_group.scc_accurate_citrix.path]
    services           = [nsxt_policy_service.netscaler_snip_ports.path]
  }
  rule {
    display_name       = "brs citrix to accurate oracle"
    description        = "Change ref: CHG0151059"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "78"
    source_groups      = [nsxt_policy_group.brs_citrix.path]
    destination_groups = [nsxt_policy_group.sc1uxprgdb05-new.path]
    services           = [nsxt_policy_service.tcp1521.path]
  }
  rule {
    display_name       = "brs citrix to accurate batch"
    description        = "Change ref: CHG0151059"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "79"
    source_groups      = [nsxt_policy_group.brs_citrix.path]
    destination_groups = [nsxt_policy_group.sc1wnpreap10-new.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "brs citrix to accurate web"
    description        = "Change ref: CHG0151059"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "80"
    source_groups      = [nsxt_policy_group.brs_citrix.path]
    destination_groups = [nsxt_policy_group.sc1wnprewb10-new.path]
    services           = [nsxt_policy_service.tcp8443.path]
  }
  rule {
    display_name       = "deny brs openbet citrix to accurate web"
    description        = "Change ref: CHG0151059"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "81"
    source_groups      = [nsxt_policy_group.brs_openbet_citrix.path]
    destination_groups = [nsxt_policy_group.sc1wnpreap10-new.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "scc bomgar to aws unity db"
    description        = "Change ref: CHG0151090"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "82"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.aws_unity_db.path]
    services           = [nsxt_policy_service.tcp3306.path, nsxt_policy_service.postgresql.path]
  }
  rule {
    display_name       = "user access to trs server"
    description        = "Change ref: CHG0151198"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "83"
    source_groups      = [nsxt_policy_group.trs_users.path]
    destination_groups = [nsxt_policy_group.trs_mysql.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "aws prod ireland vpc to trading report server"
    description        = "Change ref: CHG0151337"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "84"
    source_groups      = [nsxt_policy_group.aws_prod_ireland_vpc_trading.path]
    destination_groups = [nsxt_policy_group.trs_mysql.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "retail bi reporting to kms server"
    description        = "Change ref: CHG0151433"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "85"
    source_groups      = [nsxt_policy_group.sc1wnprrmimg01.path]
    destination_groups = [nsxt_policy_group.sc1wndremg002.path]
    services           = [nsxt_policy_service.tcp1688.path]
  }
  rule {
    display_name       = "WH AWS to sc1wnpredc17"
    description        = "Change ref: CHG0151491"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "86"
    source_groups      = [nsxt_policy_group.rfc_6598.path]
    destination_groups = [nsxt_policy_group.sc1wnpredc17.path]
    services           = [nsxt_policy_service.rodc_ports.path]
  }
  rule {
    display_name       = "sc1wnpredc17 to KMS"
    description        = "Change ref: CHG0151491"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "87"
    source_groups      = [nsxt_policy_group.sc1wnpredc17.path]
    destination_groups = [nsxt_policy_group.brs_sc1_wnpremg002.path]
    services           = [nsxt_policy_service.kms_ports.path]
  }
  rule {
    display_name       = "RFC1918 to sc1wnpredc17"
    description        = "Change ref: CHG0151491"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "88"
    source_groups      = [nsxt_policy_group.rfc_1918.path]
    destination_groups = [nsxt_policy_group.sc1wnpredc17.path]
    services           = [nsxt_policy_service.rodc_ports.path]
  }
  rule {
    display_name       = "sc1wnpredc17 to ossec and splunk"
    description        = "Change ref: CHG0151491"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "89"
    source_groups      = [nsxt_policy_group.sc1wnpredc17.path]
    destination_groups = [nsxt_policy_group.ossec_splunk.path]
    services           = [nsxt_policy_service.ossec_splunk_ports.path]
  }
  rule {
    display_name       = "rodc-subnets to sc1wnpredc15-17"
    description        = "Change ref: CHG0151491"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "90"
    source_groups      = [nsxt_policy_group.rodc_subnets.path]
    destination_groups = [nsxt_policy_group.sc1wnpredc15-17.path]
    services           = [nsxt_policy_service.tcp636.path]
  }
  rule {
    display_name       = "rpa to uno pres readonly"
    description        = "Change ref: CHG0151587"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "91"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.uno-present-readonly.path]
    services           = [nsxt_policy_service.tcp1433.path]
  }
  rule {
    display_name       = "access to sc1uxprnap019 sftp server"
    description        = "Change ref: NETACCESS-375"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "92"
    source_groups      = [nsxt_policy_group.emis-servers.path]
    destination_groups = [nsxt_policy_group.sc1uxprnap019.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "access from bomgar to storage nodes"
    description        = "Change ref: CHG0151660"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "93"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.storage_devices_group.path]
    services           = [nsxt_policy_service.storage_ports.path]
  }
  rule {
    display_name       = "access from bomgar to suricata nodes"
    description        = "Change ref: CHG0151854"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "94"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.suricata-ids.path]
    services           = [nsxt_policy_service.scc_jumphost_to_suricata_ids_ports.path]
  }
  rule {
    display_name       = "access from ob to splunk instance"
    description        = "Change ref: CHG0151859"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "95"
    source_groups      = [nsxt_policy_group.ob_live_vpn.path]
    destination_groups = [nsxt_policy_group.sc1uxpremn81.path]
    services           = [nsxt_policy_service.tcp8000.path]
  }
  rule {
    display_name       = "whus vpn to citrix"
    description        = "Change ref: CHG0151892"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "96"
    source_groups      = [nsxt_policy_group.whus-vpn-subnet.path]
    destination_groups = [nsxt_policy_group.whlan-prod.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "rpa access to unity platform"
    description        = "Change ref: CHG0151897"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "97"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.unity-prod.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "aws central ingress access to splunk"
    description        = "Change ref: CHG0151941"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "98"
    source_groups      = [nsxt_policy_group.aws_central_ingress.path]
    destination_groups = [nsxt_policy_group.scc_splunk.path]
    services           = [nsxt_policy_service.tcp514.path]
  }
  rule {
    display_name       = "scc_bomgar_to_aws_central_ingress"
    description        = "Change ref: CHG0151929"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "99"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.aws_central_ingress.path]
    services           = [nsxt_policy_service.tcp_8443_tcp_443_tcp_22.path]
  }
  rule {
    display_name       = "user access to epos datastore server"
    description        = "Change ref: RITM0156908"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "100"
    source_groups      = [nsxt_policy_group.epos_datastore_user_access.path]
    destination_groups = [nsxt_policy_group.epos_datastore_server.path]
    services           = [nsxt_policy_service.tcp1521.path]
  }
  rule {
    display_name       = "ns1 load balancer probe"
    description        = "Change ref: CHG0152079"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "101"
    source_groups      = [nsxt_policy_group.rodc_subnets.path]
    destination_groups = [nsxt_policy_group.irewnprejamf01-02.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "ad sccm to anyconnect ports"
    description        = "Change ref: CHG0152108"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "102"
    source_groups      = [nsxt_policy_group.ad_sccm_poc.path]
    destination_groups = [nsxt_policy_group.ac_vpn_ranges.path]
    services           = [nsxt_policy_service.ad_sccm_to_anyconnect_ports.path]
  }
  rule {
    display_name       = "jira rodc ext"
    description        = "Change ref: CHG0151491"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "103"
    source_groups      = [nsxt_policy_group.service_now_grp.path, nsxt_policy_group.crowd_platform_grp.path, nsxt_policy_group.wg-wrproxy-usa.path]
    destination_groups = [nsxt_policy_group.sc1wnpredc17.path]
    services           = [nsxt_policy_service.tcp636.path]
  }
  rule {
    display_name       = "jamf cloud to adscs"
    description        = "Change ref: CHG0152079"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "104"
    source_groups      = [nsxt_policy_group.jamf_cloud.path]
    destination_groups = [nsxt_policy_group.irewnprejamf01-02.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "bomgar cde to rundeck db"
    description        = "Change ref: CHG0152247"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "105"
    source_groups      = [nsxt_policy_group.bomgar_hosts.path]
    destination_groups = [nsxt_policy_group.rundeck_db.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "citrix vda to accurate citrix"
    description        = "Change ref: CHANGE-2801"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "106"
    source_groups      = [nsxt_policy_group.sc1wnprefs04.path]
    destination_groups = [nsxt_policy_group.scc_accurate_citrix.path]
    services           = [nsxt_policy_service.citrix_vda.path]
  }
  rule {
    display_name       = "test sailpoint va to ad iq"
    description        = "Change ref: NETAR-197"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "107"
    source_groups      = [nsxt_policy_group.sailpoint_test_vas.path]
    destination_groups = [nsxt_policy_group.testad_iq.path]
    services           = [nsxt_policy_service.ad_iq_ports.path]
  }
  rule {
    display_name       = "uno jumpbox to uno read only db"
    description        = "Change ref: NETAR-200"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "108"
    source_groups      = [nsxt_policy_group.sc1wnprnmg020.path]
    destination_groups = [nsxt_policy_group.uno-present-readonly.path]
    services           = [nsxt_policy_service.uno_sandbox_ports.path]
  }
  rule {
    display_name       = "test sailpoint va to ad test"
    description        = "Change ref: NETAR-229"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "109"
    source_groups      = [nsxt_policy_group.sailpoint_test_vas.path]
    destination_groups = [nsxt_policy_group.testad_iq.path]
    services           = [nsxt_policy_service.ad_test_ports.path]
  }
  rule {
    display_name       = "test sailpoint va to ad test gc port"
    description        = "Change ref: NETAR-243"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "110"
    source_groups      = [nsxt_policy_group.sailpoint_test_vas.path]
    destination_groups = [nsxt_policy_group.ad_autopilot_poc.path]
    services           = [nsxt_policy_service.tcp3268.path, nsxt_policy_service.ad_test_ports.path]
  }
  rule {
    display_name       = "rpa prod robots to tableau mrg"
    description        = "Change ref: NETAR-260"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "111"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.tableau_mrgreen_zone.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "aws eks gateway to mars"
    description        = "Change ref: NETAR-352"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "112"
    source_groups      = [nsxt_policy_group.aws_sports_whapi.path]
    destination_groups = [nsxt_policy_group.mars-backofficeadmin.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "uno jump host to presentation layer"
    description        = "Change ref: NETAR-299"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "113"
    source_groups      = [nsxt_policy_group.uno-remote-access.path]
    destination_groups = [nsxt_policy_group.whdppresent02.path]
    services           = [nsxt_policy_service.tcp23000.path]
  }
  rule {
    display_name       = "uno jump host to presentation layer RO"
    description        = "Change ref: NETAR-401"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "114"
    source_groups      = [nsxt_policy_group.uno-remote-access.path]
    destination_groups = [nsxt_policy_group.uno_readonly_db.path]
    services           = [nsxt_policy_service.tcp30000.path]
  }
  rule {
    display_name       = "Darshaan to int-lb-oxi-proxy"
    description        = "Change ref: NETAR-466"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "115"
    source_groups      = [nsxt_policy_group.trs_servers.path]
    destination_groups = [nsxt_policy_group.int-lb-oxi-proxy.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "SC1 Jump Host to TPAM"
    description        = "Change ref: NETAR-270"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "116"
    source_groups      = [nsxt_policy_group.sc1_cde_linux_jump.path]
    destination_groups = [nsxt_policy_group.scc_tpam.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "RPA Robots to Evoke Reporting"
    description        = "Change ref: NETAR-579"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "117"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.evoke_report_services.path]
    services           = [nsxt_policy_service.tcp-http-https.path]
  }
  rule {
    display_name       = "Trading Reports Server to then Retail MI database via 1521"
    description        = "Change ref: NETAR-670"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "118"
    source_groups      = [nsxt_policy_group.trading_reports_server.path]
    destination_groups = [nsxt_policy_group.emis-servers.path]
    services           = [nsxt_policy_service.tcp1521.path]
  }
  rule {
    display_name       = "Citrix subnets to DFS root namespace servers via 445"
    description        = "Change ref: NETAR-797"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "119"
    source_groups      = [nsxt_policy_group.citrix.path]
    destination_groups = [nsxt_policy_group.dfs_root_namespace_servers.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "Inter DC Communication between Malta and SCC/LD6"
    description        = "Change ref: NETAR-909"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "120"
    source_groups      = [nsxt_policy_group.ld6-scc-dcs.path]
    destination_groups = [nsxt_policy_group.malta-sliema-dc-access.path]
    services           = [nsxt_policy_service.rodc_ports.path]
  }
  rule {
    display_name       = "Inter DC Communication between Malta and SCC/LD6"
    description        = "Change ref: NETAR-909"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "121"
    source_groups      = [nsxt_policy_group.ld6-scc-dcs.path]
    destination_groups = [nsxt_policy_group.malta-sliema-dc-access.path]
    services           = [nsxt_policy_service.tcp139.path]
  }
  rule {
    display_name       = "RPA Robots Subnet to Gib Fileshare"
    description        = "Change ref: NETAR-1052"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "122"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.gibwnprefs01.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "AWS Central Prod to Aspect"
    description        = "Change ref: NETAR-1082"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "123"
    source_groups      = [nsxt_policy_group.aws_central_prod.path]
    destination_groups = [nsxt_policy_group.aspect_stunnel.path]
    services           = [nsxt_policy_service.tcp6861.path]
  }
  rule {
    display_name       = "sc1 darktrace to aws darktrace"
    description        = "Change ref: NETAR-1203"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "124"
    source_groups      = [nsxt_policy_group.sc1_darktrace.path]
    destination_groups = [nsxt_policy_group.aws_darktrace_master.path]
    services           = [nsxt_policy_service.tcp8089.path]
  }
  rule {
    display_name       = "aws darktrace to sc1 darktrace"
    description        = "Change ref: NETAR-1203"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "125"
    source_groups      = [nsxt_policy_group.aws_darktrace_master.path]
    destination_groups = [nsxt_policy_group.sc1_darktrace.path]
    services           = [nsxt_policy_service.tcp8089.path]
  }
  rule {
    display_name       = "direct access servers to mrg fileshare"
    description        = "Change ref: NETAR-1211"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "126"
    source_groups      = [nsxt_policy_group.direct_access_servers.path]
    destination_groups = [nsxt_policy_group.mrg-fileshare.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "New WH SAP Router to SAP DC"
    description        = "Change ref: NETAR-1344"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "127"
    source_groups      = [nsxt_policy_group.sc1uxprsap02.path]
    destination_groups = [nsxt_policy_group.sap_datacenter_pri.path, nsxt_policy_group.sap_datacenter_dr.path]
    services           = [nsxt_policy_service.sap_services.path]
  }
  rule {
    display_name       = "SAP DC to new WH SAP Router"
    description        = "Change ref: NETAR-1360"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "128"
    source_groups      = [nsxt_policy_group.sap_datacenter_pri.path, nsxt_policy_group.sap_datacenter_dr.path]
    destination_groups = [nsxt_policy_group.sc1uxprsap02.path]
    services           = [nsxt_policy_service.sap_services.path]
  }
  rule {
    display_name       = "New WH SAP Router to SAP Frankfurt DC"
    description        = "Change ref: NETAR-1369"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "129"
    source_groups      = [nsxt_policy_group.sc1uxprsap02.path]
    destination_groups = [nsxt_policy_group.sap_datacenter_frankfurt.path]
    services           = [nsxt_policy_service.sap_services.path]
  }
  rule {
    display_name       = "SAP Frankfurt DC to new WH SAP Router"
    description        = "Change ref: NETAR-1369"
    action             = "ALLOW"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "130"
    source_groups      = [nsxt_policy_group.sap_datacenter_frankfurt.path]
    destination_groups = [nsxt_policy_group.sc1uxprsap02.path]
    services           = [nsxt_policy_service.sap_services.path]
  }
  rule {
    display_name       = "UI Path Robots to Central Product AWS"
    description        = "Change ref: NETAR-1338"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "131"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.aws_central_prod.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "commvault_scc_to_aws_dev_commvault"
    description        = "Change ref: NETAR-1786"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "132"
    source_groups      = [nsxt_policy_group.comm_vault_servers_scc.path]
    destination_groups = [nsxt_policy_group.aws-tss-vpc-dev.path]
    services           = [nsxt_policy_service.commvault_proxy_services.path]
  }
  rule {
    display_name       = "aws_dev_commvault_to_commvault_scc"
    description        = "Change ref: NETAR-1786"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "133"
    source_groups      = [nsxt_policy_group.aws-tss-vpc-dev.path]
    destination_groups = [nsxt_policy_group.comm_vault_servers_scc.path]
    services           = [nsxt_policy_service.commvault_proxy_services.path]
  }
  rule {
    display_name       = "Manila ISP to Citrix"
    description        = "Change ref: NETAR-1847"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "134"
    source_groups      = [nsxt_policy_group.manila-isp.path]
    destination_groups = [nsxt_policy_group.groupras-williamhill-plc-uk.path]
    services           = [nsxt_policy_service.groupras_ports.path]
  }
  rule {
    display_name       = "Hatfield SCCM DP to SCC SCCM"
    description        = "Change ref: NETAR-2035"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "135"
    source_groups      = [nsxt_policy_group.hatwnprecp001.path]
    destination_groups = [nsxt_policy_group.sc1wnprwsus01.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "Hatfield SCCM DP to SCC Splunk"
    description        = "Change ref: NETAR-2035"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "136"
    source_groups      = [nsxt_policy_group.hatwnprecp001.path]
    destination_groups = [nsxt_policy_group.ossec_splunk.path]
    services           = [nsxt_policy_service.ossec_splunk_ports.path]
  }
  rule {
    display_name       = "Ceuta SCCM DP to SCC SCCM"
    description        = "Change ref: NETAR-2972"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "137"
    source_groups      = [nsxt_policy_group.cdgwnprecp001.path]
    destination_groups = [nsxt_policy_group.sc1wnprwsus01.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "Ceuta SCCM DP to SCC Splunk"
    description        = "Change ref: NETAR-2972"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "138"
    source_groups      = [nsxt_policy_group.cdgwnprecp001.path]
    destination_groups = [nsxt_policy_group.ossec_splunk.path]
    services           = [nsxt_policy_service.ossec_splunk_ports.path]
  }
  rule {
    display_name       = "DM AWS to TRS"
    description        = "Change ref: NETAR-2144"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "139"
    source_groups      = [nsxt_policy_group.aws_data_prod.path]
    destination_groups = [nsxt_policy_group.trs_mysql.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "RPA Robots to Sofia FS"
    description        = "Change ref: NETAR-2150"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "140"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.sofia_fileserver.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "RPA Robots to MRG Featurespace"
    description        = "Change ref: NETAR-2216"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "141"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.mrg_featurespace.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "SCC WSUS to ILOs"
    description        = "Change ref: NETAR-2231"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "142"
    source_groups      = [nsxt_policy_group.sc1wnprwsus01.path]
    destination_groups = [nsxt_policy_group.scc_ilo_network.path, nsxt_policy_group.gib_ilo_network.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "sailpoint vas to idam ftp server"
    description        = "Change ref: NETAR-2303"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "143"
    source_groups      = [nsxt_policy_group.sailpoint_vas.path]
    destination_groups = [nsxt_policy_group.irewnpreftp01-ftp.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "sailpoint and 888 to irewnpreftp01"
    description        = "Change ref: NETAR-2260"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "144"
    source_groups      = [nsxt_policy_group.dc_888_ips.path, nsxt_policy_group.sailpoint_iq_servers.path]
    destination_groups = [nsxt_policy_group.irewnpreftp01.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "Commvault Commcell to WHC-PP vCenter"
    description        = "Change ref: NETAR-2331"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "145"
    source_groups      = [nsxt_policy_group.grp_commvault.path]
    destination_groups = [nsxt_policy_group.ireuxppbkvsa01-02.path]
    services           = [nsxt_policy_service.commvault_proxy_services.path]
  }
  rule {
    display_name       = "WHC-PP vCenter to Commvault Commcell"
    description        = "Change ref: NETAR-2331"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "146"
    source_groups      = [nsxt_policy_group.ireuxppbkvsa01-02.path]
    destination_groups = [nsxt_policy_group.grp_commvault.path]
    services           = [nsxt_policy_service.commvault_proxy_services.path]
  }
  rule {
    display_name       = "robots to test TNA server"
    description        = "Change ref: NETAR-2319"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "147"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.brswntstdb01.path]
    services           = [nsxt_policy_service.tcp1433.path]
  }
  rule {
    display_name       = "sc1wnprwsus01 to Internet"
    description        = "Change ref: NETAR-2403"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "148"
    source_groups      = [nsxt_policy_group.sc1wnprwsus01.path]
    destination_groups = [nsxt_policy_group.internet_minus_rfc1918.path]
    services           = [nsxt_policy_service.tcp-http-https.path]
  }
  rule {
    display_name       = "oneview appliances to oneview global dashboard"
    description        = "Change ref: NETAR-2487"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "149"
    source_groups      = [nsxt_policy_group.oneview_appliances.path]
    destination_groups = [nsxt_policy_group.sc1uxpremg27.path]
    services           = [nsxt_policy_service.tcp_5671.path]
  }
  rule {
    display_name       = "oneview appliances from oneview global dashboard"
    description        = "Change ref: NETAR-2487"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "150"
    source_groups      = [nsxt_policy_group.sc1uxpremg27.path]
    destination_groups = [nsxt_policy_group.oneview_appliances.path]
    services           = [nsxt_policy_service.tcp_5671.path]
  }
  rule {
    display_name       = "sailpoint to sailpoint ssh tunnels"
    description        = "Change ref: NETAR-2571"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "151"
    source_groups      = [nsxt_policy_group.sailpoint_test_vas.path]
    destination_groups = [nsxt_policy_group.sailpoint_ssh_tunnel_ips.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "bomgar to cde monitoring nets"
    description        = "Change ref: NETAR-2692"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "152"
    source_groups      = [nsxt_policy_group.bomgar_hosts.path]
    destination_groups = [nsxt_policy_group.cde_monitoring_nets.path]
    services           = [nsxt_policy_service.tcp3389.path]
  }
  rule {
    display_name       = "euc management server to idam ftp"
    description        = "Change ref: NETAR-2494"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "153"
    source_groups      = [nsxt_policy_group.brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.irewnpreftp01-ftp.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "retail workstation to sc1wnprnap002"
    description        = "Change ref: NETAR-2723"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "154"
    source_groups      = [nsxt_policy_group.retail_dev_vmc_workstation.path]
    destination_groups = [nsxt_policy_group.sc1wnprnap002.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "retail workstation to sc1wnprefs03"
    description        = "Change ref: NETAR-2734"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "155"
    source_groups      = [nsxt_policy_group.retail_dev_vmc_workstation.path]
    destination_groups = [nsxt_policy_group.sc1wnprefs03.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "log insights access to splunk"
    description        = "Change ref: NETAR-2697"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "156"
    source_groups      = [nsxt_policy_group.sc1prapli01.path]
    destination_groups = [nsxt_policy_group.int-pres-clp-sc1.path]
    services           = [nsxt_policy_service.tcp514.path]
  }
  rule {
    display_name       = "Oneview MRG to Global Dashboard"
    description        = "Change ref: NETAR-2691"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "157"
    source_groups      = [nsxt_policy_group.slmprmrgov01.path]
    destination_groups = [nsxt_policy_group.sc1uxpremg27.path]
    services           = [nsxt_policy_service.oneview_ports.path]
  }
  rule {
    display_name       = "Global Dashboard to MRG Oneview"
    description        = "Change ref: NETAR-2691"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "158"
    source_groups      = [nsxt_policy_group.sc1uxpremg27.path]
    destination_groups = [nsxt_policy_group.slmprmrgov01.path]
    services           = [nsxt_policy_service.oneview_ports.path]
  }
  rule {
    display_name       = "Access to CLP from SC1 Prod Log Insight"
    description        = "Change ref: NETAR-2860"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "159"
    source_groups      = [nsxt_policy_group.sc1prapli01.path]
    destination_groups = [nsxt_policy_group.brsuxpremn004.path]
    services           = [nsxt_policy_service.tcp514.path]
  }
  rule {
    display_name       = "Access to Parkview External from SCC Parkview Servers"
    description        = "Change ref: NETAR-3024"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "160"
    source_groups      = [nsxt_policy_group.parkviewscc.path]
    destination_groups = [nsxt_policy_group.parkviewext.path]
    services           = [nsxt_policy_service.parkview_ports.path]
  }
  rule {
    display_name       = "Bomgar to BRS Citrix"
    description        = "Change ref: NETAR-3035"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "161"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.brs_citrix.path]
    services           = [nsxt_policy_service.tcp3389_udp3389.path]
  }
  rule {
    display_name       = "UI Path to 888"
    description        = "Change ref: NETAR-3001"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "162"
    source_groups      = [nsxt_policy_group.irewnprnrbt024.path]
    destination_groups = [nsxt_policy_group.duuf-ntsadmin-vip.path, nsxt_policy_group.duuc-passivests-vip.path, nsxt_policy_group.duuc-customeradmin-vip.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "UI Path to 888"
    description        = "Change ref: NETAR-3001"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "163"
    source_groups      = [nsxt_policy_group.irewnprnrbt024.path]
    destination_groups = [nsxt_policy_group.duuc-qmanager-vip.path]
    services           = [nsxt_policy_service.tcp-83.path]
  }
  rule {
    display_name       = "888 networks to sc1wnpredc15-17"
    description        = "Change ref: NETAR-3137"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "164"
    source_groups      = [nsxt_policy_group.networks_888.path]
    destination_groups = [nsxt_policy_group.sc1wnpredc15-17.path]
    services           = [nsxt_policy_service.ad_ports.path]
  }
  rule {
    display_name       = "sc1wnpredc15-17 to 888 AD"
    description        = "Change ref: NETAR-3137"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "165"
    source_groups      = [nsxt_policy_group.sc1wnpredc15-17.path]
    destination_groups = [nsxt_policy_group.ad-servers-888.path]
    services           = [nsxt_policy_service.ad_ports.path]
  }
  rule {
    display_name       = "ParkviewSCC to iLO Networks"
    description        = "Change ref: NETAR-3313"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "166"
    source_groups      = [nsxt_policy_group.parkviewscc.path]
    destination_groups = [nsxt_policy_group.scc_ilo_network.path]
    services           = [nsxt_policy_service.snmp-traps.path, nsxt_policy_service.snmp.path]
  }
  rule {
    display_name       = "SCC DA to LD6 FS"
    description        = "Change ref: NETAR-3402"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "167"
    source_groups      = [nsxt_policy_group.direct_access_servers.path]
    destination_groups = [nsxt_policy_group.ld6_fileservers.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "Propman Server Rules DR to Prod"
    description        = "Change ref: NETAR-3366"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "168"
    source_groups      = [nsxt_policy_group.brswndredb04.path]
    destination_groups = [nsxt_policy_group.irewnpredb04.path]
    services           = [nsxt_policy_service.accurate_batch_dfs.path]
  }
  rule {
    display_name       = "Propman Server Rules Prod to DR"
    description        = "Change ref: NETAR-3366"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "169"
    source_groups      = [nsxt_policy_group.irewnpredb04.path]
    destination_groups = [nsxt_policy_group.brswndredb04.path]
    services           = [nsxt_policy_service.accurate_batch_dfs.path]
  }
  rule {
    display_name       = "Open SMB access to TNA Servers"
    description        = "Change ref: NETAR-3469"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "170"
    source_groups      = [nsxt_policy_group.sc1wnprgdb13-14.path]
    destination_groups = [nsxt_policy_group.brs-tna-servers.path]
    services           = [nsxt_policy_service.smb_ports.path]
  }
  rule {
    display_name       = "AWS Webproxy to Epos servers"
    description        = "Change ref: NETAR-3398"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "171"
    source_groups      = [nsxt_policy_group.aws_webproxy.path]
    destination_groups = [nsxt_policy_group.sc1uxprnap019.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "888 to sc1 citrix"
    description        = "Change ref: NETAR-3525"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "172"
    source_groups      = [nsxt_policy_group.networks_888.path]
    destination_groups = [nsxt_policy_group.citrix_corp_tech.path]
    services           = [nsxt_policy_service.groupras_ports.path]
  }
  rule {
    display_name       = "RPA Robots to LD6 FS03"
    description        = "Change ref: NETAR-3552"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "173"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.ld6_fileservers.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "VMC Citrix to Propman"
    description        = "Change ref: NETAR-3366"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "174"
    source_groups      = [nsxt_policy_group.scc_citrix.path]
    destination_groups = [nsxt_policy_group.irewnpredb04.path]
    services           = [nsxt_policy_service.propman_ports.path]
  }
  rule {
    display_name       = "RPA Robots TNA DB"
    description        = "Change ref: NETAR-3592"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "175"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.sc1wnprgdb13-14.path]
    services           = [nsxt_policy_service.tcp1433.path]
  }
  rule {
    display_name       = "solarwinds to smtp"
    description        = "Change ref: NETAR-3607"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "176"
    source_groups      = [nsxt_policy_group.solarwinds_primary_poller.path]
    destination_groups = [nsxt_policy_group.scc_smtp.path]
    services           = [nsxt_policy_service.smtp_port.path]
  }
  rule {
    display_name       = "solarwinds to network devices"
    description        = "Change ref: NETAR-3607"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "177"
    source_groups      = [nsxt_policy_group.solarwinds_pollers.path]
    destination_groups = [nsxt_policy_group.solarwinds_dsts.path]
    services           = [nsxt_policy_service.to_solarwinds_dsts.path]
  }
  rule {
    display_name       = "Propman to DFS root hosts"
    description        = "Change ref: NETAR-3478"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "178"
    source_groups      = [nsxt_policy_group.irewnpredb04.path, nsxt_policy_group.brswndredb04.path]
    destination_groups = [nsxt_policy_group.dfs_root_namespace_servers.path]
    services           = [nsxt_policy_service.dfs_root_hosts_services.path]
  }
  rule {
    display_name       = "Trading EKS to TRS"
    description        = "Change ref: NETAR-3607"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "179"
    source_groups      = [nsxt_policy_group.trading_aws_subnets.path]
    destination_groups = [nsxt_policy_group.trs_servers.path]
    services           = [nsxt_policy_service.tcp8081.path]
  }
  rule {
    display_name       = "solarwinds dsts to pollers"
    description        = "Change ref: NETAR-3607"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "180"
    source_groups      = [nsxt_policy_group.solarwinds_dsts.path]
    destination_groups = [nsxt_policy_group.solarwinds_pollers.path]
    services           = [nsxt_policy_service.snmp.path]
  }
  rule {
    display_name       = "solarwinds primary to network devices"
    description        = "Change ref: NETAR-3607"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "181"
    source_groups      = [nsxt_policy_group.solarwinds_primary_poller.path]
    destination_groups = [nsxt_policy_group.solarwinds_dsts.path]
    services           = [nsxt_policy_service.tcp22.path, nsxt_policy_service.tcp43.path]
  }
  rule {
    display_name       = "ld6 powerbi to trs"
    description        = "Change ref: NETAR-3725"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "182"
    source_groups      = [nsxt_policy_group.ld6_powerbi.path]
    destination_groups = [nsxt_policy_group.trs_mysql.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "spotlight server to solarwinds db"
    description        = "Change ref: NETAR-3739"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "183"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.solarwinds_db.path]
    services           = [nsxt_policy_service.retail_db_ports.path]
  }
  rule {
    display_name       = "Manila ESXi to SCC Log Insight"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "184"
    source_groups      = [nsxt_policy_group.manila_esxi_hosts.path]
    destination_groups = [nsxt_policy_group.sc1prapli01.path]
    services           = [nsxt_policy_service.tcp514.path, nsxt_policy_service.udp1514.path]
  }
  rule {
    display_name       = "Manila ESXi to SCC vCenter"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "185"
    source_groups      = [nsxt_policy_group.manila_esxi_hosts.path]
    destination_groups = [nsxt_policy_group.sc1-vcenter.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "Jumpboxes to Manila ESXi"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "186"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.manila_esxi_hosts.path]
    services           = [nsxt_policy_service.manila_bomgar_ports.path]
  }
  rule {
    display_name       = "SCC OneView to Manila ESXi"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "187"
    source_groups      = [nsxt_policy_group.sc1uxpremg26.path]
    destination_groups = [nsxt_policy_group.manila_esxi_hosts.path]
    services           = [nsxt_policy_service.manila_oneview_ports.path]
  }
  rule {
    display_name       = "Manila ESXi to SCC OneView"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "188"
    source_groups      = [nsxt_policy_group.sc1uxpremg26.path]
    destination_groups = [nsxt_policy_group.manila_esxi_hosts.path]
    services           = [nsxt_policy_service.oneview_ports_manila.path]
  }
  rule {
    display_name       = "Manila VR Appliance"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "189"
    source_groups      = [nsxt_policy_group.mnlprapvr01.path]
    destination_groups = [nsxt_policy_group.sc1-vcenter.path]
    services           = [nsxt_policy_service.vr_appliance_ports.path]
  }
  rule {
    display_name       = "Manila VR Appliance to ESXi Hosts"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "190"
    source_groups      = [nsxt_policy_group.mnlprapvr01.path]
    destination_groups = [nsxt_policy_group.manila_esxi_hosts.path]
    services           = [nsxt_policy_service.vr_appliance_vcenter.path]
  }
  rule {
    display_name       = "Manila ESXi to vSAN Witness"
    description        = "Change ref: NETAR-3806"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "191"
    source_groups      = [nsxt_policy_group.manila_esxi_hosts.path, nsxt_policy_group.manila_esxi_host.path]
    destination_groups = [nsxt_policy_group.vsan_witness.path]
    services           = [nsxt_policy_service.vsan_witness_ports.path]
  }
  rule {
    display_name       = "Bomgar to SCC Hosts"
    description        = "Change ref: NETAR-3782"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "192"
    source_groups      = [nsxt_policy_group.scc_jumpboxes.path]
    destination_groups = [nsxt_policy_group.scc_120.path]
    services           = [nsxt_policy_service.ssh_rdp.path]
  }
  rule {
    display_name       = "all servers to splunk aws"
    description        = "Change ref: NETAR-3885"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "193"
    source_groups      = [nsxt_policy_group.net_10_0_0_0s8.path]
    destination_groups = [nsxt_policy_group.splunk_aws.path]
    services           = [nsxt_policy_service.splunk_ports.path]
  }
  rule {
    display_name       = "rpa_robots to mi db"
    description        = "Change ref: NETAR-3969"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "194"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.mi_db.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "888 to testad"
    description        = "Change ref: NETAR-3952"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "195"
    source_groups      = [nsxt_policy_group.networks_888.path]
    destination_groups = [nsxt_policy_group.testad.path]
    services           = [nsxt_policy_service.tcp-https.path, nsxt_policy_service.tcp3389.path, nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "888 to sc1 bomgar"
    description        = "Change ref: NETAR-3952"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "196"
    source_groups      = [nsxt_policy_group.networks_888.path]
    destination_groups = [nsxt_policy_group.sc1jump1.path]
    services           = [nsxt_policy_service.tcp-https.path, nsxt_policy_service.tcp3389.path]
  }
  rule {
    display_name       = "Spotlight to Duo"
    description        = "Change ref: NETAR-3922"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "197"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.wh-data-duo-prod-sql2019-ec2.path]
    services           = [nsxt_policy_service.retail_db_ports.path]
  }
  rule {
    display_name       = "sftp server to retail attendance server"
    description        = "Change ref: NETAR-4187"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "198"
    source_groups      = [nsxt_policy_group.aws_centralised_sftp.path]
    destination_groups = [nsxt_policy_group.sc1wnprgdb13-14.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "888 VPN to IDAM Server"
    description        = "Change ref: NETAR-888"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "199"
    source_groups      = [nsxt_policy_group.ro_vpn_888.path, nsxt_policy_group.ciprian_graure_888.path]
    destination_groups = [nsxt_policy_group.sailpoint_iq_servers.path]
    services           = [nsxt_policy_service.smb_ports.path, nsxt_policy_service.tcp3389.path]
  }
  rule {
    display_name       = "PTE DBs to Patch reporting server"
    description        = "Change ref: NETAR-4497"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "200"
    source_groups      = [nsxt_policy_group.pte_db_tier.path]
    destination_groups = [nsxt_policy_group.sc1uxpremg30.path]
    services           = [nsxt_policy_service.tcp_60606.path]
  }
  rule {
    display_name       = "Deny NCDE to CDE Jumphosts"
    description        = "Change ref: NETAR-4497"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "201"
    source_groups      = [nsxt_policy_group.ncde_jumphosts.path]
    destination_groups = [nsxt_policy_group.ncde_jumphosts.path]
    services           = [nsxt_policy_service.ssh_rdp.path]
  }
  rule {
    display_name       = "888 DFS roots"
    description        = "Change ref: 888-321673"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "202"
    source_groups      = [nsxt_policy_group.networks_888.path]
    destination_groups = [nsxt_policy_group.dfs_root_namespace_servers.path, nsxt_policy_group.sc1wnpreap10-new.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "bomgar to nessus"
    description        = "Change ref: NETAR-4737"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "203"
    source_groups      = [nsxt_policy_group.bomgar_hosts.path]
    destination_groups = [nsxt_policy_group.nessus_servers.path]
    services           = [nsxt_policy_service.ssh_rdp.path]
  }
  rule {
    display_name       = "LD6 direct access servers"
    description        = "Change ref: NETAR-4794, NETAR-4899"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "204"
    source_groups      = [nsxt_policy_group.direct_access_servers.path]
    destination_groups = [nsxt_policy_group.ld6wnprecp001.path]
    services           = [nsxt_policy_service.da_ports.path]
  }
  rule {
    display_name       = "RPA Robot access to prod splunk UI"
    description        = "Change ref: NETAR-4814"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "205"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.splunk_aws_prod.path]
    services           = [nsxt_policy_service.tcp-http-https.path]
  }
  rule {
    display_name       = "RPA Robot access to AWS Data Prod"
    description        = "Change ref: NETAR-5072"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "206"
    source_groups      = [nsxt_policy_group.uipath_robot_servers.path]
    destination_groups = [nsxt_policy_group.aws_data_prod.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "Monitoring of ld6wnpredb02"
    description        = "Change ref: NETAR-5144"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "207"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.ld6wnpredb02.path]
    services           = [nsxt_policy_service.retail_db_ports.path]
  }
  rule {
    display_name       = "Syslog between Commvault & Splunk"
    description        = "Change ref: NETAR-5220"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "208"
    source_groups      = [nsxt_policy_group.sc1wnprbkcs01.path]
    destination_groups = [nsxt_policy_group.scc_splunk.path]
    services           = [nsxt_policy_service.syslog-ports.path]
  }
  rule {
    display_name       = "sofia hr share migration"
    description        = "Change ref: NETAR-5282"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "209"
    source_groups      = [nsxt_policy_group.sofwnprefs02.path]
    destination_groups = [nsxt_policy_group.sc1uxprein14.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "wh iam to sailpoint"
    description        = "Change ref: NETAR-5227"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "210"
    source_groups      = [nsxt_policy_group.wh_iam.path]
    destination_groups = [nsxt_policy_group.sailpoint_iq_servers.path]
    services           = [nsxt_policy_service.tcp445.path, nsxt_policy_service.tcp3389.path]
  }
  rule {
    display_name       = "db monitoring for ld6wndvdb02"
    description        = "Change ref: NETAR-5310"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "211"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.ld6wndvdb02.path]
    services           = [nsxt_policy_service.retail_db_ports.path]
  }
  rule {
    display_name       = "ro build vlan to sccm"
    description        = "Change ref: NETAR-5246"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "212"
    source_groups      = [nsxt_policy_group.ro_build_network.path]
    destination_groups = [nsxt_policy_group.sc1wnprwsus01.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "iam jump server to sailpoint sftp"
    description        = "Change ref: NETAR-5341"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "213"
    source_groups      = [nsxt_policy_group.iam-new-jump-server.path]
    destination_groups = [nsxt_policy_group.sailpoint-sftp.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "iam jump server to cluster vas"
    description        = "Change ref: NETAR-5341"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "214"
    source_groups      = [nsxt_policy_group.iam-new-jump-server.path]
    destination_groups = [nsxt_policy_group.cluster-vas.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "iam jump server to iams prod and pre-prod"
    description        = "Change ref: NETAR-5341"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "215"
    source_groups      = [nsxt_policy_group.iam-new-jump-server.path]
    destination_groups = [nsxt_policy_group.iam-prod-preprod.path]
    services           = [nsxt_policy_service.iam-ports.path]
  }
  rule {
    display_name       = "aws sftp to idam sftp server"
    description        = "Change ref: NETAR-5466"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "216"
    source_groups      = [nsxt_policy_group.aws_centralised_sftp.path]
    destination_groups = [nsxt_policy_group.sc1uxprein14.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "RPA Machine to Spectate URL"
    description        = "Change ref: NETAR-5532"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "217"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.cms_spectate.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "one view to sftp sc1uxprnap70"
    description        = "Change ref: NETAR-5532"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "218"
    source_groups      = [nsxt_policy_group.hpe_synergy_oneview.path]
    destination_groups = [nsxt_policy_group.sftp_sc1uxprnap70.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "scc smtp to aws splunk"
    description        = "Change ref: NETAR-5751"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "219"
    source_groups      = [nsxt_policy_group.scc_smtp.path]
    destination_groups = [nsxt_policy_group.splunk_aws_prod.path]
    services           = [nsxt_policy_service.syslog-ports.path]
  }
  rule {
    display_name       = "scc netscalers to aws splunk"
    description        = "Change ref: NETAR-5751"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "220"
    source_groups      = [nsxt_policy_group.scc_netscalers.path]
    destination_groups = [nsxt_policy_group.splunk_aws_prod.path]
    services           = [nsxt_policy_service.syslog-ports.path]
  }
  rule {
    display_name       = "iam jump server to sftp irewnpreftp01"
    description        = "Change ref: NETAR-5787"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "221"
    source_groups      = [nsxt_policy_group.iam-new-jump-server.path]
    destination_groups = [nsxt_policy_group.irewnpreftp01-ftp.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "Kiafka-racebook-access"
    description        = "Change ref: NETAR-5796"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "222"
    source_groups      = [nsxt_policy_group.grp-net-kafka-racebook-addrs-src.path]
    destination_groups = [nsxt_policy_group.grp-net-kafka-racebook-addrs-dest.path]
    services           = [nsxt_policy_service.tcp_9196.path]
  }
  rule {
    display_name       = "iam jump server to corp sftp server"
    description        = "Change ref: NETAR-5787"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "223"
    source_groups      = [nsxt_policy_group.iam-new-jump-server.path]
    destination_groups = [nsxt_policy_group.irewnpreftp01-ftp.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "euc management server to additional networks"
    description        = "Change ref: NETAR-6045"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "224"
    source_groups      = [nsxt_policy_group.brsapprcmg002.path, nsxt_policy_group.sc1uxpremg32.path]
    destination_groups = [nsxt_policy_group.corp-engineering-servers.path]
    services           = [nsxt_policy_service.corp-engineering-server-ports.path]
  }
  rule {
    display_name       = "crucial comp to rpa robots"
    description        = "Change ref: NETAR-6032"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "225"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.grp-net-crucial_comp.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "semperis dsp to non-vmc ad dsp agents"
    description        = "Change ref: NETAR-6071"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "226"
    source_groups      = [nsxt_policy_group.semperis-dsp-mgmt-svr.path]
    destination_groups = [nsxt_policy_group.non-vmc-ad-dsp-agents.path]
    services           = [nsxt_policy_service.corp-ad-dsp-agent-ports.path]
  }
  rule {
    display_name       = "non-vmc semperis audit agents to semperis dsp mgmt"
    description        = "Change ref: NETAR-6071"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "227"
    source_groups      = [nsxt_policy_group.all-non-vmc-ad-with-semperis.path]
    destination_groups = [nsxt_policy_group.semperis-dsp-mgmt-svr.path]
    services           = [nsxt_policy_service.corp-semperis-dsp-mgmt-svr-ports.path]
  }
  rule {
    display_name       = "semperis dsp mgmt to non-vmc pki servers"
    description        = "Change ref: NETAR-6071"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "228"
    source_groups      = [nsxt_policy_group.semperis-dsp-mgmt-svr.path]
    destination_groups = [nsxt_policy_group.non-vmc-pki-svrs.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "semperis adfr svr aws adfr agents"
    description        = "Change ref: NETAR-6071"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "229"
    source_groups      = [nsxt_policy_group.semperis-adfr-svr.path]
    destination_groups = [nsxt_policy_group.aws-ad-adfr-agents.path]
    services           = [nsxt_policy_service.corp-ad-adfr-agent-ports.path]
  }
  rule {
    display_name       = "spotlight server to semperis_dsp_db"
    description        = "Change ref: NETAR-6087"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "230"
    source_groups      = [nsxt_policy_group.sc1wnprcmn250.path]
    destination_groups = [nsxt_policy_group.semperis_dsp_db.path]
    services           = [nsxt_policy_service.retail_db_ports.path]
  }
  rule {
    display_name       = "spotlight server to semperis_dsp_db"
    description        = "Change ref: NETAR-6047"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "231"
    source_groups      = [nsxt_policy_group._10_120_194_128s27_access.path]
    destination_groups = [nsxt_policy_group.corp-engineering-servers.path]
    services           = [nsxt_policy_service.corp_engineering_ports.path]
  }
  rule {
    display_name       = "rpa machines access to ssrs"
    description        = "Change ref: NETAR-6123"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "232"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.uno-presentation-ld6.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "888 sailpoint to sailpoint openvpn"
    description        = "Change ref: NETAR-6147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "233"
    source_groups      = [nsxt_policy_group.sailpoint_888.path]
    destination_groups = [nsxt_policy_group.sailpoint_ssh_tunnel_ips.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "888 sailpoint to sailpoint openvpn"
    description        = "Change ref: NETAR-6147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "234"
    source_groups      = [nsxt_policy_group.sailpoint_888.path]
    destination_groups = [nsxt_policy_group.ad-servers-888.path]
    services           = [nsxt_policy_service.ad_888_ports.path]
  }
  rule {
    display_name       = "888 sailpoint to sailpoint openvpn"
    description        = "Change ref: NETAR-6147"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "235"
    source_groups      = [nsxt_policy_group.sailpoint_888.path]
    destination_groups = [nsxt_policy_group.sailpoint_iq_888.path]
    services           = [nsxt_policy_service.ad_iq_ports.path]
  }
  rule {
    display_name       = "ADFR communication"
    description        = "Change ref: NETAR-6191"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "236"
    source_groups      = [nsxt_policy_group.semperis-adfr-svr.path]
    destination_groups = [nsxt_policy_group.irewnpreadfr02.path]
    services           = [nsxt_policy_service.active_directory_ports.path]
  }
  rule {
    display_name       = "ADFR communication"
    description        = "Change ref: NETAR-6191"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "237"
    source_groups      = [nsxt_policy_group.irewnpreadfr02.path]
    destination_groups = [nsxt_policy_group.semperis-adfr-svr.path]
    services           = [nsxt_policy_service.active_directory_ports.path]
  }
  rule {
    display_name       = "Dublin apps access to fortisoar"
    description        = "Change ref: ITSD-33471"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "238"
    source_groups      = [nsxt_policy_group.dublin_published_apps.path]
    destination_groups = [nsxt_policy_group.fortisoar.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "888 infosec access"
    description        = "Change ref: ITSD-34565"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "239"
    source_groups      = [nsxt_policy_group._888_vpns.path, nsxt_policy_group._888_infosec.path]
    destination_groups = [nsxt_policy_group.fortisoar.path, nsxt_policy_group.sc1bigiq01.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "brs etl server to scc sftp server"
    description        = "Change ref: NETAR-6268"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "240"
    source_groups      = [nsxt_policy_group.brswn562.path]
    destination_groups = [nsxt_policy_group.sc1uxprnwb51.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "sc1 ob citrix deny"
    description        = "Change ref: NETAR-6279"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "241"
    source_groups      = [nsxt_policy_group.scc_citrix_ob.path]
    destination_groups = [nsxt_policy_group.sc1wnprefs08.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "sc1 citrix to fileshres"
    description        = "Change ref: NETAR-6279"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "242"
    source_groups      = [nsxt_policy_group.scc_accurate_citrix.path, nsxt_policy_group.scc_citrix.path]
    destination_groups = [nsxt_policy_group.sc1wnprefs08.path]
    services           = [nsxt_policy_service.tcp445.path]
  }
  rule {
    display_name       = "corp servers to splunk"
    description        = "Change ref: NETAR-6284"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "243"
    source_groups      = [nsxt_policy_group.corp-engineering-servers.path]
    destination_groups = [nsxt_policy_group.splunk_aws_prod.path]
    services           = [nsxt_policy_service.tcp514.path]
  }
  rule {
    display_name       = "dm aws to retail sftp"
    description        = "Change ref: NETAR-6498"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "244"
    source_groups      = [nsxt_policy_group.datamgmt_aws_non_prod.path]
    destination_groups = [nsxt_policy_group.sc1uxprnap019.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "TRS to new liability viewer"
    description        = "Change ref: NETAR-6518"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "245"
    source_groups      = [nsxt_policy_group.sc1uxprrdb05.path]
    destination_groups = [nsxt_policy_group.ma3uxprdb01.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "TRS to new liability viewer"
    description        = "Change ref: NETAR-6518"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "246"
    source_groups      = [nsxt_policy_group.trs_db.path]
    destination_groups = [nsxt_policy_group.ma3uxprdb01.path]
    services           = [nsxt_policy_service.tcp3306.path]
  }
  rule {
    display_name       = "MA3 oneview backups"
    description        = "Change ref: NETAR-6634"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "247"
    source_groups      = [nsxt_policy_group.ma3le1cmp.path]
    destination_groups = [nsxt_policy_group.sftp_sc1uxprnap70.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "RPA to Splunk"
    description        = "Change ref: NETAR-6671"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "248"
    source_groups      = [nsxt_policy_group.uipath_robot_server_subnet.path]
    destination_groups = [nsxt_policy_group.splunk_aws_prod.path]
    services           = [nsxt_policy_service.rpa-splunk-port.path]
  }
  rule {
    display_name       = "888 infoblox/rundeck access"
    description        = "Change ref: ITSD-49490"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "249"
    source_groups      = [nsxt_policy_group.gib-888.path]
    destination_groups = [nsxt_policy_group.infoblox-login.path, nsxt_policy_group.rundeck-login.path]
    services           = [nsxt_policy_service.tcp-https.path, nsxt_policy_service.tcp-4443.path]
  }
  rule {
    display_name       = "wh test ad to evoke test ad"
    description        = "Change ref: NETAR-6685"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "250"
    source_groups      = [nsxt_policy_group.wh-test-ad.path]
    destination_groups = [nsxt_policy_group.evoke-test-ad.path]
    services           = [nsxt_policy_service.active_directory_ports.path]
  }
  rule {
    display_name       = "evoke test ad to wh test ad"
    description        = "Change ref: NETAR-6685"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "251"
    source_groups      = [nsxt_policy_group.evoke-test-ad.path]
    destination_groups = [nsxt_policy_group.wh-test-ad.path]
    services           = [nsxt_policy_service.active_directory_ports.path]
  }
  rule {
    display_name       = "SQL Spotlight Access"
    description        = "Change ref: ITSD-51970"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "252"
    source_groups      = [nsxt_policy_group.whcsssbt.path]
    destination_groups = [nsxt_policy_group.sc1wnprcmn250.path]
    services           = [nsxt_policy_service.tcp1433.path]
  }
  rule {
    display_name       = "vmconverter to accurate db"
    description        = "Change ref: NETAR-6705"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "253"
    source_groups      = [nsxt_policy_group.sc1wnprcon01.path]
    destination_groups = [nsxt_policy_group.sc1uxprgdb05-new.path, nsxt_policy_group.suricata-ids.path]
    services           = [nsxt_policy_service.tcp-https.path, nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "ma3 vcenter backups"
    description        = "Change ref: NETAR-6693"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "254"
    source_groups      = [nsxt_policy_group.ma3prapvc01.path]
    destination_groups = [nsxt_policy_group.sftp_sc1uxprnap70.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "citrix master to db storage"
    description        = "Change ref: NETAR-6752"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "255"
    source_groups      = [nsxt_policy_group.scc_accurate_citrix.path]
    destination_groups = [nsxt_policy_group.irewnpredb04.path]
    services           = [nsxt_policy_service.accurate_batch_dfs.path]
  }
  rule {
    display_name       = "ire ironport to ld6 ironport"
    description        = "Change ref: NETAR-6767"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "256"
    source_groups      = [nsxt_policy_group.ire-ironport.path]
    destination_groups = [nsxt_policy_group.ld6-ironport.path]
    services           = [nsxt_policy_service.ironport-ports.path]
  }
  rule {
    display_name       = "ld6 ironport to ire ironport"
    description        = "Change ref: NETAR-6767"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "257"
    source_groups      = [nsxt_policy_group.ld6-ironport.path]
    destination_groups = [nsxt_policy_group.ire-ironport.path]
    services           = [nsxt_policy_service.ironport-ports.path]
  }
  rule {
    display_name       = "ironport onprem to ironport cloud"
    description        = "Change ref: NETAR-6767"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "258"
    source_groups      = [nsxt_policy_group.ire-ironport.path]
    destination_groups = [nsxt_policy_group.ironport_cloud.path]
    services           = [nsxt_policy_service.smtp_port.path]
  }
  rule {
    display_name       = "ironport onprem to ironport azure"
    description        = "Change ref: NETAR-6767"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "259"
    source_groups      = [nsxt_policy_group.ire-ironport.path]
    destination_groups = [nsxt_policy_group.azure_mailrelay.path]
    services           = [nsxt_policy_service.tcp514.path]
  }
  rule {
    display_name       = "ironport onprem to ironport azure"
    description        = "Change ref: NETAR-6767"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "260"
    source_groups      = [nsxt_policy_group.ire-ironport.path]
    destination_groups = [nsxt_policy_group.icann.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "unodb servers to whcssbt"
    description        = "Change ref: ITSD-51965"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "261"
    source_groups      = [nsxt_policy_group.ld6_uno_db_servers.path, nsxt_policy_group.ld6_powerbi.path, nsxt_policy_group.ld6wnprejmp04.path, nsxt_policy_group.stjwn561.path, nsxt_policy_group.mi_db.path, nsxt_policy_group.aws-nifi-ranges.path, nsxt_policy_group.brswn561.path]
    destination_groups = [nsxt_policy_group.whcsssbt.path]
    services           = [nsxt_policy_service.tcp1433.path]
  }
  rule {
    display_name       = "corp test servers to ironport"
    description        = "Change ref: NETAR-6563"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "262"
    source_groups      = [nsxt_policy_group.corp_test_servers.path]
    destination_groups = [nsxt_policy_group.ire-ironport.path]
    services           = [nsxt_policy_service.smtp_port.path]
  }
  rule {
    display_name       = "infoblox ironport monitoring"
    description        = "Change ref: NETAR-6563"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "263"
    source_groups      = [nsxt_policy_group.infoblox_grid_ex_scc.path]
    destination_groups = [nsxt_policy_group.ire-ironport.path]
    services           = [nsxt_policy_service.smtp_port.path]
  }
  rule {
    display_name       = "any to ironport"
    description        = "Change ref: NETAR-6929"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "264"
    source_groups      = [nsxt_policy_group.rfc_1918.path, nsxt_policy_group.rfc_6598.path]
    destination_groups = [nsxt_policy_group.ire-ironport.path, nsxt_policy_group.ld6-ironport.path]
    services           = [nsxt_policy_service.smtp_port.path]
  }
  rule {
    display_name       = "wh to evoke ad sync"
    description        = "Change ref: NETAR-6949"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "265"
    source_groups      = [nsxt_policy_group.testad.path]
    destination_groups = [nsxt_policy_group.evoke_test_ad.path]
    services           = [nsxt_policy_service.test_ad_ports.path]
  }
  rule {
    display_name       = "wh to evoke ad sync"
    description        = "Change ref: NETAR-6967"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "266"
    source_groups      = [nsxt_policy_group.evoke_test_ad.path]
    destination_groups = [nsxt_policy_group.testad.path]
    services           = [nsxt_policy_service.active_directory_ports.path]
  }
  rule {
    display_name       = "euc server to citrix brokers"
    description        = "Change ref: NETAR-6922"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "267"
    source_groups      = [nsxt_policy_group.brsapprcmg002.path]
    destination_groups = [nsxt_policy_group.citrix_controllers.path]
    services           = [nsxt_policy_service.dfs_root_hosts_services.path]
  }
  rule {
    display_name       = "citrix controllers to ma3 vcentre"
    description        = "Change ref: NETAR-6997"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "268"
    source_groups      = [nsxt_policy_group.citrix_controllers.path]
    destination_groups = [nsxt_policy_group.ma3prapvc01.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "ironport to splunk"
    description        = "Change ref: NETAR-6994"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "269"
    source_groups      = [nsxt_policy_group.ire-ironport.path]
    destination_groups = [nsxt_policy_group.splunk_aws_prod.path]
    services           = [nsxt_policy_service.tcp514.path]
  }
  rule {
    display_name       = "new relic to ma3 vcenter"
    description        = "Change ref: NETAR-6935"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "270"
    source_groups      = [nsxt_policy_group.sc1uxpremn89.path]
    destination_groups = [nsxt_policy_group.ma3prapvc01.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "scc_ma3_commvault_interconnectivity"
    description        = "Change ref: NETAR-6935"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "271"
    source_groups      = [nsxt_policy_group.sc1_commvault_network.path, nsxt_policy_group.ma3_commvault_network.path]
    destination_groups = [nsxt_policy_group.sc1_commvault_network.path, nsxt_policy_group.ma3_commvault_network.path]
    services           = [nsxt_policy_service.commvault_proxy_services.path]
  }
  rule {
    display_name       = "il infosec to fortisoar"
    description        = "Change ref: ITSD-71301"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "272"
    source_groups      = [nsxt_policy_group.il_infosec_machines.path]
    destination_groups = [nsxt_policy_group.fortisoar.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "ld6 vcenter backups"
    description        = "Change ref: NETAR-7064"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "273"
    source_groups      = [nsxt_policy_group.ld6-synergy-deployment-blade-enc.path]
    destination_groups = [nsxt_policy_group.sftp_sc1uxprnap70.path]
    services           = [nsxt_policy_service.tcp22.path]
  }
  rule {
    display_name       = "iam jump server to vmc scc vcentre"
    description        = "Change ref: NETAR-5838"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "274"
    source_groups      = [nsxt_policy_group.iam-new-jump-server.path]
    destination_groups = [nsxt_policy_group.scc_non_whc_prod_vcentre.path]
    services           = [nsxt_policy_service.tcp-https.path]
  }
  rule {
    display_name       = "testad to windows wsus"
    description        = "Change ref: NETAR-7245"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "275"
    source_groups      = [nsxt_policy_group.testad.path]
    destination_groups = [nsxt_policy_group.ld6wnprwsus02.path]
    services           = [nsxt_policy_service.http-only.path]
  }
  rule {
    display_name       = "trs to kafka topics"
    description        = "Change ref: NETAR-7174"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "276"
    source_groups      = [nsxt_policy_group.trs_servers.path]
    destination_groups = [nsxt_policy_group.kafka_topics_networks.path]
    services           = [nsxt_policy_service.kafka-topics-ports.path]
  }
}
