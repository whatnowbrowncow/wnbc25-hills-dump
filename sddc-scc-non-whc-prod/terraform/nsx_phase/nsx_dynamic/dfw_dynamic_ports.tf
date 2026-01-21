/*========================================

###########################################################################
###########################################################################
###                                                                     ###
###                DYNAMIC PORTS - NOT MIGRATED FROM SCC                ###
###                                                                     ###
###########################################################################
###########################################################################

========================================*/

# resource "nsxt_policy_service" "dynamic_ip-any" {
#   lifecycle {
#     create_before_destroy = true
#   }
#   display_name = "dynamic_ip-any"
#   description  = "description: ip"
#   ether_type_entry {
#     ether_type = "2048"
#   }
# }

resource "nsxt_policy_service" "dynamic_icmp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "dynamic_icmp-any"
  description  = "description: icmp"
  icmp_entry {
    protocol = "ICMPv4"
  }
}

resource "nsxt_policy_service" "dynamic_tcp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "dynamic_tcp-any"
  description  = "description: tcp-any"
  ip_protocol_entry {
    display_name = "tcp"
    protocol     = "6"
  }
}

resource "nsxt_policy_service" "dynamic_udp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "dynamic_udp-any"
  description  = "description: udp-any"
  ip_protocol_entry {
    display_name = "udp"
    protocol     = "17"
  }
}

resource "nsxt_policy_service" "opendns_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "opendns_ports"
  description  = "description: opendns_ports, services: [tcp-udp53, tcp80, tcp123, tcp443, tcp2222]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "80", "123", "443", "2222"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "general_internet_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "general_internet_ports"
  description  = "description: general_internet_ports, services: [tcp80, tcp443, tcp8080, tcp8443, tcp1935, tcp843]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "8080", "8443", "1935", "843"]
  }
}

resource "nsxt_policy_service" "wh_apogee_external_site_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "wh_apogee_external_site_services"
  description  = "description: wh_apogee_external_site_services, services: [tcp2560, tcp7300, tcp7310, tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2560", "7300", "7310", "8443"]
  }
}

resource "nsxt_policy_service" "aws_storage_gatweway_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_storage_gatweway_ports"
  description  = "description: aws_storage_gatweway_ports, services: [udp137, udp138, tcp139, tcp445, tcp-udp635, tcp-udp111, tcp-udp1110, tcp-udp2049, tcp-udp4045, tcp-udp4046, tcp-udp4049]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["139", "445", "635", "111", "1110", "2049", "4045"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4046", "4049"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "138", "635", "111", "1110", "2049", "4045"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["4046", "4049"]
  }
}

resource "nsxt_policy_service" "uno_presentation_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_presentation_ports"
  description  = "description: UNO Presentation SSAS Listeners, services: [tcp1433, tcp2383]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "2383"]
  }
}

resource "nsxt_policy_service" "uno_sandbox_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_sandbox_ports"
  description  = "description: UNO Sandbox SSAS Listeners, services: [tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
}

resource "nsxt_policy_service" "uno_cube_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_cube_ports"
  description  = "description: UNO Sandbox SSAS Listeners, services: [tcp2383]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2383"]
  }
}

resource "nsxt_policy_service" "uno_dpe_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_dpe_ports"
  description  = "description: UNO DPE Services, services: [tcp1433, tcp21000, tcp22000, tcp23000, tcp29000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "21000", "22000", "23000", "29000"]
  }
}

resource "nsxt_policy_service" "uno_jobscheduler" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_jobscheduler"
  description  = "description: CHG0146652, services: [tcp4445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4445"]
  }
}

resource "nsxt_policy_service" "tcp1433_udp_1434" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp1433_udp_1434"
  description  = "description: CHG0146447, services: [tcp1433, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "tcp1433_tcp_1434" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp1433_tcp_1434"
  description  = "description: CHG0146447, services: [tcp1433, tcp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "1434"]
  }
}

resource "nsxt_policy_service" "tcp8088" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp8088"
  description  = "description: CHG0146817, services: [tcp8088]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8088"]
  }
}

resource "nsxt_policy_service" "tcp3389_udp3389" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp3389_udp3389"
  description  = "description: CHG0146931, services: [tcp-udp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "tcp3389" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp3389"
  description  = "description: NETAR-2692, services: [tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "tcp8443" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp8443"
  description  = "description: CHG0146931, services: [tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443"]
  }
}

resource "nsxt_policy_service" "tcp1521" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp1521"
  description  = "description: CHG0146931, services: [tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521"]
  }
}

resource "nsxt_policy_service" "tcp445" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp445"
  description  = "description: CHG0146931, services: [tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445"]
  }
}

resource "nsxt_policy_service" "active_directory_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "active_directory_ports"
  description  = "description: CHG0146931, services: [tcp-udp88, udp123, tcp135, tcp-udp389, tcp445, tcp-udp464, tcp636, tcp3268, tcp3269, tcp9389, tcp-udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["88", "135", "389", "445", "464", "636", "3268"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3269", "9389", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["88", "123", "389", "464", "49152-65535"]
  }
}

resource "nsxt_policy_service" "tcp_udp53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp_udp53"
  description  = "description: CHG0146931, services: [tcp-udp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "accurate_batch_dfs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "accurate_batch_dfs"
  description  = "description: CHG0146931, services: [tcp445, tcp135, tcp5722, tcp3000-5000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "135", "5722", "3000-5000"]
  }
}

resource "nsxt_policy_service" "tcp1433" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp1433"
  description  = "description: CHG0146988, services: [tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
}

resource "nsxt_policy_service" "tcp1576" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp1576"
  description  = "description: CHG0147001, services: [tcp1576]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1576"]
  }
}

resource "nsxt_policy_service" "tcp1522" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp1522"
  description  = "description: CHG0147109, services: [tcp1522]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1522"]
  }
}

resource "nsxt_policy_service" "tcp3129" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp3129"
  description  = "description: CHG0147120, services: [tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3129"]
  }
}

resource "nsxt_policy_service" "commvault_server_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "commvault_server_ports"
  description  = "description: CHG0147150, services: [tcp8400, tcp8401, tcp8402, tcp8403, tcp1433, tcp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403", "1433", "1434"]
  }
}

resource "nsxt_policy_service" "uno_db_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_db_ports"
  description  = "description: CHG0147215, CHG0147209, services: [tcp22000, tcp23000, tcp29000, tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22000", "23000", "29000", "1433"]
  }
}

resource "nsxt_policy_service" "retail_db_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "retail_db_ports"
  description  = "description: CHG0147260, services: [tcp-udp135-139, tcp-udp445, tcp1433, tcp3000-3100, tcp49152-65535, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135-139", "445", "1433", "3000-3100", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["135-139", "445", "1434"]
  }
}

resource "nsxt_policy_service" "ld6_uno_db_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6_uno_db_ports"
  description  = "description: CHG0147260, services: [tcp-udp135-139, tcp-udp445, tcp3000-3100, tcp49152-65535, tcp30000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135-139", "445", "3000-3100", "49152-65535", "30000"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["135-139", "445"]
  }
}

resource "nsxt_policy_service" "tcp-https" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp-https"
  description  = "description: CHG0147284, services: [tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "tcp-http-https" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp-http-https"
  description  = "description: CHG0147311, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "tcp5022" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp5022"
  description  = "description: CHG0147317, services: [tcp5022]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5022"]
  }
}

resource "nsxt_policy_service" "tcp21000" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp21000"
  description  = "description: CHG0147937, services: [tcp21000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21000"]
  }
}

resource "nsxt_policy_service" "tcp30000" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp30000"
  description  = "description: CHG0147317, services: [tcp30000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["30000"]
  }
}

resource "nsxt_policy_service" "tcp23000" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp23000"
  description  = "description: CHG0147559, services: [tcp23000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["23000"]
  }
}

resource "nsxt_policy_service" "tcp22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp22"
  description  = "description: CHG0147891, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

resource "nsxt_policy_service" "tcp3306" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp3306"
  description  = "description: CHG0148257, services: [tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306"]
  }
}

resource "nsxt_policy_service" "scc_jumphost_to_aws_f5s_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_jumphost_to_aws_f5s_ports"
  description  = "description: CHG0148432, services: [tcp22, tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "8443"]
  }
}

resource "nsxt_policy_service" "jde_meridian_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "jde_meridian_ports"
  description  = "description: CHG0148470, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470-8478, tcp9401-9405, tcp9645, tcp443, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2001", "2300", "4402", "446", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470-8478", "9401-9405", "9645", "443", "23"]
  }
}

resource "nsxt_policy_service" "http-only" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "http-only"
  description  = "description: CHG0148928, services: [tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80"]
  }
}

resource "nsxt_policy_service" "snmp-traps" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "snmp-traps"
  description  = "description: CHG0149147, services: [tcp162, udp162]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["162"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["162"]
  }
}

resource "nsxt_policy_service" "tcp29000" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp29000"
  description  = "description: CHG0147981, services: [tcp29000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["29000"]
  }
}

resource "nsxt_policy_service" "tcp8080" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp8080"
  description  = "description: CHG0149094, services: [tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080"]
  }
}

resource "nsxt_policy_service" "tcp21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp21"
  description  = "description: CHG0149277, services: [tcp21]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21"]
  }
}

resource "nsxt_policy_service" "tcp139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp139"
  description  = "description: CHG0149277, services: [tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["139"]
  }
}

resource "nsxt_policy_service" "ping_to_ad_autopilot_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ping_to_ad_autopilot_ports"
  description  = "description: CHG0149589 CHG0149826, services: [tcp-udp53, tcp-udp88, tcp-udp389, tcp636, tcp3268, tcp3269]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "88", "389", "636", "3268", "3269"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "88", "389"]
  }
}

resource "nsxt_policy_service" "commvault_backup_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "commvault_backup_ports"
  description  = "description: CHG0149801, services: [tcp443, tcp902]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "902"]
  }
}

resource "nsxt_policy_service" "tcp_8443_tcp_443" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp_8443_tcp_443"
  description  = "description: CHG0150343, services: [tcp8443, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "443"]
  }
}

resource "nsxt_policy_service" "groupras_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "groupras_ports"
  description  = "description: CHG0125710, services: [tcp443, tcp444]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "444"]
  }
}

resource "nsxt_policy_service" "tcp135" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp135"
  description  = "description: CHG0150752, services: [tcp135]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135"]
  }
}

resource "nsxt_policy_service" "citrix_licensing_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "citrix_licensing_ports"
  description  = "description: CHG0150752, services: [tcp27000, tcp80, tcp7279, tcp8082, tcp8083]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["27000", "80", "7279", "8082", "8083"]
  }
}

resource "nsxt_policy_service" "citrix_to_vda_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "citrix_to_vda_ports"
  description  = "description: CHG0125710, services: [tcp80, tcp89]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "89"]
  }
}

resource "nsxt_policy_service" "udp1514" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "udp1514"
  description  = "description: CHG0150768, services: [udp1514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1514"]
  }
}

resource "nsxt_policy_service" "tcp81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp81"
  description  = "description: CHG0150911, services: [tcp81]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["81"]
  }
}

resource "nsxt_policy_service" "netscaler_snip_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "netscaler_snip_ports"
  description  = "description: CHG0150752, services: [tcp-udp1494, tcp-udp2598]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1494", "2598"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1494", "2598"]
  }
}

resource "nsxt_policy_service" "postgresql" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "postgresql"
  description  = "description: CHG0151090, services: [tcp5432]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5432"]
  }
}

resource "nsxt_policy_service" "tcp1688" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp1688"
  description  = "description: tcp1688, services: [tcp1688]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1688"]
  }
}

resource "nsxt_policy_service" "rodc_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "rodc_ports"
  description  = "description: CHG0151491, services: [tcp-udp123, tcp-udp135, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp49152-65535, tcp-udp88, tcp-udp53, tcp3268-3269, tcp-udp5722, tcp9389, tcp636, udp137-138]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["123", "135", "389", "445", "464", "49152-65535", "88"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "3268-3269", "5722", "9389", "636"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123", "135", "389", "445", "464", "49152-65535", "88"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "5722", "137-138"]
  }
}

resource "nsxt_policy_service" "kms_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "kms_ports"
  description  = "description: kms_ports, services: [tcp1918, tcp-udp135, tcp-udp49152-65535, tcp-udp445, tcp5985, tcp-udp139, tcp1688]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1918", "135", "49152-65535", "445", "5985", "139", "1688"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["135", "49152-65535", "445", "139"]
  }
}

resource "nsxt_policy_service" "ossec_splunk_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ossec_splunk_ports"
  description  = "description: CHG0151491, services: [tcp8089, udp1514, tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089", "9997"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1514"]
  }
}

resource "nsxt_policy_service" "tcp636" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp636"
  description  = "description: tcp636, services: [tcp636]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["636"]
  }
}

resource "nsxt_policy_service" "storage_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "storage_ports"
  description  = "description: CHG0151660, services: [tcp22, tcp443, tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "443", "8080"]
  }
}

resource "nsxt_policy_service" "scc_jumphost_to_suricata_ids_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_jumphost_to_suricata_ids_ports"
  description  = "description: CHG0151854, services: [tcp22, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "443"]
  }
}

resource "nsxt_policy_service" "tcp8000" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp8000"
  description  = "description: tcp8000, services: [tcp8000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8000"]
  }
}

resource "nsxt_policy_service" "tcp514" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp514"
  description  = "description: tcp514, services: [tcp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "tcp_8443_tcp_443_tcp_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp_8443_tcp_443_tcp_22"
  description  = "description: CHG0151929, services: [tcp8443, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "443", "22"]
  }
}

resource "nsxt_policy_service" "ad_sccm_to_anyconnect_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad_sccm_to_anyconnect_ports"
  description  = "description: CHG0152108, services: [tcp-udp80, tcp-udp445, tcp-udp135, tcp3389, tcp8530, tcp8531, tcp1024-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "445", "135", "3389", "8530", "8531", "1024-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["80", "445", "135"]
  }
}

resource "nsxt_policy_service" "citrix_vda" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "citrix_vda"
  description  = "description: CHANGE-2801, services: [tcp135, tcp389, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "389", "3389"]
  }
}

resource "nsxt_policy_service" "ad_iq_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad_iq_ports"
  description  = "description: NETAR-197, services: [tcp5050, tcp5051]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5050", "5051"]
  }
}

resource "nsxt_policy_service" "ad_test_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad_test_ports"
  description  = "description: NETAR-229, services: [tcp389, tcp636]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["389", "636"]
  }
}

resource "nsxt_policy_service" "tcp3268" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp3268"
  description  = "description: tcp3268, services: [tcp3268]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3268"]
  }
}

resource "nsxt_policy_service" "tcp6861" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp6861"
  description  = "description: tcp6861, services: [tcp6861]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["6861"]
  }
}

resource "nsxt_policy_service" "tcp8089" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp8089"
  description  = "description: tcp8089, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "sap_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sap_services"
  description  = "description: NETAR-1344, services: [tcp3200-3399]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3200-3399"]
  }
}

resource "nsxt_policy_service" "commvault_proxy_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "commvault_proxy_services"
  description  = "description: NETAR-1786, services: [tcp8400-8408, tcp10022, tcp902, tcp443, tcp2049, tcp-udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8408", "10022", "902", "443", "2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "smtp_port" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "smtp_port"
  description  = "description: NETAR-2035, services: [tcp25]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["25"]
  }
}

resource "nsxt_policy_service" "tcp_5671" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp_5671"
  description  = "description: NETAR-2487, services: [tcp5671]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671"]
  }
}

resource "nsxt_policy_service" "oneview_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "oneview_ports"
  description  = "description: NETAR-2691, services: [tcp80, tcp443, tcp5671]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "5671"]
  }
}

resource "nsxt_policy_service" "parkview_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "parkview_ports"
  description  = "description: NETAR-3024, services: [tcp3183, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3183", "443"]
  }
}

resource "nsxt_policy_service" "tcp-83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp-83"
  description  = "description: NETAR-3001, services: [tcp83]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["83"]
  }
}

resource "nsxt_policy_service" "ad_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad_ports"
  description  = "description: NETAR-3137, services: [tcp-udp88, udp123, tcp135, tcp-udp389, tcp445, tcp-udp464, tcp-udp49152-65525, tcp636, tcp3268-3269, tcp9389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["88", "135", "389", "445", "464", "49152-65525", "636"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3268-3269", "9389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["88", "123", "389", "464", "49152-65525"]
  }
}

resource "nsxt_policy_service" "snmp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "snmp"
  description  = "description: NETAR-3313, services: [udp161]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "smb_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "smb_ports"
  description  = "description: NETAR-3469, services: [tcp139, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["139", "445"]
  }
}

resource "nsxt_policy_service" "propman_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "propman_ports"
  description  = "description: NETAR-3366, services: [tcp12199, tcp12200, tcp12300-12301, tcp135, tcp2040, tcp24001-24100, tcp24501-24600, tcp445, tcp61613, tcp61623, tcp8161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["12199", "12200", "12300-12301", "135", "2040", "24001-24100", "24501-24600"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "61613", "61623", "8161"]
  }
}

resource "nsxt_policy_service" "to_solarwinds_pollers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "to_solarwinds_pollers"
  description  = "description: NETAR-3607, services: [udp162, udp514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["162", "514"]
  }
}

resource "nsxt_policy_service" "to_solarwinds_dsts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "to_solarwinds_dsts"
  description  = "description: NETAR-3607, services: [tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "dfs_root_hosts_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "dfs_root_hosts_services"
  description  = "description: NETAR-3478, services: [tcp445, tcp135, tcp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "135", "49152-65535"]
  }
}

resource "nsxt_policy_service" "tcp8081" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp8081"
  description  = "description: NETAR-3602, services: [tcp8081]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081"]
  }
}

resource "nsxt_policy_service" "tcp43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp43"
  description  = "description: NETAR-3602, services: [tcp43]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["43"]
  }
}

resource "nsxt_policy_service" "manila_bomgar_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "manila_bomgar_ports"
  description  = "description: NETAR-3806, services: [tcp22, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "443"]
  }
}

resource "nsxt_policy_service" "manila_oneview_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "manila_oneview_ports"
  description  = "description: NETAR-3806, services: [tcp80, tcp123, tcp161, tcp443, tcp17988, tcp17990]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "123", "161", "443", "17988", "17990"]
  }
}

resource "nsxt_policy_service" "oneview_ports_manila" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "oneview_ports_manila"
  description  = "description: NETAR-3806, services: [tcp22, tcp80, tcp123, tcp162, tcp443, tcp2162, tcp5671]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "123", "162", "443", "2162", "5671"]
  }
}

resource "nsxt_policy_service" "vr_appliance_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vr_appliance_ports"
  description  = "description: NETAR-3806, services: [tcp80, tcp443, tcp744, tcp8043]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "744", "8043"]
  }
}

resource "nsxt_policy_service" "vr_appliance_vcenter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vr_appliance_vcenter"
  description  = "description: NETAR-3806, services: [tcp90, tcp31031, tcp44046]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["90", "31031", "44046"]
  }
}

resource "nsxt_policy_service" "vsan_witness_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vsan_witness_ports"
  description  = "description: NETAR-3806, services: [tcp80, tcp8080, tcp223, tcp12443, tcp12321, tcp12345, tcp23451]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "8080", "223", "12443", "12321", "12345", "23451"]
  }
}

resource "nsxt_policy_service" "ssh_rdp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ssh_rdp"
  description  = "description: NETAR-3782, services: [tcp22, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "3389"]
  }
}

resource "nsxt_policy_service" "splunk_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "splunk_ports"
  description  = "description: NETAR-3885, services: [tcp8088, tcp8089, tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8088", "8089", "9997"]
  }
}

resource "nsxt_policy_service" "tcp_60606" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp_60606"
  description  = "description: NETAR-4497, services: [tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["60606"]
  }
}

resource "nsxt_policy_service" "da_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "da_ports"
  description  = "description: NETAR-4794, services: [tcp80, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "445"]
  }
}

resource "nsxt_policy_service" "syslog-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "syslog-ports"
  description  = "description: NETAR-5220, services: [tcp-udp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["514"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "iam-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "iam-ports"
  description  = "description: NETAR-5341, services: [tcp3389, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "445"]
  }
}

resource "nsxt_policy_service" "tcp_9196" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp_9196"
  description  = "description: NETAR-5796, services: [tcp9196]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9196"]
  }
}

resource "nsxt_policy_service" "corp-engineering-server-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "corp-engineering-server-ports"
  description  = "description: NETAR-6045, services: [tcp5985-5986, tcp135, tcp445, tcp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5985-5986", "135", "445", "49152-65535"]
  }
}

resource "nsxt_policy_service" "corp-ad-dsp-agent-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "corp-ad-dsp-agent-ports"
  description  = "description: NETAR-6071, services: [tcp8750, tcp8772]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8750", "8772"]
  }
}

resource "nsxt_policy_service" "corp-semperis-dsp-mgmt-svr-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "corp-semperis-dsp-mgmt-svr-ports"
  description  = "description: NETAR-6071, services: [tcp8903]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8903"]
  }
}

resource "nsxt_policy_service" "corp-ad-adfr-agent-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "corp-ad-adfr-agent-ports"
  description  = "description: NETAR-6071, services: [tcp8753, tcp8770]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8753", "8770"]
  }
}

resource "nsxt_policy_service" "corp_engineering_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "corp_engineering_ports"
  description  = "description: NETAR-6047, services: [tcp445, tcp5985-5986, tcp135, tcp49152-65535, tcp8903]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "5985-5986", "135", "49152-65535", "8903"]
  }
}

resource "nsxt_policy_service" "rpa-splunk-port" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "rpa-splunk-port"
  description  = "description: NETAR-6671, services: [tcp8090]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8090"]
  }
}

resource "nsxt_policy_service" "tcp-4443" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp-4443"
  description  = "description: ITSD-49490, services: [tcp4443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4443"]
  }
}

resource "nsxt_policy_service" "ad_888_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad_888_ports"
  description  = "description: NETAR-6047, services: [tcp636, tcp3269]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["636", "3269"]
  }
}

resource "nsxt_policy_service" "ironport-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ironport-ports"
  description  = "description: NETAR-6767, services: [tcp22, tcp2222]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "2222"]
  }
}

resource "nsxt_policy_service" "test_ad_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "test_ad_ports"
  description  = "description: NETAR-6949, services: [tcp5000-5001]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5000-5001"]
  }
}

resource "nsxt_policy_service" "kafka-topics-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "kafka-topics-ports"
  description  = "description: NETAR-7174, services: [tcp9094]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9094"]
  }
}

