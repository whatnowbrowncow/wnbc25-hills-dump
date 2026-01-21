/*=========================================================
#### Parse of ASA Service and Protocol Objects (ports) ####

######### Example Format #############

resource "nsxt_policy_service" "tcp_80" {
  display_name = "tcp-80"
  description  = "description: tcp-80, services: tcp80"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80"]
  }
}

How we will format and standardise this:
The "resource" name and "display_name" will be the same/identical, referencing the same varible: port_obj_name
The "destination_ports" will always be a list
The "description" must contain a service object's description, if it has one, and list of protocol/ports 
description: describes the service object, where this information is available. Where it isn't the port_obj_name must be added
services: lists the protocol/ports defined in the object in a comma separated format (e.g. tcp3389, udp514)
The ports must always be listed in the "description", as this allows us to overcome a limitation with the VMC rule search/filter


resource "nsxt_policy_service" "( port_obj_name )" {
  display_name = "( port_obj_name )"
  description  = "description: ( existing/valid object description | port_obj_name ), services: [( protocol )( port ), ( protocol )( port )]"
  l4_port_set_entry {
    protocol          = "( protocol (uppercase) )"
    destination_ports = [( port )]
  }
  l4_port_set_entry {
    protocol          = "( protocol (uppercase) )"
    destination_ports = [( port )]
  }
}

=========================================================*/

resource "nsxt_policy_service" "pr-c-frontend_tcp-8081_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8081_eq"
  description  = "description: tcp-8081_eq, services: [tcp8081]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-7331_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-7331_eq"
  description  = "description: tcp-7331_eq, services: [tcp7331]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7331"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-9191_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-9191_eq"
  description  = "description: tcp-9191_eq, services: [tcp9191]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9191"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_web" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_web"
  description  = "description: pr-c-frontend_web, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_3rdparties" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_3rdparties"
  description  = "description: pr-c-frontend_3rdparties, services: [tcp22, tcp843, tcp389, tcp444, tcp2156, tcp3128, tcp4002, tcp4007, tcp4009, tcp8014, tcp8080, tcp8443, tcp5119, tcp23560, tcp9000, tcp10020, tcp16010, tcp16400, tcp29002, tcp29005, tcp29006]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "843", "389", "444", "2156", "3128", "4002"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4007", "4009", "8014", "8080", "8443", "5119", "23560"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9000", "10020", "16010", "16400", "29002", "29005", "29006"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-sqlnet_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-sqlnet_eq"
  description  = "description: tcp-sqlnet_eq, services: [tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-1540_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-1540_eq"
  description  = "description: tcp-1540_eq, services: [tcp1540]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1540"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_21"
  description  = "description: pr-c-frontend_scc-migrated_tcp_21, services: [tcp3128-3129, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3128-3129", "80"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-www_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-www_eq"
  description  = "description: tcp-www_eq, services: [tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-10300_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-10300_eq"
  description  = "description: tcp-10300_eq, services: [tcp10300]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10300"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-https_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-https_eq"
  description  = "description: tcp-https_eq, services: [tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_mailhostports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_mailhostports"
  description  = "description: pr-c-frontend_mailhostports, services: [tcp10000, tcp10010, tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10000", "10010", "3306"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-smtp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-smtp_eq"
  description  = "description: tcp-smtp_eq, services: [tcp25]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["25"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_udp-syslog_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_udp-syslog_eq"
  description  = "description: udp-syslog_eq, services: [udp514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-445_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-445_eq"
  description  = "description: tcp-445_eq, services: [tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8443_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8443_eq"
  description  = "description: tcp-8443_eq, services: [tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_grp-dr-svc-propman" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp-dr-svc-propman"
  description  = "description: pr-c-frontend_grp-dr-svc-propman, services: [tcp12199, tcp12300, tcp24001-24100, tcp12200, tcp12301, tcp8161, tcp61613, tcp61623, tcp2040, tcp445, tcp135]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["12199", "12300", "24001-24100", "12200", "12301", "8161", "61613"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["61623", "2040", "445", "135"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_grp-dr-svc-tanda" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp-dr-svc-tanda"
  description  = "description: pr-c-frontend_grp-dr-svc-tanda, services: [tcp445, tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "1433"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_jde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_jde"
  description  = "description: CHG0125763, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470-8478, tcp9401-9405, tcp9645, tcp443, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2001", "2300", "4402", "446", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470-8478", "9401-9405", "9645", "443", "23"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_grp-dr-svc-jde-app" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp-dr-svc-jde-app"
  description  = "description: pr-c-frontend_grp-dr-svc-jde-app, services: [tcp8470-8476, tcp449, tcp446, tcp447]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470-8476", "449", "446", "447"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_svc-web" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svc-web"
  description  = "description: pr-c-frontend_svc-web, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8080_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8080_eq"
  description  = "description: tcp-8080_eq, services: [tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-3299_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-3299_eq"
  description  = "description: tcp-3299_eq, services: [tcp3299]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3299"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-5722_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-5722_eq"
  description  = "description: tcp-5722_eq, services: [tcp5722]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5722"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_svc-citrix-fs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_svc-citrix-fs"
  description  = "description: pr-c-frontend_svc-citrix-fs, services: [tcp445, tcp135]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "135"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-9997_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-9997_eq"
  description  = "description: tcp-9997_eq, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8089_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8089_eq"
  description  = "description: tcp-8089_eq, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-81_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-81_eq"
  description  = "description: tcp-81_eq, services: [tcp81]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["81"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp_udp_rdp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp_udp_rdp"
  description  = "description: pr-c-frontend_tcp_udp_rdp, services: [tcp3389, udp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_7"
  description  = "description: pr-c-frontend_scc-migrated_tcp_7, services: [tcp3128, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3128", "3129"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8100-8101_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8100-8101_eq"
  description  = "description: tcp-8100-8101_eq, services: [tcp8100-8101]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8100-8101"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_puppet-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_puppet-services"
  description  = "description: pr-c-frontend_puppet-services, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_6"
  description  = "description: pr-c-frontend_scc-migrated_service_6, services: [tcp4443, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4443", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp_8400-8403" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp_8400-8403"
  description  = "description: pr-c-frontend_tcp_8400-8403, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_commvault-media-server-service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_commvault-media-server-service"
  description  = "description: pr-c-frontend_commvault-media-server-service, services: [tcp1433, udp1434, tcp8400-8408]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "8400-8408"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_commvault-commcell-service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_commvault-commcell-service"
  description  = "description: pr-c-frontend_commvault-commcell-service, services: [tcp1433, udp1434, tcp445, tcp8400-8408]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "445", "8400-8408"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_commvault-proxy-server-service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_commvault-proxy-server-service"
  description  = "description: pr-c-frontend_commvault-proxy-server-service, services: [tcp10022, tcp902, tcp443, tcp2049, tcp111, udp111, tcp8400-8408]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10022", "902", "443", "2049", "111", "8400-8408"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_udp-snmptrap_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_udp-snmptrap_eq"
  description  = "description: udp-snmptrap_eq, services: [udp162]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["162"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_16"
  description  = "description: pr-c-frontend_scc-migrated_service_16, services: [tcp10022, tcp902, tcp443, tcp2049, tcp111, udp111, tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10022", "902", "443", "2049", "111", "8400-8403"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_14"
  description  = "description: pr-c-frontend_scc-migrated_service_14, services: [tcp10022, tcp8400, tcp8401, tcp8402, tcp8403, tcp902, tcp443, tcp2049, tcp111, udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10022", "8400", "8401", "8402", "8403", "902", "443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_19"
  description  = "description: pr-c-frontend_scc-migrated_service_19, services: [tcp10022, tcp8400, tcp8401, tcp8402, tcp8403, tcp902, tcp443, tcp2049, tcp111, udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10022", "8400", "8401", "8402", "8403", "902", "443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_28" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_28"
  description  = "description: pr-c-frontend_scc-migrated_tcp_28, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_39"
  description  = "description: pr-c-frontend_scc-migrated_tcp_39, services: [tcp443, tcp25, tcp8118]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "25", "8118"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_17"
  description  = "description: pr-c-frontend_scc-migrated_service_17, services: [tcp10022, tcp902, tcp443, tcp2049, tcp111, udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10022", "902", "443", "2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_112" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_112"
  description  = "description: pr-c-frontend_scc-migrated_tcp_112, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8404-8407" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8404-8407"
  description  = "description: pr-c-frontend_tcp-8404-8407, services: [tcp8404-8407]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8404-8407"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8404-8423_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8404-8423_eq"
  description  = "description: tcp-8404-8423_eq, services: [tcp8404-8423]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8404-8423"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_24"
  description  = "description: pr-c-frontend_scc-migrated_tcp_24, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-ssh_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-ssh_eq"
  description  = "description: tcp-ssh_eq, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-1523_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-1523_eq"
  description  = "description: tcp-1523_eq, services: [tcp1523]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1523"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_26"
  description  = "description: pr-c-frontend_scc-migrated_tcp_26, services: [tcp21, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-ftp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-ftp_eq"
  description  = "description: tcp-ftp_eq, services: [tcp21]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_14"
  description  = "description: pr-c-frontend_scc-migrated_tcp_14, services: [tcp1523-1524, tcp1530-1531]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1523-1524", "1530-1531"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-1530_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-1530_eq"
  description  = "description: tcp-1530_eq, services: [tcp1530]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1530"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-1560_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-1560_eq"
  description  = "description: tcp-1560_eq, services: [tcp1560]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1560"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_68"
  description  = "description: pr-c-frontend_scc-migrated_tcp_68, services: [tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_8"
  description  = "description: pr-c-frontend_scc-migrated_tcp_8, services: [tcp2598, tcp1494]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2598", "1494"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-1528_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-1528_eq"
  description  = "description: tcp-1528_eq, services: [tcp1528]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1528"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_69"
  description  = "description: pr-c-frontend_scc-migrated_tcp_69, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_grp-vtm-svc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp-vtm-svc"
  description  = "description: pr-c-frontend_grp-vtm-svc, services: [tcp9070, udp161, udp162]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161", "162"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_2"
  description  = "description: pr-c-frontend_scc-migrated_tcp_2, services: [tcp9090, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9090", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_15"
  description  = "description: pr-c-frontend_scc-migrated_tcp_15, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_web-proxy-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_web-proxy-ports"
  description  = "description: pr-c-frontend_web-proxy-ports, services: [tcp8080, tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "8443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-3389_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-3389_eq"
  description  = "description: tcp-3389_eq, services: [tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_informix_replication" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_informix_replication"
  description  = "description: pr-c-frontend_informix_replication, services: [tcp1560-1570, tcp1580]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1560-1570", "1580"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_7"
  description  = "description: pr-c-frontend_scc-migrated_service_7, services: [tcp80, tcp443, tcp22, tcp8080, tcp3389, tcp135, tcp445, udp137-139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "22", "8080", "3389", "135", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137-139"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8400-8403_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8400-8403_eq"
  description  = "description: tcp-8400-8403_eq, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_34"
  description  = "description: pr-c-frontend_scc-migrated_tcp_34, services: [tcp8080, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_43"
  description  = "description: pr-c-frontend_scc-migrated_tcp_43, services: [tcp8080, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_22"
  description  = "description: pr-c-frontend_scc-migrated_service_22, services: [tcp10022, tcp8400, tcp8401, tcp8402, tcp8403, tcp902, tcp443, tcp2049, tcp111, udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10022", "8400", "8401", "8402", "8403", "902", "443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_23"
  description  = "description: pr-c-frontend_scc-migrated_service_23, services: [tcp2049, tcp111, udp2049, udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["2049", "111"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_42"
  description  = "description: pr-c-frontend_scc-migrated_tcp_42, services: [tcp8080, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-1530" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-1530"
  description  = "description: CHG0125642, services: [tcp1530]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1530"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_49"
  description  = "description: pr-c-frontend_scc-migrated_tcp_49, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_rdp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_rdp"
  description  = "description: pr-c-frontend_rdp, services: [tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_54"
  description  = "description: pr-c-frontend_scc-migrated_tcp_54, services: [tcp27000, tcp7279, tcp8082, tcp8083, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["27000", "7279", "8082", "8083", "80"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_53" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_53"
  description  = "description: pr-c-frontend_scc-migrated_tcp_53, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcpudp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcpudp"
  description  = "description: pr-c-frontend_tcpudp, services: [udp, tcp]"
  ip_protocol_entry {
    display_name = "udp"
    protocol     = "17"
  }
  ip_protocol_entry {
    display_name = "tcp"
    protocol     = "6"
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcpudp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcpudp_1"
  description  = "description: pr-c-frontend_scc-migrated_tcpudp_1, services: [tcp-udp1494, tcp-udp2598]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1494", "2598"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1494", "2598"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_29"
  description  = "description: pr-c-frontend_scc-migrated_service_29, services: [tcp5985, tcp5986, tcp135, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5985", "5986", "135", "445"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_56"
  description  = "description: pr-c-frontend_scc-migrated_tcp_56, services: [tcp135, tcp5722, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "5722", "445"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_57"
  description  = "description: pr-c-frontend_scc-migrated_tcp_57, services: [tcp135, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-81"
  description  = "description: pr-c-frontend_tcp-81, services: [tcp81]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["81"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_66"
  description  = "description: pr-c-frontend_scc-migrated_tcp_66, services: [tcp8080, tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "8443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_9"
  description  = "description: pr-c-frontend_scc-migrated_tcp_9, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_33"
  description  = "description: pr-c-frontend_scc-migrated_tcp_33, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-9070_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-9070_eq"
  description  = "description: tcp-9070_eq, services: [tcp9070]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-citrix-pvs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-citrix-pvs"
  description  = "description: CHG0146699, services: [tcp27000, tcp7279]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["27000", "7279"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-10201-10600_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-10201-10600_eq"
  description  = "description: tcp-10201-10600_eq, services: [tcp10201-10600]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10201-10600"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_whgroup_ad_ports-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_whgroup_ad_ports-chg0144834"
  description  = "description: pr-c-frontend_whgroup_ad_ports-chg0144834, services: [tcp-udp53, tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp49152-65525, tcp636, tcp3268-3269, tcp5722, tcp9389, udp137-138]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "88", "123", "135", "139", "389", "445"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["464", "49152-65525", "636", "3268-3269", "5722", "9389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "88", "123", "135", "139", "389", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["464", "49152-65525", "137-138"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_euc_mgmt_port-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_euc_mgmt_port-group-chg0142765"
  description  = "description: pr-c-frontend_euc_mgmt_port-group-chg0142765, services: [tcp135, tcp445, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_splunk_indexing_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_splunk_indexing_port-chg0143200"
  description  = "description: pr-c-frontend_splunk_indexing_port-chg0143200, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_splunk_mgmt_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_splunk_mgmt_port-chg0143200"
  description  = "description: pr-c-frontend_splunk_mgmt_port-chg0143200, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_splunk_indexing_port-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_splunk_indexing_port-chg0142763"
  description  = "description: pr-c-frontend_splunk_indexing_port-chg0142763, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_splunk_mgmt_port-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_splunk_mgmt_port-chg0142763"
  description  = "description: pr-c-frontend_splunk_mgmt_port-chg0142763, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_18"
  description  = "description: pr-c-frontend_scc-migrated_tcp_18, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_rundeck-winrm-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_rundeck-winrm-ports"
  description  = "description: pr-c-frontend_rundeck-winrm-ports, services: [tcp5985-5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5985-5986"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_wily-outbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_wily-outbound-ports"
  description  = "description: pr-c-frontend_wily-outbound-ports, services: [tcp22, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_17"
  description  = "description: pr-c-frontend_scc-migrated_tcp_17, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_ldap-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_ldap-services"
  description  = "description: CHG0116053, services: [tcp8275, tcp8276]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8275", "8276"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_tcp_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_tcp_25"
  description  = "description: pr-c-frontend_scc-migrated_tcp_25, services: [tcp3129, tcp5671, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3129", "5671", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_grp-pr-c-wsus-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_grp-pr-c-wsus-ports"
  description  = "description: CHG0014573, services: [tcp80, tcp443, tcp8530-8531, tcp1688]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "8530-8531", "1688"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-nas-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-nas-ports"
  description  = "description: pr-c-frontend_scc-nas-ports, services: [tcp-udp2049, tcp-udp111, tcp-udp1039, tcp-udp1047, tcp-udp1048, tcp-udp1110, tcp-udp300, tcp-udp302, tcp-udp304, tcp-udp4045]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2049", "111", "1039", "1047", "1048", "1110", "300"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["302", "304", "4045"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["2049", "111", "1039", "1047", "1048", "1110", "300"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["302", "304", "4045"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_infoblox-standard-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_infoblox-standard-ports"
  description  = "description: pr-c-frontend_infoblox-standard-ports, services: [tcp-udp53, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_whgroup-ad-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_whgroup-ad-ports"
  description  = "description: pr-c-frontend_whgroup-ad-ports, services: [tcp9389, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp88, tcp135, tcp3268-3269, tcp49152-65535, tcp5722, tcp636, tcp139, udp49152-65535, udp138, udp137, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9389", "389", "445", "464", "88", "135", "3268-3269"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "5722", "636", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["389", "445", "464", "88", "49152-65535", "138", "137"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-1688_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-1688_eq"
  description  = "description: tcp-1688_eq, services: [tcp1688]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1688"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-48000-48030_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-48000-48030_eq"
  description  = "description: tcp-48000-48030_eq, services: [tcp48000-48030]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["48000-48030"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8400-8403" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8400-8403"
  description  = "description: CHG0112231, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_60606" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_60606"
  description  = "description: pr-c-frontend_60606, services: [tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["60606"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_tcp-8083_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_tcp-8083_eq"
  description  = "description: tcp-8083_eq, services: [tcp8083]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8083"]
  }
}

resource "nsxt_policy_service" "pr-c-frontend_scc-migrated_service_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-frontend_scc-migrated_service_1"
  description  = "description: pr-c-frontend_scc-migrated_service_1, services: [tcp9070, tcp22, tcp25, tcp-udp53, udp123, udp161, udp162, tcp-udp389, tcp443, tcp444, tcp636, tcp1433, tcp8443, tcp8834, tcp9443, tcp18184, tcp18191, tcp18210]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070", "22", "25", "53", "389", "443", "444"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["636", "1433", "8443", "8834", "9443", "18184", "18191"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18210"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123", "161", "162", "389"]
  }
}

