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

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_14"
  description  = "description: pr-n-mgt_scc-migrated_tcp_14, services: [tcp61613, tcp8142]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["61613", "8142"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-9977_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-9977_eq"
  description  = "description: tcp-9977_eq, services: [tcp9977]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9977"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_katello-tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_katello-tcp"
  description  = "description: pr-n-mgt_katello-tcp, services: [tcp80, tcp443, tcp5671, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "5671", "3129"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_ntp-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ntp-ports"
  description  = "description: CHG0067823, services: [udp123]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_cellmon-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cellmon-ports"
  description  = "description: CHG0068990, services: [tcp9977]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9977"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_stingray-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_stingray-ports"
  description  = "description: CHG0071650, services: [tcp9070, tcp9090]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070", "9090"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_56"
  description  = "description: pr-n-mgt_scc-migrated_tcp_56, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-https_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-https_eq"
  description  = "description: tcp-https_eq, services: [tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_puppet-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_puppet-ports"
  description  = "description: CHG0068990, services: [tcp443, tcp8140, tcp61613]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "8140", "61613"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_udp-syslog_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_udp-syslog_eq"
  description  = "description: udp-syslog_eq, services: [udp514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_udp-1812_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_udp-1812_eq"
  description  = "description: udp-1812_eq, services: [udp1812]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1812"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp_8140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp_8140"
  description  = "description: pr-n-mgt_tcp_8140, services: [tcp8140]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8140"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-ssh_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-ssh_eq"
  description  = "description: tcp-ssh_eq, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_22"
  description  = "description: pr-n-mgt_scc-migrated_tcp_22, services: [tcp5671, tcp80, tcp443, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "3129"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_16"
  description  = "description: pr-n-mgt_scc-migrated_tcp_16, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-8275_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-8275_eq"
  description  = "description: tcp-8275_eq, services: [tcp8275]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8275"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-smtp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-smtp_eq"
  description  = "description: tcp-smtp_eq, services: [tcp25]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["25"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_hp-irs-target-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_hp-irs-target-ports"
  description  = "description: pr-n-mgt_hp-irs-target-ports, services: [tcp7, udp162, tcp2381, tcp2301]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7", "2381", "2301"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["162"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_nas-access-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_nas-access-ports"
  description  = "description: pr-n-mgt_nas-access-ports, services: [tcp-udp1039, tcp-udp1047, tcp-udp1048, tcp-udp1110, tcp-udp300, tcp-udp302, tcp-udp304, tcp-udp4045, tcp-udp2049, tcp-udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1039", "1047", "1048", "1110", "300", "302", "304"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4045", "2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1039", "1047", "1048", "1110", "300", "302", "304"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["4045", "2049", "111"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_grp-pr-c-ad-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp-pr-c-ad-ports"
  description  = "description: CHG0018188, services: [tcp135, tcp153, tcp49152-65535, tcp5722, tcp636, tcp139, udp49152-65535, udp138, udp123, tcp137, tcp445, tcp464, tcp88, tcp389, udp389, udp445, udp464, udp88, udp137, tcp3268-3269, tcp138, udp4500, udp636, udp500]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "153", "49152-65535", "5722", "636", "139", "137"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "464", "88", "389", "3268-3269", "138"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["49152-65535", "138", "123", "389", "445", "464", "88"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "4500", "636", "500"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_20"
  description  = "description: pr-n-mgt_scc-migrated_tcp_20, services: [tcp5671, tcp80, tcp443, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "3129"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_76" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_76"
  description  = "description: pr-n-mgt_scc-migrated_tcp_76, services: [tcp4444, tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4444", "1521"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-sqlnet_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-sqlnet_eq"
  description  = "description: tcp-sqlnet_eq, services: [tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcpudp-623" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcpudp-623"
  description  = "description: pr-n-mgt_tcpudp-623, services: [udp623, tcp623]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["623"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["623"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_75"
  description  = "description: pr-n-mgt_scc-migrated_tcp_75, services: [tcp1159, tcp18080, tcp18443, tcp4899-4908]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1159", "18080", "18443", "4899-4908"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc_wsus_ports_tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc_wsus_ports_tcp"
  description  = "description: pr-n-mgt_scc_wsus_ports_tcp, services: [tcp80, tcp443, tcp8530, tcp8531]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "8530", "8531"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_rds_udp_tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_rds_udp_tcp"
  description  = "description: pr-n-mgt_rds_udp_tcp, services: [tcp135, tcp137, tcp138, tcp139, tcp445, tcp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "137", "138", "139", "445", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_40"
  description  = "description: pr-n-mgt_scc-migrated_service_40, services: [tcp137, tcp1433, tcp445, tcp139, udp138]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "1433", "445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["138"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_udp-623_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_udp-623_eq"
  description  = "description: udp-623_eq, services: [udp623]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["623"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_63"
  description  = "description: pr-n-mgt_scc-migrated_tcp_63, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcpudp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcpudp"
  description  = "description: pr-n-mgt_tcpudp, services: [udp, tcp]"
  ip_protocol_entry {
    display_name = "udp"
    protocol     = "17"
  }
  ip_protocol_entry {
    display_name = "tcp"
    protocol     = "6"
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-udp-623" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-udp-623"
  description  = "description: CHG0112168, services: [tcp-udp623]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["623"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["623"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-4903_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-4903_eq"
  description  = "description: tcp-4903_eq, services: [tcp4903]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4903"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcpudp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcpudp_1"
  description  = "description: pr-n-mgt_scc-migrated_tcpudp_1, services: [tcp-udp2049, tcp-udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["2049", "111"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-4903" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-4903"
  description  = "description: CHG0124796, services: [tcp4903]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4903"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_21"
  description  = "description: pr-n-mgt_scc-migrated_tcp_21, services: [tcp5671, tcp80, tcp443, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "3129"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_23"
  description  = "description: pr-n-mgt_scc-migrated_service_23, services: [tcp-udp53, tcp135, tcp3268-3269, tcp445, tcp464, tcp49152-65535, tcp5722, tcp88, tcp389, tcp636, tcp139, udp389, udp445, udp464, udp49152-65535, udp88, udp138, udp137, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "135", "3268-3269", "445", "464", "49152-65535", "5722"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["88", "389", "636", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "389", "445", "464", "49152-65535", "88", "138"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "123"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_ad_auth_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ad_auth_ports"
  description  = "description: pr-n-mgt_ad_auth_ports, services: [tcp-udp88, tcp-udp53, tcp-udp123, tcp-udp135, tcp-udp137, tcp-udp138, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp636, tcp-udp153, tcp-udp3268, tcp-udp3269, tcp-udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["88", "53", "123", "135", "137", "138", "389"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "464", "636", "153", "3268", "3269", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["88", "53", "123", "135", "137", "138", "389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445", "464", "636", "153", "3268", "3269", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_hp-laserjet-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_hp-laserjet-ports"
  description  = "description: pr-n-mgt_hp-laserjet-ports, services: [tcp-udp9100, tcp-udp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9100", "8080"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["9100", "8080"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-873_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-873_eq"
  description  = "description: tcp-873_eq, services: [tcp873]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["873"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_41"
  description  = "description: pr-n-mgt_scc-migrated_service_41, services: [tcp-udp515, tcp-udp631, tcp-udp9100, tcp-udp9101, tcp-udp9102, tcp80, udp161, tcp3910, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["515", "631", "9100", "9101", "9102", "80", "3910"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["515", "631", "9100", "9101", "9102", "161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-1504_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-1504_eq"
  description  = "description: tcp-1504_eq, services: [tcp1504]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1504"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_19"
  description  = "description: pr-n-mgt_scc-migrated_tcp_19, services: [tcp5671, tcp80, tcp443, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "3129"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_22"
  description  = "description: pr-n-mgt_scc-migrated_service_22, services: [tcp-udp53, tcp135, tcp3268-3269, tcp445, tcp464, tcp49152-65535, tcp5722, tcp88, tcp389, tcp636, tcp139, udp389, udp445, udp464, udp49152-65535, udp88, udp138, udp137, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "135", "3268-3269", "445", "464", "49152-65535", "5722"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["88", "389", "636", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "389", "445", "464", "49152-65535", "88", "138"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "123"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_mrr-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_mrr-ports"
  description  = "description: pr-n-mgt_mrr-ports, services: [tcp135, tcp137, tcp3268, tcp3269, tcp445, tcp464, tcp49152-65535, tcp5722, tcp88, tcp389, tcp636, tcp139, udp4500, udp500, udp138, udp123, udp389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "137", "3268", "3269", "445", "464", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5722", "88", "389", "636", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["4500", "500", "138", "123", "389"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_active-directory-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_active-directory-ports"
  description  = "description: CHG0018025, services: [tcp135, tcp153, tcp49152-65535, tcp5722, tcp636, tcp139, udp49152-65535, udp138, udp123, tcp137, tcp445, tcp464, tcp88, tcp389, udp389, udp445, udp464, udp88, udp137, tcp3268-3269, tcp138]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "153", "49152-65535", "5722", "636", "139", "137"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "464", "88", "389", "3268-3269", "138"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["49152-65535", "138", "123", "389", "445", "464", "88"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_cluster-ports-tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cluster-ports-tcp"
  description  = "description: pr-n-mgt_cluster-ports-tcp, services: [tcp445, tcp3343, tcp135, tcp139, tcp49152-65535, tcp5985]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "3343", "135", "139", "49152-65535", "5985"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_cluster-ports-udp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_cluster-ports-udp"
  description  = "description: pr-n-mgt_cluster-ports-udp, services: [udp137, udp3343, udp49152-65535]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "3343", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_dns" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_dns"
  description  = "description: pr-n-mgt_dns, services: [tcp53, udp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-445_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-445_eq"
  description  = "description: tcp-445_eq, services: [tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-1526_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-1526_eq"
  description  = "description: tcp-1526_eq, services: [tcp1526]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1526"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-5001_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-5001_eq"
  description  = "description: tcp-5001_eq, services: [tcp5001]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5001"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_45"
  description  = "description: pr-n-mgt_scc-migrated_tcp_45, services: [tcp4444, tcp1521, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4444", "1521", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_80" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_80"
  description  = "description: pr-n-mgt_scc-migrated_tcp_80, services: [tcp3389, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-3389_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-3389_eq"
  description  = "description: tcp-3389_eq, services: [tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_sas-admin-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_sas-admin-ports"
  description  = "description: pr-n-mgt_sas-admin-ports, services: [tcp3389, tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "1433"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_71" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_71"
  description  = "description: pr-n-mgt_scc-migrated_tcp_71, services: [tcp1433, tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_69"
  description  = "description: pr-n-mgt_scc-migrated_tcp_69, services: [tcp1433, tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_4"
  description  = "description: pr-n-mgt_scc-migrated_tcp_4, services: [tcp1433, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "3389"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_85" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_85"
  description  = "description: pr-n-mgt_scc-migrated_tcp_85, services: [tcp1433, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "3389"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_nms" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_nms"
  description  = "description: pr-n-mgt_nms, services: [udp161, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_udp-snmp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_udp-snmp_eq"
  description  = "description: udp-snmp_eq, services: [udp161]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_35"
  description  = "description: pr-n-mgt_scc-migrated_service_35, services: [tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_9"
  description  = "description: pr-n-mgt_scc-migrated_service_9, services: [tcp18000-18050, udp18000-18050, tcp445, tcp5555, udp445, udp5555]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18000-18050", "445", "5555"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["18000-18050", "445", "5555"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-kms-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-kms-ports"
  description  = "description: CHG0018025, services: [tcp135, tcp1688, tcp4168, udp9256, tcp49152-65535, udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "1688", "4168", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["9256", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_5"
  description  = "description: pr-n-mgt_scc-migrated_tcp_5, services: [tcp135, tcp139, tcp445, tcp45152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "139", "445", "45152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_23"
  description  = "description: pr-n-mgt_scc-migrated_tcp_23, services: [tcp80, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_udp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_udp_1"
  description  = "description: pr-n-mgt_scc-migrated_udp_1, services: [udp161, udp69]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161", "69"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_20"
  description  = "description: pr-n-mgt_scc-migrated_service_20, services: [tcp1521, tcp3389, tcp22, tcp1521-1525]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521", "3389", "22", "1521-1525"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_svc-obj-g-solarwinds" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_svc-obj-g-solarwinds"
  description  = "description: CHG0138643, services: [tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_3"
  description  = "description: pr-n-mgt_scc-migrated_service_3, services: [tcp-udp40000-49999, udp6001, tcp1720, udp50000-52399, tcp-udp2776-2777, udp36000-36001, tcp-udp7001-7999, udp7400, tcp2222, udp24000-29999, udp3478-3483]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["40000-49999", "1720", "2776-2777", "7001-7999", "2222"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["40000-49999", "6001", "50000-52399", "2776-2777", "36000-36001", "7001-7999", "7400"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["24000-29999", "3478-3483"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_2"
  description  = "description: pr-n-mgt_scc-migrated_service_2, services: [udp514, tcp80, tcp443, tcp22, tcp23, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "22", "23"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514", "161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_4"
  description  = "description: pr-n-mgt_scc-migrated_service_4, services: [tcp8443, tcp80, tcp443, tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "80", "443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_57" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_57"
  description  = "description: pr-n-mgt_scc-migrated_tcp_57, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp23, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2001", "2300", "4402", "446", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470", "8471", "8472", "8473", "8474", "8475", "8476"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["23", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_25"
  description  = "description: pr-n-mgt_scc-migrated_tcp_25, services: [tcp3389, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_25"
  description  = "description: pr-n-mgt_scc-migrated_service_25, services: [tcp1433, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_wily_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wily_ports"
  description  = "description: CHG0035851, services: [tcp22, tcp80, tcp1043, tcp3098, tcp8090, tcp8181, tcp8881]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "1043", "3098", "8090", "8181", "8881"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-3306_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-3306_eq"
  description  = "description: tcp-3306_eq, services: [tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_44"
  description  = "description: pr-n-mgt_scc-migrated_tcp_44, services: [tcp3389, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_67"
  description  = "description: pr-n-mgt_scc-migrated_tcp_67, services: [tcp3389, tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "8080"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_70"
  description  = "description: pr-n-mgt_scc-migrated_tcp_70, services: [tcp8014, tcp8443, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8014", "8443", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-www_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-www_eq"
  description  = "description: tcp-www_eq, services: [tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_74" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_74"
  description  = "description: pr-n-mgt_scc-migrated_tcp_74, services: [tcp22, tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "3306"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_90" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_90"
  description  = "description: pr-n-mgt_scc-migrated_tcp_90, services: [tcp3389, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_31"
  description  = "description: pr-n-mgt_scc-migrated_service_31, services: [tcp1433, tcp30000, udp1434, tcp11433, tcp135, tcp1433, tcp2559, tcp51083, tcp57324, tcp58661, tcp63480, udp1434, tcp135-139, tcp3000-3100, tcp445, udp135-139, udp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "30000", "11433", "135", "1433", "2559", "51083"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["57324", "58661", "63480", "135-139", "3000-3100", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434", "1434", "135-139", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-49152-65535_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-49152-65535_eq"
  description  = "description: tcp-49152-65535_eq, services: [tcp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_5"
  description  = "description: pr-n-mgt_scc-migrated_service_5, services: [tcp-udp135-139, tcp-udp445, tcp1433, tcp3000, tcp3000-3100, tcp49152-65535, tcp62907, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135-139", "445", "1433", "3000", "3000-3100", "49152-65535", "62907"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["135-139", "445", "1434"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_17"
  description  = "description: pr-n-mgt_scc-migrated_service_17, services: [tcp1433, tcp445, tcp139, udp1434, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "445", "139", "3389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_2"
  description  = "description: pr-n-mgt_scc-migrated_tcp_2, services: [tcp3389, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp_8400-8403" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp_8400-8403"
  description  = "description: pr-n-mgt_tcp_8400-8403, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_grp-oracle-monitoring-svcs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_grp-oracle-monitoring-svcs"
  description  = "description: pr-n-mgt_grp-oracle-monitoring-svcs, services: [tcp1521-1525, tcp3872]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521-1525", "3872"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_98" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_98"
  description  = "description: pr-n-mgt_scc-migrated_service_98, services: [tcp3389, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_83"
  description  = "description: pr-n-mgt_scc-migrated_tcp_83, services: [tcp1521-1525, tcp3872, tcp22, tcp4903]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521-1525", "3872", "22", "4903"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_150" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_150"
  description  = "description: pr-n-mgt_scc-migrated_tcp_150, services: [tcp1433, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_46" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_46"
  description  = "description: pr-n-mgt_scc-migrated_service_46, services: [tcp4371, tcp4372, udp1719]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4371", "4372"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1719"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_6"
  description  = "description: pr-n-mgt_scc-migrated_tcp_6, services: [tcp9100, tcp9191, tcp9194]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9100", "9191", "9194"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_13" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_13"
  description  = "description: pr-n-mgt_scc-migrated_service_13, services: [tcp3389, udp3389, tcp135, tcp445, tcp49152-65535, tcp5985-5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "135", "445", "49152-65535", "5985-5986"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_21"
  description  = "description: pr-n-mgt_scc-migrated_service_21, services: [tcp139, tcp3389, tcp445, tcp1433, udp3389, udp445, tcp135-139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["139", "3389", "445", "1433", "135-139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_18"
  description  = "description: pr-n-mgt_scc-migrated_service_18, services: [tcp-udp3389, tcp1433, tcp1444]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "1433", "1444"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_udp_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_udp_4"
  description  = "description: pr-n-mgt_scc-migrated_udp_4, services: [udp7400, udp2776, udp2777, udp24000-29999, udp3478-3483, udp36000-59999]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["7400", "2776", "2777", "24000-29999", "3478-3483", "36000-59999"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_86" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_86"
  description  = "description: pr-n-mgt_scc-migrated_tcp_86, services: [tcp2222, tcp2776-2777, tcp7001-7999]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2222", "2776-2777", "7001-7999"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_6"
  description  = "description: pr-n-mgt_scc-migrated_service_6, services: [tcp7445, tcp9000, tcp445, tcp80, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7445", "9000", "445", "80", "443", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_1"
  description  = "description: pr-n-mgt_scc-migrated_tcp_1, services: [tcp1433, tcp4343]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "4343"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_whgroup_ad_ports-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whgroup_ad_ports-chg0144834"
  description  = "description: pr-n-mgt_whgroup_ad_ports-chg0144834, services: [tcp-udp53, tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp49152-65525, tcp636, tcp3268-3269, tcp5722, tcp9389, udp137-138]"
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

resource "nsxt_policy_service" "pr-n-mgt_euc_mgmt_port-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_euc_mgmt_port-group-chg0142765"
  description  = "description: pr-n-mgt_euc_mgmt_port-group-chg0142765, services: [tcp135, tcp445, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_splunk_mgmt_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_splunk_mgmt_port-chg0143200"
  description  = "description: pr-n-mgt_splunk_mgmt_port-chg0143200, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_splunk_mgmt_port-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_splunk_mgmt_port-chg0142763"
  description  = "description: pr-n-mgt_splunk_mgmt_port-chg0142763, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_ise-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ise-ports"
  description  = "description: Radius and TACACS ports for ISE AAA, services: [tcp49, udp1645]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1645"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-8400-8403" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-8400-8403"
  description  = "description: CHG0112231, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-9997_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-9997_eq"
  description  = "description: tcp-9997_eq, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_rundeck-winrm-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_rundeck-winrm-ports"
  description  = "description: pr-n-mgt_rundeck-winrm-ports, services: [tcp5985-5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5985-5986"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_wily-outbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wily-outbound-ports"
  description  = "description: pr-n-mgt_wily-outbound-ports, services: [tcp22, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_wily-inbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_wily-inbound-ports"
  description  = "description: pr-n-mgt_wily-inbound-ports, services: [tcp5001]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5001"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_17"
  description  = "description: pr-n-mgt_scc-migrated_tcp_17, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_ldap-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ldap-services"
  description  = "description: CHG0116053, services: [tcp8275, tcp8276]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8275", "8276"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_ossec-client-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_ossec-client-services"
  description  = "description: pr-n-mgt_ossec-client-services, services: [tcp1515, udp1514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1515"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1514"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_whgroup-ad-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_whgroup-ad-ports"
  description  = "description: pr-n-mgt_whgroup-ad-ports, services: [tcp9389, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp88, tcp135, tcp3268-3269, tcp49152-65535, tcp636, tcp139, udp138, udp137, udp123, tcp5722, udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9389", "389", "445", "464", "88", "135", "3268-3269"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "636", "139", "5722"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["389", "445", "464", "88", "138", "137", "123"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_infoblox-standard-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_infoblox-standard-ports"
  description  = "description: pr-n-mgt_infoblox-standard-ports, services: [tcp-udp53, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_58"
  description  = "description: pr-n-mgt_scc-migrated_tcp_58, services: [tcp8530, tcp8531, tcp80, tcp443, tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8530", "8531", "80", "443", "60606"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_splunk-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_splunk-ports"
  description  = "description: pr-n-mgt_splunk-ports, services: [tcp8089, tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089", "9997"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcpudp-514" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcpudp-514"
  description  = "description: pr-n-mgt_tcpudp-514, services: [udp514, tcp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["514"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-48000-48030_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-48000-48030_eq"
  description  = "description: tcp-48000-48030_eq, services: [tcp48000-48030]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["48000-48030"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-383_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-383_eq"
  description  = "description: tcp-383_eq, services: [tcp383]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["383"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_udp-ntp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_udp-ntp_eq"
  description  = "description: udp-ntp_eq, services: [udp123]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-60606_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-60606_eq"
  description  = "description: tcp-60606_eq, services: [tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["60606"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-1688_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-1688_eq"
  description  = "description: tcp-1688_eq, services: [tcp1688]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1688"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_tcp_31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_tcp_31"
  description  = "description: pr-n-mgt_scc-migrated_tcp_31, services: [tcp5671, tcp80, tcp443, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "3129"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_tcp-8082_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_tcp-8082_eq"
  description  = "description: tcp-8082_eq, services: [tcp8082]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8082"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_14"
  description  = "description: pr-n-mgt_scc-migrated_service_14, services: [tcp11433, tcp51083, tcp57324, tcp63480, tcp3307, tcp1234, tcp1433, tcp2345, tcp3306, tcp3456, tcp4301, tcp4302, tcp4303, tcp5401, tcp5402, tcp5403, tcp5432, tcp6503, tcp6543, tcp9876, tcp80, tcp1521, udp161, udp162, tcp443, tcp443, tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["11433", "51083", "57324", "63480", "3307", "1234", "1433"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2345", "3306", "3456", "4301", "4302", "4303", "5401"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5402", "5403", "5432", "6503", "6543", "9876", "80"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521", "443", "443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161", "162", "161"]
  }
}

resource "nsxt_policy_service" "pr-n-mgt_scc-migrated_service_12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-mgt_scc-migrated_service_12"
  description  = "description: pr-n-mgt_scc-migrated_service_12, services: [tcp9070, tcp22, tcp25, tcp-udp53, udp123, udp161, udp162, tcp-udp389, tcp443, tcp444, tcp636, tcp1433, tcp8443, tcp8834, tcp9443, tcp18184, tcp18191, tcp18210]"
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

