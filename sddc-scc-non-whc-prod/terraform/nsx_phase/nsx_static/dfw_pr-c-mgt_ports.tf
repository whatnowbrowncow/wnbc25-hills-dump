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

resource "nsxt_policy_service" "pr-c-mgt_katello-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_katello-ports"
  description  = "description: CHG0067823, services: [tcp80, tcp443, tcp5671, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "5671", "3129"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_cellmgmt-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_cellmgmt-ports"
  description  = "description: CHG0068990, services: [tcp22, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_38"
  description  = "description: pr-c-mgt_scc-migrated_service_38, services: [tcp5050, tcp9955, tcp9977]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5050", "9955", "9977"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_stingray-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_stingray-ports"
  description  = "description: CHG0068990, CHG0071650, services: [tcp9090, tcp9070]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9090", "9070"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp_8140" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp_8140"
  description  = "description: pr-c-mgt_tcp_8140, services: [tcp8140]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8140"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_42"
  description  = "description: pr-c-mgt_scc-migrated_service_42, services: [tcp5900, tcp444, tcp443, tcp7578, tcp5120, tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5900", "444", "443", "7578", "5120", "8443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_hp-oneview-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_hp-oneview-access"
  description  = "description: pr-c-mgt_hp-oneview-access, services: [tcp80, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_checkpoint-user-mgmt-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_checkpoint-user-mgmt-ports"
  description  = "description: pr-c-mgt_checkpoint-user-mgmt-ports, services: [tcp18190, tcp18264, tcp18265, tcp8443, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18190", "18264", "18265", "8443", "443", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-8080-1521" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-8080-1521"
  description  = "description: CHG0123808, services: [tcp8080, tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "1521"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_73" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_73"
  description  = "description: pr-c-mgt_scc-migrated_tcp_73, services: [tcp8443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-8443_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-8443_eq"
  description  = "description: tcp-8443_eq, services: [tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_301" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_301"
  description  = "description: pr-c-mgt_scc-migrated_tcp_301, services: [tcp3389, tcp8000, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "8000", "443", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_305" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_305"
  description  = "description: pr-c-mgt_scc-migrated_tcp_305, services: [tcp8443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_30"
  description  = "description: pr-c-mgt_scc-migrated_tcp_30, services: [tcp8443, tcp22, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "22", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_40"
  description  = "description: pr-c-mgt_scc-migrated_service_40, services: [tcp3389, tcp5986, udp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "5986"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_44"
  description  = "description: pr-c-mgt_scc-migrated_tcp_44, services: [tcp8443, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_15"
  description  = "description: pr-c-mgt_scc-migrated_service_15, services: [tcp902, tcp443, tcp22, tcp7444]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["902", "443", "22", "7444"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_54"
  description  = "description: pr-c-mgt_scc-migrated_tcp_54, services: [tcp8443, tcp443, tcp22, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "443", "22", "23"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-7778_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-7778_eq"
  description  = "description: tcp-7778_eq, services: [tcp7778]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7778"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_37"
  description  = "description: pr-c-mgt_scc-migrated_tcp_37, services: [tcp8443, tcp80, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "80", "443", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_24"
  description  = "description: pr-c-mgt_scc-migrated_tcp_24, services: [tcp5671, tcp80, tcp443, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "3129"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-5001_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-5001_eq"
  description  = "description: tcp-5001_eq, services: [tcp5001]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5001"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-ssh_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-ssh_eq"
  description  = "description: tcp-ssh_eq, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-8089_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-8089_eq"
  description  = "description: tcp-8089_eq, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcpudp-514" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcpudp-514"
  description  = "description: pr-c-mgt_tcpudp-514, services: [udp514, tcp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["514"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_29"
  description  = "description: pr-c-mgt_scc-migrated_tcp_29, services: [tcp8080, tcp8182, tcp8443, tcp8765, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "8182", "8443", "8765", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-nas-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-nas-ports"
  description  = "description: pr-c-mgt_scc-nas-ports, services: [tcp-udp2049, tcp-udp111, tcp-udp1039, tcp-udp1047, tcp-udp1048, tcp-udp1110, tcp-udp300, tcp-udp302, tcp-udp304, tcp-udp4045]"
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

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_42"
  description  = "description: pr-c-mgt_scc-migrated_tcp_42, services: [tcp5671, tcp80, tcp443, tcp3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "3129"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-www_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-www_eq"
  description  = "description: tcp-www_eq, services: [tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_udp_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_udp_8"
  description  = "description: pr-c-mgt_scc-migrated_udp_8, services: [udp161, udp162]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161", "162"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-ldap_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-ldap_eq"
  description  = "description: tcp-ldap_eq, services: [tcp389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["389"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_49" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_49"
  description  = "description: pr-c-mgt_scc-migrated_service_49, services: [tcp514, udp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["514"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_48"
  description  = "description: pr-c-mgt_scc-migrated_service_48, services: [tcp514, udp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["514"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_17"
  description  = "description: pr-c-mgt_scc-migrated_tcp_17, services: [tcp8100, tcp8101]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8100", "8101"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-8088_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-8088_eq"
  description  = "description: tcp-8088_eq, services: [tcp8088]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8088"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_25"
  description  = "description: pr-c-mgt_scc-migrated_tcp_25, services: [tcp8443, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_cde-mgmt-nets-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_cde-mgmt-nets-services"
  description  = "description: pr-c-mgt_cde-mgmt-nets-services, services: [tcp17988, tcp17990, tcp902, tcp3389, tcp9443, tcp8443, tcp9090, tcp9031, tcp9999, tcp443, tcp80, tcp22, udp161, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["17988", "17990", "902", "3389", "9443", "8443", "9090"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9031", "9999", "443", "80", "22", "5986"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-https_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-https_eq"
  description  = "description: tcp-https_eq, services: [tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_32"
  description  = "description: pr-c-mgt_scc-migrated_tcp_32, services: [tcp8443, tcp9443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "9443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_33" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_33"
  description  = "description: pr-c-mgt_scc-migrated_tcp_33, services: [tcp10000, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10000", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_35"
  description  = "description: pr-c-mgt_scc-migrated_tcp_35, services: [tcp8443, tcp9090, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "9090", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_36"
  description  = "description: pr-c-mgt_scc-migrated_tcp_36, services: [tcp18079-18089, tcp2383, tcp3128, tcp3129, tcp4440, tcp4443, tcp5001, tcp5250, tcp54331, tcp54332, tcp54333, tcp5567, tcp7001, tcp7803, tcp8000, tcp8080, tcp8081, tcp8082, tcp8443, tcp8444, tcp8445, tcp9090, tcp9645, tcp21, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18079-18089", "2383", "3128", "3129", "4440", "4443", "5001"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5250", "54331", "54332", "54333", "5567", "7001", "7803"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8000", "8080", "8081", "8082", "8443", "8444", "8445"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9090", "9645", "21", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_29"
  description  = "description: pr-c-mgt_scc-migrated_service_29, services: [tcp5480, tcp8084, tcp902, tcp9080, tcp9084, tcp80, tcp443, tcp22, udp902]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5480", "8084", "902", "9080", "9084", "80", "443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["902"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_ilo-access-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ilo-access-ports"
  description  = "description: pr-c-mgt_ilo-access-ports, services: [tcp17988, tcp17990, tcp80, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["17988", "17990", "80", "443", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-9084_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-9084_eq"
  description  = "description: tcp-9084_eq, services: [tcp9084]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9084"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_7"
  description  = "description: pr-c-mgt_scc-migrated_service_7, services: [tcp902, udp902]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["902"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["902"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-60606_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-60606_eq"
  description  = "description: tcp-60606_eq, services: [tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["60606"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-22-3389" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-22-3389"
  description  = "description: CHG0114077, services: [tcp3389, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tufincheckpointports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tufincheckpointports"
  description  = "description: CHG0054399, services: [tcp18184, tcp18190, tcp18210, udp161, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18184", "18190", "18210", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_checkpointmanagmentports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_checkpointmanagmentports"
  description  = "description: CHG0038670, services: [tcp18184, tcp18190, tcp18210]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18184", "18190", "18210"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_rsa-new-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_rsa-new-services"
  description  = "description: pr-c-mgt_rsa-new-services, services: [tcp1812, tcp1813, tcp2334, tcp5506, tcp5560, tcp7002, tcp7004, tcp7082, udp1812, udp5500, tcp5550, tcp5580, udp5550]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1812", "1813", "2334", "5506", "5560", "7002", "7004"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7082", "5550", "5580"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1812", "5500", "5550"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_sc1-solarwindsports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_sc1-solarwindsports"
  description  = "description: CHG0035636, services: [udp9991, udp161, udp162]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["9991", "161", "162"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_45"
  description  = "description: pr-c-mgt_scc-migrated_service_45, services: [tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_udp-snmp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_udp-snmp_eq"
  description  = "description: udp-snmp_eq, services: [udp161]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_21"
  description  = "description: pr-c-mgt_scc-migrated_service_21, services: [tcp50123, tcp50124, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50123", "50124", "80"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_19"
  description  = "description: pr-c-mgt_scc-migrated_service_19, services: [udp161, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_grp-pr-c-altris-task-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp-pr-c-altris-task-ports"
  description  = "description: CHG0018071, services: [tcp50124, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50124", "80"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_grp-pr-c-ad-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_grp-pr-c-ad-ports"
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

resource "nsxt_policy_service" "pr-c-mgt_udp-tftp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_udp-tftp_eq"
  description  = "description: udp-tftp_eq, services: [udp69]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["69"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_hp-irs-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_hp-irs-ports"
  description  = "description: pr-c-mgt_hp-irs-ports, services: [tcp5989, tcp7, udp161, tcp2301, tcp2381, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5989", "7", "2301", "2381", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_1"
  description  = "description: CHG0131744, services: [tcp443, tcp22, tcp18190, tcp8443, tcp18264, tcp18265, tcp2068]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "22", "18190", "8443", "18264", "18265", "2068"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_whapi-access-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_whapi-access-ports"
  description  = "description: pr-c-mgt_whapi-access-ports, services: [tcp8443, tcp9443, tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "9443", "8080"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_97"
  description  = "description: pr-c-mgt_scc-migrated_tcp_97, services: [tcp8443, tcp9443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "9443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_99"
  description  = "description: pr-c-mgt_scc-migrated_tcp_99, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_58" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_58"
  description  = "description: pr-c-mgt_scc-migrated_tcp_58, services: [tcp80, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_72"
  description  = "description: pr-c-mgt_scc-migrated_tcp_72, services: [tcp9070, tcp9090, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070", "9090", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_66"
  description  = "description: pr-c-mgt_scc-migrated_tcp_66, services: [tcp18191, tcp257]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18191", "257"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_92" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_92"
  description  = "description: pr-c-mgt_scc-migrated_tcp_92, services: [tcp18191, tcp257, tcp18264]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18191", "257", "18264"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_93" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_93"
  description  = "description: pr-c-mgt_scc-migrated_tcp_93, services: [tcp18191, tcp257]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18191", "257"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_checkpoint-mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_checkpoint-mgmt"
  description  = "description: pr-c-mgt_checkpoint-mgmt, services: [tcp256, tcp18202, tcp18266, tcp18191, tcp18192, tcp18208, tcp18183, tcp18221, tcp18211, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["256", "18202", "18266", "18191", "18192", "18208", "18183"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18221", "18211", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_provider-1-mgt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_provider-1-mgt"
  description  = "description: pr-c-mgt_provider-1-mgt, services: [tcp18190, tcp18191, tcp18192, tcp18209, tcp18210, tcp18211, tcp18221, tcp256]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18190", "18191", "18192", "18209", "18210", "18211", "18221"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["256"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-3389_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-3389_eq"
  description  = "description: tcp-3389_eq, services: [tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_128" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_128"
  description  = "description: pr-c-mgt_scc-migrated_tcp_128, services: [tcp9070, tcp9090]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070", "9090"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-9090-9070" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-9090-9070"
  description  = "description: pr-c-mgt_tcp-9090-9070, services: [tcp9070, tcp9090]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070", "9090"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-9090_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-9090_eq"
  description  = "description: tcp-9090_eq, services: [tcp9090]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9090"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-1526_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-1526_eq"
  description  = "description: tcp-1526_eq, services: [tcp1526]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1526"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-9070_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-9070_eq"
  description  = "description: tcp-9070_eq, services: [tcp9070]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_85" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_85"
  description  = "description: pr-c-mgt_scc-migrated_tcp_85, services: [tcp8000, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8000", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcpudp-623" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcpudp-623"
  description  = "description: pr-c-mgt_tcpudp-623, services: [udp623, tcp623]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["623"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["623"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_networkmanagementports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_networkmanagementports"
  description  = "description: CHG0056783, services: [tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_storage-mgt-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_storage-mgt-ports"
  description  = "description: pr-c-mgt_storage-mgt-ports, services: [tcp21, tcp22, tcp80, tcp443, tcp2162, tcp2163, tcp5201, tcp5414, tcp8000, tcp6389-6392, tcp9519, tcp13456, tcp60020]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "22", "80", "443", "2162", "2163", "5201"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5414", "8000", "6389-6392", "9519", "13456", "60020"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_vr-ops" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vr-ops"
  description  = "description: pr-c-mgt_vr-ops, services: [tcp10000-10010, tcp20000-20010, tcp5433, tcp5480, tcp6061, tcp80, tcp443, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10000-10010", "20000-20010", "5433", "5480", "6061", "80", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_brsdatafabman01_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_brsdatafabman01_ports"
  description  = "description: pr-c-mgt_brsdatafabman01_ports, services: [tcp-udp161, tcp-udp162, tcp-udp22, tcp-udp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["161", "162", "22", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161", "162", "22", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_cisco_dcmn_ports_monitoring" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_cisco_dcmn_ports_monitoring"
  description  = "description: pr-c-mgt_cisco_dcmn_ports_monitoring, services: [tcp-udp1162-1170, tcp-udp9100, tcp-udp4447, tcp-udp2162]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1162-1170", "9100", "4447", "2162"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1162-1170", "9100", "4447", "2162"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_splunk-xiv-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_splunk-xiv-ports"
  description  = "description: CHG0075038, services: [tcp5989, tcp7778]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5989", "7778"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_perf_metrics_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_perf_metrics_ports"
  description  = "description: Ports for collecting various performance metrics from devices, services: [tcp8443, tcp443, tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_udp-623_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_udp-623_eq"
  description  = "description: udp-623_eq, services: [udp623]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["623"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_mailhostports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_mailhostports"
  description  = "description: pr-c-mgt_mailhostports, services: [tcp10000, tcp10010, tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10000", "10010", "3306"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-10000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-10000_eq"
  description  = "description: tcp-10000_eq, services: [tcp10000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10000"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp_8182_8675" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp_8182_8675"
  description  = "description: pr-c-mgt_tcp_8182_8675, services: [tcp8182, tcp8675]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8182", "8675"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_38"
  description  = "description: pr-c-mgt_scc-migrated_tcp_38, services: [tcp8000, tcp8834]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8000", "8834"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_30"
  description  = "description: pr-c-mgt_scc-migrated_service_30, services: [tcp10022, tcp8400, tcp8401, tcp8402, tcp8403, tcp902, tcp443, tcp2049, tcp111, udp111]"
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

resource "nsxt_policy_service" "pr-c-mgt_comm_vault_service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_comm_vault_service"
  description  = "description: pr-c-mgt_comm_vault_service, services: [tcp10022, tcp902, tcp443, tcp2049, tcp111, udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10022", "902", "443", "2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["111"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcpudp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcpudp"
  description  = "description: pr-c-mgt_tcpudp, services: [udp, tcp]"
  ip_protocol_entry {
    display_name = "udp"
    protocol     = "17"
  }
  ip_protocol_entry {
    display_name = "tcp"
    protocol     = "6"
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-udp-623" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-udp-623"
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

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_63"
  description  = "description: pr-c-mgt_scc-migrated_tcp_63, services: [tcp8080, tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "8443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_vmware-tcp-groups" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmware-tcp-groups"
  description  = "description: CHG0115599, services: [tcp11711, tcp11712, tcp1514, tcp2012, tcp2014, tcp2020, tcp5480, tcp6500, tcp6501, tcp6502, tcp7444, tcp8088, tcp88, tcp902, tcp903, tcp9443, tcp80, tcp443, tcp389, tcp636, tcp514, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["11711", "11712", "1514", "2012", "2014", "2020", "5480"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["6500", "6501", "6502", "7444", "8088", "88", "902"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["903", "9443", "80", "443", "389", "636", "514"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_web-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_web-ports"
  description  = "description: pr-c-mgt_web-ports, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_211" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_211"
  description  = "description: pr-c-mgt_scc-migrated_service_211, services: [tcp623, udp623, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["623", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["623"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-9070" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-9070"
  description  = "description: pr-c-mgt_tcp-9070, services: [tcp9070]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_solarwinds-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_solarwinds-ports"
  description  = "description: CHG0132371, services: [tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_2"
  description  = "description: pr-c-mgt_scc-migrated_service_2, services: [tcp443, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_zabbix-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_zabbix-ports"
  description  = "description: CHG0121232, services: [tcp10050, tcp10051]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10050", "10051"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_82"
  description  = "description: pr-c-mgt_scc-migrated_tcp_82, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_4"
  description  = "description: pr-c-mgt_scc-migrated_tcp_4, services: [tcp902, tcp903, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["902", "903", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_6"
  description  = "description: pr-c-mgt_scc-migrated_tcp_6, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_9"
  description  = "description: pr-c-mgt_scc-migrated_tcp_9, services: [tcp8088, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8088", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_10"
  description  = "description: pr-c-mgt_scc-migrated_tcp_10, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_14"
  description  = "description: pr-c-mgt_scc-migrated_tcp_14, services: [tcp9100, tcp9191, tcp9194]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9100", "9191", "9194"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_26"
  description  = "description: pr-c-mgt_scc-migrated_tcp_26, services: [tcp8443, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_23"
  description  = "description: pr-c-mgt_scc-migrated_service_23, services: [tcp31031, tcp44046, tcp4500, tcp8043, tcp9086, tcp443, udp4500, udp500]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["31031", "44046", "4500", "8043", "9086", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["4500", "500"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-whc-prod-vmc-service-grp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-whc-prod-vmc-service-grp"
  description  = "description: pr-c-mgt_scc-whc-prod-vmc-service-grp, services: [tcp10000-10010, tcp20000-20010, tcp5433, tcp5480, tcp6061, tcp80, tcp443, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10000-10010", "20000-20010", "5433", "5480", "6061", "80", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-31031_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-31031_eq"
  description  = "description: tcp-31031_eq, services: [tcp31031]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["31031"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_cisco_dcmn_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_cisco_dcmn_ports"
  description  = "description: pr-c-mgt_cisco_dcmn_ports, services: [tcp-udp1162-1170, tcp-udp22, tcp-udp80, tcp-udp443, tcp-udp161, tcp-udp514, tcp-udp2162, tcp-udp4447, tcp-udp5457, tcp-udp5455]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1162-1170", "22", "80", "443", "161", "514", "2162"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4447", "5457", "5455"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1162-1170", "22", "80", "443", "161", "514", "2162"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["4447", "5457", "5455"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_11"
  description  = "description: pr-c-mgt_scc-migrated_service_11, services: [tcp8043, tcp9086, tcp31031, tcp44046, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8043", "9086", "31031", "44046", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_whgroup_ad_ports-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_whgroup_ad_ports-chg0144834"
  description  = "description: pr-c-mgt_whgroup_ad_ports-chg0144834, services: [tcp-udp53, tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp49152-65525, tcp636, tcp3268-3269, tcp5722, tcp9389, udp137-138]"
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

resource "nsxt_policy_service" "pr-c-mgt_euc_mgmt_port-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_euc_mgmt_port-group-chg0142765"
  description  = "description: pr-c-mgt_euc_mgmt_port-group-chg0142765, services: [tcp135, tcp445, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_splunk_indexing_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_splunk_indexing_port-chg0143200"
  description  = "description: pr-c-mgt_splunk_indexing_port-chg0143200, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_splunk_mgmt_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_splunk_mgmt_port-chg0143200"
  description  = "description: pr-c-mgt_splunk_mgmt_port-chg0143200, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_splunk_indexing_port-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_splunk_indexing_port-chg0142763"
  description  = "description: pr-c-mgt_splunk_indexing_port-chg0142763, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_splunk_mgmt_port-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_splunk_mgmt_port-chg0142763"
  description  = "description: pr-c-mgt_splunk_mgmt_port-chg0142763, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_ise-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ise-ports"
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

resource "nsxt_policy_service" "pr-c-mgt_tcp8400-8403" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp8400-8403"
  description  = "description: CHG0112231, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_udp-syslog_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_udp-syslog_eq"
  description  = "description: udp-syslog_eq, services: [udp514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_4"
  description  = "description: pr-c-mgt_scc-migrated_service_4, services: [tcp9997, udp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_rundeck-winrm-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_rundeck-winrm-ports"
  description  = "description: pr-c-mgt_rundeck-winrm-ports, services: [tcp5985-5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5985-5986"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_27"
  description  = "description: pr-c-mgt_scc-migrated_tcp_27, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_8089" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_8089"
  description  = "description: pr-c-mgt_8089, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_ldap-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ldap-services"
  description  = "description: pr-c-mgt_ldap-services, services: [tcp8275, tcp8276]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8275", "8276"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_wily-outbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wily-outbound-ports"
  description  = "description: pr-c-mgt_wily-outbound-ports, services: [tcp22, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_wily-inbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_wily-inbound-ports"
  description  = "description: pr-c-mgt_wily-inbound-ports, services: [tcp5001]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5001"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-smtp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-smtp_eq"
  description  = "description: tcp-smtp_eq, services: [tcp25]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["25"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_hp-oneview-client-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_hp-oneview-client-services"
  description  = "description: Inbound Connections from client to server, services: [tcp5671, tcp80, tcp443, udp2162, udp123, udp162, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5671", "80", "443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["2162", "123", "162"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_hp-oneview-server-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_hp-oneview-server-services"
  description  = "description: Outbound Connections from server to Client, services: [tcp17988, tcp17990, tcp80, tcp443, udp161, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["17988", "17990", "80", "443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_ossec-client-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_ossec-client-services"
  description  = "description: pr-c-mgt_ossec-client-services, services: [tcp1515, udp1514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1515"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1514"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_5"
  description  = "description: pr-c-mgt_scc-migrated_service_5, services: [udp123, udp137, udp138, tcp135, tcp636, tcp-udp464, tcp-udp389, tcp-udp445, tcp-udp88, tcp3268-3269, tcp5722, tcp139, udp53, tcp-udp49152-65535, tcp9389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "636", "464", "389", "445", "88", "3268-3269"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5722", "139", "49152-65535", "9389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123", "137", "138", "464", "389", "445", "88"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_vcenteruseraccess" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vcenteruseraccess"
  description  = "description: pr-c-mgt_vcenteruseraccess, services: [tcp-udp1514, tcp-udp2020, tcp-udp389, tcp-udp514, tcp-udp6500, tcp-udp902, tcp11711-11712, tcp2012, tcp2014, tcp5480, tcp6501-6502, tcp7444, tcp8088, tcp88, tcp903, tcp9443, tcp80, tcp443, tcp636, tcp-udp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1514", "2020", "389", "514", "6500", "902", "11711-11712"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2012", "2014", "5480", "6501-6502", "7444", "8088", "88"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["903", "9443", "80", "443", "636", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1514", "2020", "389", "514", "6500", "902", "22"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_vmware-access-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_vmware-access-ports"
  description  = "description: pr-c-mgt_vmware-access-ports, services: [tcp-udp10000-10010, tcp-udp1514, tcp-udp20000-20010, tcp-udp2020, tcp-udp902, tcp10080, tcp10443, tcp11711-11712, tcp3091-3094, tcp3389, tcp5480, tcp7331, tcp7343, tcp7444, tcp8084, tcp903, tcp9084, tcp9090, tcp9443, tcp80, tcp443, tcp22, tcp6501-6502, tcp8000-8001, tcp8543, tcp8580, tcp9000-9100, tcp51914-51915, tcp636, tcp-udp88, tcp-udp389, tcp8080, tcp-udp6500, tcp12721, tcp7080-7081, tcp9087, tcp-udp750, tcp8009, tcp31031, tcp44046, tcp8123, udp4011, udp67, udp69, tcp-udp6061, tcp7580, tcp8444, tcp-udp427, tcp-udp514, tcp-udp8100, tcp-udp8200-8201, tcp-udp8300-8303, tcp1234-1235, tcp2012-2015, tcp2233, tcp49000-65000, tcp5671, tcp5900-5964, tcp7005, tcp7009, tcp8088-8089, tcp8889, tcp9080, tcp9123, udp12345, udp23451, tcp5988-5989, udp12321]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10000-10010", "1514", "20000-20010", "2020", "902", "10080", "10443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["11711-11712", "3091-3094", "3389", "5480", "7331", "7343", "7444"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8084", "903", "9084", "9090", "9443", "80", "443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "6501-6502", "8000-8001", "8543", "8580", "9000-9100", "51914-51915"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["636", "88", "389", "8080", "6500", "12721", "7080-7081"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9087", "750", "8009", "31031", "44046", "8123", "6061"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7580", "8444", "427", "514", "8100", "8200-8201", "8300-8303"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1234-1235", "2012-2015", "2233", "49000-65000", "5671", "5900-5964", "7005"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7009", "8088-8089", "8889", "9080", "9123", "5988-5989"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["10000-10010", "1514", "20000-20010", "2020", "902", "88", "389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["6500", "750", "4011", "67", "69", "6061", "427"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514", "8100", "8200-8201", "8300-8303", "12345", "23451", "12321"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_infoblox-standard-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_infoblox-standard-ports"
  description  = "description: pr-c-mgt_infoblox-standard-ports, services: [tcp-udp53, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcpudp-domain" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcpudp-domain"
  description  = "description: pr-c-mgt_tcpudp-domain, services: [udp53, tcp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_120"
  description  = "description: pr-c-mgt_scc-migrated_tcp_120, services: [tcp8530, tcp8531, tcp80, tcp443, tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8530", "8531", "80", "443", "60606"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_121"
  description  = "description: pr-c-mgt_scc-migrated_tcp_121, services: [tcp4343, tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4343", "8080"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_udp-ntp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_udp-ntp_eq"
  description  = "description: udp-ntp_eq, services: [udp123]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_90" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_90"
  description  = "description: pr-c-mgt_scc-migrated_tcp_90, services: [tcp60606, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["60606", "80"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_tcp_91" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_tcp_91"
  description  = "description: pr-c-mgt_scc-migrated_tcp_91, services: [tcp3129, tcp5671, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3129", "5671", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-48000-48030_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-48000-48030_eq"
  description  = "description: tcp-48000-48030_eq, services: [tcp48000-48030]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["48000-48030"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_8"
  description  = "description: pr-c-mgt_scc-migrated_service_8, services: [udp514, tcp443, tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514", "161"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_tcp-8083_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_tcp-8083_eq"
  description  = "description: tcp-8083_eq, services: [tcp8083]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8083"]
  }
}

resource "nsxt_policy_service" "pr-c-mgt_scc-migrated_service_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-c-mgt_scc-migrated_service_1"
  description  = "description: pr-c-mgt_scc-migrated_service_1, services: [tcp9070, tcp22, tcp25, tcp-udp53, udp123, udp161, udp162, tcp-udp389, tcp443, tcp444, tcp636, tcp1433, tcp8443, tcp8834, tcp9443, tcp18184, tcp18191, tcp18210, tcp18190]"
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
    destination_ports = ["18210", "18190"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123", "161", "162", "389"]
  }
}

