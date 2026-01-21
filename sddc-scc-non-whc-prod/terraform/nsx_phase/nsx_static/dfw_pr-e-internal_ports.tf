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

resource "nsxt_policy_service" "pr-e-internal_svc-obj-g-solarwinds" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_svc-obj-g-solarwinds"
  description  = "description: CHG0138766, services: [tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_9"
  description  = "description: pr-e-internal_scc-migrated_tcp_9, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-https_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-https_eq"
  description  = "description: tcp-https_eq, services: [tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-60606_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-60606_eq"
  description  = "description: tcp-60606_eq, services: [tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["60606"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-3306_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-3306_eq"
  description  = "description: tcp-3306_eq, services: [tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-1523_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-1523_eq"
  description  = "description: tcp-1523_eq, services: [tcp1523]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1523"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-9977" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-9977"
  description  = "description: pr-e-internal_tcp-9977, services: [tcp9977]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9977"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-ssh_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-ssh_eq"
  description  = "description: tcp-ssh_eq, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-9070_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-9070_eq"
  description  = "description: tcp-9070_eq, services: [tcp9070]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-3306" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-3306"
  description  = "description: pr-e-internal_tcp-3306, services: [tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-8081_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-8081_eq"
  description  = "description: tcp-8081_eq, services: [tcp8081]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_37"
  description  = "description: pr-e-internal_scc-migrated_service_37, services: [tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_udp-snmp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_udp-snmp_eq"
  description  = "description: udp-snmp_eq, services: [udp161]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_ca-hub-services-group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ca-hub-services-group"
  description  = "description: pr-e-internal_ca-hub-services-group, services: [tcp48000-48030]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["48000-48030"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-873_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-873_eq"
  description  = "description: tcp-873_eq, services: [tcp873]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["873"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-8089_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-8089_eq"
  description  = "description: tcp-8089_eq, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_89"
  description  = "description: pr-e-internal_scc-migrated_tcp_89, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-1433_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-1433_eq"
  description  = "description: tcp-1433_eq, services: [tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_21" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_21"
  description  = "description: pr-e-internal_scc-migrated_service_21, services: [tcp17988, tcp17990, tcp80, tcp443, tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["17988", "17990", "80", "443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_70"
  description  = "description: pr-e-internal_scc-migrated_tcp_70, services: [tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "22"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_25"
  description  = "description: pr-e-internal_scc-migrated_service_25, services: [tcp1433, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_27"
  description  = "description: pr-e-internal_scc-migrated_service_27, services: [tcp17988, tcp17990, tcp80, tcp443, tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["17988", "17990", "80", "443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_29"
  description  = "description: pr-e-internal_scc-migrated_service_29, services: [tcp1444, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1444"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_132" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_132"
  description  = "description: pr-e-internal_scc-migrated_tcp_132, services: [tcp5989, tcp7778]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5989", "7778"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tufincheckpointports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tufincheckpointports"
  description  = "description: pr-e-internal_tufincheckpointports, services: [tcp18184, tcp18190, tcp18210, tcp22, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["18184", "18190", "18210", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-22000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-22000_eq"
  description  = "description: tcp-22000_eq, services: [tcp22000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22000"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-23000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-23000_eq"
  description  = "description: tcp-23000_eq, services: [tcp23000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["23000"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-29000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-29000_eq"
  description  = "description: tcp-29000_eq, services: [tcp29000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["29000"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_3"
  description  = "description: pr-e-internal_scc-migrated_service_3, services: [tcp1433, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_4"
  description  = "description: pr-e-internal_scc-migrated_service_4, services: [tcp1422, tcp30000, udp1434, tcp135, tcp136, tcp137, tcp138, tcp139, tcp3000-3100, tcp445, udp135, udp136, udp137, udp138, udp139, udp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1422", "30000", "135", "136", "137", "138", "139"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3000-3100", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434", "135", "136", "137", "138", "139", "445"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_sql-monitoring" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_sql-monitoring"
  description  = "description: pr-e-internal_sql-monitoring, services: [tcp11433, tcp135, tcp1433, tcp2559, tcp51083, tcp57324, tcp58661, tcp63480, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["11433", "135", "1433", "2559", "51083", "57324", "58661"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["63480"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_5"
  description  = "description: pr-e-internal_scc-migrated_service_5, services: [tcp3307, tcp3308, tcp8066, tcp8080, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3307", "3308", "8066", "8080"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-www_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-www_eq"
  description  = "description: tcp-www_eq, services: [tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_83" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_83"
  description  = "description: pr-e-internal_scc-migrated_service_83, services: [tcp443, udp161]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_25"
  description  = "description: pr-e-internal_scc-migrated_tcp_25, services: [tcp8088, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8088", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_6"
  description  = "description: pr-e-internal_scc-migrated_tcp_6, services: [tcp10301, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10301", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_26"
  description  = "description: pr-e-internal_scc-migrated_tcp_26, services: [tcp8080, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-8500_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-8500_eq"
  description  = "description: tcp-8500_eq, services: [tcp8500]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8500"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-oracle-instances-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-oracle-instances-services"
  description  = "description: pr-e-internal_scc-oracle-instances-services, services: [tcp1521-1525]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521-1525"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_whgroup_ad_ports-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_whgroup_ad_ports-chg0144834"
  description  = "description: pr-e-internal_whgroup_ad_ports-chg0144834, services: [tcp-udp53, tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp49152-65525, tcp636, tcp3268-3269, tcp5722, tcp9389, udp137-138]"
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

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_udp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_udp_1"
  description  = "description: pr-e-internal_scc-migrated_udp_1, services: [udp162, udp514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["162", "514"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-9070" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-9070"
  description  = "description: pr-e-internal_tcp-9070, services: [tcp9070]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-1688_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-1688_eq"
  description  = "description: tcp-1688_eq, services: [tcp1688]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1688"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_15" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_15"
  description  = "description: pr-e-internal_scc-migrated_service_15, services: [tcp2049, tcp111, udp2049, udp111]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2049", "111"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["2049", "111"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-9996_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-9996_eq"
  description  = "description: tcp-9996_eq, services: [tcp9996]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9996"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_nimsoft-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_nimsoft-ports"
  description  = "description: pr-e-internal_nimsoft-ports, services: [tcp48000-48005]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["48000-48005"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_36"
  description  = "description: pr-e-internal_scc-migrated_service_36, services: [tcp-udp135-139, tcp1433, tcp300-3100, tcp30000, tcp49152-65535, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135-139", "1433", "300-3100", "30000", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["135-139", "1434"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_35"
  description  = "description: pr-e-internal_scc-migrated_service_35, services: [tcp4443, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4443", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-8089" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-8089"
  description  = "description: pr-e-internal_tcp-8089, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_splunk_mgmt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_splunk_mgmt"
  description  = "description: CHG0067511, services: [tcp443, tcp22, udp161, udp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "22"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161", "514"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_120"
  description  = "description: pr-e-internal_scc-migrated_tcp_120, services: [tcp17777, tcp445, tcp17778, tcp1801, tcp4369, tcp5671]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["17777", "445", "17778", "1801", "4369", "5671"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_27"
  description  = "description: pr-e-internal_scc-migrated_tcp_27, services: [tcp17777, tcp17778, tcp1801, tcp4369, tcp445, tcp5671]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["17777", "17778", "1801", "4369", "445", "5671"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_12" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_12"
  description  = "description: pr-e-internal_scc-migrated_service_12, services: [tcp1433, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_125" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_125"
  description  = "description: pr-e-internal_scc-migrated_tcp_125, services: [tcp3129, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3129", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_22"
  description  = "description: pr-e-internal_scc-migrated_tcp_22, services: [tcp3129, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3129", "80"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_maria-db-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_maria-db-services"
  description  = "description: pr-e-internal_maria-db-services, services: [tcp3306, tcp4444, tcp4567, tcp4568, udp4567]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306", "4444", "4567", "4568"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["4567"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_euc_mgmt_port-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_euc_mgmt_port-group-chg0142765"
  description  = "description: pr-e-internal_euc_mgmt_port-group-chg0142765, services: [tcp135, tcp445, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_splunk_indexing_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_splunk_indexing_port-chg0143200"
  description  = "description: pr-e-internal_splunk_indexing_port-chg0143200, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_splunk_mgmt_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_splunk_mgmt_port-chg0143200"
  description  = "description: pr-e-internal_splunk_mgmt_port-chg0143200, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-8400-8403" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-8400-8403"
  description  = "description: CHG0112231, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_ad-global-rule-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ad-global-rule-ports"
  description  = "description: pr-e-internal_ad-global-rule-ports, services: [tcp9389, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp49152-65535, tcp-udp88, tcp135, tcp3268-3269, tcp5722, tcp636, tcp139, udp138, udp137, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9389", "389", "445", "464", "49152-65535", "88", "135"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3268-3269", "5722", "636", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["389", "445", "464", "49152-65535", "88", "138", "137"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_wily-outbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_wily-outbound-ports"
  description  = "description: pr-e-internal_wily-outbound-ports, services: [tcp22, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_wily-inbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_wily-inbound-ports"
  description  = "description: pr-e-internal_wily-inbound-ports, services: [tcp5001, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5001", "80"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_rundeck-winrm-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_rundeck-winrm-ports"
  description  = "description: pr-e-internal_rundeck-winrm-ports, services: [tcp5985-5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5985-5986"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_infoblox-standard-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_infoblox-standard-ports"
  description  = "description: pr-e-internal_infoblox-standard-ports, services: [tcp-udp53, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-smtp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-smtp_eq"
  description  = "description: tcp-smtp_eq, services: [tcp25]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["25"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_6"
  description  = "description: pr-e-internal_scc-migrated_service_6, services: [tcp8089, tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089", "9997"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_4"
  description  = "description: pr-e-internal_scc-migrated_tcp_4, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_ldap-service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_ldap-service"
  description  = "description: CHG0116053, services: [tcp8275, tcp8276]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8275", "8276"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_8089" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_8089"
  description  = "description: pr-e-internal_8089, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_11"
  description  = "description: pr-e-internal_scc-migrated_service_11, services: [tcp-udp9997, tcp-udp53, udp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997", "53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["9997", "53", "514"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_8"
  description  = "description: pr-e-internal_scc-migrated_service_8, services: [tcp3306, tcp11433, tcp3307, tcp51083, tcp57324, tcp63480, tcp3308, tcp1521, udp161, udp162, tcp1433, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306", "11433", "3307", "51083", "57324", "63480", "3308"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521", "1433", "80", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161", "162"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_udp-syslog_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_udp-syslog_eq"
  description  = "description: udp-syslog_eq, services: [udp514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_service_10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_service_10"
  description  = "description: pr-e-internal_scc-migrated_service_10, services: [tcp-udp9997, tcp-udp53, udp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997", "53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["9997", "53", "514"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_tcp-3389" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_tcp-3389"
  description  = "description: pr-e-internal_tcp-3389, services: [tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_scc-migrated_tcp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_scc-migrated_tcp_1"
  description  = "description: pr-e-internal_scc-migrated_tcp_1, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-e-internal_solarwinds-netflow" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-e-internal_solarwinds-netflow"
  description  = "description: pr-e-internal_solarwinds-netflow, services: [udp2055]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["2055"]
  }
}

