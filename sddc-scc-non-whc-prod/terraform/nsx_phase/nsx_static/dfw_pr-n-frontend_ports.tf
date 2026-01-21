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

resource "nsxt_policy_service" "pr-n-frontend_infoblox-vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_infoblox-vpn"
  description  = "description: pr-n-frontend_infoblox-vpn, services: [udp1194, udp2114]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1194", "2114"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_udp-snmptrap_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_udp-snmptrap_eq"
  description  = "description: udp-snmptrap_eq, services: [udp162]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["162"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-9997_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-9997_eq"
  description  = "description: tcp-9997_eq, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-2222_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-2222_eq"
  description  = "description: tcp-2222_eq, services: [tcp2222]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2222"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_web-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_web-ports"
  description  = "description: pr-n-frontend_web-ports, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_infoblox-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_infoblox-ports"
  description  = "description: pr-n-frontend_infoblox-ports, services: [tcp-udp53, tcp-udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "123"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_dns" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_dns"
  description  = "description: pr-n-frontend_dns, services: [tcp-udp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_ftp-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_ftp-ports"
  description  = "description: pr-n-frontend_ftp-ports, services: [tcp21, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_3rdparties" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_3rdparties"
  description  = "description: pr-n-frontend_3rdparties, services: [tcp22, tcp843, tcp389, tcp444, tcp2156, tcp3128, tcp4002, tcp4007, tcp4009, tcp8014, tcp8080, tcp8443, tcp5119, tcp23560, tcp9000, tcp10020, tcp16010, tcp16400, tcp29002, tcp29005, tcp29006]"
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

resource "nsxt_policy_service" "pr-n-frontend_udp-ntp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_udp-ntp_eq"
  description  = "description: udp-ntp_eq, services: [udp123]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-ssh_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-ssh_eq"
  description  = "description: tcp-ssh_eq, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_24"
  description  = "description: pr-n-frontend_scc-migrated_service_24, services: [tcp445, tcp139, udp138, udp137]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["138", "137"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_41"
  description  = "description: pr-n-frontend_scc-migrated_service_41, services: [tcp4443, tcp2222]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4443", "2222"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_171" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_171"
  description  = "description: pr-n-frontend_scc-migrated_tcp_171, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_95" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_95"
  description  = "description: pr-n-frontend_scc-migrated_tcp_95, services: [tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_176" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_176"
  description  = "description: pr-n-frontend_scc-migrated_tcp_176, services: [tcp135-139, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135-139", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-10201-10500_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-10201-10500_eq"
  description  = "description: tcp-10201-10500_eq, services: [tcp10201-10500]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10201-10500"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1433_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1433_eq"
  description  = "description: tcp-1433_eq, services: [tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_48" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_48"
  description  = "description: pr-n-frontend_scc-migrated_tcp_48, services: [tcp137, tcp138, tcp8474, tcp8476, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "138", "8474", "8476", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3306_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3306_eq"
  description  = "description: tcp-3306_eq, services: [tcp3306]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-sqlnet_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-sqlnet_eq"
  description  = "description: tcp-sqlnet_eq, services: [tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8080_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8080_eq"
  description  = "description: tcp-8080_eq, services: [tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_udp-5001-5003_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_udp-5001-5003_eq"
  description  = "description: udp-5001-5003_eq, services: [udp5001-5003]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["5001-5003"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_bacs-transfer" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_bacs-transfer"
  description  = "description: CHG0074764, services: [tcp449, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp23, tcp445, tcp139, udp135, udp138, udp137]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["449", "8470", "8471", "8472", "8473", "8474", "8475"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8476", "23", "445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["135", "138", "137"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_qlickview_ports_udp_tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_qlickview_ports_udp_tcp"
  description  = "description: pr-n-frontend_qlickview_ports_udp_tcp, services: [tcp4730, tcp4747, tcp4750, tcp445, tcp137, tcp138, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4730", "4747", "4750", "445", "137", "138", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-smtp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-smtp_eq"
  description  = "description: tcp-smtp_eq, services: [tcp25]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["25"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-www_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-www_eq"
  description  = "description: tcp-www_eq, services: [tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-9997" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-9997"
  description  = "description: pr-n-frontend_tcp-9997, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-https_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-https_eq"
  description  = "description: tcp-https_eq, services: [tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_105" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_105"
  description  = "description: pr-n-frontend_scc-migrated_tcp_105, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_449" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_449"
  description  = "description: pr-n-frontend_scc-migrated_service_449, services: [tcp443, tcp139, udp138, udp137, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443", "139", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["138", "137"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_43"
  description  = "description: pr-n-frontend_scc-migrated_service_43, services: [tcp8000, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8000", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_172" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_172"
  description  = "description: pr-n-frontend_scc-migrated_tcp_172, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_mi-app-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_mi-app-ports"
  description  = "description: pr-n-frontend_mi-app-ports, services: [tcp6400-6410]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["6400-6410"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_486" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_486"
  description  = "description: pr-n-frontend_scc-migrated_tcp_486, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1522_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1522_eq"
  description  = "description: tcp-1522_eq, services: [tcp1522]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1522"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_36" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_36"
  description  = "description: pr-n-frontend_scc-migrated_tcp_36, services: [tcp1528, tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1528", "1521"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-ftp_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-ftp_eq"
  description  = "description: tcp-ftp_eq, services: [tcp21]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_34" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_34"
  description  = "description: pr-n-frontend_scc-migrated_tcp_34, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1528_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1528_eq"
  description  = "description: tcp-1528_eq, services: [tcp1528]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1528"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_2"
  description  = "description: pr-n-frontend_scc-migrated_tcp_2, services: [tcp4730, tcp4747, tcp4750]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4730", "4747", "4750"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_23" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_23"
  description  = "description: pr-n-frontend_scc-migrated_tcp_23, services: [tcp4730, tcp4747, tcp4750]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4730", "4747", "4750"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_20" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_20"
  description  = "description: pr-n-frontend_scc-migrated_tcp_20, services: [tcp4720, tcp4730, tcp4747, tcp4774, tcp4799, tcp4750]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4720", "4730", "4747", "4774", "4799", "4750"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_106" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_106"
  description  = "description: pr-n-frontend_scc-migrated_tcp_106, services: [tcp449, tcp8470, tcp8471, tcp8476, tcp8478]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["449", "8470", "8471", "8476", "8478"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_127" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_127"
  description  = "description: pr-n-frontend_scc-migrated_tcp_127, services: [tcp449, tcp8470, tcp8471, tcp8476, tcp8478]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["449", "8470", "8471", "8476", "8478"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-445_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-445_eq"
  description  = "description: tcp-445_eq, services: [tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_bacs_sql" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_bacs_sql"
  description  = "description: pr-n-frontend_bacs_sql, services: [tcp-udp1434, tcp-udp137, tcp-udp138, tcp-udp139, tcp-udp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1434", "137", "138", "139", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434", "137", "138", "139", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-ldap_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-ldap_eq"
  description  = "description: tcp-ldap_eq, services: [tcp389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["389"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-5701_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-5701_eq"
  description  = "description: tcp-5701_eq, services: [tcp5701]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5701"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_jde_ports_tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_jde_ports_tcp"
  description  = "description: pr-n-frontend_jde_ports_tcp, services: [tcp449, tcp8471, tcp8476, tcp8470, tcp8475]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["449", "8471", "8476", "8470", "8475"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3307_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3307_eq"
  description  = "description: tcp-3307_eq, services: [tcp3307]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3307"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1530_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1530_eq"
  description  = "description: tcp-1530_eq, services: [tcp1530]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1530"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-10287_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-10287_eq"
  description  = "description: tcp-10287_eq, services: [tcp10287]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10287"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_97" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_97"
  description  = "description: pr-n-frontend_scc-migrated_tcp_97, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1521" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1521"
  description  = "description: CHG0123808, services: [tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_19"
  description  = "description: pr-n-frontend_scc-migrated_service_19, services: [tcp445, udp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1523_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1523_eq"
  description  = "description: tcp-1523_eq, services: [tcp1523]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1523"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8443_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8443_eq"
  description  = "description: tcp-8443_eq, services: [tcp8443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_56" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_56"
  description  = "description: pr-n-frontend_scc-migrated_tcp_56, services: [tcp135, tcp445, tcp5722]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5722"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1526_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1526_eq"
  description  = "description: tcp-1526_eq, services: [tcp1526]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1526"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_45"
  description  = "description: pr-n-frontend_scc-migrated_service_45, services: [udp445, tcp22, tcp-udp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445", "53"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_11"
  description  = "description: pr-n-frontend_scc-migrated_service_11, services: [tcp5722, tcp135, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5722", "135", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_1"
  description  = "description: pr-n-frontend_scc-migrated_tcp_1, services: [tcp21, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_32"
  description  = "description: pr-n-frontend_scc-migrated_tcp_32, services: [tcp14501-14509, tcp8999]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["14501-14509", "8999"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_54" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_54"
  description  = "description: pr-n-frontend_scc-migrated_tcp_54, services: [tcp50410-50425, tcp8410, tcp8411, tcp8412]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50410-50425", "8410", "8411", "8412"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_70"
  description  = "description: pr-n-frontend_scc-migrated_tcp_70, services: [tcp445-449, tcp50410-50425, tcp8410-8412]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445-449", "50410-50425", "8410-8412"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_63" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_63"
  description  = "description: pr-n-frontend_scc-migrated_tcp_63, services: [tcp50410-50425, tcp8410-8412, tcp445-449, tcp3777]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50410-50425", "8410-8412", "445-449", "3777"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_65" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_65"
  description  = "description: pr-n-frontend_scc-migrated_tcp_65, services: [tcp50410-50425, tcp8410-8412, tcp445-449]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50410-50425", "8410-8412", "445-449"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_72" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_72"
  description  = "description: pr-n-frontend_scc-migrated_tcp_72, services: [tcp9100, tcp515]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9100", "515"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-exec_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-exec_eq"
  description  = "description: tcp-exec_eq, services: [tcp512]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["512"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3777_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3777_eq"
  description  = "description: tcp-3777_eq, services: [tcp3777]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3777"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_jde-enterprise-service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_jde-enterprise-service"
  description  = "description: pr-n-frontend_jde-enterprise-service, services: [tcp2300, tcp2001, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp21, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2300", "2001", "4402", "446", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470", "8471", "8472", "8473", "8474", "8475", "8476"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-lpd_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-lpd_eq"
  description  = "description: tcp-lpd_eq, services: [tcp515]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["515"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_148" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_148"
  description  = "description: pr-n-frontend_scc-migrated_tcp_148, services: [tcp25, tcp465]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["25", "465"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_175" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_175"
  description  = "description: pr-n-frontend_scc-migrated_tcp_175, services: [tcp446, tcp447, tcp448, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["446", "447", "448", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_25"
  description  = "description: pr-n-frontend_scc-migrated_tcp_25, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470-8476, tcp23, tcp137, tcp14501-14509, tcp397, tcp445, tcp447, tcp8999, tcp139, tcp21, tcp9060]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2001", "2300", "4402", "446", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470-8476", "23", "137", "14501-14509", "397", "445", "447"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8999", "139", "21", "9060"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3128_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3128_eq"
  description  = "description: tcp-3128_eq, services: [tcp3128]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3128"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-6016_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-6016_eq"
  description  = "description: tcp-6016_eq, services: [tcp6016]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["6016"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_10"
  description  = "description: pr-n-frontend_scc-migrated_service_10, services: [tcp6016-6025, udp6016-6025]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["6016-6025"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["6016-6025"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_249" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_249"
  description  = "description: pr-n-frontend_scc-migrated_tcp_249, services: [tcp135, tcp49152-65535, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "49152-65535", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_420" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_420"
  description  = "description: pr-n-frontend_scc-migrated_service_420, services: [tcp8080, tcp142, tcp9060, tcp14501-14502, tcp6016, tcp6080, tcp8470-8476, tcp-udp137, tcp-udp139, tcp-udp445, tcp-udp6017-6026, tcp2001, tcp446, tcp449, tcp5544, tcp5555, tcp8999-9000, tcp9401-9403, tcp9411-9412, tcp9413-9414, tcp9645-9655, tcp9665, tcp21, tcp1521, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "142", "9060", "14501-14502", "6016", "6080", "8470-8476"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "139", "445", "6017-6026", "2001", "446", "449"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5544", "5555", "8999-9000", "9401-9403", "9411-9412", "9413-9414", "9645-9655"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9665", "21", "1521", "23"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "139", "445", "6017-6026"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_40"
  description  = "description: pr-n-frontend_scc-migrated_service_40, services: [tcp8080, tcp14501-14502, tcp6016, tcp6080, tcp8470-8476, tcp142, tcp9060, tcp8879, tcp8880-8890, tcp7001, tcp2001, tcp446, tcp449, tcp21, tcp1521, tcp23, tcp-udp137, tcp-udp445, tcp-udp139, tcp8999-9000, tcp5544, tcp5555, tcp-udp6017-6026, tcp9401-9403, tcp9411-9412, tcp9413-9414, tcp9645-9655, tcp9665]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "14501-14502", "6016", "6080", "8470-8476", "142", "9060"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8879", "8880-8890", "7001", "2001", "446", "449", "21"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521", "23", "137", "445", "139", "8999-9000", "5544"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5555", "6017-6026", "9401-9403", "9411-9412", "9413-9414", "9645-9655", "9665"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "445", "139", "6017-6026"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_118" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_118"
  description  = "description: pr-n-frontend_scc-migrated_tcp_118, services: [tcp9043, tcp9044, tcp9045, tcp9046, tcp9061, tcp9062, tcp9063]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9043", "9044", "9045", "9046", "9061", "9062", "9063"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-14502-14520_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-14502-14520_eq"
  description  = "description: tcp-14502-14520_eq, services: [tcp14502-14520]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["14502-14520"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_124" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_124"
  description  = "description: pr-n-frontend_scc-migrated_tcp_124, services: [tcp9053, tcp9054, tcp9055, tcp9056, tcp9057, tcp9070-9075]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9053", "9054", "9055", "9056", "9057", "9070-9075"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_136" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_136"
  description  = "description: pr-n-frontend_scc-migrated_tcp_136, services: [tcp9099, tcp9122, tcp9123, tcp9126]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9099", "9122", "9123", "9126"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_451" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_451"
  description  = "description: pr-n-frontend_scc-migrated_service_451, services: [tcp8089, tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089", "9997"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_453" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_453"
  description  = "description: pr-n-frontend_scc-migrated_service_453, services: [tcp49152-65535, tcp135, tcp3268, tcp3269, tcp445, tcp464, tcp88, tcp9389, tcp389, tcp636, udp389, udp464, udp88, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "135", "3268", "3269", "445", "464", "88"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9389", "389", "636"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["389", "464", "88", "123"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_455" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_455"
  description  = "description: pr-n-frontend_scc-migrated_service_455, services: [tcp49152-65535, tcp135, tcp1688, tcp1918, tcp445, tcp5985, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "135", "1688", "1918", "445", "5985", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_459" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_459"
  description  = "description: pr-n-frontend_scc-migrated_service_459, services: [tcp53, udp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_466" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_466"
  description  = "description: pr-n-frontend_scc-migrated_tcp_466, services: [tcp137, tcp14501, tcp14502, tcp2001, tcp445, tcp446, tcp449, tcp5544, tcp5555, tcp7001, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp8879, tcp8999, tcp9000, tcp9043, tcp9044, tcp9045, tcp9046, tcp9060, tcp9061, tcp9062, tcp9063, tcp9401, tcp9402, tcp9403, tcp9411, tcp9412, tcp9413, tcp9414, tcp9645, tcp9655, tcp9665, tcp21, tcp139, tcp23, tcp14502-14503, tcp14502-14520, tcp9070-9075, tcp6017-6026, tcp8880-8890]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "14501", "14502", "2001", "445", "446", "449"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5544", "5555", "7001", "8470", "8471", "8472", "8473"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8474", "8475", "8476", "8879", "8999", "9000", "9043"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9044", "9045", "9046", "9060", "9061", "9062", "9063"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9401", "9402", "9403", "9411", "9412", "9413", "9414"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9645", "9655", "9665", "21", "139", "23", "14502-14503"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["14502-14520", "9070-9075", "6017-6026", "8880-8890"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_whcard-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_whcard-ports"
  description  = "description: pr-n-frontend_whcard-ports, services: [tcp80, tcp443, tcp7291, tcp7292, tcp7293, tcp7294, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "7291", "7292", "7293", "7294", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3151_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3151_eq"
  description  = "description: tcp-3151_eq, services: [tcp3151]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3151"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_cobain-distribution" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_cobain-distribution"
  description  = "description: pr-n-frontend_cobain-distribution, services: [tcp5118, tcp5119, tcp80, tcp443, udp5119]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5118", "5119", "80", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["5119"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-sccm" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-sccm"
  description  = "description: pr-n-frontend_tcp-sccm, services: [tcp135, tcp445, tcp49152-65535, tcp8530, tcp8531, tcp80, tcp443, tcp1433, tcp88, tcp389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "49152-65535", "8530", "8531", "80", "443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "88", "389"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcpudp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcpudp"
  description  = "description: pr-n-frontend_tcpudp, services: [udp, tcp]"
  ip_protocol_entry {
    display_name = "udp"
    protocol     = "17"
  }
  ip_protocol_entry {
    display_name = "tcp"
    protocol     = "6"
  }
}

resource "nsxt_policy_service" "pr-n-frontend_ad_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_ad_ports"
  description  = "description: CHG0057230, services: [tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp138, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp636, tcp-udp3268, tcp-udp3269, tcp-udp5722, tcp-udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["88", "123", "135", "138", "139", "389", "445"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["464", "636", "3268", "3269", "5722", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["88", "123", "135", "138", "139", "389", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["464", "636", "3268", "3269", "5722", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8089_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8089_eq"
  description  = "description: tcp-8089_eq, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_153" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_153"
  description  = "description: pr-n-frontend_scc-migrated_tcp_153, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcpudp_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcpudp_4"
  description  = "description: pr-n-frontend_scc-migrated_tcpudp_4, services: [tcp-udp1494, tcp-udp2598]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1494", "2598"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1494", "2598"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-81"
  description  = "description: CHG0126550, services: [tcp81]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["81"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_udp-syslog_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_udp-syslog_eq"
  description  = "description: udp-syslog_eq, services: [udp514]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-7141_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-7141_eq"
  description  = "description: tcp-7141_eq, services: [tcp7141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7141"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-5672_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-5672_eq"
  description  = "description: tcp-5672_eq, services: [tcp5672]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5672"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8081-8084_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8081-8084_eq"
  description  = "description: tcp-8081-8084_eq, services: [tcp8081-8084]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081-8084"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_ad-kms" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_ad-kms"
  description  = "description: pr-n-frontend_ad-kms, services: [tcp-udp389, tcp-udp445, tcp-udp49152-65535, tcp-udp88, tcp135, tcp1688, tcp3268-3269, tcp-udp464, tcp1918, tcp5985, tcp9389, tcp636, tcp139, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["389", "445", "49152-65535", "88", "135", "1688", "3268-3269"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["464", "1918", "5985", "9389", "636", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["389", "445", "49152-65535", "88", "464", "123"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_142" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_142"
  description  = "description: pr-n-frontend_scc-migrated_tcp_142, services: [tcp80, tcp443, tcp1025-5000, tcp135, tcp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "1025-5000", "135", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3128-3129_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3128-3129_eq"
  description  = "description: tcp-3128-3129_eq, services: [tcp3128-3129]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3128-3129"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_151" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_151"
  description  = "description: pr-n-frontend_scc-migrated_tcp_151, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-5050-5051_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-5050-5051_eq"
  description  = "description: tcp-5050-5051_eq, services: [tcp5050-5051]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5050-5051"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_398" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_398"
  description  = "description: pr-n-frontend_scc-migrated_service_398, services: [tcp49152-65535, tcp135, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "135", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcpudp_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcpudp_6"
  description  = "description: pr-n-frontend_scc-migrated_tcpudp_6, services: [tcp-udp1025-5000, tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp138, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp636, tcp-udp3268, tcp-udp3269, tcp-udp5722, tcp-udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1025-5000", "88", "123", "135", "138", "139", "389"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "464", "636", "3268", "3269", "5722", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1025-5000", "88", "123", "135", "138", "139", "389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445", "464", "636", "3268", "3269", "5722", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8100-8101_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8100-8101_eq"
  description  = "description: tcp-8100-8101_eq, services: [tcp8100-8101]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8100-8101"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-2383_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-2383_eq"
  description  = "description: tcp-2383_eq, services: [tcp2383]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2383"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-7011_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-7011_eq"
  description  = "description: tcp-7011_eq, services: [tcp7011]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["7011"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_8080" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_8080"
  description  = "description: pr-n-frontend_8080, services: [tcp8080]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-23000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-23000_eq"
  description  = "description: tcp-23000_eq, services: [tcp23000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["23000"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8000_eq"
  description  = "description: tcp-8000_eq, services: [tcp8000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8000"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_75" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_75"
  description  = "description: pr-n-frontend_scc-migrated_tcp_75, services: [tcp138, tcp445, tcp5722]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["138", "445", "5722"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_82" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_82"
  description  = "description: pr-n-frontend_scc-migrated_tcp_82, services: [tcp1688, tcp8530, tcp8531, tcp80, tcp443, tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp138, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp636, tcp-udp3268, tcp-udp3269, tcp-udp5722, tcp-udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1688", "8530", "8531", "80", "443", "88", "123"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "138", "139", "389", "445", "464", "636"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3268", "3269", "5722", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["88", "123", "135", "138", "139", "389", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["464", "636", "3268", "3269", "5722", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_147" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_147"
  description  = "description: pr-n-frontend_scc-migrated_tcp_147, services: [tcp135, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcpudp-domain" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcpudp-domain"
  description  = "description: pr-n-frontend_tcpudp-domain, services: [udp53, tcp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_163" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_163"
  description  = "description: pr-n-frontend_scc-migrated_tcp_163, services: [tcp8530, tcp8531, tcp443, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8530", "8531", "443", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_164" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_164"
  description  = "description: pr-n-frontend_scc-migrated_tcp_164, services: [tcp135, tcp1688, tcp1918, tcp445, tcp5985, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "1688", "1918", "445", "5985", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcpudp_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcpudp_5"
  description  = "description: pr-n-frontend_scc-migrated_tcpudp_5, services: [tcp-udp389, tcp-udp464, tcp-udp49152-65535, tcp-udp88]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["389", "464", "49152-65535", "88"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["389", "464", "49152-65535", "88"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_165" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_165"
  description  = "description: pr-n-frontend_scc-migrated_tcp_165, services: [tcp135, tcp3268, tcp3269, tcp445, tcp9389, tcp636]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "3268", "3269", "445", "9389", "636"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_168" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_168"
  description  = "description: pr-n-frontend_scc-migrated_tcp_168, services: [tcp445, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_166" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_166"
  description  = "description: pr-n-frontend_scc-migrated_tcp_166, services: [tcp135, tcp445, tcp49152-65535, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "49152-65535", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcpudp-49152-65535" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcpudp-49152-65535"
  description  = "description: pr-n-frontend_tcpudp-49152-65535, services: [udp49152-65535, tcp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3299_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3299_eq"
  description  = "description: tcp-3299_eq, services: [tcp3299]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3299"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_katello-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_katello-ports"
  description  = "description: pr-n-frontend_katello-ports, services: [tcp3129, tcp5671, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3129", "5671", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_162" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_162"
  description  = "description: pr-n-frontend_scc-migrated_tcp_162, services: [tcp80, tcp443, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_grp-aspect-stunnel-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_grp-aspect-stunnel-ports"
  description  = "description: CHG0133344, services: [tcp3129, tcp6861, tcp6963, tcp6982, tcp6996, tcp6997, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3129", "6861", "6963", "6982", "6996", "6997", "80"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_121" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_121"
  description  = "description: pr-n-frontend_scc-migrated_tcp_121, services: [tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_cluster-ports-tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_cluster-ports-tcp"
  description  = "description: pr-n-frontend_cluster-ports-tcp, services: [tcp445, tcp3343, tcp135, tcp139, tcp49152-65535, tcp5985]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "3343", "135", "139", "49152-65535", "5985"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_cluster-ports-udp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_cluster-ports-udp"
  description  = "description: pr-n-frontend_cluster-ports-udp, services: [udp3343, udp137, udp49152-65535]"
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3343", "137", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_135_5985" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_135_5985"
  description  = "description: pr-n-frontend_135_5985, services: [tcp135, tcp5985]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "5985"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_dpe-replication-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_dpe-replication-ports"
  description  = "description: pr-n-frontend_dpe-replication-ports, services: [tcp30000, tcp5022]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["30000", "5022"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_49430" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_49430"
  description  = "description: pr-n-frontend_49430, services: [tcp49430]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49430"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_92" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_92"
  description  = "description: pr-n-frontend_scc-migrated_tcp_92, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_dm_redis_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_dm_redis_ports"
  description  = "description: pr-n-frontend_dm_redis_ports, services: [tcp6379, tcp16379]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["6379", "16379"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_mgmt-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_mgmt-ports"
  description  = "description: pr-n-frontend_mgmt-ports, services: [tcp22, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_11" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_11"
  description  = "description: pr-n-frontend_scc-migrated_tcp_11, services: [tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_14"
  description  = "description: pr-n-frontend_scc-migrated_service_14, services: [tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_31" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_31"
  description  = "description: pr-n-frontend_scc-migrated_service_31, services: [tcp445, udp137-139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137-139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_7"
  description  = "description: pr-n-frontend_scc-migrated_service_7, services: [tcp137, tcp445, tcp6502, tcp139, udp138, udp137]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "445", "6502", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["138", "137"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_111" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_111"
  description  = "description: pr-n-frontend_scc-migrated_tcp_111, services: [tcp3306, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8082" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8082"
  description  = "description: CHG0119468, services: [tcp8082]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8082"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-5001_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-5001_eq"
  description  = "description: tcp-5001_eq, services: [tcp5001]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5001"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-22000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-22000_eq"
  description  = "description: tcp-22000_eq, services: [tcp22000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22000"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_ms_filesharing_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_ms_filesharing_ports"
  description  = "description: pr-n-frontend_ms_filesharing_ports, services: [tcp445, tcp139, udp138, udp137]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["138", "137"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_128" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_128"
  description  = "description: pr-n-frontend_scc-migrated_tcp_128, services: [tcp21, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_42"
  description  = "description: pr-n-frontend_scc-migrated_service_42, services: [tcp49152-65535, tcp135, tcp445, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "135", "445", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_dpe-mon-tcp-srv" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_dpe-mon-tcp-srv"
  description  = "description: pr-n-frontend_dpe-mon-tcp-srv, services: [tcp1433, tcp21000, tcp22000, tcp29000, tcp23000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "21000", "22000", "29000", "23000"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_39" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_39"
  description  = "description: pr-n-frontend_scc-migrated_service_39, services: [tcp49152-65535, tcp135, tcp445, tcp5985, tcp5986, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "135", "445", "5985", "5986", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_14"
  description  = "description: pr-n-frontend_scc-migrated_tcp_14, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8014_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8014_eq"
  description  = "description: tcp-8014_eq, services: [tcp8014]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8014"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3389_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3389_eq"
  description  = "description: tcp-3389_eq, services: [tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_grp-svc-vtm" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_grp-svc-vtm"
  description  = "description: pr-n-frontend_grp-svc-vtm, services: [tcp9070, udp161-162]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["161-162"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_grp-svc-vtm-admin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_grp-svc-vtm-admin"
  description  = "description: pr-n-frontend_grp-svc-vtm-admin, services: [tcp9090, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9090", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_32"
  description  = "description: pr-n-frontend_scc-migrated_service_32, services: [tcp2382, tcp2383]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2382", "2383"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-29000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-29000_eq"
  description  = "description: tcp-29000_eq, services: [tcp29000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["29000"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_7" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_7"
  description  = "description: pr-n-frontend_scc-migrated_tcp_7, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-10301_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-10301_eq"
  description  = "description: tcp-10301_eq, services: [tcp10301]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10301"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-10302_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-10302_eq"
  description  = "description: tcp-10302_eq, services: [tcp10302]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10302"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_18" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_18"
  description  = "description: pr-n-frontend_scc-migrated_tcp_18, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_24" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_24"
  description  = "description: pr-n-frontend_scc-migrated_tcp_24, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp23, tcp3389, tcp137, tcp445, tcp139, tcp8576]"
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
    destination_ports = ["23", "3389", "137", "445", "139", "8576"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_35" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_35"
  description  = "description: pr-n-frontend_scc-migrated_service_35, services: [tcp10021, tcp10023, tcp10050, tcp10058, tcp10059, tcp10061, tcp10065, tcp10020, tcp446]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10021", "10023", "10050", "10058", "10059", "10061", "10065"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10020", "446"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_22" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_22"
  description  = "description: pr-n-frontend_scc-migrated_service_22, services: [tcp-udp137, tcp445, tcp139, udp138]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "138"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_45" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_45"
  description  = "description: pr-n-frontend_scc-migrated_tcp_45, services: [tcp3306, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3306", "3389"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_41" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_41"
  description  = "description: pr-n-frontend_scc-migrated_tcp_41, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470-8476, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2001", "2300", "4402", "446", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470-8476", "23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-9401-9405_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-9401-9405_eq"
  description  = "description: tcp-9401-9405_eq, services: [tcp9401-9405]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9401-9405"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_42" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_42"
  description  = "description: pr-n-frontend_scc-migrated_tcp_42, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_cobain-client" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_cobain-client"
  description  = "description: pr-n-frontend_cobain-client, services: [tcp5119, udp5119]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5119"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["5119"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-5118_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-5118_eq"
  description  = "description: tcp-5118_eq, services: [tcp5118]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5118"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_55" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_55"
  description  = "description: pr-n-frontend_scc-migrated_tcp_55, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp21, tcp23]"
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
    destination_ports = ["21", "23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_bis-devjde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_bis-devjde"
  description  = "description: CHG0052038, services: [tcp137, tcp2001, tcp2809, tcp445, tcp449, tcp5544, tcp5555, tcp5557, tcp5559, tcp7873, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp8880, tcp9060, tcp9080, tcp9090, tcp9401, tcp9402, tcp9403, tcp9404, tcp9405, tcp9443, tcp9501, tcp9502, tcp9503, tcp53, tcp512, tcp21, tcp139, tcp22, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "2001", "2809", "445", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5557", "5559", "7873", "8470", "8471", "8472", "8473"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8474", "8475", "8476", "8880", "9060", "9080", "9090"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9401", "9402", "9403", "9404", "9405", "9443", "9501"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9502", "9503", "53", "512", "21", "139", "22"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_bis-prodjde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_bis-prodjde"
  description  = "description: CHG0052038, services: [tcp137, tcp2001, tcp445, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp53, tcp512, tcp21, tcp139, tcp22, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "2001", "445", "449", "5544", "5555", "8470"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8471", "8472", "8473", "8474", "8475", "8476", "53"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["512", "21", "139", "22", "23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_100" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_100"
  description  = "description: pr-n-frontend_scc-migrated_tcp_100, services: [tcp137, tcp2001, tcp2809, tcp445, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp8880, tcp9080, tcp9090, tcp9443, tcp9501, tcp9502, tcp9503, tcp53, tcp512, tcp21, tcp139, tcp22, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "2001", "2809", "445", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470", "8471", "8472", "8473", "8474", "8475", "8476"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8880", "9080", "9090", "9443", "9501", "9502", "9503"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53", "512", "21", "139", "22", "23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_99" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_99"
  description  = "description: pr-n-frontend_scc-migrated_tcp_99, services: [tcp137, tcp2001, tcp445, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp53, tcp512, tcp21, tcp139, tcp22, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["137", "2001", "445", "449", "5544", "5555", "8470"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8471", "8472", "8473", "8474", "8475", "8476", "53"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["512", "21", "139", "22", "23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_101" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_101"
  description  = "description: pr-n-frontend_scc-migrated_tcp_101, services: [tcp3389, tcp8999]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "8999"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_102" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_102"
  description  = "description: pr-n-frontend_scc-migrated_tcp_102, services: [tcp3389, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-9645_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-9645_eq"
  description  = "description: tcp-9645_eq, services: [tcp9645]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9645"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_17"
  description  = "description: pr-n-frontend_scc-migrated_service_17, services: [tcp445, tcp139, udp138, udp137]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["138", "137"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_16"
  description  = "description: pr-n-frontend_scc-migrated_service_16, services: [tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470-8476, tcp53, tcp23, udp53]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2001", "2300", "4402", "446", "449", "5544", "5555"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470-8476", "53", "23"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_64" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_64"
  description  = "description: pr-n-frontend_scc-migrated_tcp_64, services: [tcp50410-50425, tcp8410-8412]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50410-50425", "8410-8412"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_67" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_67"
  description  = "description: pr-n-frontend_scc-migrated_tcp_67, services: [tcp50410-50425, tcp8410-8412, tcp445-449, tcp3777]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50410-50425", "8410-8412", "445-449", "3777"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-9000_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-9000_eq"
  description  = "description: tcp-9000_eq, services: [tcp9000]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9000"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_68" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_68"
  description  = "description: pr-n-frontend_scc-migrated_tcp_68, services: [tcp50410-50425, tcp8410-8412]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50410-50425", "8410-8412"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_69" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_69"
  description  = "description: pr-n-frontend_scc-migrated_tcp_69, services: [tcp50410-50425, tcp8410-8412]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50410-50425", "8410-8412"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_104" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_104"
  description  = "description: pr-n-frontend_scc-migrated_tcp_104, services: [tcp449, tcp8470, tcp8471, tcp8476, tcp8478]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["449", "8470", "8471", "8476", "8478"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-10300_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-10300_eq"
  description  = "description: tcp-10300_eq, services: [tcp10300]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["10300"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_88" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_88"
  description  = "description: pr-n-frontend_scc-migrated_tcp_88, services: [tcp21, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_79" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_79"
  description  = "description: pr-n-frontend_scc-migrated_tcp_79, services: [tcp21, tcp20, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["21", "20", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_84" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_84"
  description  = "description: pr-n-frontend_scc-migrated_tcp_84, services: [tcp445-449, tcp50410-50425, tcp8410-8412]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445-449", "50410-50425", "8410-8412"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_86" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_86"
  description  = "description: pr-n-frontend_scc-migrated_tcp_86, services: [tcp445-449, tcp50410-50425, tcp8410-8412]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445-449", "50410-50425", "8410-8412"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_110" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_110"
  description  = "description: pr-n-frontend_scc-migrated_tcp_110, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_windows_file_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_windows_file_services"
  description  = "description: pr-n-frontend_windows_file_services, services: [tcp-udp445, tcp-udp137, tcp-udp138, tcp-udp139, tcp-udp135]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "137", "138", "139", "135"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445", "137", "138", "139", "135"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_jde" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_jde"
  description  = "description: CHG0125763, services: [tcp8477, tcp8478, tcp9645, tcp2001, tcp2300, tcp4402, tcp446, tcp449, tcp5544, tcp5555, tcp8470-8476, tcp9401, tcp9402, tcp9403, tcp9404, tcp9405, tcp443, tcp23]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8477", "8478", "9645", "2001", "2300", "4402", "446"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["449", "5544", "5555", "8470-8476", "9401", "9402", "9403"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9404", "9405", "443", "23"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_accurate_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_accurate_ports"
  description  = "description: pr-n-frontend_accurate_ports, services: [tcp-udp445, tcp-udp8080, tcp-udp8443, tcp-udp137, tcp-udp138, tcp-udp139, tcp-udp443, tcp-udp3389, tcp-udp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "8080", "8443", "137", "138", "139", "443"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389", "80"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445", "8080", "8443", "137", "138", "139", "443"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_nevada-trs-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_nevada-trs-ports"
  description  = "description: pr-n-frontend_nevada-trs-ports, services: [tcp445, tcp139, udp137-138]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137-138"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tape_drive_acces_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tape_drive_acces_services"
  description  = "description: pr-n-frontend_tape_drive_acces_services, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_cluster-query-tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_cluster-query-tcp"
  description  = "description: pr-n-frontend_cluster-query-tcp, services: [tcp135, tcp49152-65535, tcp5985]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "49152-65535", "5985"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_419" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_419"
  description  = "description: pr-n-frontend_scc-migrated_tcp_419, services: [tcp444, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["444", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_116" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_116"
  description  = "description: pr-n-frontend_scc-migrated_tcp_116, services: [tcp444, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["444", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-13211_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-13211_eq"
  description  = "description: tcp-13211_eq, services: [tcp13211]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["13211"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_ssas-listeners" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_ssas-listeners"
  description  = "description: pr-n-frontend_ssas-listeners, services: [tcp1433, tcp2383]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "2383"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp_1433_8080" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp_1433_8080"
  description  = "description: pr-n-frontend_tcp_1433_8080, services: [tcp8080, tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "1433"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_66" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_66"
  description  = "description: pr-n-frontend_scc-migrated_tcp_66, services: [tcp2383, tcp2382, tcp2838]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2383", "2382", "2838"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-4445_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-4445_eq"
  description  = "description: tcp-4445_eq, services: [tcp4445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["4445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-44445_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-44445_eq"
  description  = "description: tcp-44445_eq, services: [tcp44445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["44445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_25" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_25"
  description  = "description: pr-n-frontend_scc-migrated_service_25, services: [tcp135, tcp1433, udp1434, tcp11433, tcp2559, tcp51083, tcp57324, tcp58661, tcp63480]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "1433", "11433", "2559", "51083", "57324", "58661"]
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

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_139" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_139"
  description  = "description: pr-n-frontend_scc-migrated_tcp_139, services: [tcp389, tcp636]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["389", "636"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_2"
  description  = "description: pr-n-frontend_scc-migrated_service_2, services: [tcp-udp135-139, tcp-udp445, tcp1433, tcp3000-3200, tcp30000, tcp49152-65535, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135-139", "445", "1433", "3000-3200", "30000", "49152-65535"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["135-139", "445", "1434"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_1"
  description  = "description: pr-n-frontend_scc-migrated_service_1, services: [tcp1433, udp1434]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["1434"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-9070_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-9070_eq"
  description  = "description: tcp-9070_eq, services: [tcp9070]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9070"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_10"
  description  = "description: pr-n-frontend_scc-migrated_tcp_10, services: [tcp1433, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "3389"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_5" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_5"
  description  = "description: pr-n-frontend_scc-migrated_service_5, services: [tcp3307, tcp3308, tcp3306, tcp80, tcp1433]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3307", "3308", "3306", "80", "1433"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-3308_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-3308_eq"
  description  = "description: tcp-3308_eq, services: [tcp3308]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3308"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_16" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_16"
  description  = "description: pr-n-frontend_scc-migrated_tcp_16, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8531_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8531_eq"
  description  = "description: tcp-8531_eq, services: [tcp8531]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8531"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_30"
  description  = "description: pr-n-frontend_scc-migrated_service_30, services: [tcp512, tcp-udp139, tcp-udp445, tcp137, tcp2001, tcp449, tcp5544, tcp5555, tcp8470, tcp8471, tcp8472, tcp8473, tcp8474, tcp8475, tcp8476, tcp53, tcp21, tcp22, tcp23, tcp1433, tcp1521]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["512", "139", "445", "137", "2001", "449", "5544"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5555", "8470", "8471", "8472", "8473", "8474", "8475"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8476", "53", "21", "22", "23", "1433", "1521"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["139", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_77" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_77"
  description  = "description: pr-n-frontend_scc-migrated_tcp_77, services: [tcp135, tcp445, tcp5722]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5722"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_78" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_78"
  description  = "description: pr-n-frontend_scc-migrated_tcp_78, services: [tcp12199, tcp12200, tcp12300, tcp12301, tcp135, tcp2040, tcp24001-24100, tcp445, tcp61613, tcp61623, tcp8161, tcp24501-24600]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["12199", "12200", "12300", "12301", "135", "2040", "24001-24100"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "61613", "61623", "8161", "24501-24600"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_112" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_112"
  description  = "description: pr-n-frontend_scc-migrated_tcp_112, services: [tcp8400, tcp8401, tcp8402, tcp8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400", "8401", "8402", "8403"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_144" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_144"
  description  = "description: pr-n-frontend_scc-migrated_tcp_144, services: [tcp8081, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_3" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_3"
  description  = "description: pr-n-frontend_scc-migrated_service_3, services: [tcp8080, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_er-studio" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_er-studio"
  description  = "description: pr-n-frontend_er-studio, services: [tcp5331, tcp5332, tcp5333, tcp5567, tcp54331, tcp54332, tcp54333]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5331", "5332", "5333", "5567", "54331", "54332", "54333"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_er-studio-access-tcp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_er-studio-access-tcp"
  description  = "description: pr-n-frontend_er-studio-access-tcp, services: [tcp5567, tcp54331, tcp54333]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5567", "54331", "54333"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_155" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_155"
  description  = "description: pr-n-frontend_scc-migrated_tcp_155, services: [tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_161" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_161"
  description  = "description: pr-n-frontend_scc-migrated_tcp_161, services: [tcp9031, tcp9032]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9031", "9032"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_167" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_167"
  description  = "description: pr-n-frontend_scc-migrated_tcp_167, services: [tcp135, tcp445, tcp49152-65535, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "49152-65535", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcpudp-3389" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcpudp-3389"
  description  = "description: pr-n-frontend_tcpudp-3389, services: [udp3389, tcp3389]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["3389"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_169" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_169"
  description  = "description: pr-n-frontend_scc-migrated_tcp_169, services: [tcp6963, tcp6982, tcp6861]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["6963", "6982", "6861"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_euc_brokers_ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_euc_brokers_ports"
  description  = "description: pr-n-frontend_euc_brokers_ports, services: [tcp135, tcp5986, tcp5985, tcp445, tcp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "5986", "5985", "445", "49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_8"
  description  = "description: pr-n-frontend_scc-migrated_tcp_8, services: [tcp1433, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-5050_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-5050_eq"
  description  = "description: tcp-5050_eq, services: [tcp5050]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5050"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_38" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_38"
  description  = "description: pr-n-frontend_scc-migrated_service_38, services: [tcp49152-65535, tcp-udp3389, tcp135, tcp5985, tcp5986, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "3389", "135", "5985", "5986", "445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["3389"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_40" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_40"
  description  = "description: pr-n-frontend_scc-migrated_tcp_40, services: [tcp1521, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1521", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcpudp-445" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcpudp-445"
  description  = "description: pr-n-frontend_tcpudp-445, services: [udp445, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_43" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_43"
  description  = "description: pr-n-frontend_scc-migrated_tcp_43, services: [tcp135, tcp445, tcp5722]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5722"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_61" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_61"
  description  = "description: pr-n-frontend_scc-migrated_tcp_61, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_410" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_410"
  description  = "description: pr-n-frontend_scc-migrated_service_410, services: [tcp8470-8476, tcp8080, tcp142, tcp9060, tcp14501-14502, tcp6016, tcp6080, tcp2001, tcp449, tcp5544, tcp5555, tcp23, tcp-udp137, tcp-udp139, tcp-udp445, tcp446, tcp8999-9000, tcp21, tcp1521, tcp-udp6017-6026, tcp9401-9403, tcp9411-9412, tcp9413-9414, tcp9645-9655, tcp9665]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8470-8476", "8080", "142", "9060", "14501-14502", "6016", "6080"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["2001", "449", "5544", "5555", "23", "137", "139"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "446", "8999-9000", "21", "1521", "6017-6026", "9401-9403"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9411-9412", "9413-9414", "9645-9655", "9665"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["137", "139", "445", "6017-6026"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_44" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_44"
  description  = "description: pr-n-frontend_scc-migrated_service_44, services: [tcp8080, tcp10301, tcp5119, tcp8080, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8080", "10301", "5119", "8080", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_174" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_174"
  description  = "description: pr-n-frontend_scc-migrated_tcp_174, services: [tcp446, tcp447, tcp448, tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["446", "447", "448", "22"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_491" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_491"
  description  = "description: pr-n-frontend_scc-migrated_service_491, services: [udp445, tcp445, tcp139, udp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_4" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_4"
  description  = "description: pr-n-frontend_scc-migrated_tcp_4, services: [tcp445, tcp139]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["445", "139"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_9"
  description  = "description: pr-n-frontend_scc-migrated_tcp_9, services: [tcp1433, tcp4343]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1433", "4343"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_8"
  description  = "description: pr-n-frontend_scc-migrated_service_8, services: [tcp30000, tcp445, tcp5022, tcp139, udp139, udp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["30000", "445", "5022", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["139", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_19" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_19"
  description  = "description: pr-n-frontend_scc-migrated_tcp_19, services: [tcp135, tcp445, tcp5722]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5722"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_6"
  description  = "description: pr-n-frontend_scc-migrated_tcp_6, services: [tcp135, tcp445]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_whgroup_ad_ports-chg0144834" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_whgroup_ad_ports-chg0144834"
  description  = "description: pr-n-frontend_whgroup_ad_ports-chg0144834, services: [tcp-udp53, tcp-udp88, tcp-udp123, tcp-udp135, tcp-udp139, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp49152-65525, tcp636, tcp3268-3269, tcp5722, tcp9389, udp137-138]"
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

resource "nsxt_policy_service" "pr-n-frontend_euc_mgmt_port-group-chg0142765" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_euc_mgmt_port-group-chg0142765"
  description  = "description: pr-n-frontend_euc_mgmt_port-group-chg0142765, services: [tcp135, tcp445, tcp5985, tcp5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["135", "445", "5985", "5986"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_splunk_indexing_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_splunk_indexing_port-chg0143200"
  description  = "description: pr-n-frontend_splunk_indexing_port-chg0143200, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_splunk_mgmt_port-chg0143200" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_splunk_mgmt_port-chg0143200"
  description  = "description: pr-n-frontend_splunk_mgmt_port-chg0143200, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_splunk_indexing_port-chg0142763" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_splunk_indexing_port-chg0142763"
  description  = "description: pr-n-frontend_splunk_indexing_port-chg0142763, services: [tcp9997]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9997"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8400-8403" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8400-8403"
  description  = "description: CHG0112231, services: [tcp8400-8403]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8400-8403"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_90" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_90"
  description  = "description: pr-n-frontend_scc-migrated_tcp_90, services: [tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_37" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_37"
  description  = "description: pr-n-frontend_scc-migrated_tcp_37, services: [tcp8081, tcp8140, tcp8141]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8081", "8140", "8141"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_ldap-services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_ldap-services"
  description  = "description: CHG0116053, services: [tcp8275, tcp8276]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8275", "8276"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_rundeck-winrm-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_rundeck-winrm-ports"
  description  = "description: pr-n-frontend_rundeck-winrm-ports, services: [tcp5985-5986]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5985-5986"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_wily-outbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_wily-outbound-ports"
  description  = "description: pr-n-frontend_wily-outbound-ports, services: [tcp22, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_wily-inbound-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_wily-inbound-ports"
  description  = "description: pr-n-frontend_wily-inbound-ports, services: [tcp5001]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["5001"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_8089" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_8089"
  description  = "description: pr-n-frontend_8089, services: [tcp8089]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8089"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_ad-global-rule-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_ad-global-rule-ports"
  description  = "description: CHG0066653, services: [tcp9389, udp123, udp137, udp138, tcp135, tcp636, tcp49152-65535, tcp-udp389, tcp-udp445, tcp-udp464, tcp-udp88, tcp3268-3269, tcp5722, tcp139, udp49152-65535]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["9389", "135", "636", "49152-65535", "389", "445", "464"]
  }
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["88", "3268-3269", "5722", "139"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["123", "137", "138", "389", "445", "464", "88"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["49152-65535"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_infoblox-standard-ports" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_infoblox-standard-ports"
  description  = "description: pr-n-frontend_infoblox-standard-ports, services: [tcp-udp53, udp123]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["53"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["53", "123"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_27"
  description  = "description: pr-n-frontend_scc-migrated_tcp_27, services: [tcp8530, tcp8531, tcp80, tcp443]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8530", "8531", "80", "443"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcpudp-514" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcpudp-514"
  description  = "description: pr-n-frontend_tcpudp-514, services: [udp514, tcp514]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["514"]
  }
  l4_port_set_entry {
    protocol          = "UDP"
    destination_ports = ["514"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_tcp_29" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_tcp_29"
  description  = "description: pr-n-frontend_scc-migrated_tcp_29, services: [tcp50123, tcp50124, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["50123", "50124", "80"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-60606_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-60606_eq"
  description  = "description: tcp-60606_eq, services: [tcp60606]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["60606"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-1688_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-1688_eq"
  description  = "description: tcp-1688_eq, services: [tcp1688]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["1688"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-48000-48030_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-48000-48030_eq"
  description  = "description: tcp-48000-48030_eq, services: [tcp48000-48030]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["48000-48030"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_tcp-8083_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_tcp-8083_eq"
  description  = "description: tcp-8083_eq, services: [tcp8083]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["8083"]
  }
}

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_9" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_9"
  description  = "description: pr-n-frontend_scc-migrated_service_9, services: [tcp9070, tcp22, tcp25, tcp-udp53, udp123, udp161, udp162, tcp-udp389, tcp443, tcp444, tcp636, tcp1433, tcp8443, tcp8834, tcp9443, tcp18184, tcp18191, tcp18210]"
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

resource "nsxt_policy_service" "pr-n-frontend_scc-migrated_service_292" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pr-n-frontend_scc-migrated_service_292"
  description  = "description: pr-n-frontend_scc-migrated_service_292, services: [tcp49152-65535, tcp135, tcp80]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["49152-65535", "135", "80"]
  }
}

