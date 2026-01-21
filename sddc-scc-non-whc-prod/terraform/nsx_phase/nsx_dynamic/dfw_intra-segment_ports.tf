/*========================================

###########################################################################
###########################################################################
###                                                                     ###
###             INTRA-SEGMENT PORTS - NOT MIGRATED FROM SCC             ###
###                                                                     ###
###########################################################################
###########################################################################

========================================*/

# resource "nsxt_policy_service" "intra-segment_ip-any" {
#   lifecycle {
#     create_before_destroy = true
#   }
#   display_name = "intra-segment_ip-any"
#   description  = "description: ip"
#   ether_type_entry {
#     ether_type = "2048"
#   }
# }

resource "nsxt_policy_service" "intra-segment_icmp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_icmp-any"
  description  = "description: icmp"
  icmp_entry {
    protocol = "ICMPv4"
  }
}

resource "nsxt_policy_service" "intra-segment_tcp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_tcp-any"
  description  = "description: tcp-any"
  ip_protocol_entry {
    display_name = "tcp"
    protocol     = "6"
  }
}

resource "nsxt_policy_service" "intra-segment_udp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segment_udp-any"
  description  = "description: udp-any"
  ip_protocol_entry {
    display_name = "udp"
    protocol     = "17"
  }
}

resource "nsxt_policy_service" "intra-segement_tcp-ssh_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "intra-segement_tcp-ssh_eq"
  description  = "description: tcp-ssh_eq, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

