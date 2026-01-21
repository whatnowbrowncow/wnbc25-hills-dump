/*=========================================================

###########################################################################
###########################################################################
###                                                                     ###
###             STATIC SHARED PORTS - NOT MIGRATED FROM SCC             ###
###                                                                     ###
###########################################################################
###########################################################################

=========================================================*/

resource "nsxt_policy_service" "ip-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ip-any"
  description  = "description: ip"
  ether_type_entry {
    ether_type = "2048"
  }
}

resource "nsxt_policy_service" "icmp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "icmp-any"
  description  = "description: icmp"
  icmp_entry {
    protocol = "ICMPv4"
  }
}

resource "nsxt_policy_service" "tcp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tcp-any"
  description  = "description: tcp-any"
  ip_protocol_entry {
    display_name = "tcp"
    protocol     = "6"
  }
}

resource "nsxt_policy_service" "udp-any" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "udp-any"
  description  = "description: udp-any"
  ip_protocol_entry {
    display_name = "udp"
    protocol     = "17"
  }
}