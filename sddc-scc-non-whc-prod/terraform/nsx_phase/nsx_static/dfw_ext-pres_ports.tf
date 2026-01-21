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

resource "nsxt_policy_service" "ext-pres_tcp-ssh_eq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ext-pres_tcp-ssh_eq"
  description  = "description: tcp-ssh_eq, services: [tcp22]"
  l4_port_set_entry {
    protocol          = "TCP"
    destination_ports = ["22"]
  }
}

