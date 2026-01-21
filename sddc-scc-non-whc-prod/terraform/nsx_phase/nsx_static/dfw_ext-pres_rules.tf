/*======================================

############ Example Format ############

resource "nsxt_policy_security_policy" "policy1" {
  display_name = "policy1"
  description = "Terraform provisioned Security Policy"
  category = "Application"
  locked = false
  stateful = true
  tcp_strict = false
  scope = [nsxt_policy_group.pets.path]
 
  rule {
    display_name = "block_icmp"
    destination_groups = [nsxt_policy_group.cats.path, nsxt_policy_group.dogs.path]
    action = "DROP"
    services = [nsxt_policy_service.icmp.path]
    logged = true
  }
 
  rule {
    display_name = "allow_udp"
    source_groups = [nsxt_policy_group.fish.path]
    sources_excluded = true
    scope = [nsxt_policy_group.aquarium.path]
    action = "ALLOW"
    services = [nsxt_policy_service.udp.path]
    logged = true
    disabled = true
    notes = "Disabled by starfish for debugging"
  }
}


How we will format and standardise this:

- The policy_security_policy on initial build is split into 2 sections: "Core_Management" and "SDDC_Specific"
  - "Core_Management" section holds the base rules for the SDDC, deployed when the SDDC is     instantiated and fully managed based on the Infra CoE team "dfw_core" TF module
  - "SDDC_Specific" section holds all channel specific rules for the SDDC. This is the section into which channel rules are deployed and is managed by Network Services
  
- The intial Security Policy resource names, display_names, descriptions, category, and stateful variables are fixed by the Infa CoE team TF code

- Additional Security Policy sections can be defined to allow for splitting up of the DFW rules into logical sections. E.g. for the SCC migration we will create a section for each ASA firewall context
- Each rule is defined in a "rule" section in the main nsxt_policy_security_policy TF resource:
  - "display_name" is optional, but would be useful to help identify a rule's purpose in the VMC GUI
  - "description" is a required element and must contain the ServiceNow FAR reference(s) for this rule


resource "nsxt_policy_security_policy" "( section_name )" {
  display_name = "( section_name )"
  description  = "Firewall section for ( section_name ) - ${var.specific_policy_description}"
  category     = var.category
  stateful     = var.stateful
  domain       = "cgw"
  rule {
    display_name       = "( rule_description | leave blank )"
    description        = "Change ref: ( list_of_far_refs )"
    action             = "( ALLOW | DROP )"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    source_groups      = [( list_of_source_groups )]
    destination_groups = [( list_of_destination_groups )]
    services           = [( list_of_service_groups )]
  }
  rule {
    display_name       = "( rule_description )"
    description        = "Change ref: ( list_of_far_refs )"
    action             = "( ALLOW | DROP )"
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    source_groups      = [( list_of_source_groups )]
    destination_groups = [( list_of_destination_groups )]
    services           = [( list_of_service_groups )]
  }
}

======================================*/

resource "nsxt_policy_security_policy" "ext-pres" {
  display_name    = "ext-pres"
  description     = "Firewall section for ext-pres"
  category        = var.category
  stateful        = var.stateful
  sequence_number = "80"
  domain          = "cgw"
  rule {
    display_name       = "ext-pres to pr-c-frontend"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "1"
    source_groups      = [nsxt_policy_group.ext-pres_network.path]
    destination_groups = [nsxt_policy_group.ext-pres_all_pr-c-frontend_networks.path]
  }
  rule {
    display_name       = "pr-c-frontend to ext-pres"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "2"
    source_groups      = [nsxt_policy_group.ext-pres_all_pr-c-frontend_networks.path]
    destination_groups = [nsxt_policy_group.ext-pres_network.path]
  }
  rule {
    display_name       = "ext-pres to pr-n-frontend"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "3"
    source_groups      = [nsxt_policy_group.ext-pres_network.path]
    destination_groups = [nsxt_policy_group.ext-pres_all_pr-n-frontend_networks.path]
  }
  rule {
    display_name       = "pr-n-frontend to ext-pres"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "4"
    source_groups      = [nsxt_policy_group.ext-pres_all_pr-n-frontend_networks.path]
    destination_groups = [nsxt_policy_group.ext-pres_network.path]
  }
  rule {
    display_name       = "ext-pres to pr-e-internal"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "5"
    source_groups      = [nsxt_policy_group.ext-pres_network.path]
    destination_groups = [nsxt_policy_group.ext-pres_all_pr-e-internal_networks.path]
  }
  rule {
    display_name       = "pr-e-internal to ext-pres"
    description        = "Change ref: CHG0146428"
    action             = "DROP"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "6"
    source_groups      = [nsxt_policy_group.ext-pres_all_pr-e-internal_networks.path]
    destination_groups = [nsxt_policy_group.ext-pres_network.path]
  }
  rule {
    display_name       = "ext-pres to ANY"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "7"
    source_groups      = [nsxt_policy_group.ext-pres_network.path]
    destination_groups = [nsxt_policy_group.wh_any.path]
  }
  rule {
    display_name       = "ANY to ext-pres"
    description        = "Change ref: CHG0146428"
    action             = "ALLOW"
    disabled           = false
    logged             = true
    ip_version         = "IPV4"
    direction          = "IN_OUT"
    sequence_number    = "8"
    source_groups      = [nsxt_policy_group.wh_any.path]
    destination_groups = [nsxt_policy_group.ext-pres_network.path]
  }
}
