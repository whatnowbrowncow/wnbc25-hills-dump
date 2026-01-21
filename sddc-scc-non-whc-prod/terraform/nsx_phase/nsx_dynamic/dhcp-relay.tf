resource "nsxt_policy_dhcp_relay" "WH_DHCP" {
  display_name     = "WH_DHCP"
  description      = "WH Infoblox DHCP Relay"
  server_addresses = ["10.120.193.235", "10.120.193.236"]
}