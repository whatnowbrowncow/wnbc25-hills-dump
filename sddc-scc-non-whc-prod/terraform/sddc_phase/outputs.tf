output "nsxt_reverse_proxy" {
  value = module.sddc.nsxt_reverse_proxy
}

output "vc_url" {
  value = module.sddc.vc_url
}

output "cloud_username" {
  value = module.sddc.cloud_username
}

output "cloud_password" {
  value     = module.sddc.cloud_password
  sensitive = true
}
