# modules/network-hub/shared-tgw-tags.tf


locals {
  # Explicitly check each environment variable (known at plan time)
  environments_to_check = {
    "dev"     = var.enable_dev_environment
    "nonprod" = var.enable_nonprod_environment
    "prod"    = var.enable_prod_environment
  }
  
  # Only tag environments that are enabled and not the current one
  tgws_to_tag = {
    for env, is_enabled in local.environments_to_check : 
    env => local.tgw_ids[env]
    if env != var.environment && is_enabled
  }
}

# Tag: Name
resource "aws_ec2_tag" "shared_tgw_name" {
  for_each = local.tgws_to_tag

  resource_id = each.value
  key         = "Name"
  value       = "network-hub-${each.key}-tgw"
}

# Tag: Environment
resource "aws_ec2_tag" "shared_tgw_environment" {
  for_each = local.tgws_to_tag

  resource_id = each.value
  key         = "Environment"
  value       = each.key
}

# Tag: SharedResource
resource "aws_ec2_tag" "shared_tgw_shared" {
  for_each = local.tgws_to_tag

  resource_id = each.value
  key         = "SharedResource"
  value       = "true"
}

# Tag: OwnerAccount
resource "aws_ec2_tag" "shared_tgw_owner" {
  for_each = local.tgws_to_tag

  resource_id = each.value
  key         = "OwnerAccount"
  value       = each.key
}

# Tag: OwnerAccountId
resource "aws_ec2_tag" "shared_tgw_owner_id" {
  for_each = local.tgws_to_tag

  resource_id = each.value
  key         = "OwnerAccountId"
  value       = local.environment_to_account[each.key]
}