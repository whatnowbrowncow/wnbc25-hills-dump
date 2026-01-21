# ==================================================
# AWS Resource Access Manager (RAM) Configuration
# ==================================================
# This file creates RAM shares to allow other AWS accounts in the organization
# to access the Transit Gateway for cross-account connectivity
# ==================================================


# ==================================================
# RAM RESOURCE SHARE
# ==================================================
# Creates a resource share for the Transit Gateway

resource "aws_ram_resource_share" "transit_gateway_share" {
  name                      = "${var.project_name}-${var.environment}-tgw-share"
  allow_external_principals = false  # Only share within organization

  tags = merge(var.common_tags, {
    Name    = "${var.project_name}-${var.environment}-tgw-share"
    Type    = "ram-share"
    Purpose = "transit-gateway-cross-account-access"
  })
}

# ==================================================
# RESOURCE ASSOCIATIONS
# ==================================================
# Associate resources with the RAM share

# ------------------------------------------------------
# Transit Gateway Association
# ------------------------------------------------------
# Makes the Transit Gateway available through the RAM share

resource "aws_ram_resource_association" "transit_gateway_share" {
  resource_arn       = aws_ec2_transit_gateway.main.arn
  resource_share_arn = aws_ram_resource_share.transit_gateway_share.arn
}

# ==================================================
# PRINCIPAL ASSOCIATIONS
# ==================================================
# Define who can access the shared resources

# ------------------------------------------------------
# Organization-wide Access
# ------------------------------------------------------
# Share with entire AWS Organization for cross-account connectivity
# Uses management account ID for organization ARN

resource "aws_ram_principal_association" "organization" {
  principal          = "arn:aws:organizations::703671905140:organization/${var.organization_id}"
  resource_share_arn = aws_ram_resource_share.transit_gateway_share.arn

  # Ensure resource association is complete before principal association
  depends_on = [
    aws_ram_resource_association.transit_gateway_share
  ]
}