# modules/network-hub/transit-gateway-peering.tf

# ==================================================
# PEERING ATTACHMENT CREATION (INITIATOR SIDE - DEV)
# ==================================================

resource "aws_ec2_transit_gateway_peering_attachment" "dev_to_prod" {
  count = var.environment == "dev" && var.enable_dev_prod_peering ? 1 : 0

  peer_account_id         = local.environment_to_account["prod"]
  peer_region             = var.region
  peer_transit_gateway_id = local.tgw_ids["prod"]
  transit_gateway_id      = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name              = "tgw-peering-dev-to-prod"
    Type              = "tgw-peering"
    Side              = "Initiator"
    Direction         = "outbound"
    SourceEnvironment = "dev"
    TargetEnvironment = "prod"
    SourceAccountId   = local.environment_to_account["dev"]
    TargetAccountId   = local.environment_to_account["prod"]
  })
}

# ==================================================
# ROUTE TABLE ASSOCIATION (INITIATOR SIDE - DEV)
# ==================================================

resource "aws_ec2_transit_gateway_route_table_association" "dev_to_prod" {
  count = var.environment == "dev" && var.enable_dev_prod_peering ? 1 : 0

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.dev_to_prod[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

# ==================================================
# STATIC ROUTES (INITIATOR SIDE - DEV)
# ==================================================

resource "aws_ec2_transit_gateway_route" "dev_to_prod" {
  count = var.environment == "dev" && var.enable_dev_prod_peering ? 1 : 0

  destination_cidr_block         = var.prod_supernet_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.dev_to_prod[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

data "external" "dev_peering_attachment" {
  count = var.environment == "prod" && var.enable_dev_prod_peering ? 1 : 0
  
  program = ["bash", "-c", <<-EOT
    result=$(aws ec2 describe-transit-gateway-peering-attachments \
      --region ${var.region} \
      --filters \
        "Name=transit-gateway-id,Values=${aws_ec2_transit_gateway.main.id}" \
        "Name=state,Values=available,pendingAcceptance" \
      --output json | jq '.TransitGatewayPeeringAttachments[] | select(.RequesterTgwInfo.OwnerId=="${local.environment_to_account["dev"]}") | {id: .TransitGatewayAttachmentId}')
    
    if [ -z "$result" ]; then
      echo '{"id":""}'
    else
      echo "$result"
    fi
  EOT
  ]
}

locals {
  # Keep this one
  dev_to_prod_attachment_id = var.environment == "prod" && var.enable_dev_prod_peering ? try(
    data.external.dev_peering_attachment[0].result.id,
    ""
  ) : ""
  
  dev_to_nonprod_attachment_id = var.environment == "nonprod" && var.enable_dev_nonprod_peering ? try(
    data.external.dev_peering_attachment_nonprod[0].result.id,
    ""
  ) : ""
  
  nonprod_to_prod_attachment_id = var.environment == "prod" && var.enable_nonprod_prod_peering ? try(
    data.external.nonprod_peering_attachment[0].result.id,
    ""
  ) : ""
}

# ==================================================
# PEERING ACCEPTANCE (ACCEPTER SIDE - PROD)
# ==================================================

resource "aws_ec2_transit_gateway_peering_attachment_accepter" "from_dev_to_prod" {
  count = var.environment == "prod" && var.enable_dev_prod_peering ? 1 : 0

  transit_gateway_attachment_id = local.dev_to_prod_attachment_id

  tags = merge(var.common_tags, {
    Name              = "tgw-peering-dev-to-prod"
    Type              = "tgw-peering"
    Side              = "Accepter"
    Direction         = "inbound"
    SourceEnvironment = "dev"
    TargetEnvironment = "prod"
    SourceAccountId   = local.environment_to_account["dev"]
    TargetAccountId   = local.environment_to_account["prod"]
  })
}

# ==================================================
# ROUTE TABLE ASSOCIATION (ACCEPTER SIDE - PROD)
# ==================================================

resource "aws_ec2_transit_gateway_route_table_association" "from_dev_to_prod" {
  count = var.environment == "prod" && var.enable_dev_prod_peering ? 1 : 0
  transit_gateway_attachment_id  = local.dev_to_prod_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  
  depends_on = [aws_ec2_transit_gateway_peering_attachment_accepter.from_dev_to_prod]
}

# ==================================================
# STATIC ROUTES (ACCEPTER SIDE - PROD)
# ==================================================

resource "aws_ec2_transit_gateway_route" "prod_to_dev" {
  count = var.environment == "prod" && var.enable_dev_prod_peering ? 1 : 0

  destination_cidr_block         = var.dev_supernet_cidr
  transit_gateway_attachment_id  = local.dev_to_prod_attachment_id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  
  depends_on = [aws_ec2_transit_gateway_peering_attachment_accepter.from_dev_to_prod]
}


# ==================================================
# DEV → NONPROD PEERING
# ==================================================

# ------------------------------------------------------
# PEERING ATTACHMENT CREATION (INITIATOR SIDE - DEV)
# ------------------------------------------------------

resource "aws_ec2_transit_gateway_peering_attachment" "dev_to_nonprod" {
  count = var.environment == "dev" && var.enable_dev_nonprod_peering ? 1 : 0

  peer_account_id         = local.environment_to_account["nonprod"]
  peer_region             = var.region
  peer_transit_gateway_id = local.tgw_ids["nonprod"]
  transit_gateway_id      = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name              = "tgw-peering-dev-to-nonprod"
    Type              = "tgw-peering"
    Side              = "Initiator"
    Direction         = "outbound"
    SourceEnvironment = "dev"
    TargetEnvironment = "nonprod"
    SourceAccountId   = local.environment_to_account["dev"]
    TargetAccountId   = local.environment_to_account["nonprod"]
  })
}

resource "aws_ec2_transit_gateway_route_table_association" "dev_to_nonprod" {
  count = var.environment == "dev" && var.enable_dev_nonprod_peering ? 1 : 0

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.dev_to_nonprod[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

resource "aws_ec2_transit_gateway_route" "dev_to_nonprod" {
  count = var.environment == "dev" && var.enable_dev_nonprod_peering ? 1 : 0

  destination_cidr_block         = var.nonprod_supernet_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.dev_to_nonprod[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

# ------------------------------------------------------
# PEERING ATTACHMENT DISCOVERY (ACCEPTER SIDE - NONPROD)
# ------------------------------------------------------

data "external" "dev_peering_attachment_nonprod" {
  count = var.environment == "nonprod" && var.enable_dev_nonprod_peering ? 1 : 0
  
  program = ["bash", "-c", <<-EOT
    result=$(aws ec2 describe-transit-gateway-peering-attachments \
      --region ${var.region} \
      --filters \
        "Name=transit-gateway-id,Values=${aws_ec2_transit_gateway.main.id}" \
        "Name=state,Values=available,pendingAcceptance" \
      --output json | jq '.TransitGatewayPeeringAttachments[] | select(.RequesterTgwInfo.OwnerId=="${local.environment_to_account["dev"]}") | {id: .TransitGatewayAttachmentId}')
    
    if [ -z "$result" ]; then
      echo '{"id":""}'
    else
      echo "$result"
    fi
  EOT
  ]
}

# ------------------------------------------------------
# PEERING ACCEPTANCE (ACCEPTER SIDE - NONPROD)
# ------------------------------------------------------

resource "aws_ec2_transit_gateway_peering_attachment_accepter" "from_dev_to_nonprod" {
  count = var.environment == "nonprod" && var.enable_dev_nonprod_peering ? 1 : 0

  transit_gateway_attachment_id = data.external.dev_peering_attachment_nonprod[0].result.id

  lifecycle {
    precondition {
      condition     = can(data.external.dev_peering_attachment_nonprod[0].result.id)
      error_message = "No pending peering attachment found from Dev. Ensure Dev has created the peering first."
    }
  }

  tags = merge(var.common_tags, {
    Name              = "tgw-peering-dev-to-nonprod"
    Type              = "tgw-peering"
    Side              = "Accepter"
    Direction         = "inbound"
    SourceEnvironment = "dev"
    TargetEnvironment = "nonprod"
    SourceAccountId   = local.environment_to_account["dev"]
    TargetAccountId   = local.environment_to_account["nonprod"]
  })
}

resource "aws_ec2_transit_gateway_route_table_association" "from_dev_to_nonprod" {
  count = var.environment == "nonprod" && var.enable_dev_nonprod_peering ? 1 : 0

  transit_gateway_attachment_id  = data.external.dev_peering_attachment_nonprod[0].result.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  
  depends_on = [aws_ec2_transit_gateway_peering_attachment_accepter.from_dev_to_nonprod]
}

resource "aws_ec2_transit_gateway_route" "nonprod_to_dev" {
  count = var.environment == "nonprod" && var.enable_dev_nonprod_peering ? 1 : 0

  destination_cidr_block         = var.dev_supernet_cidr
  transit_gateway_attachment_id  = data.external.dev_peering_attachment_nonprod[0].result.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  
  depends_on = [aws_ec2_transit_gateway_peering_attachment_accepter.from_dev_to_nonprod]
}

# ==================================================
# NONPROD → PROD PEERING
# ==================================================

# ------------------------------------------------------
# PEERING ATTACHMENT CREATION (INITIATOR SIDE - NONPROD)
# ------------------------------------------------------

resource "aws_ec2_transit_gateway_peering_attachment" "nonprod_to_prod" {
  count = var.environment == "nonprod" && var.enable_nonprod_prod_peering ? 1 : 0

  peer_account_id         = local.environment_to_account["prod"]
  peer_region             = var.region
  peer_transit_gateway_id = local.tgw_ids["prod"]
  transit_gateway_id      = aws_ec2_transit_gateway.main.id

  tags = merge(var.common_tags, {
    Name              = "tgw-peering-nonprod-to-prod"
    Type              = "tgw-peering"
    Side              = "Initiator"
    Direction         = "outbound"
    SourceEnvironment = "nonprod"
    TargetEnvironment = "prod"
    SourceAccountId   = local.environment_to_account["nonprod"]
    TargetAccountId   = local.environment_to_account["prod"]
  })
}

resource "aws_ec2_transit_gateway_route_table_association" "nonprod_to_prod" {
  count = var.environment == "nonprod" && var.enable_nonprod_prod_peering ? 1 : 0

  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.nonprod_to_prod[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

resource "aws_ec2_transit_gateway_route" "nonprod_to_prod" {
  count = var.environment == "nonprod" && var.enable_nonprod_prod_peering ? 1 : 0

  destination_cidr_block         = var.prod_supernet_cidr
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_peering_attachment.nonprod_to_prod[0].id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
}

# ------------------------------------------------------
# PEERING ATTACHMENT DISCOVERY (ACCEPTER SIDE - PROD)
# ------------------------------------------------------

# For Nonprod → Prod
data "external" "nonprod_peering_attachment" {
  count = var.environment == "prod" && var.enable_nonprod_prod_peering ? 1 : 0
  
  program = ["bash", "-c", <<-EOT
    result=$(aws ec2 describe-transit-gateway-peering-attachments \
      --region ${var.region} \
      --filters \
        "Name=transit-gateway-id,Values=${aws_ec2_transit_gateway.main.id}" \
        "Name=state,Values=available,pendingAcceptance" \
      --output json | jq '.TransitGatewayPeeringAttachments[] | select(.RequesterTgwInfo.OwnerId=="${local.environment_to_account["nonprod"]}") | {id: .TransitGatewayAttachmentId}')
    
    if [ -z "$result" ]; then
      echo '{"id":""}'
    else
      echo "$result"
    fi
  EOT
  ]
}

# ------------------------------------------------------
# PEERING ACCEPTANCE (ACCEPTER SIDE - PROD)
# ------------------------------------------------------

resource "aws_ec2_transit_gateway_peering_attachment_accepter" "from_nonprod_to_prod" {
  count = var.environment == "prod" && var.enable_nonprod_prod_peering ? 1 : 0

  transit_gateway_attachment_id = data.external.nonprod_peering_attachment[0].result.id

  lifecycle {
    precondition {
      condition     = can(data.external.nonprod_peering_attachment[0].result.id)
      error_message = "No pending peering attachment found from Nonprod. Ensure Nonprod has created the peering first."
    }
  }

  tags = merge(var.common_tags, {
    Name              = "tgw-peering-nonprod-to-prod"
    Type              = "tgw-peering"
    Side              = "Accepter"
    Direction         = "inbound"
    SourceEnvironment = "nonprod"
    TargetEnvironment = "prod"
    SourceAccountId   = local.environment_to_account["nonprod"]
    TargetAccountId   = local.environment_to_account["prod"]
  })
}

resource "aws_ec2_transit_gateway_route_table_association" "from_nonprod_to_prod" {
  count = var.environment == "prod" && var.enable_nonprod_prod_peering ? 1 : 0

  transit_gateway_attachment_id  = data.external.nonprod_peering_attachment[0].result.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  
  depends_on = [aws_ec2_transit_gateway_peering_attachment_accepter.from_nonprod_to_prod]
}

resource "aws_ec2_transit_gateway_route" "prod_to_nonprod" {
  count = var.environment == "prod" && var.enable_nonprod_prod_peering ? 1 : 0

  destination_cidr_block         = var.nonprod_supernet_cidr
  transit_gateway_attachment_id  = data.external.nonprod_peering_attachment[0].result.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.main.id
  
  depends_on = [aws_ec2_transit_gateway_peering_attachment_accepter.from_nonprod_to_prod]
}