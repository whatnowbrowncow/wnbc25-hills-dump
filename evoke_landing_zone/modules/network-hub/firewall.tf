# ------------------------------------------------------
# Firewall Policy
# ------------------------------------------------------
# Defines how traffic should be processed by the firewall
# Stateless rules process individual packets
# Stateful rules track connection state and can inspect application data

resource "aws_networkfirewall_firewall_policy" "main" {
  name = local.firewall_policy_name

  firewall_policy {
    # Stateless traffic handling
    # Forward all packets to stateful engine for deeper inspection
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    # Stateful traffic handling
    # Drop established connections that don't match rules
    # Alert on strict rule violations
    stateful_default_actions = [
      "aws:drop_established",
      "aws:alert_strict"
    ]

    # Process stateful rules in strict order (first match wins)
    stateful_engine_options {
      rule_order = "STRICT_ORDER"
    }

    # Attach rule groups to the policy
    dynamic "stateful_rule_group_reference" {
      for_each = local.active_rule_groups
      content {
        resource_arn = stateful_rule_group_reference.value.arn
        priority     = stateful_rule_group_reference.value.priority
      }
    }
  }

  # Resource tagging
  tags = merge(var.common_tags, {
    Name = local.firewall_policy_name
    Type = "firewall-policy"
  })
}

# ------------------------------------------------------
# Network Firewall
# ------------------------------------------------------
# The actual firewall appliance that processes traffic
# Deployed across multiple subnets for high availability

resource "aws_networkfirewall_firewall" "main" {
  name                = local.firewall_name
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.firewall.id

  # Deploy firewall endpoints across all availability zones
  # This ensures high availability and proper traffic distribution
  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall_endpoint
    content {
      subnet_id = subnet_mapping.value.id
    }
  }

  # Resource tagging
  tags = merge(var.common_tags, {
    Name = local.firewall_name
    Type = "network-firewall"
  })
}

# ------------------------------------------------------
# VPC Endpoint Associations
# ------------------------------------------------------
# Connects the firewall to egress VPC for traffic inspection
# Each subnet gets its own endpoint for traffic processing

# VPC endpoint association with explicit dependencies
resource "awscc_networkfirewall_vpc_endpoint_association" "egress" {
  for_each = { for idx, subnet in aws_subnet.egress_firewall_endpoint : idx => subnet }
  firewall_arn = aws_networkfirewall_firewall.main.arn
  vpc_id = aws_vpc.central_egress.id
  subnet_mapping = {
    subnet_id = each.value.id
  }
  tags = [
    for key, value in merge(var.common_tags, {
      Name = "${var.project_name}-${var.environment}-egress-fw-endpoint-${each.key}"
    }) : {
      key = key
      value = value
    }
  ]
  # Make dependencies explicit
  depends_on = [
    aws_networkfirewall_firewall.main,
    aws_subnet.egress_firewall_endpoint,
    aws_vpc.central_egress
  ]
}