# ==================================================
# Network Firewall Rules Configuration
# ==================================================
# This file defines firewall rules for AWS Network Firewall
# - IP-based rules for specific network access control
# - Domain allowlist rules for HTTP/HTTPS traffic filtering
# ==================================================

# ------------------------------------------------------
# Data Processing - Combine Environment and Global Rules
# ------------------------------------------------------

locals {
  # Combine IP rules: Environment-specific rules take precedence over global rules
  all_ip_rules = concat(
    var.environment_ip_rules,
    local.global_ip_rules
  )

  # Combine domain rules: Merge allowed domains from both sources
  all_allowed_domains = concat(
    var.environment_domain_rules.allowed_domains,
    local.global_domain_rules.allowed_domains
  )

  # Auto-generate unique SID numbers for each IP rule
  # SID (Signature ID) is required for Suricata rule identification
  ip_rules_with_sid = [
    for idx, rule in local.all_ip_rules : merge(rule, {
      sid = idx + 1
    })
  ]
}

# ------------------------------------------------------
# IP-Based Rule Group
# ------------------------------------------------------
# Creates stateful firewall rules for IP-based traffic control
# Only creates the resource if there are IP rules to process

resource "aws_networkfirewall_rule_group" "ip_rules" {
  count = length(local.all_ip_rules) > 0 ? 1 : 0

  # Basic configuration
  name     = "${var.project_name}-${var.environment}-ip-rule-group"
  type     = "STATEFUL"
  capacity = 100

  rule_group {
    # Process rules in strict order (first match wins)
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      # Create individual stateful rules for each IP rule
      dynamic "stateful_rule" {
        for_each = local.ip_rules_with_sid
        content {
          action = stateful_rule.value.action

          # Define traffic flow characteristics
          header {
            destination      = stateful_rule.value.destination
            destination_port = stateful_rule.value.port
            direction        = "ANY"
            protocol         = stateful_rule.value.protocol
            source           = stateful_rule.value.source
            source_port      = "ANY"
          }

          # Add unique identifier for rule tracking
          rule_option {
            keyword  = "sid"
            settings = [tostring(stateful_rule.value.sid)]
          }
        }
      }
    }
  }

  # Resource tagging
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-ip-rule-group"
    Type = "rule-group"
  })
}

# ------------------------------------------------------
# Domain Allowlist Rule Group
# ------------------------------------------------------
# Creates rules to allow HTTP/HTTPS traffic to specific domains
# Uses AWS Network Firewall's built-in domain filtering capability

resource "aws_networkfirewall_rule_group" "domain_allowlist" {
  count = length(local.all_allowed_domains) > 0 ? 1 : 0

  # Basic configuration
  name     = "${var.project_name}-${var.environment}-domain-allowlist"
  type     = "STATEFUL"
  capacity = 100

  rule_group {
    # Define network variables for rule context
    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set {
          definition = [
            var.local_supernet_cidr # Internal network range
          ]
        }
      }
    }

    # Process rules in strict order
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      # Use AWS managed domain list functionality
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets              = local.all_allowed_domains
      }
    }
  }

  # Resource tagging
  tags = merge(var.common_tags, {
    Name = "${var.project_name}-${var.environment}-domain-allowlist"
    Type = "rule-group"
  })
}