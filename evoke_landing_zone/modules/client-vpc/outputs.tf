# ==================================================
# CLIENT VPC MODULE - Outputs
# ==================================================

# ==================================================
# VPC OUTPUTS
# ==================================================
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "vpc_arn" {
  description = "ARN of the VPC"
  value       = aws_vpc.main.arn
}

# ==================================================
# SUBNET OUTPUTS
# ==================================================
output "workload_subnet_ids" {
  description = "List of workload subnet IDs"
  value       = aws_subnet.workload[*].id
}

output "workload_subnet_cidrs" {
  description = "List of workload subnet CIDR blocks"
  value       = aws_subnet.workload[*].cidr_block
}

output "workload_subnet_azs" {
  description = "List of availability zones for workload subnets"
  value       = aws_subnet.workload[*].availability_zone
}

output "tgw_subnet_ids" {
  description = "List of Transit Gateway attachment subnet IDs"
  value       = aws_subnet.tgw[*].id
}

output "tgw_subnet_cidrs" {
  description = "List of Transit Gateway subnet CIDR blocks"
  value       = aws_subnet.tgw[*].cidr_block
}

output "tgw_subnet_azs" {
  description = "List of availability zones for TGW subnets"
  value       = aws_subnet.tgw[*].availability_zone
}

# ==================================================
# ROUTE TABLE OUTPUTS
# ==================================================
output "workload_route_table_id" {
  description = "ID of the workload route table"
  value       = aws_route_table.workload.id
}

output "tgw_route_table_id" {
  description = "ID of the Transit Gateway route table"
  value       = aws_route_table.tgw.id
}

# ==================================================
# TRANSIT GATEWAY OUTPUTS
# ==================================================
output "tgw_attachment_id" {
  description = "ID of the Transit Gateway VPC attachment"
  value       = aws_ec2_transit_gateway_vpc_attachment.main.id
}

output "tgw_attachment_state" {
  description = "State of the Transit Gateway VPC attachment"
  value       = aws_ec2_transit_gateway_vpc_attachment.main.state
}

output "transit_gateway_id" {
  description = "ID of the Transit Gateway (passthrough)"
  value       = var.transit_gateway_id
}

# ==================================================
# FLOW LOGS OUTPUTS
# ==================================================
output "flow_logs_id" {
  description = "ID of the VPC Flow Logs"
  value       = var.enable_flow_logs ? aws_flow_log.main[0].id : null
}

output "flow_logs_log_group_name" {
  description = "Name of the CloudWatch Log Group for flow logs"
  value       = var.enable_flow_logs && var.flow_logs_destination_arn == "" ? aws_cloudwatch_log_group.flow_logs[0].name : null
}

output "flow_logs_role_arn" {
  description = "ARN of the IAM role for flow logs"
  value       = var.enable_flow_logs && var.flow_logs_role_arn == "" ? aws_iam_role.flow_logs[0].arn : var.flow_logs_role_arn
}

# ==================================================
# TEST INSTANCE OUTPUTS
# ==================================================
output "test_instance_id" {
  description = "ID of the test instance"
  value       = var.enable_test_instance ? aws_instance.test[0].id : null
}

output "test_instance_private_ip" {
  description = "Private IP address of the test instance"
  value       = var.enable_test_instance ? aws_instance.test[0].private_ip : null
}

output "test_instance_security_group_id" {
  description = "Security group ID for the test instance"
  value       = var.enable_test_instance ? aws_security_group.test_instance[0].id : null
}

# ==================================================
# METADATA OUTPUTS
# ==================================================
output "account_name" {
  description = "Account name"
  value       = var.account_name
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "availability_zones" {
  description = "Availability zones used"
  value       = var.availability_zones
}
