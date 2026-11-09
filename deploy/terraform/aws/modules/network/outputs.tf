output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "availability_zones" {
  value = local.azs
}

output "public_subnet_ids" {
  value = [for az in local.azs : aws_subnet.public[az].id]
}

output "private_subnet_ids" {
  value = [for az in local.azs : aws_subnet.private[az].id]
}

output "isolated_subnet_ids" {
  value = [for az in local.azs : aws_subnet.isolated[az].id]
}

output "private_subnet_cidrs" {
  value = [for az in local.azs : aws_subnet.private[az].cidr_block]
}

output "isolated_subnet_cidrs" {
  value = [for az in local.azs : aws_subnet.isolated[az].cidr_block]
}

output "nat_public_ips" {
  value = [for az in local.nat_azs : aws_eip.nat[az].public_ip]
}

output "vpc_endpoint_security_group_id" {
  value = aws_security_group.endpoints.id
}

output "flow_log_group_name" {
  value = aws_cloudwatch_log_group.flow.name
}

# Regional S3 prefix-list CIDRs routed through the gateway endpoint (NetworkPolicy egress for ota).
output "s3_gateway_cidrs" {
  value = aws_vpc_endpoint.s3.cidr_blocks
}
