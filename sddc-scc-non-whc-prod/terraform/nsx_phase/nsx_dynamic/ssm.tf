data "aws_ssm_parameter" "non_whc_prod_nsx_admin_pw" {
  name = var.nsx_password_ssm_parameter
}