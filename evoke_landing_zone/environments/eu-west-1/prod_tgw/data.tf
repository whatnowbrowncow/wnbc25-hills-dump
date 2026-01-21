# Read Dev's state file to get the attachment ID
data "terraform_remote_state" "dev" {
  backend = "local"  # Since you're using local state files
  
  config = {
    path = "../dev_tgw/terraform.tfstate"
  }
}