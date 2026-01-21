#### Import the state from sddc phase and read the outputs
data "terraform_remote_state" "sddc_phase" {
  backend = "s3"

  config = {
    bucket = "${var.org}-${var.channel}-${var.product}-${var.env}-${var.region}-tfstate"
    key    = "${var.env}-sddc.tfstate"
    region = var.region
  }
}
