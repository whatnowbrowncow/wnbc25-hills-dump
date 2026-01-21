aws_account_number = "784159675407"
clusters = [
  {
    cluster            = "2"
    num_hosts          = "6"
    host_instance_type = "I3_METAL"
    min_hosts          = 6
  },
]
deployment_type    = "MultiAZ"
edrs_policy_type   = "storage-scaleup"
enable_edrs        = true
host_instance_type = "I3_METAL"
max_hosts          = 16
min_hosts          = 6
num_hosts          = 16
org_id             = "2424d387-d5e6-4b7c-bd7e-646ef5ea22f9"
sddc_name          = "SCC-NON-WHC-PROD"
sddc_type          = "DEFAULT"
vpc_cidr           = "10.126.224.0/20"
vxlan_subnet       = "192.168.1.0/24"
size               = "large"
subnet_1           = 1
subnet_2           = 2
