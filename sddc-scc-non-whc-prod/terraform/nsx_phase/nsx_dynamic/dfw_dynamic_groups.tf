/*========================================

###########################################################################
###########################################################################
###                                                                     ###
###               DYNAMIC GROUPS - NOT MIGRATED FROM SCC                ###
###                                                                     ###
###########################################################################
###########################################################################

========================================*/

resource "nsxt_policy_group" "vmc_corp_subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vmc_corp_subnets"
  description  = "role: all scc corporate networks migrated to vmc, ip: [10.120.192.0/23, 10.120.194.0/25, 10.120.194.160/27, 10.120.194.192/26, 10.120.196.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.0/23", "10.120.194.0/25", "10.120.194.160/27", "10.120.194.192/26", "10.120.196.0/22"]
    }
  }
}
resource "nsxt_policy_group" "rfc_1918" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "rfc_1918"
  description  = "role: internal private address space, ip: [10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    }
  }
}
resource "nsxt_policy_group" "rfc_6598" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "rfc_6598"
  description  = "role: shared address space - internal AWS IP range, ip: [100.64.0.0/10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.64.0.0/10"]
    }
  }
}
resource "nsxt_policy_group" "opendns_virtual_appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "opendns_virtual_appliances"
  description  = "role: opendns virtual appliances, ip: [10.120.193.238, 10.120.193.239]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.238", "10.120.193.239"]
    }
  }
}
resource "nsxt_policy_group" "opendns_ntp_service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "opendns_ntp_service"
  description  = "role: opendns ntp servers, ip: [91.189.94.4, 91.189.89.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["91.189.94.4", "91.189.89.199"]
    }
  }
}
resource "nsxt_policy_group" "opendns_dns_service" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "opendns_dns_service"
  description  = "role: opendns dns servers, ip: [67.215.71.201, 72.21.91.29, 117.18.237.29, 208.67.220.220, 208.67.220.222, 208.67.222.220, 208.67.222.222, 67.215.92.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["67.215.71.201", "72.21.91.29", "117.18.237.29", "208.67.220.220", "208.67.220.222", "208.67.222.220", "208.67.222.222", "67.215.92.0/24"]
    }
  }
}
resource "nsxt_policy_group" "internet_minus_rfc1918" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "internet_minus_rfc1918"
  description  = "role: internet minus rfc 1918, ip: [0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12", "172.32.0.0/11", "172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7", "176.0.0.0/4", "192.0.0.0/9", "192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14", "192.176.0.0/12", "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5", "208.0.0.0/4"]
    }
  }
}
resource "nsxt_policy_group" "wh_apogee_external_site" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "wh_apogee_external_site"
  description  = "role: william-hill.apogee.eu.eophcp.com, ip: [34.252.199.173, 18.202.147.163, 52.19.122.66, 52.50.253.210]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["34.252.199.173", "18.202.147.163", "52.19.122.66", "52.50.253.210"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpregw01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpregw01"
  description  = "role: sc1uxpregw01, ip: [10.120.194.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.40"]
    }
  }
}
resource "nsxt_policy_group" "aws_storage_gateway" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_storage_gateway"
  description  = "role: ireprnapsg01.prod.williamhill.plc, ip: [10.156.5.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.170"]
    }
  }
}
resource "nsxt_policy_group" "scc_dc_networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_dc_networks"
  description  = "role: scc_dc_networks, ip: [10.120.0.0/16, 10.121.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.0.0/16", "10.121.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "uno_presentation_access_group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_presentation_access_group"
  description  = "role: This group is for user access to UNO Presentation SQL Server, ip: [10.40.9.55, 10.55.15.233, 10.55.224.197, 10.56.225.38, 10.1.74.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.9.55", "10.55.15.233", "10.55.224.197", "10.56.225.38", "10.1.74.212"]
    }
  }
}
resource "nsxt_policy_group" "uno_sandbox_access_group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_sandbox_access_group"
  description  = "role: This group is for user access to UNO Sandbox SQL Server, ip: [10.40.9.55, 10.55.15.233, 10.55.224.197, 10.56.225.38, 10.1.74.212]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.9.55", "10.55.15.233", "10.55.224.197", "10.56.225.38", "10.1.74.212"]
    }
  }
}
resource "nsxt_policy_group" "uno_cube_access_group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_cube_access_group"
  description  = "role: This group is for user access to the various UNO Cube SQL Server Instances, ip: [10.40.9.55, 10.55.15.233, 10.55.224.197]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.9.55", "10.55.15.233", "10.55.224.197"]
    }
  }
}
resource "nsxt_policy_group" "uno_dpe_access_group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_dpe_access_group"
  description  = "role: This group is for user access to the various UNO DPE Services, ip: [10.40.9.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.9.55"]
    }
  }
}
resource "nsxt_policy_group" "uno_presentation_lb_vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_presentation_lb_vip"
  description  = "role: UNO Presentation Database VIP, ip: [10.120.74.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.51"]
    }
  }
}
resource "nsxt_policy_group" "uno_sandbox_lb_vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_sandbox_lb_vip"
  description  = "role: UNO Sandbox Database VIP, ip: [10.120.74.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.50"]
    }
  }
}
resource "nsxt_policy_group" "uno_cube_lb_vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_cube_lb_vip"
  description  = "role: UNO Cube Database VIP, ip: [10.120.74.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.22"]
    }
  }
}
resource "nsxt_policy_group" "uno_dpe_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_dpe_servers"
  description  = "role: UNO DPE Servers, ip: [10.120.100.80, 10.120.100.81, 10.120.100.82, 10.120.100.83, 10.120.100.84, 10.120.100.86, 10.120.100.88]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.80", "10.120.100.81", "10.120.100.82", "10.120.100.83", "10.120.100.84", "10.120.100.86", "10.120.100.88"]
    }
  }
}
resource "nsxt_policy_group" "role-modelvillage-zookeeper" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "role-modelvillage-zookeeper"
  description  = "role: CHG0146652, ip: [10.121.67.29, 10.121.67.63]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.67.29", "10.121.67.63"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprndb004" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprndb004"
  description  = "role: CHG0146652, ip: [10.120.100.18, 10.120.100.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.18", "10.120.100.20"]
    }
  }
}
resource "nsxt_policy_group" "brsuxdrrdb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brsuxdrrdb04"
  description  = "role: CHG0146480, ip: [10.200.4.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.200.4.15"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprnap013" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprnap013"
  description  = "role: CHG0146447, ip: [10.120.66.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.246"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprgdb05_06_cluster" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprgdb05_06_cluster"
  description  = "role: CHG0146447, ip: [10.120.99.52, 10.120.99.54, 10.120.99.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.52", "10.120.99.54", "10.120.99.55"]
    }
  }
}
resource "nsxt_policy_group" "vmcprapvrli02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vmcprapvrli02"
  description  = "role: CHG0146817, ip: [10.156.4.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.4.23"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpremn126" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpremn126"
  description  = "role: CHG0146817, ip: [10.120.163.126]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.126"]
    }
  }
}
resource "nsxt_policy_group" "irewnprewb10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnprewb10"
  description  = "role: CHG0146931, ip: [10.120.103.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.103.3"]
    }
  }
}
resource "nsxt_policy_group" "irewnpreap10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnpreap10"
  description  = "role: CHG0146931, ip: [10.120.103.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.103.4"]
    }
  }
}
resource "nsxt_policy_group" "end_user_accurate_access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "end_user_accurate_access"
  description  = "role: CHG0146931, ip: [10.1.71.101, 10.1.71.102, 10.1.82.184, 10.1.82.24, 10.1.83.11, 10.1.83.154, 10.1.83.221, 10.1.83.5, 10.53.32.107, 10.53.32.93, 10.53.33.120, 10.53.33.56, 10.55.14.80]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.71.101", "10.1.71.102", "10.1.82.184", "10.1.82.24", "10.1.83.11", "10.1.83.154", "10.1.83.221", "10.1.83.5", "10.53.32.107", "10.53.32.93", "10.53.33.120", "10.53.33.56", "10.55.14.80"]
    }
  }
}
resource "nsxt_policy_group" "scc_citrix" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_citrix"
  description  = "role: CHG0146931, ip: [10.120.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "brs_citrix" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brs_citrix"
  description  = "role: CHG0146931, ip: [10.210.39.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.0/24"]
    }
  }
}
resource "nsxt_policy_group" "aws_accurate_prod_database" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_accurate_prod_database"
  description  = "role: CHG0146931, ip: [100.79.16.0/23, 100.79.18.0/23, 100.79.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.16.0/23", "100.79.18.0/23", "100.79.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "aws_active_directory" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_active_directory"
  description  = "role: CHG0146931, ip: [100.97.1.135, 100.97.1.167, 100.72.225.135, 100.72.225.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.97.1.135", "100.97.1.167", "100.72.225.135", "100.72.225.167"]
    }
  }
}
resource "nsxt_policy_group" "infoblox_grid_ex_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "infoblox_grid_ex_scc"
  description  = "role: CHG0146931, ip: [10.210.193.235, 10.210.193.236, 10.180.193.235, 10.180.193.236, 10.112.208.11, 10.112.208.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.193.235", "10.210.193.236", "10.180.193.235", "10.180.193.236", "10.112.208.11", "10.112.208.12"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnpreap10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnpreap10"
  description  = "role: CHG0146931, ip: [10.120.99.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.81"]
    }
  }
}
resource "nsxt_policy_group" "ld6wnpreap10" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wnpreap10"
  description  = "role: CHG0146931, ip: [10.118.214.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.214.32"]
    }
  }
}
resource "nsxt_policy_group" "snow_mid_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "snow_mid_servers"
  description  = "role: CHG0146988, ip: [10.120.163.138, 10.120.163.139, 10.120.163.141]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.138", "10.120.163.139", "10.120.163.141"]
    }
  }
}
resource "nsxt_policy_group" "williamhillssl-cloudsoftcat-com-secondary" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "williamhillssl-cloudsoftcat-com-secondary"
  description  = "role: CHG0146988, ip: [130.0.80.205]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["130.0.80.205"]
    }
  }
}
resource "nsxt_policy_group" "trs_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "trs_servers"
  description  = "role: CHG0147001, ip: [10.120.101.10, 10.120.101.11, 10.120.101.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.101.10", "10.120.101.11", "10.120.101.12"]
    }
  }
}
resource "nsxt_policy_group" "trs_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "trs_db"
  description  = "role: NETAR-6589, ip: [10.120.101.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.101.16"]
    }
  }
}
resource "nsxt_policy_group" "gib_rss_server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "gib_rss_server"
  description  = "role: CHG0147001, ip: [10.180.139.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.139.140"]
    }
  }
}
resource "nsxt_policy_group" "ld6_rss_server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6_rss_server"
  description  = "role: CHG0147001, ip: [10.118.104.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.104.32"]
    }
  }
}
resource "nsxt_policy_group" "non-cde-bomgar-jump-hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "non-cde-bomgar-jump-hosts"
  description  = "role: CHG0147120, ip: [10.120.151.31, 10.120.151.32, 10.120.151.33, 10.120.151.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.31", "10.120.151.32", "10.120.151.33", "10.120.151.34"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpremg32" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpremg32"
  description  = "role: CHG0147120, ip: [10.120.163.130]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.130"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprbkcs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprbkcs01"
  description  = "role: CHG0147150, ip: [10.120.46.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30"]
    }
  }
}
resource "nsxt_policy_group" "commvault_mrg_media_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "commvault_mrg_media_servers"
  description  = "role: CHG0147150, ip: [10.40.46.0/24, 10.130.46.0/24, 10.131.46.0/24, 10.132.46.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.46.0/24", "10.130.46.0/24", "10.131.46.0/24", "10.132.46.0/24"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprndb002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprndb002"
  description  = "role: CHG0147230, ip: [10.120.100.224]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.224"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprcmn250" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprcmn250"
  description  = "role: CHG0147215, ip: [10.120.163.250]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.250"]
    }
  }
}
resource "nsxt_policy_group" "retail_vmc_retail_db_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "retail_vmc_retail_db_servers"
  description  = "role: CHG0147260, ip: [10.233.0.60, 10.233.0.62, 10.233.0.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.0.60", "10.233.0.62", "10.233.0.64"]
    }
  }
}
resource "nsxt_policy_group" "spotlight_monitoring_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "spotlight_monitoring_servers"
  description  = "role: CHG0147215, ip: [10.118.160.170, 10.118.160.171, 10.118.160.172, 10.118.160.172]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.170", "10.118.160.171", "10.118.160.172", "10.118.160.172"]
    }
  }
}
resource "nsxt_policy_group" "ld6_uno_db_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6_uno_db_servers"
  description  = "role: CHG0147209, ip: [10.118.160.161, 10.118.160.162, 10.118.160.163, 10.118.160.164, 10.118.160.165, 10.118.160.166, 10.118.160.169, 10.118.160.170, 10.118.160.172, 10.118.160.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.161", "10.118.160.162", "10.118.160.163", "10.118.160.164", "10.118.160.165", "10.118.160.166", "10.118.160.169", "10.118.160.170", "10.118.160.172", "10.118.160.174"]
    }
  }
}
resource "nsxt_policy_group" "uipath_robot_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uipath_robot_servers"
  description  = "role: CHG0147311, ip: [10.120.66.59, 10.120.66.60, 10.120.66.61, 10.120.66.62, 10.120.66.63, 10.120.66.64, 10.120.66.65, 10.120.66.66, 10.120.66.67, 10.120.66.68, 10.120.71.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.59", "10.120.66.60", "10.120.66.61", "10.120.66.62", "10.120.66.63", "10.120.66.64", "10.120.66.65", "10.120.66.66", "10.120.66.67", "10.120.66.68", "10.120.71.0/24"]
    }
  }
}
resource "nsxt_policy_group" "mrg_nyx_services_for_uipath" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mrg_nyx_services_for_uipath"
  description  = "role: CHG0147311, ip: [10.1.76.11, 10.10.21.6, 10.10.21.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.76.11", "10.10.21.6", "10.10.21.12"]
    }
  }
}
resource "nsxt_policy_group" "uipath_robot_server_subnet" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uipath_robot_server_subnet"
  description  = "role: CHG0147284, ip: [10.120.71.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.71.0/24"]
    }
  }
}
resource "nsxt_policy_group" "jira_mrgreen_zone" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "jira_mrgreen_zone"
  description  = "role: CHG0147284, ip: [10.40.220.10, 172.17.100.225]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.220.10", "172.17.100.225"]
    }
  }
}
resource "nsxt_policy_group" "whdpmigration02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whdpmigration02"
  description  = "role: CHG0147317, ip: [10.118.160.175]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.175"]
    }
  }
}
resource "nsxt_policy_group" "scc_uno_db_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_uno_db_servers"
  description  = "role: CHG0147317, ip: [10.120.100.170, 10.120.100.17, 10.120.100.19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.170", "10.120.100.17", "10.120.100.19"]
    }
  }
}
resource "nsxt_policy_group" "whdpmigration01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whdpmigration01"
  description  = "role: CHG0147414, ip: [10.120.100.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.170"]
    }
  }
}
resource "nsxt_policy_group" "citrix_controllers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "citrix_controllers"
  description  = "role: CHG0147368, ip: [10.120.39.105, 10.120.39.106]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.105", "10.120.39.106"]
    }
  }
}
resource "nsxt_policy_group" "scc_non_whc_prod_vcentre" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_non_whc_prod_vcentre"
  description  = "role: CHG0147368, ip: [10.126.238.4]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.238.4"]
    }
  }
}
resource "nsxt_policy_group" "scc_non_whc_prod_vsphere_net" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_non_whc_prod_vsphere_net"
  description  = "role: CHG0147444, ip: [10.126.224.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.224.0/20"]
    }
  }
}
resource "nsxt_policy_group" "irepraptcp02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irepraptcp02"
  description  = "role: CHG0147444, ip: [10.156.4.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.4.10"]
    }
  }
}
resource "nsxt_policy_group" "aws_data_prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_data_prod"
  description  = "role: CHG0147548, ip: [100.76.16.0/23, 100.76.18.0/23, 100.76.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.16.0/23", "100.76.18.0/23", "100.76.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "mars_on_prem_app_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mars_on_prem_app_servers"
  description  = "role: CHG0147433, ip: [10.120.99.151, 10.120.99.152]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.151", "10.120.99.152"]
    }
  }
}
resource "nsxt_policy_group" "mars_rss_adapter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mars_rss_adapter"
  description  = "role: CHG0147433, ip: [10.181.5.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.5.167"]
    }
  }
}
resource "nsxt_policy_group" "mrg-fileshare" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mrg-fileshare"
  description  = "role: CHG0147919, ip: [10.40.60.7, 10.40.60.107]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.60.7", "10.40.60.107"]
    }
  }
}
resource "nsxt_policy_group" "ld6-fileshare" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6-fileshare"
  description  = "role: CHG0152337, ip: [10.19.2.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.27"]
    }
  }
}
resource "nsxt_policy_group" "gibux353-354-mgt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "gibux353-354-mgt"
  description  = "role: CHG0147891, ip: [10.180.139.143, 10.180.139.144]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.139.143", "10.180.139.144"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprnwb51" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprnwb51"
  description  = "role: CHG0147891, ip: [10.120.67.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.67.51"]
    }
  }
}
resource "nsxt_policy_group" "stjwn561" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "stjwn561"
  description  = "role: AWSMIG-253, ip: [10.120.104.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.14"]
    }
  }
}
resource "nsxt_policy_group" "featurespace_ui" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "featurespace_ui"
  description  = "role: CHG0148052, ip: [10.180.74.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.74.35"]
    }
  }
}
resource "nsxt_policy_group" "trs_mysql" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "trs_mysql"
  description  = "role: CHG0148257, ip: [10.120.146.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.20"]
    }
  }
}
resource "nsxt_policy_group" "prod_solarwinds" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "prod_solarwinds"
  description  = "role: CHG0148302, ip: [10.120.162.122, 10.120.163.123, 10.120.163.132, 10.120.163.142, 10.120.163.143]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.162.122", "10.120.163.123", "10.120.163.132", "10.120.163.142", "10.120.163.143"]
    }
  }
}
resource "nsxt_policy_group" "ireprnapsg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ireprnapsg01"
  description  = "role: CHG0148302, ip: [10.156.5.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.170"]
    }
  }
}
resource "nsxt_policy_group" "scc_jumpboxes" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_jumpboxes"
  description  = "role: CHG0148432, ip: [10.120.141.41, 10.120.141.42, 10.120.141.43, 10.120.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.41", "10.120.141.42", "10.120.141.43", "10.120.141.44"]
    }
  }
}
resource "nsxt_policy_group" "aws_whddos_oregon_f5s" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_whddos_oregon_f5s"
  description  = "role: CHG0148432, ip: [10.125.24.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.24.0/22"]
    }
  }
}
resource "nsxt_policy_group" "jde_meridian_svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "jde_meridian_svrs"
  description  = "role: CHG0148470, ip: [10.155.0.12, 10.155.0.24, 10.155.0.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.155.0.12", "10.155.0.24", "10.155.0.44"]
    }
  }
}
resource "nsxt_policy_group" "int-lb-backoffice" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "int-lb-backoffice"
  description  = "role: CHG0148498, ip: [10.180.74.54]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.74.54"]
    }
  }
}
resource "nsxt_policy_group" "gib-int-api-bonuswallet" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "gib-int-api-bonuswallet"
  description  = "role: CHG0148632, ip: [10.181.4.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.4.170"]
    }
  }
}
resource "nsxt_policy_group" "rundeck_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "rundeck_db"
  description  = "role: CHG0148398, ip: [10.120.163.235, 10.120.163.236]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.235", "10.120.163.236"]
    }
  }
}
resource "nsxt_policy_group" "cde_jumphosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "cde_jumphosts"
  description  = "role: CHG0148398, ip: [10.120.141.41, 10.120.141.42, 10.120.141.43, 10.120.141.44]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.41", "10.120.141.42", "10.120.141.43", "10.120.141.44"]
    }
  }
}
resource "nsxt_policy_group" "scc_tpam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_tpam"
  description  = "role: CHG0148704, ip: [10.120.136.66, 10.120.33.147]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.66", "10.120.33.147"]
    }
  }
}
resource "nsxt_policy_group" "sc1pisilon01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1pisilon01"
  description  = "role: CHG0148704, ip: [10.120.46.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.10"]
    }
  }
}
resource "nsxt_policy_group" "aws_whddos_ireland" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_whddos_ireland"
  description  = "role: CHG0148830, ip: [10.125.5.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.125.5.0/24"]
    }
  }
}
resource "nsxt_policy_group" "scc_uno_load_balancers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_uno_load_balancers"
  description  = "role: CHG0148856, ip: [10.120.74.11, 10.120.74.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.11", "10.120.74.12"]
    }
  }
}
resource "nsxt_policy_group" "whdppresent02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whdppresent02"
  description  = "role: CHG0148856, ip: [10.118.160.171]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.171"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprnwb040" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprnwb040"
  description  = "role: CHG0148876, ip: [10.120.67.120]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.67.120"]
    }
  }
}
resource "nsxt_policy_group" "prodjden" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "prodjden"
  description  = "role: CHG0148876, ip: [10.155.0.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.155.0.12"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprnft001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprnft001"
  description  = "role: CHG0122284, ip: [10.120.67.66]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.67.66"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprnap019" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprnap019"
  description  = "role: CHG0122284, ip: [10.120.99.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.99.34"]
    }
  }
}
resource "nsxt_policy_group" "grp_prod1_dev1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "grp_prod1_dev1"
  description  = "role: CHG0122284, ip: [10.155.0.18, 10.155.0.48]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.155.0.18", "10.155.0.48"]
    }
  }
}
resource "nsxt_policy_group" "ld6wnprndb001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wnprndb001"
  description  = "role: CHG0148614, ip: [10.118.160.161]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.161"]
    }
  }
}
resource "nsxt_policy_group" "whdp02tabular" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whdp02tabular"
  description  = "role: CHG0148971, ip: [10.118.160.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.174"]
    }
  }
}
resource "nsxt_policy_group" "uno_mds" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_mds"
  description  = "role: CHG0148975, ip: [10.118.160.174]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.174"]
    }
  }
}
resource "nsxt_policy_group" "uno_ssrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_ssrs"
  description  = "role: CHG0148976, ip: [10.118.160.169]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.169"]
    }
  }
}
resource "nsxt_policy_group" "nyx-spain" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "nyx-spain"
  description  = "role: CHG0148928, ip: [10.10.21.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.10.21.18"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpremg26" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpremg26"
  description  = "role: CHG0149147, ip: [10.120.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.110"]
    }
  }
}
resource "nsxt_policy_group" "aws-tss-vpc-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws-tss-vpc-prod"
  description  = "role: CHG0149147, ip: [100.79.16.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.16.0/20"]
    }
  }
}
resource "nsxt_policy_group" "aws-tss-vpc-dev" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws-tss-vpc-dev"
  description  = "role: CHG0149147, ip: [100.79.80.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.80.0/20"]
    }
  }
}
resource "nsxt_policy_group" "whdpservices01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whdpservices01"
  description  = "role: CHG0147981, ip: [10.120.100.84]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.84"]
    }
  }
}
resource "nsxt_policy_group" "ld6wnprndb005" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wnprndb005"
  description  = "role: CHG0147981, ip: [10.118.160.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.165"]
    }
  }
}
resource "nsxt_policy_group" "uno-remote-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno-remote-access"
  description  = "role: CHG0149220, ip: [10.120.100.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.28"]
    }
  }
}
resource "nsxt_policy_group" "uno-presentation-ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno-presentation-ld6"
  description  = "role: CHG0149220, ip: [10.118.148.51]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.148.51"]
    }
  }
}
resource "nsxt_policy_group" "uno-dmtfs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno-dmtfs"
  description  = "role: CHG0149220, ip: [10.120.100.241]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.241"]
    }
  }
}
resource "nsxt_policy_group" "ld6-ncde-stingray" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6-ncde-stingray"
  description  = "role: CHG0149220, ip: [10.118.148.11, 10.118.148.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.148.11", "10.118.148.12"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprncp001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprncp001"
  description  = "role: CHG0149277, ip: [10.120.66.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.66.112"]
    }
  }
}
resource "nsxt_policy_group" "prod1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "prod1"
  description  = "role: CHG0149277, ip: [10.155.0.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.155.0.18"]
    }
  }
}
resource "nsxt_policy_group" "int-pres-clp-sc1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "int-pres-clp-sc1"
  description  = "role: int-pres-clp.sc1.prod.williamhill.plc, ip: [10.121.4.150]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.4.150"]
    }
  }
}
resource "nsxt_policy_group" "sofia-commvault-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sofia-commvault-server"
  description  = "role: CHG0149455, ip: [10.53.96.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.96.36"]
    }
  }
}
resource "nsxt_policy_group" "ld6_lab_esxi_hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6_lab_esxi_hosts"
  description  = "role: CHG0149246, ip: [10.61.8.13, 10.61.8.14, 10.61.8.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.61.8.13", "10.61.8.14", "10.61.8.15"]
    }
  }
}
resource "nsxt_policy_group" "bonusadmin_mrgreen_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "bonusadmin_mrgreen_services"
  description  = "role: CHG0149626, ip: [10.10.11.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.10.11.45"]
    }
  }
}
resource "nsxt_policy_group" "ping_federate_aws_subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ping_federate_aws_subnets"
  description  = "role: CHG0149589 CHG0149826, ip: [100.106.128.0/20, 100.106.160.0/20, 100.106.192.0/20, 100.75.32.0/20, 100.75.64.0/20, 100.75.0.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.106.128.0/20", "100.106.160.0/20", "100.106.192.0/20", "100.75.32.0/20", "100.75.64.0/20", "100.75.0.0/20"]
    }
  }
}
resource "nsxt_policy_group" "ad_autopilot_poc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad_autopilot_poc"
  description  = "role: CHG0149589, ip: [10.120.33.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.240"]
    }
  }
}
resource "nsxt_policy_group" "campaignmanager_mrgreen_zone" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "campaignmanager_mrgreen_zone"
  description  = "role: CHG0149628, ip: [10.10.11.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.10.11.115"]
    }
  }
}
resource "nsxt_policy_group" "comm_vault_servers_ld6" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "comm_vault_servers_ld6"
  description  = "role: CHG0149801, ip: [10.112.46.30, 10.112.46.31, 10.112.46.32, 10.112.46.33, 10.112.46.34, 10.112.46.35, 10.112.46.36, 10.112.46.37, 10.112.46.38, 10.112.46.39]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.46.30", "10.112.46.31", "10.112.46.32", "10.112.46.33", "10.112.46.34", "10.112.46.35", "10.112.46.36", "10.112.46.37", "10.112.46.38", "10.112.46.39"]
    }
  }
}
resource "nsxt_policy_group" "comm_vault_servers_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "comm_vault_servers_scc"
  description  = "role: CHG0149801, ip: [10.120.46.30, 10.120.46.31, 10.120.46.32, 10.120.46.35, 10.120.46.36, 10.120.46.37, 10.120.46.38, 10.120.46.39, 10.120.47.11, 10.120.47.12, 10.120.47.13, 10.120.47.14, 10.120.47.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30", "10.120.46.31", "10.120.46.32", "10.120.46.35", "10.120.46.36", "10.120.46.37", "10.120.46.38", "10.120.46.39", "10.120.47.11", "10.120.47.12", "10.120.47.13", "10.120.47.14", "10.120.47.15"]
    }
  }
}
resource "nsxt_policy_group" "vsa_proxy_vmc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vsa_proxy_vmc"
  description  = "role: CHG0149801, ip: [10.156.5.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.133"]
    }
  }
}
resource "nsxt_policy_group" "esx_hosts_vmc_scc_non-whc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "esx_hosts_vmc_scc_non-whc"
  description  = "role: CHG0149801, ip: [10.126.226.0/24, 10.126.225.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.126.226.0/24", "10.126.225.0/24"]
    }
  }
}
resource "nsxt_policy_group" "sc1_cx_nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1_cx_nets"
  description  = "role: CHG0079131, ip: [10.121.0.0/18, 10.121.64.0/18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.121.0.0/18", "10.121.64.0/18"]
    }
  }
}
resource "nsxt_policy_group" "grp_commvault" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "grp_commvault"
  description  = "role: CHG0150040, ip: [10.120.46.30, 10.112.46.30, 10.53.98.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.30", "10.112.46.30", "10.53.98.37"]
    }
  }
}
resource "nsxt_policy_group" "mars-backofficeadmin-users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mars-backofficeadmin-users"
  description  = "role: RITM0148510, ip: [10.40.10.221, 10.40.10.155, 10.40.10.132]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.10.221", "10.40.10.155", "10.40.10.132"]
    }
  }
}
resource "nsxt_policy_group" "mars-backofficeadmin" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mars-backofficeadmin"
  description  = "role: RITM0148510, ip: [10.120.74.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.74.32"]
    }
  }
}
resource "nsxt_policy_group" "sc1-vcenter" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1-vcenter"
  description  = "role: CHG0150040, ip: [10.120.134.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.253"]
    }
  }
}
resource "nsxt_policy_group" "f5_big-iq_nonprod_caesars" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "f5_big-iq_nonprod_caesars"
  description  = "role: CHG0150343, ip: [100.98.52.234]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.98.52.234"]
    }
  }
}
resource "nsxt_policy_group" "vmc_preprod_and_dev_vropss_appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vmc_preprod_and_dev_vropss_appliances"
  description  = "role: CHG0150362, ip: [10.208.63.254, 10.195.10.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.208.63.254", "10.195.10.253"]
    }
  }
}
resource "nsxt_policy_group" "bulgaria_sec_isp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "bulgaria_sec_isp"
  description  = "role: CHG0125710, ip: [92.247.8.98]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["92.247.8.98"]
    }
  }
}
resource "nsxt_policy_group" "groupras-williamhill-plc-uk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "groupras-williamhill-plc-uk"
  description  = "role: CHG0125710, ip: [10.120.69.202]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.202"]
    }
  }
}
resource "nsxt_policy_group" "vmc_prod_vrops_appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vmc_prod_vrops_appliances"
  description  = "role: CHG0150584, ip: [10.156.1.16, 10.156.3.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.1.16", "10.156.3.140"]
    }
  }
}
resource "nsxt_policy_group" "bulgaria_lan" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "bulgaria_lan"
  description  = "role: CHG0125710, ip: [10.53.32.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.32.0/23"]
    }
  }
}
resource "nsxt_policy_group" "gib-int-api-bonuswallet-2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "gib-int-api-bonuswallet-2"
  description  = "role: CHG0148632, ip: [10.181.5.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.181.5.170"]
    }
  }
}
resource "nsxt_policy_group" "scc_accurate_citrix" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_accurate_citrix"
  description  = "role: CHG0150752, ip: [10.120.33.64/27, 10.120.40.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.64/27", "10.120.40.0/24"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprelic01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprelic01"
  description  = "role: CHG0150752, ip: [10.120.39.108]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.108"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprefs04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprefs04"
  description  = "role: CHG0150752, ip: [10.120.39.109]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.39.109"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprcmn001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprcmn001"
  description  = "role: CHG0150768, ip: [10.120.163.38]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.38"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprens01_bo_vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprens01_bo_vip"
  description  = "role: CHG0150911, ip: [10.120.69.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.207"]
    }
  }
}
resource "nsxt_policy_group" "trading_aws_subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "trading_aws_subnets"
  description  = "role: CHG0150798, ip: [100.72.128.0/20, 100.72.144.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.128.0/20", "100.72.144.0/20"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprens01_snip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprens01_snip"
  description  = "role: CHG0150911, ip: [10.120.69.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.200"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprewb10-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprewb10-new"
  description  = "role: CHG0151059, ip: [10.120.104.26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.26"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprgdb05-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprgdb05-new"
  description  = "role: CHG0151059, ip: [10.120.104.25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.25"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnpreap10-new" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnpreap10-new"
  description  = "role: CHG0151059, ip: [10.120.104.24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.24"]
    }
  }
}
resource "nsxt_policy_group" "brs_openbet_citrix" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brs_openbet_citrix"
  description  = "role: CHG0151059, ip: [10.210.39.142, 10.210.39.143, 10.210.39.148, 10.210.39.149, 10.210.39.150, 10.210.39.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.39.142", "10.210.39.143", "10.210.39.148", "10.210.39.149", "10.210.39.150", "10.210.39.151"]
    }
  }
}
resource "nsxt_policy_group" "aws_unity_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_unity_db"
  description  = "role: CHG0151090, ip: [100.77.96.0/20, 100.92.0.0/17, 100.93.0.0/17, 100.75.96.0/20, 100.92.128.0/17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.77.96.0/20", "100.92.0.0/17", "100.93.0.0/17", "100.75.96.0/20", "100.92.128.0/17"]
    }
  }
}
resource "nsxt_policy_group" "trs_users" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "trs_users"
  description  = "role: CHG0151198, ip: [10.1.13.0/24, 10.1.18.0/24, 10.1.30.0/24, 10.1.62.0/23, 10.1.66.0/23, 10.1.74.0/24, 10.1.112.0/23, 10.180.18.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.1.13.0/24", "10.1.18.0/24", "10.1.30.0/24", "10.1.62.0/23", "10.1.66.0/23", "10.1.74.0/24", "10.1.112.0/23", "10.180.18.0/23"]
    }
  }
}
resource "nsxt_policy_group" "aws_prod_ireland_vpc_trading" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_prod_ireland_vpc_trading"
  description  = "role: CHG0151337, ip: [100.72.128.0/19]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.128.0/19"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprrmimg01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprrmimg01"
  description  = "role: sc1wnprrmimg01, ip: [10.120.104.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.20"]
    }
  }
}
resource "nsxt_policy_group" "sc1wndremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wndremg002"
  description  = "role: sc1wndremg002, ip: [10.120.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.52"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnpredc17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnpredc17"
  description  = "role: sc1wnpredc17, ip: [10.120.69.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.214"]
    }
  }
}
resource "nsxt_policy_group" "brs_sc1_wnpremg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brs_sc1_wnpremg002"
  description  = "role: CHG0151491, ip: [10.210.194.52, 10.120.194.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.52", "10.120.194.52"]
    }
  }
}
resource "nsxt_policy_group" "ossec_splunk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ossec_splunk"
  description  = "role: ossec_splunk, ip: [10.120.163.99, 10.120.163.38, 10.120.163.95, 10.120.163.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.99", "10.120.163.38", "10.120.163.95", "10.120.163.96"]
    }
  }
}
resource "nsxt_policy_group" "rodc_subnets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "rodc_subnets"
  description  = "role: rodc_subnets, ip: [163.114.224.0/24, 163.114.225.0/24, 163.114.226.0/24, 163.114.227.0/24, 163.114.228.0/24, 163.114.229.0/24, 163.114.230.0/24, 163.114.231.0/24, 163.114.231.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["163.114.224.0/24", "163.114.225.0/24", "163.114.226.0/24", "163.114.227.0/24", "163.114.228.0/24", "163.114.229.0/24", "163.114.230.0/24", "163.114.231.0/24", "163.114.231.0/24"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnpredc15-17" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnpredc15-17"
  description  = "role: sc1wnpredc15-17, ip: [10.120.69.213, 10.120.69.214]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.213", "10.120.69.214"]
    }
  }
}
resource "nsxt_policy_group" "uno-present-readonly" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno-present-readonly"
  description  = "role: CHG0151587, ip: [10.118.144.32]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.144.32"]
    }
  }
}
resource "nsxt_policy_group" "emis-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "emis-servers"
  description  = "role: NETACCESS-375, ip: [10.120.146.154, 10.120.104.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.154", "10.120.104.8"]
    }
  }
}
resource "nsxt_policy_group" "msc-pure-storage" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "msc-pure-storage"
  description  = "role: CHG0151660, ip: [10.129.11.1, 10.129.11.2, 10.129.11.3, 10.129.11.4, 10.129.11.5, 10.129.11.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.129.11.1", "10.129.11.2", "10.129.11.3", "10.129.11.4", "10.129.11.5", "10.129.11.6"]
    }
  }
}
resource "nsxt_policy_group" "sc1-pure-storage" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1-pure-storage"
  description  = "role: CHG0151660, ip: [10.120.143.171, 10.120.143.172, 10.120.143.173, 10.120.143.181, 10.120.143.182, 10.120.143.183]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.143.171", "10.120.143.172", "10.120.143.173", "10.120.143.181", "10.120.143.182", "10.120.143.183"]
    }
  }
}
resource "nsxt_policy_group" "sc1-isilon-storage" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1-isilon-storage"
  description  = "role: CHG0151660, ip: [10.120.46.10, 10.120.46.11, 10.120.46.12, 10.120.46.13, 10.120.46.14, 10.120.46.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.10", "10.120.46.11", "10.120.46.12", "10.120.46.13", "10.120.46.14", "10.120.46.15"]
    }
  }
}
resource "nsxt_policy_group" "suricata-ids" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "suricata-ids"
  description  = "role: CHG0151854, ip: [10.120.104.27, 10.120.104.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.27", "10.120.104.28"]
    }
  }
}
resource "nsxt_policy_group" "ob_live_vpn" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ob_live_vpn"
  description  = "role: CHG0151859, ip: [10.194.20.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.194.20.0/24"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpremn81" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpremn81"
  description  = "role: CHG0151859, ip: [10.120.163.81]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.81"]
    }
  }
}
resource "nsxt_policy_group" "whus-vpn-subnet" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whus-vpn-subnet"
  description  = "role: CHG0151892, ip: [10.18.0.0/23, 10.58.20.0/24, 172.17.85.0/24, 172.17.3.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.18.0.0/23", "10.58.20.0/24", "172.17.85.0/24", "172.17.3.0/24"]
    }
  }
}
resource "nsxt_policy_group" "whlan-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whlan-prod"
  description  = "role: CHG0151892, ip: [10.120.69.201]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.201"]
    }
  }
}
resource "nsxt_policy_group" "unity-prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "unity-prod"
  description  = "role: CHG0151897, ip: [100.73.96.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.73.96.0/20"]
    }
  }
}
resource "nsxt_policy_group" "aws_central_ingress" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_central_ingress"
  description  = "role: CHG0151941, ip: [100.79.0.0/20, 100.78.32.0/20, 100.78.64.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.0.0/20", "100.78.32.0/20", "100.78.64.0/20"]
    }
  }
}
resource "nsxt_policy_group" "scc_splunk" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_splunk"
  description  = "role: CHG0151941, ip: [10.120.163.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.35"]
    }
  }
}
resource "nsxt_policy_group" "epos_datastore_user_access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "epos_datastore_user_access"
  description  = "role: RITM0156908, ip: [10.3.20.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.3.20.6"]
    }
  }
}
resource "nsxt_policy_group" "epos_datastore_server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "epos_datastore_server"
  description  = "role: RITM0156908, ip: [10.120.146.154]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.154"]
    }
  }
}
resource "nsxt_policy_group" "irewnprejamf01-02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnprejamf01-02"
  description  = "role: CHG0152079, ip: [10.120.69.228, 10.120.69.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.228", "10.120.69.229"]
    }
  }
}
resource "nsxt_policy_group" "ad_sccm_poc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad_sccm_poc"
  description  = "role: CHG0152108, ip: [10.120.33.245]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.245"]
    }
  }
}
resource "nsxt_policy_group" "ac_vpn_ranges" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ac_vpn_ranges"
  description  = "role: ac vpn ranges, ip: [192.168.48.0/20, 192.168.0.0/21, 192.168.12.0/22, 192.168.16.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.168.48.0/20", "192.168.0.0/21", "192.168.12.0/22", "192.168.16.0/22"]
    }
  }
}
resource "nsxt_policy_group" "service_now_grp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "service_now_grp"
  description  = "role: CHG0151491, ip: [199.91.137.0/24, 37.98.232.0/24, 148.139.3.0/24, 148.139.2.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["199.91.137.0/24", "37.98.232.0/24", "148.139.3.0/24", "148.139.2.0/24"]
    }
  }
}
resource "nsxt_policy_group" "crowd_platform_grp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "crowd_platform_grp"
  description  = "role: CHG0151491, ip: [3.9.50.26, 18.133.46.22, 54.220.110.201, 35.177.140.147, 18.133.96.184, 134.213.60.128, 52.49.230.246, 18.133.84.226]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["3.9.50.26", "18.133.46.22", "54.220.110.201", "35.177.140.147", "18.133.96.184", "134.213.60.128", "52.49.230.246", "18.133.84.226"]
    }
  }
}
resource "nsxt_policy_group" "wg-wrproxy-usa" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "wg-wrproxy-usa"
  description  = "role: CHG0151491, ip: [208.87.136.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["208.87.136.0/23"]
    }
  }
}
resource "nsxt_policy_group" "bomgar_hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "bomgar_hosts"
  description  = "role: CHG0152247 dynamic, ip: [10.210.141.42, 10.210.141.43, 10.120.141.42, 10.120.141.43, 10.180.141.42, 10.180.141.43, 10.112.15.42, 10.112.15.43]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.141.42", "10.210.141.43", "10.120.141.42", "10.120.141.43", "10.180.141.42", "10.180.141.43", "10.112.15.42", "10.112.15.43"]
    }
  }
}
resource "nsxt_policy_group" "sailpoint_test_vas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sailpoint_test_vas"
  description  = "role: NETAR-197, ip: [10.120.70.20, 10.118.208.110, 10.120.70.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.20", "10.118.208.110", "10.120.70.14"]
    }
  }
}
resource "nsxt_policy_group" "testad_iq" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "testad_iq"
  description  = "role: NETAR-197, ip: [10.120.33.247]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.247"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprnmg020" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprnmg020"
  description  = "role: NETAR-200, ip: [10.120.100.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.100.28"]
    }
  }
}
resource "nsxt_policy_group" "tableau_mrgreen_zone" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "tableau_mrgreen_zone"
  description  = "role: NETAR-260, ip: [10.20.30.27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.20.30.27"]
    }
  }
}
resource "nsxt_policy_group" "aws_sports_whapi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_sports_whapi"
  description  = "role: NETAR-352, ip: [100.73.112.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.73.112.0/22"]
    }
  }
}
resource "nsxt_policy_group" "uno_readonly_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "uno_readonly_db"
  description  = "role: NETAR-403, ip: [10.118.160.166, 10.118.160.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.166", "10.118.160.162"]
    }
  }
}
resource "nsxt_policy_group" "int-lb-oxi-proxy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "int-lb-oxi-proxy"
  description  = "role: NETAR-466, ip: [10.180.74.140]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.74.140"]
    }
  }
}
resource "nsxt_policy_group" "sc1_cde_linux_jump" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1_cde_linux_jump"
  description  = "role: NETAR-270, ip: [10.120.141.13, 10.120.141.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.141.13", "10.120.141.14"]
    }
  }
}
resource "nsxt_policy_group" "evoke_report_services" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "evoke_report_services"
  description  = "role: NETAR-579, ip: [10.40.220.18, 10.1.92.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.220.18", "10.1.92.11"]
    }
  }
}
resource "nsxt_policy_group" "trading_reports_server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "trading_reports_server"
  description  = "role: NETAR-670, ip: [10.120.101.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.101.10"]
    }
  }
}
resource "nsxt_policy_group" "dfs_root_namespace_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "dfs_root_namespace_servers"
  description  = "role: NETAR-797, ip: [10.120.194.48, 10.120.194.49]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.48", "10.120.194.49"]
    }
  }
}
resource "nsxt_policy_group" "malta-sliema-dc-access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "malta-sliema-dc-access"
  description  = "role: NETAR-797, ip: [10.40.110.9, 10.40.110.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.110.9", "10.40.110.10"]
    }
  }
}
resource "nsxt_policy_group" "ld6-scc-dcs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6-scc-dcs"
  description  = "role: NETAR-797, ip: [10.120.76.12, 10.118.208.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.76.12", "10.118.208.68"]
    }
  }
}
resource "nsxt_policy_group" "gibwnprefs01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "gibwnprefs01"
  description  = "role: NETAR-1052, ip: [10.180.194.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.194.20"]
    }
  }
}
resource "nsxt_policy_group" "aws_central_prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_central_prod"
  description  = "role: NETAR-1082, ip: [100.76.144.0/23, 100.76.146.0/23, 100.76.148.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.144.0/23", "100.76.146.0/23", "100.76.148.0/23"]
    }
  }
}
resource "nsxt_policy_group" "aspect_stunnel" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aspect_stunnel"
  description  = "role: NETAR-1082, ip: [10.120.65.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.134"]
    }
  }
}
resource "nsxt_policy_group" "sc1_darktrace" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1_darktrace"
  description  = "role: NETAR-1203, ip: [10.120.163.156]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.156"]
    }
  }
}
resource "nsxt_policy_group" "aws_darktrace_master" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_darktrace_master"
  description  = "role: NETAR-1203, ip: [52.52.139.68]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["52.52.139.68"]
    }
  }
}
resource "nsxt_policy_group" "direct_access_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "direct_access_servers"
  description  = "role: NETAR-1211, ip: [10.120.76.13, 10.120.76.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.76.13", "10.120.76.14"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprsap02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprsap02"
  description  = "role: NETAR-1344, ip: [10.120.65.101]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.101"]
    }
  }
}
resource "nsxt_policy_group" "sap_datacenter_dr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sap_datacenter_dr"
  description  = "role: NETAR-1344, ip: [34.91.42.149, 34.90.197.160]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["34.91.42.149", "34.90.197.160"]
    }
  }
}
resource "nsxt_policy_group" "sap_datacenter_pri" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sap_datacenter_pri"
  description  = "role: NETAR-1344, ip: [34.107.112.35, 34.89.141.13, 34.89.143.40]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["34.107.112.35", "34.89.141.13", "34.89.143.40"]
    }
  }
}
resource "nsxt_policy_group" "sap_datacenter_frankfurt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sap_datacenter_frankfurt"
  description  = "role: NETAR-1369, ip: [35.246.224.53, 34.107.88.2]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["35.246.224.53", "34.107.88.2"]
    }
  }
}
resource "nsxt_policy_group" "manila-isp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "manila-isp"
  description  = "role: NETAR-1847, ip: [115.84.238.240/29, 116.50.151.24/29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["115.84.238.240/29", "116.50.151.24/29"]
    }
  }
}
resource "nsxt_policy_group" "hatwnprecp001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "hatwnprecp001"
  description  = "role: NETAR-2035, ip: [10.135.10.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.135.10.11"]
    }
  }
}
resource "nsxt_policy_group" "cdgwnprecp001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "cdgwnprecp001"
  description  = "role: NETAR-2972, ip: [10.135.12.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.135.12.10"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprwsus01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprwsus01"
  description  = "role: NETAR-2035, ip: [10.120.163.114]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.114"]
    }
  }
}
resource "nsxt_policy_group" "scc_smtp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_smtp"
  description  = "role: NETAR-2035, ip: [10.120.33.164, 10.120.33.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.164", "10.120.33.165"]
    }
  }
}
resource "nsxt_policy_group" "sofia_fileserver" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sofia_fileserver"
  description  = "role: NETAR-2150, ip: [10.53.98.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.15"]
    }
  }
}
resource "nsxt_policy_group" "mrg_featurespace" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mrg_featurespace"
  description  = "role: NETAR-2216, ip: [10.10.60.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.10.60.11"]
    }
  }
}
resource "nsxt_policy_group" "scc_ilo_network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_ilo_network"
  description  = "role: NETAR-2231, ip: [10.120.130.0/24, 10.120.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.130.0/24", "10.120.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "gib_ilo_network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "gib_ilo_network"
  description  = "role: NETAR-2231, ip: [10.180.130.0/24, 10.180.80.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.180.130.0/24", "10.180.80.0/24"]
    }
  }
}
resource "nsxt_policy_group" "sailpoint_vas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sailpoint_vas"
  description  = "role: NETAR-197, ip: [10.118.208.100, 10.118.208.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.208.100", "10.118.208.110"]
    }
  }
}
resource "nsxt_policy_group" "irewnpreftp01-ftp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnpreftp01-ftp"
  description  = "role: NETAR-197, ip: [10.120.69.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.230"]
    }
  }
}
resource "nsxt_policy_group" "dc_888_ips" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "dc_888_ips"
  description  = "role: NETAR-2260, ip: [192.118.64.27, 192.118.64.28, 192.118.64.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.118.64.27", "192.118.64.28", "192.118.64.29"]
    }
  }
}
resource "nsxt_policy_group" "irewnpreftp01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnpreftp01"
  description  = "role: NETAR-2260, ip: [10.120.69.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.230"]
    }
  }
}
resource "nsxt_policy_group" "sailpoint_iq_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sailpoint_iq_servers"
  description  = "role: NETAR-2260, ip: [10.120.70.16, 10.120.70.22, 10.118.208.102, 10.118.208.112]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.16", "10.120.70.22", "10.118.208.102", "10.118.208.112"]
    }
  }
}
resource "nsxt_policy_group" "ireuxppbkvsa01-02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ireuxppbkvsa01-02"
  description  = "role: NETAR-2331, ip: [10.156.5.35, 10.156.5.36]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.156.5.35", "10.156.5.36"]
    }
  }
}
resource "nsxt_policy_group" "brswntstdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brswntstdb01"
  description  = "role: NETAR-2319, ip: [10.210.146.207]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.146.207"]
    }
  }
}
resource "nsxt_policy_group" "oneview_appliances" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "oneview_appliances"
  description  = "role: NETAR-2487, ip: [10.112.11.254, 10.120.163.110, 10.180.163.110, 10.210.163.110]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.11.254", "10.120.163.110", "10.180.163.110", "10.210.163.110"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpremg27" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpremg27"
  description  = "role: NETAR-2487, ip: [10.120.163.115]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.115"]
    }
  }
}
resource "nsxt_policy_group" "sailpoint_ssh_tunnel_ips" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sailpoint_ssh_tunnel_ips"
  description  = "role: NETAR-2571, ip: [52.206.133.183, 52.206.132.240, 52.206.130.59, 35.157.132.22, 35.157.185.79, 35.157.251.228, 18.130.210.174, 18.130.148.201, 35.178.220.78, 52.65.42.92, 13.55.78.212, 3.24.127.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["52.206.133.183", "52.206.132.240", "52.206.130.59", "35.157.132.22", "35.157.185.79", "35.157.251.228", "18.130.210.174", "18.130.148.201", "35.178.220.78", "52.65.42.92", "13.55.78.212", "3.24.127.50"]
    }
  }
}
resource "nsxt_policy_group" "cde_monitoring_nets" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "cde_monitoring_nets"
  description  = "role: NETAR-2692, ip: [10.120.163.0/24, 10.180.163.0/24, 10.210.163.0/24, 10.112.13.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.0/24", "10.180.163.0/24", "10.210.163.0/24", "10.112.13.0/24"]
    }
  }
}
resource "nsxt_policy_group" "brsapprcmg002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brsapprcmg002"
  description  = "role: NETAR-2494, ip: [10.210.163.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13"]
    }
  }
}
resource "nsxt_policy_group" "retail_dev_vmc_workstation" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "retail_dev_vmc_workstation"
  description  = "role: NETAR-2723, ip: [10.233.11.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.233.11.50"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprnap002" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprnap002"
  description  = "role: NETAR-2723, ip: [10.120.153.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.153.10"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprefs03" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprefs03"
  description  = "role: NETAR-2734, ip: [10.120.192.162]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.162"]
    }
  }
}
resource "nsxt_policy_group" "sc1prapli01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1prapli01"
  description  = "role: NETAR-2697, ip: [10.120.134.246]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.246"]
    }
  }
}
resource "nsxt_policy_group" "slmprmrgov01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "slmprmrgov01"
  description  = "role: NETAR-2691, ip: [10.40.60.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.60.60"]
    }
  }
}
resource "nsxt_policy_group" "brsuxpremn004" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brsuxpremn004"
  description  = "role: NETAR-2860, ip: [10.210.163.73]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.73"]
    }
  }
}
resource "nsxt_policy_group" "parkviewscc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "parkviewscc"
  description  = "role: NETAR-3024, ip: [10.120.163.112, 10.120.163.113]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.112", "10.120.163.113"]
    }
  }
}
resource "nsxt_policy_group" "parkviewext" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "parkviewext"
  description  = "role: NETAR-3024, ip: [52.167.178.64, 52.167.178.66, 52.167.178.67, 52.167.178.68, 52.184.234.3, 52.184.234.4, 52.184.234.5, 207.54.131.225, 207.54.131.226, 207.54.131.228, 207.54.131.229]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["52.167.178.64", "52.167.178.66", "52.167.178.67", "52.167.178.68", "52.184.234.3", "52.184.234.4", "52.184.234.5", "207.54.131.225", "207.54.131.226", "207.54.131.228", "207.54.131.229"]
    }
  }
}
resource "nsxt_policy_group" "duuf-ntsadmin-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "duuf-ntsadmin-vip"
  description  = "role: NETAR-3001, ip: [10.213.2.18]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.213.2.18"]
    }
  }
}
resource "nsxt_policy_group" "duuc-qmanager-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "duuc-qmanager-vip"
  description  = "role: NETAR-3001, ip: [10.213.2.35]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.213.2.35"]
    }
  }
}
resource "nsxt_policy_group" "duuc-passivests-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "duuc-passivests-vip"
  description  = "role: NETAR-3001, ip: [10.213.2.52]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.213.2.52"]
    }
  }
}
resource "nsxt_policy_group" "duuc-customeradmin-vip" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "duuc-customeradmin-vip"
  description  = "role: NETAR-3001, ip: [10.213.2.41]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.213.2.41"]
    }
  }
}
resource "nsxt_policy_group" "irewnprnrbt024" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnprnrbt024"
  description  = "role: NETAR-3001, ip: [10.120.71.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.71.34"]
    }
  }
}
resource "nsxt_policy_group" "networks_888" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "networks_888"
  description  = "role: NETAR-3137, ip: [10.20.0.0/16, 10.105.0.0/16, 10.50.20.0/22, 10.50.24.0/22, 10.231.0.0/20, 10.213.0.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.20.0.0/16", "10.105.0.0/16", "10.50.20.0/22", "10.50.24.0/22", "10.231.0.0/20", "10.213.0.0/20"]
    }
  }
}
resource "nsxt_policy_group" "ad-servers-888" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ad-servers-888"
  description  = "role: NETAR-3137, ip: [10.154.124.13, 10.154.24.13, 10.105.5.100, 10.105.5.101, 10.215.15.21, 10.215.15.22, 172.16.129.23, 172.16.129.24, 10.50.25.100, 10.50.25.101, 10.20.5.106, 10.20.5.12, 10.20.5.21, 10.20.5.20, 10.20.5.11, 10.17.38.11, 10.17.38.12, 10.19.4.21, 10.19.4.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.154.124.13", "10.154.24.13", "10.105.5.100", "10.105.5.101", "10.215.15.21", "10.215.15.22", "172.16.129.23", "172.16.129.24", "10.50.25.100", "10.50.25.101", "10.20.5.106", "10.20.5.12", "10.20.5.21", "10.20.5.20", "10.20.5.11", "10.17.38.11", "10.17.38.12", "10.19.4.21", "10.19.4.22"]
    }
  }
}
resource "nsxt_policy_group" "ld6_fileservers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6_fileservers"
  description  = "role: NETAR-3402, ip: [10.19.2.28, 10.19.2.29]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.28", "10.19.2.29"]
    }
  }
}
resource "nsxt_policy_group" "brswndredb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brswndredb04"
  description  = "role: NETAR-3366, ip: [10.210.65.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.65.69"]
    }
  }
}
resource "nsxt_policy_group" "irewnpredb04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnpredb04"
  description  = "role: NETAR-3366, ip: [10.120.65.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.65.69"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprgdb13-14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprgdb13-14"
  description  = "role: NETAR-3469, ip: [10.120.146.116, 10.120.146.115, 10.120.99.115, 10.120.99.116]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.116", "10.120.146.115", "10.120.99.115", "10.120.99.116"]
    }
  }
}
resource "nsxt_policy_group" "brs-tna-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brs-tna-servers"
  description  = "role: NETAR-3469, ip: [10.210.146.207, 10.210.146.206]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.146.207", "10.210.146.206"]
    }
  }
}
resource "nsxt_policy_group" "aws_webproxy" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_webproxy"
  description  = "role: NETAR-3398, ip: [100.72.16.0/20, 100.72.48.0/20, 100.72.80.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.16.0/20", "100.72.48.0/20", "100.72.80.0/20"]
    }
  }
}
resource "nsxt_policy_group" "citrix_corp_tech" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "citrix_corp_tech"
  description  = "role: NETAR-3525, ip: [10.120.69.208]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.208"]
    }
  }
}
resource "nsxt_policy_group" "solarwinds_pollers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "solarwinds_pollers"
  description  = "role: NETAR-3607, ip: [10.120.138.195, 10.120.138.196, 10.120.138.197, 10.120.138.198]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.138.195", "10.120.138.196", "10.120.138.197", "10.120.138.198"]
    }
  }
}
resource "nsxt_policy_group" "solarwinds_dsts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "solarwinds_dsts"
  description  = "role: NETAR-3607, ip: [10.0.0.0/8, 192.168.9.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8", "192.168.9.0/24"]
    }
  }
}
resource "nsxt_policy_group" "solarwinds_primary_poller" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "solarwinds_primary_poller"
  description  = "role: NETAR-3607, ip: [10.120.138.195]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.138.195"]
    }
  }
}
resource "nsxt_policy_group" "solarwinds_webserver" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "solarwinds_webserver"
  description  = "role: NETAR-3607, ip: [10.120.138.199]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.138.199"]
    }
  }
}
resource "nsxt_policy_group" "ld6_powerbi" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6_powerbi"
  description  = "role: NETAR-3725, ip: [10.118.214.33, 10.118.214.34]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.214.33", "10.118.214.34"]
    }
  }
}
resource "nsxt_policy_group" "solarwinds_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "solarwinds_db"
  description  = "role: NETAR-3739, ip: [10.120.138.190]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.138.190"]
    }
  }
}
resource "nsxt_policy_group" "manila_esxi_hosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "manila_esxi_hosts"
  description  = "role: NETAR-3806, ip: [10.123.198.0/24, 10.123.125.0/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.198.0/24", "10.123.125.0/25"]
    }
  }
}
resource "nsxt_policy_group" "mnlprapvr01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mnlprapvr01"
  description  = "role: NETAR-3806, ip: [10.123.125.60]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.125.60"]
    }
  }
}
resource "nsxt_policy_group" "vsan_witness" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "vsan_witness"
  description  = "role: NETAR-3806, ip: [10.120.134.241, 10.120.134.238, 10.120.134.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.134.241", "10.120.134.238", "10.120.134.253"]
    }
  }
}
resource "nsxt_policy_group" "manila_esxi_host" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "manila_esxi_host"
  description  = "role: NETAR-3806, ip: [10.123.210.128/25]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.123.210.128/25"]
    }
  }
}
resource "nsxt_policy_group" "scc_120" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_120"
  description  = "role: NETAR-3782, ip: [10.120.0.0/16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.0.0/16"]
    }
  }
}
resource "nsxt_policy_group" "net_10_0_0_0s8" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "net_10_0_0_0s8"
  description  = "role: NETAR-3885, ip: [10.0.0.0/8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.0.0.0/8"]
    }
  }
}
resource "nsxt_policy_group" "splunk_aws" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "splunk_aws"
  description  = "role: NETAR-3885, ip: [100.72.96.0/20, 100.74.48.0/20, 100.76.0.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.96.0/20", "100.74.48.0/20", "100.76.0.0/20"]
    }
  }
}
resource "nsxt_policy_group" "mi_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "mi_db"
  description  = "role: NETAR-3969, ip: [10.120.104.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.16"]
    }
  }
}
resource "nsxt_policy_group" "testad" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "testad"
  description  = "role: NETAR-3952, ip: [10.120.33.192/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.192/26"]
    }
  }
}
resource "nsxt_policy_group" "ld6wnprwsus02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wnprwsus02"
  description  = "role: NETAR-7245, ip: [10.19.2.45]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.45"]
    }
  }
}
resource "nsxt_policy_group" "sc1jump1" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1jump1"
  description  = "role: NETAR-3952, ip: [10.120.151.59]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.59"]
    }
  }
}
resource "nsxt_policy_group" "wh-data-duo-prod-sql2019-ec2" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "wh-data-duo-prod-sql2019-ec2"
  description  = "role: NETAR-3922, ip: [100.76.19.254]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.19.254"]
    }
  }
}
resource "nsxt_policy_group" "aws_centralised_sftp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws_centralised_sftp"
  description  = "role: NETAR-4187, ip: [100.79.16.0/20, 100.79.48.0/20, 100.79.80.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.79.16.0/20", "100.79.48.0/20", "100.79.80.0/20"]
    }
  }
}
resource "nsxt_policy_group" "ro_vpn_888" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ro_vpn_888"
  description  = "role: NETAR-888, ip: [10.105.220.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.105.220.0/22"]
    }
  }
}
resource "nsxt_policy_group" "ciprian_graure_888" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ciprian_graure_888"
  description  = "role: NETAR-888, ip: [10.105.14.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.105.14.11"]
    }
  }
}
resource "nsxt_policy_group" "pte_db_tier" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "pte_db_tier"
  description  = "role: NETAR-4497, ip: [10.114.98.0]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.114.98.0"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpremg30" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpremg30"
  description  = "role: NETAR-4497, ip: [10.120.136.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.136.30"]
    }
  }
}
resource "nsxt_policy_group" "ncde_jumphosts" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ncde_jumphosts"
  description  = "role: NETAR-69, ip: [10.120.151.13, 10.120.151.14]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.151.13", "10.120.151.14"]
    }
  }
}
resource "nsxt_policy_group" "nessus_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "nessus_servers"
  description  = "role: NETAR-4737, ip: [172.17.200.28, 10.180.142.230, 10.1.43.55, 10.10.220.55]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["172.17.200.28", "10.180.142.230", "10.1.43.55", "10.10.220.55"]
    }
  }
}
resource "nsxt_policy_group" "ld6wnprecp001" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wnprecp001"
  description  = "role: NETAR-4794, ip: [10.19.2.26, 10.19.2.30]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.26", "10.19.2.30"]
    }
  }
}
resource "nsxt_policy_group" "splunk_aws_prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "splunk_aws_prod"
  description  = "role: NETAR-4814, ip: [100.72.96.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.96.0/20"]
    }
  }
}
resource "nsxt_policy_group" "ld6wnpredb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wnpredb02"
  description  = "role: NETAR-5144, ip: [10.118.214.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.214.62"]
    }
  }
}
resource "nsxt_policy_group" "sofwnprefs02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sofwnprefs02"
  description  = "role: NETAR-5282, ip: [10.53.98.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.53.98.22"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprein14" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprein14"
  description  = "role: NETAR-5282, ip: [10.120.145.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.37"]
    }
  }
}
resource "nsxt_policy_group" "wh_iam" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "wh_iam"
  description  = "role: NETAR-5227, ip: [10.120.194.22, 10.120.194.23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.22", "10.120.194.23"]
    }
  }
}
resource "nsxt_policy_group" "ld6wndvdb02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wndvdb02"
  description  = "role: NETAR-5310, ip: [10.118.214.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.214.50"]
    }
  }
}
resource "nsxt_policy_group" "ro_build_network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ro_build_network"
  description  = "role: NETAR-5246, ip: [10.105.135.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.105.135.0/24"]
    }
  }
}
resource "nsxt_policy_group" "iam-prod-preprod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "iam-prod-preprod"
  description  = "role: NETAR-5341, ip: [10.120.70.16, 10.120.70.22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.16", "10.120.70.22"]
    }
  }
}
resource "nsxt_policy_group" "cluster-vas" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "cluster-vas"
  description  = "role: NETAR-5341, ip: [10.120.70.14, 10.120.70.20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.14", "10.120.70.20"]
    }
  }
}
resource "nsxt_policy_group" "sailpoint-sftp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sailpoint-sftp"
  description  = "role: NETAR-5341, ip: [10.120.145.37]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.145.37"]
    }
  }
}
resource "nsxt_policy_group" "iam-new-jump-server" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "iam-new-jump-server"
  description  = "role: NETAR-5341, ip: [10.19.2.96]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.96"]
    }
  }
}
resource "nsxt_policy_group" "cms_spectate" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "cms_spectate"
  description  = "role: NETAR-5532, ip: [54.76.76.29, 54.54.76.29, 54.154.80.106, 54.73.60.230]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["54.76.76.29", "54.54.76.29", "54.154.80.106", "54.73.60.230"]
    }
  }
}
resource "nsxt_policy_group" "hpe_synergy_oneview" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "hpe_synergy_oneview"
  description  = "role: NETAR-5643, ip: [10.210.130.70]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.130.70"]
    }
  }
}
resource "nsxt_policy_group" "sftp_sc1uxprnap70" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sftp_sc1uxprnap70"
  description  = "role: NETAR-5643, ip: [10.120.146.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.135"]
    }
  }
}
resource "nsxt_policy_group" "scc_netscalers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_netscalers"
  description  = "role: NETAR-5751, ip: [10.120.69.198, 10.120.69.199, 10.120.69.200]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.69.198", "10.120.69.199", "10.120.69.200"]
    }
  }
}
resource "nsxt_policy_group" "jamf_cloud" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "jamf_cloud"
  description  = "role: NETAR-5822, ip: [3.8.240.231, 35.176.203.6, 13.41.154.59, 3.11.42.21, 18.135.155.218, 18.168.143.142, 18.135.241.236, 18.168.141.199, 3.11.44.253, 3.10.137.75, 3.9.2.225, 3.11.115.18, 35.178.147.36, 18.134.197.23, 35.176.159.21, 18.132.124.105, 13.40.247.171, 52.49.168.205, 3.8.240.231, 35.176.203.6]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["3.8.240.231", "35.176.203.6", "13.41.154.59", "3.11.42.21", "18.135.155.218", "18.168.143.142", "18.135.241.236", "18.168.141.199", "3.11.44.253", "3.10.137.75", "3.9.2.225", "3.11.115.18", "35.178.147.36", "18.134.197.23", "35.176.159.21", "18.132.124.105", "13.40.247.171", "52.49.168.205", "3.8.240.231", "35.176.203.6"]
    }
  }
}
resource "nsxt_policy_group" "grp-net-kafka-racebook-addrs-dest" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "grp-net-kafka-racebook-addrs-dest"
  description  = "role: NETAR-5796, ip: [3.106.33.249, 3.106.155.65]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["3.106.33.249", "3.106.155.65"]
    }
  }
}
resource "nsxt_policy_group" "grp-net-kafka-racebook-addrs-src" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "grp-net-kafka-racebook-addrs-src"
  description  = "role: NETAR-5796, ip: [10.120.101.11, 10.120.101.12]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.101.11", "10.120.101.12"]
    }
  }
}
resource "nsxt_policy_group" "corp-engineering-servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "corp-engineering-servers"
  description  = "role: NETAR-6045, ip: [10.120.194.128/27, 10.120.104.0/27]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.128/27", "10.120.104.0/27"]
    }
  }
}
resource "nsxt_policy_group" "grp-net-crucial_comp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "grp-net-crucial_comp"
  description  = "role: NETAR-6032, ip: [100.76.179.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.179.0/24"]
    }
  }
}
resource "nsxt_policy_group" "semperis-dsp-mgmt-svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "semperis-dsp-mgmt-svr"
  description  = "role: NETAR-6071, ip: [10.120.194.134]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.134"]
    }
  }
}
resource "nsxt_policy_group" "semperis-adfr-svr" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "semperis-adfr-svr"
  description  = "role: NETAR-6071, ip: [10.120.194.135]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.135"]
    }
  }
}
resource "nsxt_policy_group" "non-vmc-ad-dsp-agents" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "non-vmc-ad-dsp-agents"
  description  = "role: NETAR-6071, ip: [10.210.194.11, 10.19.2.21]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.11", "10.19.2.21"]
    }
  }
}
resource "nsxt_policy_group" "all-non-vmc-ad-with-semperis" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "all-non-vmc-ad-with-semperis"
  description  = "role: NETAR-6071, ip: [10.19.2.21, 10.19.2.22, 10.55.9.11, 10.55.9.12, 10.40.110.9, 10.40.110.10, 10.123.197.11, 10.123.197.16, 10.210.194.12, 10.210.194.13, 10.180.194.12, 10.180.194.13, 100.72.225.135, 100.72.225.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.21", "10.19.2.22", "10.55.9.11", "10.55.9.12", "10.40.110.9", "10.40.110.10", "10.123.197.11", "10.123.197.16", "10.210.194.12", "10.210.194.13", "10.180.194.12", "10.180.194.13", "100.72.225.135", "100.72.225.167"]
    }
  }
}
resource "nsxt_policy_group" "non-vmc-pki-svrs" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "non-vmc-pki-svrs"
  description  = "role: NETAR-6071, ip: [10.210.194.31]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.194.31"]
    }
  }
}
resource "nsxt_policy_group" "aws-ad-adfr-agents" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws-ad-adfr-agents"
  description  = "role: NETAR-6071, ip: [100.72.225.135, 100.72.225.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.135", "100.72.225.167"]
    }
  }
}
resource "nsxt_policy_group" "semperis_dsp_db" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "semperis_dsp_db"
  description  = "role: NETAR-6071, ip: [10.120.194.133]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.194.133"]
    }
  }
}
resource "nsxt_policy_group" "_10_120_194_128s27_access" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "_10_120_194_128s27_access"
  description  = "role: NETAR-6041, ip: [10.210.163.13, 10.19.2.22, 10.55.9.11, 10.55.9.12, 10.19.2.21, 10.40.110.9, 10.40.110.10, 10.123.197.16, 10.210.194.13, 10.120.69.213, 10.120.194.13, 10.120.194.15, 10.120.194.18, 10.180.194.13, 10.123.197.11, 10.120.194.14, 10.120.69.214, 10.180.194.12, 10.210.194.12, 100.72.225.167, 100.72.225.135, 100.72.225.199, 100.72.225.136, 10.120.194.11, 10.120.194.12, 10.210.194.11]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.210.163.13", "10.19.2.22", "10.55.9.11", "10.55.9.12", "10.19.2.21", "10.40.110.9", "10.40.110.10", "10.123.197.16", "10.210.194.13", "10.120.69.213", "10.120.194.13", "10.120.194.15", "10.120.194.18", "10.180.194.13", "10.123.197.11", "10.120.194.14", "10.120.69.214", "10.180.194.12", "10.210.194.12", "100.72.225.167", "100.72.225.135", "100.72.225.199", "100.72.225.136", "10.120.194.11", "10.120.194.12", "10.210.194.11"]
    }
  }
}
resource "nsxt_policy_group" "sailpoint_888" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sailpoint_888"
  description  = "role: NETAR-6147, ip: [10.120.70.15]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.70.15"]
    }
  }
}
resource "nsxt_policy_group" "sailpoint_iq_888" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sailpoint_iq_888"
  description  = "role: NETAR-6147, ip: [10.20.5.194, 10.105.5.194]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.20.5.194", "10.105.5.194"]
    }
  }
}
resource "nsxt_policy_group" "irewnpreadfr02" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "irewnpreadfr02"
  description  = "role: NETAR-6147, ip: [100.72.225.139]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.72.225.139"]
    }
  }
}
resource "nsxt_policy_group" "dublin_published_apps" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "dublin_published_apps"
  description  = "role: ITSD-33471, ip: [10.217.4.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.217.4.0/22"]
    }
  }
}
resource "nsxt_policy_group" "fortisoar" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "fortisoar"
  description  = "role: ITSD-33471, ip: [10.120.163.28]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.28"]
    }
  }
}
resource "nsxt_policy_group" "_888_vpns" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "_888_vpns"
  description  = "role: ITSD-34565, ip: [10.105.220.0/22, 10.20.220.0/22]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.105.220.0/22", "10.20.220.0/22"]
    }
  }
}
resource "nsxt_policy_group" "sc1bigiq01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1bigiq01"
  description  = "role: ITSD-34565, ip: [10.120.140.13]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.140.13"]
    }
  }
}
resource "nsxt_policy_group" "_888_infosec" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "_888_infosec"
  description  = "role: ITSD-34565, ip: [10.20.168.64]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.20.168.64"]
    }
  }
}
resource "nsxt_policy_group" "brswn562" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brswn562"
  description  = "role: NETAR-6268, ip: [10.201.9.62]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.9.62"]
    }
  }
}
resource "nsxt_policy_group" "scc_citrix_ob" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "scc_citrix_ob"
  description  = "role: NETAR-6279, ip: [10.120.33.81, 10.120.33.82, 10.120.33.83, 10.120.33.84, 10.120.33.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.81", "10.120.33.82", "10.120.33.83", "10.120.33.84", "10.120.33.85"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprefs08" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprefs08"
  description  = "role: NETAR-6279, ip: [10.120.192.165]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.165"]
    }
  }
}
resource "nsxt_policy_group" "datamgmt_aws_non_prod" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "datamgmt_aws_non_prod"
  description  = "role: NETAR-6498, ip: [100.76.48.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.48.0/20"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxprrdb05" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxprrdb05"
  description  = "role: NETAR-6518, ip: [10.120.146.16]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.146.16"]
    }
  }
}
resource "nsxt_policy_group" "ma3uxprdb01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ma3uxprdb01"
  description  = "role: NETAR-6518, ip: [10.120.177.69]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.177.69"]
    }
  }
}
resource "nsxt_policy_group" "ma3le1cmp" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ma3le1cmp"
  description  = "role: NETAR-6634, ip: [10.120.125.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.125.10"]
    }
  }
}
resource "nsxt_policy_group" "rundeck-login" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "rundeck-login"
  description  = "role: ITSD-49490, ip: [10.120.163.238]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.238"]
    }
  }
}
resource "nsxt_policy_group" "infoblox-login" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "infoblox-login"
  description  = "role: ITSD-49489, ip: [10.120.193.240]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.193.240"]
    }
  }
}
resource "nsxt_policy_group" "gib-888" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "gib-888"
  description  = "role: ITSD-49489, ip: [10.50.20.0/23]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.50.20.0/23"]
    }
  }
}
resource "nsxt_policy_group" "evoke-test-ad" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "evoke-test-ad"
  description  = "role: NETAR-6685, ip: [10.114.68.4, 10.114.68.5]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.114.68.4", "10.114.68.5"]
    }
  }
}
resource "nsxt_policy_group" "wh-test-ad" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "wh-test-ad"
  description  = "role: NETAR-6685, ip: [10.120.33.240, 10.120.33.235]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.240", "10.120.33.235"]
    }
  }
}
resource "nsxt_policy_group" "whcsssbt" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "whcsssbt"
  description  = "role: ITSD-51970, ip: [10.120.104.3]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.104.3"]
    }
  }
}
resource "nsxt_policy_group" "sc1wnprcon01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1wnprcon01"
  description  = "role: NETAR-6705, ip: [10.120.162.85]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.162.85"]
    }
  }
}
resource "nsxt_policy_group" "ma3prapvc01" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ma3prapvc01"
  description  = "role: NETAR-6693, ip: [10.120.126.253]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.126.253"]
    }
  }
}
resource "nsxt_policy_group" "ld6-ironport" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6-ironport"
  description  = "role: NETAR-6767, ip: [10.114.33.166, 10.114.33.167, 10.114.33.170]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.114.33.166", "10.114.33.167", "10.114.33.170"]
    }
  }
}
resource "nsxt_policy_group" "ire-ironport" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ire-ironport"
  description  = "role: NETAR-6767, ip: [10.120.33.166, 10.120.33.167]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.166", "10.120.33.167"]
    }
  }
}
resource "nsxt_policy_group" "ironport_cloud" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ironport_cloud"
  description  = "role: NETAR-6767, ip: [139.138.37.116, 216.71.139.17]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["139.138.37.116", "216.71.139.17"]
    }
  }
}
resource "nsxt_policy_group" "azure_mailrelay" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "azure_mailrelay"
  description  = "role: NETAR-6767, ip: [10.40.0.7, 10.40.0.10]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.40.0.7", "10.40.0.10"]
    }
  }
}
resource "nsxt_policy_group" "icann" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "icann"
  description  = "role: NETAR-6792, ip: [192.0.46.8, 192.0.43.8]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["192.0.46.8", "192.0.43.8"]
    }
  }
}
resource "nsxt_policy_group" "ld6wnprejmp04" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6wnprejmp04"
  description  = "role: ITSD-51965, ip: [10.118.160.179]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.118.160.179"]
    }
  }
}
resource "nsxt_policy_group" "aws-nifi-ranges" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "aws-nifi-ranges"
  description  = "role: ITSD-51966, ip: [100.76.16.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["100.76.16.0/20"]
    }
  }
}
resource "nsxt_policy_group" "brswn561" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "brswn561"
  description  = "role: ITSD-51966, ip: [10.201.9.61, 10.1.28.61]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.201.9.61", "10.1.28.61"]
    }
  }
}
resource "nsxt_policy_group" "corp_test_servers" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "corp_test_servers"
  description  = "role: NETAR-6563, ip: [10.19.2.92, 10.19.2.93, 10.19.2.94, 10.19.2.97]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.19.2.92", "10.19.2.93", "10.19.2.94", "10.19.2.97"]
    }
  }
}
resource "nsxt_policy_group" "evoke_test_ad" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "evoke_test_ad"
  description  = "role: NETAR-6949, ip: [10.114.68.0/26]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.114.68.0/26"]
    }
  }
}
resource "nsxt_policy_group" "sc1uxpremn89" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1uxpremn89"
  description  = "role: NETAR-6935, ip: [10.120.163.89]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.163.89"]
    }
  }
}
resource "nsxt_policy_group" "sc1_commvault_network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "sc1_commvault_network"
  description  = "role: CHG0147150, ip: [10.120.46.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.46.0/24"]
    }
  }
}
resource "nsxt_policy_group" "ma3_commvault_network" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ma3_commvault_network"
  description  = "role: CHG0147150, ip: [10.120.47.0/24]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.47.0/24"]
    }
  }
}
resource "nsxt_policy_group" "il_infosec_machines" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "il_infosec_machines"
  description  = "role: ITSD-71301, ip: [10.20.168.26, 10.20.160.218]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.20.168.26", "10.20.160.218"]
    }
  }
}
resource "nsxt_policy_group" "ld6-synergy-deployment-blade-enc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ld6-synergy-deployment-blade-enc"
  description  = "role: NETAR-7064, ip: [10.112.11.50]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.112.11.50"]
    }
  }
}
resource "nsxt_policy_group" "ma3wnprfs08-group-williamhill-plc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "ma3wnprfs08-group-williamhill-plc"
  description  = "role: NETAR-7228, ip: [10.120.192.231]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.192.231"]
    }
  }
}
resource "nsxt_policy_group" "citrix_ob_scc" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "citrix_ob_scc"
  description  = "role: NETAR-7228, ip: [10.120.33.81, 10.120.33.82, 10.120.33.83, 10.120.33.84, 10.120.33.85, 10.120.39.147, 10.120.39.148, 10.120.39.149, 10.120.39.150, 10.120.39.151]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.120.33.81", "10.120.33.82", "10.120.33.83", "10.120.33.84", "10.120.33.85", "10.120.39.147", "10.120.39.148", "10.120.39.149", "10.120.39.150", "10.120.39.151"]
    }
  }
}
resource "nsxt_policy_group" "kafka_topics_networks" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "kafka_topics_networks"
  description  = "role: NETAR7174, ip: [10.132.64.0/20, 10.132.80.0/20, 10.132.96.0/20]"
  domain       = "cgw"
  criteria {
    ipaddress_expression {
      ip_addresses = ["10.132.64.0/20", "10.132.80.0/20", "10.132.96.0/20"]
    }
  }
}

/*======================================
#### object-groups ####
========================================*/

resource "nsxt_policy_group" "comm_vault_servers_group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "comm_vault_servers_group"
  description  = "role: group_containing_dc_com_vault_server_groups"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.comm_vault_servers_ld6.path, nsxt_policy_group.comm_vault_servers_scc.path]
    }
  }
}
resource "nsxt_policy_group" "storage_devices_group" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "storage_devices_group"
  description  = "role: group_containing_mt_scc_storage"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.msc-pure-storage.path, nsxt_policy_group.sc1-pure-storage.path, nsxt_policy_group.sc1-isilon-storage.path]
    }
  }
}
resource "nsxt_policy_group" "citrix" {
  lifecycle {
    create_before_destroy = true
  }
  display_name = "citrix"
  description  = "role: group_containing_citrix_subnets"
  domain       = "cgw"
  criteria {
    path_expression {
      member_paths = [nsxt_policy_group.scc_citrix.path, nsxt_policy_group.scc_accurate_citrix.path, nsxt_policy_group.brs_citrix.path]
    }
  }
}
