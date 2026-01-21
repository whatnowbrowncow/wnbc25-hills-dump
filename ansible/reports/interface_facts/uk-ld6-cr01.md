# uk-ld6-cr01

## Interface List
| Interface name | IP address |
|---------------|-----------------|
  - TenGigabitEthernet5/14.1  |  10.92.1.129  |  gi-mpl-ar01 : te0/0/0.1
  - mgmt0  |  10.112.129.8  |  uk-ld6-ms01 : management : Eth1/27
  - TenGigabitEthernet5/1.1  |  10.92.1.93  |  uk-ld6-cr02 : Te5/1.1
  - TenGigabitEthernet5/10.1  |  10.92.10.38  |  VM-EVPN : MPLS
  - Loopback0  |  10.92.0.38  |  default-vrf : routing : router-id
  - Loopback20  |  10.99.253.59  |  group-vrf : management : management interface
  - Port-channel1.9  |  10.89.0.1  |  transit-vrf : transit : uk-ld6-ls03/04 eth1/22 : pte-internal-vrf
  - Port-channel1.8  |  10.89.0.65  |  transit-vrf : transit : uk-ld6-ls03/04 eth1/22 : common:default-vrf
  - Port-channel1.1  |  10.19.0.1  |  group-vrf : transit : uk-ld6-ls03/04 eth1/22
  - Port-channel1.3  |  10.59.0.1  |  retail-vrf : transit : uk-ld6-ls03/04 eth1/22
  - Port-channel1.2  |  10.79.0.1  |  storage-vrf : transit : uk-ld6-ls03/04 eth1/22
  - Port-channel1.5  |  10.39.0.1  |  tote-vrf : transit : uk-ld6-ls03/04 eth1/22
  - Port-channel1.4  |  10.29.0.1  |  sis-vrf : transit : uk-ld6-ls03/04 eth1/22
  - Port-channel1.6  |  10.49.0.1  |  wan-vrf : transit : uk-ld6-ls03/04 eth1/22
