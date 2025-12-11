#! /usr/bin/env python
# Modules
from curses import delay_output
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
from logging import exception
from unicodedata import name
from click import prompt
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_netmiko.tasks import netmiko_send_command
from nornir.core.filter import F
import re
import json
from rich.console import Console
from rich.table import Table
console = Console()
# Local artefacts
import retail_helper_functions as rhf

# Variables
config_file = "/dbdev/retail_dmvpn_cipher/config_files/retail_dmvpn.yaml"
scc_tunnel_interface = 'Tunnel11'
scc_public_ip = '141.138.128.105'
ld6_tunnel_interface = 'Tunnel11'
ld6_public_ip = '185.119.152.46'
new_psk = '69nnw55v2r7d4whmwh3u2bc6q5kfbr'

dmvpntable = Table(title='DMVPN Check Summary',show_header=True, header_style="bold blue")
dmvpntable.add_column('Spoke',justify='center')
dmvpntable.add_column('Peer IP',justify='center')
dmvpntable.add_column('Status',justify='center')
dmvpntable.add_column('UP/DOWN Time',justify='center')
dmvpntable.add_column('Spoke Status',justify='center')
# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    nr_spokes = nr.filter(role="spokes")
    spoke_eigrp = nr_spokes.run(task=netmiko_send_command, command_string="show ip eigrp neighbors", use_genie=True, use_timing=True)
    eigrp_neighbours = rhf.spoke_eigrp_neighbours(spoke_eigrp)
    print(eigrp_neighbours)
    spoke_crypto = nr_spokes.run(task=netmiko_send_command, command_string="show run | section crypto", use_genie=False, use_timing=True)
    crypto_config = rhf.parse_crypto(spoke_crypto)
    print(crypto_config)

    filepath = '/dbdev/retail_dmvpn_cipher/crypto_config.json'
    with open(filepath, "w") as outfile: 
        json.dump(crypto_config, outfile)
    
    #render config from what we've learnt
    with open('/dbdev/retail_dmvpn_cipher/cipher_config.txt') as f:
        golden_config = f.read().splitlines()
        
    for device in crypto_config:

        config_changes = {}
    
    #########psk checks below, need to be moved into 2nd script
        if crypto_config[device]['keys'][str(ld6_public_ip)] != new_psk:
            console.print('[italic yellow]{}[/italic yellow] [blue]has incorrect PSK for[/blue] [italic yellow]LD6[/italic yellow][blue] tunnel'.format(device))
            console.print('[blue]current cipher:[/blue] [italic yellow]{}[/italic yellow] | [blue]correct cipher:[/blue] [italic yellow]{}[/italic yellow]'.format(crypto_config[device]['keys'][str(ld6_public_ip)],new_psk))
            console.print('[blue]adding device to update list')
            devices_to_update.append(device)
        else:
            console.print('[italic green]{}[/italic green] [blue]has correct PSK for[/blue] [italic green]LD6[/italic green][blue] tunnel'.format(device))
    exit()

#eigrp['statue_router'][0].result['eigrp_instance']['100']['vrf']['default']['address_family']['ipv4']['eigrp_interface']['Tunnel12']
    #eigrp['uk-ld6-dmvpn01'][0].result['eigrp_instance']['100']['vrf']['retail-vrf']['address_family']['ipv4']['eigrp_interface']['Tunnel0']['eigrp_nbr']
    #print_result(eigrp)



                




