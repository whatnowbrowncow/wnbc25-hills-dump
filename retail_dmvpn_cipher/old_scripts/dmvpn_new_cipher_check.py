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
from nornir_scrapli.functions import print_structured_result
from nornir_scrapli.tasks import send_command
from nornir_scrapli.tasks import send_commands
from nornir_scrapli.tasks import send_configs
from nornir_scrapli.tasks import send_interactive
from nornir_netmiko.tasks import netmiko_send_command
from nornir_netmiko.tasks import netmiko_send_config
from nornir_netmiko.tasks import netmiko_save_config
from nornir.core.filter import F
from nornir.core.task import Task, Result
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
policy = {'number':'2',
           'data':{
           'encryption':'aes 256',
           'hash':'sha',
           'group':'5',
           'authentication':'pre-share'}}
retail_transform_set = {'name':'tset-retail-dmvpn',
           'data':{
           'set':'esp-aes 256 esp-sha-hmac',
           'mode':'transport'}}
profile = {'name':'pfl-retail-dmvpn',
           'data':{
           'lifetime':'28800',
           'transform set':'tset-retail-dmvpn',
           'pfs':'None'}}

dmvpnciphertable = Table(title='DMVPN Cipher Check Summary',show_header=True, header_style="bold blue")
dmvpnciphertable.add_column('Device',justify='center')
dmvpnciphertable.add_column('Policy',justify='center')
dmvpnciphertable.add_column('Transform-set',justify='center')
dmvpnciphertable.add_column('Profile',justify='center')
dmvpnciphertable.add_column('Update required',justify='center')

if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    nr_spokes = nr.filter(role="spokes")
    #spoke_eigrp = nr_spokes.run(task=netmiko_send_command, command_string="show ip eigrp neighbors", use_genie=True, use_timing=True)
    #eigrp_neighbours = rhf.spoke_eigrp_neighbours(spoke_eigrp)
    #print(eigrp_neighbours)
    spoke_crypto = nr_spokes.run(task=netmiko_send_command, command_string="show run | section crypto", use_genie=False, use_timing=True)
    clean_spoke_crypto,failed_hosts = rhf.clean_facts_single_result(spoke_crypto)
    crypto_config = rhf.parse_crypto(clean_spoke_crypto)
    print(crypto_config)

    filepath = '/dbdev/retail_dmvpn_cipher/crypto_config.json'
    with open(filepath, "w") as outfile: 
        json.dump(crypto_config, outfile)
    
    #Confirm devices require update
    for device, data in crypto_config.items():
        if policy['number'] not in data['policies'].keys() and retail_transform_set['name'] not in data['tf_sets'].keys() and profile['name'] not in data['profiles'].keys():
            dmvpnciphertable.add_row(device,'[yellow]\u271B','[yellow]\u271B','[yellow]\u271B','[yellow]\u2713')
        else:
            config_match = True
            if policy['number'] in data['policies'].keys():
                if policy['data']==data['policies'][policy['number']]:
                    rich_policy = '[green]\u2713'
                    
                else:
                    rich_policy = '[red]\u2717'
                    config_match = False
            else:
                rich_policy = '[yellow]\u271B'
                config_match = False
            if retail_transform_set['name'] in data['tf_sets'].keys():
                tf1 = retail_transform_set['data']
                tf2 = data['tf_sets'][retail_transform_set['name']]
                if retail_transform_set['data'] == data['tf_sets'][retail_transform_set['name']]:
                    rich_tfs = '[green]\u2713'
                else:
                    rich_tfs = '[red]\u2717'
                    config_match = False
            else:
                rich_tfs = '[yellow]\u271B'
                config_match = False
            if profile['name'] in data['profiles'].keys():
                prof1 = profile['data']
                prof2 = data['profiles'][profile['name']]
                if profile['data'] == data['profiles'][profile['name']]:
                    rich_profile = '[green]\u2713'
                else:
                    rich_profile = '[red]\u2717'
                    config_match = False
            else:
                rich_profile = '[yellow]\u271B'
                config_match = False
            if config_match == True:
                dmvpnciphertable.add_row(device,rich_policy,rich_tfs,rich_profile,'[yellow]\u2717')
            else:
                dmvpnciphertable.add_row(device,rich_policy,rich_tfs,rich_profile,'[red]\u2717')
    console.print(dmvpnciphertable)
    console.print('''Key: Configured correctly - [green]\u2713[/green]
     Update required - [yellow]\u2713[/yellow]
     Not configured - [yellow]\u271B[/yellow]
     Update not required - [yellow]\u2717[/yellow]
     Configured incorrectly / Update not possible - [red]\u2717''')
    console.print('\n[red]Failed hosts:')
    if len(failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed and will be removed from the final results:")
        for device,reason in failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))