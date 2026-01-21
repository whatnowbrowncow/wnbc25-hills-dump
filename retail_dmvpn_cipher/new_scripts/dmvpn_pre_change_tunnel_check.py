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
from nornir_netmiko.tasks import netmiko_send_config
from nornir_netmiko.tasks import netmiko_save_config
from nornir.core.filter import F
from nornir.core.task import Task, Result
from nornir.core.filter import F
from tqdm import tqdm
import pickle
import os
from datetime import datetime
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
scc_tunnel_ip = '10.92.26.1'
scc_public_ip = '141.138.128.105'
ld6_tunnel_interface = 'Tunnel12'
ld6_tunnel_ip = '10.92.27.1'
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

dmvpntable = Table(title='DMVPN Tunnel State',show_header=True, header_style="bold blue")
dmvpntable.add_column('Device',justify='center')
dmvpntable.add_column('Tunnel 11 state',justify='center')
dmvpntable.add_column('Tu11 EIGRP  neighbour',justify='center')
dmvpntable.add_column('Tunnel 12 state',justify='center')
dmvpntable.add_column('Tu12 EIGRP  neighbour',justify='center')

# Body
def tunnel_check():
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    nr_spokes = nr.filter(role="spokes")

    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show run all | section crypto", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show run | section crypto", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show run | section interface Tunnel", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show ip eigrp neighbors", use_genie=True, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show dmvpn", use_genie=False, use_timing=False)
    
    ### Calling the above function against a set of devices


        """
        This task takes two paramters that are in fact bars;
        napalm_get_bar and other_bar. When we want to tell
        to each respective bar that we are done and should update
        the progress we can do so with bar_name.update()
        """
        #task.run(task=gatherfacts)
        netmiko_bar.update()
    
   
    
    
    # we create the first bar named napalm_get_bar
    console.print("[blue]##################\nStep 1 of 4 - Gathering device facts ({} devices), this may take a while\n##################".format(len(nr_spokes.inventory.hosts)))
    with tqdm(
        total=len(nr_spokes.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            device_facts=nr_spokes.run(
                task=gatherfacts,
                netmiko_bar=netmiko_bar,
                
            )


    device_facts,failed_hosts=rhf.clean_facts(device_facts)
    crypto_config = rhf.parse_crypto(device_facts,1,2)
    spoke_tunnels_parsed = rhf.get_tunnel_interface_data(device_facts,3)
    eigrp_neighbours = rhf.spoke_eigrp_neighbours(device_facts,4)
    dmvpn = rhf.dmpvn_per_tunnel(device_facts,5)
    filepath = '/dbdev/retail_dmvpn_cipher/crypto_config.json'
    with open(filepath, "w") as outfile: 
        json.dump(crypto_config, outfile)
    

    devices_to_skip = []
    devices_to_configure = []
    devices_configured = []
    #Confirm devices require update
    check_results={}


    device_tunnels = {}

    for device, data in device_facts.items():
        device_tunnels[device]={}
        try:
            device_tunnels[device]['tunnel 11 state'] = dmvpn[device]['Tunnels']['11'][scc_public_ip]['state']
        except:
            device_tunnels[device]['tunnel 11 state'] = 'not found'
        try:
            device_tunnels[device]['tunnel 12 state'] = dmvpn[device]['Tunnels']['12'][ld6_public_ip]['state']
        except:
            device_tunnels[device]['tunnel 12 state'] = 'not found'
        try:
            if str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP']) in eigrp_neighbours[device]['neighbours'].keys():
                device_tunnels[device]['tunnel 11 nbr'] = str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP'])
            else:
                device_tunnels[device]['tunnel 11 nbr'] = 'not found'
        except:
            device_tunnels[device]['tunnel 11 nbr'] = 'not found'
        try:
            if str(dmvpn[device]['Tunnels']['12'][ld6_public_ip]['tunnel IP']) in eigrp_neighbours[device]['neighbours'].keys():
                device_tunnels[device]['tunnel 12 nbr'] = str(dmvpn[device]['Tunnels']['12'][ld6_public_ip]['tunnel IP'])
            else:
                device_tunnels[device]['tunnel 12 nbr'] = 'not found'
        except:
            device_tunnels[device]['tunnel 12 nbr'] = 'not found'


    for device, data in device_tunnels.items():
        if device_tunnels[device]['tunnel 11 state'] == 'UP':
            device_tunnels[device]['tu11state'] = '[green]\u2713[/green]'
            tu11state = '[green]\u2713[/green]'
        else:
            device_tunnels[device]['tu11state'] = '[red]\u2717[/red]'
            tu11state = '[red]\u2717[/red]'
        if device_tunnels[device]['tunnel 12 state'] == 'UP':
            device_tunnels[device]['tu12state'] = '[green]\u2713[/green]'
            tu12state = '[green]\u2713[/green]'
        else:
            device_tunnels[device]['tu12state'] = '[red]\u2717[/red]'
            tu12state = '[red]\u2717[/red]'
        if device_tunnels[device]['tunnel 11 nbr'] == scc_tunnel_ip:
            device_tunnels[device]['tu11nbr'] = '[green]{}[/green]'.format(str(device_tunnels[device]['tunnel 11 nbr']))
            tu11nbr = '[green]{}[/green]'.format(str(device_tunnels[device]['tunnel 11 nbr']))
        else:
            device_tunnels[device]['tu11nbr'] = '[red]{}[/red]'.format(str(device_tunnels[device]['tunnel 11 nbr']))
            tu11nbr = '[red]{}[/red]'.format(str(device_tunnels[device]['tunnel 11 nbr']))
        if device_tunnels[device]['tunnel 12 nbr'] == ld6_tunnel_ip:
            device_tunnels[device]['tu12nbr'] = '[green]{}[/green]'.format(str(device_tunnels[device]['tunnel 12 nbr']))
            tu12nbr = '[green]{}[/green]'.format(str(device_tunnels[device]['tunnel 12 nbr']))
        else:
            device_tunnels[device]['tu12nbr'] = '[red]{}[/red]'.format(str(device_tunnels[device]['tunnel 12 nbr']))
            tu12nbr = '[red]{}[/red]'.format(str(device_tunnels[device]['tunnel 12 nbr']))
        dmvpntable.add_row(device,tu11state,tu11nbr,tu12state,tu12nbr)
    console.print(dmvpntable)

    #exit()       
    
    ################### WRITE DICT TO JSON #####################

    
    ########### ADD DATA TO LOGS ##################
    console.print('[red]The following devices failed:\n______________________________\n\n')
    for device,reason in failed_hosts.items():
        console.print('[bold red]{}[/bold red][red]: {}'.format(device,reason))

    curfoltime = str(datetime.now().strftime('%Y_%m_%d@%H:%M:%S'))
    os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/golden_tunnel_state/'+curfoltime)

    filepath1 = '/dbdev/retail_dmvpn_cipher/outputs/golden_tunnel_state/'+curfoltime+'/pre_change_tunnel_state.json'
    with open(filepath1, "w") as outfile: 
        json.dump(device_tunnels, outfile)

    filepath2 = '/dbdev/retail_dmvpn_cipher/outputs/golden_tunnel_state/pre_change_tunnel_state.json'
    with open(filepath2, "w") as outfile: 
        json.dump(device_tunnels, outfile)
#
    with open(f'/dbdev/retail_dmvpn_cipher/outputs/golden_tunnel_state/'+curfoltime+'/pre_change_tunnel_state.pickle', 'wb') as file:
        pickle.dump(dmvpntable, file)

    with open(f'/dbdev/retail_dmvpn_cipher/outputs/golden_tunnel_state/pre_change_tunnel_state.pickle', 'wb') as file:
        pickle.dump(dmvpntable, file)


if __name__ == "__main__":
    tunnel_check()
