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
import time
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
new_mtu = '1390'
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

dmvpnmtupretable = Table(title='DMVPN SCC Tunnel 11 + MTU Pre change Summary',show_header=True, header_style="bold blue")
dmvpnmtupretable.add_column('Device',justify='center')
dmvpnmtupretable.add_column('Tunnel 11 UP',justify='center')
dmvpnmtupretable.add_column('EIGRP  neighbour 10.92.27.1',justify='center')
dmvpnmtupretable.add_column('Profile being used',justify='center')
dmvpnmtupretable.add_column('PSK being used',justify='center')
dmvpnmtupretable.add_column('MTU old/new',justify='center')
dmvpnmtupretable.add_column('Update required',justify='center')

# Body
if __name__ == "__main__":
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


    combined_data = {}  
    combined_data['Tunnel 11 pre-change']={}

    for device, data in device_facts.items():
        try:
            combined_data['Tunnel 11 pre-change'][device]={}
            combined_data['Tunnel 11 pre-change'][device]['psk'] = crypto_config[device]['keys'][scc_public_ip]
            combined_data['Tunnel 11 pre-change'][device]['mtu'] = spoke_tunnels_parsed[device]['Tunnel11']['mtu']
            combined_data['Tunnel 11 pre-change'][device]['profile'] = spoke_tunnels_parsed[device]['Tunnel11']['profile']
            combined_data['Tunnel 11 pre-change'][device]['tunnel state'] = dmvpn[device]['Tunnels']['11'][scc_public_ip]['state']
            if str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP']) in eigrp_neighbours[device]['neighbours'].keys():
                combined_data['Tunnel 11 pre-change'][device]['Tunnel 11 nbr'] = str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP'])
            else:
                #console.print('[bold blue]{}[/bold blue] has not been added device update list, error processing data:\n [red]EIGRP neighbour not found'.format(device))
                combined_data['Tunnel 11 pre-change'][device]['Tunnel 11 nbr'] = '[red]not found[/red]'
                #combined_data['Tunnel 11 pre-change'].pop(device)
                #continue
        
        except Exception as e:
            console.print('[bold blue]{}[/bold blue] has not been added to combined data, error processing data:\n [red]{}'.format(device,str(e)))
            combined_data['Tunnel 11 pre-change'].pop(device)


    for device, data in combined_data['Tunnel 11 pre-change'].items():
        update_required = False
        if combined_data['Tunnel 11 pre-change'][device]['tunnel state'] == 'UP':
            combined_data['Tunnel 11 pre-change'][device]['tu12state'] = '[green]\u2713[/green]'
            tu12state = '[green]\u2713[/green]'
        else:
            combined_data['Tunnel 11 pre-change'][device]['tu12state'] = '[red]\u2717[/red]'
            tu12state = '[red]\u2717[/red]'
        if combined_data['Tunnel 11 pre-change'][device]['psk'] == new_psk:
            combined_data['Tunnel 11 pre-change'][device]['psk_match'] = '[green]\u2713 New PSK[/green]'
            psk_match = '[green]\u2713 New PSK[/green]'
        else:
            combined_data['Tunnel 11 pre-change'][device]['psk_match'] = '[red]\u2717 old PSK[/red]'
            psk_match = '[red]\u2717 old PSK[/red]'
            update_required = True
        if combined_data['Tunnel 11 pre-change'][device]['mtu'] == new_mtu:
            combined_data['Tunnel 11 pre-change'][device]['mtu_match'] = '[green]\u2713 New MTU[/green]'
            mtu_match = '[green]\u2713 New MTU[/green]'
        else:
            combined_data['Tunnel 11 pre-change'][device]['mtu_match'] = '[red]\u2717 old MTU[/red]'
            mtu_match = '[red]\u2717 old MTU[/red]'
            update_required = True
        if combined_data['Tunnel 11 pre-change'][device]['Tunnel 11 nbr'] == scc_tunnel_ip:
            eigrp_neighbour = '[green]\u2713[/green]'
            combined_data['Tunnel 11 pre-change'][device]['Tunnel 11 nbr match'] = '[green]\u2713[/green]'
        else:
            eigrp_neighbour = '[red]\u2717[/red]'
            combined_data['Tunnel 11 pre-change'][device]['Tunnel 11 nbr match'] = '[red]\u2717[/red]'
        if combined_data['Tunnel 11 pre-change'][device]['profile'] == profile['name']:
            combined_data['Tunnel 11 pre-change'][device]['profile_match'] = '[green]\u2713 New profile[/green]'
            profile_match = '[green]\u2713 New profile[/green]'
        else:
            combined_data['Tunnel 11 pre-change'][device]['profile_match'] = '[red]\u2717 Old profile[/red]'
            profile_match = '[red]\u2717 Old profile[/red]'
            update_required = True
        if update_required == True:
            combined_data['Tunnel 11 pre-change'][device]['update'] = '[yellow]\u2713[/yellow]'
            update = '[yellow]\u2713[/yellow]'
            devices_to_configure.append(device)
        elif update_required == False:
            combined_data['Tunnel 11 pre-change'][device]['update'] = '[yellow]\u2717[/yellow]'
            update = '[yellow]\u2717[/yellow]'
            devices_configured.append(device)
        dmvpnmtupretable.add_row(device,tu12state,eigrp_neighbour,profile_match,psk_match,mtu_match,update)
    console.print(dmvpnmtupretable)
    console.print('''Key: Configured correctly - [green]\u2713[/green]
     Update required - [yellow]\u2713[/yellow]
     Not configured - [yellow]\u271B[/yellow]
     Update not required - [yellow]\u2717[/yellow]
     Configured incorrectly / Update not possible - [red]\u2717''')
    exit()