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

dmvpnciphertable = Table(title='DMVPN Cipher Check Summary',show_header=True, header_style="bold blue")
dmvpnciphertable.add_column('Device',justify='center')
dmvpnciphertable.add_column('Policy',justify='center')
dmvpnciphertable.add_column('Transform-set',justify='center')
dmvpnciphertable.add_column('Profile',justify='center')
dmvpnciphertable.add_column('Update required',justify='center')
# Body

def ssh_check():
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    nr_spokes = nr.filter(role="spokes")
    #spoke_eigrp = nr_spokes.run(task=netmiko_send_command, command_string="show ip eigrp neighbors", use_genie=True, use_timing=True)
    #spoke_eigrp,failed_hosts = rhf.clean_facts_single_result(spoke_eigrp)
    #eigrp_neighbours = rhf.spoke_eigrp_neighbours(spoke_eigrp)
    #print(eigrp_neighbours)
    #spoke_crypto = nr_spokes.run(task=netmiko_send_command, command_string="show run | section crypto", use_genie=False, use_timing=True)
    #spoke_crypto,failed_hosts = rhf.clean_facts_single_result(spoke_crypto)
    #crypto_config = rhf.parse_crypto(spoke_crypto)
    #print(crypto_config)
    #spoke_tunnels = nr_spokes.run(task=netmiko_send_command, command_string="show run | section interface Tunnel", use_genie=False, use_timing=True)
    #spoke_tunnels,failed_hosts = rhf.clean_facts_single_result(spoke_tunnels)
    #spoke_tunnels_parsed = rhf.get_tunnel_interface_data(spoke_tunnels)


    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show version", use_genie=True, use_timing=False)
    
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
    devices_to_retry = []
    for host,reason in failed_hosts.items():
        if 'missing a result' in str(reason):
            devices_to_retry.append(host)
            
    while len(devices_to_retry) != 0:
        retry_devices = nr_spokes.filter(F(name__any=devices_to_retry))
        console.print("[blue]##################\nStep 2 of 4 - Retry - Gathering device facts for ({} devices), this may take a while\n##################".format(len(retry_devices.inventory.hosts)))
        with tqdm(
            total=len(retry_devices.inventory.hosts), desc="progress",
        ) as netmiko_bar:
    
                # we call our grouped task passing both bars
                retry_device_facts=retry_devices.run(
                    task=gatherfacts,
                    netmiko_bar=netmiko_bar,
                    
                )
        retry_device_facts,retry_failed_hosts=rhf.clean_facts(retry_device_facts) 
        device_facts = {**device_facts,**retry_device_facts}
        failed_hosts = {**failed_hosts,**retry_failed_hosts}
        devices_to_retry = []
        for host,reason in retry_failed_hosts.items():
            if 'missing a result' in str(reason):
                devices_to_retry.append(host)
    hardware_type=rhf.get_hardware_type(device_facts,1)
    
    with open('/dbdev/retail_dmvpn_cipher/isr4321_ssh_config.txt') as f:
        isr4321_ssh_config = f.read().splitlines()
    with open('/dbdev/retail_dmvpn_cipher/cisco1941_ssh_config.txt') as f:
        c1941_ssh_config = f.read().splitlines()
    with open('/dbdev/retail_dmvpn_cipher/cisco2960_ssh_config.txt') as f:
        c2960_ssh_config = f.read().splitlines()
    devices_to_configure = []
    
        ## create output folder for run
    curfoltime = str(datetime.now().strftime('%d_%m_%Y_%H_%M_%S'))
    os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/results/ssh/'+curfoltime)
    config_changes = {}

    for device,hardware in hardware_type.items():
        if hardware == str(nr_spokes.inventory.hosts[device].data['device_type']):
            console.print("[green]{} hardware type ({}) matches inventory - PASS".format(device,hardware))
            devices_to_configure.append(device)
            if hardware == "ISR4321/K9" :
                config_changes[device]=isr4321_ssh_config
            elif hardware == "CISCO1941/K9" :
                config_changes[device]=c1941_ssh_config
            elif hardware == "WS-C2960X-24PS-L" or hardware == "WS-C2960-24-S" or hardware == "WS-C2960+24LC-L" :
                config_changes[device]=c2960_ssh_config
        else:
            console.print("[red]{} hardware type ({}) does not match inventory ({}) - FAIL".format(device,hardware,str(nr_spokes.inventory.hosts[device].data['device_type'])))

    if len(failed_hosts.items()) > 0:
        console.print('\n[red]Failed hosts:')
        console.print("[bold italic red]The following devices have failed and will be removed from the final results:")
        for device,reason in failed_hosts.items():
            if 'missing a result' not in reason:
                console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    else:
        console.print('\n[green]All devices have been checked successfully')

if __name__ == "__main__":
    ssh_check()