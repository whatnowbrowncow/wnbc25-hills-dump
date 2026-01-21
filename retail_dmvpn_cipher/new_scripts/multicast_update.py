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

def multicast_update():
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    nr_spokes = nr.filter(role="router")



    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show version", use_genie=True, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show interfaces", use_genie=True, use_timing=False)
    
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
    
    lan_interfaces = rhf.get_lan_interface(device_facts,2)
    

    
    
    with open('/dbdev/retail_dmvpn_cipher/isr4321_multicast_config.txt') as f:
        isr4321_multicast_config = f.read().splitlines()
    with open('/dbdev/retail_dmvpn_cipher/cisco1941_multicast_config.txt') as f:
        c1941_multicast_config = f.read().splitlines()
    with open('/dbdev/retail_dmvpn_cipher/multicast_lan_config.txt') as f:
        multicast_lan_config = f.read().splitlines()
    devices_to_configure = []

        ## create output folder for run
    curfoltime = str(datetime.now().strftime('%d_%m_%Y_%H_%M_%S'))
    os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/results/multicast/'+curfoltime)
    config_changes = {}

    for device,hardware in hardware_type.items():
        if hardware == str(nr_spokes.inventory.hosts[device].data['device_type']):
            console.print("[green]{} hardware type ({}) matches inventory - PASS".format(device,hardware))
            devices_to_configure.append(device)
            if "stadium_concentrator" in nr_spokes.inventory.hosts[device].groups:
                console.print("[green]{} is a stadium concentrator, applying special config".format(device))
                device_config = []
                device_config.extend(isr4321_multicast_config)
                device_config.extend(multicast_lan_config)
                config_changes[device]=device_config
            elif hardware == "ISR4321/K9" or hardware == "ISR" :
                device_config = []
                device_config.extend(isr4321_multicast_config)
                device_config.append("Interface {}".format(lan_interfaces[device]))
                device_config.extend(multicast_lan_config)
                config_changes[device]=device_config
            elif hardware == "CISCO1941/K9" or hardware == "CISCO1921/K9" :
                device_config = []
                device_config.extend(c1941_multicast_config)
                device_config.append("Interface {}".format(lan_interfaces[device]))
                device_config.extend(multicast_lan_config)
                config_changes[device]=device_config
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
    
    #exit()
    cfg_devices = nr_spokes.filter(F(name__any=devices_to_configure))
    def update_multicast_config(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_save_config)
        task.run(task=netmiko_send_config, config_commands=config_changes[str(task.host)])
        netmiko_bar.update()
    
    console.print("\n")
    console.print("[bold italic]############################################################################")
    console.print("[bold italic]Making changes")
    console.print("[bold italic]############################################################################")
    
    with tqdm(
        total=len(devices_to_configure),desc="progress",
    ) as netmiko_bar:
        ssh_update=cfg_devices.run(task=update_multicast_config,netmiko_bar=netmiko_bar)
    #clean config results
    ssh_update_clean,ssh_update_failed_hosts = rhf.clean_facts(ssh_update)
    
    #print('####################testing function#####################')
    processed_results,full_processed_results = rhf.process_update_results(ssh_update_clean)
    #print('#########################################')
        
    console.print('[bold blue]################ SUMMARY OF CHANGES MADE #################')
    console.print("Total devices targeted: [blue]{}".format(len(nr_spokes.inventory.hosts)))
    console.print("Data gathering from hosts: [green]Success:{} [/green]/[red] Failed:{}".format(len(list(config_changes)),len(list(failed_hosts))))
    console.print("Total devices requiring config change: [blue]{}".format(len(list(devices_to_configure))))
    console.print("Total devices changed succesfully: [green]Success:{} [/green]/[red] Failed:{}".format(len(list(ssh_update_clean)),len(list(ssh_update_failed_hosts))))
    if len(ssh_update_failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed at the configuration stage:")
        for device,reason in ssh_update_failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    
    filepath7 = '/dbdev/retail_dmvpn_cipher/outputs/results/multicast/'+curfoltime+'/processed_results.json'
    with open(filepath7, "w") as outfile: 
        json.dump(processed_results, outfile)
    #save it
    with open(f'/dbdev/retail_dmvpn_cipher/outputs/results/multicast/'+curfoltime+'/full_processed_results.pickle', 'wb') as file:
        pickle.dump(full_processed_results, file)
    #console.print(full_processed_results)
##### check devices are still active and save the config
    cfg_devices = nr_spokes.filter(F(name__any=devices_to_configure))

    console.print("\n")
    console.print("[bold italic]############################################################################")
    console.print("[bold italic]Checking for any failed hosts following changes")
    console.print("[bold italic]############################################################################")

    with tqdm(
        total=len(devices_to_configure),desc="progress",
    ) as netmiko_bar:
        device_check=cfg_devices.run(task=gatherfacts,netmiko_bar=netmiko_bar)
    #clean config results
    #console.print("[bold italic]Checking for any failed hosts following changes")
    device_check_clean,device_check_failed_hosts = rhf.clean_facts(device_check)
    

    #print('#########################################')
    
    for device,reason in device_check_clean.items():
        console.print('[green]{} has been succesfully updated and access confirmed'.format(device))
    if len(device_check_failed_hosts.items()) > 0:
        for device,reason in device_check_failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
            devices_to_configure.remove(device)
            
    console.print("\n")
    console.print("[bold italic]############################################################################")
    console.print("[bold italic]Saving configs following changes and checks")
    console.print("[bold italic]############################################################################")

    save_devices = nr_spokes.filter(F(name__any=devices_to_configure))
    def save_config(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_save_config)
        netmiko_bar.update()
    
    with tqdm(
        total=len(devices_to_configure),desc="progress",
    ) as netmiko_bar:
        device_save=save_devices.run(task=save_config,netmiko_bar=netmiko_bar)
    #clean config results
    device_save_clean,device_save_failed_hosts = rhf.clean_facts(device_save)
    
    
    if len(device_save_failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed at the save stage (all other devices successful):")
        for device,reason in device_save_failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    else:
        console.print("[bold italic green]All devices have been succesfully saved:")
   

if __name__ == "__main__":
    multicast_update()