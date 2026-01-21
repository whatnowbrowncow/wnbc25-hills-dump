#! /usr/bin/env python
# Modules
from curses import delay_output
import schedule
import time
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
import helper_functions as hf
# Variables
config_file = "/dbdev/nornir/config_files/krk_config.yaml"

# Body

def latency_check():
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)

    nr_devices = nr.filter(role="ios")



    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="ping vrf group-vrf 10.92.50.1 rep 500 source gigabitEthernet 0/0/4.127", read_timeout=100,use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="ping vrf group-vrf 10.92.50.5 rep 500 source gigabitEthernet 0/0/4.127", read_timeout=100,use_genie=False, use_timing=False)
    
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
    console.print("[blue]##################\nStep 1 of 4 - Gathering device facts ({} devices), this may take a while\n##################".format(len(nr_devices.inventory.hosts)))
    with tqdm(
        total=len(nr_devices.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            device_facts=nr_devices.run(
                task=gatherfacts,
                netmiko_bar=netmiko_bar,
                
            )




    device_facts,failed_hosts=hf.clean_facts(device_facts)
    devices_to_retry = []
    for host,reason in failed_hosts.items():
        if 'missing a result' in str(reason):
            devices_to_retry.append(host)
            
    while len(devices_to_retry) != 0:
        retry_devices = nr_devices.filter(F(name__any=devices_to_retry))
        console.print("[blue]##################\nStep 2 of 4 - Retry - Gathering device facts for ({} devices), this may take a while\n##################".format(len(retry_devices.inventory.hosts)))
        with tqdm(
            total=len(retry_devices.inventory.hosts), desc="progress",
        ) as netmiko_bar:
    
                # we call our grouped task passing both bars
                retry_device_facts=retry_devices.run(
                    task=gatherfacts,
                    netmiko_bar=netmiko_bar,
                    
                )
        retry_device_facts,retry_failed_hosts=hf.clean_facts(retry_device_facts)
        device_facts = {**device_facts,**retry_device_facts}
        failed_hosts = {**failed_hosts,**retry_failed_hosts}
        devices_to_retry = []
        for host,reason in retry_failed_hosts.items():
            if 'missing a result' in str(reason):
                devices_to_retry.append(host)

    latency = hf.parse_pings(device_facts,1,2)
    filepath = '/dbdev/nornir/krk_latency.json'
    with open(filepath, "w") as outfile: 
        json.dump(latency, outfile)

#
#    #####################do some config###############################
#   
#        if not os.path.exists('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device):
#            os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device)
#        if not os.path.exists('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive'):
#            os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive')
#
#    ################### WRITE DICT TO JSON #####################
#    
#        filepath = '/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/config_changes_latest.txt'
#        with open(filepath, "w") as outfile: 
#            outfile.write('\n'.join(config_changes[device]))
#    
#    ########### GET TIME ########
#    
#        curtime = str(datetime.now().strftime('%H_%M_%S_%d_%m_%Y'))
#    
#    ########### ADD DATA TO LOGS ##################
#    
#        logfilename = 'config_changes_' + curtime + '.txt'
#        filepath = '/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive/'+logfilename
#        with open(filepath, "w") as outfile: 
#            outfile.write('\n'.join(config_changes[device]))
#
#
#
#    filepath4 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/config_changes.json'
#    with open(filepath4, "w") as outfile: 
#        json.dump(config_changes, outfile)
#
#    filepath5 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/crypto_config.json'
#    with open(filepath5, "w") as outfile: 
#        json.dump(crypto_config, outfile)
#
#    return(curfoltime,failed_hosts,crypto_config,nr_spokes,devices_configured,devices_to_configure,devices_to_skip,config_changes)

if __name__ == "__main__":
    latency_check()
    schedule.every(60).minutes.do(latency_check)
    while True:
        schedule.run_pending()
        time.sleep(1)
    #latency_check()