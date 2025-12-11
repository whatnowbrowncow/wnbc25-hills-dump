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
import dmvpn_cipher_check as dcc

curfoltime,failed_hosts,crypto_config,nr_spokes,devices_configured,devices_to_configure,devices_to_skip,config_changes=dcc.cipher_check()
filepath4 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/config_changes.json'
with open(filepath4, "w") as outfile: 
    json.dump(config_changes, outfile)

filepath5 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/crypto_config.json'
with open(filepath5, "w") as outfile: 
    json.dump(crypto_config, outfile)

if len(devices_to_configure) > 0:
    console.print("[blue]##################\nStep 2 of 2 - Making changes ({} devices), this may take a while\n##################".format(len(devices_to_configure)))
else:
    console.print("[green]No configuration changes are required, all contacted devices are configured correctly")
cfg_devices = nr_spokes.filter(F(name__any=devices_to_configure))
def update_cypher_config(task:Task,netmiko_bar) -> Result:
    task.run(task=netmiko_send_config, config_commands=config_changes[str(task.host)])
    task.run(task=netmiko_save_config)
    netmiko_bar.update()

with tqdm(
    total=len(devices_to_configure),desc="progress",
) as netmiko_bar:
    cipher_update=cfg_devices.run(task=update_cypher_config,netmiko_bar=netmiko_bar)
#clean config results
cipher_update_clean,cipher_update_failed_hosts = rhf.clean_facts(cipher_update)

#print('####################testing function#####################')
processed_results,full_processed_results = rhf.process_update_results(cipher_update_clean)
#print('#########################################')
    
console.print('[bold blue]################ SUMMARY OF CHANGES MADE #################')
console.print("Total devices targeted: [blue]{}".format(len(nr_spokes.inventory.hosts)))
console.print("Data gathering from hosts: [green]Success:{} [/green]/[red] Failed:{}".format(len(list(crypto_config)),len(list(failed_hosts))))
console.print("Total devices skipped (no config change required): [yellow]{}".format(len(list(devices_configured))))
console.print("Total devices skipped (cannot be changed at this time): [red]{}".format(len(list(devices_to_skip))))
console.print("Total devices requiring config change: [blue]{}".format(len(list(devices_to_configure))))
console.print("Total devices changed succesfully: [green]Success:{} [/green]/[red] Failed:{}".format(len(list(cipher_update_clean)),len(list(cipher_update_failed_hosts))))
if len(cipher_update_failed_hosts.items()) > 0:
    console.print("[bold italic red]The following devices have failed at the configuration stage:")
    for device,reason in cipher_update_failed_hosts.items():
        console.print('[red]{}[/red][bold red]:{}'.format(device,reason))

filepath7 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/processed_results.json'
with open(filepath7, "w") as outfile: 
    json.dump(processed_results, outfile)
#save it
with open(f'/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/full_processed_results.pickle', 'wb') as file:
    pickle.dump(full_processed_results, file)
