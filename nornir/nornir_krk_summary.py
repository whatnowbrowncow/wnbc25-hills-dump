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

def latency_summary():
    console = Console()
    ## Initiate Nornir
    ping_summary_table = Table(title='Ping Test Summary',show_header=True, header_style="bold blue")
    ping_summary_table.add_column('Device')
    ping_summary_table.add_column('Number of Tests',justify='center')
    ping_summary_table.add_column('Average Success Rate',justify='center')
    ping_summary_table.add_column('Best Success Rate',justify='center')
    ping_summary_table.add_column('Worst Success Rate',justify='center')
    with open('/dbdev/nornir/krk_latency.json') as json_file: 
        ping_results=json.load(json_file)
    ar01_sov_success_rates = []
    ar01_ld6_success_rates = []
    ar02_sov_success_rates = []
    ar02_ld6_success_rates = []  
    for result in ping_results['pl-krk-ar01']['sov'].keys():
        ar01_sov_success_rates.append(int(ping_results['pl-krk-ar01']['sov'][result]['success rate']))
    for result in ping_results['pl-krk-ar01']['ld6'].keys():
        ar01_ld6_success_rates.append(int(ping_results['pl-krk-ar01']['ld6'][result]['success rate']))
    for result in ping_results['pl-krk-ar02']['sov'].keys():
        ar02_sov_success_rates.append(int(ping_results['pl-krk-ar02']['sov'][result]['success rate']))
    for result in ping_results['pl-krk-ar02']['ld6'].keys():
        ar02_ld6_success_rates.append(int(ping_results['pl-krk-ar02']['ld6'][result]['success rate']))
    ping_summary_table.add_row('ar01-sov',str(len(ar01_sov_success_rates)),str(sum(ar01_sov_success_rates)/len(ar01_sov_success_rates)),str(max(ar01_sov_success_rates)),str(min(ar01_sov_success_rates)))       
    ping_summary_table.add_row('ar01-ld6',str(len(ar01_ld6_success_rates)),str(sum(ar01_ld6_success_rates)/len(ar01_ld6_success_rates)),str(max(ar01_ld6_success_rates)),str(min(ar01_ld6_success_rates)))       
    ping_summary_table.add_row('ar02-sov',str(len(ar02_sov_success_rates)),str(sum(ar02_sov_success_rates)/len(ar02_sov_success_rates)),str(max(ar02_sov_success_rates)),str(min(ar02_sov_success_rates)))       
    ping_summary_table.add_row('ar02-ld6',str(len(ar02_ld6_success_rates)),str(sum(ar02_ld6_success_rates)/len(ar02_ld6_success_rates)),str(max(ar02_ld6_success_rates)),str(min(ar02_ld6_success_rates)))          
    console.print(ping_summary_table)

    
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
    latency_summary()