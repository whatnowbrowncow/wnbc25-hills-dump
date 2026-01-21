#! /usr/bin/env python
# Modules
from curses import delay_output
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
from logging import exception
from unicodedata import name
from click import prompt
from nornir import InitNornir
import pprint
import jinja2
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
import apic_helper_functions as ahf

# Variables
config_file = "/dbdev/aci/config_files/apic_lab.yaml"


# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(role="apics")

    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show endpoints", use_genie=True, use_timing=False, read_timeout=20)

    
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

    #print(device_facts)
    #print_result(device_facts)
    device_facts,failed_hosts=ahf.clean_facts(device_facts)
  #crypto_config = rhf.parse_crypto(device_facts,1,2)
    epg_data,multiple_endpoints = ahf.get_epg_data(device_facts,1)
    #print(epg_data)

    filepath1 = '/dbdev/aci/outputs/endpoints_post_change.json'
    with open(filepath1, "w") as outfile: 
        json.dump(epg_data, outfile)

    #pprint.pprint(epg_data)
    print('~~~~~~~~~~~~~~~~Active Endpoints~~~~~~~~~~~~~~~~\n')



    #console.print('There are [yellow]{}[/yellow] EPGs with multiple VLAN tags'.format(str(len(multiple_endpoints))))
    endpointtable = Table(title= 'Active Endpoint Data',show_header=True, header_style="bold blue")
    endpointtable.add_column('EPG',justify='center')
    endpointtable.add_column('Tenant',justify='center')
    endpointtable.add_column('Application profile',justify='center')
    endpointtable.add_column('Active Endpoints (count)',justify='center')
    for tenant,aps in epg_data['Tenants'].items():
        for ap,epgs in epg_data['Tenants'][tenant]['Application_profiles'].items():
            for epg,data in epg_data['Tenants'][tenant]['Application_profiles'][ap]['EPGs'].items():
                endpointtable.add_row(tenant,ap,epg,str(len(data['Endpoints'].keys())))
    console.print(endpointtable)