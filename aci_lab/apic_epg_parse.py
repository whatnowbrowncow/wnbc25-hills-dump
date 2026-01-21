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
config_file = "/dbdev/aci_lab/config_files/apic_lab.yaml"


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
    print(epg_data)

    filepath1 = '/dbdev/aci_lab/outputs/endpoints.json'
    with open(filepath1, "w") as outfile: 
        json.dump(epg_data, outfile)

    pprint.pprint(epg_data)
    print('~~~~~~~~~~~~~~~~Multiple Endpoints~~~~~~~~~~~~~~~~')
    multiencaptable = Table(title= 'EPGs with multiple VLANS',show_header=True, header_style="bold blue")
    multiencaptable.add_column('EPG',justify='center')
    multiencaptable.add_column('Tenant',justify='center')
    multiencaptable.add_column('Application profile',justify='center')
    multiencaptable.add_column('VLANs (count)',justify='center')
    for row in multiple_endpoints:
         multiencaptable.add_row(str(row[0]),str(row[1]),str(row[2]),str(row[3]),)
    console.print(multiencaptable)

    templateLoader = jinja2.FileSystemLoader(searchpath="./")
    templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
    TEMPLATE_FILE = "epg_yaml_creator.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)
    
    outputText = template.render(data = epg_data)  # this is where to put args to the template renderer
    file = "epgs.yaml"
    csv_file = open(file, "w")
    csv_file.write(outputText)

    templateLoader = jinja2.FileSystemLoader(searchpath="./")
    templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
    TEMPLATE_FILE = "vlan_config_creator.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)
    
    outputText = template.render(data = epg_data)  # this is where to put args to the template renderer
    file = "vlan_config.txt"
    csv_file = open(file, "w")
    csv_file.write(outputText)