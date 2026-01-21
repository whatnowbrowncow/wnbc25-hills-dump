#! /usr/bin/env python
# Modules
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_netmiko.tasks import netmiko_send_command
from nornir_netmiko.tasks import netmiko_send_config
from nornir_netmiko.tasks import netmiko_save_config
from nornir.core.filter import F
from nornir.core.task import Task, Result
from netaddr import IPNetwork, IPAddress
import json
import re
import json
from rich.console import Console
from rich.table import Table
from tokenize import String
import difflib
from pprint import pprint
console = Console()
# Local artefacts
import oob_helper_functions as ohf
from tqdm import tqdm
import logging

logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
logger = logging.getLogger("netmiko")

# Variables
config_files = {'oob'  :"./config_files/oob_config.yaml"}

config_file = "/dbdev/oob/config_files/oob_config.yaml"


# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ### Get list devices from inventory based on role
    nr_devices = nr.filter(role="oob")
    
    ### Function to run various show commands on the device
    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show license", use_genie=True, use_timing=True)

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
    console.print("[blue]##################\nStep 1 of 1 - Gathering device facts ({} devices), this may take a while\n##################".format(len(nr_devices.inventory.hosts)))
    with tqdm(
        total=len(nr_devices.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            device_facts=nr_devices.run(
                task=gatherfacts,
                netmiko_bar=netmiko_bar,
                
            )



    
    #device_facts=nr_devices.run(task=gatherfacts)
    device_facts,failed_hosts=ohf.clean_facts(device_facts)

    ##parse version information
    licence_parsed = ohf.get_licence(device_facts,1)
    
    ## put together a combined data dictionary of all the facts we have parsed
    combined_data = {}
    devices_with_errors = []
    for router,details in licence_parsed.items():
        #try:
        combined_data[router] = details
    #if len(failed_hosts.items()) > 0:
    #    console.print("[bold italic red]The following devices have failed and will be removed from the final results:")
    #    for device,reason in failed_hosts.items():
    #        console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    #else:
    #    console.print("[bold italic green]Good news! There are no failed devices")

    console.print("[blue]##########################################################################\n#                                 Results                                #\n##########################################################################")
    console.print("Number of devices attempted: [cyan]{}".format(len(nr_devices.inventory.hosts)))
    console.print("Number of devices successfully connected to: [green]{}".format(len(combined_data.keys())))
    console.print("Number of devices that failed to connect: [red]{}".format(len(failed_hosts.keys())))
    console.print("[blue]--------------------------------------------------------------------------")
    for device in nr_devices.inventory.hosts:
        if device in combined_data.keys():
            console.print("{} : [green]SUCCESS!".format(device))
        else:
            console.print("{} : [red]FAILED! : [italic dark red]{}".format(device,failed_hosts[device]))
#
## create various output files

    console.print("[blue]##########################################################################\n#                                 Security Licence Check                                #\n##########################################################################")
    for device,data in combined_data.items():
        if 'securityk9' in data.keys():
            if data['securityk9']['Type'] == 'Permanent':
                console.print("{} : [green]SUCCESS - Device has a valid security license".format(device))
            elif data['securityk9']['Type'] != 'Permanent':
                console.print("{} : [red]Fail - Device has a security license type of [/red]{}. [red]Time left on license = [/red]{}".format(device,str(data['securityk9']['Type'])),str(data['securityk9']['Period left']))


    filepath1 = '/dbdev/oob/outputs/license_data.json'
    with open(filepath1, "w") as outfile: 
        json.dump(combined_data, outfile)
    filepath2 = '/dbdev/oob/outputs/failed_hosts.json'
    with open(filepath2, "w") as outfile: 
        json.dump(failed_hosts, outfile)
