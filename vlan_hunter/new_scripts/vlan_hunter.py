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
import network_helper_functions as nhf

# Variables
config_file = "/dbdev/vlan_hunter/config_files/config.yaml"

dmvpnciphertable = Table(title='DMVPN Cipher Check Summary',show_header=True, header_style="bold blue")
dmvpnciphertable.add_column('Device',justify='center')
dmvpnciphertable.add_column('Policy',justify='center')
dmvpnciphertable.add_column('Transform-set',justify='center')
dmvpnciphertable.add_column('Profile',justify='center')
dmvpnciphertable.add_column('Update required',justify='center')
# Body

def vlan_hunt():
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="core_switch") | F(role="asa"))
    nr_core_switches_ios = nr.filter(role="core_switch_ios")
    nr_core_switches_nxos = nr.filter(role="core_switch_nxos")
    nr_asa = nr.filter(role="asa")


    def get_contexts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="changeto system", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show context", use_genie=True, use_timing=False)
    
    ### Calling the above function against a set of devices


        """
        This task takes two paramters that are in fact bars;
        napalm_get_bar and other_bar. When we want to tell
        to each respective bar that we are done and should update
        the progress we can do so with bar_name.update()
        """
        #task.run(task=gatherfacts)
        netmiko_bar.update()
    
    
    def gather_raw_data_nxos(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show ip interface brief vrf all", use_genie=True, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show vlan", use_genie=True, use_timing=False)
    
    ### Calling the above function against a set of devices


        """
        This task takes two paramters that are in fact bars;
        napalm_get_bar and other_bar. When we want to tell
        to each respective bar that we are done and should update
        the progress we can do so with bar_name.update()
        """
        #task.run(task=gatherfacts)
        netmiko_bar.update()

    def gather_raw_data_ios(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show ip interface brief", use_genie=True, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show vlan", use_genie=True, use_timing=False)
    
    ### Calling the above function against a set of devices


        """
        This task takes two paramters that are in fact bars;
        napalm_get_bar and other_bar. When we want to tell
        to each respective bar that we are done and should update
        the progress we can do so with bar_name.update()
        """
        #task.run(task=gatherfacts)
        netmiko_bar.update()

    def gather_firewall_raw_data(task:Task,netmiko_bar) -> Result:

        for context in contexts[str(task.host)][2].result.keys():
            task.run(task=netmiko_send_command, command_string="changeto context {}".format(context), use_genie=True, use_timing=False)
            task.run(task=netmiko_send_command, command_string="show interface summary", use_genie=True, use_timing=False)

    ### Calling the above function against a set of devices


        """
        This task takes two paramters that are in fact bars;
        napalm_get_bar and other_bar. When we want to tell
        to each respective bar that we are done and should update
        the progress we can do so with bar_name.update()
        """
        #task.run(task=gatherfacts)
        netmiko_bar.update()
    
   

    console.print("[blue]##################\nStep 1 of 4 - Gathering contexts ({} devices), this may take a while\n##################".format(len(nr_asa.inventory.hosts)))
    with tqdm(
        total=len(nr_asa.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            contexts=nr_asa.run(
                task=get_contexts,
                netmiko_bar=netmiko_bar,
                
            )
    asa_raw_data = nr_asa.run(task=gather_firewall_raw_data,netmiko_bar=netmiko_bar)
    #print('contexts~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    #print_result(contexts)
    #print('vlans~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    #print_result(asa_raw_data)

    raw_data_ios = nr_core_switches_ios.run(task=gather_raw_data_ios,netmiko_bar=netmiko_bar)
    #print('ios vlans~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    #print_result(raw_data_ios)

    raw_data_nxos = nr_core_switches_nxos.run(task=gather_raw_data_nxos,netmiko_bar=netmiko_bar)
    #print('nxos vlans~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    #print_result(raw_data_nxos)

    core_switch_vlans = {
         "birstall":{},
         "scc":{},
         "gib":{}
    }
    core_switch_interfaces = {
         "birstall":{},
         "scc":{},
         "gib":{}
    }
    for hostname, entry_1_level in raw_data_nxos.items():
        core_switch_vlans["birstall"][hostname]={}
        core_switch_vlans["birstall"][hostname]["total vlans"] = len(entry_1_level[2].result["vlans"].items())
        core_switch_vlans["birstall"][hostname]["vlan list"] = []
        for vlan,data in entry_1_level[2].result["vlans"].items():
            core_switch_vlans["birstall"][hostname]["vlan list"].append(vlan)
        core_switch_interfaces["birstall"][hostname]={}
        core_switch_interfaces["birstall"][hostname]["total interfaces"] = len(entry_1_level[1].result["interface"].items())
        core_switch_interfaces["birstall"][hostname]["interfaces"] = {}
        for interface,data in entry_1_level[1].result["interface"].items():
            core_switch_interfaces["birstall"][hostname]["interfaces"][interface]={}
            core_switch_interfaces["birstall"][hostname]["interfaces"][interface]["vrf"]=raw_data_nxos[hostname][1].result["interface"][interface]["vrf"]
            core_switch_interfaces["birstall"][hostname]["interfaces"][interface]["ip"]=raw_data_nxos[hostname][1].result["interface"][interface]["ip_address"]
        
    print("vlans")
    print(core_switch_vlans)
    print("interfaces")
    print(core_switch_interfaces)
    print("end")



if __name__ == "__main__":
    vlan_hunt()