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
scc_tunnel_interface = 'Tunnel11'
scc_public_ip = '141.138.128.105'
ld6_tunnel_interface = 'Tunnel11'
ld6_public_ip = '185.119.152.46'
new_psk = '69nnw55v2r7d4whmwh3u2bc6q5kfbr'
policy = {'number':'2',
           'data':{
           'encryption':'aes 256',
           'hash':'sha',
           'group':'5',
           'authentication':'pre-share'}}
retail_transform_set = {'name':'tset-retail-dmvpn',
           'data':{
           'set':'esp-aes esp-sha-hmac',
           'mode':'transport'}}
profile = {'name':'pfl-retail-dmvpn',
           'data':{
           'lifetime':'28800',
           'transform set':'tset-retail-dmvpn',
           'pfs':'None'}}

dmvpnciphertable = Table(title='DMVPN Cipher Check Summary',show_header=True, header_style="bold blue")
dmvpnciphertable.add_column('Device',justify='center')
dmvpnciphertable.add_column('Policy',justify='center')
dmvpnciphertable.add_column('Transform-set',justify='center')
dmvpnciphertable.add_column('Profile',justify='center')
dmvpnciphertable.add_column('Update required',justify='center')
# Body
if __name__ == "__main__":
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
        task.run(task=netmiko_send_command, command_string="show run all | section crypto", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show run | section crypto", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show run | section interface Tunnel", use_genie=False, use_timing=False)
    
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

    crypto_config = rhf.parse_crypto(device_facts,1,2)
    spoke_tunnels_parsed = rhf.get_tunnel_interface_data(device_facts,3)
    filepath = '/dbdev/retail_dmvpn_cipher/crypto_config.json'
    with open(filepath, "w") as outfile: 
        json.dump(crypto_config, outfile)
    

    devices_to_skip = []
    devices_to_configure = []
    devices_configured = []
    #Confirm devices require update
    check_results={}
    for device, data in crypto_config.items():
        if policy['number'] not in data['policies'].keys() and retail_transform_set['name'] not in data['tf_sets'].keys() and profile['name'] not in data['profiles'].keys():
            dmvpnciphertable.add_row(device,'[yellow]\u271B','[yellow]\u271B','[yellow]\u271B','[yellow]\u2713')
            check_results[device]=['Check passed','none of the elements present, config required']
            devices_to_configure.append(device)
        else:
            config_match = True
            config_apply = False
            check_results[device]=['Check failed']
            if policy['number'] in data['policies'].keys():
                if policy['data']==data['policies'][policy['number']]:
                    rich_policy = '[green]\u2713'
                    check_results[device].append('policy elements match')
                    
                else:
                    rich_policy = '[red]\u2717'
                    config_match = False
                    check_results[device].append('''policy elements don't match''')
            else:
                rich_policy = '[yellow]\u271B'
                config_apply = True
                check_results[device].append('policy elements not present')
            if retail_transform_set['name'] in data['tf_sets'].keys():
                tf1 = retail_transform_set['data']
                tf2 = data['tf_sets'][retail_transform_set['name']]
                if retail_transform_set['data'] == data['tf_sets'][retail_transform_set['name']]:
                    rich_tfs = '[green]\u2713'
                    check_results[device].append('tf-set elements match')
                else:

                    for hostname,data1 in spoke_tunnels_parsed.items():
                        if device == hostname:
                            rich_tfs = '[yellow]\u2713'
                            config_apply = True
                            tfs_check ='''Tset elements don't match but bound profile is not in use'''
                            for tunnel,values in data1.items():
                                if spoke_tunnels_parsed[hostname][tunnel]['profile'] == profile['name']:
                                    rich_tfs = '[red]\u2717'
                                    config_match = False
                                    tfs_check = '''Tset elements don't match and bound profile is in use'''
                                    break
                            check_results[device].append(tfs_check)



                    #rich_tfs = '[red]\u2717'
                    #config_match = False
                    #check_results[device].append('''tf-set elements don't match''')
            else:
                rich_tfs = '[yellow]\u271B'
                config_apply = True
                check_results[device].append('tf-set elements not present')
            if profile['name'] in data['profiles'].keys():
                prof1 = profile['data']
                prof2 = data['profiles'][profile['name']]
                if profile['data'] == data['profiles'][profile['name']]:
                    rich_profile = '[green]\u2713'
                    check_results[device].append('profile elements match')
                else:
                    for hostname,data1 in spoke_tunnels_parsed.items():
                        if device == hostname:
                            rich_profile = '[yellow]\u2713'
                            config_apply = True
                            profile_check ='''profile elements don't match but profile is not in use'''
                            for tunnel,values in data1.items():
                                if spoke_tunnels_parsed[hostname][tunnel]['profile'] == profile['name']:
                                    rich_profile = '[red]\u2717'
                                    config_match = False
                                    profile_check = '''profile elements don't match and profile is in use'''
                                    break
                            check_results[device].append(profile_check)

            else:
                rich_profile = '[yellow]\u271B'
                config_apply = True
                check_results[device].append('profile elements not present')
            if config_match == True and config_apply == False:
                check_results[device][0]='Check passed'
                dmvpnciphertable.add_row(device,rich_policy,rich_tfs,rich_profile,'[yellow]\u2717')
                devices_configured.append(device)
            elif config_match == True and config_apply == True:
                check_results[device][0]='Check passed'
                dmvpnciphertable.add_row(device,rich_policy,rich_tfs,rich_profile,'[yellow]\u2713')
                devices_to_configure.append(device)
            else:
                check_results[device][0]='Check failed'
                dmvpnciphertable.add_row(device,rich_policy,rich_tfs,rich_profile,'[red]\u2717')
                devices_to_skip.append(device)
    console.print(dmvpnciphertable)
    console.print('''Key: Configured correctly - [green]\u2713[/green]
     Update required - [yellow]\u2713[/yellow]
     Not configured - [yellow]\u271B[/yellow]
     Update not required - [yellow]\u2717[/yellow]
     Configured incorrectly / Update not possible - [red]\u2717''')
    console.print('\n[red]Failed hosts:')
    if len(failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed and will be removed from the final results:")
        for device,reason in failed_hosts.items():
            if 'missing a result' not in reason:
                console.print('[red]{}[/red][bold red]:{}'.format(device,reason))

    #for device,result in check_results.items():
    #    print(device+':'+':'.join(result))
    with open('/dbdev/retail_dmvpn_cipher/cipher_config.txt') as f:
        cipher_config = f.read().splitlines()

    config_changes = {}
    ## create output folder for run
    curfoltime = str(datetime.now().strftime('%d_%m_%Y_%H_%M_%S'))
    os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime)
    for device in devices_to_configure:
        config_changes[device]=cipher_config

    #####################do some config###############################
   
        if not os.path.exists('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device):
            os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device)
        if not os.path.exists('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive'):
            os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive')

    ################### WRITE DICT TO JSON #####################
    
        filepath = '/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/config_changes_latest.txt'
        with open(filepath, "w") as outfile: 
            outfile.write('\n'.join(config_changes[device]))
    
    ########### GET TIME ########
    
        curtime = str(datetime.now().strftime('%H_%M_%S_%d_%m_%Y'))
    
    ########### ADD DATA TO LOGS ##################
    
        logfilename = 'config_changes_' + curtime + '.txt'
        filepath = '/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive/'+logfilename
        with open(filepath, "w") as outfile: 
            outfile.write('\n'.join(config_changes[device]))



    filepath4 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/config_changes.json'
    with open(filepath4, "w") as outfile: 
        json.dump(config_changes, outfile)

    filepath5 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/crypto_config.json'
    with open(filepath5, "w") as outfile: 
        json.dump(crypto_config, outfile)  