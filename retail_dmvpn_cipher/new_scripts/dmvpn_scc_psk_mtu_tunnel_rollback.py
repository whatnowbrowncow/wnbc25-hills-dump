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
import time
console = Console()
# Local artefacts
import retail_helper_functions as rhf

# Variables
config_file = "/dbdev/retail_dmvpn_cipher/config_files/retail_dmvpn.yaml"
scc_tunnel_interface = 'Tunnel11'
scc_tunnel_ip = '10.92.26.1'
scc_public_ip = '141.138.128.105'
ld6_tunnel_interface = 'Tunnel12'
ld6_tunnel_ip = '10.92.27.1'
ld6_public_ip = '185.119.152.46'
new_psk = '69nnw55v2r7d4whmwh3u2bc6q5kfbr'
old_mtu = '1400'
policy = {'number':'2',
           'data':{
           'encryption':'aes 256',
           'hash':'sha',
           'group':'5',
           'authentication':'pre-share'}}
retail_transform_set = {'name':'tset-retail-dmvpn',
           'data':{
           'set':'esp-aes 256 esp-sha-hmac',
           'mode':'transport'}}
old_profile = {'name':'dmvpn',
           'data':{
           'lifetime':'28800',
           'transform set':'3deswan',
           'pfs':'group2'}}

dmvpnmtupretable = Table(title='DMVPN SCC Tunnel 11 + MTU Pre change Summary',show_header=True, header_style="bold blue")
dmvpnmtupretable.add_column('Device',justify='center')
dmvpnmtupretable.add_column('Tunnel 11 UP',justify='center')
dmvpnmtupretable.add_column('EIGRP  neighbour 10.92.26.1',justify='center')
dmvpnmtupretable.add_column('Profile being used',justify='center')
dmvpnmtupretable.add_column('PSK being used',justify='center')
dmvpnmtupretable.add_column('MTU old/new',justify='center')
dmvpnmtupretable.add_column('Update required',justify='center')

dmvpnmtuposttable = Table(title='DMVPN SCC Tunnel 11 + MTU Post change Summary',show_header=True, header_style="bold blue")
dmvpnmtuposttable.add_column('Device',justify='center')
dmvpnmtuposttable.add_column('Tunnel 11 UP',justify='center')
dmvpnmtuposttable.add_column('EIGRP  neighbour 10.92.26.1',justify='center')
dmvpnmtuposttable.add_column('Profile being used',justify='center')
dmvpnmtuposttable.add_column('PSK being used',justify='center')
dmvpnmtuposttable.add_column('MTU old/new',justify='center')
dmvpnmtuposttable.add_column('Update required',justify='center')

dmvpnmturesultstable = Table(title='DMVPN SCC Tunnel 11 + MTU change results Summary',show_header=True, header_style="bold blue")
dmvpnmturesultstable.add_column('Device',justify='center')
dmvpnmturesultstable.add_column('Tunnel 11 UP pre/post',justify='center')
dmvpnmturesultstable.add_column('EIGRP nbr 10.92.26.1 up pre/post',justify='center')
dmvpnmturesultstable.add_column('Profile pre/post',justify='center')
dmvpnmturesultstable.add_column('PSK pre/post',justify='center')
dmvpnmturesultstable.add_column('MTU pre/post',justify='center')

dmvpnposttable = Table(title='DMVPN Tunnel State Post Changes',show_header=True, header_style="bold blue")
dmvpnposttable.add_column('Device',justify='center')
dmvpnposttable.add_column('Tunnel 11 state match',justify='center')
dmvpnposttable.add_column('Tu11 EIGRP  neighbour match',justify='center')
dmvpnposttable.add_column('Tunnel 11 state match',justify='center')
dmvpnposttable.add_column('Tu11 EIGRP  neighbour match',justify='center')

# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    nr_spokes = nr.filter(role="spokes")

    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show run all | section crypto", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show run | section crypto", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show run | section interface Tunnel", use_genie=False, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show ip eigrp neighbors", use_genie=True, use_timing=False)
        task.run(task=netmiko_send_command, command_string="show dmvpn", use_genie=False, use_timing=False)
    
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
    crypto_config = rhf.parse_crypto(device_facts,1,2)
    spoke_tunnels_parsed = rhf.get_tunnel_interface_data(device_facts,3)
    eigrp_neighbours = rhf.spoke_eigrp_neighbours(device_facts,4)
    dmvpn = rhf.dmpvn_per_tunnel(device_facts,5)
    filepath = '/dbdev/retail_dmvpn_cipher/crypto_config.json'
    with open(filepath, "w") as outfile: 
        json.dump(crypto_config, outfile)
    

    devices_to_skip = []
    devices_to_configure = []
    devices_configured = []
    #Confirm devices require update
    check_results={}


    combined_data = {}  
    combined_data['tunnel 11 pre-change']={}

    for device, data in device_facts.items():
        try:
            combined_data['tunnel 11 pre-change'][device]={}
            combined_data['tunnel 11 pre-change'][device]['psk'] = crypto_config[device]['keys'][scc_public_ip]
            combined_data['tunnel 11 pre-change'][device]['mtu'] = spoke_tunnels_parsed[device]['Tunnel11']['mtu']
            combined_data['tunnel 11 pre-change'][device]['profile'] = spoke_tunnels_parsed[device]['Tunnel11']['profile']
            combined_data['tunnel 11 pre-change'][device]['tunnel state'] = dmvpn[device]['Tunnels']['11'][scc_public_ip]['state']
            if str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP']) in eigrp_neighbours[device]['neighbours'].keys():
                combined_data['tunnel 11 pre-change'][device]['tunnel 11 nbr'] = str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP'])
            else:
                #console.print('[bold blue]{}[/bold blue] has not been added device update list, error processing data:\n [red]EIGRP neighbour not found'.format(device))
                combined_data['tunnel 11 pre-change'][device]['tunnel 11 nbr'] = '[red]not found[/red]'
                #combined_data['tunnel 11 pre-change'].pop(device)
                #continue
        
        except Exception as e:
            console.print('[bold blue]{}[/bold blue] has not been added to combined data, error processing data:\n [red]{}'.format(device,str(e)))
            combined_data['tunnel 11 pre-change'].pop(device)


    for device, data in combined_data['tunnel 11 pre-change'].items():
        update_required = False
        if combined_data['tunnel 11 pre-change'][device]['tunnel state'] == 'UP':
            combined_data['tunnel 11 pre-change'][device]['tu11state'] = '[green]\u2713[/green]'
            tu11state = '[green]\u2713[/green]'
        else:
            combined_data['tunnel 11 pre-change'][device]['tu11state'] = '[red]\u2717[/red]'
            tu11state = '[red]\u2717[/red]'
        if combined_data['tunnel 11 pre-change'][device]['psk'] == new_psk:
            combined_data['tunnel 11 pre-change'][device]['psk_match'] = '[red]\u2717 New PSK[/red]'
            psk_match = '[red]\u2717 New PSK[/red]'
            update_required = True
        else:
            combined_data['tunnel 11 pre-change'][device]['psk_match'] = '[green]\u2713 old PSK[/green]'
            psk_match = '[green]\u2713 old PSK[/green]'
        if combined_data['tunnel 11 pre-change'][device]['mtu'] == old_mtu:
            combined_data['tunnel 11 pre-change'][device]['mtu_match'] = '[green]\u2713 Old MTU[/green]'
            mtu_match = '[green]\u2713 Old MTU[/green]'
        else:
            combined_data['tunnel 11 pre-change'][device]['mtu_match'] = '[red]\u2717 New MTU[/red]'
            mtu_match = '[red]\u2717 New MTU[/red]'
            update_required = True
        if combined_data['tunnel 11 pre-change'][device]['tunnel 11 nbr'] == scc_tunnel_ip:
            eigrp_neighbour = '[green]\u2713[/green]'
            combined_data['tunnel 11 pre-change'][device]['tunnel 11 nbr match'] = '[green]\u2713[/green]'
        else:
            eigrp_neighbour = '[red]\u2717[/red]'
            combined_data['tunnel 11 pre-change'][device]['tunnel 11 nbr match'] = '[red]\u2717[/red]'
        if combined_data['tunnel 11 pre-change'][device]['profile'] == old_profile['name']:
            combined_data['tunnel 11 pre-change'][device]['profile_match'] = '[green]\u2713 Old profile[/green]'
            profile_match = '[green]\u2713 Old profile[/green]'
        else:
            combined_data['tunnel 11 pre-change'][device]['profile_match'] = '[red]\u2717 New profile[/red]'
            profile_match = '[red]\u2717 New profile[/red]'
            update_required = True
        if update_required == True:
            combined_data['tunnel 11 pre-change'][device]['update'] = '[yellow]\u2713[/yellow]'
            update = '[yellow]\u2713[/yellow]'
            devices_to_configure.append(device)
        elif update_required == False:
            combined_data['tunnel 11 pre-change'][device]['update'] = '[yellow]\u2717[/yellow]'
            update = '[yellow]\u2717[/yellow]'
            devices_configured.append(device)
        dmvpnmtupretable.add_row(device,tu11state,eigrp_neighbour,profile_match,psk_match,mtu_match,update)
    console.print(dmvpnmtupretable)
    console.print('''Key: Configured correctly - [green]\u2713[/green]
     Update required - [yellow]\u2713[/yellow]
     Not configured - [yellow]\u271B[/yellow]
     Update not required - [yellow]\u2717[/yellow]
     Configured incorrectly / Update not possible - [red]\u2717''')
    #exit()       

    #console.print('\n[red]Failed hosts:')
    #if len(failed_hosts.items()) > 0:
    #    console.print("[bold italic red]The following devices have failed and will be removed from the final results:")
    #    for device,reason in failed_hosts.items():
    #        console.print('[red]{}[/red][bold red]:{}'.format(device,reason))

    #for device,result in check_results.items():
    #    print(device+':'+':'.join(result))
    with open('/dbdev/retail_dmvpn_cipher/psk_mtu_tunnel_rollback_scc.txt') as f:
        mtu_config = f.read().splitlines()

    config_changes = {}
    ## create output folder for run
    curfoltime = str(datetime.now().strftime('%d_%m_%Y_%H_%M_%S'))
    os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime)
    for device in devices_to_configure:
        config_changes[device]=mtu_config

    #####################do some config###############################
   
        if not os.path.exists('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device):
            os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device)
        if not os.path.exists('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive'):
            os.makedirs('/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive')

    ################### WRITE DICT TO JSON #####################
    
        filepath = '/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/mtu_config_changes_latest.txt'
        with open(filepath, "w") as outfile: 
            outfile.write('\n'.join(config_changes[device]))
    
    ########### GET TIME ########
    
        curtime = str(datetime.now().strftime('%H_%M_%S_%d_%m_%Y'))
    
    ########### ADD DATA TO LOGS ##################
    
        logfilename = 'mtu_config_changes_' + curtime + '.txt'
        filepath = '/dbdev/retail_dmvpn_cipher/outputs/site_configs/'+device+'/archive/'+logfilename
        with open(filepath, "w") as outfile: 
            outfile.write('\n'.join(config_changes[device]))



    filepath4 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/mtu_config_changes.json'
    with open(filepath4, "w") as outfile: 
        json.dump(config_changes, outfile)

    filepath5 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/crypto_config.json'
    with open(filepath5, "w") as outfile: 
        json.dump(crypto_config, outfile)





    #exit()
    cfg_devices = nr_spokes.filter(F(name__any=devices_to_configure))
    def update_cypher_config(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_config, config_commands=config_changes[str(task.host)])
        task.run(task=netmiko_save_config)
        netmiko_bar.update()

    console.print("[blue]##################\nStep 2 of 4 - Making changes ({} devices), this may take a while\n##################".format(len(nr_spokes.inventory.hosts)))
    with tqdm(
        total=len(cfg_devices.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            mtu_update=cfg_devices.run(
                task=update_cypher_config,
                netmiko_bar=netmiko_bar,
                
            )


    #mtu_update=cfg_devices.run(task=update_cypher_config)
    #clean config results
    mtu_update_clean,cipher_update_failed_hosts = rhf.clean_facts(mtu_update)

    


    #print('####################testing function#####################')
    processed_results,full_processed_results = rhf.process_update_results(mtu_update_clean)
    #print('#########################################')
    
    filepath7 = '/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/processed_results.json'
    with open(filepath7, "w") as outfile: 
        json.dump(processed_results, outfile)
    #save it
    with open(f'/dbdev/retail_dmvpn_cipher/outputs/results/'+curfoltime+'/full_processed_results.pickle', 'wb') as file:
        pickle.dump(full_processed_results, file)

    time.sleep(15)
    
    console.print("[blue]##################\nStep 3 of 4 - Gathering device facts after change ({} devices), this may take a while\n##################".format(len(nr_spokes.inventory.hosts)))
    with tqdm(
        total=len(nr_spokes.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            device_facts=nr_spokes.run(
                task=gatherfacts,
                netmiko_bar=netmiko_bar,
                
            )


    device_facts,failed_hosts=rhf.clean_facts(device_facts)
    crypto_config = rhf.parse_crypto(device_facts,1,2)
    spoke_tunnels_parsed = rhf.get_tunnel_interface_data(device_facts,3)
    eigrp_neighbours = rhf.spoke_eigrp_neighbours(device_facts,4)
    dmvpn = rhf.dmpvn_per_tunnel(device_facts,5)
    filepath = '/dbdev/retail_dmvpn_cipher/crypto_config.json'
    with open(filepath, "w") as outfile: 
        json.dump(crypto_config, outfile)
    

    devices_to_skip = []
    devices_to_configure = []
    devices_configured = []
    #Confirm devices require update
    check_results={}



    combined_data['tunnel 12 post-change']={}
    combined_data['tunnel 11 post-change']={}

    for device, data in device_facts.items():
        try:
            combined_data['tunnel 12 post-change'][device]={}
            combined_data['tunnel 12 post-change'][device]['psk'] = crypto_config[device]['keys'][ld6_public_ip]
            combined_data['tunnel 12 post-change'][device]['mtu'] = spoke_tunnels_parsed[device]['Tunnel12']['mtu']
            combined_data['tunnel 12 post-change'][device]['profile'] = spoke_tunnels_parsed[device]['Tunnel12']['profile']
            combined_data['tunnel 12 post-change'][device]['tunnel 12 state'] = dmvpn[device]['Tunnels']['12'][ld6_public_ip]['state']
            
            
            if str(dmvpn[device]['Tunnels']['12'][ld6_public_ip]['tunnel IP']) in eigrp_neighbours[device]['neighbours'].keys():
                combined_data['tunnel 12 post-change'][device]['tunnel 12 nbr'] = str(dmvpn[device]['Tunnels']['12'][ld6_public_ip]['tunnel IP'])
            else:
                combined_data['tunnel 12 post-change'][device]['tunnel 12 nbr'] = '[red]not found[/red]'
        
        except Exception as e:
            console.print('[bold blue]{}[/bold blue] has not been added to combined data, error processing data:\n [red]{}'.format(device,str(e)))
            combined_data['tunnel 12 post-change'].pop(device)

        try:
            combined_data['tunnel 11 post-change'][device]={}
            combined_data['tunnel 11 post-change'][device]['psk'] = crypto_config[device]['keys'][scc_public_ip]
            combined_data['tunnel 11 post-change'][device]['mtu'] = spoke_tunnels_parsed[device]['Tunnel11']['mtu']
            combined_data['tunnel 11 post-change'][device]['profile'] = spoke_tunnels_parsed[device]['Tunnel11']['profile']
            combined_data['tunnel 11 post-change'][device]['tunnel 11 state'] = dmvpn[device]['Tunnels']['11'][scc_public_ip]['state']
            
            
            if str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP']) in eigrp_neighbours[device]['neighbours'].keys():
                combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr'] = str(dmvpn[device]['Tunnels']['11'][scc_public_ip]['tunnel IP'])
            else:
                combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr'] = '[red]not found[/red]'
        
        except Exception as e:
            console.print('[bold blue]{}[/bold blue] has not been added to combined data, error processing data:\n [red]{}'.format(device,str(e)))
            combined_data['tunnel 11 post-change'].pop(device)


    for device, data in combined_data['tunnel 11 post-change'].items():
        update_required = False
        if combined_data['tunnel 11 post-change'][device]['tunnel 11 state'] == 'UP':
            combined_data['tunnel 11 post-change'][device]['tu11state'] = '[green]\u2713[/green]'
            tu11state = '[green]\u2713[/green]'
        else:
            combined_data['tunnel 11 post-change'][device]['tu11state'] = '[red]\u2717[/red]'
            tu11state = '[red]\u2717[/red]'
        if combined_data['tunnel 11 post-change'][device]['psk'] == new_psk:
            combined_data['tunnel 11 post-change'][device]['psk_match'] = '[red]\u2717 New PSK[/red]'
            psk_match = '[red]\u2717 New PSK[/red]'
            update_required = True
        else:
            combined_data['tunnel 11 post-change'][device]['psk_match'] = '[green]\u2713 old PSK[/green]'
            psk_match = '[green]\u2713 old PSK[/green]'

        if combined_data['tunnel 11 post-change'][device]['mtu'] == old_mtu:
            combined_data['tunnel 11 post-change'][device]['mtu_match'] = '[green]\u2713 Old MTU[/green]'
            mtu_match = '[green]\u2713 Old MTU[/green]'
        else:
            combined_data['tunnel 11 post-change'][device]['mtu_match'] = '[red]\u2717 New MTU[/red]'
            mtu_match = '[red]\u2717 New MTU[/red]'
            update_required = True
        if combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr'] == scc_tunnel_ip:
            eigrp_neighbour = '[green]\u2713[/green]'
            combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr match'] = '[green]\u2713[/green]'
        else:
            eigrp_neighbour = '[red]\u2717[/red]'
            combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr match'] = '[red]\u2717[/red]'
        if combined_data['tunnel 11 post-change'][device]['profile'] == old_profile['name']:
            combined_data['tunnel 11 post-change'][device]['profile_match'] = '[green]\u2713 Old profile[/green]'
            profile_match = '[green]\u2713 Old profile[/green]'
        else:
            combined_data['tunnel 11 post-change'][device]['profile_match'] = '[red]\u2717 New profile[/red]'
            profile_match = '[red]\u2717 New profile[/red]'
            update_required = True
        if update_required == True:
            combined_data['tunnel 11 post-change'][device]['update'] = '[yellow]\u2713[/yellow]'
            update = '[yellow]\u2713[/yellow]'
            devices_to_configure.append(device)
        elif update_required == False:
            combined_data['tunnel 11 post-change'][device]['update'] = '[yellow]\u2717[/yellow]'
            update = '[yellow]\u2717[/yellow]'
            devices_configured.append(device)
        dmvpnmtuposttable.add_row(device,tu11state,eigrp_neighbour,profile_match,psk_match,mtu_match,update)
    console.print(dmvpnmtuposttable)
    console.print('''Key: Configured correctly - [green]\u2713[/green]
     Update required - [yellow]\u2713[/yellow]
     Not configured - [yellow]\u271B[/yellow]
     Update not required - [yellow]\u2717[/yellow]
     Configured incorrectly / Update not possible - [red]\u2717''')
    
    
    console.print("[blue]##################\nStep 4 of 4 - Comparing data pre and post change, please wait\n##################")
    
    
    for device, data in combined_data['tunnel 11 post-change'].items():
        dmvpnmturesultstable.add_row(device,str(combined_data['tunnel 11 pre-change'][device]['tu11state'])+'[yellow]     |     [/yellow]'+str(combined_data['tunnel 11 post-change'][device]['tu11state']),str(combined_data['tunnel 11 pre-change'][device]['tunnel 11 nbr match'])+'[yellow]     |     [/yellow]'+str(combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr match']),str(combined_data['tunnel 11 pre-change'][device]['profile_match'])+'[yellow]  |  [/yellow]'+str(combined_data['tunnel 11 post-change'][device]['profile_match']),str(combined_data['tunnel 11 pre-change'][device]['psk_match'])+'[yellow]  |  [/yellow]'+str(combined_data['tunnel 11 post-change'][device]['psk_match']),str(combined_data['tunnel 11 pre-change'][device]['mtu_match'])+'[yellow]  |  [/yellow]'+str(combined_data['tunnel 11 post-change'][device]['mtu_match']))
    console.print(dmvpnmturesultstable)


    console.print("[blue]##################\nStep 5 of 5 - Comparing end state with state pre change, please wait\n##################")
    
    #with open(f'/dbdev/retail_dmvpn_cipher/outputs/golden_tunnel_state/pre_change_tunnel_state.pickle', 'wb') as file:
    #    dmvpntable = pickle.load(file)
    with open('/dbdev/retail_dmvpn_cipher/outputs/golden_tunnel_state/pre_change_tunnel_state.json') as file1:
        device_tunnels = json.load(file1)

    for device,data in device_tunnels.items():
        match = True
        if device in combined_data['tunnel 11 post-change'].keys() and device in combined_data['tunnel 12 post-change'].keys():
            if device_tunnels[device]['tunnel 11 state'] == combined_data['tunnel 11 post-change'][device]['tunnel 11 state']:
                tu11state = '[green]\u2713[/green]'
                tu11statedetail = ''
            else:
                tu11state = '[red]\u2717[/red]'
                tu11statedetail = '[red]{}[/red] | [red]{}[/red]'.format(device_tunnels[device]['tunnel 11 state'],combined_data['tunnel 11 post-change'][device]['tunnel 11 state'])
                match = False
            if device_tunnels[device]['tunnel 11 nbr'] == combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr']:
                tu11nbr = '[green]{}[/green]'.format(str(device_tunnels[device]['tunnel 11 nbr']))
                tu11nbrdetail = ''
            else:
                tu11nbr = '[red]{}[/red]'.format(str(device_tunnels[device]['tunnel 11 nbr']))
                tu11nbrdetail = '[red]{}[/red] | [red]{}[/red]'.format(device_tunnels[device]['tunnel 11 nbr'],combined_data['tunnel 11 post-change'][device]['tunnel 11 nbr'])
                
                match = False
            if device_tunnels[device]['tunnel 12 state'] == combined_data['tunnel 12 post-change'][device]['tunnel 12 state']:
                tu12state = '[green]\u2713[/green]'
                tu12statedetail = ''
            else:
                tu12state = '[red]\u2717[/red]'
                tu12statedetail = '[red]{}[/red] | [red]{}[/red]'.format(device_tunnels[device]['tunnel 12 state'],combined_data['tunnel 12 post-change'][device]['tunnel 12 state'])
                match = False
            if device_tunnels[device]['tunnel 12 nbr'] == combined_data['tunnel 12 post-change'][device]['tunnel 12 nbr']:
                tu12nbr = '[green]{}[/green]'.format(str(device_tunnels[device]['tunnel 12 nbr']))
                tu12nbrdetail = ''
            else:
                tu12nbr = '[red]{}[/red]'.format(str(device_tunnels[device]['tunnel 12 nbr']))
                tu12nbrdetail = '[red]{}[/red] | [red]{}[/red]'.format(device_tunnels[device]['tunnel 12 nbr'],combined_data['tunnel 12 post-change'][device]['tunnel 12 nbr'])
                match = False
            if match == False:
                dmvpnposttable.add_row(device,tu11state,tu11nbr,tu12state,tu12nbr)
                dmvpnposttable.add_row('',tu11statedetail,tu11nbrdetail,tu12statedetail,tu12nbrdetail,end_section=True)
            else:
                dmvpnposttable.add_row(device,tu11state,tu11nbr,tu12state,tu12nbr,end_section=True)
        #else:
        #    dmvpnposttable.add_row('[red]{}[/red]'.format(device),'[red]NOT[/red]','[red]FOUND[/red]','[red]IN[/red]','[red]RESULTS[/red]')
    console.print(dmvpnposttable)






    