#! /usr/bin/env python
# Modules
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_netmiko.tasks import netmiko_send_command
from nornir.core.filter import F
from graphviz import Graph
import re
import json
from rich.console import Console
from rich.table import Table
console = Console()
# Local artefacts
import oob_helper_functions as ohf

# Variables
config_files = {'dmvpn'  :"./config_files/dmvpn_config.yaml",
                 'oob'  :"./config_files/oob_config.yaml"}

config_file = config_files['dmvpn']
#graph variables
dot = Graph(comment='DMVPN Map', format='png', node_attr={'color': 'deepskyblue1', 'style': 'filled'})
path_output = './oob_inventory/topology/autogen.gv'


# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    failed_devices = []

    #r2 = nr_devices.run(task=send_configs, configs=["no username test6969","\r"])
    print("Checking dmvpn connectivity") 
    print('DMVPN.............................')
    dmvpn = nr_devices.run(task=netmiko_send_command, command_string="show dmvpn", use_genie=True, use_timing=True)
    for device,details in dmvpn.items():
        if details[0].failed == True:
            failed_devices.append(device)
    #print_result(dmvpn)
    tunnels = nr_devices.run(task=netmiko_send_command, command_string="show ip interface brief | inc Tunnel", use_genie=True, use_timing=True)
    interfaces = ohf.get_tunnel_interfaces(tunnels)
    parsed_dmvpn = ohf.dmvpn_per_tunnel(dmvpn)

    for host in nr.inventory.hosts:
        if nr.inventory.hosts[host]['role']=='hubs':
            dot.attr('node', color='coral')
            dot.node(host)
        elif nr.inventory.hosts[host]['role']=='spokes':
            dot.attr('node', color='deepskyblue')
            dot.node(host)
    
    for host in nr.inventory.hosts:
        dmvpntable = ohf.build_dmvpntable(host)
        if nr.inventory.hosts[host]['role']=='hubs':
            #print(host)
            #print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            for k,v in parsed_dmvpn[host]['Tunnels'].items():
                dmvpntable.add_row('[bold blue]Tunnel:{}'.format(k),'','','','',)
                for a,b in v.items():
                    intfound = False
                    spokematch = False
                    for device,interf in interfaces.items():
                        #for tunnels,data in interf.items():
                            for ip,tunnel in interf.items():
                                if str(b['tunnel IP']) == str(ip):
                                    spoke_name = str(device)
                                    intfound = True
                                    dot.attr('edge', color='green3')
                                    dot.edge(host, device)
                                    for spoke_tunnel,IP in parsed_dmvpn[device]['Tunnels'].items():
                                        for pub_IP,spoke_data in IP.items():
                                            if spoke_data['tunnel IP'] in interfaces[host].keys():
                                                spokematch = True
                    if intfound == True and spokematch == True:
                        dmvpntable.add_row(spoke_name,str(b['tunnel IP']),'[green]{}'.format(str(b['state'])),str(b['UP/DOWN time']),'[green]Connection verified on Spoke')
                    elif intfound == True and spokematch == False:
                        dmvpntable.add_row(spoke_name,str(b['tunnel IP']),'[green]{}'.format(str(b['state'])),str(b['UP/DOWN time']),'[red]No corresponding spoke connection found')
                    else:
                        spoke_name = '''[red]Peer not found in spoke list'''
                        dmvpntable.add_row(spoke_name,str(b['tunnel IP']),'[green]{}'.format(str(b['state'])),str(b['UP/DOWN time']),'''don't know right now''')
                dmvpntable.add_row(end_section=True)
            console.print(dmvpntable)
            console.print('[red]Failed to execute commands on the following devices:')
            for device in failed_devices:
                console.print('[bold red]- {}'.format(device))
                
    
            

    with open(path_output, 'w') as file:
        file.write(dot.source)
    try:
        dot.render(path_output, view=True)
    except:
        exit()
    exit()
    