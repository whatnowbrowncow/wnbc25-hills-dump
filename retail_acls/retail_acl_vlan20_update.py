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
from datetime import datetime
import json
import pickle
import re
import time
import os
from rich.console import Console
from rich.table import Table
from tokenize import String
import difflib
from pprint import pprint
console = Console()
# Local artefacts
import retail_helper_functions as rhf
from tqdm import tqdm
import logging

#logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
#logger = logging.getLogger("netmiko")

# Variables

config_file = "/dbdev/retail_acls/config_files/retail_config.yaml"
##new acls to be applied to the devices (141 goes on sub interface x.140, 141 goes on all others)
new_acls = {
    '102':
['access-list 102 remark Allow ICMP','access-list 102 permit icmp any any','access-list 102 remark Remote Store Subnets','access-list 102 deny   ip any 10.160.0.0 0.7.255.255','access-list 102 deny   ip any 10.93.0.0 0.0.255.255','access-list 102 deny   ip any 10.94.0.0 0.0.255.255','access-list 102 deny   ip any 10.95.0.0 0.0.255.255','access-list 102 deny   ip any 10.96.0.0 0.0.255.255','access-list 102 permit ip any any'],
    '103':{'pre':
['access-list 103 remark Allow ICMP','access-list 103 permit icmp any any','access-list 103 remark Allow Local 120 Subnet'],
           'post':
['access-list 103 remark Remote Store Subnets','access-list 103 deny   ip any 10.160.0.0 0.7.255.255','access-list 103 deny   ip any 10.93.0.0 0.0.255.255','access-list 103 deny   ip any 10.94.0.0 0.0.255.255','access-list 103 deny   ip any 10.95.0.0 0.0.255.255','access-list 103 deny   ip any 10.96.0.0 0.0.255.255','access-list 103 permit ip any any']
},
    '121':{'pre':
['access-list 121 remark Allow ICMP','access-list 121 permit icmp any any','access-list 121 remark Allow Local 120 and 130 Subnets'],
           'post':
['access-list 121 remark Remote Store Subnets','access-list 121 deny   ip any 10.160.0.0 0.7.255.255','access-list 121 deny   ip any 10.93.0.0 0.0.255.255','access-list 121 deny   ip any 10.94.0.0 0.0.255.255','access-list 121 deny   ip any 10.95.0.0 0.0.255.255','access-list 121 deny   ip any 10.96.0.0 0.0.255.255','access-list 121 permit ip any any']
},
    '122':{'pre':
['access-list 122 remark Allow ICMP','access-list 122 permit icmp any any','access-list 122 remark Allow Local 1 and 130 Subnets'],
           'post':
['access-list 122 remark Remote Store Subnets','access-list 122 deny   ip any 10.160.0.0 0.7.255.255','access-list 122 deny   ip any 10.93.0.0 0.0.255.255','access-list 122 deny   ip any 10.94.0.0 0.0.255.255','access-list 122 deny   ip any 10.95.0.0 0.0.255.255','access-list 122 deny   ip any 10.96.0.0 0.0.255.255','access-list 122 permit ip any any']
},
    '123':{'pre':
['access-list 123 remark Allow ICMP','access-list 123 permit icmp any any','access-list 123 remark Allow Local 120 Subnet'],
           'post':
['access-list 123 remark Remote Store Subnets','access-list 123 deny   ip any 10.160.0.0 0.7.255.255','access-list 123 deny   ip any 10.93.0.0 0.0.255.255','access-list 123 deny   ip any 10.94.0.0 0.0.255.255','access-list 123 deny   ip any 10.95.0.0 0.0.255.255','access-list 123 deny   ip any 10.96.0.0 0.0.255.255','access-list 123 permit ip any any']
},
    '141':
['access-list 141 remark Allow ICMP','access-list 141 permit icmp any any','access-list 141 remark Store to Store Voip Calls','access-list 141 permit udp any 10.163.0.0 0.0.255.255 range 16384 32767','access-list 141 remark Remote Store Subnets','access-list 141 deny   ip any 10.160.0.0 0.7.255.255','access-list 141 deny   ip any 10.93.0.0 0.0.255.255','access-list 141 deny   ip any 10.94.0.0 0.0.255.255','access-list 141 deny   ip any 10.95.0.0 0.0.255.255','access-list 141 deny   ip any 10.96.0.0 0.0.255.255','access-list 141 permit ip any any']
}



# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ### Get list devices from inventory based on role
    nr_devices = nr.filter(role="routers")
    failed_devices = []
    
    ### Function to run various show commands on the device
    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show run | begin interface", enable=True,use_genie=True)
        task.run(task=netmiko_send_command, command_string="show interfaces", use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show version", use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show run | section access-list", enable = True, use_genie=True)
    
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



    
    #device_facts=nr_devices.run(task=gatherfacts)
    device_facts,failed_hosts=rhf.clean_facts(device_facts)
    
    #parse list of sub interfaces and acls applied
    sub_acls_parsed = rhf.get_sub_interface_acls(device_facts,1)

    #build dictionary of sub interface acls
    aclnos = {}
    for device,values in sub_acls_parsed.items():
        tempaclnos = []
        for interface,acl in values['sub_interface_acls'].items():
            if acl != 'none configured':
                tempaclnos.append(acl)
        aclnos[device]=tempaclnos
#
    ##parse interface information
    interfaces_parsed = rhf.get_interfaces(device_facts,2)

    ##from parsed interface information, parse all sub interfaces
    sub_interfaces_parsed = rhf.get_sub_interfaces(interfaces_parsed)

    ##parse version information
    versions_parsed = rhf.get_version(device_facts,3)
    
    ##parse the ACL contents   
    numbered_acls_parsed = rhf.get_numbered_acls(device_facts,aclnos,list(new_acls),4)

    ##loop through all device facts and compare the hostname on the device to the hostname listed in the inventory
    ##if values don't match then add device to a list to change the hostname
    
    ## put together a combined data dictionary of all the facts we have parsed
    combined_data = {}
    devices_with_errors = []
    for router,sub_interface_acls in sub_acls_parsed.items():
        #try:
        combined_data[router] = {}
        for sub_int,acl in sub_interface_acls['sub_interface_acls'].items():
            if sub_int in sub_interfaces_parsed[router].keys():
                combined_data[router][sub_int] = {}
                combined_data[router][sub_int]['acl'] = acl
                if acl != 'none configured':
                    #for aclno,line in acls_parsed[router][acl]['rules'].items():
                    #    temp_acl_list.append(str(aclno)+'-'+line)
                    if acl in numbered_acls_parsed[router]['sub_interface_acls'].keys():
                        combined_data[router][sub_int]['acl']={}
                        combined_data[router][sub_int]['acl'][acl]=numbered_acls_parsed[router]['sub_interface_acls'][acl]
                        combined_data[router][sub_int]['acl'][str(acl+'-acl')]=numbered_acls_parsed[router]['sub_interface_acls'][str(acl+'-acl')]
                    else:
                        #print(router+' cannot add acl '+str(acl)+ ' to combined_data\n It did not appear in numbered_acls_parsed\nDevice will be removed from final results')
                        devices_with_errors.append(router)
                        failed_hosts[router]='ACL attached to interface not found in config'
                        break
                combined_data[router][sub_int]['vlan'] = sub_interfaces_parsed[router][sub_int]['dot1q']
                combined_data[router][sub_int]['ip'] = sub_interfaces_parsed[router][sub_int]['ip']
       # except Exception as e:
            #print(router+' failed this task with the following error:\n'+str(e))
    console.print("[blue]##################\nStep 2 of 4 - Checking for hostname miss-matches\n##################")
    hostname_change_required = []
    for device,values in versions_parsed.items():
        if 'dmvpn_site' in nr_devices.inventory.hosts[device].groups:
            if values['hostname'] == nr_devices.inventory.hosts[device].data['device_hostname']:
                console.print('[green]{}: Hostname matches inventory, no change required'.format(str(device)))
            else:
                #print(device)
                console.print('[red]{}: Mismatch for device - Hostname is[/red][bold italic red] {}[/bold italic red][red] and it should be[/red][bold italic red] {}[/bold italic red][red]. Adding device to hostname update list....'.format((str(device)),str(values['hostname']),str(nr_devices.inventory.hosts[device].data['device_hostname'])))
                #print('adding device to hostname update list....')
                hostname_change_required.append(device)
    console.print("[blue]##################\nStep 3 of 4 - Checking for any device errors\n##################")
    for device in devices_with_errors:
        #print(device)
        combined_data.pop(device)
    if len(failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed and will be removed from the final results:")
        for device,reason in failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    else:
        console.print("[bold italic green]Good news! There are no failed devices")
## create output folder for run
    curfoltime = str(datetime.now().strftime('%d_%m_%Y_%H_%M_%S'))
    os.makedirs('/dbdev/retail_acls/outputs/results/'+curfoltime)

## create various output files
    filepath = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/sub_acls_parsed.json'
    with open(filepath, "w") as outfile: 
        json.dump(sub_acls_parsed, outfile)
    filepath1 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/combined_data.json'
    with open(filepath1, "w") as outfile: 
        json.dump(combined_data, outfile)
    filepath2 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/failed_hosts.json'
    with open(filepath2, "w") as outfile: 
        json.dump(failed_hosts, outfile)
    filepath3 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/numbered_acls_parsed.json'
    with open(filepath3, "w") as outfile: 
        json.dump(numbered_acls_parsed, outfile)


    config_changes={}
    config_rollback={}
    target_devices = []
    skipped_devices = []
    console.print("[italic blue]##################\nStep 4 of 4 - generating config changes for each device\n#####################")
    #console.print("[italic cyan]~~~~~~~~~~~~~Dynamic section of Access List 121 For illustrative/testing purposes~~~~~~~~~~~~~~~~~")
    for device,interfaces in combined_data.items():
        for interface,values in interfaces.items():
            if str(interface).endswith('.10') or '.402' in str(interface):
                ip10 = IPNetwork(combined_data[device][interface]['ip'])
            elif '.120' in str(interface) or '.1020' in str(interface):
                ip120 = IPNetwork(combined_data[device][interface]['ip'])
            elif '.130' in str(interface) or '.1030' in str(interface):
                ip130 = IPNetwork(combined_data[device][interface]['ip'])
                
        #add device to target list
        config_changes[device]= []
        config_rollback[device]= []
        for acl in list(new_acls):
            if str(acl) == "103":
                temp_103_acl = []
                for line in new_acls[acl]['pre']:
                    temp_103_acl.append(line)
                temp_103_acl.append('access-list 103 permit ip '+ str(ip10.network)+' '+str(ip10.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                for line in new_acls[acl]['post']:
                    temp_103_acl.append(line)
                if acl in numbered_acls_parsed[device]['new_acls'].keys():
                    if temp_103_acl == numbered_acls_parsed[device]['new_acls'][acl]:
                        continue                
                    else:
                        config_changes[device].append('no access-list '+str(acl))
                        for ace in numbered_acls_parsed[device]['new_acls'][acl]:
                            config_rollback[device].append(ace)
                        for line in new_acls[acl]['pre']:
                            config_changes[device].append(line) 
                        #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                        #console.print('| access-list 103 permit ip [italic green]{} {}[/italic green] [italic red]{} {}'.format(str(ip10.network),str(ip10.hostmask),str(ip120.network),str(ip120.hostmask)))
                        config_changes[device].append('access-list 103 permit ip '+ str(ip10.network)+' '+str(ip10.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                        for line in new_acls[acl]['post']:
                            config_changes[device].append(line)
                else:
                    for line in new_acls[acl]['pre']:
                        config_changes[device].append(line) 
                    #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                    #console.print('| access-list 103 permit ip [italic green]{} {}[/italic green] [italic red]{} {}'.format(str(ip10.network),str(ip10.hostmask),str(ip120.network),str(ip120.hostmask)))
                    config_changes[device].append('access-list 103 permit ip '+ str(ip10.network)+' '+str(ip10.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                    for line in new_acls[acl]['post']:
                        config_changes[device].append(line)

            elif str(acl) == "121":
                temp_121_acl = []
                for line in new_acls[acl]['pre']:
                    temp_121_acl.append(line)
                temp_121_acl.append('access-list 121 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip130.network)+' '+str(ip130.hostmask))
                temp_121_acl.append('access-list 121 permit ip '+ str(ip130.network)+' '+str(ip130.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                for line in new_acls[acl]['post']:
                    temp_121_acl.append(line)
                if acl in numbered_acls_parsed[device]['new_acls'].keys():
                    if temp_121_acl == numbered_acls_parsed[device]['new_acls'][acl]:
                        continue                
                    else:
                        config_changes[device].append('no access-list '+str(acl))
                        for ace in numbered_acls_parsed[device]['new_acls'][acl]:
                            config_rollback[device].append(ace)
                        for line in new_acls[acl]['pre']:
                            config_changes[device].append(line) 
                        #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                        #console.print('| access-list 121 permit ip [italic green]{} {}[/italic green] [italic red]{} {}'.format(str(ip120.network),str(ip120.hostmask),str(ip130.network),str(ip130.hostmask)))
                        #console.print('| access-list 121 permit ip [italic red]{} {}[/italic red] [italic green]{} {}'.format(str(ip130.network),str(ip130.hostmask),str(ip120.network),str(ip120.hostmask)))
                        config_changes[device].append('access-list 121 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip130.network)+' '+str(ip130.hostmask))
                        config_changes[device].append('access-list 121 permit ip '+ str(ip130.network)+' '+str(ip130.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                        for line in new_acls[acl]['post']:
                            config_changes[device].append(line)
                else:
                    for line in new_acls[acl]['pre']:
                        config_changes[device].append(line) 
                    #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                    #console.print('| access-list 121 permit ip [italic green]{} {}[/italic green] [italic red]{} {}'.format(str(ip120.network),str(ip120.hostmask),str(ip130.network),str(ip130.hostmask)))
                    #console.print('| access-list 121 permit ip [italic red]{} {}[/italic red] [italic green]{} {}'.format(str(ip130.network),str(ip130.hostmask),str(ip120.network),str(ip120.hostmask)))
                    config_changes[device].append('access-list 121 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip130.network)+' '+str(ip130.hostmask))
                    config_changes[device].append('access-list 121 permit ip '+ str(ip130.network)+' '+str(ip130.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                    for line in new_acls[acl]['post']:
                        config_changes[device].append(line)

            elif str(acl) == "122":
                temp_122_acl = []
                for line in new_acls[acl]['pre']:
                    temp_122_acl.append(line)
                temp_122_acl.append('access-list 122 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip10.network)+' '+str(ip10.hostmask))
                temp_122_acl.append('access-list 122 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip130.network)+' '+str(ip130.hostmask))
                for line in new_acls[acl]['post']:
                    temp_122_acl.append(line)
                if acl in numbered_acls_parsed[device]['new_acls'].keys():
                    if temp_122_acl == numbered_acls_parsed[device]['new_acls'][acl]:
                        continue                
                    else:
                        config_changes[device].append('no access-list '+str(acl))
                        for ace in numbered_acls_parsed[device]['new_acls'][acl]:
                            config_rollback[device].append(ace)
                        for line in new_acls[acl]['pre']:
                            config_changes[device].append(line) 
                        #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                        #console.print('| access-list 122 permit ip [italic green]{} {}[/italic green] [italic red]{} {}'.format(str(ip120.network),str(ip120.hostmask),str(ip10.network),str(ip10.hostmask)))
                        #console.print('| access-list 122 permit ip [italic red]{} {}[/italic red] [italic green]{} {}'.format(str(ip120.network),str(ip120.hostmask),str(ip130.network),str(ip130.hostmask)))
                        config_changes[device].append('access-list 122 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip10.network)+' '+str(ip10.hostmask))
                        config_changes[device].append('access-list 122 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip130.network)+' '+str(ip130.hostmask))
                        for line in new_acls[acl]['post']:
                            config_changes[device].append(line)
                else:
                    for line in new_acls[acl]['pre']:
                        config_changes[device].append(line) 
                    #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                    #console.print('| access-list 122 permit ip [italic green]{} {}[/italic green] [italic red]{} {}'.format(str(ip120.network),str(ip120.hostmask),str(ip10.network),str(ip10.hostmask)))
                    #console.print('| access-list 122 permit ip [italic red]{} {}[/italic red] [italic green]{} {}'.format(str(ip120.network),str(ip120.hostmask),str(ip130.network),str(ip130.hostmask)))
                    config_changes[device].append('access-list 122 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip10.network)+' '+str(ip10.hostmask))
                    config_changes[device].append('access-list 122 permit ip '+ str(ip120.network)+' '+str(ip120.hostmask) +' '+str(ip130.network)+' '+str(ip130.hostmask))
                    for line in new_acls[acl]['post']:
                        config_changes[device].append(line)

            elif str(acl) == "123":
                temp_123_acl = []
                for line in new_acls[acl]['pre']:
                    temp_123_acl.append(line)
                temp_123_acl.append('access-list 123 permit ip '+ str(ip130.network)+' '+str(ip130.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                for line in new_acls[acl]['post']:
                    temp_123_acl.append(line)
                if acl in numbered_acls_parsed[device]['new_acls'].keys():
                    if temp_123_acl == numbered_acls_parsed[device]['new_acls'][acl]:
                        continue                
                    else:
                        config_changes[device].append('no access-list '+str(acl))
                        for ace in numbered_acls_parsed[device]['new_acls'][acl]:
                            config_rollback[device].append(ace)
                        for line in new_acls[acl]['pre']:
                            config_changes[device].append(line) 
                        #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                        #console.print('| access-list 123 permit ip [italic red]{} {}[/italic red] [italic green]{} {}'.format(str(ip130.network),str(ip130.hostmask),str(ip120.network),str(ip120.hostmask)))
                        config_changes[device].append('access-list 123 permit ip '+ str(ip130.network)+' '+str(ip130.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                        for line in new_acls[acl]['post']:
                            config_changes[device].append(line)
                else:
                    for line in new_acls[acl]['pre']:
                        config_changes[device].append(line) 
                    #console.print('[italic blue]{}[/italic blue]'.format(str(device)))
                    #console.print('| access-list 123 permit ip [italic red]{} {}[/italic red] [italic green]{} {}'.format(str(ip130.network),str(ip130.hostmask),str(ip120.network),str(ip120.hostmask)))
                    config_changes[device].append('access-list 123 permit ip '+ str(ip130.network)+' '+str(ip130.hostmask) +' '+str(ip120.network)+' '+str(ip120.hostmask))
                    for line in new_acls[acl]['post']:
                        config_changes[device].append(line)

            else:
                if acl in numbered_acls_parsed[device]['new_acls'].keys():
                    if new_acls[acl] == numbered_acls_parsed[device]['new_acls'][acl]:
                        continue
                    else:
                        #print('device '+device+' already has ACL '+str(acl)+' applied, needs to be removed')
                        config_changes[device].append('no access-list '+str(acl))
                        for ace in numbered_acls_parsed[device]['new_acls'][acl]:
                            config_rollback[device].append(ace)
                        for line in new_acls[acl]:
                            config_changes[device].append(line)
                else:
                    for line in new_acls[acl]:
                        config_changes[device].append(line)


        #print(str('#########'+device+'########'))
        for interface,values in interfaces.items():
            if str(interface).endswith('.10') == False and '.402' not in str(interface) and '.120' not in str(interface) and '.1020' not in str(interface) and '.130' not in str(interface) and '.1030' not in str(interface) and '.140' not in str(interface) and '.1040' not in str(interface):
                if str(list(combined_data[device][interface]['acl'])[0]) != "102":
                    config_changes[device].append('interface '+interface)
                    config_changes[device].append('ip access-group 102 in')
                    if combined_data[device][interface]['acl'] == 'none configured':
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('no ip access-group 102 in')
                    else:
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('ip access-group '+str(list(combined_data[device][interface]['acl'])[0])+' in')
                #print(interface+': \ninterface '+interface+'\nip access-group 102 in\n')
            elif str(interface).endswith('.10') or '.402' in str(interface):
                if str(list(combined_data[device][interface]['acl'])[0]) != "103":
                    config_changes[device].append('interface '+interface)
                    config_changes[device].append('ip access-group 103 in')
                    if combined_data[device][interface]['acl'] == 'none configured':
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('no ip access-group 103 in')
                    else:
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('ip access-group '+str(list(combined_data[device][interface]['acl'])[0])+' in')
            elif '.120' in str(interface) or '.1020' in str(interface):
                if str(list(combined_data[device][interface]['acl'])[0]) != "122":
                    config_changes[device].append('interface '+interface)
                    config_changes[device].append('ip access-group 122 in')
                    if combined_data[device][interface]['acl'] == 'none configured':
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('no ip access-group 122 in')
                    else:
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('ip access-group '+str(list(combined_data[device][interface]['acl'])[0])+' in')  
            elif '.130' in str(interface) or '.1030' in str(interface):
                if str(list(combined_data[device][interface]['acl'])[0]) != "123":
                    config_changes[device].append('interface '+interface)
                    config_changes[device].append('ip access-group 123 in')
                    if combined_data[device][interface]['acl'] == 'none configured':
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('no ip access-group 123 in')
                    else:
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('ip access-group '+str(list(combined_data[device][interface]['acl'])[0])+' in') 
            elif '.140' in str(interface) or '.1040' in str(interface):
                if str(list(combined_data[device][interface]['acl'])[0]) != "141":
                    config_changes[device].append('interface '+interface)
                    config_changes[device].append('ip access-group 141 in')
                    if combined_data[device][interface]['acl'] == 'none configured':
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('no ip access-group 141 in')
                    else:
                        config_rollback[device].append('interface '+interface)
                        config_rollback[device].append('ip access-group '+str(list(combined_data[device][interface]['acl'])[0])+' in') 
        if len(config_changes[device]) > 0:
            target_devices.append(device)
    #####################do some config###############################
   
            if not os.path.exists('/dbdev/retail_acls/outputs/site_configs/'+device):
                os.makedirs('/dbdev/retail_acls/outputs/site_configs/'+device)
            if not os.path.exists('/dbdev/retail_acls/outputs/site_configs/'+device+'/archive'):
                os.makedirs('/dbdev/retail_acls/outputs/site_configs/'+device+'/archive')
    
    ################### WRITE DICT TO JSON #####################
    
            filepath = '/dbdev/retail_acls/outputs/site_configs/'+device+'/config_changes_latest.txt'
            with open(filepath, "w") as outfile: 
                outfile.write('\n'.join(config_changes[device]))
            filepath = '/dbdev/retail_acls/outputs/site_configs/'+device+'/config_rollback_latest.txt'
            with open(filepath, "w") as outfile: 
                outfile.write('\n'.join(config_rollback[device]))
    
    
    ########### GET TIME ########
    
            curtime = str(datetime.now().strftime('%H_%M_%S_%d_%m_%Y'))
    
    ########### ADD DATA TO LOGS ##################
    
            logfilename = 'config_changes_' + curtime + '.txt'
            filepath = '/dbdev/retail_acls/outputs/site_configs/'+device+'/archive/'+logfilename
            with open(filepath, "w") as outfile: 
                outfile.write('\n'.join(config_changes[device]))
            logfilename = 'config_rollback_' + curtime + '.txt'
            filepath = '/dbdev/retail_acls/outputs/site_configs/'+device+'/archive/'+logfilename
            with open(filepath, "w") as outfile: 
                outfile.write('\n'.join(config_changes[device]))

        else:
            skipped_devices.append(device)

    filepath4 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/config_changes.json'
    with open(filepath4, "w") as outfile: 
        json.dump(config_changes, outfile)
    filepath5 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/config_rollback.json'
    with open(filepath5, "w") as outfile: 
        json.dump(config_rollback, outfile)


    #exit()
    



    lab_devices = nr.filter(role="routers")
    cfg_failed_devices = []
    skip_devices = ['uk-brs-lab-cr02']
    standard_devices = ['uk-brs-lab-cr01']
    cfg_devices = lab_devices.filter(F(name__any=target_devices))
    hostname_devices = lab_devices.filter(F(name__any=hostname_change_required))
    


    #def update_acl_config(task:Task) -> Result:
    #    task.run(task=netmiko_send_config, config_commands=new_acls['102'])
    #    task.run(task=netmiko_send_config, config_commands=new_acls['141'])
    #    task.run(task=netmiko_save_config)

    def update_acl_config(task:Task) -> Result:
        task.run(task=netmiko_send_config, config_commands=config_changes[str(task.host)])
        task.run(task=netmiko_save_config)
    
    def update_hostname(task:Task) -> Result:
        task.run(task=netmiko_send_config, config_commands='hostname '+str(hostname_devices.inventory.hosts[str(task.host)].data['device_hostname']))
    #    
    def save_config_after_hostname_change(task:Task) -> Result:    
        task.run(task=netmiko_save_config)
#
    update_acls=cfg_devices.run(task=update_acl_config)
    #clean config results
    update_acls_clean,update_acls_failed_hosts = rhf.clean_facts(update_acls)
    filepath10 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/failed_config_hosts.json'
    with open(filepath10, "w") as outfile: 
        json.dump(update_acls_failed_hosts, outfile)


    #print('####################testing function#####################')
    processed_results,full_processed_results = rhf.process_update_acls_results(update_acls_clean)
    #print('#########################################')
    
    filepath7 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/processed_results.json'
    with open(filepath7, "w") as outfile: 
        json.dump(processed_results, outfile)
    #save it
    with open(f'/dbdev/retail_acls/outputs/results/'+curfoltime+'/full_processed_results.pickle', 'wb') as file:
        pickle.dump(full_processed_results, file)
    #load it
    #with open(f'/dbdev/retail_acls/full_processed_results.pickle', 'rb') as file2:
    #    full_results = pickle.load(file2)
#
    #console.print("[cyan]++++++++++++++++++++++++ Making any changes required ++++++++++++++++++++++++")
    #console.print("[blue]ACL update result summary.....")
    #console.print("[blue]--------")
    #for device, results in full_results.items():
    #    print(device)
    #    print("netmiko_send_config:" + full_results[device]["netmiko_send_config"]["result"])
    #    print("netmiko_save_config:" + full_results[device]["netmiko_save_config"]["result"])
    #    print("------")
    #console.print("[blue]Logs.....")
    #console.print("[blue]--------")
    #for device, results in full_results.items():
    #    print(device)
    #    print("netmiko_send_config:\n" + full_results[device]["netmiko_send_config"]["log"])
    #    print("netmiko_save_config:\n" + full_results[device]["netmiko_save_config"]["log"])
    #    print("------")
    #console.print("[blue]Tables.....")
    #console.print("[blue]--------")
    #for device, results in full_results.items():
    #    print(device)
    #    console.print(full_results[device]["table"])
    #    console.print("[blue]------")
    
    #print(type(newtable))
    #console.print(newtable)
    #filepath7 = '/dbdev/retail_acls/outputs/update_acls_results.txt'
    #with open(filepath7, "w") as outfile:
    #    outfile.write(rhf.log_update_acls_results(update_acls)) 
        #json.dump(update_acls, outfile)

    #print_result(update_acls)

    update_device_hostname=hostname_devices.run(task=update_hostname)
    update_hostname_clean,update_hostname_failed_hosts = rhf.clean_facts(update_device_hostname)
    filepath10 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/failed_update_hostname.json'
    with open(filepath10, "w") as outfile: 
        json.dump(update_hostname_failed_hosts, outfile)
    processed_hostname_results,full_processed_hostname_results = rhf.process_update_acls_results(update_hostname_clean)
    nr = InitNornir(config_file=config_file)
    lab_devices = nr.filter(role="routers")
    hostname_devices = lab_devices.filter(F(name__any=hostname_change_required))
    save_config=hostname_devices.run(task=save_config_after_hostname_change)



    #print(config_changes)
    console.print('[bold blue]################ SUMMARY OF CHANGES MADE #################')
    console.print("Total devices targeted: [blue]{}".format(len(nr_devices.inventory.hosts)))
    console.print("Data gathering from hosts: [green]Success:{} [/green]/[red] Failed:{}".format(len(list(combined_data)),len(list(failed_hosts))))
    console.print("[dark_goldenrod]    -please see ./failed_hosts.json for more information on failed hosts")
    console.print("Total devices skipped (no config change required): [yellow]{}".format(len(list(skipped_devices))))
    console.print("Total devices requiring config change: [blue]{}".format(len(list(target_devices))))
    console.print("Total devices requiring hostname change: [blue]{}".format(len(list(hostname_change_required))))
    console.print("Total devices changed succesfully: [green]Success:{} [/green]/[red] Failed:{}".format(len(list(update_acls_clean)),len(list(update_acls_failed_hosts))))
    console.print("[dark_goldenrod]    -please see ./failed_config_hosts.json for more information on failed configuration hosts")



    
    print('#########################################')

    console.print("[blue]Results per device:")

    for device in nr_devices.inventory.hosts:
        if device in list(update_acls_failed_hosts):
            console.print("{}:[red]FAILED - Device failed at configuration stage".format(device))
        elif device in list(skipped_devices) and device not in list(update_hostname_clean):
            console.print("{}:[green]SUCCESS[/green] - [yellow]Successfully gathered data but no changes were required".format(device))
        elif device in list(update_acls_clean) and device in list(update_hostname_clean):
            console.print("{}:[green]SUCCESS - Changes succesfully applied and hostname changed".format(device))
        elif device in list(update_acls_clean):
            console.print("{}:[green]SUCCESS - Changes succesfully applied".format(device))
        elif device in list(update_hostname_clean):
            console.print("{}:[green]SUCCESS - Hostname succesfully changed,[/green][yellow] no other changes required".format(device))
        elif device in list(update_acls_failed_hosts):
            console.print("{}:[red]FAILED - Successfully gathered data but configuration change failed".format(device))
        elif device in list(failed_hosts):
            console.print("{}:[red]FAILED - Failed to complete data gathering stage".format(device))     

    
    filepath8 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/processed_hostname_results.json'
    with open(filepath8, "w") as outfile: 
        json.dump(processed_hostname_results, outfile)
    #save it
    with open(f'/dbdev/retail_acls/outputs/results/'+curfoltime+'/full_processed_hostname_results.pickle', 'wb') as file:
        pickle.dump(full_processed_hostname_results, file)
    #load it
    #with open(f'/dbdev/retail_acls/full_processed_hostname_results.pickle', 'rb') as file2:
    #    full_hostname_results = pickle.load(file2)
#
    #console.print("[blue]\nHostname changes result summary.....")
    #console.print("[blue]--------")
    #for device, results in full_hostname_results.items():
    #    print(device)
    #    print("netmiko_send_config:" + full_hostname_results[device]["netmiko_send_config"]["result"])
    #    print("------")
    #console.print("[blue]Logs.....")
    #console.print("[blue]--------")
    #for device, results in full_hostname_results.items():
    #    print(device)
    #    print("netmiko_send_config:\n" + full_hostname_results[device]["netmiko_send_config"]["log"])
    #    console.print("[blue]------")
    #console.print("[blue]Tables.....")
    #console.print("[blue]--------")
    #for device, results in full_hostname_results.items():
    #    print(device)
    #    console.print(full_hostname_results[device]["table"])
    #    console.print("[blue]------")
#
    processed_hostname_save_results,full_processed_hostname_save_results = rhf.process_update_acls_results(save_config)
    #console.print('[blue]\n#########################################\n')
    
    filepath9 = '/dbdev/retail_acls/outputs/results/'+curfoltime+'/processed_hostname_save_results.json'
    with open(filepath9, "w") as outfile: 
        json.dump(processed_hostname_save_results, outfile)
    #save it
    with open(f'/dbdev/retail_acls/outputs/results/'+curfoltime+'/full_processed_hostname_save_results.pickle', 'wb') as file:
        pickle.dump(full_processed_hostname_save_results, file)
    #load it
    #with open(f'/dbdev/retail_acls/full_processed_hostname_save_results.pickle', 'rb') as file2:
    #    full_hostname_save_results = pickle.load(file2)
#
    #console.print("[blue]Post hostname change save config result summary.....")
    #console.print("[blue]--------")
    #for device, results in full_hostname_save_results.items():
    #    print(device)
    #    print("netmiko_save_config:" + full_hostname_save_results[device]["netmiko_save_config"]["result"])
    #    console.print("[blue]------")
    #console.print("[blue]Logs.....")
    #console.print("[blue]--------")
    #for device, results in full_hostname_save_results.items():
    #    print(device)
    #    print("netmiko_save_config:\n" + full_hostname_save_results[device]["netmiko_save_config"]["log"])
    #    console.print("[blue]------")
    #console.print("[blue]Tables.....")
    #console.print("[blue]--------")
    #for device, results in full_hostname_save_results.items():
    #    print(device)
    #    console.print(full_hostname_save_results[device]["table"])
    #    console.print("[blue]------")
    ##rhf.rich_table(update_acls)
    ##print(config_rollback)
    exit()