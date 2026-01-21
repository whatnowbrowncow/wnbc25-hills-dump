#! /usr/bin/env python
# Modules
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_netmiko.tasks import netmiko_send_command
from nornir.core.filter import F
from nornir.core.task import Task, Result
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
import retail_helper_functions as rhf

# Variables
config_files = {'retail':"./config_files/retail_dmvpn_config.yaml",
                 'oob'  :"./config_files/oob_dmvpn_config.yaml"}

config_file = "./config_files/retail_config.yaml"

new_acls = {
    '102':'''access-list 102 remark Allow ICMP
access-list 102 permit icmp any any
access-list 102 remark Remote Store Subnets
access-list 102 deny   ip any 10.160.0.0 0.7.255.255
access-list 102 deny   ip any 10.93.0.0 0.0.255.255
access-list 102 deny   ip any 10.94.0.0 0.0.255.255
access-list 102 deny   ip any 10.95.0.0 0.0.255.255
access-list 102 deny   ip any 10.96.0.0 0.0.255.255
access-list 102 permit ip any any
''',
    '141':'''access-list 141 remark Allow ICMP
access-list 141 permit icmp any any
access-list 141 remark Store to Store Voip Calls
access-list 141 permit udp any 10.163.0.0 0.0.255.255 range 16384 32767
access-list 141 remark Remote Store Subnets
access-list 141 deny   ip any 10.160.0.0 0.7.255.255
access-list 141 deny   ip any 10.93.0.0 0.0.255.255
access-list 141 deny   ip any 10.94.0.0 0.0.255.255
access-list 141 deny   ip any 10.95.0.0 0.0.255.255
access-list 141 deny   ip any 10.96.0.0 0.0.255.255
access-list 141 permit ip any any
'''}

golden_config = {
    'sub_interfaces':['10','140','180'],
    'acls':{
        '101':{
        'vlans':['1','10'],
        'acl':'''access-list 101 remark Local Store Subnet
access-list 101 permit ip 10.94.247.96 0.0.0.31 10.94.247.96 0.0.0.31
access-list 101 remark Remote Store Subnets
access-list 101 deny   ip any 10.93.0.0 0.0.255.255
access-list 101 deny   ip any 10.94.0.0 0.0.255.255
access-list 101 deny   ip any 10.95.0.0 0.0.255.255
access-list 101 permit ip any any
'''},
        '140':{
        'vlans':['140'],
        'acl':'''access-list 140 permit udp any host 10.112.208.11 eq bootps
access-list 140 permit udp any host 10.120.193.235 eq bootps
access-list 140 permit udp any host 10.112.208.11 eq bootpc
access-list 140 permit udp any host 10.120.193.235 eq bootpc
access-list 140 permit udp any host 255.255.255.255 eq bootps
access-list 140 permit udp any host 255.255.255.255 eq bootpc
access-list 140 permit udp any host 10.112.208.11 eq domain
access-list 140 permit udp any host 10.112.208.12 eq domain
access-list 140 permit udp any host 10.120.193.235 eq domain
access-list 140 permit udp any host 10.120.193.236 eq domain
access-list 140 permit tcp any host 10.112.208.11 eq domain
access-list 140 permit tcp any host 10.112.208.12 eq domain
access-list 140 permit tcp any host 10.120.193.235 eq domain
access-list 140 permit tcp any host 10.120.193.236 eq domain
access-list 140 permit udp any host 10.120.194.70 eq tftp
access-list 140 permit udp any host 10.120.194.71 eq tftp
access-list 140 permit udp any host 10.210.194.71 eq tftp
access-list 140 permit tcp any host 10.120.194.70 eq 2443
access-list 140 permit tcp any host 10.120.194.71 eq 2443
access-list 140 permit tcp any host 10.210.194.71 eq 2443
access-list 140 permit tcp any host 10.120.194.70 eq 2445
access-list 140 permit tcp any host 10.120.194.71 eq 2445
access-list 140 permit tcp any host 10.210.194.71 eq 2445
access-list 140 permit tcp any host 10.120.194.70 eq 3804
access-list 140 permit tcp any host 10.120.194.71 eq 3804
access-list 140 permit tcp any host 10.210.194.71 eq 3804
access-list 140 permit tcp any host 10.120.194.70 eq 5060
access-list 140 permit tcp any host 10.120.194.71 eq 5060
access-list 140 permit tcp any host 10.210.194.71 eq 5060
access-list 140 permit tcp any host 10.120.194.70 eq 5061
access-list 140 permit tcp any host 10.120.194.71 eq 5061
access-list 140 permit tcp any host 10.210.194.71 eq 5061
access-list 140 permit udp any host 10.120.194.70 eq 5061
access-list 140 permit udp any host 10.120.194.71 eq 5061
access-list 140 permit udp any host 10.210.194.71 eq 5061
access-list 140 permit tcp any host 10.120.194.70 eq 6970
access-list 140 permit tcp any host 10.120.194.71 eq 6970
access-list 140 permit tcp any host 10.210.194.71 eq 6970
access-list 140 permit tcp any host 10.120.194.70 eq 8080
access-list 140 permit tcp any host 10.120.194.71 eq 8080
access-list 140 permit tcp any host 10.210.194.71 eq 8080
access-list 140 permit udp any host 10.120.194.70 range 16384 32767
access-list 140 permit udp any host 10.120.194.71 range 16384 32767
access-list 140 permit udp any host 10.210.194.71 range 16384 32767
access-list 140 permit tcp any host 10.120.194.70 eq 2000
access-list 140 permit tcp any host 10.120.194.71 eq 2000
access-list 140 permit tcp any host 10.210.194.71 eq 2000
access-list 140 permit udp any any range 16384 32767
access-list 140 permit tcp any any eq 5060
access-list 140 permit icmp any 10.120.194.64 0.0.0.63
access-list 140 permit tcp any eq 443 10.120.194.64 0.0.0.63
access-list 140 permit udp any host 10.19.2.140 eq tftp
access-list 140 permit tcp any host 10.19.2.140 eq 2443
access-list 140 permit tcp any host 10.19.2.140 eq 2445
access-list 140 permit tcp any host 10.19.2.140 eq 3804
access-list 140 permit tcp any host 10.19.2.140 eq 5060
access-list 140 permit tcp any host 10.19.2.140 eq 5061
access-list 140 permit udp any host 10.19.2.140 eq 5061
access-list 140 permit tcp any host 10.19.2.140 eq 6970
access-list 140 permit tcp any host 10.19.2.140 eq 8080
access-list 140 permit udp any host 10.19.2.140 range 16384 32767
access-list 140 permit tcp any host 10.19.2.140 eq 2000
access-list 140 permit udp any host 10.19.2.141 eq tftp
access-list 140 permit tcp any host 10.19.2.141 eq 2443
access-list 140 permit tcp any host 10.19.2.141 eq 2445
access-list 140 permit tcp any host 10.19.2.141 eq 3804
access-list 140 permit tcp any host 10.19.2.141 eq 5060
access-list 140 permit tcp any host 10.19.2.141 eq 5061
access-list 140 permit udp any host 10.19.2.141 eq 5061
access-list 140 permit tcp any host 10.19.2.141 eq 6970
access-list 140 permit tcp any host 10.19.2.141 eq 8080
access-list 140 permit udp any host 10.19.2.141 range 16384 32767
access-list 140 permit tcp any host 10.19.2.141 eq 2000
access-list 140 permit icmp any 192.168.0.0 0.0.15.255
access-list 140 permit icmp any 192.168.48.0 0.0.15.255
access-list 140 permit tcp any eq 443 192.168.0.0 0.0.15.255
access-list 140 permit tcp any eq 443 192.168.48.0 0.0.15.255
'''},
        '141':{
        'vlans':['140'],
        'acl':'''access-list 141 remark Allow ICMP
access-list 141 permit icmp any any
access-list 141 remark Store to Store Voip Calls
access-list 141 permit udp any 10.163.0.0 0.0.255.255 range 16384 32767
access-list 141 remark Remote Store Subnets
access-list 141 deny   ip any 10.160.0.0 0.7.255.255
access-list 141 deny   ip any 10.93.0.0 0.0.255.255
access-list 141 deny   ip any 10.94.0.0 0.0.255.255
access-list 141 deny   ip any 10.95.0.0 0.0.255.255
access-list 141 deny   ip any 10.96.0.0 0.0.255.255
access-list 141 permit ip any any
'''},
        '180':{
        'vlans':['180'],
        'acl':'''access-list 180 remark Guest WiFi ACL
access-list 180 permit udp any host 10.112.208.11 eq bootps
access-list 180 permit udp any host 10.120.193.235 eq bootps
access-list 180 permit udp any host 10.112.208.11 eq bootpc
access-list 180 permit udp any host 10.120.193.235 eq bootpc
access-list 180 permit udp any 10.167.0.0 0.0.255.255 eq bootps
access-list 180 permit udp any 10.167.0.0 0.0.255.255 eq bootpc
access-list 180 permit udp any host 255.255.255.255 eq bootps
access-list 180 permit udp any host 255.255.255.255 eq bootpc
access-list 180 permit udp any host 10.112.208.11 eq domain
access-list 180 permit udp any host 10.112.208.12 eq domain
access-list 180 permit udp any host 10.120.193.235 eq domain
access-list 180 permit udp any host 10.120.193.236 eq domain
access-list 180 permit tcp any host 10.112.208.11 eq domain
access-list 180 permit tcp any host 10.112.208.12 eq domain
access-list 180 permit tcp any host 10.120.193.235 eq domain
access-list 180 permit tcp any host 10.120.193.236 eq domain
access-list 180 permit udp any 109.144.192.128 0.0.0.63 eq 5246
access-list 180 permit udp any 109.144.192.128 0.0.0.63 eq 5247
access-list 180 permit udp any 217.39.0.128 0.0.0.63 eq 5246
access-list 180 permit udp any 217.39.0.128 0.0.0.63 eq 5247
'''}
}}

# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    nr_devices = nr.filter(role="routers")
    failed_devices = []
    
    def gatherfacts(task:Task) -> Result:
        task.run(task=netmiko_send_command, command_string="show run | section include interface", enable=True,use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show interfaces", use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show version", use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show run | section access-list", enable = True, use_genie=True, use_timing=True)

    device_facts=nr_devices.run(task=gatherfacts)
    device_facts,failed_hosts=rhf.clean_facts(device_facts)
    #validate results

    sub_acls_parsed = rhf.get_sub_interface_acls(device_facts,1)
    #print(sub_acls_parsed)
    #build dictionary of sub interface acls
    aclnos = {}
    for device,data in sub_acls_parsed.items():
        tempaclnos = []
        for interface,acl in data['sub_interface_acls'].items():
            if acl != 'none configured':
                tempaclnos.append(acl)
        aclnos[device]=tempaclnos

    #aclnos = [101,140,180]
    interfaces_parsed = rhf.get_interfaces(device_facts,2)
    #print(interfaces_parsed)
    sub_interfaces_parsed = rhf.get_sub_interfaces(interfaces_parsed)
    #print(sub_interfaces_parsed)
    versions_parsed = rhf.get_version(device_facts,3)
    #print(versions_parsed)
    
    numbered_acls_parsed = rhf.get_numbered_acls(device_facts,aclnos,4)
    #print(numbered_acls_parsed)
    
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
                        print(router+' cannot add acl '+str(acl)+ ' to combined_data\n It did not appear in numbered_acls_parsed\nDevice will be removed from final results')
                        devices_with_errors.append(router)
                        failed_hosts[router]='ACL attached to interface not found in config'
                        break
                combined_data[router][sub_int]['vlan'] = sub_interfaces_parsed[router][sub_int]['dot1q']
                combined_data[router][sub_int]['ip'] = sub_interfaces_parsed[router][sub_int]['ip']
       # except Exception as e:
            #print(router+' failed this task with the following error:\n'+str(e))
    print('The following devices will be removed from the final results:')
    for device in devices_with_errors:
        print(device)
        combined_data.pop(device)


    filepath = './sub_acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(sub_acls_parsed, outfile)
        filepath = './sub_acls.json'
    filepath1 = './combined_data.json'
    with open(filepath1, "w") as outfile: 
        json.dump(combined_data, outfile)
    filepath2 = './failed_hosts.json'
    with open(filepath2, "w") as outfile: 
        json.dump(failed_hosts, outfile)

    print('running comparisons')

    for device,data in combined_data.items():
        print('################################################################################################')
        print('checking '+str(device)+'...........')
        for acl in golden_config['acls'].keys():
            #print('looking for ACL '+str(acl)+'.......')
            for interface in data.keys():
                if data[interface]['acl'] != 'none configured' and acl in data[interface]['acl'].keys() and data[interface]['vlan'] in golden_config['acls'][acl]['vlans']:
                    #print('acl match found for '+str(acl)+'. checking ACL config')
                    ###temp try
                    #try:
                    if data[interface]['acl'][str(acl+'-acl')] == golden_config['acls'][acl]['acl']:
                        print('ACL ' + str(acl)+'++++++++++++ MATCH')
                    else:
                        print('ACL ' + str(acl)+'------------ FAIL')
                        d = difflib.Differ()
                        diff = list(d.compare(golden_config['acls'][acl]['acl'].splitlines(),data[interface]['acl'][str(acl+'-acl')].splitlines()))
                        #pprint(diff)
                    #except Exception as e:
                        #print(e)
                #else:
                #    print(str(acl)+' not found on this device')
    print('Processing unique ACLs')
    unique_acls={}
    for acl in golden_config['acls'].keys():
        device_count = 0
        unique_acls[acl]={}
        unique_acls[acl]['not found on']=[]
        numberfound = 0
        for device,data in combined_data.items():
            acl_found = False
            for interface in data.keys():
                if data[interface]['acl'] != 'none configured' and acl in data[interface]['acl'].keys() and data[interface]['vlan'] in golden_config['acls'][acl]['vlans']:
                    device_count = device_count +1
                    acl_found = True
                    #try:
                    for item in unique_acls[acl]:
                        if item != 'not found on':
                            device_acl = data[interface]['acl'][str(acl+'-acl')].splitlines()
                            unique_acl = unique_acls[acl][item]['rules'].splitlines()
                            if set(device_acl)==set(unique_acl):
                                unique_acls[acl][item]['devices'].append(device)
                                break
                    else:
                            
                        #if rules not in unique_acls_list:
                        unique_acls[acl][str(numberfound+1)] = {}
                        unique_acls[acl][str(numberfound+1)]['rules'] = data[interface]['acl'][str(acl+'-acl')]
                        unique_acls[acl][str(numberfound+1)]['devices'] = []
                        unique_acls[acl][str(numberfound+1)]['devices'].append(device)
                        numberfound = numberfound + 1
                    #except:
                        #print('failed for '+str(device))
            if acl_found == False:
                #print('couldnt find '+ str(acl) + ' on '+str(device))
                unique_acls[acl]['not found on'].append(device)
        unique_acls[acl]['device_count'] = device_count



    unique_acls1 = {}
    for acl in unique_acls:
        aclname = str(acl)+' ['+str(unique_acls[acl]['device_count'])+' device(s)]'
        unique_acls1[aclname]={}
        for group in unique_acls[acl]:
            if group != 'device_count' and group != 'not found on':
                group_name = 'group '+str(group)+' ['+str(len(unique_acls[acl][group]['devices']))+' device(s)]' 
                unique_acls1[aclname][group_name] = {}
                unique_acls1[aclname][group_name]['devices'] = unique_acls[acl][group]['devices']
                unique_acls1[aclname][group_name]['rules'] = unique_acls[acl][group]['rules']
        not_found_name = 'not found on ['+str(len(unique_acls[acl]['not found on']))+' device(s)]'
        unique_acls1[aclname][not_found_name] = unique_acls[acl]['not found on']
    unique_acls = unique_acls1
    
    
        
    
        #print(a)
    
    
    filepath = './unique_retail_acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(unique_acls, outfile)
    
    
    #####################do some config###############################
    
    
    
    exit()

    


    print("Checking interfaces") 
    interfaces = nr_devices.run(task=netmiko_send_command, command_string="show interfaces", use_genie=True, use_timing=True)
    for device,details in interfaces.items():
        if details[0].failed == True:
            failed_devices.append(device)
    #print_result(dmvpn)
    #tunnels = nr_devices.run(task=netmiko_send_command, command_string="show ip interface brief | inc Tunnel", use_genie=True, use_timing=True)
    interfaces_parsed = rhf.get_interfaces(interfaces)
    print(interfaces_parsed)



    combined_data = {}
    for router,sub_interface_acls in sub_acls_parsed.items():
        combined_data[router] = {}
        for sub_int,acl in sub_interface_acls['sub_interface_acls'].items():
            if sub_int in sub_interfaces_parsed[router].keys():
                combined_data[router][sub_int] = {}
                combined_data[router][sub_int]['acl'] = acl
                combined_data[router][sub_int]['vlan'] = sub_interfaces_parsed[router][sub_int]['dot1q']
                combined_data[router][sub_int]['ip'] = sub_interfaces_parsed[router][sub_int]['ip']


    filepath = './sub_acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(sub_acls_parsed, outfile)
        filepath = './sub_acls.json'
    filepath1 = './combined_data.json'
    with open(filepath1, "w") as outfile: 
        json.dump(combined_data, outfile)
        

    #print("Checking interfaces") 
    #interfaces = nr_devices.run(task=netmiko_send_command, command_string="show interfaces", use_genie=True, use_timing=True)
    #for device,details in interfaces.items():
    #    if details[0].failed == True:
    #        failed_devices.append(device)
    ##print_result(dmvpn)
    ##tunnels = nr_devices.run(task=netmiko_send_command, command_string="show ip interface brief | inc Tunnel", use_genie=True, use_timing=True)
    #interfaces_parsed = rhf.get_interfaces(interfaces)
    #print(interfaces_parsed)
#
    #sub_interfaces_parsed = rhf.get_sub_interfaces(interfaces_parsed)
    #print(sub_interfaces_parsed)



    #for host in nr.inventory.hosts:
    #    if nr.inventory.hosts[host]['role']=='hubs':
    #        dot.attr('node', color='coral')
    #        dot.node(host)
    #    elif nr.inventory.hosts[host]['role']=='spokes':
    #        dot.attr('node', color='deepskyblue')
    #        dot.node(host)
    #
    #for host in nr.inventory.hosts:
    #    dmvpntable = rhf.build_dmvpntable(host)
    #    if nr.inventory.hosts[host]['role']=='hubs':
    #        #print(host)
    #        #print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    #        for k,v in parsed_dmvpn[host]['Tunnels'].items():
    #            dmvpntable.add_row('[bold blue]Tunnel:{}'.format(k),'','','','',)
    #            for a,b in v.items():
    #                intfound = False
    #                spokematch = False
    #                for device,interf in interfaces.items():
    #                    #for tunnels,data in interf.items():
    #                        for ip,tunnel in interf.items():
    #                            if str(b['tunnel IP']) == str(ip):
    #                                spoke_name = str(device)
    #                                intfound = True
    #                                dot.attr('edge', color='green3')
    #                                dot.edge(host, device)
    #                                for spoke_tunnel,IP in parsed_dmvpn[device]['Tunnels'].items():
    #                                    for pub_IP,spoke_data in IP.items():
    #                                        if spoke_data['tunnel IP'] in interfaces[host].keys():
    #                                            spokematch = True
    #                if intfound == True and spokematch == True:
    #                    dmvpntable.add_row(spoke_name,str(b['tunnel IP']),'[green]{}'.format(str(b['state'])),str(b['UP/DOWN time']),'[green]Connection verified on Spoke')
    #                elif intfound == True and spokematch == False:
    #                    dmvpntable.add_row(spoke_name,str(b['tunnel IP']),'[green]{}'.format(str(b['state'])),str(b['UP/DOWN time']),'[red]No corresponding spoke connection found')
    #                else:
    #                    spoke_name = '''[red]Peer not found in spoke list'''
    #                    dmvpntable.add_row(spoke_name,str(b['tunnel IP']),'[green]{}'.format(str(b['state'])),str(b['UP/DOWN time']),'''don't know right now''')
    #            dmvpntable.add_row(end_section=True)
    #        console.print(dmvpntable)
    #        console.print('[red]Failed to execute commands on the following devices:')
    #        for device in failed_devices:
    #            console.print('[bold red]- {}'.format(device))
    #        
#
    #with open(path_output, 'w') as file:
    #    file.write(dot.source)
    #try:
    #    dot.render(path_output, view=True)
    #except:
    #    exit()
    #exit()
    