#! /usr/bin/env python
# Modules
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_netmiko.tasks import netmiko_send_command
from nornir_netmiko.tasks import netmiko_send_config
from nornir_netmiko.tasks import netmiko_save_config
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

config_file = "./config_files/lab_config.yaml"
##new acls to be applied to the devices (141 goes on sub interface x.140, 141 goes on all others)
new_acls = {
    '102':
['access-list 102 remark Allow ICMP','access-list 102 permit icmp any any','access-list 102 remark Remote Store Subnets','access-list 102 deny   ip any 10.160.0.0 0.7.255.255','access-list 102 deny   ip any 10.93.0.0 0.0.255.255','access-list 102 deny   ip any 10.94.0.0 0.0.255.255','access-list 102 deny   ip any 10.95.0.0 0.0.255.255','access-list 102 deny   ip any 10.96.0.0 0.0.255.255','access-list 102 permit ip any any'],
    '141':
['access-list 141 remark Allow ICMP','access-list 141 permit icmp any any','access-list 141 remark Store to Store Voip Calls','access-list 141 permit udp any 10.163.0.0 0.0.255.255 range 16384 32767','access-list 141 remark Remote Store Subnets','access-list 141 deny   ip any 10.160.0.0 0.7.255.255','access-list 141 deny   ip any 10.93.0.0 0.0.255.255','access-list 141 deny   ip any 10.94.0.0 0.0.255.255','access-list 141 deny   ip any 10.95.0.0 0.0.255.255','access-list 141 deny   ip any 10.96.0.0 0.0.255.255','access-list 141 permit ip any any']
}

##current ACL config to be compared against for each device during the facts gathering phase
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
   
    ### Get list devices from inventory based on role
    nr_devices = nr.filter(role="lab_routers")
    failed_devices = []
    
    ### Function to run various show commands on the device
    def gatherfacts(task:Task) -> Result:
        task.run(task=netmiko_send_command, command_string="show run | begin interface", enable=True,use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show interfaces", use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show version", use_genie=True, use_timing=True)
        task.run(task=netmiko_send_command, command_string="show run | section access-list", enable = True, use_genie=True, use_timing=True)
    
    ### Calling the above function against a set of devices
    device_facts=nr_devices.run(task=gatherfacts)
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
    
    ##loop through all device facts and compare the hostname on the device to the hostname listed in the inventory
    ##if values don't match then add device to a list to change the hostname
    print('Skip Checking hostnames')
    #hostname_change_required = []
    #for device,values in versions_parsed.items():
    #    if 'dmvpn_site' in nr_devices.inventory.hosts[device].groups:
    #        if values['hostname'] == nr_devices.inventory.hosts[device].data['device_hostname']:
    #            print(str(device) + ' hostname matches inventory, no change required')
    #        else:
    #            print(device)
    #            print('mismatch for device: '+str(device)+'. Hostname is '+str(values['hostname'])+' and it should be '+ str(nr_devices.inventory.hosts[device].data['device_hostname']))
    #            print('adding device to hostname update list....')
    #            hostname_change_required.append(device)

    ##parse the ACL contents   
    numbered_acls_parsed = rhf.get_numbered_acls(device_facts,aclnos,list(new_acls),4)
    
    
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
#
## create various output files
    filepath = './lab_sub_acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(sub_acls_parsed, outfile)
        filepath = './sub_acls.json'
    filepath1 = './lbo_combined_data.json'
    with open(filepath1, "w") as outfile: 
        json.dump(combined_data, outfile)
    filepath2 = './lbo_failed_hosts.json'
    with open(filepath2, "w") as outfile: 
        json.dump(failed_hosts, outfile)
    filepath3 = './lbo_numbered_acls.json'
    with open(filepath3, "w") as outfile: 
        json.dump(numbered_acls_parsed, outfile)

## compare the ACLs configured on the devices to the 'golden config'
    print('running comparisons')
#
    for device,values in combined_data.items():
        print('################################################################################################')
        print('checking '+str(device)+'...........')
        for acl in golden_config['acls'].keys():
            #print('looking for ACL '+str(acl)+'.......')
            for interface in values.keys():
                if values[interface]['acl'] != 'none configured' and acl in values[interface]['acl'].keys() and values[interface]['vlan'] in golden_config['acls'][acl]['vlans']:
                    #print('acl match found for '+str(acl)+'. checking ACL config')
                    ###temp try
                    #try:
                    if values[interface]['acl'][str(acl+'-acl')] == golden_config['acls'][acl]['acl']:
                        print('ACL ' + str(acl)+'++++++++++++ MATCH')
                    else:
                        print('ACL ' + str(acl)+'------------ FAIL')
                        d = difflib.Differ()
                        diff = list(d.compare(golden_config['acls'][acl]['acl'].splitlines(),values[interface]['acl'][str(acl+'-acl')].splitlines()))
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
        for device,values in combined_data.items():
            acl_found = False
            for interface in values.keys():
                if values[interface]['acl'] != 'none configured' and acl in values[interface]['acl'].keys() and values[interface]['vlan'] in golden_config['acls'][acl]['vlans']:
                    device_count = device_count +1
                    acl_found = True
                    #try:
                    for item in unique_acls[acl]:
                        if item != 'not found on':
                            device_acl = values[interface]['acl'][str(acl+'-acl')].splitlines()
                            unique_acl = unique_acls[acl][item]['rules'].splitlines()
                            if set(device_acl)==set(unique_acl):
                                unique_acls[acl][item]['devices'].append(device)
                                break
                    else:
                            
                        #if rules not in unique_acls_list:
                        unique_acls[acl][str(numberfound+1)] = {}
                        unique_acls[acl][str(numberfound+1)]['rules'] = values[interface]['acl'][str(acl+'-acl')]
                        unique_acls[acl][str(numberfound+1)]['devices'] = []
                        unique_acls[acl][str(numberfound+1)]['devices'].append(device)
                        numberfound = numberfound + 1
                    #except:
                        #print('failed for '+str(device))
            if acl_found == False:
                #print('couldnt find '+ str(acl) + ' on '+str(device))
                unique_acls[acl]['not found on'].append(device)
        unique_acls[acl]['device_count'] = device_count
#
#
#
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
    
    
    filepath = './lab_unique_retail_acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(unique_acls, outfile)

    config_changes={}
    config_rollback={}
    target_devices = []
    print('generating config changes for each device......')
    for device,interfaces in combined_data.items():
        #add device to target list
        target_devices.append(device)
        config_changes[device]= []
        config_rollback[device]= []
        for acl in list(new_acls):
            if acl in numbered_acls_parsed[device]['new_acls'].keys():
                #print('device '+device+' already has ACL '+str(acl)+' applied, needs to be removed')
                config_changes[device].append('no access-list '+str(acl))
                for ace in numbered_acls_parsed[device]['new_acls'][acl]:
                    config_rollback[device].append(ace)
            for line in new_acls[acl]:
                config_changes[device].append(line)
        print(str('#########'+device+'########'))
        for interface,values in interfaces.items():
            if '.140' not in str(interface):
                config_changes[device].append('interface '+interface)
                config_changes[device].append('ip access-group 102 in')
                if combined_data[device][interface]['acl'] == 'none configured':
                    config_rollback[device].append('interface '+interface)
                    config_rollback[device].append('no ip access-group 102 in')
                else:
                    config_rollback[device].append('interface '+interface)
                    config_rollback[device].append('ip access-group '+str(list(combined_data[device][interface]['acl'])[0])+' in')
                #print(interface+': \ninterface '+interface+'\nip access-group 102 in\n')
            elif '.140' in str(interface):
                config_changes[device].append('interface '+interface)
                config_changes[device].append('ip access-group 141 in')
                if combined_data[device][interface]['acl'] == 'none configured':
                    config_rollback[device].append('interface '+interface)
                    config_rollback[device].append('no ip access-group 141 in')
                else:
                    config_rollback[device].append('interface '+interface)
                    config_rollback[device].append('ip access-group '+str(list(combined_data[device][interface]['acl'])[0])+' in')   
    
    #####################do some config###############################
    filepath4 = './lbo_config_changes.json'
    with open(filepath4, "w") as outfile: 
        json.dump(config_changes, outfile)
    filepath5 = './lbo_config_rollback.json'
    with open(filepath5, "w") as outfile: 
        json.dump(config_rollback, outfile)

###############################unique configs####################################
    print('Processing unique configs')
    unique_configs={}
    configs = 0
    for device,config in config_changes.items():
        for version in list(unique_configs):
            if set(config)==set(unique_configs[version]["config"]):
                unique_configs[version]['devices'].append(device)
                break 
        else:
            unique_configs[str(configs+1)]={}
            unique_configs[str(configs+1)]["config"]=config
            unique_configs[str(configs+1)]["devices"]=[]
            unique_configs[str(configs+1)]["devices"].append(device)
            configs = configs +1

    unique_configs1 = {}
    for config in unique_configs:
        configname = str(config)+' ['+str(len(unique_configs[config]['devices']))+' device(s)]'
        unique_configs1[configname]=unique_configs[config]
    unique_configs = unique_configs1

    filepath6 = './lbo_unique_configs.json'
    with open(filepath6, "w") as outfile: 
        json.dump(unique_configs, outfile)
#
#

    
#    def lbo_details(lbo):
#        if lbo in config_changes.keys():
#            print("#######"+lbo+"#######")
#            print("Proposed config changes")
#            print("-----------------------")
#            for line in config_changes[lbo]:
#                print(line)
#            print("Config rollback")
#            print("---------------")
#            for line in config_rollback[lbo]:
#                print(line)
#            another = input("Would you line to see details of another LBO?:")
#            if another.lower() == "y" or another.lower() == "yes":
#                success = False
#            else:
#                success = True
#        else:
#            print("The LBO you entered is not a valid LBO name, please select from the following list:")
#            for shop in list(config_changes):
#                print(shop)
#            success = False
#        return success
#    success = False
#    while success == False:
#        lbo = input("Please enter the name of the LBO you would like to see details of:")
#        success = lbo_details(lbo)

    exit()
    



    lab_devices = nr.filter(role="lab_routers")
    cfg_failed_devices = []
    skip_devices = ['uk-brs-lab-cr02']
    standard_devices = ['uk-brs-lab-cr01']
    cfg_devices = lab_devices.filter(F(name__any=target_devices))
    hostname_devices = lab_devices.filter(F(name__any=hostname_change_required))
    


    def update_acl_config(task:Task) -> Result:
        task.run(task=netmiko_send_config, config_commands=new_acls['102'])
        task.run(task=netmiko_send_config, config_commands=new_acls['141'])
        task.run(task=netmiko_save_config)
    
    def update_hostname(task:Task) -> Result:
        task.run(task=netmiko_send_config, config_commands='hostname '+str(hostname_devices.inventory.hosts[str(task.host)].data['device_hostname']))
        
    def save_config_after_hostname_change(task:Task) -> Result:    
        task.run(task=netmiko_save_config)
#
    update_acls=cfg_devices.run(task=update_acl_config)
    print_result(update_acls)

    update_device_hostname=hostname_devices.run(task=update_hostname)
    print_result(update_device_hostname)
    nr = InitNornir(config_file=config_file)
    lab_devices = nr.filter(role="lab_routers")
    hostname_devices = lab_devices.filter(F(name__any=hostname_change_required))
    save_config=hostname_devices.run(task=save_config_after_hostname_change)
    print_result(save_config)

    print(config_changes)
    print('#################################')
    print(config_rollback)
    exit()

    #save config result = 
    #update_acls['uk-brs-lab-cr01'][3].result
    #'write mem\nBuilding configuration...\n\n  [OK]\nuk-brs-lab-cr01#'