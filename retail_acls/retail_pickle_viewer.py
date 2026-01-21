#! /usr/bin/env python
# Modules

from datetime import datetime
import json
import pickle
import re
import time
import os
from rich.console import Console
from rich.table import Table
console = Console()
# Local artefacts
import retail_helper_functions as rhf
from tqdm import tqdm




# Variables
config_files = {'retail':"/dbdev/retail_acls/config_files/retail_dmvpn_config.yaml",
                 'oob'  :"/dbdev/retail_acls/config_files/oob_dmvpn_config.yaml"}

config_file = "/dbdev/retail_acls/config_files/retail_test_config.yaml"
##new acls to be applied to the devices (141 goes on sub interface x.140, 141 goes on all others)
new_acls = {
    '102':
['access-list 102 remark Allow ICMP','access-list 102 permit icmp any any','access-list 102 remark Remote Store Subnets','access-list 102 deny   ip any 10.160.0.0 0.7.255.255','access-list 102 deny   ip any 10.93.0.0 0.0.255.255','access-list 102 deny   ip any 10.94.0.0 0.0.255.255','access-list 102 deny   ip any 10.95.0.0 0.0.255.255','access-list 102 deny   ip any 10.96.0.0 0.0.255.255','access-list 102 permit ip any any'],
    '121':{'pre':
['access-list 121 remark Allow ICMP','access-list 121 permit icmp any any','access-list 121 remark Allow Local 120 and 130 Subnets'],
           'post':
['access-list 121 remark Remote Store Subnets','access-list 121 deny   ip any 10.160.0.0 0.7.255.255','access-list 121 deny   ip any 10.93.0.0 0.0.255.255','access-list 121 deny   ip any 10.94.0.0 0.0.255.255','access-list 121 deny   ip any 10.95.0.0 0.0.255.255','access-list 121 deny   ip any 10.96.0.0 0.0.255.255','access-list 121 permit ip any any']
},
    '141':
['access-list 141 remark Allow ICMP','access-list 141 permit icmp any any','access-list 141 remark Store to Store Voip Calls','access-list 141 permit udp any 10.163.0.0 0.0.255.255 range 16384 32767','access-list 141 remark Remote Store Subnets','access-list 141 deny   ip any 10.160.0.0 0.7.255.255','access-list 141 deny   ip any 10.93.0.0 0.0.255.255','access-list 141 deny   ip any 10.94.0.0 0.0.255.255','access-list 141 deny   ip any 10.95.0.0 0.0.255.255','access-list 141 deny   ip any 10.96.0.0 0.0.255.255','access-list 141 permit ip any any']   
}

##current ACL config to be compared against for each device during the facts gathering phase
golden_config = {
    'sub_interfaces':['10','140','180'],
    'acls':{
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

    #load it
    with open(f'/dbdev/retail_acls/outputs/results/14_02_2023_17_46_29/full_processed_results.pickle', 'rb') as file2:
        full_results = pickle.load(file2)

    console.print("[cyan]++++++++++++++++++++++++ Making any changes required ++++++++++++++++++++++++")
    console.print("[blue]ACL update result summary.....")
    console.print("[blue]--------")
    for device, results in full_results.items():
        print(device)
        print("netmiko_send_config:" + full_results[device]["netmiko_send_config"]["result"])
        print("netmiko_save_config:" + full_results[device]["netmiko_save_config"]["result"])
        print("------")
    console.print("[blue]Logs.....")
    console.print("[blue]--------")
    for device, results in full_results.items():
        print(device)
        print("netmiko_send_config:\n" + full_results[device]["netmiko_send_config"]["log"])
        print("netmiko_save_config:\n" + full_results[device]["netmiko_save_config"]["log"])
        print("------")
    console.print("[blue]Tables.....")
    console.print("[blue]--------")
    for device, results in full_results.items():
        print(device)
        console.print(full_results[device]["table"])
        console.print("[blue]------")
    
    #print(type(newtable))
    #console.print(newtable)
    #filepath7 = '/dbdev/retail_acls/outputs/update_acls_results.txt'
    #with open(filepath7, "w") as outfile:
    #    outfile.write(rhf.log_update_acls_results(update_acls)) 
        #json.dump(update_acls, outfile)

    #print_result(update_acls)

    update_device_hostname=hostname_devices.run(task=update_hostname)
    update_hostname_clean,update_hostname_failed_hosts = rhf.clean_facts(update_device_hostname)
    filepath10 = '/dbdev/retail_acls/outputs/failed_update_hostname.json'
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

    
    filepath8 = '/dbdev/retail_acls/outputs/processed_hostname_results.json'
    with open(filepath8, "w") as outfile: 
        json.dump(processed_hostname_results, outfile)
    #save it
    with open(f'/dbdev/retail_acls/full_processed_hostname_results.pickle', 'wb') as file:
        pickle.dump(full_processed_hostname_results, file)
    #load it
    with open(f'/dbdev/retail_acls/full_processed_hostname_results.pickle', 'rb') as file2:
        full_hostname_results = pickle.load(file2)

    console.print("[blue]\nHostname changes result summary.....")
    console.print("[blue]--------")
    for device, results in full_hostname_results.items():
        print(device)
        print("netmiko_send_config:" + full_hostname_results[device]["netmiko_send_config"]["result"])
        print("------")
    console.print("[blue]Logs.....")
    console.print("[blue]--------")
    for device, results in full_hostname_results.items():
        print(device)
        print("netmiko_send_config:\n" + full_hostname_results[device]["netmiko_send_config"]["log"])
        console.print("[blue]------")
    console.print("[blue]Tables.....")
    console.print("[blue]--------")
    for device, results in full_hostname_results.items():
        print(device)
        console.print(full_hostname_results[device]["table"])
        console.print("[blue]------")

    processed_hostname_save_results,full_processed_hostname_save_results = rhf.process_update_acls_results(save_config)
    console.print('[blue]\n#########################################\n')
    
    filepath9 = '/dbdev/retail_acls/outputs/processed_hostname_save_results.json'
    with open(filepath9, "w") as outfile: 
        json.dump(processed_hostname_save_results, outfile)
    #save it
    with open(f'/dbdev/retail_acls/full_processed_hostname_save_results.pickle', 'wb') as file:
        pickle.dump(full_processed_hostname_save_results, file)
    #load it
    with open(f'/dbdev/retail_acls/full_processed_hostname_save_results.pickle', 'rb') as file2:
        full_hostname_save_results = pickle.load(file2)

    console.print("[blue]Post hostname change save config result summary.....")
    console.print("[blue]--------")
    for device, results in full_hostname_save_results.items():
        print(device)
        print("netmiko_save_config:" + full_hostname_save_results[device]["netmiko_save_config"]["result"])
        console.print("[blue]------")
    console.print("[blue]Logs.....")
    console.print("[blue]--------")
    for device, results in full_hostname_save_results.items():
        print(device)
        print("netmiko_save_config:\n" + full_hostname_save_results[device]["netmiko_save_config"]["log"])
        console.print("[blue]------")
    console.print("[blue]Tables.....")
    console.print("[blue]--------")
    for device, results in full_hostname_save_results.items():
        print(device)
        console.print(full_hostname_save_results[device]["table"])
        console.print("[blue]------")
    #rhf.rich_table(update_acls)
    #print(config_rollback)
    exit()

    #save config result = 
    #update_acls['uk-brs-lab-cr01'][3].result
    #'write mem\nBuilding configuration...\n\n  [OK]\nuk-brs-lab-cr01#'