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
from nornir_scrapli.functions import print_structured_result
from nornir_scrapli.tasks import send_command
from nornir_scrapli.tasks import send_commands
from nornir_scrapli.tasks import send_configs
from nornir_scrapli.tasks import send_interactive
from nornir_netmiko.tasks import netmiko_send_command
from nornir.core.filter import F
import re
import json
from rich.console import Console
from rich.table import Table
console = Console()
# Local artefacts
import retail_helper_functions as rhf

# Variables
config_file = "/dbdev/retail_dmvpn_cipher/config_files/retail_dmvpn.yaml"

dmvpntable = Table(title='DMVPN Check Summary',show_header=True, header_style="bold blue")
dmvpntable.add_column('Spoke',justify='center')
dmvpntable.add_column('Peer IP',justify='center')
dmvpntable.add_column('Status',justify='center')
dmvpntable.add_column('UP/DOWN Time',justify='center')
dmvpntable.add_column('Spoke Status',justify='center')
# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    eigrp = nr_hubs.run(task=netmiko_send_command, command_string="show ip eigrp vrf retail-vrf neighbors", use_genie=True, use_timing=True)
    for device,results in eigrp.items():
        for inst,data in results[0].result['eigrp_instance'].items():
            for vrf,addfm in data['vrf'].items():
                for af,eigrp_int in addfm['address_family'].items():
                    for int, eigrp_nbr in eigrp_int['eigrp_interface'].items():
                        print(device)
                        print('number of neighbours:')
                        print(len(list(eigrp_nbr['eigrp_nbr'])))
                        #for nbr in list(eigrp_nbr['eigrp_nbr']):
                        #    print(nbr)




    #eigrp['uk-ld6-dmvpn01'][0].result['eigrp_instance']['100']['vrf']['retail-vrf']['address_family']['ipv4']['eigrp_interface']['Tunnel0']['eigrp_nbr']
    #print_result(eigrp)



                






    #print(nr_devices)
    #r1 = nr_devices.run(task=send_command, command="show ip arp")
    pers_bt_tacacs_failed_devices=[]
    wh_tacacs_failed_devices=[]
    bt_devices = 0
    wh_devices = 0
    failed_devices = 0

    #r2 = nr_devices.run(task=send_configs, configs=["no username test6969","\r"])
    print("Checking dmvpn connectivity") 
    print('DMVPN.............................')
    dmvpn = nr_devices.run(task=netmiko_send_command, command_string="show dmvpn", use_genie=True, use_timing=True)
    for device,details in dmvpn.items():
        if details[0].failed == True:
            console.print('[red]{} - Failed to execute command'.format(device))
    #print_result(dmvpn)
    tunnels = nr_devices.run(task=netmiko_send_command, command_string="show ip interface brief | inc Tunnel", use_genie=True, use_timing=True)
    interfaces = {}
    for hostname, entry_1_level in tunnels.items():
        interfaces[hostname]={}
        #interfaces[hostname]['interfaces']={}
        for intfa,data in entry_1_level[0].result['interface'].items():
            interfaces[hostname][data['ip_address']]=intfa
    #print(interfaces)
    #print('testing regex')
    parsed_dmvpn = rhf.dmpvn_per_tunnel(dmvpn)

    eigrp = nr_hubs.run(task=netmiko_send_command, command_string="show ip eigrp vrf retail-vrf neighbors", use_genie=True, use_timing=True)
    #print_result(eigrp)
    #print(parsed_dmvpn)
    #print('hosts================')
    #print(nr.inventory.hosts)
    print('''~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
DMVPN CONNECTIVITY
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~''')
    print('''HUBS:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~''')
    for host in nr.inventory.hosts:
        dmvpntable = Table(title= str(host) + ' DMVPN Check Summary',show_header=True, header_style="bold blue")
        dmvpntable.add_column('Spoke',justify='center')
        dmvpntable.add_column('Peer IP',justify='center')
        dmvpntable.add_column('Status',justify='center')
        dmvpntable.add_column('UP/DOWN Time',justify='center')
        dmvpntable.add_column('Spoke Status',justify='center')
        if nr.inventory.hosts[host]['role']=='hubs':
            #print(host)
            #print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
            for k,v in parsed_dmvpn[host]['Tunnels'].items():
                for a,b in v.items():
                    intfound = False
                    spokematch = False
                    for device,interf in interfaces.items():
                        #for tunnels,data in interf.items():
                            for ip,tunnel in interf.items():
                                if str(b['tunnel IP']) == str(ip):
                                    spoke_name = str(device)
                                    intfound = True
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
            console.print(dmvpntable)

    
    
    











                
        #print(host)
        #print(nr.inventory.hosts[host].keys())
    exit()
    #print(type(acls))
    #print(dir(acls))
    #wak = acls['uk-wak-ar01'][0]
    #print(type(wak))
    #print(dir(wak))
    #print(wak)
    #print('################')
    print(acls)
    #print_result(acls)
    report = {}
    report['summary']={}
    temp_data={}
    temp_data['devices']={}
    temp_data['devices']={}
    temp_data['devices']['Failed Devices']={}
    temp_data['devices']['BT Tacacs Devices']={}
    temp_data['devices']['WH Tacacs Devices']={}
    device_count = 0
    acl_count = 0
    for device,details in acls.items():
        device_count = device_count+1
        if details[0].failed == True:
            if str(details[0].exception).split('\n')[0] == 'Authentication to device failed.':
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print (error)
            #print('++'+device+'++')
            #print(device)
            #print(dir(details[0]))
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(str(details[0].exception).split('\n'))
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(details[0].stderr)
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(details[0].failed)
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(details[0].stdout)
                #temp_data['devices'][device]={}
                #temp_data['devices'][device]['1st run failure']=str(details[0].exception).split('\n')[0]
                #temp_data['devices'][device]['acls']={}
                print('Connection to ' +device + ' failed: '+str(details[0].exception).split('\n')[0])
                pers_bt_tacacs_failed_devices.append(device)
            else:
                
                temp_data['devices']['Failed Devices'][device]={}
                temp_data['devices']['Failed Devices'][device]['Failure reason']=str(details[0].exception).split('\n')[0]
                failed_devices = failed_devices + 1
        else:
            bt_devices = bt_devices + 1
            temp_data['devices']['BT Tacacs Devices'][device]={}
            temp_data['devices']['BT Tacacs Devices'][device]['auth_type'] = 'personal BT tacacs'
            temp_data['devices']['BT Tacacs Devices'][device]['acls']={}
            print('-----------' +device + ' ACLs -----------')
            #print(dir(details[0].result))
            #print(type(details[0].result))
            #print(details[0].result)
            try:
                for acl,rules in details[0].result.items():
                    acl_count = acl_count+1
                    if 'aces' in details[0].result[acl]:
                        temp_data['devices']['BT Tacacs Devices'][device]['acls'][acl]={}
                        temp_data['devices']['BT Tacacs Devices'][device]['acls'][acl]['type']=details[0].result[acl]['acl_type']
                        temp_data['devices']['BT Tacacs Devices'][device]['acls'][acl]['rules']={}
                        print(acl)
                        try:
                            for rule,aces in details[0].result[acl]['aces'].items():
                                if 'destination_network' in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4'].keys():
                                    for k,v in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                        for k1,v1 in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4']['destination_network'].items():
                                            temp_data['devices']['BT Tacacs Devices'][device]['acls'][acl]['rules'][rule]=str(details[0].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))+' '+str(re.sub(' 0.0.0.0','',k1))
                                else:
                                    for k,v in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                        temp_data['devices']['BT Tacacs Devices'][device]['acls'][acl]['rules'][rule]=str(details[0].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))
                                        #print('hello')
                                        #print(k)
                                        #print(v)
                                    
                        except Exception as e:
                            temp_data['devices']['BT Tacacs Devices'][device]['acls'][acl]['rules']=str(e)
                    else:
                        temp_data['devices']['BT Tacacs Devices'][device]['acls'][acl]='No rules found'
    
            except Exception as e:
                temp_data['devices']['BT Tacacs Devices'][str(device)+' could not be processed']=str(e)

        #print(device)
        #print(details[0]) 
    
    
    #print(devices)

    print('##############failed devices########################')
    print(pers_bt_tacacs_failed_devices)
    print('attempting failed devices using global account')
    config_file = "./retail_global_config.yaml"
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    nr_devices = nr.filter(F(name__in=pers_bt_tacacs_failed_devices))
    #print(nr_devices)
    #r1 = nr_devices.run(task=send_command, command="show ip arp")
    
    #r2 = nr_devices.run(task=send_configs, configs=["no username test6969","\r"])
    print("Checking connectivity for failed devices") 
    
    acls1 = nr_devices.run(task=netmiko_send_command, command_string="show access-lists", use_genie=True, use_timing=True)
    for device,details in acls1.items():
        if details[0].failed == True:
            if str(details[0].exception).split('\n')[0] == 'Authentication to device failed.':
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print (error)
            #print('++'+device+'++')
            #print(device)
            #print(dir(details[0]))
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(str(details[0].exception).split('\n'))
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(details[0].stderr)
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(details[0].failed)
            #print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            #print(details[0].stdout)
                #temp_data['devices']['WH Tacacs Devices'][device]['2nd run failure']=str(details[0].exception).split('\n')[0]
                #temp_data['devices']['WH Tacacs Devices'][device]['acls']={}
                print('Connection to ' +device + ' failed: '+str(details[0].exception).split('\n')[0])
                wh_tacacs_failed_devices.append(device)
                temp_data['devices']['Failed Devices'][device]={}
                temp_data['devices']['Failed Devices'][device]['Failure reason']=str(details[0].exception).split('\n')[0]
                failed_devices = failed_devices + 1
            else:
                temp_data['devices']['Failed Devices'][device]={}
                temp_data['devices']['Failed Devices'][device]['Failure reason']=str(details[0].exception).split('\n')[0]
                failed_devices = failed_devices + 1

        else:
            wh_devices = wh_devices + 1
            temp_data['devices']['WH Tacacs Devices'][device]={}
            temp_data['devices']['WH Tacacs Devices'][device]['auth_type'] = 'WH tacacs'
            temp_data['devices']['WH Tacacs Devices'][device]['acls']={}
            print('-----------' +device + ' ACLs -----------')
            #print(dir(details[0].result))
            #print(type(details[0].result))
            #print(details[0].result)
            try:
                for acl,rules in details[0].result.items():
                    acl_count = acl_count+1
                    if 'aces' in details[0].result[acl]:
                        temp_data['devices']['WH Tacacs Devices'][device]['acls'][acl]={}
                        temp_data['devices']['WH Tacacs Devices'][device]['acls'][acl]['type']=details[0].result[acl]['acl_type']
                        temp_data['devices']['WH Tacacs Devices'][device]['acls'][acl]['rules']={}
                        print(acl)
                        try:
                            for rule,aces in details[0].result[acl]['aces'].items():
                                if 'destination_network' in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4'].keys():
                                    for k,v in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                        for k1,v1 in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4']['destination_network'].items():
                                            temp_data['devices']['WH Tacacs Devices'][device]['acls'][acl]['rules'][rule]=str(details[0].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))+' '+str(re.sub(' 0.0.0.0','',k1))
                                else:
                                    for k,v in details[0].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                        temp_data['devices']['WH Tacacs Devices'][device]['acls'][acl]['rules'][rule]=str(details[0].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))
                                        #print('hello')
                                        #print(k)
                                        #print(v)
                                    
                        except Exception as e:
                            temp_data['devices']['WH Tacacs Devices'][device]['acls'][acl]['rules']=str(e)
                    else:
                        temp_data['devices']['WH Tacacs Devices'][device]['acls'][acl]='No rules found'
    
            except Exception as e:
                temp_data['devices']['WH Tacacs Devices'][str(device)+' could not be processed']=str(e)

    report['summary']['Device Count'] = device_count
    report['summary']['BT Tacacs Devices('+str(bt_devices)+')'] = temp_data['devices']['BT Tacacs Devices']
    report['summary']['WH Tacacs Devices('+str(wh_devices)+')'] = temp_data['devices']['WH Tacacs Devices']
    report['summary']['Failed Devices('+str(failed_devices)+')'] = temp_data['devices']['Failed Devices']
    #report['summary']['ACL Count'] = acl_count

    filepath = './retail_acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(report, outfile)

    print('############################Complete###################')
    print('Device Count: '+str(device_count))
    print('ACL Count: '+str(acl_count))
