#! /usr/bin/env python
# Modules
from curses import delay_output
from ipaddress import ip_address
from logging import exception
from tokenize import String
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
#from nornir.plugins.tasks import networking
from nornir.core.filter import F
from nornir.core.task import Task, Result
from collections import Counter
import re
import json

# Local artefacts
import helper_functions as hf

# Variables
config_file = "./config.yaml"

route = "10.1.1.1"
# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    nr_devices = nr.filter(F(role="ios") | F(role="nxos") | F(role="oob"))
    ios_devices = nr.filter(role="ios")
    iosxr_devices = nr.filter(role="iosxr")
    nxos_devices = nr.filter(role="nxos")
    oob_devices = nr.filter(role="oob")
    asa_devices = nr.filter(role="asa")
    #nr_devices = nr.filter(role="oob")
    #r1 = nr_devices.run(task=send_command, command="show ip arp")
    
    #r2 = nr_devices.run(task=send_configs, configs=["no username test6969","\r"])
    print("obtaining ACLs")



    ios_vty = ios_devices.run(task=netmiko_send_command, command_string="show run | begin line vty")
    oob_vty = oob_devices.run(task=netmiko_send_command, command_string="show run | begin line vty")
    nxos_vty = nxos_devices.run(task=netmiko_send_command, command_string="show run | section line")

    vty_acl = {}
    for device,details in ios_vty.items():
        mgmt_acl = re.search('access-class (\S+)',details[0].result)
        #print(mgmt_acl.group(1))
        try:
            vty_acl[device]=mgmt_acl.group(1)
            print(device+' mgmt acl found')
        except Exception as e:
            print(device+' mgmt acl NOT FOUND!: '+str(e))

    for device,details in oob_vty.items():
        mgmt_acl = re.search('access-class (\S+)',details[0].result)
        #print(mgmt_acl.group(1))
        try:
            vty_acl[device]=mgmt_acl.group(1)
            print(device+' mgmt acl found')
        except Exception as e:
            print(device+' mgmt acl NOT FOUND!: '+str(e))

    for device,details in nxos_vty.items():
        mgmt_acl = re.search('access-class (\S+)',details[0].result)
        #print(mgmt_acl.group(1))
        try:
            vty_acl[device]=mgmt_acl.group(1)
            print(device+' mgmt acl found')
        except Exception as e:
            print(device+' mgmt acl NOT FOUND!: '+str(e))

    #print(vty_acl)

    #for device,details in vty.items():
    #    nr_device = nr.filter(name=device)
    
    def get_mgmt_acls(task):
        cmd = "show access-lists "+ str(vty_acl[str(task.host)])
        multi_result= task.run(task=netmiko_send_command, command_string=cmd, use_genie=True, use_timing=True)
        #print(multi_result)
    acls = nr_devices.run(task=get_mgmt_acls)
    #print_result(acls)
    #print_result(test)
    #acls = nr_devices.run(task=netmiko_send_command, command_string="show access-lists "+vty_acl[{nornir.core.task.hostname}], use_genie=True, use_timing=True)
    #print(acls)
    #print(type(acls))
    #print(dir(acls))
    #wak = acls['uk-wak-ar01'][0]
    #print(type(wak))
    #print(dir(wak))
    #print(wak)
    #print('################')
    #print_result(acls)
    device_acls = {}
    device_count = 0
    acl_count = 0
    #print(type(acls))
    #print(dir(acls))
    for device,details in acls.items():
        #print(device)
        #print(details)
        device_count = device_count+1
        device_acls[device]={}
        #print(dir(details[1].result))
        #print(type(details[1].result))
        #print(details[1].result)
        try:
            for acl,rules in details[1].result.items():
                acl_count = acl_count+1
                if 'aces' in details[1].result[acl]:
                    device_acls[device][acl]={}
                    if 'acl_type' in details[1].result[acl]:
                        device_acls[device][acl]['type']=details[1].result[acl]['acl_type']
                    else:
                        device_acls[device][acl]['type']='not found'
                    device_acls[device][acl]['rules']={}
                    #print(acl)
                    try:
                        for rule,aces in details[1].result[acl]['aces'].items():
                            if 'destination_network' in details[1].result[acl]['aces'][rule]['matches']['l3']['ipv4'].keys():
                                for k,v in details[1].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                    for k1,v1 in details[1].result[acl]['aces'][rule]['matches']['l3']['ipv4']['destination_network'].items():
                                        device_acls[device][acl]['rules'][rule]=str(details[1].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))+' '+str(re.sub(' 0.0.0.0','',k1))
                            else:
                                for k,v in details[1].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                    device_acls[device][acl]['rules'][rule]=str(details[1].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))
                                    #print('hello')
                                    #print(k)
                                    #print(v)
                                
                    except Exception as e:
                        device_acls[device][acl]['rules']=str(e)
                else:
                    device_acls[device][acl]='No rules found'

        except Exception as e:
            device_acls[str(device)+' could not be processed']=str(e)

        #print(device)
        #print(details[1]) 
    
    
    #print(device_acls)
    filepath = './acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(device_acls, outfile)

    print('############################Complete###################')
    print('Device Count: '+str(device_count))
    print('ACL Count: '+str(acl_count))
    
    unique_acls={}
    numberfound = 0
    unique_acls_list = []
    for device,accesslist in device_acls.items():
        if type(accesslist) != String:
            try:
                rules = []
                for line_no,lines in accesslist.items():
                    for line,ace in lines['rules'].items():
                        rules.append(str(line)+' '+str(ace))
                    for item in unique_acls:
                        if Counter(rules) == Counter(unique_acls[item]['rules']):
                            unique_acls[item]['devices'].append(device)
                            break
                    else:
                            
                        #if rules not in unique_acls_list:
                        unique_acls[str(numberfound+1)] = {}
                        unique_acls[str(numberfound+1)]['rules'] = rules
                        unique_acls[str(numberfound+1)]['devices'] = []
                        unique_acls[str(numberfound+1)]['devices'].append(device)
                        unique_acls_list.append(rules)
                        numberfound = numberfound + 1
            except:
                print('failed for '+str(device))


a = sorted(unique_acls.items(), key=lambda x: len(x['devices']))    
print(a)


filepath = './unique_acls.json'
with open(filepath, "w") as outfile: 
    json.dump(unique_acls, outfile)



    
    exit()
    for device,details in contexts.items():
        print(device)
        print(details[1])
        for context in details:
            print(context.result)
            for con,deeta in context.result.items():
                    csystem = nr_devices.run(task=netmiko_send_command, command_string="changeto context "+con)
                    print_result(csystem)
                    ccontexts = nr_devices.run(task=netmiko_send_command, command_string="show route "+route, use_genie=True, use_timing=True)
                    print_result(ccontexts)
                #print(con)
                #print(deeta)
    #print(acls['uk-sc1-fw04'][0])
#    with open('uk-sc1-fw04.txt', 'w') as f:
#        f.write(str(acls['uk-sc1-fw04'][0]))
#    with open('uk-ld6-fw04.txt', 'w') as f:
#        f.write(str(acls['uk-ld6-fw04'][0]))
#       for interface, details in interfaces.scrapli_response.genie_parse_output().items():
#           if "ipv4" in details:
#               print("interface with IP found")
#               print("interface: "+ interface)
#               #print(details)
#               print(details['ipv4'])
#               for k in details['ipv4']:
#                   print("IP address: "+ details['ipv4'][k]['ip'])
#                   print("adding to dict......")
#                   ints[hostname][interface]={}
#                   ints[hostname][interface]['ip_address']=details['ipv4'][k]['ip']
#               if "description" in details:
#                   print("interface description found")
#                   print("Description: "+ details['description'])
#                   print("adding to dict......")
#                   ints[hostname][interface]['description']=details['description']
#    normal_acls = hf.get_acls(acls)
#    #print(normal_acls)
#
#    final_acls = {}
#    for hostname,acls in normal_acls.items():
#        final_acls[hostname] = []
#        for acl in acls:
#            final_acls[hostname].append(acl)
#
#
##print(final_acls)
#ld6_lines_not_in_scc = []
#scc_lines_not_in_ld6 = []
#
#for row in final_acls['uk-sc1-fw04']:
#    if row not in final_acls['uk-ld6-fw04']:
#        scc_lines_not_in_ld6.append(row)
#
#for row in final_acls['uk-ld6-fw04']:
#    if row not in final_acls['uk-sc1-fw04']:
#        ld6_lines_not_in_scc.append(row)        
#
#print("SCC config not in LD6:")
#print(str(len(scc_lines_not_in_ld6))+" lines found")
#for row in scc_lines_not_in_ld6:
#    print(row)
#print("LD6 config not in SCC:")
#print(str(len(ld6_lines_not_in_scc))+" lines found")
#for row in ld6_lines_not_in_scc:
#    print(row)
#    #show_interfaces_brief = nr_devices.run(task=send_command, command="show ip interface brief")
#    #show_interfaces_desc = nr_devices.run(task=send_command, command="show interfaces description")
#    
#
#    #interfaces=hf.get_ints(show_interfaces)
#    #print(json.dumps(interfaces, indent=4, sort_keys=True))
#    #user_ip = str(input("What IP would you like to search for?"))
#    #for device,details in interfaces.items():
#    #    for interface in details:
#    #        if "ip_address" in interfaces[device][interface].keys() and interfaces[device][interface]['ip_address'] == user_ip:
#    #            print("ADDRESS FOUND!")
#    #            print("Device: " + device)
#    #            print("Interface: "+ interface)
#    #        
#    #    
##
#    #else:
#    #    print("Sorry I cannot find that IP")
#    #ip_ints = hf.get_ip_ints(show_interfaces_brief)
#    #print(json.dumps(ip_ints, indent=4, sort_keys=True))
#    #ip_ints = hf.get_ip_int_descs(show_interfaces_desc,ip_ints)
#    #print(json.dumps(ip_ints, indent=4, sort_keys=True))
#    #for hostname, interfaces in show_interfaces.items():
#    #    print(hostname+":")
#    #    #print(interfaces)
#    #    #print(type(interfaces.scrapli_response.genie_parse_output()))
#    #    #print(dir(interfaces.scrapli_response.genie_parse_output()))
#    #    #print("INTS###################################")
#    #    
#    #    #ints = interfaces.scrapli_response.genie_parse_output()
#    #    #print(type(ints))
#    #    #print(ints.items())
#    #    #print("BREAK###################################")
#    #    #print(ints['interface'].items())
#    #    
#   #    for interface, details in interfaces.scrapli_response.genie_parse_output()['interface'].items():
#   #        #print(interface)
#   #        #print(details)
#   #        if details['ip_address'] != "unassigned":
#   #            print("interface with IP found found")
#   #            print("interface: "+ interface)
#   #            print("IP address: "+ details['ip_address'])
#
#   #print("un parsed data")
#   #print_result(interfaces)
#   #print("parsed data")
#   #print_structured_result(result=interfaces, parser="genie")
#   #host_result = acls["uk-brs-lab-sw01"][0]
#   #print(acls)
#   #print(type(host_result))
#   #print(dir(host_result))
#   #print(type(host_result.stdout))
#   #print(dir(host_result.stdout))
#   ##print("GENIE results")
#   ##genie_results = host_result.scrapli_response.genie_parse_output()
#   ##print("GENIE RESULTS: \n", genie_results)
#   ##print("####################################################################################################")
#   ##print("obtaining usernames...........")
#   ##
#   ##r1 = nr_devices.run(task=send_commands, commands=["show run | inc ^username"])
#   ##print_result(r1)
#   ##users = hf.get_unique_users(user_table=r1)
#   ##print(f"{len(users)} Devices found:")
    ##print(json.dumps(users, indent=4, sort_keys=True))
    ##
    ##
    ##print("Deleting bad users..............")
    #
    #for device,usernames in users.items():
    #    for user in usernames:
    #        if user not in good_users:
    #            nr_device = nr.filter(name=device)
    #            print("deleting " + user + " from " + device)
    #            rdevice = nr_device.run(task=send_interactive, privilege_level="configuration", interact_events=[("no username "+user,"This operation will remove all username related configurations with same name.Do you want to continue? [confirm]"),("\r","")])
    #            print_result(rdevice)
    #print("adding good users.....")
    #r4 = nr_devices.run(task=send_configs, configs=["username netadmin privilege 15 secret !2vua*zT5acy ","username svcnetworkauto privilege 15 secret Aut0mat1on"])
    #print_result(r4)
    #print("Saving configuration")
    #r2 = nr_devices.run(task=send_commands, commands=["wr mem"])
    #print_result(r2)
    #print("obtaining username again following deletion...........")
    #r3 = nr_devices.run(task=send_commands, commands=["show run | inc ^username"])
#
    ### Normalise Usernames
    #users = hf.get_unique_users(user_table=r3)
    #print_result(r3)
    #print(f"{len(users)} Devices found:")
    #print(json.dumps(users, indent=4, sort_keys=True))
    #
    #
    #