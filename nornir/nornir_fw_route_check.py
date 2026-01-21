#! /usr/bin/env python
# Modules
from curses import delay_output
from ipaddress import ip_address
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
    nr_devices = nr.filter(role="asa")
    #r1 = nr_devices.run(task=send_command, command="show ip arp")
    
    #r2 = nr_devices.run(task=send_configs, configs=["no username test6969","\r"])
    print("obtaining ACLs")
    system = nr_devices.run(task=netmiko_send_command, command_string="changeto system")
    print_result(system)
    contexts = nr_devices.run(task=netmiko_send_command, command_string="show context", use_genie=True, use_timing=True)
    print_result(contexts)
    for device,details in contexts.items():
        print(device)
        print(details[0])
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