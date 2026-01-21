#! /usr/bin/env python
# Modules
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

# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    nr_devices = nr.filter(role="oob")
    #r1 = nr_devices.run(task=send_command, command="show ip arp")
    
    #r2 = nr_devices.run(task=send_configs, configs=["no username test6969","\r"])
    print("obtaining interfaces with IP Addresses")
    show_interfaces = nr_devices.run(task=send_command, command="show interfaces")
    #show_interfaces_brief = nr_devices.run(task=send_command, command="show ip interface brief")
    #show_interfaces_desc = nr_devices.run(task=send_command, command="show interfaces description")
    

    interfaces=hf.get_ints(show_interfaces)
    print(json.dumps(interfaces, indent=4, sort_keys=True))
    #user_ip = str(input("What IP would you like to search for?"))
    for device,details in interfaces.items():
        nr_device = nr.filter(name=device)
        if "Tunnel0" in interfaces[device].keys() and "Tunnel1" in interfaces[device].keys():
            print("Tunnel interfaces 0 + 1 found on "+device)
            rdevice = nr_device.run(task=send_configs, configs=["interface Tunnel0 ","description oob-dmvpn tunnel : int-vrf","interface Tunnel1 ","description oob-dmvpn tunnel : ext-vrf"])
            print_result(rdevice)
            print("Saving configuration")
            r2 = nr_device.run(task=send_commands, commands=["wr mem"])
            print_result(r2)
        elif "Tunnel0" in interfaces[device].keys():
            print("Tunnel interface 0 found on "+device)
            rdevice = nr_device.run(task=send_configs, configs=["interface Tunnel0 ","description oob-dmvpn tunnel : int-vrf"])
            print_result(rdevice)
            print("Saving configuration")
            r2 = nr_device.run(task=send_commands, commands=["wr mem"])
            print_result(r2)
        else:
            print("No Tunnel interfaces found on "+device)

    #        if "ip_address" in interfaces[device][interface].keys() and interfaces[device][interface]['ip_address'] == user_ip:
    #            print("ADDRESS FOUND!")
    #            print("Device: " + device)
    #            print("Interface: "+ interface)
    #        
    #    
#
    #else:
    #    print("Sorry I cannot find that IP")
    #ip_ints = hf.get_ip_ints(show_interfaces_brief)
    #print(json.dumps(ip_ints, indent=4, sort_keys=True))
    #ip_ints = hf.get_ip_int_descs(show_interfaces_desc,ip_ints)
    #print(json.dumps(ip_ints, indent=4, sort_keys=True))
    #for hostname, interfaces in show_interfaces.items():
    #    print(hostname+":")
    #    #print(interfaces)
    #    #print(type(interfaces.scrapli_response.genie_parse_output()))
    #    #print(dir(interfaces.scrapli_response.genie_parse_output()))
    #    #print("INTS###################################")
    #    
    #    #ints = interfaces.scrapli_response.genie_parse_output()
    #    #print(type(ints))
    #    #print(ints.items())
    #    #print("BREAK###################################")
    #    #print(ints['interface'].items())
    #    
    #    for interface, details in interfaces.scrapli_response.genie_parse_output()['interface'].items():
    #        #print(interface)
    #        #print(details)
    #        if details['ip_address'] != "unassigned":
    #            print("interface with IP found found")
    #            print("interface: "+ interface)
    #            print("IP address: "+ details['ip_address'])

    #print("un parsed data")
    #print_result(interfaces)
    #print("parsed data")
    #print_structured_result(result=interfaces, parser="genie")
    ##host_result = interfaces["uk-brs-lab-sw01"][0]
 
    ##print(type(host_result))
    ##print(dir(host_result))
    ##print(type(host_result.scrapli_response))
    ##print(dir(host_result.scrapli_response))
    ##print("GENIE results")
    ##genie_results = host_result.scrapli_response.genie_parse_output()
    ##print("GENIE RESULTS: \n", genie_results)
    ##print("####################################################################################################")
    ##print("obtaining usernames...........")
    ##
    ##r1 = nr_devices.run(task=send_commands, commands=["show run | inc ^username"])
    ##print_result(r1)
    ##users = hf.get_unique_users(user_table=r1)
    ##print(f"{len(users)} Devices found:")
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