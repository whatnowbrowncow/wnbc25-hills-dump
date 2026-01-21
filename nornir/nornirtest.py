#! /usr/bin/env python
# Modules
from click import prompt
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_scrapli.tasks import send_command
from nornir_scrapli.tasks import send_commands
from nornir_scrapli.tasks import send_configs
from nornir_scrapli.tasks import send_interactive
import json

# Local artefacts
import helper_functions as hf

# Variables
config_file = "./config.yaml"

# Body
if __name__ == "__main__":
    ## Initiate Nornir
    good_users = ["svcnetworkauto","netadmin","netsec"]
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    nr_lab = nr.filter(role="lab")
    #r1 = nr_lab.run(task=send_command, command="show ip arp")
    r3 = nr_lab.run(task=send_configs, configs=["username test privilege 7 password testy","username test6969 privilege 7 password testytest99"])
    #r2 = nr_lab.run(task=send_configs, configs=["no username test6969","\r"])
    r = nr_lab.run(task=send_commands, commands=["show run | inc ^username"])
    print_result(r)
    users = hf.get_unique_users(user_table=r)
    print(f"{len(users)} Devices found:")
    print(json.dumps(users, indent=4, sort_keys=True))
    
    
    print("Deleting bad users..............")
    
    print(nr.inventory.hosts)
    for device,usernames in users.items():
        for user in usernames:
            if user not in good_users:
                nr_device = nr.filter(name=device)
                print("deleting " + user + " from " + device)
                rdevice = nr_device.run(task=send_interactive, privilege_level="configuration", interact_events=[("no username "+user,"This operation will remove all username related configurations with same name.Do you want to continue? [confirm]"),("\r","")])
                print_result(rdevice)
    
    
    r4 = nr_lab.run(task=send_interactive, interact_events=[("cop r s","Destination filename [startup-config]?"),("\r","")])
    r1 = nr_lab.run(task=send_commands, commands=["show run | inc ^username"])

    ## Normalise Usernames
    users = hf.get_unique_users(user_table=r1)


    #print("USERS:")
    #print(users)

    ## Normalise ARP
    #arp_table = hf.get_unique_hosts(arp_table=r1)

    #print("AAAAAAAAAAARRRRRRRRRRRRRRRRRRRRRRRPPPPPPPPPPPPPPP")
    #print(arp_table)

    ## Collect MAC from lab
    #r2 = nr_lab.run(task=send_command, command="show mac address-table")
   
    ## Collect Interface description
    #r3 = nr_lab.run(task=send_command, command="show interface description")

    ## Map all the data
    #final_mapping = hf.match_ip_mac_port_description(arp_table=arp_table,
    #                                                 mac_table=r2, interfaces_table=r3)

    print("############Outputs below#################\n\n\n")
    print_result(r3)
    #print(r1['uk-brs-lab-sw01'].result)
    
    #print(r2['uk-brs-lab-sw01'].result)
    print_result(r4)
    print_result(r1)
    #print(r3['uk-brs-lab-sw01'].result
    ## Print results
    print(f"{len(users)} Devices found:")
    print(json.dumps(users, indent=4, sort_keys=True))
    
    
    