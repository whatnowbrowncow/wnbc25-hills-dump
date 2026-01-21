#! /usr/bin/env python
# Modules
from unicodedata import name
from click import prompt
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir_scrapli.functions import print_structured_result
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
    nr_devices = nr.filter(role="lab")
    #r1 = nr_devices.run(task=send_command, command="show ip arp")
    
    #r2 = nr_devices.run(task=send_configs, configs=["no username test6969","\r"])
    print("obtaining active users and performing genie test")
    show_users = nr_devices.run(task=send_command, command="show interfaces")
    print("un parsed data")
    print_result(show_users)
    print("parsed data")
    print_structured_result(result=show_users, parser="genie")
    host_result = show_users["uk-brs-lab-sw01"][0]
    print(type(host_result))
    print(dir(host_result))
    print(type(host_result.scrapli_response))
    print(dir(host_result.scrapli_response))
    print("GENIE results")
    genie_results = host_result.scrapli_response.genie_parse_output()
    print("GENIE RESULTS: \n", genie_results)
    print("####################################################################################################")
    print("obtaining usernames...........")
    
    r1 = nr_devices.run(task=send_commands, commands=["show run | inc ^username"])
    print_result(r1)
    users = hf.get_unique_users(user_table=r1)
    print(f"{len(users)} Devices found:")
    print(json.dumps(users, indent=4, sort_keys=True))
    
    
    print("Deleting bad users..............")
    
    for device,usernames in users.items():
        for user in usernames:
            if user not in good_users:
                nr_device = nr.filter(name=device)
                print("deleting " + user + " from " + device)
                rdevice = nr_device.run(task=send_interactive, privilege_level="configuration", interact_events=[("no username "+user,"This operation will remove all username related configurations with same name.Do you want to continue? [confirm]"),("\r","")])
                print_result(rdevice)
    print("adding good users.....")
    r4 = nr_devices.run(task=send_configs, configs=["username netadmin privilege 15 secret !2vua*zT5acy ","username svcnetworkauto privilege 15 secret Aut0mat1on"])
    print_result(r4)
    print("Saving configuration")
    r2 = nr_devices.run(task=send_commands, commands=["wr mem"])
    print_result(r2)
    print("obtaining username again following deletion...........")
    r3 = nr_devices.run(task=send_commands, commands=["show run | inc ^username"])

    ## Normalise Usernames
    users = hf.get_unique_users(user_table=r3)
    print_result(r3)
    print(f"{len(users)} Devices found:")
    print(json.dumps(users, indent=4, sort_keys=True))
    
    
    