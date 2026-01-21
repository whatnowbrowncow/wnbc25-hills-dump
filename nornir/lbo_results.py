import json
import re
from rich.console import Console
console = Console()


with open('./lbo_config_changes.json') as json_file: 
    config_changes=json.load(json_file)

with open('./lbo_config_rollback.json') as json_file: 
    config_rollback=json.load(json_file)

with open('./lbo_failed_hosts.json') as json_file: 
    failed_hosts=json.load(json_file)

def lbo_details(lbo):
    if lbo in config_changes.keys():
        console.print("#######  "+lbo+"  #######\n")
        console.print("[green]Proposed config changes")
        console.print("-----------------------")
        for line in config_changes[lbo]:
            console.print(line)
        console.print("\n[red]Config rollback")
        console.print("---------------")
        for line in config_rollback[lbo]:
            console.print(line)
        another = input("Would you line to see details of another LBO?:")
        if another.lower() == "y" or another.lower() == "yes":
            success = False
        else:
            success = True
    else:
        console.print("[italic red]The LBO you entered is not a valid LBO name, please select from the following list:")
        for shop in list(config_changes):
            console.print(shop)
        success = False
    return success
success = False
while success == False:
    lbo = input("Please enter the name of the LBO you would like to see details of:")
    success = lbo_details(lbo)