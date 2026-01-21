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



with open('./unique_acls.json') as json_file: 
    unique_acls=json.load(json_file)
unique_acls = sorted(unique_acls, key=lambda k: len(unique_acls[k]['devices']), reverse=True)

#print(a)


filepath = './unique_acls_sorted.json'
with open(filepath, "w") as outfile: 
    json.dump(unique_acls, outfile)



    
exit()
