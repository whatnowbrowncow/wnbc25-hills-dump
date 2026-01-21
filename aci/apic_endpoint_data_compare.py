#! /usr/bin/env python
# Modules
from curses import delay_output
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
from logging import exception
from unicodedata import name
from click import prompt
from nornir import InitNornir
import pprint
import jinja2
from nornir_utils.plugins.functions import print_result
from nornir_netmiko.tasks import netmiko_send_command
from nornir_netmiko.tasks import netmiko_send_config
from nornir_netmiko.tasks import netmiko_save_config
from nornir.core.filter import F
from nornir.core.task import Task, Result
from nornir.core.filter import F
from tqdm import tqdm
import pickle
import os
from datetime import datetime
import re
import json
from rich.console import Console
from rich.table import Table
console = Console()
# Local artefacts
import apic_helper_functions as ahf

# Variables
config_file = "/dbdev/aci/config_files/apic_lab.yaml"


# Body
if __name__ == "__main__":
    
    with open('/dbdev/aci/outputs/endpoints_pre_change.json') as prefile: 
        epg_data_pre = json.load(prefile)
    with open('/dbdev/aci/outputs/endpoints_post_change.json') as postfile: 
        epg_data_post = json.load(postfile)

    #pprint.pprint(epg_data)
    print('~~~~~~~~~~~~~~~~Active Endpoints~~~~~~~~~~~~~~~~\n')



    #console.print('There are [yellow]{}[/yellow] EPGs with multiple VLAN tags'.format(str(len(multiple_endpoints))))
    endpointtable = Table(title= 'Active Endpoint Data',show_header=True, header_style="bold blue")
    endpointtable.add_column('EPG',justify='center')
    endpointtable.add_column('Tenant',justify='center')
    endpointtable.add_column('Application profile',justify='center')
    endpointtable.add_column('Active Endpoints (count)',justify='center')
    for tenant,aps in epg_data_pre['Tenants'].items():
        if tenant in epg_data_post['Tenants'].keys():
            for ap,epgs in epg_data_pre['Tenants'][tenant]['Application_profiles'].items():
                if ap in epg_data_post['Tenants'][tenant]['Application_profiles'].keys():
                    for epg,data in epg_data_pre['Tenants'][tenant]['Application_profiles'][ap]['EPGs'].items():
                        if epg in epg_data_post['Tenants'][tenant]['Application_profiles'][ap]['EPGs'].keys():
                            if str(len(data['Endpoints'].keys())) == str(len(epg_data_post['Tenants'][tenant]['Application_profiles'][ap]['EPGs'][epg]['Endpoints'].keys())):
                                endpointtable.add_row("[green]{}".format(tenant),"[green]{}".format(ap),"[green]{}".format(epg),"[green]{}".format(str(len(data['Endpoints'].keys()))))
                            else:
                                endpointtable.add_row("[green]{}".format(tenant),"[green]{}".format(ap),"[green]{}".format(epg),"[red]{}|{}".format(str(len(data['Endpoints'].keys())),str(len(epg_data_post['Tenants'][tenant]['Application_profiles'][ap]['EPGs'][epg]['Endpoints'].keys()))))
                        else:
                            endpointtable.add_row("[green]{}".format(tenant),"[green]{}".format(ap),"[red]{} | missing".format(epg),"[red]{} | missing".format(str(len(data['Endpoints'].keys()))))
                else:
                    endpointtable.add_row("[green]{}".format(tenant),"[red]{} | missing".format(ap),"[red]---","[red]---")
        else:
            endpointtable.add_row("[red]{} | missing".format(tenant),"[red]---","[red]---","[red]---")
    for tenant,aps in epg_data_post['Tenants'].items():
        if tenant in epg_data_pre['Tenants'].keys():
            for ap,epgs in epg_data_post['Tenants'][tenant]['Application_profiles'].items():
                if ap in epg_data_pre['Tenants'][tenant]['Application_profiles'].keys():
                    for epg,data in epg_data_post['Tenants'][tenant]['Application_profiles'][ap]['EPGs'].items():
                        if epg in epg_data_pre['Tenants'][tenant]['Application_profiles'][ap]['EPGs'].keys():
                            continue
                        else:
                            endpointtable.add_row("[green]{}".format(tenant),"[green]{}".format(ap),"[red]missing | {}".format(epg),"[red]{}".format(str(len(data['Endpoints'].keys()))))
                else:
                    endpointtable.add_row("[green]{}".format(tenant),"[red]missing | {}".format(ap),"[red]---","[red]---")
        else:
            endpointtable.add_row("[red]missing | {}".format(tenant),"[red]---","[red]---","[red]---")
    console.print(endpointtable)