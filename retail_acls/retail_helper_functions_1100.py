import re
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
import logging
import pprint
import threading
from typing import List, cast
from collections import OrderedDict
import json
import pickle
import copy

from colorama import Fore, Style, init

from nornir.core.task import AggregatedResult, MultiResult, Result

def clean_facts(device_facts):
    #validate results
    failed_hosts = {}
    try:
        for hostname, entry_1_level in device_facts.items():
            if entry_1_level.failed == False:
                for data_pos in entry_1_level:
                    if data_pos.result == '':
                        #print(hostname+' is missing a result, adding to removal list')
                        failed_hosts[hostname] = str('missing a result '+str(data_pos))
                        break
            else:
                #print(hostname+' failed, adding to removal list')
                failed_hosts[hostname] = str(device_facts[hostname][0].exception.result[0].exception.args[0].splitlines()[0])
        for host,reason in failed_hosts.items():
            #print('Removing '+str(host)+' from device_facts......')
            device_facts.pop(host)
    except:
        print("Nothing to process")
    return device_facts,failed_hosts


def get_sub_interface_acls(raw_input,data_position = 0):

    result = {}

    for hostname, entry_1_level in raw_input.items():
        try:
            if entry_1_level[0].failed == False:
                result[hostname] = {}
                sub_interfaces = re.findall('interface \S+\.\S+\n(?:.*\n)+?(?=interface \S+|\Z)',str(entry_1_level[data_position]))
                #print(tunnels)
                result[hostname]['sub_interface_acls']={}
                for sub in sub_interfaces:
                   #print(tunnel)
                    sub_int = re.match('interface (\S+)',str(sub))
                    sub_int=sub_int.group(1)
                    acl = re.search('ip access-group (\d+)',str(sub))
                    try:
                        acl=acl.group(1)
                    except:
                        acl='none configured'
                    #print(entries)
                    result[hostname]['sub_interface_acls'][sub_int] = str(acl)
                #result[hostname]['Tunnels']=tunnels
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return result

def get_interfaces(raw_input,data_position = 0):
    interfaces = {}
    for hostname, entry_1_level in raw_input.items():
        try:
            if entry_1_level[0].failed == False:
                interfaces[hostname]={}
                #interfaces[hostname]['interfaces']={}
                for intfa,data in entry_1_level[data_position].result.items():
                    interfaces[hostname][intfa] = {}
                    interfaces[hostname][intfa]['type'] = data['type']
                    if 'description' in data.keys():
                        interfaces[hostname][intfa]['description'] = data['description']
                    if 'link_type' in data.keys():
                        interfaces[hostname][intfa]['link_type'] = data['link_type']
                    if 'ipv4' in data.keys():
                        for ip,details in data['ipv4'].items():
                            interfaces[hostname][intfa]['ip'] = ip
                    if 'encapsulations' in data.keys() and 'first_dot1q' in data['encapsulations'].keys():
                        interfaces[hostname][intfa]['dot1q'] = data['encapsulations']['first_dot1q']
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return interfaces

def get_sub_interfaces(raw_input):
    sub_interfaces = {}
    for hostname, entry_1_level in raw_input.items():
        sub_interfaces[hostname]={}
        #sub_interfaces[hostname]['sub_interfaces']={}
        for intfa,data in entry_1_level.items():
            if 'ip' in data.keys():
                if hasattr(re.match('(\S+\d+\.\d+)',intfa),'group') and re.match('(\S+\d+\.\d+)',intfa).group(1) == intfa:
                    sub_interfaces[hostname][intfa] = {}
                    sub_interfaces[hostname][intfa]['type'] = data['type']
                    sub_interfaces[hostname][intfa]['ip'] = data['ip']
                    if 'description' in data.keys():
                        sub_interfaces[hostname][intfa]['description'] = data['description']
                    if 'link_type' in data.keys():
                        sub_interfaces[hostname][intfa]['link_type'] = data['link_type']
                    if 'dot1q' in data.keys():
                        sub_interfaces[hostname][intfa]['dot1q'] = data['dot1q']
    return sub_interfaces

def get_version(raw_input,data_position = 0):
    versions = {}
    for hostname, entry_1_level in raw_input.items():
        try:
            if entry_1_level[0].failed == False:
                versions[hostname]={}
                #interfaces[hostname]['interfaces']={}
                try:
                    for version,data in entry_1_level[data_position].result.items():
                        versions[hostname]['hostname'] = data['hostname']
                        versions[hostname]['version'] = data['version_short']
                        versions[hostname]['router_type'] = data['rtr_type']
                        versions[hostname]['chassis'] = data['chassis']
                except Exception as e:
                    versions[hostname]['router_type'] = 'Failed'
                    versions[hostname]['chassis'] = 'Failed'
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return versions

def get_numbered_acls(raw_input,acl_numbers,new_acls,data_position = 0):
    new_acl_devices = []
    old_acl_devices = []
    numbered_acls = {}
    for hostname, entry_1_level in raw_input.items():
        new_acl_syntax = False
        new_syntax_acls = 0
        old_syntax_acls = 0
        if entry_1_level[0].failed == False:
            numbered_acls[hostname]={}
            numbered_acls[hostname]['sub_interface_acls']={}
            numbered_acls[hostname]['new_acls']={}
            for acl_no in acl_numbers[hostname]:
                try:
                    #aclregex = '((?:access-list '+str(acl_no)+'.*(?:\n|\Z))+)'
                    aclregex = '((?:access-list '+str(acl_no)+'.*(?:\n|\Z))+|(?:ip access-list extended '+str(acl_no)+'\n(?: .*\n|(?:\n|\Z))+))'
                    #aclregex = '(?:((?:access-list '+str(acl_no)+'.*(?:\n|\Z))+)|((?:ip access-list extended '+str(acl_no)+'\n(?: .*(?:\n|\Z))+)))'
                    lineregex = '(access-list '+str(acl_no)+'.*)'
                    acl = re.search(aclregex,str(entry_1_level[data_position]))
                    #acl1=acl.group(2)
                    acl=acl.group(1)
                    if 'ip access-list extended' in acl:
                        new_acl_syntax = True
                        new_syntax_acls = new_syntax_acls + 1
                    else:
                        old_syntax_acls = old_syntax_acls + 1
                    acl_lines = acl.split('\n')
                    acl_lines = list(filter(None,acl_lines))
                    acl_lines = [re.sub('^ \d+',"",x) for x in acl_lines]
                    new_acl_lines = []
                    for line in acl_lines:
                        new_acl_lines.append(re.sub('^ \d+','',str(line)))
                    acl_lines = new_acl_lines
                    #acl_lines = re.findall(lineregex,str(acl))
                #print(tunnels)
                
                    numbered_acls[hostname]['sub_interface_acls'][acl_no]=acl_lines
                    numbered_acls[hostname]['sub_interface_acls'][str(acl_no+'-acl')]=acl
                except Exception as e:
                    print('{} - {}'.format(hostname,e))
                    continue
                    #clair fails bcause it has an ACL applied to the interface but the acl is not defined in config
                    #print(hostname+' failed to process acl '+acl_no+ ' with the following error:\n'+str(e)+'\nPlease check that ACL is configured correctly on the device')
            for acl_no in new_acls:
                try:
                    #aclregex = '((?:access-list '+str(acl_no)+'.*(?:\n|\Z))+)'
                    aclregex = '((?:access-list '+str(acl_no)+'.*(?:\n|\Z))+|(?:ip access-list extended '+str(acl_no)+'\n(?: .*\n|(?:\n|\Z))+))'
                    lineregex = '(access-list '+str(acl_no)+'.*)'
                    acl = re.search(aclregex,str(entry_1_level[data_position]))
                    acl=acl.group(1)
                    if 'ip access-list extended' in acl:
                        new_acl_syntax = True
                        new_syntax_acls = new_syntax_acls + 1
                    else:
                        old_syntax_acls = old_syntax_acls + 1
                    acl_lines = re.findall(lineregex,str(acl))
                    acl_lines = acl.split('\n')
                    acl_lines = list(filter(None,acl_lines))
                    acl_lines = [re.sub('^ \d+',"",x) for x in acl_lines]
                    new_acl_lines = []
                    for line in acl_lines:
                        new_acl_lines.append(re.sub('^ \d+','',str(line)))
                    acl_lines = new_acl_lines
                #print(tunnels)
                
                    numbered_acls[hostname]['new_acls'][acl_no]=acl_lines
                    numbered_acls[hostname]['new_acls'][str(acl_no+'-acl')]=acl
                except Exception as e:
                    continue
                    #clair fails bcause it has an ACL applied to the interface but the acl is not defined in config
                    #print(hostname+' failed to process acl '+acl_no+ ' with the following error:\n'+str(e)+'\nIt appears that the new ACL is not configured on the device')
        if new_acl_syntax == True:
            if old_syntax_acls == 0:
                new_acl_devices.append(hostname)
                #print('{} has {} new acls and {} acls'.format(hostname,new_syntax_acls,old_syntax_acls))
            #else:
                #print('Error device {} has a mix of old and new syntax ACLs'.format(hostname))
        else:
            old_acl_devices.append(hostname)
            #print('{} has {} new acls and {} acls'.format(hostname,new_syntax_acls,old_syntax_acls))
    return numbered_acls,new_acl_devices,old_acl_devices




#def log_update_acls_results(update_acls):
    


    #def print_title(title: str) -> None:
    #    """
    #    Helper function to print a title.
    #    """
    #    msg = "**** {} ".format(title)
    #    print("{}{}{}{}".format(Style.BRIGHT, Fore.GREEN, msg, "*" * (80 - len(msg))))    
    #
#
    #def _get_color(result: Result, failed: bool) -> str:
    #    if result.failed or failed:
    #        color = Fore.RED
    #    elif result.changed:
    #        color = Fore.YELLOW
    #    else:
    #        color = Fore.GREEN
    #    return cast(str, color)    
    #
#
    #def _print_individual_result(
    #    result: Result,
    #    attrs: List[str],
    #    failed: bool,
    #    severity_level: int,
    #    task_group: bool = False,
    #    print_host: bool = False,
    #) -> None:
    #    if result.severity_level < severity_level:
    #        return    
#
    #    color = _get_color(result, failed)
    #    subtitle = (
    #        "" if result.changed is None else " ** changed : {} ".format(result.changed)
    #    )
    #    level_name = logging.getLevelName(result.severity_level)
    #    symbol = "v" if task_group else "-"
    #    host = (
    #        f"{result.host.name}: "
    #        if (print_host and result.host and result.host.name)
    #        else ""
    #    )
    #    msg = "{} {}{}{}".format(symbol * 4, host, result.name, subtitle)
    #    print(
    #        "{}{}{}{} {}".format(
    #            Style.BRIGHT, color, msg, symbol * (80 - len(msg)), level_name
    #        )
    #    )
    #    for attribute in attrs:
    #        x = getattr(result, attribute, "")
    #        if isinstance(x, BaseException):
    #            print('here1')
    #            # for consistency between py3.6 and py3.7
    #            print(f"{x.__class__.__name__}{x.args}")
    #        elif x and not isinstance(x, str):
    #            print('here2')
    #            if isinstance(x, OrderedDict):
    #                print('here3')
    #                print(json.dumps(x, indent=2))
    #            else:
    #                print('here4')
    #                pprint.pprint(x, indent=2)
    #        elif x:
    #            print('here5')
    #            print(x)    
    #
#
    #def _print_result(
    #    result: Result,
    #    attrs: List[str] = None,
    #    failed: bool = False,
    #    severity_level: int = logging.INFO,
    #    print_host: bool = False,
    #) -> None:
    #    attrs = attrs or ["diff", "result", "stdout"]
    #    if isinstance(attrs, str):
    #        attrs = [attrs]    
#
    #    if isinstance(result, AggregatedResult):
    #        msg = result.name
    #        print("{}{}{}{}".format(Style.BRIGHT, Fore.CYAN, msg, "*" * (80 - len(msg))))
    #        for host, host_data in sorted(result.items()):
    #            title = (
    #                ""
    #                if host_data.changed is None
    #                else " ** changed : {} ".format(host_data.changed)
    #            )
    #            msg = "* {}{}".format(host, title)
    #            print(
    #                "{}{}{}{}".format(Style.BRIGHT, Fore.BLUE, msg, "*" * (80 - len(msg)))
    #            )
    #            _print_result(host_data, attrs, failed, severity_level)
    #    elif isinstance(result, MultiResult):
    #        _print_individual_result(
    #            result[0],
    #            attrs,
    #            failed,
    #            severity_level,
    #            task_group=True,
    #            print_host=print_host,
    #        )
    #        for r in result[1:]:
    #            _print_result(r, attrs, failed, severity_level)
    #        color = _get_color(result[0], failed)
    #        msg = "^^^^ END {} ".format(result[0].name)
    #        if result[0].severity_level >= severity_level:
    #            print("{}{}{}{}".format(Style.BRIGHT, color, msg, "^" * (80 - len(msg))))
    #    elif isinstance(result, Result):
    #        _print_individual_result(
    #            result, attrs, failed, severity_level, print_host=print_host
    #        )    
    #
#
    #def print_result(
    #    result: Result,
    #    vars: List[str] = None,
    #    failed: bool = False,
    #    severity_level: int = logging.INFO,
    #) -> None:
    #    """
    #    Prints an object of type `nornir.core.task.Result`
    #    Arguments:
    #      result: from a previous task
    #      vars: Which attributes you want to print
    #      failed: if ``True`` assume the task failed
    #      severity_level: Print only errors with this severity level or higher
    #    """
#
    #    try:
    #        _print_result(result, vars, failed, severity_level, print_host=True)
    #    finally:
    #        print()
    #print_result(update_acls)
#
#
def process_update_acls_results(results: AggregatedResult) -> None:
    console = Console()
    update_acls_results = {}
    full_update_acls_results = {}
    try:
        for hostname, host_result in results.items():
            update_acls_results[hostname] = {}
            
    
            table = Table(box=box.MINIMAL_DOUBLE_HEAD)
            table.add_column(hostname, justify="right", style="cyan", no_wrap=True)
            table.add_column("result")
            table.add_column("changed")
    
            for r in host_result:
                text = Text()
                if r.failed:
                    update_acls_results[hostname][r.name]={}
                    update_acls_results[hostname][r.name]['result'] = "failed"
                    update_acls_results[hostname][r.name]['log'] = r.result
                    update_acls_results[hostname][r.name]['changed'] = r.changed
                    text.append(f"{r.exception}", style="red")
                elif r.result:
                    update_acls_results[hostname][r.name]={}
                    update_acls_results[hostname][r.name]['result'] = "passed"
                    update_acls_results[hostname][r.name]['log'] = r.result
                    update_acls_results[hostname][r.name]['changed'] = r.changed
    
                    text.append(f"{r.result or ''}", style="green") 
                else:
                    continue
    
                changed = Text()
                if r.changed:
                    color = "orange3"
                else:
                    color = "green"
                changed.append(f"{r.changed}", style=color)
                table.add_row(r.name, text, changed)
            full_update_acls_results[hostname] = copy.deepcopy(update_acls_results[hostname])
            full_update_acls_results[hostname]['table'] = table
    except:
        print("Nothing to process")
    return update_acls_results,full_update_acls_results