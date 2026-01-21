import re
from datetime import datetime
import json
def clean_facts(device_facts):
    #validate results
    failed_hosts = {}
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
    return device_facts,failed_hosts

def parse_pings(pings,data_position_1 = 0,data_position_2 = 0):
    #ping_results = {}
    with open('/dbdev/nornir/krk_latency.json') as json_file: 
        ping_results=json.load(json_file)
    curtime = str(datetime.now().strftime('%Y_%m_%d___%H_%M_%S'))
    for hostname, result in pings.items():
        if result[0].failed == False:
            ping_results[hostname]['sov'][curtime] = {}
            ping_results[hostname]['ld6'][curtime] = {}
            ping_results[hostname]['sov'][curtime]['output'] = str(result[data_position_1].result)
            ping_results[hostname]['ld6'][curtime]['output'] = str(result[data_position_2].result)
            sov_success_rate = re.search('Success rate is (\d+)',str(result[data_position_1].result))
            sov_success_rate =sov_success_rate.group(1)
            sov_min_max_avg = re.search('Success rate is \d+ percent .*max = (.*) ms',str(result[data_position_1].result))
            sov_min_max_avg =sov_min_max_avg.group(1)
            ping_results[hostname]['sov'][curtime]['success rate'] = sov_success_rate
            ping_results[hostname]['sov'][curtime]['mix_max_avg'] = sov_min_max_avg
            ld6_success_rate = re.search('Success rate is (\d+)',str(result[data_position_2].result))
            ld6_success_rate =ld6_success_rate.group(1)
            ld6_min_max_avg = re.search('Success rate is \d+ percent .*max = (.*) ms',str(result[data_position_2].result))
            ld6_min_max_avg =ld6_min_max_avg.group(1)
            ping_results[hostname]['ld6'][curtime]['success rate'] = ld6_success_rate
            ping_results[hostname]['ld6'][curtime]['mix_max_avg'] = ld6_min_max_avg            

    return ping_results

def parse_vmb_pings(pings,data_position_1 = 0,data_position_2 = 0):
    #ping_results = {}
    with open('/dbdev/nornir/vmb_latency.json') as json_file: 
        ping_results=json.load(json_file)
    curtime = str(datetime.now().strftime('%Y_%m_%d___%H_%M_%S'))
    for hostname, result in pings.items():
        if result[0].failed == False:
            ping_results[hostname]['sov'][curtime] = {}
            ping_results[hostname]['scc'][curtime] = {}
            ping_results[hostname]['sov'][curtime]['output'] = str(result[data_position_1].result)
            ping_results[hostname]['scc'][curtime]['output'] = str(result[data_position_2].result)
            sov_success_rate = re.search('Success rate is (\d+)',str(result[data_position_1].result))
            sov_success_rate =sov_success_rate.group(1)
            sov_min_max_avg = re.search('Success rate is \d+ percent .*max = (.*) ms',str(result[data_position_1].result))
            sov_min_max_avg =sov_min_max_avg.group(1)
            ping_results[hostname]['sov'][curtime]['success rate'] = sov_success_rate
            ping_results[hostname]['sov'][curtime]['mix_max_avg'] = sov_min_max_avg
            scc_success_rate = re.search('Success rate is (\d+)',str(result[data_position_2].result))
            scc_success_rate =scc_success_rate.group(1)
            scc_min_max_avg = re.search('Success rate is \d+ percent .*max = (.*) ms',str(result[data_position_2].result))
            scc_min_max_avg =scc_min_max_avg.group(1)
            ping_results[hostname]['scc'][curtime]['success rate'] = scc_success_rate
            ping_results[hostname]['scc'][curtime]['mix_max_avg'] = scc_min_max_avg            

    return ping_results

def _normalise_data(raw_input, unique_field: int, mapping: dict, filter: list, add_host: bool = False) -> dict:
    """
    This helper functions allows to convery semi-formatted text into a structure
    dictionary by choosing a key field and other important fields for nested data.
    """
    result = {}

    for hostname, entry_1_level in raw_input.items():
        result[hostname] = {}
        for entry_2_level in str(entry_1_level[0]).splitlines():
            list_3_level = entry_2_level.split()

            try:
                if list_3_level[unique_field] not in result[hostname] and list_3_level[unique_field] not in filter:
                    if "interface" not in mapping or not re.match(r'.*Po.*',list_3_level[mapping["interface"]]):
                        key_field = list_3_level[unique_field] if not add_host else f"{hostname},{list_3_level[unique_field]}"

                        result[hostname].update({key_field: {}})

                        for key_name, key_index in mapping.items():
                            value = f"{hostname},{list_3_level[key_index]}" if key_name == "interface" else list_3_level[key_index]
                            result[hostname][key_field].update({key_name: value})

            except:
                pass

    return result
def get_ints(raw_input):
    ints = {}
    for hostname, interfaces in raw_input.items():
        print(hostname+":")
        ints[hostname]={}
        
        for interface, details in interfaces.scrapli_response.genie_parse_output().items():
            if "ipv4" in details:
                print("interface with IP found")
                print("interface: "+ interface)
                #print(details)
                print(details['ipv4'])
                for k in details['ipv4']:
                    print("IP address: "+ details['ipv4'][k]['ip'])
                    print("adding to dict......")
                    ints[hostname][interface]={}
                    ints[hostname][interface]['ip_address']=details['ipv4'][k]['ip']
                if "description" in details:
                    print("interface description found")
                    print("Description: "+ details['description'])
                    print("adding to dict......")
                    ints[hostname][interface]['description']=details['description']
    return ints

def get_ip_ints(raw_input):
    ip_ints = {}
    for hostname, interfaces in raw_input.items():
        print(hostname+":")
        ip_ints[hostname]={}
        
        for interface, details in interfaces.scrapli_response.genie_parse_output()['interface'].items():
            if details['ip_address'] != "unassigned":
                print("interface with IP found found")
                print("interface: "+ interface)
                print("IP address: "+ details['ip_address'])
                print("adding to dict......")
                ip_ints[hostname][interface]={}
                ip_ints[hostname][interface]['ip_address']=details['ip_address']
    return ip_ints

def get_ip_int_descs(raw_input, ip_ints):
    ip_descs = {}
    for hostname, interfaces in ip_ints.items():
        print(hostname+":")
        for interface, details in interfaces.items():
            if interface in raw_input[hostname].scrapli_response.genie_parse_output()["interfaces"].keys(): 
                print("adding description to "+interface)
                ip_ints[hostname][interface]["description"] = raw_input[hostname].scrapli_response.genie_parse_output()["interfaces"][interface]["description"]

def get_acls(acls) -> dict:
    """
    This helper function performs conversion of the ARP table into a dictionary.
    """
    return _normalise_data(raw_input=acls,
                           unique_field=1,
                           mapping={},
                           filter=[])

def get_unique_users(user_table) -> dict:
    """
    This helper function performs conversion of the ARP table into a dictionary.
    """
    return _normalise_data(raw_input=user_table,
                           unique_field=1,
                           mapping={"username": 1,"privilege":3},
                           filter=[])

def get_unique_hosts(arp_table) -> dict:
    """
    This helper function performs conversion of the local users on each device into a dictionary.
    """
    return _normalise_data(raw_input=arp_table,
                           unique_field=1,
                           mapping={"mac": 3},
                           filter=["Address"])


def match_ip_mac_port_description(arp_table: dict, mac_table, interfaces_table) -> dict:
    """
    This helper function performs conversion of the MAC address tables,
    interfaces description table, and collected ARP in a singe dictionary.
    """
    result = arp_table

    normailed_mac_table = _normalise_data(raw_input=mac_table,
                                          unique_field=1,
                                          mapping={"vlan": 0, "interface": -1},
                                          filter=["Entries", "mac", "EOF", "ffff.ffff.ffff"])


    normalized_interface_table = _normalise_data(raw_input=interfaces_table,
                                                 unique_field=0,
                                                 mapping={"description": -1},
                                                 filter=["Interface"],
                                                 add_host=True)

    for ip_entry, ip_var in arp_table.items():
        to = {}

        if ip_var["mac"] in normailed_mac_table:
            pre_normalized_interface = normailed_mac_table[ip_var["mac"]]["interface"].split(",")
            normalized_interface_name = pre_normalized_interface[0] + "," + pre_normalized_interface[1]#[0:2] + re.sub(r'^\D+(\d?/?\d+)$', r'\1',   pre_normalized_interface[1])
            if normalized_interface_name in normalized_interface_table and not re.match(r'.*Po.*', pre_normalized_interface[1]):
                to= {
                        "switch": pre_normalized_interface[0],
                        "interface": pre_normalized_interface[1],
                        "vlan": int(normailed_mac_table[ip_var["mac"]]["vlan"]),
                        "server": normalized_interface_table[normalized_interface_name]["description"]
                    }

        if not to:
            to= {
                    "switch": None,
                    "interface": None,
                    "vlan": None,
                    "server": None
                }

        result[ip_entry].update(to)

    return result

    