import re
from rich.console import Console
from rich.table import Table
from logging import exception
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

def dmpvn_per_tunnel(raw_input):

    result = {}

    for hostname, entry_1_level in raw_input.items():
        if entry_1_level[0].failed == False:
            result[hostname] = {}
            tunnels = re.findall('(Interface(?:.*\n)+?)(?=Interface|\Z)',str(entry_1_level[0]))
            #print(tunnels)
            result[hostname]['Tunnels']={}
            for tunnel in tunnels:
               #print(tunnel)
                tunnel_no = re.match('^Interface: Tunnel(\d+)',str(tunnel))
                tunnel_no=tunnel_no.group(1)
                entries = re.findall('(\s{5}\d\s.*)',str(tunnel))
                #print(entries)
                result[hostname]['Tunnels'][tunnel_no] = {}
                for entry in entries:
                    peer = re.match('\s+\d+\s+(\d+\.\d+\.\d+\.\d+)',entry).group(1)
                    tunnel_ip = re.match('\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+(\d+\.\d+\.\d+\.\d+)',entry).group(1)
                    state = re.match('\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+(\S+)',entry).group(1)
                    updn_time = re.match('\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+\s+(\S+)',entry).group(1)
                    
                    result[hostname]['Tunnels'][tunnel_no][peer]={}
                    result[hostname]['Tunnels'][tunnel_no][peer]['tunnel IP']=tunnel_ip
                    result[hostname]['Tunnels'][tunnel_no][peer]['state']=state
                    result[hostname]['Tunnels'][tunnel_no][peer]['UP/DOWN time']=updn_time
            #result[hostname]['Tunnels']=tunnels
    return result
def clean_facts(device_facts):
    #validate results
    failed_hosts = {}
    for hostname, entry_1_level in device_facts.items():
        if entry_1_level.failed == False:
            for data_pos in entry_1_level:
                if data_pos.result == '':
                    print(hostname+' is missing a result, adding to removal list')
                    failed_hosts[hostname] = str('missing a result '+str(data_pos))
                    break
        else:
            print(hostname+' failed, adding to removal list')
            failed_hosts[hostname] = str(device_facts[hostname][0].exception.result[0].exception.args[0].splitlines()[0])
    for host,reason in failed_hosts.items():
        print('Removing '+str(host)+' from device_facts......')
        device_facts.pop(host)
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

def get_tunnel_interfaces(raw_input):
    interfaces = {}
    for hostname, entry_1_level in raw_input.items():
        interfaces[hostname]={}
        #interfaces[hostname]['interfaces']={}
        for intfa,data in entry_1_level[0].result['interface'].items():
            interfaces[hostname][data['ip_address']]=intfa
    return interfaces

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
                except Exception as e:
                    versions[hostname]['router_type'] = 'Failed'
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return versions

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

def get_acls(raw_input,data_position = 0):
    device_acls = {}
    for hostname, entry_1_level in raw_input.items():
        try:
            if entry_1_level[0].failed == False:
                device_acls[hostname]={}
                try:
                    for acl,rules in entry_1_level[data_position].result.items():
                        if 'aces' in entry_1_level[data_position].result[acl]:
                            device_acls[hostname][acl]={}
                            device_acls[hostname][acl]['type']=entry_1_level[data_position].result[acl]['acl_type']
                            device_acls[hostname][acl]['rules']={}
                            try:
                                for rule,aces in entry_1_level[data_position].result[acl]['aces'].items():
                                    if 'destination_network' in entry_1_level[data_position].result[acl]['aces'][rule]['matches']['l3']['ipv4'].keys():
                                        for k,v in entry_1_level[data_position].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                            for k1,v1 in entry_1_level[data_position].result[acl]['aces'][rule]['matches']['l3']['ipv4']['destination_network'].items():
                                                device_acls[hostname][acl]['rules'][rule]=str(entry_1_level[data_position].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))+' '+str(re.sub(' 0.0.0.0','',k1))
                                    else:
                                        for k,v in entry_1_level[data_position].result[acl]['aces'][rule]['matches']['l3']['ipv4']['source_network'].items():
                                            device_acls[hostname][acl]['rules'][rule]=str(entry_1_level[data_position].result[acl]['aces'][rule]['actions']['forwarding'])+' '+str(re.sub(' 0.0.0.0','',k))           
                            except Exception as e:
                                device_acls[hostname][acl]['rules']=str(e)
                        else:
                            device_acls[hostname][acl]='No rules found'    
                except Exception as e:
                    device_acls[str(hostname)+' could not be processed']=str(e)
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return device_acls



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

def get_numbered_acls(raw_input,acl_numbers,new_acls,data_position = 0):
    numbered_acls = {}
    for hostname, entry_1_level in raw_input.items():
        if entry_1_level[0].failed == False:
            numbered_acls[hostname]={}
            numbered_acls[hostname]['sub_interface_acls']={}
            numbered_acls[hostname]['new_acls']={}
            for acl_no in acl_numbers[hostname]:
                try:
                    aclregex = '((?:access-list '+str(acl_no)+'.*(?:\n|\Z))+)'
                    lineregex = '(access-list '+str(acl_no)+'.*)'
                    acl = re.search(aclregex,str(entry_1_level[data_position]))
                    acl=acl.group(1)
                    acl_lines = re.findall(lineregex,str(acl))
                #print(tunnels)
                
                    numbered_acls[hostname]['sub_interface_acls'][acl_no]=acl_lines
                    numbered_acls[hostname]['sub_interface_acls'][str(acl_no+'-acl')]=acl
                except Exception as e:
                    #clair fails bcause it has an ACL applied to the interface but the acl is not defined in config
                    print(hostname+' failed to process acl '+acl_no+ ' with the following error:\n'+str(e)+'\nPlease check that ACL is configured correctly on the device')
            for acl_no in new_acls:
                try:
                    aclregex = '((?:access-list '+str(acl_no)+'.*(?:\n|\Z))+)'
                    lineregex = '(access-list '+str(acl_no)+'.*)'
                    acl = re.search(aclregex,str(entry_1_level[data_position]))
                    acl=acl.group(1)
                    acl_lines = re.findall(lineregex,str(acl))
                #print(tunnels)
                
                    numbered_acls[hostname]['new_acls'][acl_no]=acl_lines
                    numbered_acls[hostname]['new_acls'][str(acl_no+'-acl')]=acl
                except Exception as e:
                    #clair fails bcause it has an ACL applied to the interface but the acl is not defined in config
                    print(hostname+' failed to process acl '+acl_no+ ' with the following error:\n'+str(e)+'\nPlease check that ACL is configured correctly on the device')

    return numbered_acls



def build_dmvpntable(host):
    dmvpntable = Table(title= str(host) + ' DMVPN Check Summary',show_header=True, header_style="bold blue")
    dmvpntable.add_column('Spoke',justify='center')
    dmvpntable.add_column('Peer IP',justify='center')
    dmvpntable.add_column('Status',justify='center')
    dmvpntable.add_column('UP/DOWN Time',justify='center')
    dmvpntable.add_column('Spoke Status',justify='center')
    return dmvpntable
#========================================================================
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

def get_acls_old(acls) -> dict:
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

    