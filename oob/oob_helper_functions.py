import re
from rich.console import Console
from rich.table import Table

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
                except Exception as e:
                    versions[hostname]['router_type'] = 'Failed'
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return versions


    for hostname, result in crypto.items():
        if result[0].failed == False:
            crypto_config[hostname] = {}
            crypto_config[hostname]['policies'] = {}
            crypto_config[hostname]['keys'] = {}
            crypto_config[hostname]['tf_sets'] = {}
            crypto_config[hostname]['profiles'] = {}
            isakmp_policies = re.findall('crypto isakmp policy \d+(?:\n\s+.*)+',str(result[0]))
            isakmp_keys = re.findall('crypto isakmp key .*',str(result[0]))
            transform_sets = re.findall('crypto ipsec transform-set .*(?:\n\s+.*)+',str(result[0]))
            ipsec_profiles = re.findall('crypto ipsec profile.*(?:\n\s+.*)+',str(result[0]))
            for policy in isakmp_policies:
                policy_no = re.match('crypto isakmp policy (\d+)',str(policy))
                crypto_config[hostname]['policies'][policy_no.group(1)] = {}
                encryption = re.search(' encr (.*)',str(policy))
                crypto_config[hostname]['policies'][policy_no.group(1)]['encryption'] = encryption.group(1)


def get_licence(raw_input,data_position = 0):
    licences = {}
    for hostname, entry_1_level in raw_input.items():
        try:
            if entry_1_level[0].failed == False:
                licences[hostname]={}
                #interfaces[hostname]['interfaces']={}
                try:

                    licence_matches = re.findall('Index \d+ Feature: (\S+).*\n\s+Period left: (.*)\n(\s+License Type: (\S+)|(?:\s+.*\n)\s+License Type: (\S+))',str(entry_1_level[data_position].result))
                    for license in licence_matches:
                        try:
                            if license[3] != '':
                                licences[hostname][str(license[0])] = {}
                                licences[hostname][str(license[0])]['Type'] = license[3]
                                licences[hostname][str(license[0])]['Period left'] = license[1]
                            if license[4] != '':
                                licences[hostname][str(license[0])] = {}
                                licences[hostname][str(license[0])]['Type'] = license[4]
                                licences[hostname][str(license[0])]['Period left'] = license[1]
                        except:
                            continue
                    print(licence_matches)
                    print(licences)
                        #licences[hostname]['hostname'] = data['hostname']
                        #licences[hostname]['version'] = data['version_short']
                        #licences[hostname]['router_type'] = data['rtr_type']
                except Exception as e:
                    licences[hostname]['router_type'] = 'Failed'
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return licences

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
                    continue
                    #clair fails bcause it has an ACL applied to the interface but the acl is not defined in config
                    #print(hostname+' failed to process acl '+acl_no+ ' with the following error:\n'+str(e)+'\nIt appears that the new ACL is not configured on the device')

    return numbered_acls 

def dmvpn_per_tunnel(raw_input):

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

def build_dmvpntable(host):
    dmvpntable = Table(title= str(host) + ' DMVPN Check Summary',show_header=True, header_style="bold blue")
    dmvpntable.add_column('Spoke',justify='center')
    dmvpntable.add_column('Peer IP',justify='center')
    dmvpntable.add_column('Status',justify='center')
    dmvpntable.add_column('UP/DOWN Time',justify='center')
    dmvpntable.add_column('Spoke Status',justify='center')
    return dmvpntable

def get_tunnel_interfaces(raw_input):
    interfaces = {}
    for hostname, entry_1_level in raw_input.items():
        interfaces[hostname]={}
        #interfaces[hostname]['interfaces']={}
        for intfa,data in entry_1_level[0].result['interface'].items():
            interfaces[hostname][data['ip_address']]=intfa
    return interfaces 