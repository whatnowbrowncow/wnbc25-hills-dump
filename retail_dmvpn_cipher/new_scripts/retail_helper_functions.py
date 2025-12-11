import re
from rich.console import Console
from rich.table import Table
from logging import exception
from nornir.core.task import AggregatedResult, MultiResult, Result
import copy
from rich.text import Text
from rich import box

def get_tunnel_interface_state(tunnel_data,data_position = 0):
    tunnels = {}
    for device,results in tunnel_data.items():
        tunnels[device] = {}
        for tun,data in results[data_position].result['interface'].items():
            tunnels[device][tun] = {}
            tunnels[device][tun]['ip_address'] = data['ip_address']
            tunnels[device][tun]['int_status'] = data['interface_status']
            tunnels[device][tun]['protocol_status'] = data['protocol_status']
    return tunnels

def dmpvn_per_tunnel(raw_input,data_position = 0):

    result = {}

    for hostname, entry_1_level in raw_input.items():
        if entry_1_level[0].failed == False:
            result[hostname] = {}
            tunnels = re.findall('(Interface(?:.*\n)+?)(?=Interface|\Z)',str(entry_1_level[data_position].result))
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

def clean_facts_single_result(device_facts):
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
            failed_hosts[hostname] = str(device_facts[hostname][0].exception.args[0].splitlines()[0])
    for host,reason in failed_hosts.items():
        print('Removing '+str(host)+' from device_facts......')
        device_facts.pop(host)
    return device_facts,failed_hosts

def get_tunnel_interface_data(raw_input,data_position = 0):
    interfaces = {}
    for hostname, entry_1_level in raw_input.items():
        try:
            if entry_1_level[0].failed == False:
                interfaces[hostname] = {}
                tunnels = re.findall('(interface Tunnel\d+(?:\n\s+.*)+)',str(entry_1_level[data_position].result))
                for tunnel in tunnels:
                    tunnel_no = re.match('^interface (Tunnel\d+)',str(tunnel))
                    tunnel_no=tunnel_no.group(1)
                    interfaces[hostname][tunnel_no]={}
                    ip =  re.search(' ip address (.*)',str(tunnel))
                    interfaces[hostname][tunnel_no]['ip config'] = ip.group(1)
                    description =  re.search(' description (.*)',str(tunnel))
                    interfaces[hostname][tunnel_no]['description'] = description.group(1)
                    mtu= re.search(' ip mtu (\d+)',str(tunnel))
                    interfaces[hostname][tunnel_no]['mtu'] = mtu.group(1)
                    try:
                        profile =  re.search(' tunnel protection ipsec profile (.*) shared',str(tunnel))
                        interfaces[hostname][tunnel_no]['profile'] = profile.group(1)
                    except:
                        interfaces[hostname][tunnel_no]['profile'] = 'None'
        except Exception as e:
            print(hostname+' failed this task with the following error:\n'+str(e))
    return interfaces

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

def get_hardware_type(raw_input,data_position = 0):
    hardware_type = {}
    for hostname, entry_1_level in raw_input.items():
            for version,data in entry_1_level[data_position].result.items():
                hardware_type[hostname] = data['rtr_type']
    return hardware_type

def get_lan_interface(raw_input,data_position = 0):
    lan_interfaces = {}
    for hostname, entry_1_level in raw_input.items():
        for intfa,data in entry_1_level[data_position].result.items():
            if '.160' in intfa:
                lan_interfaces[hostname]=intfa
                
    return lan_interfaces

def spoke_eigrp_neighbours(eigrp,data_position = 0):
    eigrp_neighbours = {}
    for device,results in eigrp.items():
        eigrp_neighbours[device] = {}
        eigrp_neighbours[device]['neighbours'] = {}
        for inst,data in results[data_position].result['eigrp_instance'].items():
            for int, eigrp_nbr in data['vrf']['default']['address_family']['ipv4']['eigrp_interface'].items():
                #print(device)
                #print(int)
                #print('number of neighbours:')
                #print(len(list(eigrp_nbr['eigrp_nbr'])))
                for nbr in list(eigrp_nbr['eigrp_nbr']):
                    eigrp_neighbours[device]['neighbours'][nbr] = {}
                    eigrp_neighbours[device]['neighbours'][nbr]['uptime'] = eigrp_nbr['eigrp_nbr'][nbr]['uptime']
                    eigrp_neighbours[device]['neighbours'][nbr]['interface'] = int
    return eigrp_neighbours

def parse_crypto(crypto,data_position_1 = 0,data_position_2 = 0):
    crypto_config = {}

    for hostname, result in crypto.items():
        if result[0].failed == False:
            crypto_config[hostname] = {}
            crypto_config[hostname]['policies'] = {}
            crypto_config[hostname]['keys'] = {}
            crypto_config[hostname]['tf_sets'] = {}
            crypto_config[hostname]['profiles'] = {}
            isakmp_policies = re.findall('crypto isakmp policy \d+(?:\n\s+.*)+',str(result[data_position_1].result))
            isakmp_keys = re.findall('crypto isakmp key .*',str(result[data_position_2]))
            transform_sets = re.findall('crypto ipsec transform-set .*(?:\n\s+.*)+',str(result[data_position_1].result))
            ipsec_profiles = re.findall('crypto ipsec profile.*(?:\n\s+.*)+',str(result[data_position_1].result))
            for policy in isakmp_policies:
                policy_no = re.match('crypto isakmp policy (\d+)',str(policy))
                crypto_config[hostname]['policies'][policy_no.group(1)] = {}
                encryption = re.search(' (?:encr|encryption) (.*)',str(policy))
                crypto_config[hostname]['policies'][policy_no.group(1)]['encryption'] = encryption.group(1)
                try:
                    crypto_config[hostname]['policies'][policy_no.group(1)]['hash'] = re.search(' hash (.*)',str(policy)).group(1)
                except:
                    crypto_config[hostname]['policies'][policy_no.group(1)]['hash'] = 'sha'
                #crypto_config[hostname]['policies'][policy_no.group(1)]['hash'] = hash.group(1)
                group = re.search('group (\d+)',str(policy))
                try:
                    crypto_config[hostname]['policies'][policy_no.group(1)]['group'] = group.group(1)
                except:
                    crypto_config[hostname]['policies'][policy_no.group(1)]['group'] = 'None'
                auth = re.search('authentication (\S+)',str(policy))
                try:
                    crypto_config[hostname]['policies'][policy_no.group(1)]['authentication'] = auth.group(1)
                except:
                    crypto_config[hostname]['policies'][policy_no.group(1)]['authentication'] = 'None'
            for key in isakmp_keys:
                crypto_key = re.match('crypto isakmp key (\S+)',key).group(1)
                address = re.match('crypto isakmp key \S+ address (\d+\.\d+\.\d+\.\d+)',key).group(1)
                crypto_config[hostname]['keys'][address]=crypto_key
            for tfs in transform_sets:
                tfs_name = re.match('crypto ipsec transform-set (\S+)',tfs).group(1)
                tfs_set = re.match('crypto ipsec transform-set \S+ (.*) ',tfs).group(1)
                tfs_mode = re.search('mode (\S+)',tfs).group(1)
                crypto_config[hostname]['tf_sets'][tfs_name] = {}
                crypto_config[hostname]['tf_sets'][tfs_name]['set'] = tfs_set
                crypto_config[hostname]['tf_sets'][tfs_name]['mode'] = tfs_mode
            for profile in ipsec_profiles:
                profile_name = re.match('crypto ipsec profile (\S+)',profile).group(1)
                if profile_name == "default":
                    continue
                lifetime = re.search('set security-association lifetime seconds (\d+)',profile).group(1)
                transform_set = re.search('set transform-set (\S+)',profile).group(1)
                try:
                    pfs = re.search('set pfs (\S+)',profile).group(1)
                except:
                    pfs = 'None'
                crypto_config[hostname]['profiles'][profile_name] = {}
                crypto_config[hostname]['profiles'][profile_name]['lifetime'] = lifetime
                crypto_config[hostname]['profiles'][profile_name]['transform set'] = transform_set
                crypto_config[hostname]['profiles'][profile_name]['pfs'] = pfs

    return crypto_config


def build_dmvpntable(host):
    dmvpntable = Table(title= str(host) + ' DMVPN Check Summary',show_header=True, header_style="bold blue")
    dmvpntable.add_column('Spoke',justify='center')
    dmvpntable.add_column('Peer IP',justify='center')
    dmvpntable.add_column('Status',justify='center')
    dmvpntable.add_column('UP/DOWN Time',justify='center')
    dmvpntable.add_column('Spoke Status',justify='center')
    return dmvpntable

def process_update_results(results: AggregatedResult) -> None:
    console = Console()
    update_results = {}
    full_update_results = {}
    try:
        for hostname, host_result in results.items():
            update_results[hostname] = {}
            
    
            table = Table(box=box.MINIMAL_DOUBLE_HEAD)
            table.add_column(hostname, justify="right", style="cyan", no_wrap=True)
            table.add_column("result")
            table.add_column("changed")
    
            for r in host_result:
                text = Text()
                if r.failed:
                    update_results[hostname][r.name]={}
                    update_results[hostname][r.name]['result'] = "failed"
                    update_results[hostname][r.name]['log'] = r.result
                    update_results[hostname][r.name]['changed'] = r.changed
                    text.append(f"{r.exception}", style="red")
                elif r.result:
                    update_results[hostname][r.name]={}
                    update_results[hostname][r.name]['result'] = "passed"
                    update_results[hostname][r.name]['log'] = r.result
                    update_results[hostname][r.name]['changed'] = r.changed
    
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
            full_update_results[hostname] = copy.deepcopy(update_results[hostname])
            full_update_results[hostname]['table'] = table
    except:
        print("Nothing to process")
    return update_results,full_update_results

