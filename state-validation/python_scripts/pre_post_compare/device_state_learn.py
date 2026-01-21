from genie.testbed import load
from genie.utils.diff import Diff
from datetime import datetime
from rich.console import Console
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    SpinnerColumn,
)
import time
import json
import os

console = Console()

def progress_bar(count):
    if count == True:
        progress = Progress("•",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.1f}%",
        TextColumn("[blue][progress.description]{task.description}:"),
        "[cyan][progress.completed]{task.completed}[/cyan]",
        SpinnerColumn())
        return progress
    else:
        progress = Progress("•",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.1f}%",
        TextColumn("[blue][progress.description]{task.description}"),
        SpinnerColumn())
        return progress

def device_state_learn(target_device,max_routes,snapshot):
    # load the testbed file
    testbed = load('./testbed_files/wh-testbed.yml')
    print()
    console.print('[dim yellow]Gathering state data for[/dim yellow] [bold yellow]{}[/bold yellow][dim yellow], this may take a few minutes...........[/dim yellow]'.format(target_device))
    print()
    
    #create a master dictionary for storing device data
    master_dict = {}
    #Loop through devices
    #target_device = 'uk-brs-cr01'
    
    # print the device and connect and run commands (supress log output)
    #print()
    #console.print('[yellow dim]Checking {}'.format(target_device))
    #print()
    csr = testbed.devices[target_device]
    csr.connect(log_stdout=False, init_exec_commands=[], init_config_commands=[])
    #set device name with 'pre' prefix
    device = str(target_device) + '-' + str(snapshot)
    #setup dictionary structure
    master_dict[device] = {}
    master_dict[device]['os'] = testbed.devices[target_device].os


    ############## VRFS ############
    master_dict[device]['vrfs'] = {}

    vrfs = []
    #console.print('Gathering VRF information')
    try:
        vrfslearn = csr.learn('vrf')
        vrf_progress = progress_bar(True)
        with vrf_progress:
            task1 = vrf_progress.add_task('Gathering VRF information - VRFs',total=len(vrfslearn.info['vrfs'].keys()))
            for vrf in vrfslearn.info['vrfs'].keys():
                vrfs.append(vrf)
                master_dict[device]['vrfs'][vrf] = {}
                master_dict[device]['vrfs'][vrf]['routing'] = {}        
                master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}
                master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = {}
                master_dict[device]['vrfs'][vrf]['routing']['ospf'] = {}
            #while not vrf_progress.finished:
                vrf_progress.update(task1, advance=1)
                time.sleep(0.02)
    except Exception as e:
        vrf_progress = progress_bar(True)
        with vrf_progress:
            task1 = vrf_progress.add_task('Gathering VRF information - VRFs',total=1)
            vrf_progress.update(task1, advance=1)
    

    ####### CDP ######

    try:
        master_dict[device]['cdp'] = csr.parse('show cdp neighbors detail')
    except:
        master_dict[device]['cdp'] = {}

    ########## VLANS ##########

    try:
        vlans = csr.learn('vlan')
    except:
        vlans = {}
    try:
        master_dict[device]['vlans'] = vlans.info['vlans']
    except:
        master_dict[device]['vlans'] = 'N/A'

    #####MAC ADDRESS DATA#############
    #gather MAC address data
    try:
        mac_table = csr.parse('show mac address-table')
    except:
        mac_table = 'N/A'
    #print(mac_table)
    master_dict[device]['mac_table'] = {}
    
    if mac_table != 'N/A' and '-' not in mac_table['mac_table']['vlans'].keys():
        #print('Gathering MAC data')
        mac_progress = progress_bar(False)
        with mac_progress:
            task1 = mac_progress.add_task('Gathering MAC address data',total=len(mac_table['mac_table']['vlans']))
            for vlan in mac_table['mac_table']['vlans']:
                for mac in mac_table['mac_table']['vlans'][vlan]['mac_addresses']:
                    if mac not in master_dict[device]['mac_table'].keys():
                        master_dict[device]['mac_table'][mac] = {}
                    master_dict[device]['mac_table'][mac]['mac_address'] = mac_table['mac_table']['vlans'][vlan]['mac_addresses'][mac]['mac_address']
                    master_dict[device]['mac_table'][mac]['vlans'] = []
                    master_dict[device]['mac_table'][mac]['vlans'].append(vlan)
                    master_dict[device]['mac_table'][mac]['interfaces'] = []
                    for int in mac_table['mac_table']['vlans'][vlan]['mac_addresses'][mac]['interfaces']:
                        master_dict[device]['mac_table'][mac]['interfaces'].append(int)
                    master_dict[device]['mac_table'][mac]['cdp_neighbors'] = {}
                mac_progress.update(task1, advance=1)
            if 'index' in master_dict[device]['cdp'].keys():
                for mac in master_dict[device]['mac_table']:
                    for index in master_dict[device]['cdp']['index']:
                        if master_dict[device]['cdp']['index'][index]['local_interface'] in master_dict[device]['mac_table'][mac]['interfaces']:
                            master_dict[device]['mac_table'][mac]['cdp_neighbors']['device'] = master_dict[device]['cdp']['index'][index]['device_id']
                            master_dict[device]['mac_table'][mac]['cdp_neighbors']['remote_interface'] = master_dict[device]['cdp']['index'][index]['port_id']
        
                for neigh in master_dict[device]['cdp']['index']:
                    for mac in master_dict[device]['mac_table']:
                        for int in master_dict[device]['mac_table'][mac]['interfaces']:
                            if int == master_dict[device]['cdp']['index'][neigh]['local_interface']:
                                master_dict[device]['cdp']['index'][neigh]['mac_address'] = mac

    
    ##### NXOS TASKS #######

    if testbed.devices[target_device].os == 'nxos':
        

        ############# ROUTING ##########

        #print('Gathering OSPF data')
        ospf_progress = progress_bar(False)
        with ospf_progress:
            task1 = ospf_progress.add_task('Gathering OSPF data',total=1)
        #for a in track(range (1)):
            try:
                ospf = csr.learn('ospf')
            except:
                ospf = 'N/A'
            ospf_progress.update(task1, advance=1)
        #print('Gathering EIGRP data')
        eigrp_progress = progress_bar(False)
        with eigrp_progress:
            task1 = eigrp_progress.add_task('Gathering EIGRP data',total=1)
        #for a in track(range (1)):
            try:
                eigrp = csr.learn('eigrp')
            except:
                eigrp = 'N/A'
            eigrp_progress.update(task1, advance=1)
        #print('Gathering routing data')
        routing_progress = progress_bar(False)
        with routing_progress:
            task1 = routing_progress.add_task('Gathering Routing data',total=1)
        #for a in track(range (1)):
            try:
                routes = csr.learn('routing')
            except:
                routes = 'N/A'
            routing_progress.update(task1, advance=1)
        
        #print('Gathering routing data per VRF')
        vrf_route_progress = progress_bar(True)
        with vrf_route_progress:
            task1 = vrf_route_progress.add_task('Gathering routing data per VRF - VRFs',total=len(vrfs))
            for vrf in vrfs:
                try:
                    route_sum = csr.parse('show ip route summary vrf '+ vrf)
                except:
                    route_sum= {}
                    route_sum['vrf'] = {}
                    route_sum['vrf'][vrf] = {}
                    route_sum['vrf'][vrf]['total_routes'] = 0
                master_dict[device]['vrfs'][vrf]['routing']['total_routes'] = route_sum['vrf'][vrf]['total_routes']
                if route_sum['vrf'][vrf]['total_routes'] < max_routes:
                    try:
                        master_dict[device]['vrfs'][vrf]['routing']['routes'] = routes.info['vrf'][vrf]
                    except:
                        master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}
                master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort'] = {}
                master_dict[device]['vrfs'][vrf]['routing']['default_hop'] = []
                #print('###########' + vrf + '##########')
                #print()
                if 'address_family' in master_dict[device]['vrfs'][vrf]['routing']['routes'].keys():
                    #print(vrf + ' has ' + str(len(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes'])) + ' routes')
                    if '0.0.0.0/0' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']:
                        master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['gateway'] = master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][1]['next_hop']
                        master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['to_network'] = '0.0.0.0'
                        for hop in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list']:
                            master_dict[device]['vrfs'][vrf]['routing']['default_hop'].append(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][hop]['next_hop'])
                    else:
                        master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['gateway'] = 'not set'
    
                if ospf != 'N/A':
                    try:
                        master_dict[device]['vrfs'][vrf]['routing']['ospf'] = ospf.info['vrf'][vrf]
                    except:
                        master_dict[device]['vrfs'][vrf]['routing']['ospf'] = {}
                if hasattr(eigrp,'info'):
                    master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = {}
                    for inst in eigrp.info['eigrp_instance']:
                        if vrf in eigrp.info['eigrp_instance'][inst]['vrf'].keys():
                            master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'] = {}
                            master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst] = eigrp.info['eigrp_instance'][inst]['vrf'][vrf]
                else:
                     master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = {}       
            #master_dict[device]['eigrp']['default'] = csr.learn('eigrp')
                vrf_route_progress.update(task1, advance=1)

        #print('Gathering version data')
        ver_progress = progress_bar(False)
        with ver_progress:
            task1 = ver_progress.add_task('Gathering version data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['version_data'] = csr.parse('show version')
            except:
                master_dict[device]['version_data'] = 'N/A'
            ver_progress.update(task1, advance=1)
        #print('Gathering Boot data')
        boot_progress = progress_bar(False)
        with boot_progress:
            task1 = boot_progress.add_task('Gathering boot data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['boot_data'] = csr.parse('show boot')
            except:
                master_dict[device]['boot_data'] = 'N/A'
            boot_progress.update(task1, advance=1)
        #print('Gathering Etherchannel data')
        #for a in track(range (1)):
        #    #try:
        #        #master_dict[device]['Etherchannel_data'] = csr.parse('show etherchannel summary')
        #    #except:
        master_dict[device]['Etherchannel_data'] = 'N/A'
        master_dict[device]['switch_data'] = 'N/A'  

    ######## INTERFACES ##########
        

        master_dict[device]['interfaces'] = {}
        interfaces = csr.parse('show interface')
        
        int_progress = progress_bar(True)
        with int_progress:
            task1 = int_progress.add_task('Gathering interface data - Interfaces',total=len(interfaces))
        
        
            for inf in interfaces:
                infpath = interfaces[inf]
                master_dict[device]['interfaces'][inf] = {}
                try:
                    master_dict[device]['interfaces'][inf]['oper_status'] = infpath['oper_status']
                except:
                    print(inf + ' has no operational status, skipping ')
                    int_progress.update(task1, advance=1)
                    time.sleep(0.1)
                if 'description' in infpath.keys():
                    master_dict[device]['interfaces'][inf]['description'] = infpath['description']
                else:
                    master_dict[device]['interfaces'][inf]['description'] = 'Not configured'
                if 'type' in infpath.keys():            
                    master_dict[device]['interfaces'][inf]['type'] = infpath['ethertype']
                else:
                    master_dict[device]['interfaces'][inf]['type'] = 'Not recorded'
                if 'ipv4' in infpath.keys():
                    for pfix in infpath['ipv4']:
                        master_dict[device]['interfaces'][inf]['IP'] = infpath['ipv4'][pfix]['ip']
                else:
                    master_dict[device]['interfaces'][inf]['IP'] = 'Not configured'
                if 'index' in master_dict[device]['cdp'].keys(): 
                    for cdpnbr in master_dict[device]['cdp']['index']:
                        if 'local_interface' in master_dict[device]['cdp']['index'][cdpnbr].keys() and master_dict[device]['cdp']['index'][cdpnbr]['local_interface'].lower() == inf.lower():
                            cdppath = master_dict[device]['cdp']['index'][cdpnbr]
                            master_dict[device]['interfaces'][inf]['cdp'] = {}
                            master_dict[device]['interfaces'][inf]['cdp']['device_id'] = cdppath['device_id']
                            master_dict[device]['interfaces'][inf]['cdp']['local_interface'] = cdppath['local_interface']
                            master_dict[device]['interfaces'][inf]['cdp']['platform'] = cdppath['platform']
                            master_dict[device]['interfaces'][inf]['cdp']['remote_port'] = cdppath['port_id']
                int_progress.update(task1, advance=1)
                time.sleep(0.1)
    ###### IOS TASKS ######


    elif testbed.devices[target_device].os == 'ios':
        
        vrfs.append('default')
        master_dict[device]['vrfs']['default'] = {}
        master_dict[device]['vrfs']['default']['routing'] = {}
        master_dict[device]['vrfs']['default']['routing']['routes'] = {}
        #print('Gathering version data')
        ver_progress = progress_bar(False)
        with ver_progress:
            task1 = ver_progress.add_task('Gathering version data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['version_data'] = csr.parse('show version')
            except:
                master_dict[device]['version_data'] = 'N/A'
            ver_progress.update(task1, advance=1)
        #print('Gathering Boot data')
        boot_progress = progress_bar(False)
        with boot_progress:
            task1 = boot_progress.add_task('Gathering boot data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['boot_data'] = csr.parse('show boot')
            except:
                master_dict[device]['boot_data'] = 'N/A'
            boot_progress.update(task1, advance=1)
        #print('Gathering switch data')
        switch_progress = progress_bar(False)
        with switch_progress:
            task1 = switch_progress.add_task('Gathering switch data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['switch_data'] = csr.parse('show switch')
            except:
                master_dict[device]['switch_data'] = 'N/A'
            switch_progress.update(task1, advance=1)
        #print('Gathering Etherchannel data')
        eth_progress = progress_bar(False)
        with eth_progress:
            task1 = eth_progress.add_task('Gathering etherchannel data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['Etherchannel_data'] = csr.parse('show etherchannel summary')
            except:
                master_dict[device]['Etherchannel_data'] = 'N/A'
            eth_progress.update(task1, advance=1)

    ######### INTERFACES ########

        
        master_dict[device]['interfaces'] = {}
        #print('Gathering interface data')
        interfaces = csr.learn('interface')
        int_progress = progress_bar(True)
        with int_progress:
            task1 = int_progress.add_task('Gathering interface data - Interfaces',total=len(interfaces.info))
            for inf in interfaces.info:
                infpath = interfaces.info[inf]
                master_dict[device]['interfaces'][inf] = {}
                try:
                    master_dict[device]['interfaces'][inf]['oper_status'] = infpath['oper_status']
                except:
                    int_progress.update(task1, advance=1)
                    time.sleep(0.1)
                if 'description' in infpath.keys():
                    master_dict[device]['interfaces'][inf]['description'] = infpath['description']
                else:
                    master_dict[device]['interfaces'][inf]['description'] = 'Not configured'
                if 'type' in infpath.keys():            
                    master_dict[device]['interfaces'][inf]['type'] = infpath['type']
                else:
                    master_dict[device]['interfaces'][inf]['type'] = 'Not recorded'
                if 'ipv4' in infpath.keys():
                    for pfix in infpath['ipv4']:
                        try:
                            master_dict[device]['interfaces'][inf]['IP'] = infpath['ipv4'][pfix]['ip']
                        except:
                            master_dict[device]['interfaces'][inf]['IP'] = None
                else:
                    master_dict[device]['interfaces'][inf]['IP'] = 'Not configured'
                
                if 'index' in master_dict[device]['cdp'].keys(): 
                    for cdpnbr in master_dict[device]['cdp']['index']:
                        if 'local_interface' in master_dict[device]['cdp']['index'][cdpnbr].keys() and master_dict[device]['cdp']['index'][cdpnbr]['local_interface'].lower() == inf.lower():
                            cdppath = master_dict[device]['cdp']['index'][cdpnbr]
                            master_dict[device]['interfaces'][inf]['cdp'] = {}
                            master_dict[device]['interfaces'][inf]['cdp']['device_id'] = cdppath['device_id']
                            master_dict[device]['interfaces'][inf]['cdp']['local_interface'] = cdppath['local_interface']
                            master_dict[device]['interfaces'][inf]['cdp']['platform'] = cdppath['platform']
                            master_dict[device]['interfaces'][inf]['cdp']['remote_port'] = cdppath['port_id']
            #while not int_progress.finished:
                int_progress.update(task1, advance=1)
                time.sleep(0.1)
    #### ROUTING #######
        #print('Gathering BGP data')
        bgp_progress = progress_bar(False)
        with bgp_progress:
            task1 = bgp_progress.add_task('Gathering BGP data',total=1)
            bgpdata = {}
            try:
                bgpdata['neighbors'] = csr.parse('show bgp all neighbors')
            except:
                bgpdata['neighbors'] = {}
            try:
                bgpdata['summary'] = csr.parse('show bgp all summary')
            except:
                bgpdata['summary'] = {}
            bgp_progress.update(task1, advance=1)

        #print('Gathering OSPF data')
        ospf_progress = progress_bar(False)
        with ospf_progress:
            task1 = ospf_progress.add_task('Gathering OSPF data',total=1)
        #for a in track(range (1)):
            try:
                ospf = csr.parse('show ip ospf neighbor detail')
            except:
                ospf = 'N/A'
            ospf_progress.update(task1, advance=1)

        #print('Gathering routing data per VRF')
        #for vrf in track(vrfs):
        
        vrf_route_progress = progress_bar(True)
        with vrf_route_progress:
            task1 = vrf_route_progress.add_task('Gathering routing data per VRF - VRFs',total=len(vrfs))
            for vrf in vrfs:
                if 'vrf' in bgpdata['neighbors'].keys():
                    if vrf in bgpdata['neighbors']['vrf']:
                        master_dict[device]['vrfs'][vrf]['routing']['bgp'] = bgpdata['neighbors']['vrf'][vrf]
                        for nbr in master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor']:
                            for vrf1 in bgpdata['summary']['vrf']:
                                for afam in bgpdata['summary']['vrf'][vrf1]['neighbor'][nbr]['address_family']:
                                    master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes'] = bgpdata['summary']['vrf'][vrf1]['neighbor'][nbr]['address_family'][afam]['prefixes']
                #### for default vrf gather summary route data, if not routes then set summary route data as 0
                if vrf == 'default':
                    try:
                        route_sum = csr.parse('show ip route summary')
                        master_dict[device]['vrfs'][vrf]['routing']['total_routes'] = route_sum['vrf'][vrf]['total_route_source']['subnets'] + route_sum['vrf'][vrf]['total_route_source']['networks']
                    except:
                        route_sum = {}
                        route_sum['vrf'] = {}
                        route_sum['vrf'][vrf] = {}
                        route_sum['vrf'][vrf]['total_route_source'] = {}
                        route_sum['vrf'][vrf]['total_route_source']['subnets'] = 0
                        route_sum['vrf'][vrf]['total_route_source']['networks'] = 0
    
    
                  ####### If less than 1000 routes
                    if route_sum['vrf'][vrf]['total_route_source']['subnets'] + route_sum['vrf'][vrf]['total_route_source']['networks'] < max_routes:
                        #print('number of routes less than 1000 for ' + vrf + '......processing routes')
                        #master_dict[device]['vrfs'][vrf] = {}
                        #master_dict[device]['vrfs'][vrf]['routing'] = {}
                        master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}
                        master_dict[device]['vrfs'][vrf]['routing']['total_routes'] = route_sum['vrf'][vrf]['total_route_source']['subnets'] + route_sum['vrf'][vrf]['total_route_source']['networks']
                        master_dict[device]['vrfs'][vrf]['routing']['routes'] = csr.learn('routing')
                        #master_dict[device]['vrfs'][vrf]['routing']['bgp'] = {}
                        #master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbors'] = csr.parse('show bgp all neighbors')
                        #master_dict[device]['vrfs'][vrf]['routing']['bgp']['summary'] = csr.parse('show bgp all summary')
                        #try:
                        #    master_dict[device]['vrfs'][vrf]['routing']['bgp']['routes'] = csr.parse('show ip route bgp')
                        #except:
                        #    master_dict[device]['vrfs'][vrf]['routing']['bgp']['routes'] = []
                        ############# ROUTES ###########
                        try:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = master_dict[device]['vrfs'][vrf]['routing']['routes'].info['vrf'][vrf]
                            #print('Routing recorded for ' + vrf)
                        except Exception as e:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}
                            #print(vrf + ' exception: ' + str(e) + ' -skipping')
                    master_dict[device]['vrfs'][vrf]['routing']['default_hop'] = []
                    master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort'] = {}
                #print('###########' + vrf + '##########')
                    if 'address_family' in master_dict[device]['vrfs'][vrf]['routing']['routes'].keys():
                        #print(vrf + ' has ' + str(len(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes'])) + ' routes')
                        if 'ipv4' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family'].keys():
                            if '0.0.0.0/0' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']:
                                master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['gateway'] = master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][1]['next_hop']
                                master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['to_network'] = '0.0.0.0'
                                for hop in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list']:
                                    master_dict[device]['vrfs'][vrf]['routing']['default_hop'].append(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][hop]['next_hop'])
                        else:
                            master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['gateway'] = 'not set'
                        ###################  EIGRP ########
                    try:
                        master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = csr.parse('show ip eigrp neighbors detail')
                        #print('EIGRP recorded for ' + vrf)
                    except Exception as e:
                        master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = {}
                        #print(vrf + ' exception: ' + str(e) + ' -skipping')
                    ############ OSPF #########
                    if ospf != 'N/A':
                        if vrf in ospf['vrf'].keys():
                            master_dict[device]['vrfs'][vrf]['routing']['ospf'] = ospf['vrf'][vrf]
                    #else:
                        #print('number of routes exceeds 1000 for ' + vrf + '......too many to process')
                else:
    
                    try:
                        route_sum = csr.parse('show ip route vrf '+ vrf +' summary')
                    except:
                        route_sum= {}
                        route_sum['vrf'] = {}
                        route_sum['vrf'][vrf] = {}
                        route_sum['vrf'][vrf]['total_route_source'] = {}
                        route_sum['vrf'][vrf]['total_route_source']['subnets'] = 0
                        route_sum['vrf'][vrf]['total_route_source']['networks'] = 0
    
                    master_dict[device]['vrfs'][vrf]['routing']['total_routes'] = route_sum['vrf'][vrf]['total_route_source']['subnets'] + route_sum['vrf'][vrf]['total_route_source']['networks']
                    if route_sum['vrf'][vrf]['total_route_source']['subnets'] + route_sum['vrf'][vrf]['total_route_source']['networks'] < max_routes:
                        #print('number of routes less than 1000 for ' + vrf + '......processing routes')
                        master_dict[device]['vrfs'][vrf]['routing']['routes'] = csr.learn('routing',vrf=vrf)
                        try:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = master_dict[device]['vrfs'][vrf]['routing']['routes'].info['vrf'][vrf]
                        except Exception as e:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}

                    master_dict[device]['vrfs'][vrf]['routing']['default_hop'] = []
                    master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort'] = {}
                #print('###########' + vrf + '##########')
                    if 'address_family' in master_dict[device]['vrfs'][vrf]['routing']['routes'].keys():
                        #print(vrf + ' has ' + str(len(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes'])) + ' routes')
                        if 'ipv4' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family'].keys():
                            if '0.0.0.0/0' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']:
                                master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['gateway'] = master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][1]['next_hop']
                                master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['to_network'] = '0.0.0.0'
                                for hop in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list']:
                                    master_dict[device]['vrfs'][vrf]['routing']['default_hop'].append(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][hop]['next_hop'])
                            else:
                                master_dict[device]['vrfs'][vrf]['routing']['routes']['last_resort']['gateway'] = 'not set'
                                #print('Routing recorded for ' + vrf)
                        #master_dict[device]['vrfs'][vrf]['routing']['routes'] = master_dict[device]['vrfs'][vrf]['routing']['routes'].info['vrf'][vrf]
                        #if vrf == 'online-vrf':
                            #bgpdata = csr.parse('show bgp all neighbors')
                            #print(bgpdata)
                            #if vrf in bgpdata['vrf'].keys():
                            #    master_dict[device]['vrfs'][vrf]['routing']['bgp'] = bgpdata['vrf'][vrf]
                                #for instance in master_dict[device]['vrfs'][vrf]['routing']['bgp'].info['instance']:
                                #    master_dict[device]['vrfs'][vrf]['routing']['bgp'] = master_dict[device]['vrfs'][vrf]['routing']['bgp'].info['instance'][instance]['vrf'][vrf]
                            #original belo    
                        #try:
                        #    master_dict[device]['vrfs'][vrf]['routing']['bgp']['routes'] = csr.parse('show ip route vrf ' + str(vrf) +' bgp')
                        #except:
                        #    master_dict[device]['vrfs'][vrf]['routing']['bgp']['routes'] = []
                            #master_dict[device]['vrfs'][vrf]['routing']['bgp'] = csr.learn('bgp',vrf=vrf)
                            #master_dict[device]['vrfs'][vrf]['routing']['bgp'] = master_dict[device]['vrfs'][vrf]['routing']['bgp'].info
                            #for instance in master_dict[device]['vrfs'][vrf]['routing']['bgp'].info['instance']:
                            #    master_dict[device]['vrfs'][vrf]['routing']['bgp'] = master_dict[device]['vrfs'][vrf]['routing']['bgp'].info['instance'][instance]['vrf'][vrf]
                    try:
                        master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = csr.parse('show ip eigrp vrf ' + vrf + ' neighbors detail')
                        #print('EIGRP recorded for ' + vrf)
                    except Exception as e:
                        master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = {}
                        #print(vrf + ' exception: ' + str(e) + ' -skipping')
                    if ospf != 'N/A':
                        if vrf in ospf['vrf'].keys():
                            master_dict[device]['vrfs'][vrf]['routing']['ospf'] = ospf['vrf'][vrf]
                    #else:
                        #print('number of routes exceeds 1000 for ' + vrf + '......too many to process')
                #if vrf in bgpdata['vrf'].keys():
                #    master_dict[device]['vrfs'][vrf]['routing']['bgp'] = bgpdata['vrf'][vrf]
            #while not vrf_route_progress.finished:
                vrf_route_progress.update(task1, advance=1)
                #time.sleep(0.02)
###### IOSXR TASKS ######


    elif testbed.devices[target_device].os == 'iosxr':
        
        vrfs.append('default')
        master_dict[device]['vrfs']['default'] = {}
        master_dict[device]['vrfs']['default']['routing'] = {}
        master_dict[device]['vrfs']['default']['routing']['routes'] = {}
        #print('Gathering version data')
        ver_progress = progress_bar(False)
        with ver_progress:
            task1 = ver_progress.add_task('Gathering version data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['version_data'] = csr.parse('show version')
            except:
                master_dict[device]['version_data'] = 'N/A'
            ver_progress.update(task1, advance=1)
        #print('Gathering Boot data')
        boot_progress = progress_bar(False)
        with boot_progress:
            task1 = boot_progress.add_task('Gathering boot data',total=1)
        #for a in track(range (1)):
            try:
                master_dict[device]['boot_data'] = csr.parse('show variables boot')
            except:
                master_dict[device]['boot_data'] = 'N/A'
            boot_progress.update(task1, advance=1)
        
        master_dict[device]['switch_data'] = 'N/A'
        master_dict[device]['Etherchannel_data'] = 'N/A'

    ######### INTERFACES ########

        
        #print('Gathering interface data')
        master_dict[device]['interfaces'] = {}
        interfaces = csr.learn('interface')
        int_progress = progress_bar(True)
        with int_progress:
            task1 = int_progress.add_task('Gathering interface data - Interfaces',total=len(interfaces.info))
            for inf in interfaces.info:
                infpath = interfaces.info[inf]
                master_dict[device]['interfaces'][inf] = {}
                try:
                    master_dict[device]['interfaces'][inf]['oper_status'] = infpath['oper_status']
                except:
                    #continue
                    int_progress.update(task1, advance=1)
                    time.sleep(0.1)
                if 'description' in infpath.keys():
                    master_dict[device]['interfaces'][inf]['description'] = infpath['description']
                else:
                    master_dict[device]['interfaces'][inf]['description'] = 'Not configured'
                if 'type' in infpath.keys():            
                    master_dict[device]['interfaces'][inf]['type'] = infpath['type']
                else:
                    master_dict[device]['interfaces'][inf]['type'] = 'Not recorded'
                if 'ipv4' in infpath.keys():
                    for pfix in infpath['ipv4']:
                        try:
                            master_dict[device]['interfaces'][inf]['IP'] = infpath['ipv4'][pfix]['ip']
                        except:
                            master_dict[device]['interfaces'][inf]['IP'] = None
                else:
                    master_dict[device]['interfaces'][inf]['IP'] = 'Not configured'
                
                if 'index' in master_dict[device]['cdp'].keys(): 
                    for cdpnbr in master_dict[device]['cdp']['index']:
                        if 'local_interface' in master_dict[device]['cdp']['index'][cdpnbr].keys() and master_dict[device]['cdp']['index'][cdpnbr]['local_interface'].lower() == inf.lower():
                            cdppath = master_dict[device]['cdp']['index'][cdpnbr]
                            master_dict[device]['interfaces'][inf]['cdp'] = {}
                            master_dict[device]['interfaces'][inf]['cdp']['device_id'] = cdppath['device_id']
                            master_dict[device]['interfaces'][inf]['cdp']['local_interface'] = cdppath['local_interface']
                            master_dict[device]['interfaces'][inf]['cdp']['platform'] = cdppath['platform']
                            master_dict[device]['interfaces'][inf]['cdp']['remote_port'] = cdppath['port_id']

                int_progress.update(task1, advance=1)
                #time.sleep(0.05)

        ############# ROUTING ##########


        #print('Gathering bgp data')
        #for a in track(range (1)):
        bgp_progress = progress_bar(False)
        with bgp_progress:
            task1 = bgp_progress.add_task('Gathering BGP data',total=1) 
            try:
                bgp = csr.parse('show bgp vrf all neighbors')
            except:
                bgp = 'N/A'
            try:
                bgpdefault = csr.parse('show bgp neighbors')
            except:
                bgpdefault = 'N/A'
            bgp_progress.update(task1, advance=1)
        #print('Gathering OSPF data')
        ospf_progress = progress_bar(False)
        with ospf_progress:
            task1 = ospf_progress.add_task('Gathering OSPF data',total=1)
        #for a in track(range (1)):
            try:
                ospf = csr.parse('show ospf vrf all-inclusive neighbor detail')
            except:
                ospf = 'N/A'
            ospf_progress.update(task1, advance=1)
        #print('Gathering EIGRP data')
        #for a in track(range (1)):
        #    try:
        #        eigrp = csr.learn('eigrp')
        #        master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = csr.parse('show eigrp ipv4 vrf '+ vrf +' neighbors detail')
        #    except:
        #        master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = 'N/A'
        #print('Gathering routing data per VRF')
        vrf_route_progress = progress_bar(True)
        with vrf_route_progress:
            task1 = vrf_route_progress.add_task('Gathering routing data per VRF - VRFs',total=len(vrfs))
            for vrf in vrfs:
                if vrf == 'default':
                    try:
                        master_dict[device]['vrfs'][vrf]['routing']['bgp'] = bgpdefault['instance']['all']['vrf'][vrf]
                    except:
                        master_dict[device]['vrfs'][vrf]['routing']['bgp'] = {}
                else:    
                    try:
                        master_dict[device]['vrfs'][vrf]['routing']['bgp'] = bgp['instance']['all']['vrf'][vrf]
                    except:
                        master_dict[device]['vrfs'][vrf]['routing']['bgp'] = {}
                try:
                    master_dict[device]['vrfs'][vrf]['routing']['ospf'] = ospf['vrf'][vrf]
                except:
                    master_dict[device]['vrfs'][vrf]['routing']['ospf'] = {}
                try:
                    master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = csr.parse('show eigrp ipv4 vrf '+ vrf +' neighbors detail')
                except:
                    master_dict[device]['vrfs'][vrf]['routing']['eigrp'] = {}
    
                if vrf == 'default':
                    try:
                        route_sum = csr.parse('show route afi-all safi-all summary')
                    except:
                        route_sum = {}
                        route_sum['vrf'] = {}
                        route_sum['vrf'][vrf] = {}
                        route_sum['vrf'][vrf]['address_family'] = {}
                        route_sum['vrf'][vrf]['address_family']['IPv4 Unicast'] = {}
                        route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source'] = {}
                        route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source']['routes'] = 0
                    master_dict[device]['vrfs'][vrf]['routing']['total_routes'] = route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source']['routes']
                    
                    if route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source']['routes'] < max_routes:
                        master_dict[device]['vrfs'][vrf]['routing']['routes'] = csr.parse('show route ipv4')
                        try:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = master_dict[device]['vrfs'][vrf]['routing']['routes']['vrf'][vrf]
                            #print('Routing recorded for ' + vrf)
                        except Exception as e:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}        
                else:
                    try:
                        route_sum = csr.parse('show route vrf all afi-all safi-all summary')
                    except:
                        route_sum = {}
                        route_sum['vrf'] = {}
                        route_sum['vrf'][vrf] = {}
                        route_sum['vrf'][vrf]['address_family'] = {}
                        route_sum['vrf'][vrf]['address_family']['IPv4 Unicast'] = {}
                        route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source'] = {}
                        route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source']['routes'] = 0
                    master_dict[device]['vrfs'][vrf]['routing']['total_routes'] = route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source']['routes']
    
                    if route_sum['vrf'][vrf]['address_family']['IPv4 Unicast']['total_route_source']['routes'] < max_routes:
                        try:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = csr.parse('show route vrf '+vrf+' ipv4')
                        except:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}
                        try:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = master_dict[device]['vrfs'][vrf]['routing']['routes']['vrf'][vrf]
                            #print('Routing recorded for ' + vrf)
                        except:
                            master_dict[device]['vrfs'][vrf]['routing']['routes'] = {}
                vrf_route_progress.update(task1, advance=1)


    ####### Default Route Gather #####

    #if testbed.devices[device].os == 'nxos':
    #    for vrf in vrfs:
    #        master_dict[device]['vrfs'][vrf]['routing']['default_hop'] = []
    #        #print('###########' + vrf + '##########')
    #        #print()
    #        if 'address_family' in master_dict[device]['vrfs'][vrf]['routing']['routes'].keys():
    #            #print(vrf + ' has ' + str(len(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes'])) + ' routes')
    #            if '0.0.0.0/0' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']:
    #                for hop in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list']:
    #                    master_dict[device]['vrfs'][vrf]['routing']['default_hop'].append(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][hop]['next_hop'])
    #elif testbed.devices[device].os == 'ios':
    #    for vrf in vrfs:
    #        master_dict[device]['vrfs'][vrf]['routing']['default_hop'] = []
    #        #print('###########' + vrf + '##########')
    #        if 'address_family' in master_dict[device]['vrfs'][vrf]['routing']['routes'].keys():
    #            #print(vrf + ' has ' + str(len(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes'])) + ' routes')
    #            if 'ipv4' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family'].keys():
    #                if '0.0.0.0/0' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']:
    #                    for hop in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list']:
    #                        master_dict[device]['vrfs'][vrf]['routing']['default_hop'].append(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']['0.0.0.0/0']['next_hop']['next_hop_list'][hop]['next_hop'])
    
    if not os.path.exists('./json_log_files/'+target_device):
        os.makedirs('./json_log_files/'+target_device)
    if not os.path.exists('./json_log_files/'+target_device+'/archive'):
        os.makedirs('./json_log_files/'+target_device+'/archive')
    
    ################### WRITE DICT TO JSON #####################
    
    filepath = './json_log_files/'+target_device+'/master_dict_'+str(snapshot) +'_latest.json'
    with open(filepath, "w") as outfile: 
        json.dump(master_dict, outfile)
    
    
    ########### GET TIME ########
    
    curtime = str(datetime.now().strftime('%H_%M_%S_%d_%m_%Y'))
    
    ########### ADD DATA TO LOGS ##################
    
    logfilename = 'master_dict_'+str(snapshot) +'_' + curtime + '.json'
    filepath = './json_log_files/'+target_device+'/archive/'+logfilename
    with open(filepath, "w") as outfile: 
        json.dump(master_dict, outfile)

    print()
    console.print('[dim green]Snapshot gathering for[/dim green] [bold green]{}[/bold green][dim green] complete. JSON data file can be found here:[/dim green][bold green]./json_log_files/{}/master_dict_{}_latest.json[/bold green]'.format(target_device,target_device,snapshot,highlight=False))
    print()

if __name__ == "__main__":
    core_devices = ['uk-ld6-cr01','uk-ld6-cr02','uk-ld6-cs01','uk-ld6-cs02']
    
    for device in core_devices:
        device_state_learn(device,5000,'curr')