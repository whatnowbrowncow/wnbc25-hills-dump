from prettytable import PrettyTable
from rich.table import Table
import json

results = {}
results['vrfs'] = {}

def compare_vrfrouting(target_device,devicepre,devicepost):
    def bgp_pfix_diff(pfix_pre,pfix_post):
        diff = abs(pfix_pre - pfix_post)
        avg = (pfix_pre + pfix_post)/2
        diff = diff / avg
        pfix_diff = diff * 100
        return pfix_diff
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)
    #devicepre = str(target_device) + '-pre'
    #devicepost = str(target_device) + '-post'
    ##console = #console()
    ##print()
    ##console.print('[cyan]#############################Checking for interface differences#########################')
    ##print()
    allvrfsmatch = True
    mismatchedvrfs = []
    routedata = {}
    routedata['commonvrfs'] = []
    routedata['uniqueprevrfs'] = {}
    routedata['uniquepostvrfs'] = {}
    routedatamatch = True
    allvrfs = []
    for device in [devicepre, devicepost]:
        for vrf in master_dict[devicepre]['vrfs']:
            allvrfs.append(vrf)
    allvrfs = list(dict.fromkeys(allvrfs))
    route_lists = {}
    neighbordata = {}
    neighbormismatch = False
    
    vrfid = 1
    for vrf in allvrfs:
        results['vrfs'][vrf] = {}
        results['vrfs'][vrf]['vrfid'] = vrfid
        results['vrfs'][vrf]['missingfrompre'] = False
        results['vrfs'][vrf]['missingfrompost'] = False
        vrfid = vrfid + 1
        ##print()
        ##console.print('[magenta]------------------ {} ------------------'.format(vrf))
        ##print()
        ##print()
        ##console.print('[cyan]EIGRP / OSPF / BGP Neighbors')
        ##print()
        vrfneighbormismatch = False
        vrfneighbormissing = False
        vrfroutetotalmismatch = False
        neighbordata[vrf] = {}
        neighbordata[vrf][devicepre] = []
        neighbordata[vrf][devicepost] = []
        route_lists[vrf] = {}
        richvrfrouting = Table(title='Routing Neighbor Summary',show_header=True, header_style="bold blue")
        richvrfrouting.add_column('Device')
        richvrfrouting.add_column('Neighbor',justify='center')
        richvrfrouting.add_column('Description',justify='center')
        richvrfrouting.add_column('Protocol',justify='center')
        richvrfrouting.add_column('Interface',justify='center')
        richvrfrouting.add_column('Uptime / Last Change',justify='center')
        richvrfrouting.add_column('State',justify='center')
        richvrfrouting.add_column('Prefixes',justify='center')
        richvrfroutes = Table(title='Routing Summary',show_header=True, header_style="bold blue")
        richvrfroutes.add_column('Comparison')
        richvrfroutes.add_column('Unique Routes pre ',justify='center')
        richvrfroutes.add_column('Common Routes',justify='center')
        richvrfroutes.add_column('Unique Routes post ',justify='center')
        vrfroutes = PrettyTable(['Comparison','Unique Routes','Common Routes'])
        #for device in [devicepre, devicepost]:
        if vrf in master_dict[devicepre]['vrfs'].keys() and vrf in master_dict[devicepost]['vrfs'].keys():
            if 'eigrp' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys() and 'eigrp' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'eigrp_instance' in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp'].keys():
                    if 'eigrp_instance' in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp'].keys():
                        for inst in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance']:
                            for vrf1 in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf']:
                                for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family']:
                                    if 'eigrp_interface' in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                        for inf in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface']:
                                            if 'eigrp_interface' in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                                if inf in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'].keys():
                                                    for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                                        if nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'].keys():
                                                            if master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'] ==master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes']:
                                                                richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]EIGRP','[green]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[green]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])))
                                                                richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]EIGRP','[green]{}'.format(inf),'{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[green]{}'.format(str(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                                            else:
                                                                richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]EIGRP','[green]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])))
                                                                richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]EIGRP','[green]{}'.format(inf),'{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                                                vrfneighbormismatch = True
                                                        else:
                                                            richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                                            vrfneighbormissing = True
                                                            vrfneighbormismatch = True
                                                else:
                                                    for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                                            richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                                            vrfneighbormissing = True
                                                            vrfneighbormismatch = True  
                                            else:
                                                for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                                        richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                                        vrfneighbormissing = True
                                                        vrfneighbormismatch = True
                    else:
                        for inst in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance']:
                            for vrf1 in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf']:
                                for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family']:
                                    if 'eigrp_interface' in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                        for inf in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface']:
                                            for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                                richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                                vrfneighbormissing = True
                                                vrfneighbormismatch = True
                                                

            elif 'eigrp' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys():
                if 'eigrp_instance' in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp'].keys():
                    for inst in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance']:
                        for vrf1 in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf']:
                            for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family']:
                                if 'eigrp_interface' in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                    for inf in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface']:
                                        for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                            richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                            vrfneighbormissing = True
                                            vrfneighbormismatch = True

            elif 'eigrp' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'eigrp_instance' in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp'].keys():
                    for inst in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance']:
                        for vrf1 in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf']:
                            for afam in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family']:
                                if 'eigrp_interface' in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                    for inf in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface']:
                                        for nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                            richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                            vrfneighbormissing = True
                                            vrfneighbormismatch = True
            
            if 'ospf' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys() and 'ospf' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'address_family' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf'].keys():
                    for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family']:
                        for inst in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance']:
                            if 'areas' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst].keys():
                                for area in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas']:
                                    for interface in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces']:
                                        if 'neighbors' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface].keys():                          
                                            for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors']:
                                                if 'uptime' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    if 'address_family' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf'].keys() and interface in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'].keys() and nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'].keys():
                                                        if master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state'] == master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']:
                                                            richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[green]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-')
                                                            richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[green]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                        else:
                                                            richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-')
                                                            richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                            vrfneighbormismatch = True
                                                        
                                                    else:
                                                        richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                        vrfneighbormissing = True
                                                        vrfneighbormismatch = True
                                                elif 'neighbor_uptime' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    if 'address_family' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf'].keys() and interface in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'].keys() and nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'].keys():
                                                        if master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state'] == master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']:
                                                            richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[green]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-')
                                                            richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[green]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                        else:
                                                            richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-')
                                                            richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                            vrfneighbormismatch = True
                                                        
                                                    else:
                                                        richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                        vrfneighbormissing = True
                                                        vrfneighbormismatch = True
                                                elif 'last_state_change' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    if 'address_family' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf'].keys() and interface in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'].keys() and nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'].keys():
                                                        if master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state'] == master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']:
                                                            richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[green]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-')
                                                            richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[green]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                        else:
                                                            richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-')
                                                            richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),'---','[green]OSPF','[green]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                            vrfneighbormismatch = True
                                                    else:
                                                        richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)  
                                                        vrfneighbormissing = True
                                                        vrfneighbormismatch = True

            elif 'ospf' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys():
                if 'address_family' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf'].keys():
                    for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family']:
                        for inst in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance']:
                            if 'areas' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst].keys():
                                for area in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas']:
                                    for interface in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces']:
                                        if 'neighbors' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface].keys():                          
                                            for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors']:
                                                if 'uptime' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
                                                elif 'neighbor_uptime' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
                                                elif 'last_state_change' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)  
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True

            elif 'ospf' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'address_family' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf'].keys():
                    for afam in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family']:
                        for inst in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance']:
                            if 'areas' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst].keys():
                                for area in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas']:
                                    for interface in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces']:                              
                                        if 'neighbors' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface].keys():
                                            for nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors']:
                                                if 'uptime' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
                                                if 'neighbor_uptime' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
                                                elif 'last_state_change' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)  
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
    
            if 'bgp' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys():
                if 'bgp' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                    if 'neighbor' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp'].keys():
                        for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor']:
                            total_pfx_entries_pre = 0
                            total_pfx_entries_post = 0
                            for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family']:
                                if 'prefixes' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries_pre = total_pfx_entries_pre + master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes']['total_entries']
                                elif 'accepted_prefixes' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries_pre = total_pfx_entries_pre + master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['accepted_prefixes']
                                else:
                                    total_pfx_entries_pre = '-N/A-'
                            if nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'].keys():
                                if 'description' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys() and 'description' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                    if master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description'] == master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description']:
                                        richdescription_pre = '[green]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description'])
                                        richdescription_post = '[green]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description'])
                                    else:
                                        richdescription_pre = '[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description'])
                                        richdescription_post = '[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description'])
                                elif 'description' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys() and 'description' not in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                    richdescription_pre = '[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description'])
                                    richdescription_post = '[red]---'
                                elif 'description' not in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys() and 'description' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                    richdescription_pre = '[red]---'
                                    richdescription_post = '[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description'])
                                else:
                                    richdescription_pre = '[green]---'
                                    richdescription_post = '[green]---'
                                for afam in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family']:
                                    if 'prefixes' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                        total_pfx_entries_post = total_pfx_entries_post + master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes']['total_entries']
                                    elif 'accepted_prefixes' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                        total_pfx_entries_post = total_pfx_entries_post + master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['accepted_prefixes']
                                    else:
                                        total_pfx_entries_post = '-N/A-'
                                if 'up_time' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                    richtimer_pre = master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['up_time']
                                   # richtimer_post = master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['up_time']
                                elif 'last_reset' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['bgp_session_transport']['connection'].keys():
                                    richtimer_pre = 'up_time_discrepancy to fix'
                                   # richtimer_post = 'up_time_discrepancy to fix'
                                else:
                                    richtimer_pre = 'N/A'
                                    #richtimer_post = 'N/A'
                                if 'up_time' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                    #richtimer_pre = master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['up_time']
                                    richtimer_post = master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['up_time']
                                elif 'last_reset' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['bgp_session_transport']['connection'].keys():
                                    #richtimer_pre = 'up_time_discrepancy to fix'
                                    richtimer_post = 'up_time_discrepancy to fix'
                                else:
                                    #richtimer_pre = 'N/A'
                                    richtimer_post = 'N/A'
            
                                if master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state'] == master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']:
                                    richbgpstate_pre = '[green]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state'])
                                    richbgpstate_post = '[green]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state'])
                                    
                                else:
                                    richbgpstate_pre = '[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state'])
                                    richbgpstate_post = '[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state'])
                                    vrfneighbormismatch = True
    
                                if total_pfx_entries_pre == total_pfx_entries_post:
                                    if total_pfx_entries_pre == '-N/A-' and total_pfx_entries_post == '-N/A-':
                                        richbgppfx_pre = total_pfx_entries_pre
                                        richbgppfx_post = total_pfx_entries_post
                                    else:
                                        richbgppfx_pre = '[green]{}'.format(total_pfx_entries_pre)
                                        richbgppfx_post = '[green]{}'.format(total_pfx_entries_post)
    
                                else:
                                    pfix_diff = bgp_pfix_diff(total_pfx_entries_pre,total_pfx_entries_post)
                                    print(vrf + 'missmatch found')

                                    print('difference is ' + str(pfix_diff) + '%')
                                    if pfix_diff < 2:
                                        richbgppfx_pre = '[green]{}[/green][blue bold]*'.format(total_pfx_entries_pre)
                                        richbgppfx_post = '[green]{}[/green][blue bold]*'.format(total_pfx_entries_post) 
                                    else:
                                        richbgppfx_pre = '[red]{}[/red][blue bold]*'.format(total_pfx_entries_pre)
                                        richbgppfx_post = '[red]{}[/red][blue bold]*'.format(total_pfx_entries_post)
                                        vrfneighbormismatch = True
    
            
                                richvrfrouting.add_row('[green]{}'.format(devicepre),'[green]{}'.format(nbr),richdescription_pre,'[green]bgp','N/A','{}'.format(richtimer_pre),richbgpstate_pre,richbgppfx_pre)
                                richvrfrouting.add_row('[green]{}'.format(devicepost),'[green]{}'.format(nbr),richdescription_post,'[green]bgp','N/A','{}'.format(richtimer_post),richbgpstate_post,richbgppfx_post,end_section=True)
    
                            else:
                                if 'description' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                    richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'[green]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description']),'[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_pre),end_section=True)
                                else:
                                    richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'[green]---','[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_pre),end_section=True)
                                vrfneighbormissing = True
                                vrfneighbormismatch = True
                else:
                    if 'neighbor' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp'].keys():
                        for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor']:
                            total_pfx_entries_pre = 0
                            for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family']:
                                if 'prefixes' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries_pre = total_pfx_entries_pre + master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes']['total_entries']
                                elif 'accepted_prefixes' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries_pre = total_pfx_entries_pre + master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['accepted_prefixes']
                                else:
                                    total_pfx_entries_pre = '-N/A-'
                            
                            if 'description' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description']),'[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_pre),end_section=True)
                            else:
                                richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'[red]---','[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_pre),end_section=True)
                            vrfneighbormissing = True
                            vrfneighbormismatch = True
        
            if 'bgp' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'neighbor' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp'].keys():
                    for nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor']:
                        total_pfx_entries_post = 0
                        for afam in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family']:
                            if 'prefixes' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                total_pfx_entries_post = total_pfx_entries_post + master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes']['total_entries']
                            elif 'accepted_prefixes' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                total_pfx_entries_post = total_pfx_entries_post + master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['accepted_prefixes']
                            else:
                                total_pfx_entries_post = '-N/A-'
                        if 'bgp' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys():
                            if nbr not in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'].keys():
                                if 'description' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                    richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description']),'[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_post),end_section=True)
                                else:
                                    richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'[red]---','[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_post),end_section=True)
                                vrfneighbormissing = True
                                vrfneighbormismatch = True
                        else:
                            if 'description' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description']),'[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_post),end_section=True)
                            else:
                                richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'[red]---','[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_post),end_section=True)
                            vrfneighbormissing = True
                            vrfneighbormismatch = True
#######################


        elif vrf in master_dict[devicepre]['vrfs'].keys() and vrf not in master_dict[devicepost]['vrfs'].keys():
            if 'eigrp' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys():
                if 'eigrp_instance' in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp'].keys():
                    for inst in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance']:
                        for vrf1 in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf']:
                            for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family']:
                                if 'eigrp_interface' in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                    for inf in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface']:
                                        for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                            richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepre]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                            vrfneighbormissing = True
                                            vrfneighbormismatch = True

            if 'ospf' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys():
                if 'address_family' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf'].keys():
                    for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family']:
                        for inst in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance']:
                            if 'areas' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst].keys():
                                for area in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas']:
                                    for interface in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces']:
                                        if 'neighbors' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface].keys():                          
                                            for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors']:
                                                if 'uptime' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
                                                elif 'neighbor_uptime' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['neighbor_uptime'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
                                                elif 'last_state_change' in master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                        richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)  
                                                        vrfneighbormissing = True
                                                        vrfneighbormismatch = True


            if 'bgp' in master_dict[devicepre]['vrfs'][vrf]['routing'].keys():
                    if 'neighbor' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp'].keys():
                        for nbr in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor']:
                            total_pfx_entries_pre = 0
                            total_pfx_entries_post = 0
                            for afam in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family']:
                                if 'prefixes' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries_pre = total_pfx_entries_pre + master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes']['total_entries']
                                elif 'accepted_prefixes' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries_pre = total_pfx_entries_pre + master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['accepted_prefixes']
                                else:
                                    total_pfx_entries_pre = '-N/A-'

                            if 'description' in master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                                richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'[green]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description']),'[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_pre),end_section=True)
                            else:
                                richvrfrouting.add_row('[red]{}'.format(devicepre),'[red]{}'.format(nbr),'[green]---','[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepre]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_pre),end_section=True)
                            vrfneighbormissing = True
                            vrfneighbormismatch = True
        
        
        
        #############################
        
        
        
        elif vrf in master_dict[devicepost]['vrfs'].keys() and vrf not in master_dict[devicepre]['vrfs'].keys():
            if 'eigrp' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'eigrp_instance' in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp'].keys():
                    for inst in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance']:
                        for vrf1 in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf']:
                            for afam in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family']:
                                if 'eigrp_interface' in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                    for inf in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface']:
                                        for nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                            richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'---','[red]EIGRP','[red]{}'.format(inf),'{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['uptime']),'-N/A-','[red]{}'.format(str(master_dict[devicepost]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])),end_section=True)
                                            vrfneighbormissing = True
                                            vrfneighbormismatch = True
            

    
            if 'ospf' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'address_family' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf'].keys():
                    for afam in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family']:
                        for inst in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance']:
                            if 'areas' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst].keys():
                                for area in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas']:
                                    for interface in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces']:                              
                                        if 'neighbors' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface].keys():
                                            for nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors']:
                                                if 'uptime' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['uptime'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True
                                                elif 'last_state_change' in master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                    richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'---','[red]OSPF','[red]{}'.format(interface),master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['last_state_change'],'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state']),'-N/A-',end_section=True)  
                                                    vrfneighbormissing = True
                                                    vrfneighbormismatch = True

        
            if 'bgp' in master_dict[devicepost]['vrfs'][vrf]['routing'].keys():
                if 'neighbor' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp'].keys():
                    for nbr in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor']:
                        total_pfx_entries_post = 0
                        for afam in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family']:
                            if 'prefixes' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                total_pfx_entries_post = total_pfx_entries_post + master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes']['total_entries']
                            elif 'accepted_prefixes' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                total_pfx_entries_post = total_pfx_entries_post + master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['accepted_prefixes']
                            else:
                                total_pfx_entries_post = '-N/A-'

                        if 'description' in master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr].keys():
                            richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['description']),'[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_post),end_section=True)
                        else:
                            richvrfrouting.add_row('[red]{}'.format(devicepost),'[red]{}'.format(nbr),'[red]---','[red]bgp','N/A','{}'.format('up_time_discrepancy to fix'),'[red]{}'.format(master_dict[devicepost]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state']),'[red]{}'.format(total_pfx_entries_post),end_section=True)
                        vrfneighbormissing = True
                        vrfneighbormismatch = True


###########################
            

    
        #print(vrfrouting)
        ##console.print(richvrfrouting)
        results['vrfs'][vrf]['vrfrouting'] = richvrfrouting
        results['vrfs'][vrf]['vrfneighbormismatch'] = vrfneighbormismatch
        results['vrfs'][vrf]['vrfneighbormissing'] = vrfneighbormissing
    
        for device in [devicepre, devicepost]:
            if vrf in master_dict[device]['vrfs'].keys():
                route_lists[vrf][device] = {}
                route_lists[vrf][device]['routes'] = []
                if 'routes' in master_dict[device]['vrfs'][vrf]['routing'].keys():
                    if 'address_family' in master_dict[device]['vrfs'][vrf]['routing']['routes'].keys():
                        if 'ipv4' in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family'].keys():
                            route_lists[vrf][device]['totalroutes'] = len(master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes'])
                            for route in master_dict[device]['vrfs'][vrf]['routing']['routes']['address_family']['ipv4']['routes']:
                                route_lists[vrf][device]['routes'].append(route)
                if 'eigrp' in master_dict[device]['vrfs'][vrf]['routing'].keys():
                    if 'eigrp_instance' in master_dict[device]['vrfs'][vrf]['routing']['eigrp'].keys():
                        for inst in master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance']:
                            for vrf1 in master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf']:
                                for afam in master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family']:
                                    if 'eigrp_interface' in master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam].keys():
                                        for inf in master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface']:
                                            for nbr in master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr']:
                                                matchrow = [nbr,'EIGRP',inf,'-N/A-',str(master_dict[device]['vrfs'][vrf]['routing']['eigrp']['eigrp_instance'][inst]['vrf'][vrf1]['address_family'][afam]['eigrp_interface'][inf]['eigrp_nbr'][nbr]['prefixes'])]
                                                neighbordata[vrf][device].append(matchrow)
                if 'ospf' in master_dict[device]['vrfs'][vrf]['routing'].keys():
                    if 'address_family' in master_dict[device]['vrfs'][vrf]['routing']['ospf'].keys():
                        for afam in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family']:
                            for inst in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance']:
                                if 'areas' in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst].keys():
                                    for area in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas']:
                                        for interface in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces']:                              
                                            if 'neighbors' in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface].keys():
                                                for nbr in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors']:
                                                    if 'uptime' in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                        matchrow = [nbr,'OSPF',interface,master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state'],'-N/A-']
                                                    elif 'last_state_change' in master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr].keys():
                                                        matchrow = [nbr,'OSPF',interface,master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state'],'-N/A-']
                                                    else:
                                                        matchrow = [nbr,'OSPF',interface,master_dict[device]['vrfs'][vrf]['routing']['ospf']['address_family'][afam]['instance'][inst]['areas'][area]['interfaces'][interface]['neighbors'][nbr]['state'],'-N/A-']
                                                    neighbordata[vrf][device].append(matchrow)
                if 'bgp' in master_dict[device]['vrfs'][vrf]['routing'].keys():
                    if 'neighbor' in master_dict[device]['vrfs'][vrf]['routing']['bgp'].keys():
                        for nbr in master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor']:
                            total_pfx_entries = 0
                            for afam in master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family']:
                                if 'prefixes' in master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries = total_pfx_entries + master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['prefixes']['total_entries']
                                elif 'accepted_prefixes' in master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam].keys():
                                    total_pfx_entries = total_pfx_entries + master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['address_family'][afam]['accepted_prefixes']
                            matchrow = [nbr,'bgp','N/A',master_dict[device]['vrfs'][vrf]['routing']['bgp']['neighbor'][nbr]['session_state'],total_pfx_entries]
                            neighbordata[vrf][device].append(matchrow)
        if neighbordata[vrf][devicepre] == neighbordata[vrf][devicepost]:
            neighbordata[vrf]['match'] = True
        else:
            neighbordata[vrf]['match'] = False
    
        if devicepre in route_lists[vrf].keys() and devicepost in route_lists[vrf].keys():
            #print('unique cs1 vs cs1 new')
            prevpostdiff = (list(set(route_lists[vrf][devicepre]['routes']) - set(route_lists[vrf][devicepost]['routes'])))
            prevpostdiff = [x for x in prevpostdiff if '/32' not in x]
            #print(str(len(prevpostdiff))+ ' different routes')
            prevpostcmn = (list(set(route_lists[vrf][devicepre]['routes']) & set(route_lists[vrf][devicepost]['routes'])))
            prevpostcmn = [x for x in prevpostcmn if '/32' not in x]
            #print(str(len(prevpostcmn))+ ' common routes')
            row = [str(devicepre) +'/'+str(devicepost),str(len(prevpostdiff)),str(len(prevpostcmn))]
            #richvrfroutes.add_row(str(devicepre) +'/'+str(devicepost),str(len(prevpostdiff)),str(len(prevpostcmn)))
            vrfroutes.add_row(row)
            #print('unique cs1 new vs cs1')
            postvprediff = (list(set(route_lists[vrf][devicepost]['routes']) - set(route_lists[vrf][devicepre]['routes'])))
            postvprediff = [x for x in postvprediff if '/32' not in x]
            #print(str(len(postvprediff))+ ' different routes')
            postvprecmn = (list(set(route_lists[vrf][devicepost]['routes']) & set(route_lists[vrf][devicepre]['routes'])))
            postvprecmn = [x for x in postvprecmn if '/32' not in x]
            #print(str(len(postvprecmn))+ ' common routes')
            row = [str(devicepost) +'/'+str(devicepre),str(len(postvprediff)),str(len(postvprecmn))]
            #richvrfroutes.add_row(str(devicepost) +'/'+str(devicepre),str(len(postvprediff)),str(len(postvprecmn)))
            richvrfroutes.add_row(str(devicepre) +'/'+str(devicepost),'[yellow]{}'.format(str(len(prevpostdiff))) if str(len(prevpostdiff)) != '0' else '[green]{}'.format(str(len(prevpostdiff))),'[green]{}'.format(str(len(prevpostcmn))),'[yellow]{}'.format(str(len(postvprediff))) if str(len(postvprediff))!= '0' else '[green]{}'.format(str(len(postvprediff))))
            vrfroutes.add_row(row)
            ##print()
            ##console.print('[cyan]{} route comparison table'.format(vrf))
            ##print()
            #print(vrfroutes)
            ##console.print(richvrfroutes)
            results['vrfs'][vrf]['vrfroutes'] = richvrfroutes
            ##print()
            ##console.print('[cyan]Common routes between pre and post....')
            ##print()
            
            
            
            if len(prevpostcmn) > 0:
                richcommonroutes = Table(title='Common Routes',show_header=True, header_style="bold blue")
                richcommonroutes.add_column('Common Routes',justify='center')
                for route in prevpostcmn:
                    richcommonroutes.add_row('[green]{}'.format(route))
                #print(common_routes_table)
                ##console.print(richcommonroutes)
                results['vrfs'][vrf]['commonroutes'] = richcommonroutes
                results['vrfs'][vrf]['numbercommonroutes'] = len(prevpostcmn)
                routedata['commonvrfs'].append(vrf)
            else:

                richcommonroutes = Table(title='Common Routes',show_header=True, header_style="bold blue")
                richcommonroutes.add_column('Common Routes',justify='center')

                richcommonroutes.add_row('[red]--NONE--')
                #print(common_routes_table)
                #console.print(richcommonroutes)
                results['vrfs'][vrf]['commonroutes'] = richcommonroutes
                results['vrfs'][vrf]['numbercommonroutes'] = 0
            #print()
            #console.print('[cyan]Unique routes on pre snapshot....')
            if len(prevpostdiff) > 0:
                richuniqueroutes = Table(title='Unique Routes',show_header=True, header_style="bold blue")
                richuniqueroutes.add_column('Unique Routes',justify='center')
                for route in prevpostdiff:
                    richuniqueroutes.add_row('[yellow]{}'.format(route))
                #print(unique_routes_table)
                #console.print(richuniqueroutes)
                results['vrfs'][vrf]['uniquepreroutes'] = richuniqueroutes
                results['vrfs'][vrf]['numberuniquepreroutes'] = len(prevpostdiff)
                routedata['uniqueprevrfs'][vrf] = []
                for route in prevpostdiff:
                    routedata['uniqueprevrfs'][vrf].append(route)
                routedatamatch = False
                vrfroutetotalmismatch = True
                neighbormismatch = True
            else:

                richuniqueroutes = Table(title='Unique Routes',show_header=True, header_style="bold blue")
                richuniqueroutes.add_column('Unique Routes',justify='center')
                richuniqueroutes.add_row('[red]--NONE--')
                #print(unique_routes_table)
                #console.print(richuniqueroutes)
                results['vrfs'][vrf]['uniquepreroutes'] = richuniqueroutes
                results['vrfs'][vrf]['numberuniquepreroutes'] = 0
            #print()
            #console.print('[cyan]Unique routes on post snapshot....')
            if len(postvprediff) > 0:
                richuniqueroutes = Table(title='Unique Routes',show_header=True, header_style="bold blue")
                richuniqueroutes.add_column('Unique Routes',justify='center')
                for route in postvprediff:
                    richuniqueroutes.add_row('[yellow]{}'.format(route))
    
                #print(unique_routes_table)
                #console.print(richuniqueroutes)
                results['vrfs'][vrf]['uniquepostroutes'] = richuniqueroutes
                results['vrfs'][vrf]['numberuniquepostroutes'] = len(postvprediff)
                routedata['uniquepostvrfs'][vrf] = []
                for route in prevpostdiff:
                    routedata['uniquepostvrfs'][vrf].append(route)
                routedatamatch = False
                vrfroutetotalmismatch = True
                neighbormismatch = True
            else:

                richuniqueroutes = Table(title='Unique Routes',show_header=True, header_style="bold blue")
                richuniqueroutes.add_column('Unique Routes',justify='center')
                richuniqueroutes.add_row('[red]--NONE--')

                #print(unique_routes_table)
                #console.print(richuniqueroutes)
                results['vrfs'][vrf]['uniquepostroutes'] = richuniqueroutes
                results['vrfs'][vrf]['numberuniquepostroutes'] = 0
            #print()
            if len(prevpostcmn) == 0 and len(prevpostdiff) == 0  and len(postvprediff) == 0:
                routedata['commonvrfs'].append(vrf)
        elif devicepre in route_lists[vrf].keys() and devicepost not in route_lists[vrf].keys():
            #print()
            #console.print('[red]{} not found on post snapshot, there is nothing to compare'.format(vrf))
            #print()
            allvrfsmatch = False
            mismatchedvrfs.append(vrf)
            results['vrfs'][vrf]['missingfrompost'] = True
        elif devicepre not in route_lists[vrf].keys() and devicepost in route_lists[vrf].keys():
            #print()
            #console.print('[red]{} not found on pre snapshot, there is nothing to compare'.format(vrf))
            #print()
            allvrfsmatch = False
            mismatchedvrfs.append(vrf)
            results['vrfs'][vrf]['missingfrompre'] = True
        results['vrfs'][vrf]['vrfroutetotalmismatch'] = vrfroutetotalmismatch
    for vrf in allvrfs:
        #if neighbordata[vrf]['match'] == False:
        if results['vrfs'][vrf]['missingfrompre'] or results['vrfs'][vrf]['missingfrompost'] or results['vrfs'][vrf]['vrfneighbormissing'] or results['vrfs'][vrf]['vrfneighbormismatch'] or results['vrfs'][vrf]['vrfroutetotalmismatch']:
            neighbormismatch = True
    return(results,neighbormismatch)
    
    



