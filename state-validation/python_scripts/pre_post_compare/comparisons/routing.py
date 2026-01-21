from collections import Counter
from rich.table import Table
import json

def compare_routing(target_device,devicepre,devicepost):
    def route_diff(route_pre,route_post):
        diff = abs(route_pre - route_post)
        avg = (route_pre + route_post)/2
        diff = diff / avg
        route_diff = diff * 100
        return route_diff
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)

    routetotalmatch = True
    routestaticmatch = True
    routeospfmatch = True
    routeeigrpmatch = True
    routebgpmatch = True
    routeconnectedmatch = True
    routelocalmatch = True
    routehsrpmatch = True
    routedirectmatch = True
    
    richvrfroutetablepre = Table(title='Routing Summary - Device Pre',show_header=True, header_style="bold blue")
    richvrfroutetablepre.add_column('VRF')
    richvrfroutetablepre.add_column('Devices')
    richvrfroutetablepre.add_column('Total Routes',justify='center')
    richvrfroutetablepre.add_column('Static',justify='center')
    richvrfroutetablepre.add_column('OSPF',justify='center')
    richvrfroutetablepre.add_column('EIGRP',justify='center')
    richvrfroutetablepre.add_column('BGP',justify='center')
    richvrfroutetablepre.add_column('Connected',justify='center')
    richvrfroutetablepre.add_column('Local',justify='center')
    richvrfroutetablepre.add_column('HSRP',justify='center')
    richvrfroutetablepre.add_column('Direct',justify='center')

    richvrfroutetablepost = Table(title='Routing Summary - Device Post',show_header=True, header_style="bold blue")
    richvrfroutetablepost.add_column('VRF')
    richvrfroutetablepost.add_column('Devices')
    richvrfroutetablepost.add_column('Total Routes',justify='center')
    richvrfroutetablepost.add_column('Static',justify='center')
    richvrfroutetablepost.add_column('OSPF',justify='center')
    richvrfroutetablepost.add_column('EIGRP',justify='center')
    richvrfroutetablepost.add_column('BGP',justify='center')
    richvrfroutetablepost.add_column('Connected',justify='center')
    richvrfroutetablepost.add_column('Local',justify='center')
    richvrfroutetablepost.add_column('HSRP',justify='center')
    richvrfroutetablepost.add_column('Direct',justify='center')

    for vrfa in master_dict[devicepre]['vrfs']:
        #for vrfb in master_dict[devicepost]['vrfs']:
            #if master_dict[devicepre]['interfaces'][inta]['type'] == 'EtherSVI':
        if vrfa in master_dict[devicepost]['vrfs']:
            if 'address_family' in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes'].keys() and 'ipv4' in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family'].keys():
                routecounta = Counter(master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'][route]['source_protocol'] for route in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'])
                routetotala = 0
                for k,v in routecounta.items():
                    routetotala = routetotala + int(v)
                if 'address_family' in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes'].keys():
                    if 'ipv4' in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family'].keys():
                        routecountb = Counter(master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'][route]['source_protocol'] for route in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'])
                    else:
                        routecountb = {}
                        routecountb['static'] = 0 
                else:
                    routecountb = {}
                    routecountb['static'] = 0   
                routetotalb = 0
                for k,v in routecountb.items():
                    routetotalb = routetotalb + int(v)
                if routetotala == routetotalb:
                    richtotalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routetotala,routetotalb)
                elif route_diff(routetotala,routetotalb) < 2:
                    richtotalroutes = '[cyan]{}[/cyan]/[cyan]{}[/cyan][cyan bold]*'.format(routetotala,routetotalb)
                elif routetotala > routetotalb:
                    richtotalroutes = '[green]{}[/green]/[red]{}[/red]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                elif routetotala < routetotalb:
                    richtotalroutes = '[red]{}[/red]/[green]{}[/green]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                if routecounta['static'] == routecountb['static']:
                    richstaticroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['static'],routecountb['static'])
                elif routecounta['static'] > routecountb['static']:
                    richstaticroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['static'],routecountb['static'])
                    routestaticmatch = False
                elif routecounta['static'] < routecountb['static']:
                    richstaticroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['static'],routecountb['static'])
                    routestaticmatch = False
                if 'ospf' in routecounta.keys() and 'ospf' in routecountb.keys():
                    if routecounta['ospf'] == routecountb['ospf']:
                        richospfroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['ospf'],routecountb['ospf'])
                    elif routecounta['ospf'] < routecountb['ospf']:
                        richospfroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['ospf'],routecountb['ospf'])
                        routeospfmatch = False
                    elif routecounta['ospf'] > routecountb['ospf']:
                        richospfroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['ospf'],routecountb['ospf'])
                        routeospfmatch = False
                elif 'ospf' in routecounta.keys() and 'ospf' not in routecountb.keys():
                    richospfroutes = '[green]{}[/green]/[red]0'.format(routecounta['ospf'])
                    routeospfmatch = False
                elif 'ospf' not in routecounta.keys() and 'ospf' in routecountb.keys():
                    richospfroutes = '[red]0[/red]/[green]{}'.format(routecountb['ospf'])
                    routeospfmatch = False
                elif 'ospf' not in routecounta.keys() and 'ospf' not in routecountb.keys():
                    richospfroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'eigrp' in routecounta.keys() and 'eigrp' in routecountb.keys():
                    if routecounta['eigrp'] == routecountb['eigrp']:
                        richeigrproutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['eigrp'],routecountb['eigrp'])
                    elif routecounta['eigrp'] < routecountb['eigrp']:
                        richeigrproutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['eigrp'],routecountb['eigrp'])
                        routeeigrpmatch = False
                    elif routecounta['eigrp'] > routecountb['eigrp']:
                        richeigrproutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['eigrp'],routecountb['eigrp'])
                        routeeigrpmatch = False
                elif 'eigrp' in routecounta.keys() and 'eigrp' not in routecountb.keys():
                    richeigrproutes = '[green]{}[/green]/[red]0'.format(routecounta['eigrp'])
                    routeeigrpmatch = False
                elif 'eigrp' not in routecounta.keys() and 'eigrp' in routecountb.keys():
                    richeigrproutes = '[red]0[/red]/[green]{}'.format(routecountb['eigrp'])
                    routeeigrpmatch = False
                elif 'eigrp' not in routecounta.keys() and 'eigrp' not in routecountb.keys():
                    richeigrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'bgp' in routecounta.keys() and 'bgp' in routecountb.keys():
                    if routecounta['bgp'] == routecountb['bgp']:
                        richbgproutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['bgp'],routecountb['bgp'])
                    elif route_diff(routecounta['bgp'],routecountb['bgp']) < 2:
                        richbgproutes = '[cyan]{}[/cyan]/[cyan]{}[/cyan][cyan bold]*'.format(routecounta['bgp'],routecountb['bgp'])
                    elif routecounta['bgp'] < routecountb['bgp']:
                        richbgproutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['bgp'],routecountb['bgp'])
                        routebgpmatch = False
                    elif routecounta['bgp'] > routecountb['bgp']:
                        richbgproutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['bgp'],routecountb['bgp'])
                        routebgpmatch = False
                elif 'bgp' in routecounta.keys() and 'bgp' not in routecountb.keys():
                    richstaticroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['bgp'],routecountb['bgp'])
                    richbgproutes = '[green]{}[/green]/[red]0'.format(routecounta['bgp'])
                    routebgpmatch = False
                elif 'bgp' not in routecounta.keys() and 'bgp' in routecountb.keys():
                    richbgproutes = '[red]0[/red]/[green]{}'.format(routecountb['bgp'])
                    routebgpmatch = False
                elif 'bgp' not in routecounta.keys() and 'bgp' not in routecountb.keys():
                    richbgproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'connected' in routecounta.keys() and 'connected' in routecountb.keys():
                    if routecounta['connected'] == routecountb['connected']:
                        richconnectedroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['connected'],routecountb['connected'])
                    elif routecounta['connected'] < routecountb['connected']:
                        richconnectedroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['connected'],routecountb['connected'])
                        routeconnectedmatch = False
                    elif routecounta['connected'] > routecountb['connected']:
                        richconnectedroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['connected'],routecountb['connected'])
                        routeconnectedmatch = False
                elif 'connected' in routecounta.keys() and 'connected' not in routecountb.keys():
                    richconnectedroutes = '[green]{}[/green]/[red]0'.format(routecounta['connected'])
                    routeconnectedmatch = False
                elif 'connected' not in routecounta.keys() and 'connected' in routecountb.keys():
                    richconnectedroutes = '[red]0[/red]/[green]{}'.format(routecountb['connected'])
                    routeconnectedmatch = False
                elif 'connected' not in routecounta.keys() and 'connected' not in routecountb.keys():
                    richconnectedroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'local' in routecounta.keys() and 'local' in routecountb.keys():
                    if routecounta['local'] == routecountb['local']:
                        richlocalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['local'],routecountb['local'])
                    elif routecounta['local'] < routecountb['local']:
                        richlocalroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['local'],routecountb['local'])
                        routelocalmatch = False
                    elif routecounta['local'] > routecountb['local']:
                        richlocalroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['local'],routecountb['local'])
                        routelocalmatch = False
                elif 'local' in routecounta.keys() and 'local' not in routecountb.keys():
                    richlocalroutes = '[green]{}[/green]/[red]0'.format(routecounta['local'])
                    routelocalmatch = False
                elif 'local' not in routecounta.keys() and 'local' in routecountb.keys():
                    richlocalroutes = '[red]0[/red]/[green]{}'.format(routecountb['local'])
                    routelocalmatch = False
                elif 'local' not in routecounta.keys() and 'local' not in routecountb.keys():
                    richlocalroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'hsrp' in routecounta.keys() and 'hsrp' in routecountb.keys():
                    if routecounta['hsrp'] == routecountb['hsrp']:
                        richhsrproutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['hsrp'],routecountb['hsrp'])
                    elif routecounta['hsrp'] < routecountb['hsrp']:
                        richhsrproutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['hsrp'],routecountb['hsrp'])
                        routehsrpmatch = False
                    elif routecounta['hsrp'] > routecountb['hsrp']:
                        richhsrproutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['hsrp'],routecountb['hsrp'])
                        routehsrpmatch = False
                elif 'hsrp' in routecounta.keys() and 'hsrp' not in routecountb.keys():
                    richhsrproutes = '[green]{}[/green]/[red]0'.format(routecounta['hsrp'])
                    routehsrpmatch = False
                elif 'hsrp' not in routecounta.keys() and 'hsrp' in routecountb.keys():
                    richhsrproutes = '[red]0[/red]/[green]{}'.format(routecountb['hsrp'])
                    routehsrpmatch = False
                elif 'hsrp' not in routecounta.keys() and 'hsrp' not in routecountb.keys():
                    richhsrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'direct' in routecounta.keys() and 'direct' in routecountb.keys():
                    if routecounta['direct'] == routecountb['direct']:
                        richdirectroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['direct'],routecountb['direct'])
                    elif routecounta['direct'] < routecountb['direct']:
                        richdirectroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['direct'],routecountb['direct'])
                        routedirectmatch = False
                    elif routecounta['direct'] > routecountb['direct']:
                        richdirectroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['direct'],routecountb['direct'])
                        routedirectmatch = False
                elif 'direct' in routecounta.keys() and 'direct' not in routecountb.keys():
                    richdirectroutes = '[green]{}[/green]/[red]0'.format(routecounta['direct'])
                    routedirectmatch = False
                elif 'direct' not in routecounta.keys() and 'direct' in routecountb.keys():
                    richdirectroutes = '[red]0[/red]/[green]{}'.format(routecountb['direct'])
                    routedirectmatch = False
                elif 'direct' not in routecounta.keys() and 'direct' not in routecountb.keys():
                    richdirectroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                richvrfroutetablepre.add_row(vrfa,'{}/{}'.format(str(devicepre),str(devicepost)),richtotalroutes,richstaticroutes,richospfroutes,richeigrproutes,richbgproutes,richconnectedroutes,richlocalroutes,richhsrproutes,richdirectroutes,end_section=True)
            else:
                routetotala = int(master_dict[devicepre]['vrfs'][vrfa]['routing']['total_routes'])
                routetotalb = int(master_dict[devicepost]['vrfs'][vrfa]['routing']['total_routes'])
                if routetotala == routetotalb:
                    if routetotala == 0:
                        richtotalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routetotala,routetotalb)
                        richvrfroutetablepre.add_row('{}[red bold] *'.format(vrfa),'{}/{}'.format(str(devicepre),str(devicepost)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
                    else:
                        richtotalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routetotala,routetotalb)
                        richvrfroutetablepre.add_row('{}[blue bold] *'.format(vrfa),'{}/{}'.format(str(devicepre),str(devicepost)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
                elif routetotala > routetotalb:
                    richtotalroutes = '[green]{}[/green]/[red]{}[/red]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                    richvrfroutetablepre.add_row('{}[blue bold] *'.format(vrfa),'{}/{}'.format(str(devicepre),str(devicepost)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
                elif routetotala < routetotalb:
                    richtotalroutes = '[red]{}[/red]/[green]{}[/green]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                    richvrfroutetablepre.add_row('{}[blue bold] *'.format(vrfa),'{}/{}'.format(str(devicepre),str(devicepost)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
        else:
            if 'address_family' in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes'].keys() and 'ipv4' in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family'].keys():
                routecounta = Counter(master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'][route]['source_protocol'] for route in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'])
                routetotala = 0
                for k,v in routecounta.items():
                    routetotala = routetotala + int(v)
                richtotalroutes = '[green]{}[/green]/[red]0[/red]'.format(routetotala)
                routetotalmatch = False
                richstaticroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['static'])
                routestaticmatch = False
                if 'ospf' in routecounta.keys():
                    richospfroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['ospf'])
                    routeospfmatch = False
                else:
                    richospfroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'eigrp' in routecounta.keys() :
                    richeigrproutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['eigrp'])
                    routeeigrpmatch = False
                else:
                    richeigrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'bgp' in routecounta.keys():
                    richbgproutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['bgp'])
                    routebgpmatch = False
                else:
                    richbgproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'connected' in routecounta.keys():
                    richconnectedroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['connected'])
                    routeconnectedmatch = False
                else:
                    richconnectedroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'local' in routecounta.keys():
                    richlocalroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['local'])
                    routelocalmatch = False
                else:
                    richlocalroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'hsrp' in routecounta.keys():
                    richhsrproutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['hsrp'])
                    routehsrpmatch = False
                else:
                    richhsrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'direct' in routecounta.keys():
                    richdirectroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['direct'])
                    routedirectmatch = False
                else:
                    richdirectroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                richvrfroutetablepre.add_row(vrfa,'{}/{}'.format(str(devicepre),str(devicepost)),richtotalroutes,richstaticroutes,richospfroutes,richeigrproutes,richbgproutes,richconnectedroutes,richlocalroutes,richhsrproutes,richdirectroutes,end_section=True)
            



    for vrfa in master_dict[devicepost]['vrfs']:
        #for vrfb in master_dict[devicepre]['vrfs']:
            #if master_dict[devicepost]['interfaces'][inta]['type'] == 'EtherSVI':
        if vrfa in master_dict[devicepre]['vrfs']:
            if 'address_family' in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes'].keys() and 'ipv4' in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family'].keys():
                routecounta = Counter(master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'][route]['source_protocol'] for route in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'])
                routetotala = 0
                for k,v in routecounta.items():
                    routetotala = routetotala + int(v)
                if 'address_family' in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes'].keys():
                    if 'ipv4' in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family'].keys():
                        routecountb = Counter(master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'][route]['source_protocol'] for route in master_dict[devicepre]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'])
                    else:
                        routecountb = {}
                        routecountb['static'] = 0 
                else:
                    routecountb = {}
                    routecountb['static'] = 0   
                routetotalb = 0
                for k,v in routecountb.items():
                    routetotalb = routetotalb + int(v)
                if routetotala == routetotalb:
                    richtotalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routetotala,routetotalb)
                elif route_diff(routetotala,routetotalb) < 2:
                    richtotalroutes = '[cyan]{}[/cyan]/[cyan]{}[/cyan][cyan bold]*'.format(routetotala,routetotalb)
                elif routetotala > routetotalb:
                    richtotalroutes = '[green]{}[/green]/[red]{}[/red]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                elif routetotala < routetotalb:
                    richtotalroutes = '[red]{}[/red]/[green]{}[/green]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                if routecounta['static'] == routecountb['static']:
                    richstaticroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['static'],routecountb['static'])
                elif routecounta['static'] > routecountb['static']:
                    richstaticroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['static'],routecountb['static'])
                    routestaticmatch = False
                elif routecounta['static'] < routecountb['static']:
                    richstaticroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['static'],routecountb['static'])
                    routestaticmatch = False
                if 'ospf' in routecounta.keys() and 'ospf' in routecountb.keys():
                    if routecounta['ospf'] == routecountb['ospf']:
                        richospfroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['ospf'],routecountb['ospf'])
                    elif routecounta['ospf'] < routecountb['ospf']:
                        richospfroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['ospf'],routecountb['ospf'])
                        routeospfmatch = False
                    elif routecounta['ospf'] > routecountb['ospf']:
                        richospfroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['ospf'],routecountb['ospf'])
                        routeospfmatch = False
                elif 'ospf' in routecounta.keys() and 'ospf' not in routecountb.keys():
                    richospfroutes = '[green]{}[/green]/[red]0'.format(routecounta['ospf'])
                    routeospfmatch = False
                elif 'ospf' not in routecounta.keys() and 'ospf' in routecountb.keys():
                    richospfroutes = '[red]0[/red]/[green]{}'.format(routecountb['ospf'])
                    routeospfmatch = False
                elif 'ospf' not in routecounta.keys() and 'ospf' not in routecountb.keys():
                    richospfroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'eigrp' in routecounta.keys() and 'eigrp' in routecountb.keys():
                    if routecounta['eigrp'] == routecountb['eigrp']:
                        richeigrproutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['eigrp'],routecountb['eigrp'])
                    elif routecounta['eigrp'] < routecountb['eigrp']:
                        richeigrproutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['eigrp'],routecountb['eigrp'])
                        routeeigrpmatch = False
                    elif routecounta['eigrp'] > routecountb['eigrp']:
                        richeigrproutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['eigrp'],routecountb['eigrp'])
                        routeeigrpmatch = False
                elif 'eigrp' in routecounta.keys() and 'eigrp' not in routecountb.keys():
                    richeigrproutes = '[green]{}[/green]/[red]0'.format(routecounta['eigrp'])
                    routeeigrpmatch = False
                elif 'eigrp' not in routecounta.keys() and 'eigrp' in routecountb.keys():
                    richeigrproutes = '[red]0[/red]/[green]{}'.format(routecountb['eigrp'])
                    routeeigrpmatch = False
                elif 'eigrp' not in routecounta.keys() and 'eigrp' not in routecountb.keys():
                    richeigrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'bgp' in routecounta.keys() and 'bgp' in routecountb.keys():
                    if routecounta['bgp'] == routecountb['bgp']:
                        richbgproutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['bgp'],routecountb['bgp'])
                    elif route_diff(routecounta['bgp'],routecountb['bgp']) < 2:
                        richbgproutes = '[cyan]{}[/cyan]/[cyan]{}[/cyan][cyan bold]*'.format(routecounta['bgp'],routecountb['bgp'])
                    elif routecounta['bgp'] < routecountb['bgp']:
                        richbgproutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['bgp'],routecountb['bgp'])
                        routebgpmatch = False
                    elif routecounta['bgp'] > routecountb['bgp']:
                        richbgproutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['bgp'],routecountb['bgp'])
                        routebgpmatch = False
                elif 'bgp' in routecounta.keys() and 'bgp' not in routecountb.keys():
                    richstaticroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['bgp'],routecountb['bgp'])
                    richbgproutes = '[green]{}[/green]/[red]0'.format(routecounta['bgp'])
                    routebgpmatch = False
                elif 'bgp' not in routecounta.keys() and 'bgp' in routecountb.keys():
                    richbgproutes = '[red]0[/red]/[green]{}'.format(routecountb['bgp'])
                    routebgpmatch = False
                elif 'bgp' not in routecounta.keys() and 'bgp' not in routecountb.keys():
                    richbgproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'connected' in routecounta.keys() and 'connected' in routecountb.keys():
                    if routecounta['connected'] == routecountb['connected']:
                        richconnectedroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['connected'],routecountb['connected'])
                    elif routecounta['connected'] < routecountb['connected']:
                        richconnectedroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['connected'],routecountb['connected'])
                        routeconnectedmatch = False
                    elif routecounta['connected'] > routecountb['connected']:
                        richconnectedroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['connected'],routecountb['connected'])
                        routeconnectedmatch = False
                elif 'connected' in routecounta.keys() and 'connected' not in routecountb.keys():
                    richconnectedroutes = '[green]{}[/green]/[red]0'.format(routecounta['connected'])
                    routeconnectedmatch = False
                elif 'connected' not in routecounta.keys() and 'connected' in routecountb.keys():
                    richconnectedroutes = '[red]0[/red]/[green]{}'.format(routecountb['connected'])
                    routeconnectedmatch = False
                elif 'connected' not in routecounta.keys() and 'connected' not in routecountb.keys():
                    richconnectedroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'local' in routecounta.keys() and 'local' in routecountb.keys():
                    if routecounta['local'] == routecountb['local']:
                        richlocalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['local'],routecountb['local'])
                    elif routecounta['local'] < routecountb['local']:
                        richlocalroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['local'],routecountb['local'])
                        routelocalmatch = False
                    elif routecounta['local'] > routecountb['local']:
                        richlocalroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['local'],routecountb['local'])
                        routelocalmatch = False
                elif 'local' in routecounta.keys() and 'local' not in routecountb.keys():
                    richlocalroutes = '[green]{}[/green]/[red]0'.format(routecounta['local'])
                    routelocalmatch = False
                elif 'local' not in routecounta.keys() and 'local' in routecountb.keys():
                    richlocalroutes = '[red]0[/red]/[green]{}'.format(routecountb['local'])
                    routelocalmatch = False
                elif 'local' not in routecounta.keys() and 'local' not in routecountb.keys():
                    richlocalroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'hsrp' in routecounta.keys() and 'hsrp' in routecountb.keys():
                    if routecounta['hsrp'] == routecountb['hsrp']:
                        richhsrproutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['hsrp'],routecountb['hsrp'])
                    elif routecounta['hsrp'] < routecountb['hsrp']:
                        richhsrproutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['hsrp'],routecountb['hsrp'])
                        routehsrpmatch = False
                    elif routecounta['hsrp'] > routecountb['hsrp']:
                        richhsrproutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['hsrp'],routecountb['hsrp'])
                        routehsrpmatch = False
                elif 'hsrp' in routecounta.keys() and 'hsrp' not in routecountb.keys():
                    richhsrproutes = '[green]{}[/green]/[red]0'.format(routecounta['hsrp'])
                    routehsrpmatch = False
                elif 'hsrp' not in routecounta.keys() and 'hsrp' in routecountb.keys():
                    richhsrproutes = '[red]0[/red]/[green]{}'.format(routecountb['hsrp'])
                    routehsrpmatch = False
                elif 'hsrp' not in routecounta.keys() and 'hsrp' not in routecountb.keys():
                    richhsrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'direct' in routecounta.keys() and 'direct' in routecountb.keys():
                    if routecounta['direct'] == routecountb['direct']:
                        richdirectroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routecounta['direct'],routecountb['direct'])
                    elif routecounta['direct'] < routecountb['direct']:
                        richdirectroutes = '[green]{}[/green]/[red]{}[/red]'.format(routecounta['direct'],routecountb['direct'])
                        routedirectmatch = False
                    elif routecounta['direct'] > routecountb['direct']:
                        richdirectroutes = '[red]{}[/red]/[green]{}[/green]'.format(routecounta['direct'],routecountb['direct'])
                        routedirectmatch = False
                elif 'direct' in routecounta.keys() and 'direct' not in routecountb.keys():
                    richdirectroutes = '[green]{}[/green]/[red]0'.format(routecounta['direct'])
                    routedirectmatch = False
                elif 'direct' not in routecounta.keys() and 'direct' in routecountb.keys():
                    richdirectroutes = '[red]0[/red]/[green]{}'.format(routecountb['direct'])
                    routedirectmatch = False
                elif 'direct' not in routecounta.keys() and 'direct' not in routecountb.keys():
                    richdirectroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                richvrfroutetablepost.add_row(vrfa,'{}/{}'.format(str(devicepost),str(devicepre)),richtotalroutes,richstaticroutes,richospfroutes,richeigrproutes,richbgproutes,richconnectedroutes,richlocalroutes,richhsrproutes,richdirectroutes,end_section=True)
            else:
                routetotala = int(master_dict[devicepost]['vrfs'][vrfa]['routing']['total_routes'])
                routetotalb = int(master_dict[devicepre]['vrfs'][vrfa]['routing']['total_routes'])
                if routetotala == routetotalb:
                    if routetotala == 0:
                        richtotalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routetotala,routetotalb)
                        richvrfroutetablepost.add_row('{}[red bold] *'.format(vrfa),'{}/{}'.format(str(devicepost),str(devicepre)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
                    else:
                        richtotalroutes = '[yellow]{}[/yellow]/[yellow]{}[/yellow]'.format(routetotala,routetotalb)
                        richvrfroutetablepost.add_row('{}[blue bold] *'.format(vrfa),'{}/{}'.format(str(devicepost),str(devicepre)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
                elif routetotala > routetotalb:
                    richtotalroutes = '[green]{}[/green]/[red]{}[/red]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                    richvrfroutetablepost.add_row('{}[blue bold] *'.format(vrfa),'{}/{}'.format(str(devicepost),str(devicepre)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
                elif routetotala < routetotalb:
                    richtotalroutes = '[red]{}[/red]/[green]{}[/green]'.format(routetotala,routetotalb)
                    routetotalmatch = False
                    richvrfroutetablepost.add_row('{}[blue bold] *'.format(vrfa),'{}/{}'.format(str(devicepost),str(devicepre)),richtotalroutes,'---','---','---','---','---','---','---','---',end_section=True)
            #break
        else:
            if 'address_family' in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes'].keys() and 'ipv4' in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family'].keys():
                routecounta = Counter(master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'][route]['source_protocol'] for route in master_dict[devicepost]['vrfs'][vrfa]['routing']['routes']['address_family']['ipv4']['routes'])
                routetotala = 0
                for k,v in routecounta.items():
                    routetotala = routetotala + int(v)
                richtotalroutes = '[green]{}[/green]/[red]0[/red]'.format(routetotala)
                routetotalmatch = False
                richstaticroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['static'])
                routestaticmatch = False
                if 'ospf' in routecounta.keys():
                    richospfroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['ospf'])
                    routeospfmatch = False
                else:
                    richospfroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'eigrp' in routecounta.keys() :
                    richeigrproutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['eigrp'])
                    routeeigrpmatch = False
                else:
                    richeigrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'bgp' in routecounta.keys():
                    richbgproutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['bgp'])
                    routebgpmatch = False
                else:
                    richbgproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'connected' in routecounta.keys():
                    richconnectedroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['connected'])
                    routeconnectedmatch = False
                else:
                    richconnectedroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'local' in routecounta.keys():
                    richlocalroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['local'])
                    routelocalmatch = False
                else:
                    richlocalroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'hsrp' in routecounta.keys():
                    richhsrproutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['hsrp'])
                    routehsrpmatch = False
                else:
                    richhsrproutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                if 'direct' in routecounta.keys():
                    richdirectroutes = '[green]{}[/green]/[red]0[/red]'.format(routecounta['direct'])
                    routedirectmatch = False
                else:
                    richdirectroutes = '[yellow]0[/yellow]/[yellow]0[/yellow]'
                richvrfroutetablepost.add_row(vrfa,'{}/{}'.format(str(devicepost),str(devicepre)),richtotalroutes,richstaticroutes,richospfroutes,richeigrproutes,richbgproutes,richconnectedroutes,richlocalroutes,richhsrproutes,richdirectroutes,end_section=True)
            #continue





    if routetotalmatch and routestaticmatch and routeospfmatch and routeeigrpmatch and routebgpmatch and routeconnectedmatch and routelocalmatch and routehsrpmatch and routedirectmatch:
        allroutesmatch = True
    else:
        allroutesmatch = False
    return richvrfroutetablepre,richvrfroutetablepost,allroutesmatch