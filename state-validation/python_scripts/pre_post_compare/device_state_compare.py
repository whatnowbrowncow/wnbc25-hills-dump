from genie.testbed import load
from genie.utils.diff import Diff
from datetime import datetime
from rich.console import Console
from rich.table import Table
from comparisons.interface import compare_interfaces
from comparisons.mac import compare_mac
from comparisons.vlan import compare_vlan
from comparisons.routing import compare_routing
from comparisons.version import compare_version
from comparisons.switch import compare_switch
from comparisons.etherchannel import compare_etherchannel
from comparisons.vrfrouting import compare_vrfrouting
import json

summarytable = Table(title='Validation Check Summary',show_header=True, header_style="bold blue")
summarytable.add_column('Validation Check',justify='center')
summarytable.add_column('Result',justify='center')
def vrfroutesdetail(summarytable,vrfchoice,vrf):
    console.print('[blue italic]\nPlease choose and option to view further data....\n')
    console.print('[italic]unique routes pre                                  (1)')
    console.print('[italic]unique routes post                                 (2)')
    console.print('[italic]common routes pre/post                             (3)')
    console.print('[italic]Show me everything you got!                        (4)')
    console.print('[italic red]Back                                               [/italic red]([italic red]0[/italic red])\n')
    vrfrouteschoice = console.input('[italic]Choice:')
    if vrfrouteschoice == '1':
        console.print(vrf_routing_results['vrfs'][vrf]['uniquepreroutes'])
        console.print(vrf_routing_results['vrfs'][vrf]['vrfroutes'])
        vrfroutesdetail(summarytable,vrfchoice,vrf)
    elif vrfrouteschoice == '2':
        console.print(vrf_routing_results['vrfs'][vrf]['uniquepostroutes'])
        console.print(vrf_routing_results['vrfs'][vrf]['vrfroutes'])
        vrfroutesdetail(summarytable,vrfchoice,vrf)
    elif vrfrouteschoice == '3':
        console.print(vrf_routing_results['vrfs'][vrf]['commonroutes'])
        console.print(vrf_routing_results['vrfs'][vrf]['vrfroutes'])
        vrfroutesdetail(summarytable,vrfchoice,vrf)
    elif vrfrouteschoice == '4':
        console.print(vrf_routing_results['vrfs'][vrf]['uniquepreroutes'])
        console.print(vrf_routing_results['vrfs'][vrf]['uniquepostroutes'])
        console.print(vrf_routing_results['vrfs'][vrf]['commonroutes'])
        console.print(vrf_routing_results['vrfs'][vrf]['vrfroutes'])
        vrfroutesdetail(summarytable,vrfchoice,vrf)
    elif vrfrouteschoice == '0':
        vrfdetail(summarytable,vrfchoice)
        



def vrfdetail(summarytable,vrfchoice):
    if vrfchoice == '0':
        print_selection(summarytable)

    for vrf in vrf_routing_results['vrfs']:
        if str(vrf_routing_results['vrfs'][vrf]['vrfid']) == str(vrfchoice):
            vrftable = Table(title='{} results summary'.format(vrf),show_header=True, header_style="bold blue")
            vrftable.add_column('Validation Check')
            vrftable.add_column('Result')
            if vrf_routing_results['vrfs'][vrf]['missingfrompre'] == False and vrf_routing_results['vrfs'][vrf]['missingfrompost'] == False:
                vrftable.add_row('VRF present in both snapshots','[green]PASS')
            elif vrf_routing_results['vrfs'][vrf]['missingfrompre'] == False and vrf_routing_results['vrfs'][vrf]['missingfrompost'] == True:
                vrftable.add_row('VRF present in both snapshots','[green]FA[/green][red]IL')
            elif vrf_routing_results['vrfs'][vrf]['missingfrompre'] == True and vrf_routing_results['vrfs'][vrf]['missingfrompost'] == False:
                vrftable.add_row('VRF present in both snapshots','[red]FA[/red][green]IL')
            if vrf_routing_results['vrfs'][vrf]['vrfneighbormissing'] == False:
                vrftable.add_row('All VRF routing neighbors present......','[green]PASS')
            else:
                vrftable.add_row('All VRF routing neighbors present......','[red]FAIL')
            if vrf_routing_results['vrfs'][vrf]['vrfneighbormismatch'] == False:
                vrftable.add_row('All VRF routing neighbor data matches..','[green]PASS')
            else:
                vrftable.add_row('All VRF routing neighbor data matches..','[red]FAIL')
            if vrf_routing_results['vrfs'][vrf]['vrfroutetotalmismatch'] == False:
                vrftable.add_row('All VRF route totals match..','[green]PASS')
            else:
                vrftable.add_row('All VRF route totals match..','[red]FAIL')
            passtest = False
            console.print(vrftable)
            console.print()
            console.print('[blue italic]Please choose an option to view further data....\n')
            console.print('[italic]Routing summary                                   (1)')
            console.print('[italic]Routing neighbor summary                          (2)')
            console.print('[italic]Show me everything you got!                       (3)')
            console.print('[italic red]Back                                              [/italic red]([italic red]0[/italic red])\n')
            vrfdetailchoice = console.input('[italic]Choice:')
            if vrfdetailchoice == '1':
                console.print(vrf_routing_results['vrfs'][vrf]['vrfroutes'])
                vrfroutesdetail(summarytable,vrfchoice,vrf)
            elif vrfdetailchoice == '2':
                console.print(vrf_routing_results['vrfs'][vrf]['vrfrouting'])
                console.print('[blue bold]*[/blue bold][blue] 2% difference allowed for BGP prefixes due to constantly changing values')
                vrfdetail(summarytable,vrfchoice)
            #elif vrfdetailchoice == '3':
            #    console.print(vrf_routing_results['vrfs'][vrf]['uniquepreroutes'])
            #elif vrfdetailchoice == '4':
            #    console.print(vrf_routing_results['vrfs'][vrf]['uniquepostroutes'])
            #elif vrfdetailchoice == '5':
            #    console.print(vrf_routing_results['vrfs'][vrf]['commonroutes'])
            elif vrfdetailchoice == '3':
                console.print(vrf_routing_results['vrfs'][vrf]['vrfroutes'])
                console.print(vrf_routing_results['vrfs'][vrf]['vrfrouting'])
                console.print(vrf_routing_results['vrfs'][vrf]['uniquepreroutes'])
                console.print(vrf_routing_results['vrfs'][vrf]['uniquepostroutes'])
                console.print(vrf_routing_results['vrfs'][vrf]['commonroutes'])
                vrfroutingsummary(summarytable)
            elif vrfdetailchoice == '0':
                vrfroutingsummary(summarytable)

def vrfroutingsummary(summarytable):
    vrfroutingsummarytable = Table(title='VRF routing Summary',show_header=True, header_style="bold blue")
    vrfroutingsummarytable.add_column('VRF')
    vrfroutingsummarytable.add_column('VRF present in both snapshots')
    vrfroutingsummarytable.add_column('All VRF routing neighbors present')
    vrfroutingsummarytable.add_column('All VRF routing neighbor data matches')
    vrfroutingsummarytable.add_column('All VRF route totals match')
    vrfroutingsummarytable.add_column('Result')
    for vrf in vrf_routing_results['vrfs']:
        passtest = True
        if vrf_routing_results['vrfs'][vrf]['missingfrompre'] == False and vrf_routing_results['vrfs'][vrf]['missingfrompost'] == False:
            vrfpresent ='[green]PASS'
            if vrf_routing_results['vrfs'][vrf]['vrfneighbormissing'] == False:
               vrfneighbormissing ='[green]PASS'
            else:
                vrfneighbormissing = '[red]FAIL'
                passtest = False
            if vrf_routing_results['vrfs'][vrf]['vrfneighbormismatch'] == False:
                vrfneighbormismatch = '[green]PASS'
            else:
                vrfneighbormismatch = '[red]FAIL'
                passtest = False
            if vrf_routing_results['vrfs'][vrf]['vrfroutetotalmismatch'] == False:
                vrfroutetotalmismatch = '[green]PASS'
            else:
                vrfroutetotalmismatch = '[red]FAIL'
                passtest = False
        elif vrf_routing_results['vrfs'][vrf]['missingfrompre'] == False and vrf_routing_results['vrfs'][vrf]['missingfrompost'] == True:
            vrfpresent ='[green]FA[/green][red]IL'
            passtest = False
            vrfneighbormissing = '[red]FAIL'
            vrfneighbormismatch = '[red]FAIL'
            vrfroutetotalmismatch = '[red]FAIL'
        elif vrf_routing_results['vrfs'][vrf]['missingfrompre'] == True and vrf_routing_results['vrfs'][vrf]['missingfrompost'] == False:
            vrfpresent ='[red]FA[/red][green]IL'
            passtest = False
            vrfneighbormissing = '[red]FAIL'
            vrfneighbormismatch = '[red]FAIL'
            vrfroutetotalmismatch = '[red]FAIL'
        if passtest:
            vrfroutingsummarytable.add_row('{}'.format(vrf + '...('+ str(vrf_routing_results['vrfs'][vrf]['vrfid'])+')'),vrfpresent,vrfneighbormissing,vrfneighbormismatch,vrfroutetotalmismatch,'[green]PASS')
        else:
            vrfroutingsummarytable.add_row('{}'.format(vrf + '...('+ str(vrf_routing_results['vrfs'][vrf]['vrfid'])+')'),vrfpresent,vrfneighbormissing,vrfneighbormismatch,vrfroutetotalmismatch,'[red]FAIL')
    vrfroutingsummarytable.add_row('[red italic]Back(0)')
    console.print(vrfroutingsummarytable)
    console.print('\n[blue italic]Please use the numbers above to view a VRF to view in more detail in more detail.......\n')
    vrfchoice = console.input('[italic]Choice:')
    console.print()
    vrfdetail(summarytable,vrfchoice)

def print_selection(summarytable):
    console.print(summarytable)
    console.print('\n[blue italic]Please use the numbers above to view data in more detail.......\n')
    choice = console.input('[italic]Choice:')
    
    if choice == '1':
        console.print(inttable)
        print()
        return choice
    elif choice == '2':
        if mactable == 0:
            console.print('[red]No MAC/CDP data found')     
        else:    
            console.print(mactable)
        print()
        return choice
    elif choice == '3':
        if vlansumtable == 0:
            console.print('[red]NO VLANS CONFIGURED ON DEVICE')
        else:
            console.print(vlansumtable)
            print()
            console.print(vlantable)
        print()
        return choice
    elif choice == '4':
        console.print(routingtablepre)
        console.print('[blue bold]*[/blue bold][blue] Number of routes too large to process in detail')
        console.print('[cyan bold]*[/cyan bold][cyan] 2 % diff allowance for totals')
        console.print('[red bold]*[/red bold][red] No routes found to process')
        print()
        console.print(routingtablepost)
        console.print('[blue bold]*[/blue bold][blue] Number of routes too large to process in detail')
        console.print('[cyan bold]*[/cyan bold][cyan] 2 % diff allowance for totals')
        console.print('[red bold]*[/red bold][red] No routes found to process')
        print()
        return choice
    elif choice == '5':
        if osmatch == True:
            console.print(vertable)
            print()
            return choice
        else:
            console.print('''[red]\n###################################################\nOS versions don't match pre/post, no data to show...........\n###################################################\n''')
            print()
            return choice  
    elif choice == '6':
        if stacktable == 0:
            console.print('''[red]\n###################################################\nNo switch information available for this device\n###################################################\n''')
        else:    
            console.print(stacktable)
        print()
        return choice
    elif choice == '7':
        if ethertable == 0:
            console.print('''[red]\n###################################################\nNo etherchannel information available for this device\n###################################################\n''')
        else:
            console.print(ethertable)
            console.print('[cyan]Member interface key:')
            print()
            console.print('[green]Etherchannel member matches pre/post:')
            console.print('[red]Etherchannel member is present pre but missing post')
            console.print('[yellow]Etherchannel member is present post but missing pre')
        print()
        return choice
    elif choice == '8':
        vrfroutingsummary(summarytable)
        return choice
    else:
        return choice
    

console = Console()
console.print('\n[italic dim]Enter the name of the device you wish to compare\n')
target_device = console.input('Device:')

console.print('\n[dim yellow]Target device is[/dim yellow] [yellow bold] {}\n'.format(target_device))

console.print('[italic dim]Are you comparing this device following an upgrade? Y/(N)\n')
upgrade = console.input('Y/(N):')

if upgrade == 'Y' or upgrade == 'y':
    upgrade = True
else:
    upgrade = False

########################################################################################################################################################### GET TIME ########################################################################################################

curtime = str(datetime.now().strftime('%H_%M_%S_%d_%m_%Y'))

with open('./json_log_files/'+target_device+'/master_dict_pre_latest.json') as json_file: 
    master_dict_pre=json.load(json_file)

with open('./json_log_files/'+target_device+'/master_dict_post_latest.json') as json_file: 
    master_dict_post=json.load(json_file)
master_dict_pre.update(master_dict_post)
master_dict = master_dict_pre

with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json', "w") as outfile: 
    json.dump(master_dict, outfile)

#with open('./json_log_files/'+target_device+'/master_dict_merge_'+curtime+'.json', "w") as outfile: 
#    json.dump(master_dict, outfile)

devicepre = str(target_device) + '-pre'
devicepost = str(target_device) + '-post'

#if master_dict[devicepre]['os'] != master_dict[devicepost]['os']:
#    console.print('''
#[red]#############################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################-WARNING-###############################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################
#The two datasets are from devices of different 'os' type, comparison may not be like for like
##############################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################-WARNING-###############################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################################\n''')
#    proceed = console.input('''[red]Do you wish to continue? Y/(N)
#''').lower()
#    if proceed != 'y':  
#        exit()







console.print('\n[dim yellow]Running state validation checks please wait, this may take a few seconds...........\n')

inttable,missingint,missmatchfound = compare_interfaces(target_device,devicepre,devicepost)
mactable,macmatch = compare_mac(target_device,devicepre,devicepost)
vlansumtable,vlantable,vlanmismatch = compare_vlan(target_device,devicepre,devicepost)
routingtablepre,routingtablepost,allroutesmatch = compare_routing(target_device,devicepre,devicepost)
if master_dict[devicepre]['os'] == master_dict[devicepost]['os']:
    vertable,vermismatch,postverhigh = compare_version(target_device,devicepre,devicepost,upgrade)
    osmatch = True
else:
    console.print('''\n[dim red]OS versions don't match pre/post, skipping version check...........\n''')
    osmatch = False
stacktable,switchmismatch,stackmismatch = compare_switch(target_device,devicepre,devicepost)
ethertable,ethermismatchfound,ethermembermismatchfound = compare_etherchannel(target_device,devicepre,devicepost)
vrf_routing_results,vrfneighbormismatch = compare_vrfrouting(target_device,devicepre,devicepost)



console.print('[green]State validation checks complete\n')


if missingint == True or missmatchfound == True:
    summarytable.add_row('([yellow]1[/yellow])Interface Check ...................','[red]FAIL')
else:
    summarytable.add_row('([yellow]1[/yellow])Interface Check ...................','[green]PASS')
if mactable == 0:
    summarytable.add_row('([yellow]2[/yellow])MAC Address / CDP Check ...........','[yellow]N/A')
elif macmatch == True:
    summarytable.add_row('([yellow]2[/yellow])MAC Address / CDP Check ...........','[green]PASS')
else:
    summarytable.add_row('([yellow]2[/yellow])MAC Address / CDP Check ...........','[red]FAIL')
if vlansumtable == 0:
    summarytable.add_row('([yellow]3[/yellow])VLAN Check ........................','[yellow]N/A')
elif vlanmismatch == True:
    summarytable.add_row('([yellow]3[/yellow])VLAN Check ........................','[red]FAIL')
else:
    summarytable.add_row('([yellow]3[/yellow])VLAN Check ........................','[green]PASS')
if allroutesmatch == True:
    summarytable.add_row('([yellow]4[/yellow])Routing Check .....................','[green]PASS')
else:
    summarytable.add_row('([yellow]4[/yellow])Routing Check .....................','[red]FAIL')
if osmatch ==True:
    if upgrade == True and postverhigh == True and vermismatch == False:
        summarytable.add_row('([yellow]5[/yellow])Version Check .....................','[green]PASS')
    elif upgrade == False and postverhigh ==False and vermismatch == False:
        summarytable.add_row('([yellow]5[/yellow])Version Check .....................','[green]PASS')
    else:
        summarytable.add_row('([yellow]5[/yellow])Version Check .....................','[red]FAIL')
else:
    summarytable.add_row('([yellow]5[/yellow])Version Check .....................','[yellow]N/A')
if stacktable == 0:
    summarytable.add_row('([yellow]6[/yellow])Switch Stack Check ................','[yellow]N/A')
elif stackmismatch == False and switchmismatch == False:
    summarytable.add_row('([yellow]6[/yellow])Switch Stack Check ................','[green]PASS')
else:
    summarytable.add_row('([yellow]6[/yellow])Switch Stack Check ................','[red]FAIL')
if ethertable == 0:
    summarytable.add_row('([yellow]7[/yellow])Etherchannel Check ................','[yellow]N/A')
elif ethermismatchfound == False and ethermembermismatchfound == False:
    summarytable.add_row('([yellow]7[/yellow])Etherchannel Check ................','[green]PASS')
else:
    summarytable.add_row('([yellow]7[/yellow])Etherchannel Check ................','[red]FAIL')
if vrfneighbormismatch == False:
    summarytable.add_row('([yellow]8[/yellow])VRF Check .........................','[green]PASS')
else:
    summarytable.add_row('([yellow]8[/yellow])VRF Check .........................','[red]FAIL')

#console.print(summarytable)

choice = '1'
valid_choice = ['1','2','3','4','5','6','7','8','9']
while choice in valid_choice:
    choice = print_selection(summarytable)


