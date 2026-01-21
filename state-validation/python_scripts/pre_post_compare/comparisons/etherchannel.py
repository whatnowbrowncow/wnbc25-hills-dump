from prettytable import PrettyTable
from termcolor import colored
from rich.table import Table
import json

def compare_etherchannel(target_device,devicepre,devicepost):
    
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)
    #devicepre = str(target_device) + '-pre'
    #devicepost = str(target_device) + '-post'
    #console = Console()
    #print()
    #console.print('[cyan]#############################Checking for interface differences#########################')
    #print()
    ethermismatchfound = False
    ethermembermismatchfound = False

    ethertablena = True
    if master_dict[devicepre]['Etherchannel_data'] != 'N/A' and 'interfaces' in master_dict[devicepre]['Etherchannel_data'].keys():
        if master_dict[devicepost]['Etherchannel_data'] != 'N/A' and 'interfaces' in master_dict[devicepost]['Etherchannel_data'].keys():
            ethertablena = False
            ethertable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','number of members'])
            robotethertable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','number of members'])
            richethertable = Table(title='Etherchannel Data',show_header=True, header_style="bold blue")
            richethertable.add_column('Device')
            richethertable.add_column('Etherchannel',justify='center')
            richethertable.add_column('Bundle ID',justify='center')
            richethertable.add_column('Protocol',justify='center')
            richethertable.add_column('Status',justify='center')
            richethertable.add_column('Flags',justify='center')
            richethertable.add_column('Number of Members',justify='center')
            ethermemtable = PrettyTable(['Device','Etherchannel','Member','Flags','status','number of members'])
            robotethermemtable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','members'])
            tablesplit = ['---','---','---','---','---','---']
            #devicepre = str(target_device) + '-pre'
            #devicepost = str(target_device) + '-post'
            prepath = master_dict[devicepre]['Etherchannel_data']['interfaces']
            postpath = master_dict[devicepost]['Etherchannel_data']['interfaces']
            for preetherchannel in prepath:
                if preetherchannel in postpath.keys():
                    prerow = [devicepre,colored(preetherchannel,'green')]
                    postrow = [devicepost,colored(preetherchannel,'green')]
                    robotprerow = [devicepre,preetherchannel]
                    robotpostrow = [devicepost,preetherchannel]
                    if prepath[preetherchannel]['bundle_id'] == postpath[preetherchannel]['bundle_id']:
                        prerow.append(colored(prepath[preetherchannel]['bundle_id'],'green'))
                        postrow.append(colored(postpath[preetherchannel]['bundle_id'],'green'))
                        robotprerow.append(prepath[preetherchannel]['bundle_id'])
                        robotpostrow.append(postpath[preetherchannel]['bundle_id'])
                        richbundle_pre = '[green]{}'.format(prepath[preetherchannel]['bundle_id'])
                        richbundle_post = '[green]{}'.format(postpath[preetherchannel]['bundle_id'])
                    else:
                        prerow.append(colored(prepath[preetherchannel]['bundle_id'],'red'))
                        postrow.append(colored(postpath[preetherchannel]['bundle_id'],'red'))
                        robotprerow.append(prepath[preetherchannel]['bundle_id'])
                        robotpostrow.append(postpath[preetherchannel]['bundle_id'])
                        richbundle_pre = '[red]{}'.format(prepath[preetherchannel]['bundle_id'])
                        richbundle_post = '[red]{}'.format(postpath[preetherchannel]['bundle_id'])
                        ethermismatchfound = True
                    
                    if 'protocol' in prepath[preetherchannel].keys() and 'protocol' in postpath[preetherchannel].keys():
                        if prepath[preetherchannel]['protocol'] == postpath[preetherchannel]['protocol']:
                            prerow.append(colored(prepath[preetherchannel]['protocol'],'green'))
                            postrow.append(colored(postpath[preetherchannel]['protocol'],'green'))
                            robotprerow.append(prepath[preetherchannel]['protocol'])
                            robotpostrow.append(postpath[preetherchannel]['protocol'])
                            richprotocol_pre = '[green]{}'.format(prepath[preetherchannel]['protocol'])
                            richprotocol_post = '[green]{}'.format(postpath[preetherchannel]['protocol'])
                        else:
                            prerow.append(colored(prepath[preetherchannel]['protocol'],'red'))
                            postrow.append(colored(postpath[preetherchannel]['protocol'],'red'))
                            robotprerow.append(prepath[preetherchannel]['protocol'])
                            robotpostrow.append(postpath[preetherchannel]['protocol'])
                            richprotocol_pre = '[red]{}'.format(prepath[preetherchannel]['protocol'])
                            richprotocol_post = '[red]{}'.format(postpath[preetherchannel]['protocol'])
                            ethermismatchfound = True
        
                    elif 'protocol' in prepath[preetherchannel].keys() and 'protocol' not in postpath[preetherchannel].keys():
                            prerow.append(colored(prepath[preetherchannel]['protocol'],'red'))
                            postrow.append(colored('N/A','red'))
                            robotprerow.append(prepath[preetherchannel]['protocol'])
                            robotpostrow.append('N/A')
                            richprotocol_pre = '[red]{}'.format(prepath[preetherchannel]['protocol'])
                            richprotocol_post = '[red]N/A'
                            ethermismatchfound = True
                    elif 'protocol' not in prepath[preetherchannel].keys() and 'protocol' in postpath[preetherchannel].keys():
                            prerow.append(colored('N/A','red'))
                            postrow.append(colored(postpath[preetherchannel]['protocol'],'red'))
                            robotprerow.append('N/A')
                            robotpostrow.append(postpath[preetherchannel]['protocol'])
                            richprotocol_pre = '[red]N/A'
                            richprotocol_post = '[red]{}'.format(postpath[preetherchannel]['protocol'])
                            ethermismatchfound = True
                    elif 'protocol' not in prepath[preetherchannel].keys() and 'protocol' not in postpath[preetherchannel].keys():
                            prerow.append(colored('N/A','green'))
                            postrow.append(colored('N/A','green'))
                            robotprerow.append('N/A')
                            robotpostrow.append('N/A')
                            richprotocol_pre = '[green]N/A'
                            richprotocol_post = '[green]N/A'
                            #ethermismatchfound = True
        
                    if prepath[preetherchannel]['oper_status'] == postpath[preetherchannel]['oper_status']:
                        prerow.append(colored(prepath[preetherchannel]['oper_status'],'green'))
                        postrow.append(colored(postpath[preetherchannel]['oper_status'],'green'))
                        robotprerow.append(prepath[preetherchannel]['oper_status'])
                        robotpostrow.append(postpath[preetherchannel]['oper_status'])
                        richopstatus_pre = '[green]{}'.format(prepath[preetherchannel]['oper_status'])
                        richopstatus_post = '[green]{}'.format(postpath[preetherchannel]['oper_status'])
                    else:
                        prerow.append(colored(prepath[preetherchannel]['oper_status'],'red'))
                        postrow.append(colored(postpath[preetherchannel]['oper_status'],'red'))
                        robotprerow.append(prepath[preetherchannel]['oper_status'])
                        robotpostrow.append(postpath[preetherchannel]['oper_status'])
                        richopstatus_pre = '[red]{}'.format(prepath[preetherchannel]['oper_status'])
                        richopstatus_post = '[red]{}'.format(postpath[preetherchannel]['oper_status'])
                        ethermismatchfound = True
        
                    if prepath[preetherchannel]['flags'] == postpath[preetherchannel]['flags']:
                        richflags_pre = '[green]{}'.format(prepath[preetherchannel]['flags'])
                        richflags_post = '[green]{}'.format(postpath[preetherchannel]['flags'])
                    else:
                        richflags_pre = '[red]{}'.format(prepath[preetherchannel]['flags'])
                        richflags_post = '[red]{}'.format(postpath[preetherchannel]['flags'])
                        ethermismatchfound = True
                    
                    if 'members' in prepath[preetherchannel].keys() and 'members' in postpath[preetherchannel].keys():            
                        if len(prepath[preetherchannel]['members']) == len(postpath[preetherchannel]['members']):
                            prerow.append(colored(len(prepath[preetherchannel]['members']),'green'))
                            postrow.append(colored(len(postpath[preetherchannel]['members']),'green'))
                            robotprerow.append(len(prepath[preetherchannel]['members']))
                            robotpostrow.append(len(postpath[preetherchannel]['members']))
                            richmembers_pre = '[green]{}'.format(len(prepath[preetherchannel]['members']))
                            richmembers_post = '[green]{}'.format(len(postpath[preetherchannel]['members']))
                        else:
                            prerow.append(colored(len(prepath[preetherchannel]['members']),'red'))
                            postrow.append(colored(len(postpath[preetherchannel]['members']),'red'))
                            robotprerow.append(len(prepath[preetherchannel]['members']))
                            robotpostrow.append(len(postpath[preetherchannel]['members']))
                            richmembers_pre = '[red]{}'.format(len(prepath[preetherchannel]['members']))
                            richmembers_post = '[red]{}'.format(len(postpath[preetherchannel]['members']))
                            ethermismatchfound = True
                    elif 'members' in prepath[preetherchannel].keys() and 'members' not in postpath[preetherchannel].keys():
                        prerow.append(colored(len(prepath[preetherchannel]['members']),'red'))
                        postrow.append(colored(0,'red'))
                        robotprerow.append(len(prepath[preetherchannel]['members']))
                        robotpostrow.append(0)
                        richmembers_pre = '[red]{}'.format(len(prepath[preetherchannel]['members']))
                        richmembers_post = '[red]{}'.format(0)
                        ethermismatchfound = True
                    elif 'members' not in prepath[preetherchannel].keys() and 'members' in postpath[preetherchannel].keys():
                        prerow.append(colored(0,'red'))
                        postrow.append(colored(len(postpath[preetherchannel]['members']),'red'))
                        robotprerow.append(0)
                        robotpostrow.append(len(postpath[preetherchannel]['members']))
                        richmembers_pre = '[red]{}'.format(0)
                        richmembers_post = '[red]{}'.format(len(postpath[preetherchannel]['members']))
                        ethermismatchfound = True
                    elif 'members' not in prepath[preetherchannel].keys() and 'members' not in postpath[preetherchannel].keys():
                        prerow.append(colored(0,'green'))
                        postrow.append(colored(0,'green'))
                        robotprerow.append(0)
                        robotpostrow.append(0)
                        richmembers_pre = '[green]{}'.format(0)
                        richmembers_post = '[green]{}'.format(0)
                        #ethermismatchfound = True
                    ethertable.add_row(prerow)
                    ethertable.add_row(postrow)
                    robotethertable.add_row(robotprerow)
                    robotethertable.add_row(robotpostrow)
                    richethertable.add_row(devicepre,'[green]{}'.format(preetherchannel),richbundle_pre,richprotocol_pre,richopstatus_pre,richflags_pre,richmembers_pre)
                    richethertable.add_row(devicepost,'[green]{}'.format(preetherchannel),richbundle_post,richprotocol_post,richopstatus_post,richflags_post,richmembers_post)
                    ethertable.add_row(tablesplit)
                    robotethertable.add_row(tablesplit)
                    if 'members' in prepath[preetherchannel].keys() and 'members' in postpath[preetherchannel].keys():
                        richethertable.add_row('Members:')
                        for member in prepath[preetherchannel]['members']:
                            if member in postpath[preetherchannel]['members'].keys():
                                memberrow = [colored(member,'green'),'---','---','---','---','---']
                                robotmemberrow = [member,'---','---','---','---','---']
                                richethertable.add_row('[green]{}'.format(member),'---','---','---','---','---','---')
                            else:
                                memberrow = [colored(member,'red'),'---','---','---','---','---']
                                robotmemberrow = [member,'---','---','---','---','---']
                                richethertable.add_row('[red]{}'.format(member),'---','---','---','---','---','---')
                                ethermembermismatchfound = True
                            ethertable.add_row(memberrow)
                            robotethertable.add_row(robotmemberrow)
                        for member in postpath[preetherchannel]['members']:
                            if member not in prepath[preetherchannel]['members'].keys():
                                memberrow = [colored(member,'yellow'),'---','---','---','---','---']
                                robotmemberrow = [member,'---','---','---','---','---']
                                richethertable.add_row('[yellow]{}'.format(member),'---','---','---','---','---','---')
                                ethertable.add_row(memberrow)
                                robotethertable.add_row(robotmemberrow)
                                ethermembermismatchfound = True
                    elif 'members' in prepath[preetherchannel].keys() and 'members' not in postpath[preetherchannel].keys():
                        richethertable.add_row('Members:')
                        for member in prepath[preetherchannel]['members']:
                            memberrow = [colored(member,'red'),'---','---','---','---','---']
                            robotmemberrow = [member,'---','---','---','---','---']
                            richethertable.add_row('[red]{}'.format(member),'---','---','---','---','---','---')
                            ethertable.add_row(memberrow)
                            robotethertable.add_row(robotmemberrow)
                            ethermembermismatchfound = True
                    elif 'members' not in prepath[preetherchannel].keys() and 'members' in postpath[preetherchannel].keys():
                        richethertable.add_row('Members:')
                        for member in postpath[preetherchannel]['members']:
                            memberrow = [colored(member,'yellow'),'---','---','---','---','---']
                            robotmemberrow = [member,'---','---','---','---','---']
                            richethertable.add_row('[yellow]{}'.format(member),'---','---','---','---','---','---')
                            ethertable.add_row(memberrow)
                            robotethertable.add_row(robotmemberrow)
                            ethermembermismatchfound = True
                else:
                    ethermismatchfound = True
                    if 'protocol' in prepath[preetherchannel].keys() and 'members' in prepath[preetherchannel].keys():
                        prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored(prepath[preetherchannel]['protocol'],'red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(len(prepath[preetherchannel]['members']),'red')]
                        robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],prepath[preetherchannel]['protocol'],prepath[preetherchannel]['oper_status'],len(prepath[preetherchannel]['members'])]
                        richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]{}'.format(prepath[preetherchannel]['protocol']),'[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(len(prepath[preetherchannel]['members'])))
                        ethertable.add_row(prerow)
                        robotethertable.add_row(robotprerow)
                    elif 'protocol' in prepath[preetherchannel].keys() and 'members' not in prepath[preetherchannel].keys():
                        prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored(prepath[preetherchannel]['protocol'],'red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(0,'red')]
                        robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],prepath[preetherchannel]['protocol'],prepath[preetherchannel]['oper_status'],0]
                        richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]{}'.format(prepath[preetherchannel]['protocol']),'[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(0))
                        ethertable.add_row(prerow)
                        robotethertable.add_row(robotprerow)
                    elif 'protocol' not in prepath[preetherchannel].keys() and 'members' in prepath[preetherchannel].keys():
                        prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(len(prepath[preetherchannel]['members']),'red')]
                        robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],'N/A',prepath[preetherchannel]['oper_status'],len(prepath[preetherchannel]['members'])]
                        richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(len(prepath[preetherchannel]['members'])))
                        ethertable.add_row(prerow)
                        robotethertable.add_row(robotprerow)
                    elif 'protocol' not in prepath[preetherchannel].keys() and 'members' not in prepath[preetherchannel].keys():
                        prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(0,'red')]
                        robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],'N/A',prepath[preetherchannel]['oper_status'],0]
                        richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(0))
                        ethertable.add_row(prerow)
                        robotethertable.add_row(robotprerow)
                ethertable.add_row(tablesplit)
                robotethertable.add_row(tablesplit)
                richethertable.add_row(end_section=True)
            for postetherchannel in postpath:
                if postetherchannel not in postpath.keys():
                    ethermismatchfound = True
                    if 'protocol' in postpath[postetherchannel].keys() and 'members' in postpath[postetherchannel].keys():
                        postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored(postpath[postetherchannel]['protocol'],'red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(len(postpath[postetherchannel]['members']),'red')]
                        robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],postpath[postetherchannel]['protocol'],postpath[postetherchannel]['oper_status'],len(postpath[postetherchannel]['members'])]            
                        richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]{}'.format(postpath[postetherchannel]['protocol']),'[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(len(postpath[postetherchannel]['members'])))
                        ethertable.add_row(postrow)
                        robotethertable.add_row(robotpostrow)
                    elif 'protocol' in postpath[postetherchannel].keys() and 'members' not in postpath[postetherchannel].keys():
                        postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored(postpath[postetherchannel]['protocol'],'red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(0,'red')]
                        robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],postpath[postetherchannel]['protocol'],postpath[postetherchannel]['oper_status'],0]
                        richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]{}'.format(postpath[postetherchannel]['protocol']),'[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(0))
                        ethertable.add_row(postrow)
                        robotethertable.add_row(robotpostrow)
                    elif 'protocol' not in postpath[postetherchannel].keys() and 'members' in postpath[postetherchannel].keys():
                        postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(len(postpath[postetherchannel]['members']),'red')]
                        robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],'N/A',postpath[postetherchannel]['oper_status'],len(postpath[postetherchannel]['members'])]
                        richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(len(postpath[postetherchannel]['members'])))
                        ethertable.add_row(postrow)
                        robotethertable.add_row(robotpostrow)
                    elif 'protocol' not in postpath[postetherchannel].keys() and 'members' not in postpath[postetherchannel].keys():
                        postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(0,'red')]
                        robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],'N/A',postpath[postetherchannel]['oper_status'],0]
                        richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(0))
                        ethertable.add_row(postrow)
                        robotethertable.add_row(robotpostrow)
                    ethertable.add_row(tablesplit)
                    robotethertable.add_row(tablesplit)
                    richethertable.add_row(end_section=True)
        else:
            ethertablena = False
            ethermismatchfound = True
            #ethermembermismatchfound = False
            ethertable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','number of members'])
            robotethertable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','number of members'])
            richethertable = Table(title='Etherchannel Data',show_header=True, header_style="bold blue")
            richethertable.add_column('Device')
            richethertable.add_column('Etherchannel',justify='center')
            richethertable.add_column('Bundle ID',justify='center')
            richethertable.add_column('Protocol',justify='center')
            richethertable.add_column('Status',justify='center')
            richethertable.add_column('Flags',justify='center')
            richethertable.add_column('Number of Members',justify='center')
            ethermemtable = PrettyTable(['Device','Etherchannel','Member','Flags','status','number of members'])
            robotethermemtable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','members'])
            tablesplit = ['---','---','---','---','---','---']
            #devicepre = str(target_device) + '-pre'
            #devicepost = str(target_device) + '-post'
            prepath = master_dict[devicepre]['Etherchannel_data']['interfaces']
            for preetherchannel in prepath:
                if 'protocol' in prepath[preetherchannel].keys() and 'members' in prepath[preetherchannel].keys():
                    prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored(prepath[preetherchannel]['protocol'],'red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(len(prepath[preetherchannel]['members']),'red')]
                    robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],prepath[preetherchannel]['protocol'],prepath[preetherchannel]['oper_status'],len(prepath[preetherchannel]['members'])]
                    richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]{}'.format(prepath[preetherchannel]['protocol']),'[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(len(prepath[preetherchannel]['members'])))
                    ethertable.add_row(prerow)
                    robotethertable.add_row(robotprerow)
                elif 'protocol' in prepath[preetherchannel].keys() and 'members' not in prepath[preetherchannel].keys():
                    prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored(prepath[preetherchannel]['protocol'],'red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(0,'red')]
                    robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],prepath[preetherchannel]['protocol'],prepath[preetherchannel]['oper_status'],0]
                    richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]{}'.format(prepath[preetherchannel]['protocol']),'[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(0))
                    ethertable.add_row(prerow)
                    robotethertable.add_row(robotprerow)
                elif 'protocol' not in prepath[preetherchannel].keys() and 'members' in prepath[preetherchannel].keys():
                    prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(len(prepath[preetherchannel]['members']),'red')]
                    robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],'N/A',prepath[preetherchannel]['oper_status'],len(prepath[preetherchannel]['members'])]
                    richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(len(prepath[preetherchannel]['members'])))
                    ethertable.add_row(prerow)
                    robotethertable.add_row(robotprerow)
                elif 'protocol' not in prepath[preetherchannel].keys() and 'members' not in prepath[preetherchannel].keys():
                    prerow = [devicepre,colored(preetherchannel,'red'),colored(prepath[preetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(prepath[preetherchannel]['oper_status'],'red'),colored(0,'red')]
                    robotprerow = [devicepre,preetherchannel,prepath[preetherchannel]['bundle_id'],'N/A',prepath[preetherchannel]['oper_status'],0]
                    richethertable.add_row(devicepre,'[red]{}'.format(preetherchannel),'[red]{}'.format(prepath[preetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(prepath[preetherchannel]['oper_status']),'[red]{}'.format(prepath[preetherchannel]['flags']),'[red]{}'.format(0))
                    ethertable.add_row(prerow)
                    robotethertable.add_row(robotprerow)

                if 'members' in prepath[preetherchannel].keys():
                    richethertable.add_row('Members:')
                    for member in prepath[preetherchannel]['members']:
                        memberrow = [colored(member,'red'),'---','---','---','---','---']
                        robotmemberrow = [member,'---','---','---','---','---']
                        richethertable.add_row('[red]{}'.format(member),'---','---','---','---','---','---')
                        ethertable.add_row(memberrow)
                        robotethertable.add_row(robotmemberrow)


                ethertable.add_row(tablesplit)
                robotethertable.add_row(tablesplit)
                richethertable.add_row(end_section=True)
        return richethertable,ethermismatchfound,ethermembermismatchfound    
    elif master_dict[devicepost]['Etherchannel_data'] != 'N/A' and 'interfaces' in master_dict[devicepost]['Etherchannel_data'].keys():
        ethertablena = False
        ethermismatchfound = True
        ethertable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','number of members'])
        robotethertable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','number of members'])
        richethertable = Table(title='Etherchannel Data',show_header=True, header_style="bold blue")
        richethertable.add_column('Device')
        richethertable.add_column('Etherchannel',justify='center')
        richethertable.add_column('Bundle ID',justify='center')
        richethertable.add_column('Protocol',justify='center')
        richethertable.add_column('Status',justify='center')
        richethertable.add_column('Flags',justify='center')
        richethertable.add_column('Number of Members',justify='center')
        ethermemtable = PrettyTable(['Device','Etherchannel','Member','Flags','status','number of members'])
        robotethermemtable = PrettyTable(['Device','Etherchannel','bundle ID','protocol','status','members'])
        tablesplit = ['---','---','---','---','---','---']
        #devicepre = str(target_device) + '-pre'
        #devicepost = str(target_device) + '-post'
        postpath = master_dict[devicepost]['Etherchannel_data']['interfaces']
        for postetherchannel in postpath:
            if 'protocol' in postpath[postetherchannel].keys() and 'members' in postpath[postetherchannel].keys():
                postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored(postpath[postetherchannel]['protocol'],'red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(len(postpath[postetherchannel]['members']),'red')]
                robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],postpath[postetherchannel]['protocol'],postpath[postetherchannel]['oper_status'],len(postpath[postetherchannel]['members'])]            
                richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]{}'.format(postpath[postetherchannel]['protocol']),'[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(len(postpath[postetherchannel]['members'])))
                ethertable.add_row(postrow)
                robotethertable.add_row(robotpostrow)
            elif 'protocol' in postpath[postetherchannel].keys() and 'members' not in postpath[postetherchannel].keys():
                postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored(postpath[postetherchannel]['protocol'],'red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(0,'red')]
                robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],postpath[postetherchannel]['protocol'],postpath[postetherchannel]['oper_status'],0]
                richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]{}'.format(postpath[postetherchannel]['protocol']),'[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(0))
                ethertable.add_row(postrow)
                robotethertable.add_row(robotpostrow)
            elif 'protocol' not in postpath[postetherchannel].keys() and 'members' in postpath[postetherchannel].keys():
                postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(len(postpath[postetherchannel]['members']),'red')]
                robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],'N/A',postpath[postetherchannel]['oper_status'],len(postpath[postetherchannel]['members'])]
                richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(len(postpath[postetherchannel]['members'])))
                ethertable.add_row(postrow)
                robotethertable.add_row(robotpostrow)
            elif 'protocol' not in postpath[postetherchannel].keys() and 'members' not in postpath[postetherchannel].keys():
                postrow = [devicepost,colored(postetherchannel,'red'),colored(postpath[postetherchannel]['bundle_id'],'red'),colored('N/A','red'),colored(postpath[postetherchannel]['oper_status'],'red'),colored(0,'red')]
                robotpostrow = [devicepost,postetherchannel,postpath[postetherchannel]['bundle_id'],'N/A',postpath[postetherchannel]['oper_status'],0]
                richethertable.add_row(devicepost,'[red]{}'.format(postetherchannel),'[red]{}'.format(postpath[postetherchannel]['bundle_id']),'[red]N/A','[red]{}'.format(postpath[postetherchannel]['oper_status']),'[red]{}'.format(postpath[postetherchannel]['flags']),'[red]{}'.format(0))
                ethertable.add_row(postrow)
                robotethertable.add_row(robotpostrow)
            if 'members' in postpath[postetherchannel].keys():
                richethertable.add_row('Members:')
                for member in postpath[postetherchannel]['members']:
                    memberrow = [colored(member,'yellow'),'---','---','---','---','---']
                    robotmemberrow = [member,'---','---','---','---','---']
                    richethertable.add_row('[yellow]{}'.format(member),'---','---','---','---','---','---')
                    ethertable.add_row(memberrow)
                    robotethertable.add_row(robotmemberrow)
            ethertable.add_row(tablesplit)
            robotethertable.add_row(tablesplit)
            richethertable.add_row(end_section=True)

        #print(ethertable)
        return richethertable,ethermismatchfound,ethermembermismatchfound
    else:
        print('here')
        return 0,False,False