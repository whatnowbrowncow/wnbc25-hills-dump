from prettytable import PrettyTable
from termcolor import colored
from rich.table import Table
import json

def compare_switch(target_device,devicepre,devicepost):
    
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)
    stackmissmatchfound = False
    mismatch = False
    richstacktable = Table(title='Switch Stack Data',show_header=True, header_style="bold blue")
    richstacktable.add_column('Device')
    richstacktable.add_column('Switch Number',justify='center')
    richstacktable.add_column('Role',justify='center')
    richstacktable.add_column('State',justify='center')
    richstacktable.add_column('Priority',justify='center')
    richstacktable.add_column('MAC Address',justify='center')

    if master_dict[devicepre]['switch_data'] != 'N/A' and 'switch' in master_dict[devicepre]['switch_data'].keys() and master_dict[devicepost]['switch_data'] != 'N/A' and 'switch' in master_dict[devicepost]['switch_data'].keys():
        if 'stack' in master_dict[devicepre]['switch_data']['switch'].keys() and 'stack' in master_dict[devicepost]['switch_data']['switch'].keys():
            prepath = master_dict[devicepre]['switch_data']['switch']['stack']
            postpath = master_dict[devicepost]['switch_data']['switch']['stack']
            for premember in prepath:
                if premember in postpath.keys():
                    if prepath[premember]['role'] == postpath[premember]['role']:
                        richrole_pre = '[green]{}'.format(prepath[premember]['role'])
                        richrole_post = '[green]{}'.format(postpath[premember]['role'])
                    else:
                        richrole_pre = '[red]{}'.format(prepath[premember]['role'])
                        richrole_post = '[red]{}'.format(postpath[premember]['role'])
                        mismatch = True
                    
                    if prepath[premember]['state'] == postpath[premember]['state']:
                        richstate_pre = '[green]{}'.format(prepath[premember]['state'])
                        richstate_post = '[green]{}'.format(postpath[premember]['state'])
                    else:
                        richstate_pre = '[red]{}'.format(prepath[premember]['state'])
                        richstate_post = '[red]{}'.format(postpath[premember]['state'])
                        mismatch = True
                    
                    if prepath[premember]['priority'] == postpath[premember]['priority']:
                        richpriority_pre = '[green]{}'.format(prepath[premember]['priority'])
                        richpriority_post = '[green]{}'.format(postpath[premember]['priority'])
                    else:
                        richpriority_pre = '[red]{}'.format(prepath[premember]['priority'])
                        richpriority_post = '[red]{}'.format(postpath[premember]['priority'])
                        mismatch = True
                    
                    if prepath[premember]['mac_address'] == postpath[premember]['mac_address']:
                        richmac_pre = '[green]{}'.format(prepath[premember]['mac_address'])
                        richmac_post = '[green]{}'.format(postpath[premember]['mac_address'])
                    else:
                        richmac_pre = '[red]{}'.format(prepath[premember]['mac_address'])
                        richmac_post = '[red]{}'.format(postpath[premember]['mac_address'])
                        mismatch = True
                    richstacktable.add_row(devicepre,'[green]{}'.format(premember),richrole_pre,richstate_pre,richpriority_pre,richmac_pre)
                    richstacktable.add_row(devicepost,'[green]{}'.format(premember),richrole_post,richstate_post,richpriority_post,richmac_post,end_section=True)
                else:
                    stackmissmatchfound = True
                    richstacktable.add_row(devicepre,'[red]{}'.format(premember),'[red]{}'.format(prepath[premember]['role']),'[red]{}'.format(prepath[premember]['state']),'[red]{}'.format(prepath[premember]['priority']),'[red]{}'.format(prepath[premember]['mac_address']),end_section=True)
            for postmember in postpath:
                if postmember not in postpath.keys():
                    stackmissmatchfound = True
                    richstacktable.add_row(devicepost,'[red]{}'.format(postmember),'[red]{}'.format(postpath[postmember]['role']),'[red]{}'.format(postpath[postmember]['state']),'[red]{}'.format(postpath[postmember]['priority']),'[red]{}'.format(postpath[postmember]['mac_address']),end_section=True)
        elif 'stack' in master_dict[devicepre]['switch_data']['switch'].keys():
            prepath = master_dict[devicepre]['switch_data']['switch']['stack']
            for premember in prepath:
                stackmissmatchfound = True
                richstacktable.add_row(devicepre,'[red]{}'.format(premember),'[red]{}'.format(prepath[premember]['role']),'[red]{}'.format(prepath[premember]['state']),'[red]{}'.format(prepath[premember]['priority']),'[red]{}'.format(prepath[premember]['mac_address']),end_section=True)
        elif 'stack' in master_dict[devicepost]['switch_data']['switch'].keys():
            postpath = master_dict[devicepost]['switch_data']['switch']['stack']
            for postmember in postpath:
                stackmissmatchfound = True
                richstacktable.add_row(devicepost,'[red]{}'.format(postmember),'[red]{}'.format(postpath[postmember]['role']),'[red]{}'.format(postpath[postmember]['state']),'[red]{}'.format(postpath[postmember]['priority']),'[red]{}'.format(postpath[postmember]['mac_address']),end_section=True)
        else:
            return '[red]No switch stack information available\n',False,False
        return richstacktable,stackmissmatchfound,mismatch
    elif master_dict[devicepre]['switch_data'] != 'N/A' and 'switch' in master_dict[devicepre]['switch_data'].keys():
        prepath = master_dict[devicepre]['switch_data']['switch']['stack']
        for premember in prepath:
            stackmissmatchfound = True
            richstacktable.add_row(devicepre,'[red]{}'.format(premember),'[red]{}'.format(prepath[premember]['role']),'[red]{}'.format(prepath[premember]['state']),'[red]{}'.format(prepath[premember]['priority']),'[red]{}'.format(prepath[premember]['mac_address']),end_section=True)
        return richstacktable,stackmissmatchfound,mismatch
    elif master_dict[devicepost]['switch_data'] != 'N/A' and 'switch' in master_dict[devicepost]['switch_data'].keys():        
        postpath = master_dict[devicepost]['switch_data']['switch']['stack']
        for postmember in postpath:
            stackmissmatchfound = True
            richstacktable.add_row(devicepost,'[red]{}'.format(postmember),'[red]{}'.format(postpath[postmember]['role']),'[red]{}'.format(postpath[postmember]['state']),'[red]{}'.format(postpath[postmember]['priority']),'[red]{}'.format(postpath[postmember]['mac_address']),end_section=True)
        return richstacktable,stackmissmatchfound,mismatch
    else:
        return 0,False,False
    
    
    