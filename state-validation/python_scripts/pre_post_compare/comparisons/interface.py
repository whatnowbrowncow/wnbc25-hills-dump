from prettytable import PrettyTable
from termcolor import colored
from rich.table import Table
import json

def compare_interfaces(target_device,devicepre,devicepost):
    
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)
    missingint = False
    missmatchfound = False
    richinttable = Table(title='Interfaces',show_header=True, header_style="bold blue")
    richinttable.add_column('Device')
    richinttable.add_column('Interface')
    richinttable.add_column('Matching Interface?')
    richinttable.add_column('Type')
    richinttable.add_column('Status')
    richinttable.add_column('Description')
    richinttable.add_column('IP')
    richinttable.add_column('CDP Neighbor')

    for inta in master_dict[devicepre]['interfaces']:
        mismatch = False
        for intb in master_dict[devicepost]['interfaces']:
            if inta == intb and 'oper_status' in master_dict[devicepre]['interfaces'][inta].keys():
                matching_interface_pre = '[green]YES'
                matching_interface_post = '[green]YES'
                inttype_pre = '[green]{}'.format(master_dict[devicepre]['interfaces'][inta]['type'])
                inttype_post = '[green]{}'.format(master_dict[devicepost]['interfaces'][intb]['type'])
                if master_dict[devicepre]['interfaces'][inta]['oper_status'] == master_dict[devicepost]['interfaces'][intb]['oper_status']:
                    oper_status_pre = '[green]{}'.format(master_dict[devicepre]['interfaces'][inta]['oper_status'])
                    oper_status_post = '[green]{}'.format(master_dict[devicepost]['interfaces'][intb]['oper_status'])
                else:
                    oper_status_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['oper_status'])
                    oper_status_post = '[yellow]{}'.format(master_dict[devicepost]['interfaces'][intb]['oper_status'])
                    mismatch = True
                if master_dict[devicepre]['interfaces'][inta]['description'] == master_dict[devicepost]['interfaces'][intb]['description']:
                    description_pre = '[green]{}'.format(master_dict[devicepre]['interfaces'][inta]['description'])
                    description_post = '[green]{}'.format(master_dict[devicepost]['interfaces'][intb]['description'])
                else:
                    description_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['description'])
                    description_post = '[yellow]{}'.format(master_dict[devicepost]['interfaces'][intb]['description'])
                    mismatch = True
                if master_dict[devicepre]['interfaces'][inta]['IP'] == master_dict[devicepost]['interfaces'][intb]['IP']:
                    ip_pre = '[green]{}'.format(master_dict[devicepre]['interfaces'][inta]['IP'])
                    ip_post = '[green]{}'.format(master_dict[devicepost]['interfaces'][intb]['IP'])
                else:
                    ip_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['IP'])
                    ip_post = '[yellow]{}'.format(master_dict[devicepost]['interfaces'][intb]['IP'])
                    mismatch = True
                if 'cdp' in master_dict[devicepre]['interfaces'][inta].keys():
                    if 'cdp' in master_dict[devicepost]['interfaces'][inta].keys():
                        if master_dict[devicepre]['interfaces'][inta]['cdp']['device_id'] == master_dict[devicepost]['interfaces'][intb]['cdp']['device_id']:
                            cdp_pre = '[green]{}'.format(master_dict[devicepre]['interfaces'][intb]['cdp']['device_id'])
                            cdp_post = '[green]{}'.format(master_dict[devicepost]['interfaces'][intb]['cdp']['device_id'])
                        else:
                            cdp_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][intb]['cdp']['device_id'])
                            cdp_post = '[yellow]{}'.format(master_dict[devicepost]['interfaces'][intb]['cdp']['device_id'])
                            mismatch = True
                    else:
                        cdp_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['cdp']['device_id'])
                        cdp_post = '[yellow]NO CDP DATA FOUND'
                        mismatch = True
                else:
                    cdp_pre = '[green]-None-'
                    cdp_post = '[green]-None'
                richinttable.add_row(devicepre,inta,matching_interface_pre,inttype_pre,oper_status_pre,description_pre,ip_pre,cdp_pre)
                richinttable.add_row(devicepost,inta,matching_interface_post,inttype_post,oper_status_post,description_post,ip_post,cdp_post,end_section=True)
                if mismatch:
                    missmatchfound = True
                break
        else:
            if 'oper_status' in master_dict[devicepre]['interfaces'][inta].keys():
                missingint = True
                if 'cdp' in master_dict[devicepre]['interfaces'][inta].keys():
                    matching_interface_pre = '[red]NO'
                    inttype_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['type'])
                    oper_status_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['oper_status'])
                    description_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['description'])
                    ip_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['IP'])
                    cdp_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['cdp']['device_id'])
                else:
                    matching_interface_pre = '[red]NO'
                    inttype_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['type'])
                    oper_status_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['oper_status'])
                    description_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['description'])
                    ip_pre = '[red]{}'.format(master_dict[devicepre]['interfaces'][inta]['IP'])
                    cdp_pre = '[red]-None-'
                richinttable.add_row(devicepre,inta,matching_interface_pre,inttype_pre,oper_status_pre,description_pre,ip_pre,cdp_pre,end_section=True)
            continue


    for inta in master_dict[devicepost]['interfaces']:
        if 'oper_status' in master_dict[devicepost]['interfaces'][inta].keys() and inta not in master_dict[devicepre]['interfaces']:
            missingint = True
            if 'cdp' in master_dict[devicepost]['interfaces'][inta].keys():
                matching_interface_post = '[red]NO'
                inttype_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['type'])
                oper_status_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['oper_status'])
                description_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['description'])
                ip_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['IP'])
                cdp_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['cdp']['device_id'])
            else:
                matching_interface_post = '[red]NO'
                inttype_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['type'])
                oper_status_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['oper_status'])
                description_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['description'])
                ip_post = '[red]{}'.format(master_dict[devicepost]['interfaces'][inta]['IP'])
                cdp_post = '[red]-None-'
            richinttable.add_row(devicepost,inta,matching_interface_post,inttype_post,oper_status_post,description_post,ip_post,cdp_post,end_section=True)
        continue


    return richinttable,missingint,missmatchfound
    