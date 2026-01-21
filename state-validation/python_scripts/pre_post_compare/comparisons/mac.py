from prettytable import PrettyTable
from rich.table import Table
import json

def compare_mac(target_device,devicepre,devicepost):
    
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)
    #devicepre = str(target_device) + '-pre'
    #devicepost = str(target_device) + '-post'

    richmacneightable = Table(title='MAC/CDP Neighbors',show_header=True, header_style="bold blue")
    richmacneightable.add_column('Device')
    richmacneightable.add_column('MAC')
    richmacneightable.add_column('MAC / CDP Match')
    richmacneightable.add_column('Local Interface')
    richmacneightable.add_column('Device ID')
    richmacneightable.add_column('Remote Interface')
    
    macmatch = True
    if 'index' in master_dict[devicepre]['cdp'].keys() and 'index' in master_dict[devicepost]['cdp'].keys():
        for neigha in master_dict[devicepre]['cdp']['index']:
            if 'mac_address' in master_dict[devicepre]['cdp']['index'][neigha].keys():
                for neighb in master_dict[devicepost]['cdp']['index']:
                    if 'mac_address' in master_dict[devicepost]['cdp']['index'][neighb].keys():
                        if master_dict[devicepre]['cdp']['index'][neigha]['mac_address'] == master_dict[devicepost]['cdp']['index'][neighb]['mac_address']:
                            #macmatch =True
                            mac_pre = '[green]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['mac_address'])
                            mac_post = '[green]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['mac_address'])
                            matching_mac_pre = '[green]YES'
                            matching_mac_post = '[green]YES'
                            local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                            local_interface_post = '{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['local_interface'])
                            if master_dict[devicepre]['cdp']['index'][neigha]['device_id'] == master_dict[devicepost]['cdp']['index'][neighb]['device_id']:
                                device_id_pre = '[green]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                                device_id_post = '[green]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['device_id'])
                            else:
                                device_id_pre = 'red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                                device_id_post = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['device_id'])
                                macmatch = False
                            if master_dict[devicepre]['cdp']['index'][neigha]['port_id'] == master_dict[devicepost]['cdp']['index'][neighb]['port_id']:
                                remote_interface_pre = '[green]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                                remote_interface_post = '[green]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['port_id'])
                            else:
                                remote_interface_pre = '[red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                                remote_interface_post = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['port_id'])
                                macmatch = False
                            richmacneightable.add_row(devicepre,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre)
                            richmacneightable.add_row(devicepost,mac_post,matching_mac_post,local_interface_post,device_id_post,remote_interface_post,end_section=True)
                            break
                else:
                    mac_pre = '[red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['mac_address'])
                    matching_mac_pre = '[red]NO'
                    local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                    device_id_pre = '[red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                    remote_interface_pre = '[red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                    richmacneightable.add_row(devicepre,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)
                    macmatch = False
                    continue
            else:
                for neighb in master_dict[devicepost]['cdp']['index']:
                    if master_dict[devicepre]['cdp']['index'][neigha]['device_id'] == master_dict[devicepost]['cdp']['index'][neighb]['device_id'] and master_dict[devicepre]['cdp']['index'][neigha]['port_id'] == master_dict[devicepost]['cdp']['index'][neighb]['port_id']:
                        cdpmatch =True
                        if 'mac_address' in master_dict[devicepre]['cdp']['index'][neigha].keys():
                            mac_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['mac_address'])
                            mac_post = '{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['mac_address'])
                            matching_mac_pre = '[green]YES'
                            matching_mac_post = '[green]YES'
                            local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                            local_interface_post = '{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['local_interface'])
                            device_id_pre = '[green]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                            device_id_post = '[green]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['device_id'])
                            remote_interface_pre = '[green]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                            remote_interface_post = '[green]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['port_id'])
                        else:
                            mac_pre = 'N/A'
                            mac_post = 'N/A'
                            matching_mac_pre = '[green]YES'
                            matching_mac_post = '[green]YES'
                            local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                            local_interface_post = '{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['local_interface'])
                            device_id_pre = '[green]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                            device_id_post = '[green]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['device_id'])
                            remote_interface_pre = '[green]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                            remote_interface_post = '[green]{}'.format(master_dict[devicepost]['cdp']['index'][neighb]['port_id'])
                        
                        richmacneightable.add_row(devicepre,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre)
                        richmacneightable.add_row(devicepost,mac_post,matching_mac_post,local_interface_post,device_id_post,remote_interface_post,end_section=True)
                        break
                else:
                    if 'mac_address' in master_dict[devicepre]['cdp']['index'][neigha].keys():
                        mac_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['mac_address'])
                        matching_mac_pre = '[red]NO'
                        local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                        device_id_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                        remote_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                        macmatch = False
    
                    else:
                        mac_pre = 'N/A'
                        matching_mac_pre = '[red]NO'
                        local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                        device_id_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                        remote_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                        macmatch = False
                    richmacneightable.add_row(devicepre,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)
                    continue
##########
    #if 'index' in master_dict[devicepost]['cdp'].keys():
        for neigha in master_dict[devicepost]['cdp']['index']:
            if 'mac_address' in master_dict[devicepost]['cdp']['index'][neigha].keys():
                for neighb in master_dict[devicepre]['cdp']['index']:
                    if 'mac_address' in master_dict[devicepre]['cdp']['index'][neighb].keys():
                        if master_dict[devicepre]['cdp']['index'][neigha]['mac_address'] == master_dict[devicepost]['cdp']['index'][neighb]['mac_address']:
                            break
                else:
                    mac_pre = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['mac_address'])
                    matching_mac_pre = '[red]NO'
                    local_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['local_interface'])
                    device_id_pre = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['device_id'])
                    remote_interface_pre = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['port_id'])
                    richmacneightable.add_row(devicepost,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)
                    macmatch = False
                    continue
            else:
                for neighb in master_dict[devicepost]['cdp']['index']:
                    if master_dict[devicepre]['cdp']['index'][neigha]['device_id'] == master_dict[devicepost]['cdp']['index'][neighb]['device_id'] and master_dict[devicepre]['cdp']['index'][neigha]['port_id'] == master_dict[devicepost]['cdp']['index'][neighb]['port_id']:
                        break
                else:
                    if 'mac_address' in master_dict[devicepost]['cdp']['index'][neigha].keys():
                        mac_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['mac_address'])
                        matching_mac_pre = '[red]NO'
                        local_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['local_interface'])
                        device_id_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['device_id'])
                        remote_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['port_id'])
                        macmatch = False
    
                    else:
                        mac_pre = 'N/A'
                        matching_mac_pre = '[red]NO'
                        local_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['local_interface'])
                        device_id_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['device_id'])
                        remote_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['port_id'])
                        macmatch = False
                    richmacneightable.add_row(devicepost,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)
                    continue
#########
        return richmacneightable,macmatch
    elif 'index' in master_dict[devicepre]['cdp'].keys():
        for neigha in master_dict[devicepre]['cdp']['index']:
            if 'mac_address' in master_dict[devicepre]['cdp']['index'][neigha].keys():
                mac_pre = '[red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['mac_address'])
                matching_mac_pre = '[red]NO'
                local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                device_id_pre = '[red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                remote_interface_pre = '[red]{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                richmacneightable.add_row(devicepre,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)
                macmatch = False
            else:

                mac_pre = 'N/A'
                matching_mac_pre = '[red]NO'
                local_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['local_interface'])
                device_id_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['device_id'])
                remote_interface_pre = '{}'.format(master_dict[devicepre]['cdp']['index'][neigha]['port_id'])
                macmatch = False
                richmacneightable.add_row(devicepre,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)
        return richmacneightable,macmatch##########
    elif 'index' in master_dict[devicepost]['cdp'].keys():
        for neigha in master_dict[devicepost]['cdp']['index']:
            if 'mac_address' in master_dict[devicepost]['cdp']['index'][neigha].keys():
                for neighb in master_dict[devicepre]['cdp']['index']:
                    mac_pre = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['mac_address'])
                    matching_mac_pre = '[red]NO'
                    local_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['local_interface'])
                    device_id_pre = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['device_id'])
                    remote_interface_pre = '[red]{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['port_id'])
                    richmacneightable.add_row(devicepost,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)
                    macmatch = False

            else:
                    mac_pre = 'N/A'
                    matching_mac_pre = '[red]NO'
                    local_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['local_interface'])
                    device_id_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['device_id'])
                    remote_interface_pre = '{}'.format(master_dict[devicepost]['cdp']['index'][neigha]['port_id'])
                    macmatch = False
                    richmacneightable.add_row(devicepost,mac_pre,matching_mac_pre,local_interface_pre,device_id_pre,remote_interface_pre,end_section=True)

        #print(macneightable)
        return richmacneightable,macmatch
    else:
        return 0,macmatch