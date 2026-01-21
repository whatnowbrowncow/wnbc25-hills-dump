from rich.table import Table
import json

def compare_vlan(target_device,devicepre,devicepost):
    
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)
    if master_dict[devicepre]['vlans'] == 'N/A' and master_dict[devicepost]['vlans'] == 'N/A':
        return 0,'\n',False
    else:
        vlanmismatch = False
        richvlansumtable = Table(title='VLAN Summary',show_header=True, header_style="bold blue")
        richvlansumtable.add_column('Device Comparison')
        richvlansumtable.add_column('Unique Vlans')
        richvlansumtable.add_column('Common Vlans')

        richvlantable = Table(title='VLANs',show_header=True, header_style="bold blue")
        richvlantable.add_column('Device')
        richvlantable.add_column('VLAN')
        richvlantable.add_column('Matching VLAN?')
        richvlantable.add_column('Name')
        richvlantable.add_column('State')
        richvlantable.add_column('Shutdown')

        if master_dict[devicepre]['vlans'] != 'N/A' and master_dict[devicepost]['vlans'] != 'N/A':

            prevpostdiff = (list(set(master_dict[devicepre]['vlans']) - set(master_dict[devicepost]['vlans'])))
            prevpostcmn = (list(set(master_dict[devicepre]['vlans']) & set(master_dict[devicepost]['vlans'])))
    
            richvlansumtable.add_row('{}/{}'.format(devicepre,devicepost),'{}'.format(str(len(prevpostdiff))),'{}'.format(str(len(prevpostcmn))),end_section=True)
            if len(prevpostdiff) > 0:
                for vlan in prevpostdiff:
                    richvlansumtable.add_row('----','[yellow]VLANID: {}'.format(vlan),'----')
                    richvlansumtable.add_row(end_section=True)
                vlanmismatch = True
            postvprediff = (list(set(master_dict[devicepost]['vlans']) - set(master_dict[devicepre]['vlans'])))
            postvprediff = [x for x in postvprediff if '/32' not in x]
            postvprecmn = (list(set(master_dict[devicepost]['vlans']) & set(master_dict[devicepre]['vlans'])))
            richvlansumtable.add_row('{}/{}'.format(str(devicepost),str(devicepre)),'{}'.format(str(len(postvprediff))),'{}'.format(str(len(postvprecmn))),end_section=True)
            if len(postvprediff) > 0:
                for vlan in postvprediff:
                    richvlansumtable.add_row('----','[yellow]VLANID: {}'.format(vlan),'----')
                    richvlansumtable.add_row(end_section=True)
                vlanmismatch = True
    
            for vlana in master_dict[devicepre]['vlans']:
                if type(master_dict[devicepre]['vlans'][vlana]) != bool:
                    if 'vlan_id' in master_dict[devicepre]['vlans'][vlana].keys():
                        for vlanb in master_dict[devicepost]['vlans']:
                            if vlana == vlanb:
                                matching_pre = '[green]YES'
                                matching_post = '[green]YES'
                                if master_dict[devicepre]['vlans'][vlana]['name'] == master_dict[devicepost]['vlans'][vlanb]['name']:
                                    name_pre = '[green]{}'.format(master_dict[devicepre]['vlans'][vlana]['name'])
                                    name_post = '[green]{}'.format(master_dict[devicepost]['vlans'][vlanb]['name'])
                                else:
                                    name_pre = '[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['name'])
                                    name_post = '[yellow]{}'.format(master_dict[devicepost]['vlans'][vlanb]['name'])
                                    vlanmismatch = True
                                if master_dict[devicepre]['vlans'][vlana]['state'] == master_dict[devicepost]['vlans'][vlanb]['state']:
                                    state_pre = '[green]{}'.format(master_dict[devicepre]['vlans'][vlana]['state'])
                                    state_post = '[green]{}'.format(master_dict[devicepost]['vlans'][vlanb]['state'])
                                else:
                                    state_pre = '[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['state'])
                                    state_post = '[yellow]{}'.format(master_dict[devicepost]['vlans'][vlanb]['state'])
                                    vlanmismatch = True
                                if master_dict[devicepre]['vlans'][vlana]['shutdown'] == master_dict[devicepost]['vlans'][vlanb]['shutdown']:
                                    shutdown_pre = '[green]{}'.format(master_dict[devicepre]['vlans'][vlana]['shutdown'])
                                    shutdown_post = '[green]{}'.format(master_dict[devicepost]['vlans'][vlanb]['shutdown'])
                                else:
                                    shutdown_pre = '[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['shutdown'])
                                    shutdown_post = '[yellow]{}'.format(master_dict[devicepost]['vlans'][vlanb]['shutdown'])
                                    vlanmismatch = True                                                  
                                richvlantable.add_row(devicepre,vlana,matching_pre,name_pre,state_pre,shutdown_pre)
                                richvlantable.add_row(devicepost,vlana,matching_post,name_post,state_post,shutdown_post,end_section=True)
                                break
                        else:
                            richvlantable.add_row(devicepre,vlana,'[red]NO','[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['name']),'[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['state']),'[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['shutdown']),end_section=True)
                            vlanmismatch = True
                            continue
    
            for vlana in master_dict[devicepost]['vlans']:
                if type(master_dict[devicepost]['vlans'][vlana]) != bool: 
                    if 'vlan_id' in master_dict[devicepost]['vlans'][vlana].keys():
                        for vlanb in master_dict[devicepre]['vlans']:
                            if vlana not in master_dict[devicepre]['vlans']:
                                richvlantable.add_row(devicepost,vlana,'[red]NO','[red]{}'.format(master_dict[devicepost]['vlans'][vlana]['name']),'[red]{}'.format(master_dict[devicepost]['vlans'][vlana]['state']),'[red]{}'.format(master_dict[devicepost]['vlans'][vlana]['shutdown']),end_section=True)
                                vlanmismatch = True
            return richvlansumtable,richvlantable,vlanmismatch
        elif master_dict[devicepre]['vlans'] != 'N/A' and master_dict[devicepost]['vlans'] == 'N/A':

    
            richvlansumtable.add_row('{}/{}'.format(devicepre,devicepost),'{}'.format(str(len(master_dict[devicepre]['vlans']))),'0',end_section=True)

            for vlan in master_dict[devicepre]['vlans']:
                richvlansumtable.add_row('----','[yellow]VLANID: {}'.format(vlan),'----')
                richvlansumtable.add_row(end_section=True)
            vlanmismatch = True

    
            for vlana in master_dict[devicepre]['vlans']:
                if type(master_dict[devicepre]['vlans'][vlana]) != bool:
                    if 'vlan_id' in master_dict[devicepre]['vlans'][vlana].keys():
                        richvlantable.add_row(devicepre,vlana,'[red]NO','[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['name']),'[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['state']),'[red]{}'.format(master_dict[devicepre]['vlans'][vlana]['shutdown']),end_section=True)
                        vlanmismatch = True
            return richvlansumtable,richvlantable,vlanmismatch



        elif master_dict[devicepre]['vlans'] == 'N/A' and master_dict[devicepost]['vlans'] != 'N/A':

            richvlansumtable.add_row('{}/{}'.format(devicepre,devicepost),'0','{}'.format(str(len(master_dict[devicepost]['vlans']))),end_section=True)

            for vlan in master_dict[devicepost]['vlans']:
                richvlansumtable.add_row('----','[yellow]VLANID: {}'.format(vlan),'----')
                richvlansumtable.add_row(end_section=True)
            vlanmismatch = True

    
            for vlana in master_dict[devicepost]['vlans']:
                if type(master_dict[devicepost]['vlans'][vlana]) != bool: 
                    if 'vlan_id' in master_dict[devicepost]['vlans'][vlana].keys():
                        
                    
                        richvlantable.add_row(devicepost,vlana,'[red]NO','[red]{}'.format(master_dict[devicepost]['vlans'][vlana]['name']),'[red]{}'.format(master_dict[devicepost]['vlans'][vlana]['state']),'[red]{}'.format(master_dict[devicepost]['vlans'][vlana]['shutdown']),end_section=True)
                        vlanmismatch = True
            return richvlansumtable,richvlantable,vlanmismatch
    
            