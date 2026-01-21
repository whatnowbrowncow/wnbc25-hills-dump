from prettytable import PrettyTable
from termcolor import colored
from rich.table import Table
import json

def compare_version(target_device,devicepre,devicepost,upgrade):
    
    with open('./json_log_files/'+target_device+'/master_dict_merge_latest.json') as json_file: 
        master_dict=json.load(json_file)
    #devicepre = str(target_device) + '-pre'
    #devicepost = str(target_device) + '-post'
    #console = Console()
    #print()
    #console.print('[cyan]#############################Checking for interface differences#########################')
    #print()

    vertable = PrettyTable(['Device','Version short','Version','OS','Image type','License level','License type','platform','Config Register'])
    robotvertable = PrettyTable(['Device','Version short','Version','OS','Image type','License level','License type','platform','Config Register'])
    richvertable = Table(title='Device Version Summary',show_header=True, header_style="bold blue")
    richvertable.add_column('Device')
    richvertable.add_column('Version Short',justify='center')
    richvertable.add_column('Version',justify='center')
    richvertable.add_column('OS',justify='center')
    richvertable.add_column('Image Type',justify='center')
    richvertable.add_column('License Level',justify='center')
    richvertable.add_column('Licence Type',justify='center')
    richvertable.add_column('Platform',justify='center')
    richvertable.add_column('Config Register',justify='center')
    
    tablesplit = ['---','---','---','---','---','---','---','---','---']
    
    #devicepre = str(target_device) + '-pre'
    #devicepost = str(target_device) + '-post'
    
    prerow = [devicepre]
    postrow = [devicepost]
    robotprerow = [devicepre]
    robotpostrow = [devicepost]
    mismatch = False
    postverhigh = False
    if master_dict[devicepre]['os'] == 'iosxr':
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richvershort_pre = '[green]{}'.format('N/A')
        richvershort_post = '[green]{}'.format('N/A')
        
        if upgrade:
            if tuple(map(int, (master_dict[devicepost]['version_data']['software_version'].split(".")))) > tuple(map(int, (master_dict[devicepre]['version_data']['software_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['software_version'],'green'))
                postrow.append(colored(master_dict[devicepost]['version_data']['software_version'],'green'))
                robotprerow.append(master_dict[devicepre]['version_data']['software_version'])
                robotpostrow.append(master_dict[devicepost]['version_data']['software_version'])
                postverhigh = True
                richver_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['software_version'])
                richver_post = '[green]{}'.format(master_dict[devicepost]['version_data']['software_version'])
            elif tuple(map(int, (master_dict[devicepost]['version_data']['software_version'].split(".")))) <= tuple(map(int, (master_dict[devicepre]['version_data']['software_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['software_version'],'red'))
                postrow.append(colored(master_dict[devicepost]['version_data']['software_version'],'red'))
                robotprerow.append('***'+master_dict[devicepre]['version_data']['software_version']+'***')
                robotpostrow.append('***'+master_dict[devicepost]['version_data']['software_version']+'***')
                richver_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['software_version'])
                richver_post = '[red]{}'.format(master_dict[devicepost]['version_data']['software_version'])
        else:
            if tuple(map(int, (master_dict[devicepost]['version_data']['software_version'].split(".")))) > tuple(map(int, (master_dict[devicepre]['version_data']['software_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['software_version'],'red'))
                postrow.append(colored(master_dict[devicepost]['version_data']['software_version'],'red'))
                robotprerow.append(master_dict[devicepre]['version_data']['software_version'])
                robotpostrow.append(master_dict[devicepost]['version_data']['software_version'])
                postverhigh = True
                richver_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['software_version'])
                richver_post = '[red]{}'.format(master_dict[devicepost]['version_data']['software_version'])
            elif tuple(map(int, (master_dict[devicepost]['version_data']['software_version'].split(".")))) <= tuple(map(int, (master_dict[devicepre]['version_data']['software_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['software_version'],'green'))
                postrow.append(colored(master_dict[devicepost]['version_data']['software_version'],'green'))
                robotprerow.append('***'+master_dict[devicepre]['version_data']['software_version']+'***')
                robotpostrow.append('***'+master_dict[devicepost]['version_data']['software_version']+'***')
                richver_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['software_version'])
                richver_post = '[green]{}'.format(master_dict[devicepost]['version_data']['software_version'])  
            
        if master_dict[devicepre]['version_data']['operating_system'] == master_dict[devicepost]['version_data']['operating_system']:
            prerow.append(colored(master_dict[devicepre]['version_data']['operating_system'],'green'))
            postrow.append(colored(master_dict[devicepost]['version_data']['operating_system'],'green'))
            robotprerow.append(master_dict[devicepre]['version_data']['operating_system'])
            robotpostrow.append(master_dict[devicepost]['version_data']['operating_system'])
            richos_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['operating_system'])
            richos_post = '[green]{}'.format(master_dict[devicepost]['version_data']['operating_system'])
        else:
            prerow.append(colored(master_dict[devicepre]['version_data']['operating_system'],'red'))
            postrow.append(colored(master_dict[devicepost]['version_data']['operating_system'],'red'))
            robotprerow.append('***'+master_dict[devicepre]['version_data']['operating_system']+'***')
            robotpostrow.append('***'+master_dict[devicepost]['version_data']['operating_system']+'***')
            richos_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['operating_system'])
            richos_post = '[red]{}'.format(master_dict[devicepost]['version_data']['operating_system'])
            mismatch = True
        
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richimagetype_pre = '[green]{}'.format('N/A')
        richimagetype_post = '[green]{}'.format('N/A')
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richlicenselevel_pre = 'N/A'
        richlicenselevel_post = 'N/A'
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richlicensetype_pre = 'N/A'
        richlicensetype_post = 'N/A'
        
        if master_dict[devicepost]['version_data']['device_family'] == master_dict[devicepre]['version_data']['device_family']:
            prerow.append(colored(master_dict[devicepre]['version_data']['device_family'],'green'))
            postrow.append(colored(master_dict[devicepost]['version_data']['device_family'],'green'))
            robotprerow.append(master_dict[devicepre]['version_data']['device_family'])
            robotpostrow.append(master_dict[devicepost]['version_data']['device_family'])
            richdevice_family_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['device_family'])
            richdevice_family_post = '[green]{}'.format(master_dict[devicepost]['version_data']['device_family'])
        else:
            prerow.append(colored(master_dict[devicepre]['version_data']['device_family'],'red'))
            postrow.append(colored(master_dict[devicepost]['version_data']['device_family'],'red'))
            robotprerow.append('***'+master_dict[devicepre]['version_data']['device_family']+'***')
            robotpostrow.append('***'+master_dict[devicepost]['version_data']['device_family']+'***')
            richdevice_family_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['device_family'])
            richdevice_family_post = '[red]{}'.format(master_dict[devicepost]['version_data']['device_family'])
            mismatch = True
        
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richconfigreg_pre = '[green]{}'.format('N/A')
        richconfigreg_post = '[green]{}'.format('N/A')
    
    
        
        vertable.add_row(prerow)
        vertable.add_row(postrow)
        robotvertable.add_row(robotprerow)
        robotvertable.add_row(robotpostrow)
        richvertable.add_row(devicepre,richvershort_pre,richver_pre,richos_pre,richimagetype_pre,richlicenselevel_pre,richlicensetype_pre,richdevice_family_pre,richconfigreg_pre)
        richvertable.add_row(devicepost,richvershort_post,richver_post,richos_post,richimagetype_post,richlicenselevel_post,richlicensetype_post,richdevice_family_post,richconfigreg_post,end_section=True)
        #print(vertable)
        #console.print(richvertable)
    
    elif master_dict[devicepre]['os'] == 'nxos':
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richvershort_pre = '[green]{}'.format('N/A')
        richvershort_post = '[green]{}'.format('N/A')
        master_dict[devicepre]['version_data']['platform']['system_version'] = master_dict[devicepre]['version_data']['platform']['system_version'].replace("(",".")
        master_dict[devicepre]['version_data']['platform']['system_version'] = master_dict[devicepre]['version_data']['platform']['system_version'].replace(")","")
        master_dict[devicepost]['version_data']['platform']['system_version'] = master_dict[devicepost]['version_data']['platform']['system_version'].replace("(",".")
        master_dict[devicepost]['version_data']['platform']['system_version'] = master_dict[devicepost]['version_data']['platform']['system_version'].replace(")","")
        
        if upgrade:
            if tuple(map(int, (master_dict[devicepost]['version_data']['platform']['system_version'].split(".")))) > tuple(map(int, (master_dict[devicepre]['version_data']['platform']['system_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['platform']['system_version'],'green'))
                postrow.append(colored(master_dict[devicepost]['version_data']['platform']['system_version'],'green'))
                robotprerow.append(master_dict[devicepre]['version_data']['platform']['system_version'])
                robotpostrow.append(master_dict[devicepost]['version_data']['platform']['system_version'])
                postverhigh = True
                richver_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['platform']['system_version'])
                richver_post = '[green]{}'.format(master_dict[devicepost]['version_data']['platform']['system_version'])
            elif tuple(map(int, (master_dict[devicepost]['version_data']['platform']['system_version'].split(".")))) <= tuple(map(int, (master_dict[devicepre]['version_data']['platform']['system_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['platform']['system_version'],'red'))
                postrow.append(colored(master_dict[devicepost]['version_data']['platform']['system_version'],'red'))
                robotprerow.append('***'+master_dict[devicepre]['version_data']['platform']['system_version']+'***')
                robotpostrow.append('***'+master_dict[devicepost]['version_data']['platform']['system_version']+'***')
                richver_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['platform']['system_version'])
                richver_post = '[red]{}'.format(master_dict[devicepost]['version_data']['platform']['system_version'])
        else:
            if tuple(map(int, (master_dict[devicepost]['version_data']['platform']['system_version'].split(".")))) > tuple(map(int, (master_dict[devicepre]['version_data']['platform']['system_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['platform']['system_version'],'red'))
                postrow.append(colored(master_dict[devicepost]['version_data']['platform']['system_version'],'red'))
                robotprerow.append(master_dict[devicepre]['version_data']['platform']['system_version'])
                robotpostrow.append(master_dict[devicepost]['version_data']['platform']['system_version'])
                postverhigh = True
                richver_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['platform']['system_version'])
                richver_post = '[red]{}'.format(master_dict[devicepost]['version_data']['platform']['system_version'])
            elif tuple(map(int, (master_dict[devicepost]['version_data']['platform']['system_version'].split(".")))) <= tuple(map(int, (master_dict[devicepre]['version_data']['platform']['system_version'].split(".")))):
                prerow.append(colored(master_dict[devicepre]['version_data']['platform']['system_version'],'green'))
                postrow.append(colored(master_dict[devicepost]['version_data']['platform']['system_version'],'green'))
                robotprerow.append('***'+master_dict[devicepre]['version_data']['platform']['system_version']+'***')
                robotpostrow.append('***'+master_dict[devicepost]['version_data']['platform']['system_version']+'***')
                richver_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['platform']['system_version'])
                richver_post = '[green]{}'.format(master_dict[devicepost]['version_data']['platform']['system_version'])  
            
        if master_dict[devicepre]['version_data']['platform']['os'] == master_dict[devicepost]['version_data']['platform']['os']:
            prerow.append(colored(master_dict[devicepre]['version_data']['platform']['os'],'green'))
            postrow.append(colored(master_dict[devicepost]['version_data']['platform']['os'],'green'))
            robotprerow.append(master_dict[devicepre]['version_data']['platform']['os'])
            robotpostrow.append(master_dict[devicepost]['version_data']['platform']['os'])
            richos_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['platform']['os'])
            richos_post = '[green]{}'.format(master_dict[devicepost]['version_data']['platform']['os'])
        else:
            prerow.append(colored(master_dict[devicepre]['version_data']['platform']['os'],'red'))
            postrow.append(colored(master_dict[devicepost]['version_data']['platform']['os'],'red'))
            robotprerow.append('***'+master_dict[devicepre]['version_data']['platform']['os']+'***')
            robotpostrow.append('***'+master_dict[devicepost]['version_data']['platform']['os']+'***')
            richos_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['platform']['os'])
            richos_post = '[red]{}'.format(master_dict[devicepost]['version_data']['platform']['os'])
            mismatch = True
        
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richimagetype_pre = '[green]{}'.format('N/A')
        richimagetype_post = '[green]{}'.format('N/A')
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richlicenselevel_pre = 'N/A'
        richlicenselevel_post = 'N/A'
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richlicensetype_pre = 'N/A'
        richlicensetype_post = 'N/A'
        
        if master_dict[devicepost]['version_data']['platform']['software']['system_image_file'] == master_dict[devicepre]['version_data']['platform']['software']['system_image_file']:
            prerow.append(colored(master_dict[devicepre]['version_data']['platform']['software']['system_image_file'],'green'))
            postrow.append(colored(master_dict[devicepost]['version_data']['platform']['software']['system_image_file'],'green'))
            robotprerow.append(master_dict[devicepre]['version_data']['platform']['software']['system_image_file'])
            robotpostrow.append(master_dict[devicepost]['version_data']['platform']['software']['system_image_file'])
            richdevice_family_pre = '[green]{}'.format(master_dict[devicepre]['version_data']['platform']['software']['system_image_file'])
            richdevice_family_post = '[green]{}'.format(master_dict[devicepost]['version_data']['platform']['software']['system_image_file'])
        else:
            prerow.append(colored(master_dict[devicepre]['version_data']['platform']['software']['system_image_file'],'red'))
            postrow.append(colored(master_dict[devicepost]['version_data']['platform']['software']['system_image_file'],'red'))
            robotprerow.append('***'+master_dict[devicepre]['version_data']['platform']['software']['system_image_file']+'***')
            robotpostrow.append('***'+master_dict[devicepost]['version_data']['platform']['software']['system_image_file']+'***')
            richdevice_family_pre = '[red]{}'.format(master_dict[devicepre]['version_data']['platform']['software']['system_image_file'])
            richdevice_family_post = '[red]{}'.format(master_dict[devicepost]['version_data']['platform']['software']['system_image_file'])
            mismatch = True
        
    
        prerow.append(colored('N/A','green'))
        postrow.append(colored('N/A','green'))
        robotprerow.append('N/A')
        robotpostrow.append('N/A')
        richconfigreg_pre = '[green]{}'.format('N/A')
        richconfigreg_post = '[green]{}'.format('N/A')
    
    
        
        vertable.add_row(prerow)
        vertable.add_row(postrow)
        robotvertable.add_row(robotprerow)
        robotvertable.add_row(robotpostrow)
        richvertable.add_row(devicepre,richvershort_pre,richver_pre,richos_pre,richimagetype_pre,richlicenselevel_pre,richlicensetype_pre,richdevice_family_pre,richconfigreg_pre)
        richvertable.add_row(devicepost,richvershort_post,richver_post,richos_post,richimagetype_post,richlicenselevel_post,richlicensetype_post,richdevice_family_post,richconfigreg_post,end_section=True)
        #print(vertable)
        #console.print(richvertable)   
    
    
    
    
    else:
        prepath = master_dict[devicepre]['version_data']['version']
        postpath = master_dict[devicepost]['version_data']['version']
        if upgrade:
            if float(postpath['version_short']) > float(prepath['version_short']):
                prerow.append(colored(prepath['version_short'],'green'))
                prerow.append(colored(prepath['version'],'green'))
                postrow.append(colored(postpath['version_short'],'green'))
                postrow.append(colored(postpath['version'],'green'))
                robotprerow.append(prepath['version_short'])
                robotprerow.append(prepath['version'])
                robotpostrow.append(postpath['version_short'])
                robotpostrow.append(postpath['version'])
                postverhigh = True
                richvershort_pre = '[green]{}'.format(prepath['version_short'])
                richvershort_post = '[green]{}'.format(postpath['version_short'])
                richver_pre = '[green]{}'.format(prepath['version'])
                richver_post = '[green]{}'.format(postpath['version'])
            elif float(postpath['version_short']) <= float(prepath['version_short']):
                prerow.append(colored(prepath['version_short'],'red'))
                prerow.append(colored(prepath['version'],'red'))
                postrow.append(colored(postpath['version_short'],'red'))
                postrow.append(colored(postpath['version'],'red'))
                robotprerow.append('***'+prepath['version_short']+'***')
                robotprerow.append('***'+prepath['version']+'***')
                robotpostrow.append('***'+postpath['version_short']+'***')
                robotpostrow.append('***'+postpath['version']+'***')
                richvershort_pre = '[red]{}'.format(prepath['version_short'])
                richvershort_post = '[red]{}'.format(postpath['version_short'])
                richver_pre = '[red]{}'.format(prepath['version'])
                richver_post = '[red]{}'.format(postpath['version'])
        else:
            if float(postpath['version_short']) > float(prepath['version_short']):
                prerow.append(colored(prepath['version_short'],'red'))
                prerow.append(colored(prepath['version'],'red'))
                postrow.append(colored(postpath['version_short'],'red'))
                postrow.append(colored(postpath['version'],'red'))
                robotprerow.append(prepath['version_short'])
                robotprerow.append(prepath['version'])
                robotpostrow.append(postpath['version_short'])
                robotpostrow.append(postpath['version'])
                postverhigh = True
                richvershort_pre = '[red]{}'.format(prepath['version_short'])
                richvershort_post = '[red]{}'.format(postpath['version_short'])
                richver_pre = '[red]{}'.format(prepath['version'])
                richver_post = '[red]{}'.format(postpath['version'])
            elif float(postpath['version_short']) <= float(prepath['version_short']):
                prerow.append(colored(prepath['version_short'],'green'))
                prerow.append(colored(prepath['version'],'green'))
                postrow.append(colored(postpath['version_short'],'green'))
                postrow.append(colored(postpath['version'],'green'))
                robotprerow.append('***'+prepath['version_short']+'***')
                robotprerow.append('***'+prepath['version']+'***')
                robotpostrow.append('***'+postpath['version_short']+'***')
                robotpostrow.append('***'+postpath['version']+'***')
                richvershort_pre = '[green]{}'.format(prepath['version_short'])
                richvershort_post = '[green]{}'.format(postpath['version_short'])
                richver_pre = '[green]{}'.format(prepath['version'])
                richver_post = '[green]{}'.format(postpath['version'])   
            
        if postpath['os'] == prepath['os']:
            prerow.append(colored(prepath['os'],'green'))
            postrow.append(colored(postpath['os'],'green'))
            robotprerow.append(prepath['os'])
            robotpostrow.append(postpath['os'])
            richos_pre = '[green]{}'.format(prepath['os'])
            richos_post = '[green]{}'.format(postpath['os'])
        else:
            prerow.append(colored(prepath['os'],'red'))
            postrow.append(colored(postpath['os'],'red'))
            robotprerow.append('***'+prepath['os']+'***')
            robotpostrow.append('***'+postpath['os']+'***')
            richos_pre = '[red]{}'.format(prepath['os'])
            richos_post = '[red]{}'.format(postpath['os'])
            mismatch = True
        
        if postpath['image_type'] == prepath['image_type']:
            prerow.append(colored(prepath['image_type'],'green'))
            postrow.append(colored(postpath['image_type'],'green'))
            robotprerow.append(prepath['image_type'])
            robotpostrow.append(postpath['image_type'])
            richimagetype_pre = '[green]{}'.format(prepath['image_type'])
            richimagetype_post = '[green]{}'.format(postpath['image_type'])
        else:
            prerow.append(colored(prepath['image_type'],'red'))
            postrow.append(colored(postpath['image_type'],'red'))
            robotprerow.append('***'+prepath['image_type']+'***')
            robotpostrow.append('***'+postpath['image_type']+'***')
            richimagetype_pre = '[red]{}'.format(prepath['image_type'])
            richimagetype_post = '[red]{}'.format(postpath['image_type'])
            mismatch = True
        
        if 'license_level' in prepath.keys() and 'license_level' in postpath.keys():
            if postpath['license_level'] == prepath['license_level']:
                prerow.append(colored(prepath['license_level'],'green'))
                postrow.append(colored(postpath['license_level'],'green'))
                robotprerow.append(prepath['license_level'])
                robotpostrow.append(postpath['license_level'])
                richlicenselevel_pre = '[green]{}'.format(prepath['license_level'])
                richlicenselevel_post = '[green]{}'.format(postpath['license_level'])
            else:
                prerow.append(colored(prepath['license_level'],'red'))
                postrow.append(colored(postpath['license_level'],'red'))
                robotprerow.append('***'+prepath['license_level']+'***')
                robotpostrow.append('***'+postpath['license_level']+'***')
                richlicenselevel_pre = '[red]{}'.format(prepath['license_level'])
                richlicenselevel_post = '[red]{}'.format(postpath['license_level'])
                mismatch = True
        
        elif 'license_level' in prepath.keys() and 'license_level' not in postpath.keys():

                prerow.append(colored(prepath['license_level'],'red'))
                postrow.append(colored('N/A','red'))
                robotprerow.append(prepath['license_level'])
                robotpostrow.append('N/A')
                richlicenselevel_pre = '[red]{}'.format(prepath['license_level'])
                richlicenselevel_post = '[red]N/A'
                mismatch = True
        elif 'license_level' not in prepath.keys() and 'license_level' in postpath.keys():

                prerow.append(colored('N/A','red'))
                postrow.append(colored(postpath['license_level'],'red'))
                robotprerow.append(postpath['license_level'])
                robotpostrow.append('N/A')
                richlicenselevel_pre = '[red]N/A'
                richlicenselevel_post = '[red]{}'.format(postpath['license_level'])
                mismatch = True
        else:
            prerow.append(colored('N/A','green'))
            postrow.append(colored('N/A','green'))
            robotprerow.append('N/A')
            robotpostrow.append('N/A')
            richlicenselevel_pre = 'N/A'
            richlicenselevel_post = 'N/A'
        
        if 'license_type' in prepath.keys() and 'license_type' in postpath.keys():
            if postpath['license_type'] == prepath['license_type']:
                prerow.append(colored(prepath['license_type'],'green'))
                postrow.append(colored(postpath['license_type'],'green'))
                robotprerow.append(prepath['license_type'])
                robotpostrow.append(postpath['license_type'])
                richlicensetype_pre = '[green]{}'.format(prepath['license_type'])
                richlicensetype_post = '[green]{}'.format(postpath['license_type'])
            else:
                prerow.append(colored(prepath['license_type'],'red'))
                postrow.append(colored(postpath['license_type'],'red'))
                robotprerow.append('***'+prepath['license_type']+'***')
                robotpostrow.append('***'+postpath['license_type']+'***')
                richlicensetype_pre = '[red]{}'.format(prepath['license_type'])
                richlicensetype_post = '[red]{}'.format(postpath['license_type'])
                mismatch = True
        elif 'license_type' in prepath.keys() and 'license_type' not in postpath.keys():

            prerow.append(colored(prepath['license_type'],'green'))
            postrow.append(colored(prepath['license_type'],'green'))
            robotprerow.append(prepath['license_type'])
            robotpostrow.append(prepath['license_type'])
            richlicensetype_pre = '[red]{}'.format(prepath['license_type'])
            richlicensetype_post = '[red]N/A'
            mismatch = True
        elif 'license_type' not in prepath.keys() and 'license_type' in postpath.keys():

            prerow.append(colored(postpath['license_type'],'green'))
            postrow.append(colored(postpath['license_type'],'green'))
            robotprerow.append(postpath['license_type'])
            robotpostrow.append(postpath['license_type'])
            richlicensetype_pre = '[red]N/A'
            richlicensetype_post = '[red]{}'.format(postpath['license_type'])
            mismatch = True
        
        else:
            prerow.append(colored('N/A','green'))
            postrow.append(colored('N/A','green'))
            robotprerow.append('N/A')
            robotpostrow.append('N/A')
            richlicensetype_pre = 'N/A'
            richlicensetype_post = 'N/A'
        
        if postpath['platform'] == prepath['platform']:
            prerow.append(colored(prepath['platform'],'green'))
            postrow.append(colored(postpath['platform'],'green'))
            robotprerow.append(prepath['platform'])
            robotpostrow.append(postpath['platform'])
            richplatform_pre = '[green]{}'.format(prepath['platform'])
            richplatform_post = '[green]{}'.format(postpath['platform'])
        else:
            prerow.append(colored(prepath['platform'],'red'))
            postrow.append(colored(postpath['platform'],'red'))
            robotprerow.append('***'+prepath['platform']+'***')
            robotpostrow.append('***'+postpath['platform']+'***')
            richplatform_pre = '[red]{}'.format(prepath['platform'])
            richplatform_post = '[red]{}'.format(postpath['platform'])
            mismatch = True
        
        if postpath['curr_config_register'] == prepath['curr_config_register']:
            prerow.append(colored(prepath['curr_config_register'],'green'))
            postrow.append(colored(postpath['curr_config_register'],'green'))
            robotprerow.append(prepath['curr_config_register'])
            robotpostrow.append(postpath['curr_config_register'])
            richconfigreg_pre = '[green]{}'.format(prepath['curr_config_register'])
            richconfigreg_post = '[green]{}'.format(postpath['curr_config_register'])
        else:
            prerow.append(colored(prepath['curr_config_register'],'red'))
            postrow.append(colored(postpath['curr_config_register'],'red'))
            robotprerow.append('***'+prepath['curr_config_register']+'***')
            robotpostrow.append('***'+postpath['curr_config_register']+'***')
            richconfigreg_pre = '[red]{}'.format(prepath['curr_config_register'])
            richconfigreg_post = '[red]{}'.format(postpath['curr_config_register'])
            mismatch = True
        
        vertable.add_row(prerow)
        vertable.add_row(postrow)
        robotvertable.add_row(robotprerow)
        robotvertable.add_row(robotpostrow)
        richvertable.add_row(devicepre,richvershort_pre,richver_pre,richos_pre,richimagetype_pre,richlicenselevel_pre,richlicensetype_pre,richplatform_pre,richconfigreg_pre)
        richvertable.add_row(devicepost,richvershort_post,richver_post,richos_post,richimagetype_post,richlicenselevel_post,richlicensetype_post,richplatform_post,richconfigreg_post,end_section=True)
        #print(vertable)
    return richvertable,mismatch,postverhigh