##################################################################### STAGE 1 #####################################################################
import wh_net_python_toolset.wh_python_toolset as wh_tools
import git
import json
from tqdm import tqdm
from pathlib import Path
args = wh_tools.import_std_arg()
parser = args.create_arg()
parser.add_argument(
    "-i",
    "--inventory",
    default=False,
    help=("produce Data files only, Do not show configuration output", "Example --dataonly"),
    action="store",
    dest="inventory",
)

arg_items = parser.parse_args()
logger = wh_tools.logging_define(level=arg_items.level, logpath=arg_items.logpath)
prog_logger = logger.logging_setup()
file_functions = wh_tools.file_functions()
console_text = wh_tools.Console_sizes()

##################################################################### STAGE 2 #####################################################################
# Class to process Object Data
class object_processing:
    # Inital definition of class
    def __init__(self,filename) -> None:
        self.filename = filename
        pass


    # Retriveing the existing data and the updated data then placing it in 2 dicts
    def retrive_data(self):
        repo = git.Repo(arg_items.inventory, search_parent_directories=True)
        headsha = repo.heads.master.commit
        prog_logger.debug(f'Head sha: { headsha }')
        updatedfile = self.filename
        prog_logger.debug(f'PATH DETAILS: {updatedfile} : {type(updatedfile)}')
        updatedfile = updatedfile.replace(f'{headsha.tree.abspath}/',"")
        prog_logger.debug(f'GIT PATH DETAILS: {json.dumps(updatedfile,indent=4)}')
        prog_logger.debug(f'Updated file Location: { updatedfile }')
        targetfile = headsha.tree / updatedfile
        tqdm.write("Retriving Existing Data")
        olddata = file_functions.load_yml(targetfile.data_stream.read())
        prog_logger.debug(f'Old Data: { olddata }')
        prog_logger.debug(f'New Data: \n{json.dumps(olddata, indent=4)}')
        newfile = f'{ headsha.tree.abspath }/{ updatedfile }'
        tqdm.write("Retriving Updated Data")
        newdata = file_functions.load_yml(newfile)
        prog_logger.debug(f'New Data: \n{json.dumps(newdata, indent=4)}')
        return newdata,olddata


    # Process to identifiy Diffrences in the before and after changes, with the data being passed to it
    def find_dict_differences(self,newdata, olddata):
        prog_logger.debug("FINDING DATA CHANGES")
        diff = [item for item in newdata if item not in olddata]
        return diff

    ### For Network Objects
    ### Using extracted data, finding diffrecnces and then compiling the data
    ### into a format to be used by ansible
    ### then placing data into a dict for yaml file production
    def network_objects(self,newdata,olddata):
        yaml_data = []
        tqdm.write("Processing Network Object Hosts")
        net_obj_hosts_diff = self.find_dict_differences(newdata['network_objects']['host_objects'],olddata['network_objects']['host_objects'])
        prog_logger.debug(F'NETWORK OBJECT HOST DIFFRENCES: {net_obj_hosts_diff}')
        tqdm.write("Processing Network Object Subnets")
        net_obj_subnets_diff = self.find_dict_differences(newdata['network_objects']['subnet_objects'],olddata['network_objects']['subnet_objects'])
        prog_logger.debug(F'NETWORK OBJECT SUBNET DIFFRENCES: {net_obj_subnets_diff}')
        tqdm.write("Processing Network Ranges Hosts")
        net_obj_range_diff = self.find_dict_differences(newdata['network_objects']['range_objects'],olddata['network_objects']['range_objects'])
        prog_logger.debug(F'NETWORK OBJECT RANGE DIFFRENCES: {net_obj_range_diff}')
        tqdm.write("Processing Network Object Groups")
        group_diff = self.find_dict_differences(newdata['network_object_groups'], olddata['network_object_groups'])
        prog_logger.debug(F'NETWORK OBJECT GROUP DIFFRENCES: {group_diff}')
        prog_logger.debug(f'Diff Data Type: \n{type(group_diff)}')
        prog_logger.debug(f'Diff Data Pre Key Add: \n{json.dumps(group_diff, indent=4)}')
        obj_grp_counter = tqdm(group_diff)
        obj_grp_counter.set_description("Processing Network Objects Within groups")
        for data in group_diff:
             obj_grp_counter.update()
             data.update(type='network')
             object_items={}
             if data['hosts'] is not None:
                 prog_logger.debug(f" HOST DATA IS TYPE: {type(data['hosts'])} | HOST DATA LEN IS: {len(data['hosts'])} | FIRST IP IS {data['hosts'][0]['ip_addr']}")
                 host_list = [value_data['ip_addr'] for value_data in data['hosts']]
                 data.pop('hosts')
                 object_items.update(host=host_list)
             else:
                 data.pop('hosts')
             if data['networks'] is not None:
                 network_list= [f"{value['ip_addr']} {value['mask']}" for value in data['networks']]
                 object_items.update(address=network_list)
                 data.pop('networks')
             else:
                 data.pop('networks')
             if data['objects'] is not None:
                 object_list =  [value['object_name'] for value in data['objects']]
                 object_items.update(object=object_list)
                 data.pop('objects')
             else:
                 data.pop('objects')
             if data['group_objects'] is not None :
                 group_object_list =  [value['group_object_name'] for value in data['group_objects']]
                 data.update(group_object=group_object_list)
                 data.pop('group_objects')
             else:
                 data.pop('group_objects')
             data.update(object_items=object_items)
        yaml_data = {'network_objects': {}}
        yaml_data['network_objects']['host_objects'] = {}
        yaml_data['network_objects']['subnet_objects'] = {}
        yaml_data['network_objects']['range_objects'] = {}
        yaml_data['network_objects']['fqdn_objects'] = {}
        yaml_data['network_object_groups'] = {}
        if len(net_obj_hosts_diff)>0 or len(net_obj_subnets_diff)>0 or len(net_obj_range_diff)>0 or len(group_diff)>0:

            if len(net_obj_hosts_diff)>0:
                yaml_data['network_objects']['host_objects'] = net_obj_hosts_diff
            if len(net_obj_subnets_diff)>0:
                yaml_data['network_objects']['subnet_objects'] = net_obj_subnets_diff
            if len(net_obj_range_diff)>0:
                yaml_data['network_objects']['range_objects'] = net_obj_range_diff
            if len(group_diff)>0:
                yaml_data['network_object_groups'] = group_diff
        prog_logger.debug(f'DIFF DATA TO SAVE TO FILE: \n{json.dumps(yaml_data, indent=4)}')
        return yaml_data


    ### For Service Objects
    ### Using extracted data, finding diffrecnces and then compiling the data
    ### into a format to be used by ansible
    ### then placing data into a dict for yaml file production

    def svc_objects(self,newdata,olddata):
        yaml_data = []
        tqdm.write("Processing Service Object")
        svc_obj_diff = self.find_dict_differences(newdata['service_objects'],olddata['service_objects'])
        prog_logger.debug(F'SERVICE OBJECT DIFFRENCES: {svc_obj_diff}')
        tqdm.write("Processing Service Object Groups")
        group_diff = self.find_dict_differences(newdata['service_object_groups'], olddata['service_object_groups'])
        prog_logger.debug(F'SERVICE OBJECT GROUP DIFFRENCES: {group_diff}')
        prog_logger.debug(f'DIFF DATA TYPE: \n{type(group_diff)}')
        prog_logger.debug(f'DIFF DATA PRE KEY ADD: \n{json.dumps(group_diff, indent=4)}')
        obj_grp_counter = tqdm(group_diff)
        obj_grp_counter.set_description("Processing Network Objects Within groups")
        objects_in_groups = []
        for data in group_diff:
            prog_logger.debug("PROCESSING DATA INTO ANSIBLE CISCO OBJ FORMAT ")
            obj_grp_counter.update()
            object_items = []
            if data['protocol'] == '':
                data.pop('protocol')
            if data['objects'] is not None:
                objects_in_groups.append({'group_name': data['name'], 'objects': data['objects']})
                data.pop('objects')
            else:
                data.pop('objects')
            if data['services'] is not None:
                if 'services_object' not in object_items:
                    object_items.append({'services_object': []})
                for value in data['services']:
                    direction = f"{value['direction']}_port"
                    if value['port_type'] is not None:
                        port_details = { value['port_type']: value['port']}
                    else:
                        port_details = { 'range': { value['range_start'], value['range_end']}}
                    services_objects = {'protocol': value['protocol'], direction: port_details}
                    if object_items != [] and 'services_object' in object_items[0]:
                        object_items[0]['services_object'].append(services_objects)
                data.pop('services')
            else:
                data.pop('services')
            if data['port_objects'] is not None:
                object_items.append({'port_object': []})
                for value in data['port_objects']:
                    if value['port_type'] == 'eq':
                        object_items[0]['port_object'].append({value['port_type']: value['port']})
                    if value['port_type'] == 'range':
                        object_items[0]['port_object'].append({'range':{'end': value['range_end'],'start':value['range_start']}})
                data.pop('port_objects')
            else:
                data.pop('port_objects')
            if data['group_objects'] is not None :
                group_object_list =  [value['group_object_name'] for value in data['group_objects']]
                data.update(group_object=group_object_list)
            else:
                data.pop('group_objects')
            tqdm.write(f"Finshed Compiling Group {data['name']}")
            object_items_list = {}
            for object_group_items in object_items:
                object_items_list.update(object_group_items)
            data.update(object_items_list)
            prog_logger.debug(f'Data Output from group diff: {json.dumps(data,indent=4)}')
        yaml_data = {}
        yaml_data['service_objects'] = svc_obj_diff
        yaml_data['service_object_groups'] = {}
        yaml_data['service_object_groups']['object_groups'] = group_diff
        yaml_data['service_object_groups']['group_with_objects'] = objects_in_groups
        prog_logger.debug(f'DIFF DATA TO SAVE TO FILE: \n{json.dumps(yaml_data, indent=4)}')
        return yaml_data


    def proto_objects(self,newdata,olddata):
        yaml_data = []
        tqdm.write("Processing Protocol Object")
        group_diff = self.find_dict_differences(newdata['protocol_object_groups'], olddata['protocol_object_groups'])
        prog_logger.debug(f'PROTOCOL OBJECT GROUP DIFFRENCES: {group_diff}')
        prog_logger.debug(f'DIFF DATA TYPE: \n{type(group_diff)}')
        prog_logger.debug(f'DIFF DATA PRE KEY ADD: \n{json.dumps(group_diff, indent=4)}')
        obj_grp_counter = tqdm(group_diff)
        obj_grp_counter.set_description("Processing Protocol Objects Within groups")
        objects_in_groups = []
        for data in group_diff:
            prog_logger.debug("PROCESSING DATA INTO ANSIBLE CISCO OBJ FORMAT ")
            obj_grp_counter.update()
            object_items = []
            if data['objects'] is not None:
                prog_logger.debug(f"PROCESSING OBJECT: {data['objects']}")
                objects_in_groups += [{'name': data['name'],'protocol': [item['object_name'] for item in data['objects']]}]
                data.pop('objects')
            else:
                data.pop('objects')
            if data['group_objects'] is not None :
                group_object_list =  [value['group_object_name'] for value in data['group_objects']]
                data.update(group_object=group_object_list)
            else:
                data.pop('group_objects')
            tqdm.write(f"Finshed Compiling Group {data['name']}")
            object_items_list = {}
            for object_group_items in object_items:
                object_items_list.update(object_group_items)
            data.update(object_items_list)
            prog_logger.debug(f'Data Output from group diff: {json.dumps(data,indent=4)}')
        yaml_data = {}
        yaml_data['protocol_objects'] = {}
        yaml_data['protocol_object_groups'] = []
        yaml_data['protocol_object_groups'] = objects_in_groups
        #yaml_data['protocol_object_groups']['group_with_objects'] = objects_in_groups
        prog_logger.debug(f'DIFF DATA TO SAVE TO FILE: \n{json.dumps(yaml_data, indent=4)}')
        return yaml_data


##################################################################### STAGE 3 #####################################################################

def main():

##################################################################### STAGE 3.1 #####################################################################
    # Retriving Data from Yaml for Network Objects

    tqdm.write(console_text.return_half_width_Text('Starting Processing of Network Object and Group Data','#'))
    net_obj_process = object_processing(f'{arg_items.inventory}/group_vars/ras/network_objects.yml')
    newdata,olddata = net_obj_process.retrive_data()

    # Processing Network Object Data into Ansible Cisco Obj format
    net_yaml_data = net_obj_process.network_objects(newdata,olddata)
    tqdm.write("Saving ansible data Network Objects File")

    # Seting network object group file information
    net_filename = 'ansible_network_object_data.yml'
    net_file_location = '/gitnet/ras-processed/data'
    tqdm.write(f"Number of network items changed: {len(net_yaml_data)}")

    # Saving File Network Object Data to Yaml
    prog_logger.debug(f"SAVING NETWORK YAML FILE TO {net_file_location}")
    file_functions.save_yml(net_yaml_data,net_filename,net_file_location)
    tqdm.write(f"File Saved to { net_file_location}/{net_filename}")

##################################################################### STAGE 3.2 #####################################################################
    # Retriving Data from Yaml for Service Objects
    tqdm.write(console_text.return_half_width_Text('Starting Processing of Service Object and Group Data','#'))
    svc_obj_process = object_processing(f'{arg_items.inventory}/group_vars/ras/svc_objects.yml')
    svc_newdata,svc_olddata = svc_obj_process.retrive_data()
    prog_logger.debug(f'SERVICE OBJECT OUTPUT: NEWDATA : {json.dumps(svc_newdata,indent=4)} | OLDDATA: {json.dumps(svc_olddata,indent=4)}')

    # Processing Service Object Data into Ansible Cisco Obj format
    svc_yaml_data = svc_obj_process.svc_objects(svc_newdata,svc_olddata)
    prog_logger.debug(f'SERVICE OBJECT CHANGES: {json.dumps(svc_yaml_data)}')
    tqdm.write("Saving ansible data Service Objects File")

    # Seting network Service group file information
    svc_filename = 'ansible_service_object_data.yml'
    svc_file_location = '/gitnet/ras-processed/data'


    # Saving File Network Object Data to Yaml
    prog_logger.debug(f"SAVING SERVICE YAML FILE TO {svc_file_location}")
    tqdm.write(f"Number of service items changed: {len(svc_yaml_data)}")
    file_functions.save_yml(svc_yaml_data,svc_filename,svc_file_location)
    tqdm.write(f"File Saved to { svc_file_location}/{svc_filename}")

##################################################################### STAGE 3.3 #####################################################################
    # Retriving Data from Yaml for Protocol Objects
    tqdm.write(console_text.return_half_width_Text('Starting Processing of Protocol Object and Group Data','#'))
    proto_obj_process = object_processing(f'{arg_items.inventory}/group_vars/ras/protocol_objects.yml')
    proto_newdata,proto_olddata = proto_obj_process.retrive_data()
    prog_logger.debug(f'SERVICE OBJECT OUTPUT: NEWDATA : {json.dumps(proto_newdata,indent=4)} | OLDDATA: {json.dumps(proto_olddata,indent=4)}')

    # Processing Service Object Data into Ansible Cisco Obj format
    proto_yaml_data = proto_obj_process.proto_objects(proto_newdata,proto_olddata)
    prog_logger.debug(f'SERVICE OBJECT CHANGES: {json.dumps(proto_yaml_data)}')
    tqdm.write("Saving ansible data Service Objects File")

    # Seting network Service group file information
    proto_filename = 'ansible_proto_object_data.yml'
    proto_file_location = '/gitnet/ras-processed/data'


    # Saving File Network Object Data to Yaml
    prog_logger.debug(f"SAVING SERVICE YAML FILE TO {proto_file_location}")
    tqdm.write(f"Number of service items changed: {len(proto_yaml_data)}")
    file_functions.save_yml(proto_yaml_data,proto_filename,proto_file_location)
    tqdm.write(f"File Saved to { proto_file_location}\/{proto_filename}")
    tqdm.write('#' * console_text.full_width)

if __name__ == "__main__":
    main()




