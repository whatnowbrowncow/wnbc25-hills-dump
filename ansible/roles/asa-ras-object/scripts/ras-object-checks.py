##################################################################### STAGE 1 #####################################################################
from collections.abc import Iterable
import sys
import ruamel.yaml
import argparse
import logging
import os
from termcolor import colored
import json
from pathlib import Path
import traceback
import git

sys.tracebacklimit = None

############################### NOTE: Any command that start 'logging' is to output infomation to the log/screen ################################

class CustomError(Exception):
    pass
class duplicate_objects(CustomError):
    def __init__(self, objectfile, objectlist, message=""):
        self.message = message + '\n' + 'PLEASE CORRECT FILE: ' + str(objectfile)
        super().__init__(self.message)

class tomanyfiles(CustomError):
    def __init__(self, excessfiles, message="MULTIPLE ACL FILES CHANGED - PLEASE CHANGE ONLY ONE FILE PER RELEASE"):
        self.excessfiles = excessfiles
        self.message = message
        super().__init__(self.message)

class nofiles(CustomError):
    def __init__(self, missingfiles, message="NO ACL FILES CHANGED - PLEASE UPDATE ACL FILES THEN RERUN"):
        self.missingfiles = missingfiles
        self.message = message
        super().__init__(self.message)

##################################################################### STAGE 2 #####################################################################
parser = argparse.ArgumentParser()

parser.add_argument(
    "-l",
    "--log",
    default="warning",
    help=(
        "Provide logging level. "
        "Example --log debug', default='warning'"),
    action="store",
    dest="log"
)

parser.add_argument(
    "-i",
    "--inventory",
    default="/gitnet/network_inventory_test/environments/dev/",
    help=(
        "This is to identify the inventory location. "
        "Example -i /gitnet/network_inventory/enviroments/dev --inventory /gitnet/network_inventory/enviroments/dev'"),
    action="store",
    dest="inventory"
)

## Converting input level to system level within debug
arg_items = parser.parse_args()
loglevels = {
    'critical': logging.CRITICAL,
    'error': logging.ERROR,
    'warning': logging.WARNING,
    'info': logging.INFO,
    'debug': logging.DEBUG
}

loglevel = loglevels.get(arg_items.log.lower())

################################ Defining working paths, both the path the python code is located and the current working path #####################################
pypath = os.path.dirname(os.path.abspath(__file__))
currentworking = os.getcwd()

################################ Confirming all required directories exists #####################################
if os.path.isdir(pypath + '/log') == False:
    os.mkdir(pypath + '/log')

if os.path.isdir('/gitnet/ras-processed') == False:
    os.mkdir('/gitnet/ras-processed')

if os.path.isdir('/gitnet/ras-processed/data') == False:
    os.mkdir('/gitnet/ras-processed/data')

################################ Removing any existing logs #####################################
if os.path.exists(pypath + '/log/ras_object_check.log'):
  os.remove(pypath + '/log/ras_object_check.log')

################################ Defining logging output and file location (default: <Python File location>/log/ras_acl_constructor.log #####################################
logging.basicConfig(filename=pypath + '/log/ras_object_check.log', filemode='a',
                        format='%(asctime)-15s : Line # %(lineno)d : %(levelname)s : %(message)s', level=loglevel)

##################################################################### STAGE 3 #####################################################################
def object_check(inventory):
        ####################################### Stage 3.1 #######################################
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True
        logging.debug('CHECKING / ON END OF INVENTORY')
        if inventory[-1] != '/':
            inventory = inventory + '/'
        logging.debug('Inventory Location ' + str(inventory))
        ####################################### Stage 3.2 #######################################
        logging.debug('Opening Network Object File and importing to dictionary')
        ## Retriving Objects within the Yaml Data and compliling into relevent list for checking
        with open(inventory + 'group_vars/ras/network_objects.yml') as ras_net_objects:
            ras_net_object_data = yaml.load(ras_net_objects)
            ras_net_object_list = ras_net_object_data
        with open(inventory + 'group_vars/ras/svc_objects.yml') as ras_svc_objects:
            ras_svc_object_data = yaml.load(ras_svc_objects)
            ras_svc_object_list = ras_svc_object_data
        with open(inventory + 'group_vars/ras/protocol_objects.yml') as ras_proto_objects:
            ras_proto_object_data = yaml.load(ras_proto_objects)
            ras_proto_object_list = ras_proto_object_data
        net_objects_list = list(map(lambda x : x['name'], ras_net_object_list['network_objects']['host_objects']))
        net_objects_list.extend(list(map(lambda x : x['name'], ras_net_object_list['network_objects']['subnet_objects'])))
        if isinstance(ras_net_object_list['network_objects']['fqdn_objects'], Iterable):
            net_objects_list.extend(list(map(lambda x : x['name'], ras_net_object_list['network_objects']['fqdn_objects'])))
        net_objects_list.extend(list(map(lambda x : x['name'], ras_net_object_list['network_objects']['range_objects'])))
        net_objects_list.extend(list(map(lambda x : x['name'], ras_net_object_list['network_object_groups'])))
        proto_objects_list = list(map(lambda x : x['name'], ras_proto_object_list['protocol_object_groups']))
        svc_objects_list = list(map(lambda x : x['name'], ras_svc_object_list['service_objects']))


        ## Checking for Network, Services and Protocols objects with duplicate names, and rasing exception where required
        logging.debug('Net Object List: ' + json.dumps(net_objects_list, indent=4))
        net_duplicates = [net_object_name for net_object_name in net_objects_list if net_objects_list.count(net_object_name) > 1]
        logging.debug('Net duplicate Object Names: ' + str(net_duplicates))
        logging.debug("Net Amount of Duplicate Objects is: " + str(len(net_duplicates)))
        if len(net_duplicates) > 0:
            raise duplicate_objects(inventory + 'group_vars/ras/network_objects.yml',net_duplicates,"FOUND " + str(len(net_duplicates)) + " DUPLICATE OBJECT NAMES - PLEASE REMOVE/RE-NAME THE DUPLICATES THEN RERUN " + "\n" + "DUPLICATE OBJECTS NAMES: " + str(set(net_duplicates)))

        logging.debug('Svc Object List: ' + json.dumps(svc_objects_list, indent=4))
        svc_duplicates = [svc_object_name for svc_object_name in svc_objects_list if svc_objects_list.count(svc_object_name) > 1]
        logging.debug('Svc duplicate Object Names: ' + str(svc_duplicates))
        logging.debug("Svc Amount of Duplicate Objects is: " + str(len(svc_duplicates)))
        if len(svc_duplicates) > 0:
            raise duplicate_objects(inventory + 'group_vars/ras/svc_objects.yml',svc_duplicates,"FOUND " + str(len(svc_duplicates)) + " DUPLICATE OBJECT NAMES IN - PLEASE REMOVE/RE-NAME THE DUPLICATES THEN RERUN " + "\n" + "DUPLICATE OBJECTS NAMES: " + str(set(svc_duplicates)))

        logging.debug('Proto Object List: ' + json.dumps(proto_objects_list, indent=4))
        proto_duplicates = [proto_object_name for proto_object_name in proto_objects_list if proto_objects_list.count(proto_object_name) > 1]
        logging.debug('Proto duplicate Object Names: ' + str(proto_duplicates))
        logging.debug("Proto Amount of Duplicate Objects is: " + str(len(proto_duplicates)))
        if len(proto_duplicates) > 0:
            raise duplicate_objects(inventory + 'group_vars/ras/protocol_objects.yml',proto_duplicates,"FOUND " + str(len(proto_duplicates)) + " DUPLICATE OBJECT NAMES - PLEASE REMOVE/RE-NAME THE DUPLICATES THEN RERUN " + "\n" + "DUPLICATE OBJECTS NAMES: " + str(set(proto_duplicates)))



def export_changes(inventory):
    import wh_python_toolset.wh_net_python_toolset as wh_tools
    repo = git.Repo(inventory, search_parent_directories=True)
    mastercommit = repo.heads.master.commit
    targetfile = mastercommit.tree / "environments/prod/group_vars/ras/network_objects.yml"
    file_functions = wh_tools
    data = {}
    data = file_functions.load_yml(targetfile)



################################ Main Module, this requires the inventory parameter to be set (done via -l in the command) #####################################

def main(inventory):
    try:
        print(colored('#' * 70, 'blue'))
        print(colored('Checking for Duplicate Objects', 'yellow'))
        object_check(inventory)
        print(colored('No Duplicate Objects Found', 'yellow'))
        print(colored('#' * 70, 'blue'))

    except Exception as err:
        print(colored('#' * 83, 'red'))
        print(colored('#' * 39 + ' ERROR ' + '#' * 37, 'red'))
        if tomanyfiles and nofiles:
            print(colored('SEE LOG ' + str(pypath) + '/log/ras_acl_constructor.log FOR FULL DETAILS' + '\n' +
            'ERROR IN FILE: ' + str(os.path.abspath(__file__)) + '\n' +
            'ERROR LINE: ' + str(err.__traceback__.tb_lineno),'red'))
        print(colored('ERROR MESSAGE: ' + str(err), 'red'))
        print(colored('#' * 83, 'red'))
        return sys.exit(1)

if __name__ == "__main__":
    main(arg_items.inventory)
