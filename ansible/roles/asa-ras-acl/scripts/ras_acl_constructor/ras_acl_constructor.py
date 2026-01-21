##################################################################### STAGE 1 #####################################################################
import inspect
import sys
import ruamel.yaml
import argparse
import logging
import os
from termcolor import colored
import json
import git
from pathlib import Path
from ras_data_processing import processing,load_yml
import traceback
from operator import itemgetter
from collections import Counter


sys.tracebacklimit = None

############################### NOTE: Any command that start 'logging' is to output infomation to the log/screen ################################

class CustomError(Exception):
    pass

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

class incompatablefile(CustomError):
    def __init__(self, file):
        self.file = file
        self.message="FILE: " + file + " IS WITHIN HIERATCHY OF A FILE THAT HAS ALSO BEEN UPDATED - PLEASE REMOVE THE CHANGES FROM THIS FILE"
        super().__init__(self.message.upper())

class versionerror(CustomError):
    def __init__(self, aclfile, message="VERSION NOT UPDATED IN FILE - PLEASE UPDATE VERSION THEN RERUN"):
        self.aclfiles = aclfile
        self.message = message
        super().__init__(self.message)

class ruleserror(CustomError):
    def __init__(self, aclfile, message="VERSION UPDATED BUT NOT RULES - PLEASE UPDATE RULES THEN RERUN"):
        self.message = message + '\n' + 'PLEASE CORRECT FILE: ' + str(aclfile)
        super().__init__(self.message)

##################################################################### STAGE 2 #####################################################################

################################ These are setting up the varibles to be able to set logging, output to console and inventory #####################################
## Allowing setting of logging level (Default:  warning)
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
    "-oc",
    "--object_change",
    default='False',
    help=(
        "Provide Flag That Objects Have Changed. "
        "Example --object_change True', default=False"),
    action="store",
    dest="object_change"
)


## Allowing to prep the file for sync between devices
parser.add_argument(
    "-s",
    "--sync",
    help=(
        "Prepare data for sync between devices. "
        "Example -s/--sync'"),
    action="store_true",
    dest="sync"
)

## Allowing input of inventory directory with -i syntax (Default: /gitnet/network_inventory/enviroments/dev)
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
if os.path.exists(pypath + '/log/ras_acl_constructor.log'):
  os.remove(pypath + '/log/ras_acl_constructor.log')

################################ Defining logging output and file location (default: <Python File location>/log/ras_acl_constructor.log #####################################
logging.basicConfig(filename=pypath + '/log/ras_acl_constructor.log', filemode='a',
    format='%(asctime)-15s : Line # %(lineno)d : %(levelname)s : %(message)s', level=loglevel)

logging.info ("Python Script Path " + str(pypath))

##################################################################### STAGE 3 #####################################################################
################################ Main Module, this requires the inventory paramenter to be set (done via -l in the command) #####################################
def full_access_check(inventory):
        ####################################### Stage 3.1 #######################################
        logging.debug(f"OBJECT CHNAGE VALUE IN TTILE CASE IS: {arg_items.object_change.title()}")
        if arg_items.object_change.title() == 'False':
           arg_items.object_change = False
        else:
            arg_items.object_change = True
        print(colored('#' * 70, 'blue'))
        print(colored('RAS ACL Constructor', 'yellow'))
        print(colored('#' * 70, 'blue'))
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True
        logging.debug('CHECKING / ON END OF INVENTORY')
        if inventory[-1] != '/':
            inventory = inventory + '/'
        logging.debug('Inventory Location ' + str(inventory))
        ## Locating .git directory in inventory in order to find which files have changes
        currentpath = Path(inventory)
        while '.git' not in os.listdir(currentpath):
            logging.debug('Checking Dir: ' + str(currentpath))
            os.chdir(currentpath.parent)
            currentpath = Path(os.getcwd())
        gitdir = str(currentpath)
        os.chdir(currentworking)
        logging.debug('Git DIR Located in : ' + str(gitdir))
        repository = git.Repo(gitdir)
        logging.debug('Repository Branch Name: ' + str(repository.active_branch.name))
        ## Identifying Files that have changed #####################################
        changed_files = []
        acl_yaml_data = {}
        with open(inventory + 'group_vars/ras/ras.yml') as ras_acls:
            ras_acls_data = yaml.load(ras_acls)
            ras_list = ras_acls_data
        logging.debug('RAS LIST: ' + str(ras_list['ra_acl']))
        logging.info('ACL NAMES RETRIEVED - RETRIVING ACL DETAILS')
        for acl in ras_list['ra_acl']:
            logging.debug('Retriving ACL Data for ' + acl)
            print(colored('Retriving ACL Data for ' + acl, 'yellow'))
            acl_path = str(inventory + 'group_vars/ras/' + acl + '.yml')
            with open(acl_path) as acl_location:
                acl_data = yaml.load(acl_location)
                logging.debug('Saving data for :' + str(acl_data[acl.replace('-','_')][0]['name']))
                acl_yaml_data[acl] = acl_data
        logging.debug('COMBINED ACL DATA: ' + json.dumps(acl_yaml_data,indent=4))
        for acl in ras_list['ra_acl']:
            ## Retriving Child and Parent data for each ACL within the Inventory
            logging.debug('LOOKING AT ACL: ' + str(acl))
            acl_filter_name = acl.replace('-','_')
            logging.debug('ACL FILTER NAME: ' + str(acl_filter_name))
            child_data= []
            logging.debug('ACL YAML DATA ' + str(acl) + json.dumps(acl_yaml_data[acl], indent=4))
            logging.debug('CHILDREN OF ACL ' + str(acl) + ' ' + str(acl_yaml_data[acl][acl_filter_name][0]['children']))
            if acl_yaml_data[acl][acl_filter_name][0]['children'] == None:
                child_data = []
            else:
                child_data = acl_yaml_data[acl][acl_filter_name][0]['children']
            ## Retriving linerage with each ACL within the Inventory
            lineage = []
            logging.debug('PARENT OF ACL ' + str(acl) + ' ' + str(acl_yaml_data[acl][acl_filter_name][0]['parents']))
            parentacl = acl_yaml_data[acl][acl_filter_name][0]['parents']
            logging.debug('Current parentacl: ' + str(parentacl))
            while parentacl != None:
                parentacl = parentacl[0]
                logging.info ('ADDING PARENT ' + str(parentacl) + ' TO LINEAGE FOR ' + str(acl) )
                lineage.append(parentacl)
                parentacl = acl_yaml_data[parentacl][parentacl.replace('-','_')][0]['parents']
            logging.debug('LINEAGE DATA FOR ACL ' + str(acl) + ' IS: ' + json.dumps(lineage, indent=4))
            acl_yaml_data[acl]['hierarchy']={'lineage': lineage, 'children': child_data}
        for file_diff in (repository.git.diff('HEAD', name_only=True)).split("\n"):
            head, tail = os.path.split(file_diff)
            if 'ras-' in tail:
                changed_files.append(file_diff)
        changed_acl = []
        ## Confirm Version has changed
        ####################################### Stage 3.2 #######################################
        ## Retriving ACLS and Data from Inventory Directory and placing them within a Dict
        print(colored('#' * 70, 'blue'))
        if ('release' not in repository.active_branch.name and arg_items.sync != True):
            print(colored('Checking File integrity', 'yellow'))
            print(colored('#' * 70, 'blue'))
        for file in changed_files:
            print(colored('Checking File integrity of ' + file, 'yellow'))
            headsha = repository.head.commit
            logging.info('CHANGED FILE IS: ' + str(file))
            logging.info('ABSOLUTE PATH IS: ' + str(headsha.tree.abspath))
            targetfile = headsha.tree / file
            logging.info('REPO FILE PATH IS: ' + str(targetfile))
            previousdata = load_yml(targetfile.data_stream.read())
            logging.debug('PREVIOUS DATA IS: ' + json.dumps(previousdata, indent=4))
            group_name = list(previousdata.keys())[1]
            logging.debug('GROUP NAME IS: ' + str(group_name))
            logging.debug('RULES DATA: ' + json.dumps(previousdata[group_name][0]['rules'],indent=4))
            previousversion = previousdata[group_name][0]['version']
            previousrules = list(previousdata[group_name][0]['rules'])
            logging.debug('PREVIOUS VERSION: ' + str(previousversion))
            logging.debug('PREVIOUS RULES: ' + str(previousrules))
            currentdata = load_yml(file.replace(file, headsha.tree.abspath + '/' + file))
            logging.debug('CURRENT DATA IS: ' + json.dumps(currentdata[group_name][0], indent=4))
            currentversion = currentdata[group_name][0]['version']
            currentrules = list(currentdata[group_name][0]['rules'])
            logging.debug('CURRENT VERSION: ' + str(currentversion))
            logging.debug('CURRENT RULES: ' + str(currentrules))
            logging.debug('RULES COMPARISON: ' + str(previousrules == currentrules))
            if previousversion >= currentversion and arg_items.sync != True:
                raise versionerror(str(headsha.tree.abspath + '/' + file))
            if (previousversion != currentversion) and (previousrules == currentrules) and arg_items.sync != True:
                raise ruleserror(str(headsha.tree.abspath + '/' + file))
        updated_files = []
        if 'release' not in repository.active_branch.name and arg_items.sync != True :
            print(colored('Checking ACL integrity', 'yellow'))
            print(colored('#' * 70, 'blue'))
        for acl in changed_files:
            print(colored('Checking acl hierarchy of ' + acl, 'yellow'))
            head, acl = os.path.split(acl)
            acl_name, ext = os.path.splitext(acl)
            logging.debug ('CHECKING ACL: ' + str(acl_name))
            print(colored('Checking ACL integrity of ' + acl_name, 'yellow'))
            if [acl_to_check for acl_to_check in changed_files if str(os.path.split(acl_to_check)[1]).split('.')[0] in acl_yaml_data[acl_name]['hierarchy']['lineage']]:
                    raise incompatablefile(acl)
            for acl_check in changed_files:
                head, acl_check = os.path.split(acl_check)
                acl_checkname, ext = os.path.splitext(acl_check)
                if acl_name not in updated_files:
                    updated_files += [acl_name]

        if len(updated_files) == 0 and ('release' in repository.active_branch.name or arg_items.sync == True):
            logging.debug ('IN RELEASE SO SETTING CHANGED FILE TO GENERAL and adding MRG files')
            updated_files += [acl for acl in ras_list['release_update_acls']]
        logging.debug('NUMBER OF CHANGED FILES IS: ' + str(len(updated_files)) + ' | DETAILS ARE ' + json.dumps(changed_files))
        if len(updated_files) == 0 and ('release' not in repository.active_branch.name  and arg_items.sync != True and arg_items.object_change == False):
            raise nofiles(len(updated_files))

        if len(updated_files) == 0 and arg_items.object_change == True:
            print(colored('Objects Changed but No ACLs to Changed, continuing but please check', 'red'))
            print(colored('#' * 70,'blue'))
        else:
            logging.info('Starting Update of ACL yml Files')
            logging.debug('DETECTED FILE CHANGED ' + str(updated_files))
            logging.info('CHANGES IDENTIFIED - RETRIVING ACL NAMES')
            print(colored('Starting Retrival of ACL Data', 'yellow'))
            if 'release' not in repository.active_branch.name and arg_items.sync != True:
                print('#' * 50)
                print(colored('Starting Identification of which ACLs have changed', 'white'))

            for acl in updated_files:
                ## Compiling a list of All ACLs that need changing
                logging.info('Compling data on ' + str(acl))
                acl_name, ext = os.path.splitext(acl)
                acl_details = acl_name.replace('-', '_')
                if 'release' not in repository.active_branch.name and arg_items.sync != True:
                    print(colored('Changed ACL =', 'white'),colored(acl_name, 'yellow'))
                    print('#' * 50)
                logging.info('COLLECTING ACLS THAT NEED TO CHANGE ')
                acls_to_change = []
                current_acl = acl_name
                logging.debug('FIRST ACL TO CHANGE ' + current_acl)
                if acl_yaml_data[acl_name][acl_details][0]['children'] != None:
                    for child in acl_yaml_data[acl_name][acl_details][0]['children']:
                        logging.debug ('CHILD TO ADD ' + child)
                        acls_to_change.append(child)
                        if acl_yaml_data[child][child.replace('-','_')][0]['children'] != None:
                            for grandchild in acl_yaml_data[child][child.replace('-','_')][0]['children']:
                                logging.debug ('GRANDCHILD TO ADD ' + grandchild)
                                acls_to_change.append(grandchild)
                                if acl_yaml_data[grandchild][grandchild.replace('-','_')][0]['children'] != None:
                                    for greatgrandchild in acl_yaml_data[grandchild][grandchild.replace('-','_')][0]['children']:
                                        logging.debug ('GREATGRANDCHILD TO ADD ' + greatgrandchild)
                                        acls_to_change.append(greatgrandchild)
                acl_to_change = acls_to_change.reverse()
                logging.debug('ACLS to CHANGE ' + json.dumps(acls_to_change, indent=4))
                ####################################### Stage 3.3 #######################################
                processing(acl_name,acl_yaml_data,acls_to_change,inventory,loglevel,repository,arg_items)
                print(colored('#' * 70, 'blue'))
                print(colored('Completed RAS ACL Data Processing', 'yellow'))
                print(colored('#' * 70, 'blue'))


def main():
    try:
        full_access_check(arg_items.inventory)

    except Exception as err:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        ## Outputing infomration if error has occured including File, Line Number Message and any additional infomation
        #print(colored('#' * 83, 'red'))
       # print(colored('#' * 39 + ' ERROR ' + '#' * 37, 'red'))
        if exc_tb.tb_next:
            err_lineno = exc_tb.tb_next.tb_lineno
        else:
            err_lineno = exc_tb.tb_lineno

        errormsg =  '#' * 39 + \
        ' ERROR ' + '#' * 37 + '\n' + \
                    'SEE LOG ' + str(pypath) + '/log/ras_acl_constructor.log FOR FULL DETAILS' + '\n' + \
                    'ERROR IN FILE: ' + str(os.path.abspath(__file__)) + '\n' + \
                    'ERROR LINE: ' + str(err_lineno) + '\n' + \
                    'ERROR MESSAGE: ' + str(err) + '\n' + \
                    '#' * 83
        print(colored(errormsg, 'red'))
        return sys.exit(errormsg)

if __name__ == "__main__":
    main()
