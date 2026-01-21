
##################################################################### STAGE 1 #####################################################################
import pkg_resources
dependencies = [
  'termcolor',
  'tldextract',
  'gitpython',
  'ruamel.yaml'
]
pkg_resources.require(dependencies)


from inspect import _empty, currentframe, getframeinfo
import sys
import ruamel.yaml
import argparse
import logging
import os
from termcolor import colored
import json
import git
from pathlib import Path
import traceback
import tldextract
from collections import Counter

sys.tracebacklimit = None


############################### NOTE: Any command that start 'logging' is to output information to the log/screen ################################
############################### Setting Custom Error Output ################################
class CustomError(Exception):
    topline_message = (colored('\n' + '#' * 83 + '\n' +
        'SEE LOG ' + str('pypath') + '/log/ras_dst_constructor.log FOR FULL DETAILS' + '\n' +
                'ERROR IN FILE: ' + str(os.path.abspath(__file__)) + '\n', 'red'))

    bottomline_message = (colored('\n' + '#' * 83, 'red'))
    pass

class nofiles(CustomError):
    def __init__(self,lineno,message):
        sys.tracebacklimit = 0        
        custmessage = (colored("LINE NO: " + str(lineno) + "\nERROR: NO DST FILES CHANGED - " + message +  " - PLEASE UPDATE DST FILES THEN RERUN",'red'))
        self.message = CustomError.topline_message + custmessage + CustomError.bottomline_message 
        super().__init__(self.message)
class tomanydst(CustomError):
    def __init__(self,dstlength,dstname,lineno):
        sys.tracebacklimit = 0
        custmessage = (colored('LINE NO: ' + str(lineno) + '\nERROR: DST ' + dstname + ' FQDN CHARCTER COUNT IS GREATER THAN 5000, A PRUNE TO DST ENTRIES IS NEEDED','red'))
        self.message =  CustomError.topline_message + custmessage + CustomError.bottomline_message
        super().__init__(self.message)
class nodstchanges(CustomError):
    def __init__(self,lineno,file,repo):
        sys.tracebacklimit = 0
        custmessage = (colored('ERROR: DST DATA IN FILE \'' + os.path.basename(file) + '\' HAS NOT BEEN UPDATED\n' + '=' * 83 + '\nGIT DIFF OUTPUT IS:\n' + str(repo.git.diff('master',file ,unified=0)),'red'))
        self.message =  CustomError.topline_message + custmessage + CustomError.bottomline_message
        super().__init__(self.message)
class domainalreadyexists(CustomError):
    def __init__(self,lineno,message):
        logging.debug ('Called Duplicate Domain Error')
        sys.tracebacklimit = 0
        custmessage = (colored('ERROR: ' + str(message),'red'))
        self.message =  CustomError.topline_message + custmessage + CustomError.bottomline_message
        super().__init__(self.message)

class versionnotupdated(CustomError):
    def __init__(self,lineno,message):
        logging.debug ('Called Version Not Updated Error')
        sys.tracebacklimit = 0
        custmessage = (colored('ERROR: ' + str(message),'red'))
        self.message =  CustomError.topline_message + custmessage + CustomError.bottomline_message
        super().__init__(self.message)


class excluded_char_exception(CustomError):
    def __init__(self,lineno,dst_entry):
        message = f'AN INVALID CHARACTER IS IN THE DST ENTRY: {dst_entry}'
        logging.debug (f'EXCEPTION RAISED:  {message}')
        sys.tracebacklimit = 0
        custmessage = (colored(f'ERROR: {message}','red'))
        self.message =  CustomError.topline_message + custmessage + CustomError.bottomline_message
        super().__init__(self.message)

##################################################################### STAGE 2 #####################################################################

################################ These are setting up the variables to be able to set logging and inventory #####################################
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
if os.path.exists(pypath + '/log/ras_dst_constructor.log'):
  os.remove(pypath + '/log/ras_dst_constructor.log')
logging.basicConfig(filename=pypath + '/log/ras_dst_constructor.log', filemode='a',
                    format='%(asctime)-15s : Line # %(lineno)d : %(funcName)s : %(levelname)s : %(message)s', level=loglevel)
logging.info ("Python Script Path " + str(pypath))
subdomainlist = [] 



def load_yml(filename):
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    if not isinstance(filename,bytes):
        with open(filename) as fp:
            yml_data = yaml.load(fp)
        fp.close()
    else:
        yml_data = yaml.load(filename)
    return yml_data

def changed_yamls(inventory,repo):
    ## Reading git information #####################################
    logging.info ('REPO DIRTY STATUS IS: ' + str(repo.is_dirty()))
    logging.info ('BRANCH NAME IS: ' + str(repo.active_branch.name))
    if repo.is_dirty() or 'release' in repo.active_branch.name or arg_items.sync == True:
        currentpath = Path(inventory)
        gitdir = str(currentpath)
        inventorypath = os.path.realpath(currentpath)
        logging.debug('Current Path: ' + str(currentworking))
        top_level = repo.git.rev_parse(show_toplevel=True)
        logging.debug('Top Level: ' + str(top_level))
        os.chdir(currentworking)
        logging.debug('Repository Branch Name: ' + str(repo.active_branch.name))
        logging.debug('Changed Files (Git Output): ' + str(repo.git.diff(None, name_only=True)))
        ## Identifying Files that have changed #####################################
        changed_files = []
        if arg_items.sync == False:
            for file_diff in (repo.git.diff('master', name_only=True)).split("\n"):
                    head, tail = os.path.split(file_diff)
                    if 'dst-' in tail:
                        changed_files.append(os.path.join(top_level,file_diff))
        else:
            currentpath = Path(f"{currentpath}/group_vars/ras")
            file_list = os.listdir(currentpath)
            for filename in file_list:
                head, tail = os.path.split(filename)                
                if 'dst-' in tail:
                    changed_files.append(os.path.join(currentpath,filename))
        if len(changed_files) == 0 and 'release' not in repo.active_branch.name:
            frameinfo = getframeinfo(currentframe())
            raise nofiles(frameinfo.lineno,'GIT FOUND FILES MODIFIED IN THE REPO BUT NONE OF THEM ARE DST FILES')
        logging.debug('Changes Files Compiled: ' + str(changed_files))
        return changed_files
    else:
        logging.warning('Repo not changed or already commited')
        frameinfo = getframeinfo(currentframe())
        raise nofiles(frameinfo.lineno,'GIT FOUND NO MODIFIED FILES IN THE REPO')

def dst_count_and_split(dst_data):
    logging.debug('DST Group Data: ' + json.dumps(dst_data, indent=4))
    logging.debug('DST Group Name: ' + str(list(dst_data.keys())[0])) 
    ## Identifying Group Name #####################################
    group_name = list(dst_data.keys())[0]
    print(colored('Validating Data for ' + group_name, 'yellow'))
    dstlength = 0 
    dst_customer_attr_length = 0
    currentdst_grp = 1
    fqdncount = 0
    dstgroups = {}
    dstgroups[group_name] = {}
    dstgroups[group_name]['dst_data'] = {}
    excluded_char = ['/','<','>','"','&','\'']
    ## Retriving DST Data #####################################
    if "-include" in group_name:
        logging.debug('Vaildating data for: ' + group_name)
        dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)] = list()
        logging.debug('DST DATA TO BE PROCESSED: ' + json.dumps(dst_data[group_name]['dst_data'], indent=4))
        for each in dst_data[group_name]['dst_data']:
            if any(character in each for character in excluded_char):
                raise excluded_char_exception(getframeinfo(currentframe()),each)
            AvlbChar = (421 - (dst_customer_attr_length + fqdncount))
            fqdnlength = len(each)
            logging.debug('Current Avalible Characters: ' + str(AvlbChar))
            dst_customer_attr_length = dst_customer_attr_length + fqdnlength
            dstlength = dstlength + (fqdnlength + 1)
            logging.debug('Total Group Character Length is ' + str(dstlength))
            ## Checking if total DST length is over 5000 Charcters  #####################################
            if dstlength > 5000:
                logging.debug('Character Length is ' + str(dstlength) + ' Rasing Error')
                frameinfo = getframeinfo(currentframe())
                raise tomanydst(dstlength,group_name,frameinfo.lineno) 
            urlitems = []
            logging.debug('FQDN to add is: ' + each + ' | FQDN Length inc \',\' is: ' + str(fqdnlength))
            ## Checking when to split command so there less than 421 Chac
            # ters  #####################################
            if (fqdnlength) < AvlbChar:
                logging.debug('Number of Current Added FQDN: ' + str(fqdncount) + ' | Avalible Characters after adding FQDN is: ' + str(AvlbChar - fqdnlength)  + ' | Adding FQDN ' + each + ' to ' + group_name + ' group ' + str(currentdst_grp))
                dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)].append(each)
                fqdncount = (len(dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)]))
                logging.debug('Current List is: ' + str(dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)]))
                logging.debug('=========================================================================================================================')
            else:
                currentdst_grp = currentdst_grp + 1
                logging.debug('Number of Current FQDN: ' + str(fqdncount) + ' | Avalible Characters after adding FQDN is: ' + str(AvlbChar - fqdnlength)  + ' | Need to Create New Group')
                logging.debug('Creating ' + group_name + ' Group ' + str(currentdst_grp))
                dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)] = list()
                AvlbChar = (421 - (fqdnlength))
                fqdncount = (len(dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)]))
                logging.debug('Number of Current Added FQDN: ' + str(fqdncount) + ' | Available Characters after adding FQDN is: ' + str(AvlbChar)  + ' | Adding FQDN ' + each + ' to ' + group_name + ' group ' + str(currentdst_grp))
                dst_customer_attr_length = fqdnlength + 1
                dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)].append(each)  
                logging.debug('Total FQDN Characters Used is: ' + str(dst_customer_attr_length))
                logging.debug('Current List is: ' + str(dstgroups[group_name]['dst_data']['dstGroup'+ str(currentdst_grp)]))    
                logging.debug('=========================================================================================================================')
    ## Updating DST with the data thats split into groups  #####################################
    dst_data[group_name]['dst_data'] = dstgroups[group_name]['dst_data']
    logging.debug('DATA TO BE SENT BACK: ' + json.dumps(dst_data[group_name], indent=4))
    return dst_data

def domain_vaildation(currentgroupdata,previousgroupdata,file,gitrepo,FileinMaster):
    dupdomain = set()
    currentdstdata = currentgroupdata['dst_data']    
    previousdstdata = previousgroupdata['dst_data']         
    if FileinMaster == True:
        if currentdstdata != previousdstdata or arg_items.sync == True :
            if (currentgroupdata['version'] == previousgroupdata['version'] and arg_items.sync != True):
                raise versionnotupdated(getframeinfo(currentframe()),'IN FILE ' + str(file) + ' DATA HAS BEEN UPDATED BUT THE VERSION HASN\'T, PLEASE CORRECT AND RE-RUN')            
            dupdomain = set([dupdomain for dupdomain in currentdstdata if currentdstdata.count(dupdomain) > 1])
            if len(dupdomain) > 0:
                raise domainalreadyexists(getframeinfo(currentframe()),'DOMAINS BELOW ARE POSSIBLE DUPLICATEs PLEASE CHECK FILE ' + str(file) + '\n\t' + '\n'.join(map(str, dupdomain)))
            previousdstdata = set(previousdstdata)
            currentdstdata = set(currentdstdata)
            removaldomains = previousdstdata.difference(currentdstdata)
            additiondomains = currentdstdata.difference(previousdstdata)
            domains = currentdstdata.symmetric_difference(previousdstdata)
            logging.debug('Removal Data Check ' + str(previousdstdata.difference(currentdstdata)))
        else:
            logging.warning('DST DATA HAS NOT BEEN UPDATED, CONFIM WITH DIFF OUTPUT ON ' + str(file))
            raise nodstchanges(getframeinfo(currentframe()),file,gitrepo)
    else:
        domains = [domain for domain,domaincount in Counter(previousdstdata).items() if domaincount == 1]
        domains = set(domains)
    if FileinMaster == True and len(additiondomains) > 0:
        print(colored('File \'' + str(os.path.basename(file)) + '\' has had the following domains added: \n\t' + 
        str('\n\t'.join(additiondomains)),'yellow'))
    if FileinMaster == False:
        print(colored('File \'' + str(os.path.basename(file)) + '\' is a new DST file and has been processed','yellow'))
    if FileinMaster == True and len(removaldomains) > 0:
        print(colored('File \'' + str(os.path.basename(file)) + '\' has had the following domains removed: \n\t' + 
            str('\n\t'.join(removaldomains)),'red'))                
        print(colored('#' * 70, 'blue'))
    logging.info('FILE : ' + str(file) + ' DATA HAS BEEN UPDATED')
    logging.info('FILE DIFFRENCES ARE ' + str(domains))
    logging.debug ('Previous DST List: ' + str(previousdstdata))
    
    for domain in domains:
        logging.debug('MATCHING SUBDOMAIN LIST IS: ' + str(subdomainlist))
        logging.debug ('CHECKING DOMAIN: ' + domain)
        check_domain = tldextract.extract(domain)
        logging.debug('TLD SPLIT IS: \n\
            SUBDOMAINS: ' + check_domain.subdomain + '\n\
            DOMAIN: ' + check_domain.domain + '\n\
            SUFFIX: ' + check_domain.suffix)
        check_tld = check_domain.registered_domain
        logging.debug ('TLD DOMAIN TO CHECK IS: ' + check_tld)                           
        if FileinMaster == True and len(removaldomains) == 0:
            if domain in previousdstdata:
                raise domainalreadyexists(getframeinfo(currentframe()),'Domain ' + domain + ' already exists in DST List' + str(file))
        if (domain != check_tld) and (check_tld in previousdstdata):
            logging.debug('APPENDING DOMAIN TO LIST')
            subdomainlist.append(domain)
                      

def dst_check(inventory,repo):
    changedfiles = changed_yamls(inventory,repo)
    if 'release' not in repo.active_branch.name and arg_items.sync == False:
        mastercommit = repo.heads.master.commit
        masterfilelist = []

        for path in mastercommit.tree.traverse():
            if path.type == 'blob':
                if 'dst-' in path.name:
                    masterfilelist.append(path.path)
        for file in changedfiles:
            filecheck = Path(file)
            if filecheck.is_file():
                headsha = repo.head.commit
                logging.info('GIT HASH IS:' + str(headsha))
                logging.debug("Hash Location is : " + str(headsha.tree.abspath))
                logging.debug("Master File List is :" + str(masterfilelist))
                updatedfile = file.replace(headsha.tree.abspath + '/',"")
                FileinMaster = updatedfile in masterfilelist   
                currentdata = load_yml(file)   
                logging.debug('CURRENT DATA IS: ' + json.dumps(currentdata, indent=4))
                group_name = list(currentdata.keys())[0]
                currentgroupdata = currentdata[group_name]
                if FileinMaster == True:
                    targetfile = headsha.tree / updatedfile                
                    previousdata = load_yml(targetfile.data_stream.read())
                    logging.debug('PREVIOUS DATA IS: ' + json.dumps(previousdata, indent=4))           
                    previousgroupdata = previousdata[group_name]
                    domain_vaildation(currentgroupdata,previousgroupdata,file,repo,FileinMaster)
                else:
                    previousgroupdata = currentdata[group_name]
                    domain_vaildation(currentgroupdata,previousgroupdata,file,repo,FileinMaster)
                if len(subdomainlist) > 0:
                    raise domainalreadyexists(getframeinfo(currentframe()),'Subdomain List:\n\t' + '\n\t'.join(subdomainlist) + '\nThe domains listed above will now be redundent, Please remove them from ' + str(file))
    return changedfiles


def output_to_file(yaml_data,file_name,file_location):
    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    logging.debug('WRITING YAML TO FILE: ' + str(file_location.format(file_name)))
    yaml_file = open(file_location + '{}'.format(file_name), 'w')
    yaml.dump(yaml_data, yaml_file)
    yaml_file.close()
    print(colored('Producing file ' + file_location + '{}'.format(file_name) + ' for: ' + str(list(yaml_data.keys())[0]), 'yellow'))

################################ Main Module, this requires the inventory parameter to be set (done via -l in the command) #####################################
def main(inventory):

    try:

        ####### ############################################################## STAGE 3 #####################################################################
        yaml = ruamel.yaml.YAML()
        yaml.default_flow_style = False
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True
        print(colored('#' * 70, 'blue'))
        print(colored('RAS DST Validator', 'yellow'))
        print(colored('#' * 70, 'blue'))
        repo = git.Repo(inventory, search_parent_directories=True)
        logging.debug('CHECKING / ON END OF INVENTORY')
        if inventory[-1] != '/':
            inventory = inventory + '/'
        logging.debug('Inventory Location ' + str(inventory))
        changed_files = dst_check(inventory,repo)
        logging.debug(json.dumps(changed_files, indent=4))
        updateddst = []
        for updated_file in changed_files:
            filecheck = Path(updated_file)
            if filecheck.is_file():
                head, tail = os.path.split(updated_file)
                data_items = load_yml(updated_file)
                group_name = list(data_items.keys())[0]
                data_items[group_name]['dst_data'] = sorted(data_items[group_name]['dst_data'])
                if 'release/' not in repo.active_branch.name:
                    output_to_file(data_items,tail,inventory + 'group_vars/ras/')
                logging.debug(json.dumps(data_items))
                final_dst = dst_count_and_split(data_items)
                output_to_file(final_dst,tail,'/gitnet/ras-processed/data/ansible-data-')
                logging.debug('Groups Name: ' + str(group_name))
                updateddst.append(group_name)
        print(colored('#' * 70, 'blue'))
        print(colored('All Data Validated.' + '\n' +
        'Data files produced for ansible are located in /gitnet/ras-processed/data', 'yellow'))
        print(colored('#' * 70, 'blue'))
    except Exception as err:
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            logging.basicConfig(filename=pypath + '/log/ras_dst_constructor.log', filemode='a',
                        format='%(asctime)-15s : LINE # ' + str(err.__traceback__.tb_lineno) + ': %(name)s : %(levelname)s : %(message)s' + 'TRACEBACK '  + str(traceback.print_exc()), level=loglevel)

        return sys.exit(1)

if __name__ == "__main__":
    main(arg_items.inventory)
