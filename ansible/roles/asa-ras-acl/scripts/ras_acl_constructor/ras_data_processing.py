import logging
import ruamel.yaml
import re
import os
import json
from termcolor import colored
import traceback
import sys
import git


sys.setrecursionlimit(9999999)

################################ Defining working paths, both the path the python code is located and the current working path #####################################
pypath = os.path.dirname(os.path.abspath(__file__))

## Converts file/acl name to acl key
def yml_key(acl):
    if re.match('.*/.*yml',acl):
        head,file = os.path.split(acl)
        key = file[:-4]
    else:
        key = acl
    return re.sub('\-', '_', key)

## Allow retriving of data from YAML file
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


## Take Each Child/Parent set of Rules and adds them to the dict to create combined dicts
def combine_rules(acl, dependent_acl_name,acl_data, inventory):
#    print(colored('#' * 70, 'blue'))
    acl_yaml_data = acl_data[acl]
    logging.debug('ACL DATA: ' + json.dumps(acl_yaml_data, indent=4))
## Obtains key and rules of ACL
    acl_yaml_acl_key = yml_key(acl)
    acl_rules = acl_yaml_data[acl_yaml_acl_key][0]['rules']
## Obtains all hierarchy data of ACL
    hierarchy_data = acl_data[dependent_acl_name]
    logging.debug('CHILD DATA: ' + json.dumps(hierarchy_data, indent=4))
    hierarchy_acl_key = yml_key(dependent_acl_name)
    child_rules = hierarchy_data[hierarchy_acl_key][0]['rules']
    #lineagedata= []
    lineagedata = child_rules
    for acl_lineage in acl_data[dependent_acl_name]['hierarchy']['lineage']:
        logging.debug('LINEAGE INFORMATION: ' + json.dumps(acl_data[acl_lineage]['hierarchy']['lineage'],indent=4))
        logging.debug('LINEAGE DATA TO ADD: ' + 'ADDING ACL: ' + acl_lineage + ' TO ACL: ' + dependent_acl_name )
        lineagedata =  acl_data[acl_lineage][acl_lineage.replace('-','_')][0]['rules'] + lineagedata
        logging.debug('COMBINED LINEAGE DATA ' + json.dumps(lineagedata))
    hierarchy_data[hierarchy_acl_key][0]['rules'] = lineagedata
    combined_data = hierarchy_data
    logging.debug('RULES COMBINED: ' + json.dumps(combined_data,indent=4))
## Pass Data back to calling module
    return combined_data

# Takes data created in combine_rules and adds the final rules on 
def append_final_yaml(changed_acl,yaml_data,yml_path,inventory,repository,arg_items):
    logging.debug('OBTAINED YML KEY DATA')    
## Obtaining key from acl
    yaml_acl_key = yml_key(yml_path)
    logging.debug('OBTAINED FINAL RULES DATA')    
# Retriving Final Rules from YML
    final_yml = load_yml(inventory + 'group_vars/ras/ras-final-rules.yml')
    logging.debug('ADDING FINAL RULES DATA - DATA TO IMPORT ' +
        json.dumps(yaml_data[yaml_acl_key],indent=4) + '\n' +
         'FINAL RULES TO IMPORT: ' + '\n' + 
         json.dumps(final_yml['final_rules'],indent=4))
    if 'release/' not in repository.active_branch.name and arg_items.sync != True:
       print(colored('Adding final rules to acl ', 'yellow') )#+ colored(yml_path, 'red'))
       logging.debug('ACL DATA TO ADD THE FINAL RULES TO: ' + json.dumps(yaml_data, indent=4))
    else:
        print(colored('Re-Generating ', 'yellow') + colored(yml_path, 'red') + colored(' Ansible Data Files', 'yellow'))
## Adding Final Rules to existing data
    yaml_data[yaml_acl_key][0]['rules'] = yaml_data[yaml_acl_key][0]['rules'] + final_yml['final_rules']
    logging.debug('ACL DATA WITH FINAL RULES: ' + json.dumps(yaml_data, indent=4))
    if 'release/' not in repository.active_branch.name and arg_items.sync != True:
        print(colored('Renumbering acl ', 'yellow') + colored(yml_path, 'red'))
        renumbered_rules = rules_renumber(yaml_data[yaml_acl_key][0]['rules'],1)
        logging.debug('ACL DATA RENUMBERED: ' + json.dumps(yaml_data, indent=4))
## Replacing All Rules within ACL Data with final renumbered data
        yaml_data[yaml_acl_key][0]['rules'] = renumbered_rules
## Update Version number within the ACL Data
    if changed_acl not in yaml_data[yaml_acl_key][0]['name'] and 'release/' not in repository.active_branch.name and arg_items.sync != True:
        yaml_data[yaml_acl_key][0]['version'] = yaml_data[yaml_acl_key][0]['version'] + 1
## Pass Data back to calling module
    return yaml_data

## Renumbered all rules pass to module starting with one where line_no key exisits then pass data back
def rules_renumber(yaml_data,line_no):


    for rule in yaml_data:
        line_no = str(line_no)
        rule['line_no'] = line_no
        line_no = int(line_no) + 1
    return yaml_data

## Create updated yaml data for RAS role to process and update User editored RAS YAMLs with new version number
def output_to_data_file(yaml_data,yml_path,full_data,repository,arg_items):
## Set YAML Formating
    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    logging.debug('YAML DATA PASSED TO MODULE output_to_data_file: ' + json.dumps(yaml_data, indent=3))
## Retrieve Directory and file name of ACL
    dir_name, file_name = os.path.split(yml_path)
    logging.debug('ACL FILE NAME TO WRITE TO: ' + str(file_name))
## Create new file for data to be processed by RAS Role
    yaml_file = open('/gitnet/ras-processed/data/ansible-data-{}'.format(file_name), 'w')
    logging.debug('FILE OPENED: ' + str(yaml_file))
    yaml.dump(yaml_data, yaml_file)
    yaml_file.close()
    if 'release/' not in repository.active_branch.name and arg_items.sync != True:
        logging.info('Processed Data File - Starting Updating version')
    ## Load in User created YAML file 
        final_yaml_file = load_yml(yml_path)
        print(colored('Writing  data file ', 'yellow'), colored(yaml_file.name,'red'))
        logging.debug('Final Data Output' + json.dumps(final_yaml_file))
    ## Retrieve Key for ACL
        final_yaml_key = yml_key(yml_path)
        logging.debug ('FINAL YML KEY ' + str(final_yaml_key))
    ## Retrieve Parent Information
        logging.debug('FINAL YAMLS PARENT: ' + json.dumps(final_yaml_file[final_yaml_key][0]['parents']))
        if (final_yaml_file[final_yaml_key][0]['parents']) is not None:
            yaml_parent_acl = final_yaml_file[final_yaml_key][0]['parents'][0]
            full_data_parent_key = yml_key(str(yaml_parent_acl))
            first_line_rules = full_data[yaml_parent_acl][full_data_parent_key][0]['rules']
            first_line_no = str(int(first_line_rules[-1]['line_no'])+1)
        else:
            first_line_no = "1"
        logging.debug('FIRST LINE NUMBER FOR ACL ' + final_yaml_file[final_yaml_key][0]['name'] + ' : ' + str(first_line_no))
        final_yaml_file[final_yaml_key][0]['rules'] = rules_renumber(final_yaml_file[final_yaml_key][0]['rules'],first_line_no)
        ## Update Version in USER Created ACL data from version within processed ACLs and renumber
        final_yaml_file[final_yaml_key][0]['version'] = yaml_data[final_yaml_key][0]['version']
    ## Write Updated Version back to file
        final_yaml_output = open(yml_path,'w')
        yaml.dump(final_yaml_file, final_yaml_output)
        logging.info('Processed YML File - Renumbered' )
        print(colored('Renumbered YML file ','yellow'),colored(str(yml_path),'red'))
        #print(colored('#' * 70, 'blue'))


##################################################################### STAGE 4 #####################################################################
def processing(changed_acl,acl_data,acl_hierarchy,inventory,loglevel,repository,arg_items_values):
####################################### Stage 4 #######################################
## Try process first and if fail call exception to screen
    try:
        ################################ Defining logging output and file location #####################################
        logging.basicConfig(filename=pypath + '/log/ras_acl_constructor.log', filemode='a',
                            format='%(asctime)-15s : Line # %(lineno)d : %(levelname)s : %(message)s', level=loglevel)

        logging.debug('ACL_HIERARCHY: ' + json.dumps(acl_hierarchy, indent=3))
        logging.debug('ACL: ' + str(changed_acl) )
## Add ACL to Hieaclay List
        acl_hierarchy.append(changed_acl)
## For Each ACL in hierarchy, retrieve file path, call combine rules module, renumber and write RAS data file, Then update version in ACL and write back to file
        for dependent_acl_name in acl_hierarchy:
            yml_path = inventory + 'group_vars/ras/' + dependent_acl_name + '.yml'
            logging.debug('PROCESSING DEPENDENT (CHILD) ACL NAME: ' + dependent_acl_name)
            acl_yaml = combine_rules(changed_acl, dependent_acl_name,acl_data,inventory)
            full_data = append_final_yaml(changed_acl,acl_yaml,dependent_acl_name,inventory,repository,arg_items_values)
            output_to_data_file(full_data,yml_path,acl_data,repository,arg_items_values)
     

## Outputing infomration if error has occured including File, Line Number Message and any additional infomation
    except Exception as err:
        err_msg = traceback.format_exc()
        print(colored('#' * 83, 'red'))
        print(colored('#' * 39 + ' ERROR ' + '#' * 37, 'red'))
        print(colored('SEE LOG ' + str(pypath) + '/log/ras_acl_constructor.log FOR FULL DETAILS' + '\n' +
            'ERROR IN FILE: ' + str(os.path.abspath(__file__)) + '\n' +
            'ERROR LINE: ' + str(err.__traceback__.tb_lineno) + '\n' +
            'ERROR MESSAGE: ' + str(err), 'red'))
        print(colored('#' * 83, 'red'))
        return sys.exit(1)







