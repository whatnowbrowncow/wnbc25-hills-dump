import re
import jinja2
import json

with open('/dbdev/vmc_pp_migration/outputs/groups.json') as json_file: 
    group_objects=json.load(json_file)

with open('/dbdev/vmc_pp_migration/outputs/asa_groups_dedupe_object_final.json') as json_file: 
    deduped_group_objects=json.load(json_file)

asa_groups={}

#len(dict.keys())


special_characters = [",","/","&","\*","\(","\)"]





asa_object_groups={}
for object in group_objects.keys():
    if group_objects[object]['display name'] not in deduped_group_objects.keys():
        if object not in asa_object_groups.keys():
            group_members=[]
            asa_object_groups[group_objects[object]['display name']]=[]

object_config_remove=[]
for group in asa_object_groups:
    newgroup = re.sub(" ","_",group)
    for char in special_characters:
        if char in newgroup:
            newgroup = re.sub(char,"",newgroup)
    object_config_remove.append(str("no object-group network "+newgroup))




            



filepath2 = '/dbdev/vmc_pp_migration/outputs/asa_objects_remove_unused_objects.json'
with open(filepath2, "w") as outfile: 
    json.dump(asa_object_groups, outfile)










templateLoader = jinja2.FileSystemLoader(searchpath="/dbdev/vmc_pp_migration/")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = object_config_remove)  # this is where to put args to the template renderer
file = "asa_object_config_remove.txt"
csv_file = open(file, "w")
csv_file.write(outputText)

exit()





dfw_order = ("Intra Segment","Temp","Rulebase","SDDC_Specific")

dfw_rules_ordered={}
for section in dfw_order:
    dfw_rules_ordered[section] = dfw_rules[section]




templateLoader = jinja2.FileSystemLoader(searchpath="/dbdev/vmc_pp_migration/")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "dfw_json_to_csv.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = dfw_rules_ordered)  # this is where to put args to the template renderer
file = "mrg_sddc_dfw.csv"
csv_file = open(file, "w")
csv_file.write(outputText)

TEMPLATE_FILE = "gw_json_to_csv.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = mgwfw_rules)  # this is where to put args to the template renderer
file = "mrg_sddc_mgwfw.csv"
csv_file = open(file, "w")
csv_file.write(outputText)

outputText = template.render(data = cgwfw_rules)  # this is where to put args to the template renderer
file = "mrg_sddc_cgwfw.csv"
csv_file = open(file, "w")
csv_file.write(outputText)

