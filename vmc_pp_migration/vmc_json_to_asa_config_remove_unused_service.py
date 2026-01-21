import re
import jinja2
import json

with open('/dbdev/vmc_pp_migration/outputs/services.json') as json_file: 
    service_objects=json.load(json_file)

with open('/dbdev/vmc_pp_migration/outputs/asa_services_dedupe_object_final.json') as json_file: 
    deduped_service_objects=json.load(json_file)

asa_groups={}

#len(dict.keys())


special_characters = [",","/","&","\*","\(","\)"]





asa_service_groups={}
for service in service_objects.keys():
    if service_objects[service]['display name'] not in deduped_service_objects.keys():
        if service not in asa_service_groups.keys():
            group_members=[]
            asa_service_groups[service_objects[service]['display name']]=[]
            for port in service_objects[service]["ports"]:
                try:
                    if port not in group_members:
                        splitport = re.match("(TCP|UDP)\/(\d+-\d+|\d+)",port)
                        protocol = splitport.groups(1)[0]
                        number = splitport.groups(1)[1]
                        #print(str(service+": protocol="+protocol+" : number="+number))
                        asa_service_groups[service_objects[service]['display name']].append(port)
                        group_members.append(port)
                    else:
                        print(str(port+" already in this group ("+str(service_objects[service]['display name'])+"), skipping"))
    
                except:
                    if port not in group_members:
                        asa_service_groups[service_objects[service]['display name']].append(port)
                        group_members.append(port)
                    else:
                        print(str(port+" already in this group ("+str(service_objects[service]['display name'])+"), skipping"))
    
                    #print(str(port+"-regex fail######################################################"))
    
        else:
            print(str(service+" is already used in the rulebase, skipping########################################################"))
    else:
        print(str(service+" is in use on the FW, skipping########################################################"))
#special_characters = [",","/","&","\*","\(","\)"]
service_config_remove=[]
for group in asa_service_groups:
    newgroup = re.sub(" ","_",group)
    for char in special_characters:
        if char in newgroup:
            newgroup = re.sub(char,"",newgroup)
    service_config_remove.append(str("no object-group service "+newgroup))




            



filepath2 = '/dbdev/vmc_pp_migration/outputs/asa_services_remove_unused_objects.json'
with open(filepath2, "w") as outfile: 
    json.dump(asa_service_groups, outfile)










templateLoader = jinja2.FileSystemLoader(searchpath="/dbdev/vmc_pp_migration/")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = service_config_remove)  # this is where to put args to the template renderer
file = "asa_service_config_remove.txt"
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

