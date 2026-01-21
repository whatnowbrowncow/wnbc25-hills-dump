import re
import jinja2
import json

data_dict = {
    "dfw" : {"json":"./outputs/dfws.json", "csv":"mrg_sddc_dfw.csv", "data":"dfw_rules"},
    "mgw" : {"json":"./outputs/mgwfw.json", "csv":"mrg_sddc_mgfw.csv", "data":"mgwfw_rules"},
    "cgw" : {"json":"./outputs/cgwfw.json", "csv":"mrg_sddc_cgfw.csv", "data":"cgwfw_rules"}}

with open('./outputs/dfws.json') as json_file: 
    dfw_rules=json.load(json_file)

with open('./outputs/mgwfw.json') as json_file: 
    mgwfw_rules=json.load(json_file)

with open('./outputs/cgwfw.json') as json_file: 
    cgwfw_rules=json.load(json_file)

with open('./outputs/groups.json') as json_file: 
    groups=json.load(json_file)

with open('./outputs/services.json') as json_file: 
    service_objects=json.load(json_file)

asa_groups={}



for section in dfw_rules.keys():
    for rule in dfw_rules[section]['rules']:
        for group in dfw_rules[section]['rules'][rule]['Source(s)']:
            if group not in asa_groups.keys():
                asa_groups[group]=[]
                for ip in dfw_rules[section]['rules'][rule]['Source(s)'][group]:
                    asa_groups[group].append(ip)
            else:
                print(str(group+" is already used in the rulebase, skipping"))
        for group in dfw_rules[section]['rules'][rule]['Destination(s)']:
            if group not in asa_groups.keys():
                asa_groups[group]=[]
                for ip in dfw_rules[section]['rules'][rule]['Destination(s)'][group]:
                    asa_groups[group].append(ip)
            else:
                print(str(group+" is already used in the rulebase, skipping"))

group_config = []

for group in asa_groups:
    group_config.append(str("object-group network "+group))
    for ip in asa_groups[group]:
        group_config.append(str(" network-object host "+ip))



asa_service_groups={}
for service in service_objects.keys():
    if service not in asa_service_groups.keys():
        asa_service_groups[service]=[]
        for port in service_objects[service]["ports"]:
            try:
                splitport = re.match("(TCP|UDP)\/(\d+-\d+|\d+)",port)
                protocol = splitport.groups(1)[0]
                number = splitport.groups(1)[1]
                print(str(service+": protocol="+protocol+" : number="+number))
                asa_service_groups[service].append(port)
            except:
                asa_service_groups[service].append(port)
                print(str(port+"-regex fail######################################################"))

    else:
        print(str(service+" is already used in the rulebase, skipping########################################################"))

service_config=[]
for group in asa_service_groups:
    service_config.append(str("object-group service "+group))
    for port in asa_service_groups[group]:
            print(port)
            try:
                splitport = re.match("(TCP|UDP)\/(\d+-\d+|\d+)",port)
                protocol = splitport.groups(1)[0]
                number = splitport.groups(1)[1]
                print(str("service "+protocol+" destination eq "+number))
                service_config.append(str(" service "+protocol+" destination eq "+number))
            except Exception as e:
                print(Exception)
                continue




filepath1 = './outputs/asa_groups.json'
with open(filepath1, "w") as outfile: 
    json.dump(asa_groups, outfile)


filepath2 = './outputs/asa_services.json'
with open(filepath2, "w") as outfile: 
    json.dump(asa_service_groups, outfile)


templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = group_config)  # this is where to put args to the template renderer
file = "asa_group_config.txt"
csv_file = open(file, "w")
csv_file.write(outputText)


templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = service_config)  # this is where to put args to the template renderer
file = "asa_service_config.txt"
csv_file = open(file, "w")
csv_file.write(outputText)

exit()





dfw_order = ("Intra Segment","Temp","Rulebase","SDDC_Specific")

dfw_rules_ordered={}
for section in dfw_order:
    dfw_rules_ordered[section] = dfw_rules[section]




templateLoader = jinja2.FileSystemLoader(searchpath="./")
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

