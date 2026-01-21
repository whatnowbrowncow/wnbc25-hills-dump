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

