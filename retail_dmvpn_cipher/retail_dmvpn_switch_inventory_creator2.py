import csv
import re
import jinja2

file = csv.reader(open('./dmvpn_sites3.csv'), delimiter=',')


templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "retailswitchinv.j2"
template = templateEnv.get_template(TEMPLATE_FILE)
outputText = template.render(file = file)  # this is where to put args to the template renderer

inv_file = open("retail_dmvpn_switch_hosts_with_concentrators.yaml", "w")
inv_file.write(outputText)