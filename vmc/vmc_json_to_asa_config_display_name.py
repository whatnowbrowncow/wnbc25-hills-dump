import re
import jinja2
import json
from netaddr import IPNetwork, IPAddress

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

#len(dict.keys())

for section in dfw_rules.keys():
    for rule in dfw_rules[section]['rules']:
        for group in dfw_rules[section]['rules'][rule]['Source(s)']:
            if group not in asa_groups.keys():
                if group == "ANY":
                    asa_groups[group]=["ANY"]
                else:
                    try:
                        group_members=[]
                        asa_groups[groups[group]['display name']]=[]
                        for ip in dfw_rules[section]['rules'][rule]['Source(s)'][group]:
                            if ip not in group_members:
                                asa_groups[groups[group]['display name']].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(groups[group]['display name'])+"), skipping"))
                    except:
                        group_members=[]
                        asa_groups[group]=[]
                        for ip in dfw_rules[section]['rules'][rule]['Source(s)'][group]:
                            if ip not in group_members:
                                asa_groups[group].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(group)+"), skipping"))
            else:
                print(str(group+" is already used in the rulebase, skipping"))
        for group in dfw_rules[section]['rules'][rule]['Destination(s)']:
            if group not in asa_groups.keys():
                if group == "ANY":
                    asa_groups[group]=["ANY"]
                else:
                    try:
                        group_members=[]
                        asa_groups[groups[group]['display name']]=[]
                        for ip in dfw_rules[section]['rules'][rule]['Destination(s)'][group]:
                            if ip not in group_members:
                                asa_groups[groups[group]['display name']].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(groups[group]['display name'])+"), skipping"))

                    except:
                        group_members=[]
                        asa_groups[group]=[]
                        for ip in dfw_rules[section]['rules'][rule]['Destination(s)'][group]:
                            if ip not in group_members:
                                asa_groups[group].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(group)+"), skipping"))

            else:
                print(str(group+" is already used in the rulebase, skipping"))
special_characters = [",","/","&","\*","\(","\)"]
group_config = []

for group in asa_groups:
    newgroup = re.sub(" ","_",group)
    for char in special_characters:
        if char in newgroup:
            newgroup = re.sub(char,"",newgroup)
    group_config.append(str("object-group network "+newgroup))
    for ip in asa_groups[group]:
        if '/' in str(ip):
            ipn = IPNetwork(ip)
            group_config.append(str(" network "+str(ipn.ip)+" "+str(ipn.netmask)))
        else:
            group_config.append(str(" network-object host "+ip))
    group_config.append("exit")


asa_service_groups={}
for service in service_objects.keys():
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
#special_characters = [",","/","&","\*","\(","\)"]
service_config=[]
for group in asa_service_groups:
    newgroup = re.sub(" ","_",group)
    for char in special_characters:
        if char in newgroup:
            newgroup = re.sub(char,"",newgroup)
    service_config.append(str("object-group service "+newgroup))
    for port in asa_service_groups[group]:
            #print(port)
            try:
                splitport = re.match("(TCP|UDP)\/(\d+-\d+|\d+)",port)
                protocol = splitport.groups(1)[0]
                number = splitport.groups(1)[1]
                if "-" in number:
                    #print(str("service "+protocol+" destination range "+re.sub("-"," ",number)))
                    service_config.append(str(" service "+protocol+" destination range "+re.sub("-"," ",number)))
                else:
                    #print(str("service "+protocol+" destination eq "+number))
                    service_config.append(str(" service "+protocol+" destination eq "+number))
            except Exception as e:
                print(e)
                continue
    service_config.append("exit")
asa_rules = []
acl_start = "access-list global_access extended "
acl_end = " log"
obj = " object-group "
for section in dfw_rules.keys():
    for rule in dfw_rules[section]['rules']:
        if len(list(dfw_rules[section]['rules'][rule]['Source(s)'])) == 1 and len(list(dfw_rules[section]['rules'][rule]['Destination(s)'])) == 1 and len(list(dfw_rules[section]['rules'][rule]['Service(s)'])) == 1:
            if dfw_rules[section]['rules'][rule]['Action'].lower() == "allow":
                action = "permit"
            elif dfw_rules[section]['rules'][rule]['Action'].lower() == "drop":
                action = "deny"
            if dfw_rules[section]['rules'][rule]['Service(s)'][list(dfw_rules[section]['rules'][rule]['Service(s)'])[0]] == "ANY":
                svc = "ip"
            else:
                svc = re.sub(" ","_",service_objects[list(dfw_rules[section]['rules'][rule]['Service(s)'])[0]]['display name'])
                for char in special_characters:
                    if char in svc:
                        svc = re.sub(str(char),"",svc)

            if next(iter(dfw_rules[section]['rules'][rule]['Source(s)'])) == "ANY":
                src = "any"
            else:
                src = re.sub(" ","_",groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name'])
                for char in special_characters:
                    if char in src:
                        src = re.sub(str(char),"",src)
                #src = groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']
            if next(iter(dfw_rules[section]['rules'][rule]['Destination(s)'])) == "ANY":
                dst = "any"
            else:
                dst = re.sub(" ","_",groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name'])
                for char in special_characters:
                    if char in dst:
                        dst = re.sub(str(char),"",dst)
                dst = groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name']
            ace = acl_start+action+obj+svc+obj+src+obj+dst+acl_end
            ace = re.sub("object-group ip","ip",ace)
            ace = re.sub("object-group any","any",ace)
            ace = re.sub("object-group migrated_icmp-any","icmp",ace)
            ace = re.sub("object-group migrated_tcp-any","tcp",ace)
            ace = re.sub("object-group migrated_udp-any","udp",ace)
            asa_rules.append(ace)
            #print(acl_start+action+obj+svc+obj+src+obj+dst+acl_end)
        else:
            if dfw_rules[section]['rules'][rule]['Action'].lower() == "allow":
                action = "permit"
            elif dfw_rules[section]['rules'][rule]['Action'].lower() == "drop":
                action = "deny"
            vars = {'Source(s)':len(list(dfw_rules[section]['rules'][rule]['Source(s)'])),'Destination(s)':len(list(dfw_rules[section]['rules'][rule]['Destination(s)'])),'Service(s)':len(list(dfw_rules[section]['rules'][rule]['Service(s)']))}
            ordered_vars =[]
            for l in sorted(vars, key=lambda l: vars[l], reverse=True):
                ordered_vars.append(l)
            print(section)
            print(rule)
            print(vars)
            print(ordered_vars)
            print(len(dfw_rules[section]['rules'][rule][str(ordered_vars[0])]))
            for x in (dfw_rules[section]['rules'][rule][str(ordered_vars[0])]):
                for y in (dfw_rules[section]['rules'][rule][str(ordered_vars[1])]):
                    for z in (dfw_rules[section]['rules'][rule][str(ordered_vars[2])]):
                        dic={}
                        if dfw_rules[section]['rules'][rule][str(ordered_vars[0])][x] == "ANY":
                            dic[str(ordered_vars[0])] = "any"
                        else:
                            dic[str(ordered_vars[0])] = x
                        if dfw_rules[section]['rules'][rule][str(ordered_vars[1])][y] == "ANY":
                            dic[str(ordered_vars[1])] = "any"
                        else:
                            dic[str(ordered_vars[1])] = y
                        if dfw_rules[section]['rules'][rule][str(ordered_vars[2])][z] == "ANY":
                            dic[str(ordered_vars[2])] = "any"
                        else:
                            dic[str(ordered_vars[2])] = z
                        #    svc = service_objects[x]['display name']
            
                        #if next(iter(dfw_rules[section]['rules'][rule]['Source(s)'])) == "ANY":
                        #    src = "any"
                        #else:
                        #    src = groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']
                        #if next(iter(dfw_rules[section]['rules'][rule]['Destination(s)'])) == "ANY":
                        #    dst = "any"
                        #else:
                        #    dst = groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name']
                        if dic["Service(s)"] == "any":
                            svc = "ip"
                        else:
                            svc = service_objects[dic["Service(s)"]]['display name']
                            svc = re.sub(" ","_",svc)
                            for char in special_characters:
                                if char in svc:
                                    svc = re.sub(str(char),"",svc)
            
                        if dic["Source(s)"] == "any":
                            src = "any"
                        else:
                            src = groups[dic["Source(s)"]]['display name']
                            src = re.sub(" ","_",src)
                            for char in special_characters:
                                if char in src:
                                    src = re.sub(str(char),"",src)
                        if dic["Destination(s)"] == "any":
                            dst = "any"
                        elif dic["Destination(s)"] == "/infra/tier-0s/vmc/groups/connected_vpc":
                            dst = "?????Cant find this Group?????"
                        elif dic["Destination(s)"] == "/infra/tier-0s/vmc/groups/s3_prefixes":
                            dst = "?????Cant find this Group?????"
                        else:
                            dst = groups[dic["Destination(s)"]]['display name']
                            dst = re.sub(" ","_",dst)
                            for char in special_characters:
                                if char in dst:
                                    dst = re.sub(str(char),"",dst)

                        ace = acl_start+action+obj+svc+obj+src+obj+dst+acl_end
                        ace = re.sub("object-group ip","ip",ace)
                        ace = re.sub("object-group any","any",ace)
                        ace = re.sub("object-group migrated_icmp-any","icmp",ace)
                        ace = re.sub("object-group migrated_tcp-any","tcp",ace)
                        ace = re.sub("object-group migrated_udp-any","udp",ace)
                        asa_rules.append(ace)
                        #print(acl_start+action+obj+svc+obj+src+obj+dst+acl_end)
            print("-------------------------------------------------------------------------")

                            #flows.append({ordered_vars[0]:vars[ordered_vars[0]][w],ordered_vars[1]:vars[ordered_vars[1]][x],ordered_vars[2]:vars[ordered_vars[2]][y],ordered_vars[3]:vars[ordered_vars[3]][z]})
#                   print(flows)

            

filepath1 = './outputs/asa_groupsnew.json'
with open(filepath1, "w") as outfile: 
    json.dump(asa_groups, outfile)


filepath2 = './outputs/asa_servicesnew.json'
with open(filepath2, "w") as outfile: 
    json.dump(asa_service_groups, outfile)

filepath3 = './outputs/asa_dfw_rule_snew.json'
with open(filepath3, "w") as outfile: 
    json.dump(asa_rules, outfile)


templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = group_config)  # this is where to put args to the template renderer
file = "asa_group_config_new.txt"
csv_file = open(file, "w")
csv_file.write(outputText)


templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = asa_rules)  # this is where to put args to the template renderer
file = "asa_dfw_rules_new.txt"
csv_file = open(file, "w")
csv_file.write(outputText)

templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = service_config)  # this is where to put args to the template renderer
file = "asa_service_config_new.txt"
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

