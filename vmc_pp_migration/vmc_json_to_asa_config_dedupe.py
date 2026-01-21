import re
import jinja2
import json
from netaddr import IPNetwork, IPAddress

data_dict = {
    "dfw" : {"json":"/dbdev/vmc_pp_migration/outputs/dfws.json", "csv":"mrg_sddc_dfw.csv", "data":"dfw_rules"},
    "mgw" : {"json":"/dbdev/vmc_pp_migration/outputs/mgwfw.json", "csv":"mrg_sddc_mgfw.csv", "data":"mgwfw_rules"},
    "cgw" : {"json":"/dbdev/vmc_pp_migration/outputs/cgwfw.json", "csv":"mrg_sddc_cgfw.csv", "data":"cgwfw_rules"}}

with open('/dbdev/vmc_pp_migration/outputs/dfws.json') as json_file: 
    dfw_rules=json.load(json_file)

with open('/dbdev/vmc_pp_migration/outputs/mgwfw.json') as json_file: 
    mgwfw_rules=json.load(json_file)

with open('/dbdev/vmc_pp_migration/outputs/cgwfw.json') as json_file: 
    cgwfw_rules=json.load(json_file)

with open('/dbdev/vmc_pp_migration/outputs/groups.json') as json_file: 
    groups=json.load(json_file)

with open('/dbdev/vmc_pp_migration/outputs/services.json') as json_file: 
    service_objects=json.load(json_file)

deduped_services = {}

asa_service_groups={}
for service in service_objects.keys():
    dupe_match = False
    if service not in asa_service_groups.keys():
        group_members=[]
        asa_service_groups[service_objects[service]['display name']]={}
        asa_service_groups[service_objects[service]['display name']]["group_members"]=[]
        
        for port in service_objects[service]["ports"]:

            try:
                if port not in group_members:
                    splitport = re.match("(TCP|UDP)\/(\d+-\d+|\d+)",port)
                    protocol = splitport.groups(1)[0]
                    number = splitport.groups(1)[1]
                    #print(str(service+": protocol="+protocol+" : number="+number))
                    asa_service_groups[service_objects[service]['display name']]["group_members"].append(port)
                    group_members.append(port)
                else:
                    print(str(port+" already in this group ("+str(service_objects[service]['display name'])+"), skipping"))

            except:
                if port not in group_members:
                    asa_service_groups[service_objects[service]['display name']]["group_members"].append(port)
                    group_members.append(port)
                else:
                    print(str(port+" already in this group ("+str(service_objects[service]['display name'])+"), skipping"))

                #print(str(port+"-regex fail######################################################"))
        for grp in deduped_services:
            if deduped_services[grp]["grp_members"] == group_members:
                #print("Found a service group :{}: that already contains the same members, skipping service group: {}".format(grp,service))
                asa_service_groups[service_objects[service]['display name']]["dedupe_master"]=grp
                dupe_match = True
                break
        if dupe_match == False:
            deduped_services[service_objects[service]['display name']]={}
            deduped_services[service_objects[service]['display name']]["grp_members"]=[]
            for svc in group_members:
                deduped_services[service_objects[service]['display name']]["grp_members"].append(svc)
            asa_service_groups[service_objects[service]['display name']]["dedupe_master"]=service_objects[service]['display name']



    else:
        print(str(service+" is already used in the rulebase, skipping########################################################"))


#exit()

asa_groups={}
deduped_groups = {}
deduped_groups["ANY"]={}
deduped_groups["ANY"]["grp_members"]=["ANY"]
#len(dict.keys())
rules_to_pop = []
for section in dfw_rules.keys(): 
    for rule in dfw_rules[section]['rules']:
        dfw_rules[section]['rules'][rule]["skip"] = False
        for group in dfw_rules[section]['rules'][rule]['Source(s)']:
            dupe_match = False
            if group not in asa_groups.keys():
                if group == "ANY":
                    group_members=["ANY"]
                    asa_groups["ANY"]={}
                    asa_groups["ANY"]["group_members"]=["ANY"]
                    asa_groups["ANY"]["dedupe_master"]=["ANY"]
                else:
                    try:
                        group_members=[]
                        asa_groups[groups[group]['display name']]={}
                        asa_groups[groups[group]['display name']]["group_members"] = []
                        for ip in dfw_rules[section]['rules'][rule]['Source(s)'][group]:
                            if ip == "cannot process - skip":
                                dfw_rules[section]['rules'][rule]["skip"] = True
                            if ip not in group_members:
                                asa_groups[groups[group]['display name']]["group_members"].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(groups[group]['display name'])+"), skipping"))
                    except:
                        group_members=[]
                        asa_groups[groups[group]['display name']]={}
                        asa_groups[groups[group]['display name']]["group_members"] = []
                        for ip in dfw_rules[section]['rules'][rule]['Source(s)'][group]:
                            if ip == "cannot process - skip":
                                dfw_rules[section]['rules'][rule]["skip"] = True
                            if ip not in group_members:
                                asa_groups[groups[group]['display name']]["group_members"].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(group)+"), skipping"))
                for grp in deduped_groups:
                    if grp!= "ANY":
                        if deduped_groups[grp]["grp_members"] == group_members:
                            #print("Found a network group :{}: that already contains the same members, skipping network group: {}".format(grp,groups[group]['display name']))
                            asa_groups[groups[group]['display name']]["dedupe_master"]=grp
                            dupe_match = True
                            break
                if dupe_match == False:
                    if group!= "ANY":
                        deduped_groups[groups[group]['display name']]={}
                        deduped_groups[groups[group]['display name']]["grp_members"]=[]
                        for net in group_members:
                            deduped_groups[groups[group]['display name']]["grp_members"].append(net)
                        asa_groups[groups[group]['display name']]["dedupe_master"]=groups[group]['display name']
            
            else:
                print(str(group+" is already used in the rulebase, skipping"))
        for group in dfw_rules[section]['rules'][rule]['Destination(s)']:
            dupe_match = False
            if group not in asa_groups.keys():
                if group == "ANY":
                    group_members=["ANY"]
                    asa_groups["ANY"]={}
                    asa_groups["ANY"]["group_members"]=["ANY"]
                    asa_groups["ANY"]["dedupe_master"]=["ANY"]
                else:
                    try:
                        group_members=[]
                        asa_groups[groups[group]['display name']]={}
                        asa_groups[groups[group]['display name']]["group_members"] = []
                        for ip in dfw_rules[section]['rules'][rule]['Destination(s)'][group]:
                            if ip == "cannot process - skip":
                                dfw_rules[section]['rules'][rule]["skip"] = True
                            if ip not in group_members:
                                asa_groups[groups[group]['display name']].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(groups[group]['display name'])+"), skipping"))

                    except:
                        group_members=[]
                        asa_groups[groups[group]['display name']]={}
                        asa_groups[groups[group]['display name']]["group_members"] = []
                        for ip in dfw_rules[section]['rules'][rule]['Destination(s)'][group]:
                            if ip == "cannot process - skip":
                                dfw_rules[section]['rules'][rule]["skip"] = True
                            if ip not in group_members:
                                asa_groups[groups[group]['display name']]["group_members"].append(ip)
                                group_members.append(ip)
                            else:
                                print(str(ip+" already in this group ("+str(group)+"), skipping"))
                for grp in deduped_groups:
                    if grp!= "ANY":
                        if deduped_groups[grp]["grp_members"] == group_members:
                            #print("Found a network group :{}: that already contains the same members, skipping network group: {}".format(grp,groups[group]['display name']))
                            asa_groups[groups[group]['display name']]["dedupe_master"]=grp
                            dupe_match = True
                            break
                if dupe_match == False:
                    if group!= "ANY":
                        deduped_groups[groups[group]['display name']]={}
                        deduped_groups[groups[group]['display name']]["grp_members"]=[]
                        for net in group_members:
                            deduped_groups[groups[group]['display name']]["grp_members"].append(net)
                        asa_groups[groups[group]['display name']]["dedupe_master"]=groups[group]['display name']

            else:
                print(str(group+" is already used in the rulebase, skipping"))


print("service totals")
print("Total services:{}".format(len(asa_service_groups.keys())))
print("Total services after dedupe:{}".format(len(deduped_services.keys())))
print("----------------------------------------------------------------------------------")
print("network totals")
print("Total network groupss:{}".format(len(asa_groups.keys())))
print("Total network groups after dedupe:{}".format(len(deduped_groups.keys())))
#exit()
special_characters = [",","/","&","\*","\(","\)"]
group_config = []

for group in deduped_groups:
    if group != "cannot process - skip":
        newgroup = re.sub(" ","_",group)
        for char in special_characters:
            if char in newgroup:
                newgroup = re.sub(char,"",newgroup)
        if newgroup != "ANY":
            if len(asa_groups[group]["group_members"])==1:
                group_config.append(str("object network "+newgroup))
                if '/' in str(asa_groups[group]["group_members"][0]):
                    try:
                        ipn = IPNetwork(asa_groups[group]["group_members"][0])
                        group_config.append(str(" subnet "+str(ipn.ip)+" "+str(ipn.netmask)))
                    except:
                        test = asa_groups[group]["group_members"]
                        group_config.append("failed to find this item")
                else:
                    group_config.append(str(" host "+asa_groups[group]["group_members"][0]))
            else:
                group_config.append(str("object-group network "+newgroup))
                for ip in asa_groups[group]["group_members"]:
                    if '/' in str(ip):
                        try:
                            ipn = IPNetwork(ip)
                            group_config.append(str(" network "+str(ipn.ip)+" "+str(ipn.netmask)))
                        except:
                            group_config.append("failed to find this item")
                    else:
                        group_config.append(str(" network-object host "+ip))
            group_config.append("exit")



#special_characters = [",","/","&","\*","\(","\)"]
service_config=[]
for group in deduped_services:
    newgroup = re.sub(" ","_",group)
    for char in special_characters:
        if char in newgroup:
            newgroup = re.sub(char,"",newgroup)
    service_config.append(str("object-group service "+newgroup))
    for port in asa_service_groups[group]["group_members"]:
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
                if port == "ICMP":
                    service_config.append(" service icmp")
                elif port == "IGMP":
                    service_config.append(" service igmp")
                elif port == "TCP":
                    service_config.append(" service tcp")
                elif port == "UDP":
                    service_config.append(" service udp")
                else:
                    print("error for group:{} processing port:{} error:{}".format(group,port,e))
                continue
    service_config.append("exit")
asa_rules = []
acl_start = "access-list global_access_dedupe extended "
acl_end = " log"
obj_grp = " object-group "
obj = " object "
srcobj = False
dstobj = False
for section in dfw_rules.keys():
    for rule in dfw_rules[section]['rules']:
        dummy_ip = False
        if dfw_rules[section]['rules'][rule]["skip"] == False:
            if len(list(dfw_rules[section]['rules'][rule]['Source(s)'])) == 1 and len(list(dfw_rules[section]['rules'][rule]['Destination(s)'])) == 1 and len(list(dfw_rules[section]['rules'][rule]['Service(s)'])) == 1:
                if dfw_rules[section]['rules'][rule]['Action'].lower() == "allow":
                    action = "permit"
                elif dfw_rules[section]['rules'][rule]['Action'].lower() == "drop":
                    action = "deny"
                if dfw_rules[section]['rules'][rule]['Service(s)'][list(dfw_rules[section]['rules'][rule]['Service(s)'])[0]] == "ANY":
                    svc = "ip"
                else:
                    svc = re.sub(" ","_",asa_service_groups[service_objects[list(dfw_rules[section]['rules'][rule]['Service(s)'])[0]]['display name']]["dedupe_master"])
                    for char in special_characters:
                        if char in svc:
                            svc = re.sub(str(char),"",svc)
    
                if next(iter(dfw_rules[section]['rules'][rule]['Source(s)'])) == "ANY":
                    src = "any"
                else:
                    if len(asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']]["group_members"]) == 1:
                        #print(type(print(asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']]["group_members"][0])))
                        #pri=str(asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']]["group_members"][0])
                        #if pri == "255.255.255.255/32":
                        #    print("pri")
                        #print(pri)
                        if str(asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']]["group_members"][0]) == "255.255.255.255/32":
                            print("Found a dummy source 255.255.255.255/32 group ({}), skipping rule".format(groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name'])) 
                            dummy_ip = True
                        else:
                            srcobj = True
                    else:
                        srcobj = False
                    src = re.sub(" ","_",asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']]["dedupe_master"])
                    for char in special_characters:
                        if char in src:
                            src = re.sub(str(char),"",src)
                    #src = groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name']
                if next(iter(dfw_rules[section]['rules'][rule]['Destination(s)'])) == "ANY":
                    dst = "any"
                else:
                    if len(asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name']]["group_members"]) == 1:
                        if str(asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name']]["group_members"][0]) == "255.255.255.255/32":
                            print("Found a dummy destination 255.255.255.255/32 group ({}), skipping rule".format(groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name'])) 
                            dummy_ip = True
                        else:
                            dstobj = True
                    else:
                        dstobj = False
                    dst = re.sub(" ","_",asa_groups[groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name']]["dedupe_master"])
                    for char in special_characters:
                        if char in dst:
                            dst = re.sub(str(char),"",dst)
                    #dst = groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name']
                if srcobj == False and dstobj == False:
                    ace = acl_start+action+obj_grp+svc+obj_grp+src+obj_grp+dst+acl_end
                elif srcobj == True and dstobj == False:
                    ace = acl_start+action+obj_grp+svc+obj+src+obj_grp+dst+acl_end
                elif srcobj == False and dstobj == True:
                    ace = acl_start+action+obj_grp+svc+obj_grp+src+obj+dst+acl_end
                elif srcobj == True and dstobj == True:
                    ace = acl_start+action+obj_grp+svc+obj+src+obj+dst+acl_end
                ace = re.sub("object-group ip ","ip ",ace)
                ace = re.sub("object-group any ","any ",ace)
                ace = re.sub("object any ","any ",ace)
                ace = re.sub("object-group migrated_icmp-any","icmp",ace)
                ace = re.sub("object-group migrated_tcp-any","tcp",ace)
                ace = re.sub("object-group migrated_udp-any","udp",ace)

                if dummy_ip == True:
                    print("Found a dummy 255.255.255.255/32 group ({} or {}), skipping rule".format(groups[next(iter(dfw_rules[section]['rules'][rule]['Source(s)']))]['display name'],groups[next(iter(dfw_rules[section]['rules'][rule]['Destination(s)']))]['display name']))
                
                elif src == dst:
                    srcdst = True#print("Source and Destination are the same in this rule ({}:{}) - Skipping".format(src,dst))
                else:
                    if ace in asa_rules:
                        srcdst = True#print("Duplicate rule- {} -removing from config list".format(ace))
                    else:
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
                #print(section)
                #print(rule)
                #print(vars)
                #print(ordered_vars)
                #print(len(dfw_rules[section]['rules'][rule][str(ordered_vars[0])]))
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
                                svc = asa_service_groups[service_objects[dic["Service(s)"]]['display name']]["dedupe_master"]
                                svc = re.sub(" ","_",svc)
                                for char in special_characters:
                                    if char in svc:
                                        svc = re.sub(str(char),"",svc)
                
                            if dic["Source(s)"] == "any":
                                src = "any"
                            else:
    
                                if len(asa_groups[groups[dic["Source(s)"]]['display name']]["group_members"]) == 1:
                                    srcobj = True
                                else:
                                    srcobj = False
                                src = asa_groups[groups[dic["Source(s)"]]['display name']]["dedupe_master"]
                                src = re.sub(" ","_",src)
                                for char in special_characters:
                                    if char in src:
                                        src = re.sub(str(char),"",src)
                            if dic["Destination(s)"] == "any":
                                dst = "any"
                            #elif dic["Destination(s)"] == "/infra/tier-0s/vmc/groups/connected_vpc":
                            #    dst = "?????Cant find this Group?????"
                            #elif dic["Destination(s)"] == "/infra/tier-0s/vmc/groups/s3_prefixes":
                            #    dst = "?????Cant find this Group?????"
                            else:
                                if len(asa_groups[groups[dic["Destination(s)"]]['display name']]["group_members"]) == 1:
                                    dstobj = True
                                else:
                                    dstobj = False
                                dst = asa_groups[groups[dic["Destination(s)"]]['display name']]["dedupe_master"]
                                dst = re.sub(" ","_",dst)
                                for char in special_characters:
                                    if char in dst:
                                        dst = re.sub(str(char),"",dst)
    
                            if srcobj == False and dstobj == False:
                                ace = acl_start+action+obj_grp+svc+obj_grp+src+obj_grp+dst+acl_end
                            elif srcobj == True and dstobj == False:
                                ace = acl_start+action+obj_grp+svc+obj+src+obj_grp+dst+acl_end
                            elif srcobj == False and dstobj == True:
                                ace = acl_start+action+obj_grp+svc+obj_grp+src+obj+dst+acl_end
                            elif srcobj == True and dstobj == True:
                                ace = acl_start+action+obj_grp+svc+obj+src+obj+dst+acl_end
                            ace = re.sub("object-group ip ","ip ",ace)
                            ace = re.sub("object-group any ","any ",ace)
                            ace = re.sub("object any ","any ",ace)
                            ace = re.sub("object-group migrated_icmp-any","icmp",ace)
                            ace = re.sub("object-group migrated_tcp-any","tcp",ace)
                            ace = re.sub("object-group migrated_udp-any","udp",ace)
                            if src == dst:
                                srcdest = True#print("Source and Destination are the same in this rule ({}:{}) - Skipping".format(src,dst))
                            else:
                                if ace in asa_rules:
                                    dup = True#print("Duplicate rule- {} -removing from config list".format(ace))
                                else:
                                    asa_rules.append(ace)
                            #print(acl_start+action+obj+svc+obj+src+obj+dst+acl_end)
                #print("-------------------------------------------------------------------------")
    
                                #flows.append({ordered_vars[0]:vars[ordered_vars[0]][w],ordered_vars[1]:vars[ordered_vars[1]][x],ordered_vars[2]:vars[ordered_vars[2]][y],ordered_vars[3]:vars[ordered_vars[3]][z]})
#                       print(flows)
    
            

filepath1 = '/dbdev/vmc_pp_migration/outputs/asa_groups_dedupe_object.json'
with open(filepath1, "w") as outfile: 
    json.dump(asa_groups, outfile)

filepathd = '/dbdev/vmc_pp_migration/outputs/asa_groups_dedupe_object_final.json'
with open(filepathd, "w") as outfile: 
    json.dump(deduped_groups, outfile)


filepath2 = '/dbdev/vmc_pp_migration/outputs/asa_services_dedupe_object.json'
with open(filepath2, "w") as outfile: 
    json.dump(asa_service_groups, outfile)

filepaths = '/dbdev/vmc_pp_migration/outputs/asa_services_dedupe_object_final.json'
with open(filepaths, "w") as outfile: 
    json.dump(deduped_services, outfile)

filepath3 = '/dbdev/vmc_pp_migration/outputs/asa_dfw_rules_dedupe_object.json'
with open(filepath3, "w") as outfile: 
    json.dump(asa_rules, outfile)


templateLoader = jinja2.FileSystemLoader(searchpath="/dbdev/vmc_pp_migration/")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = group_config)  # this is where to put args to the template renderer
file = "asa_group_config_dedupe_object.txt"
csv_file = open(file, "w")
csv_file.write(outputText)


templateLoader = jinja2.FileSystemLoader(searchpath="/dbdev/vmc_pp_migration/")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = asa_rules)  # this is where to put args to the template renderer
file = "asa_dfw_rules_dedupe_object.txt"
csv_file = open(file, "w")
csv_file.write(outputText)

templateLoader = jinja2.FileSystemLoader(searchpath="/dbdev/vmc_pp_migration/")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "groups_json_to_asaconfig.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = service_config)  # this is where to put args to the template renderer
file = "asa_service_config_dedupe_object.txt"
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

