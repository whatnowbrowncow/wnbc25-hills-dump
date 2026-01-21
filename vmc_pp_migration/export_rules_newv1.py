### Package Imports ####
import requests
import json
import jinja2
import argparse
import re
from netaddr import IPNetwork, IPAddress, iter_iprange


### Ready arguments from command line ###
parser = argparse.ArgumentParser(description='Export user created NSX-T Firewall rules and objects for a given VMC SDDC.')
parser.add_argument('orgid')
parser.add_argument('sddcid')
parser.add_argument('refreshtoken')

args = parser.parse_args()

#orgid = '2424d387-d5e6-4b7c-bd7e-646ef5ea22f9'
#sddcid = 'cc87ddfe-cd05-451a-8355-8227ef2d7c4e'
#refreshtoken = 'VEYq0O28k2NZilvJuOobgYMsyncyeGQiwedeTVPuvZb2t2FsvedNEH715UdW9St3'

### Access Token ###
authurl = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token=%s' %(args.refreshtoken)
headers = {'Accept': 'application/json'}
payload = {}
authresp = requests.post(authurl,headers=headers,data=payload)
authjson = json.loads(authresp.text)
token = authjson["access_token"]

### Get ReverseProxy URL ###
infourl = 'https://vmc.vmware.com/vmc/api/orgs/%s/sddcs/%s' %(args.orgid,args.sddcid)
headers = {'csp-auth-token': token, 'content-type': 'application/json'}
payload = {}
sddcresp = requests.get(infourl,headers=headers,data=payload)
sddcjson = json.loads(sddcresp.text)
srevproxyurl = sddcjson["resource_config"]["nsx_api_public_endpoint_url"]


### Source SDDC URL's ###
smgwgroupsurl = '%s/policy/api/v1/infra/domains/mgw/groups' %(srevproxyurl)
scgwgroupsurl = '%s/policy/api/v1/infra/domains/cgw/groups' %(srevproxyurl)
scgwgroupsp2url = '%s/policy/api/v1/infra/domains/cgw/groups?cursor=00041000' %(srevproxyurl)
t0groupsurl = '%s/policy/api/v1/infra/tier-0s/vmc/groups' %(srevproxyurl)
scgwurl = '%s/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules' %(srevproxyurl)
smgwurl = '%s/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules' %(srevproxyurl)
sservicesurl = '%s/policy/api/v1/infra/services' %(srevproxyurl)
sdfwurl = '%s/policy/api/v1/infra/domains/cgw/communication-maps' %(srevproxyurl)
segmentsurl = '%s/policy/api/v1/infra/tier-1s/cgw/segments' %(srevproxyurl)


headers = {'csp-auth-token': token, 'content-type': 'application/json'}

sfwDump = open("sourceRules.json", "a+")

segresponse = requests.get(segmentsurl,headers=headers)
segs = json.loads(segresponse.text)
segments = segs["results"]
#print(segments)
network_segments = {}
for segment in segments:
    network_segments[str(segment["path"])] = {}
    network_segments[str(segment["path"])]["display name"] = segment["display_name"]
    network_segments[str(segment["path"])]["ip address"] = segment["subnets"][0]["network"]

group_display_names = []
#filepath3 = './segs.json'
#with open(filepath3, "w") as outfile:
#    json.dump(network_segments, outfile)
#exit()
#####################

#gurl = '%s/policy/api/v1/infra/domains/cgw/groups/01243ca6-a48f-46b2-8e39-6745f17acaff' %(srevproxyurl)
#resp = requests.get(gurl,headers=headers)
#gr = json.loads(resp.text)
#print(gr)
#grs = gr["results"]
#print(grs)
#exit()


## Get Source MGW Groups ###
mgroupsresp = requests.get(smgwgroupsurl,headers=headers)
mg = json.loads(mgroupsresp.text)
mgroups = mg["results"]


## Filter out system groups ###
groups = {}
#print("###########################MGW Groups################################")
#print(mgroups)
for group in mgroups:
    #print(json.dumps(group,indent=4))
    #if group["_create_user"]!= "admin" and group["_create_user"]!="admin;admin":
    groups[str(group["path"])] = {}
    groups[str(group["path"])]["display name"] = group["display_name"]
    group_display_names.append(group["display_name"])
    if "description" in groups[str(group["path"])].keys():
        groups[str(group["path"])]["description"] = group["description"]
    else:
        groups[str(group["path"])]["description"] = "No description configured"
    groups[str(group["path"])]["created by"] = group["_create_user"]
    try:
        groups[str(group["path"])]["object type"] = group["expression"][0]["resource_type"]
        if group["expression"][0]["resource_type"] == "IPAddressExpression":
            if "-" in group["expression"][0]["ip_addresses"][0]:
                ipstart = re.match("(\d+\.\d+\.\d+\.)",group["expression"][0]["ip_addresses"][0]).group(0)
                iprangestart = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["expression"][0]["ip_addresses"][0]).group(1)
                iprangeend = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["expression"][0]["ip_addresses"][0]).group(2)
                iprange = int(iprangeend) - int(iprangestart) + 1
                octet = int(iprangestart)
                ips = []
                for x in range(iprange):
                    curip = "{}{}".format(ipstart,octet)
                    octet = octet+1
                    ips.append(curip)
                groups[str(group["path"])]["IP Addresses"] = ips
            else:    
                groups[str(group["path"])]["IP Addresses"] = group["expression"][0]["ip_addresses"]
        elif group["expression"][0]["resource_type"] == "PathExpression":
            groups[str(group["path"])]["Paths"] = group["expression"][0]["paths"]
    except:
        groups[str(group["path"])]["object type"] = "Not Found, suspect this group is empty"
        #print(json.dumps(group,indent=4))

### Get Source CGW Groups ###
cgroupsresp = requests.get(scgwgroupsurl,headers=headers)
cg = json.loads(cgroupsresp.text)
#print("#################CG####################")
#print(cg)
cgroups = cg["results"]


while 'cursor' in cg.keys():
    scgwgroupsp2url = '%s/policy/api/v1/infra/domains/cgw/groups?cursor=00041000' %(srevproxyurl)
    scgwgroupsurl = '%s/policy/api/v1/infra/domains/cgw/groups?cursor=%s' %(srevproxyurl,cg['cursor'])
    cgroupsresp = requests.get(scgwgroupsurl,headers=headers)
    cg = json.loads(cgroupsresp.text)
    cgroups = cgroups + cg["results"]

### Filter out system groups ###
#print("###########################CGW Groups############################")
#print(cgroups)

for group in cgroups:
    #print(json.dumps(group,indent=4))
    
    #if group["_create_user"]!= "admin" and group["_create_user"]!="admin;admin":
    groups[str(group["path"])] = {}
    groups[str(group["path"])]["display name"] = group["display_name"]
    group_display_names.append(group["display_name"])
    if "description" in groups[str(group["path"])].keys():
        groups[str(group["path"])]["description"] = group["description"]
    else:
        groups[str(group["path"])]["description"] = "No description configured"
    groups[str(group["path"])]["created by"] = group["_create_user"]
    try:
        groups[str(group["path"])]["object type"] = group["expression"][0]["resource_type"]
        if group["expression"][0]["resource_type"] == "IPAddressExpression":
            if "-" in group["expression"][0]["ip_addresses"][0]:
                ipstart = re.match("(\d+\.\d+\.\d+\.)",group["expression"][0]["ip_addresses"][0]).group(0)
                iprangestart = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["expression"][0]["ip_addresses"][0]).group(1)
                iprangeend = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["expression"][0]["ip_addresses"][0]).group(2)
                iprange = int(iprangeend) - int(iprangestart) + 1
                octet = int(iprangestart)
                ips = []
                for x in range(iprange):
                    curip = "{}{}".format(ipstart,octet)
                    octet = octet+1
                    ips.append(curip)
                groups[str(group["path"])]["IP Addresses"] = ips
            else:    
                groups[str(group["path"])]["IP Addresses"] = group["expression"][0]["ip_addresses"]
        elif group["expression"][0]["resource_type"] == "PathExpression":
            groups[str(group["path"])]["Paths"] = group["expression"][0]["paths"]
    except:
        groups[str(group["path"])]["object type"] = "Not Found, suspect this group is empty"
#print(groups)
        #print(json.dumps(group,indent=4))

### Get Source CGW Groups (group2) ###
#cgroupsrespp2 = requests.get(scgwgroupsp2url,headers=headers)
#cgp2 = json.loads(cgroupsrespp2.text)
##print("#################CG2####################")
##print(cgp2)
#cgroupsp2 = cgp2["results"]
#
#### Filter out system groups ###
##print("#######################CGW Groups2########################")
##print(cgroupsp2)
#
#for group in cgroupsp2:
#    #print(json.dumps(group,indent=4))
#    
#    #if group["_create_user"]!= "admin" and group["_create_user"]!="admin;admin":
#    groups[str(group["path"])] = {}
#    groups[str(group["path"])]["display name"] = group["display_name"]
#    if "description" in groups[str(group["path"])].keys():
#        groups[str(group["path"])]["description"] = group["description"]
#    else:
#        groups[str(group["path"])]["description"] = "No description configured"
#    groups[str(group["path"])]["created by"] = group["_create_user"]
#    try:
#        groups[str(group["path"])]["object type"] = group["expression"][0]["resource_type"]
#        if group["expression"][0]["resource_type"] == "IPAddressExpression":
#            groups[str(group["path"])]["IP Addresses"] = group["expression"][0]["ip_addresses"]
#        elif group["expression"][0]["resource_type"] == "PathExpression":
#            groups[str(group["path"])]["Paths"] = group["expression"][0]["paths"]
#    except:
#        groups[str(group["path"])]["object type"] = "Not Found, suspect this group is empty"

### Get Source T0 Groups (group3) ###
t0groupsresp = requests.get(t0groupsurl,headers=headers)
t0 = json.loads(t0groupsresp.text)
#print("#################CG2####################")
#print(cgp2)
t0groups = t0["results"]

### Filter out system groups ###
#print("#######################CGW Groups2########################")
#print(cgroupsp2)

for group in t0groups:
    #print(json.dumps(group,indent=4))
    
    #if group["_create_user"]!= "admin" and group["_create_user"]!="admin;admin":
    groups[str(group["path"])] = {}
    groups[str(group["path"])]["display name"] = group["display_name"]
    group_display_names.append(group["display_name"])
    if "description" in groups[str(group["path"])].keys():
        groups[str(group["path"])]["description"] = group["description"]
    else:
        groups[str(group["path"])]["description"] = "No description configured"
    groups[str(group["path"])]["created by"] = group["_create_user"]
    try:
        groups[str(group["path"])]["object type"] = group["expression"][0]["resource_type"]
        if group["expression"][0]["resource_type"] == "IPAddressExpression":
            if "-" in group["expression"][0]["ip_addresses"][0]:
                ipstart = re.match("(\d+\.\d+\.\d+\.)",group["expression"][0]["ip_addresses"][0]).group(0)
                iprangestart = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["expression"][0]["ip_addresses"][0]).group(1)
                iprangeend = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["expression"][0]["ip_addresses"][0]).group(2)
                iprange = int(iprangeend) - int(iprangestart) + 1
                octet = int(iprangestart)
                ips = []
                for x in range(iprange):
                    curip = "{}{}".format(ipstart,octet)
                    octet = octet+1
                    ips.append(curip)
                groups[str(group["path"])]["IP Addresses"] = ips
            else:    
                groups[str(group["path"])]["IP Addresses"] = group["expression"][0]["ip_addresses"]
        elif group["expression"][0]["resource_type"] == "PathExpression":
            groups[str(group["path"])]["Paths"] = group["expression"][0]["paths"]
    except:
        groups[str(group["path"])]["object type"] = "Not Found, suspect this group is empty"
#print(groups)
        #print(json.dumps(group,indent=4))

### Get Source SDDC Firewall Services ###
servicesresp = requests.get(sservicesurl,headers=headers)
srv = json.loads(servicesresp.text)
services = srv["results"]
print('ORIGINAL SERVICES#####################################################################################')
#print(services)
while 'cursor' in srv.keys():
    sservicesurl = '%s/policy/api/v1/infra/services?cursor=%s' %(srevproxyurl,srv['cursor'])
    servicesresp = requests.get(sservicesurl,headers=headers)
    srv = json.loads(servicesresp.text)
    services = services + srv["results"]
print('LOOPED SERVICES#####################################################################################')
#print(services)

service_objects = {}
duplicate_objects = {}
### Filter out system Services ###
#print("Services")
for service in services:
    #print(json.dumps(service,indent=4))
    service_list=[]
    #if service["_create_user"]!= "admin" and service["_create_user"]!="admin;admin" and service["_create_user"]!="system":
    if service["display_name"] in group_display_names:
        print("found a duplicate name: {} : {}".format(str(service["path"]),service["display_name"]))
        service_objects[str(service["path"])] = {}
        service_objects[str(service["path"])]["display name"] = "{}_svc".format(service["display_name"])
    else:
        service_objects[str(service["path"])] = {}
        service_objects[str(service["path"])]["display name"] = service["display_name"]
    if "description" in service_objects[str(service["path"])].keys():
        service_objects[str(service["path"])]["description"] = service["description"]
    else:
        service_objects[str(service["path"])]["description"] = "No description configured"
    service_objects[str(service["path"])]["created by"] = service["_create_user"]
    service_objects[str(service["path"])]["object type"] = service["resource_type"]
    service_objects[str(service["path"])]["ports"] = []
    if service["service_type"] == "NON_ETHER":
        for port in service["service_entries"]:
            port_list=[]
            if port["resource_type"] == "L4PortSetServiceEntry" :
                if len(port["destination_ports"]) == 0:
                    port_list.append(port["l4_protocol"])
                else:
                    for svc in port["destination_ports"]:
                        port_list.append(str(port["l4_protocol"])+"/"+str(svc))
                #port_list.append(str(port["l4_protocol"])+"/"+str(port["destination_ports"]))
            elif port["resource_type"] == "ICMPTypeServiceEntry":
                port_list.append("ICMP")
            elif port["resource_type"] == "IGMPTypeServiceEntry":
                port_list.append("IGMP")
            elif port["resource_type"] == "IPProtocolServiceEntry":
                port_list.append("TCP")
            elif port["resource_type"] == "ALGTypeServiceEntry":
                if port["id"] == "FTP":
                    port_list.append("TCP/21")
                elif port["id"] == "MS_RPC_TCP":
                    port_list.append("TCP/135")
                elif port["id"] == "MS_RPC_UDP":
                    port_list.append("UDP/135")
                elif port["id"] == "ORACLE_TNS":
                    port_list.append("TCP/1521")
                elif port["id"] == "SUN_RPC_TCP":
                    port_list.append("TCP/111")
                elif port["id"] == "SUN_RPC_UDP":
                    port_list.append("UDP/111")
                elif port["id"] == "TFTP":
                    port_list.append("TCP/69")
            for prt in port_list:
                service_list.append(prt)
        service_objects[str(service["path"])]["ports"] = service_list
    elif service["service_type"] == "ETHER":
        service_objects[str(service["path"])]["ports"] = "IP"
    

        #print(json.dumps(service,indent=4))
#print("-------------------------------------Groups --------------------------------------------")
#print(groups)
#print("-----------------------------------Service Objects--------------------------------------")
#print(service_objects)

### Get Management Gateway Firewall Rules ###
mgwresponse = requests.get(smgwurl,headers=headers)
m = json.loads(mgwresponse.text)
mgwrules = m["results"]

### Filter out system Rules ###
#print("MGW Rules")
mgw_rules = {}
for rule in mgwrules:
    if rule["_create_user"]!= "admin" and rule["_create_user"]!="admin;admin" and rule["_create_user"]!="system":
        mgw_rules[str(rule["sequence_number"])] = {}
        mgw_rules[str(rule["sequence_number"])]["Display name"]=str(rule["display_name"])
        mgw_rules[str(rule["sequence_number"])]["Action"]=str(rule["action"])
        mgw_rules[str(rule["sequence_number"])]["Source(s)"] = {} 
        for group in rule["source_groups"]:
            if group == "ANY":
                mgw_rules[str(rule["sequence_number"])]["Source(s)"][group] = "ANY"
            else:
                mgw_rules[str(rule["sequence_number"])]["Source(s)"][group] = []
                if groups[group]["object type"] == "IPAddressExpression":
                    for ip in groups[group]["IP Addresses"]:
                        mgw_rules[str(rule["sequence_number"])]["Source(s)"][group].append(ip)
                elif groups[group]["object type"] == "PathExpression":
                    for path in groups[group]["Paths"]:
                        mgw_rules[str(rule["sequence_number"])]["Source(s)"][group].append(path)
                else:
                    mgw_rules[str(rule["sequence_number"])]["Source(s)"][group].append(str("cannot process - skip"))
                
            #mgw_rules[str(rule["sequence_number"])]["Source(s)"].append(group)
        mgw_rules[str(rule["sequence_number"])]["Destination(s)"] = {}
        for group in rule["destination_groups"]:
            if group == "ANY":
                mgw_rules[str(rule["sequence_number"])]["Destination(s)"][group] = "ANY"
            else:
                mgw_rules[str(rule["sequence_number"])]["Destination(s)"][group] = []
                if groups[group]["object type"] == "IPAddressExpression":
                    for ip in groups[group]["IP Addresses"]:
                        mgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(ip)
                elif groups[group]["object type"] == "PathExpression":
                    for path in groups[group]["Paths"]:
                        mgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(path)
                else:
                    mgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(str("cannot process - skip"))
        mgw_rules[str(rule["sequence_number"])]["Service(s)"] = {}
        for group in rule["services"]:
            if group == "ANY":
                mgw_rules[str(rule["sequence_number"])]["Service(s)"][group] = "ANY"
            else:
                mgw_rules[str(rule["sequence_number"])]["Service(s)"][group] = []
                for port in service_objects[group]["ports"]:
                    mgw_rules[str(rule["sequence_number"])]["Service(s)"][group].append(port)

        #print(json.dumps(rule,indent=4))

### Get Compute Gateway Firewall Rules ###
cgwresponse = requests.get(scgwurl,headers=headers)
c = json.loads(cgwresponse.text)
cgwrules = c["results"]

### Filter out system Rules ###
#print("CGW Rules")
cgw_rules = {}
for rule in cgwrules:
    if rule["_create_user"]!= "admin" and rule["_create_user"]!="admin;admin" and rule["_create_user"]!="system":
        cgw_rules[str(rule["sequence_number"])] = {}
        cgw_rules[str(rule["sequence_number"])]["Display name"]=str(rule["display_name"])
        cgw_rules[str(rule["sequence_number"])]["Action"]=str(rule["action"])
        cgw_rules[str(rule["sequence_number"])]["Source(s)"] = {} 
        for group in rule["source_groups"]:
            if group == "ANY":
                cgw_rules[str(rule["sequence_number"])]["Source(s)"][group] = "ANY"
            else:
                cgw_rules[str(rule["sequence_number"])]["Source(s)"][group] = []
                if groups[group]["object type"] == "IPAddressExpression":
                    for ip in groups[group]["IP Addresses"]:
                        cgw_rules[str(rule["sequence_number"])]["Source(s)"][group].append(ip)
                elif groups[group]["object type"] == "PathExpression":
                    for path in groups[group]["Paths"]:
                        cgw_rules[str(rule["sequence_number"])]["Source(s)"][group].append(path)
                else:
                    cgw_rules[str(rule["sequence_number"])]["Source(s)"][group].append(str("cannot process - skip"))
            #cgw_rules[str(rule["sequence_number"])]["Source(s)"].append(group)
        cgw_rules[str(rule["sequence_number"])]["Destination(s)"] = {} 
        for group in rule["destination_groups"]:
            if group == "ANY":
                cgw_rules[str(rule["sequence_number"])]["Destination(s)"][group] = "ANY"
            else:
                cgw_rules[str(rule["sequence_number"])]["Destination(s)"][group] = []
                if groups[group]["object type"] == "IPAddressExpression":
                    for ip in groups[group]["IP Addresses"]:
                        cgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(ip)
                elif groups[group]["object type"] == "PathExpression":
                    for path in groups[group]["Paths"]:
                        if groups[path]["object type"] == "IPAddressExpression":
                            for ip2 in groups[path]["IP Addresses"]:
                                cgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(ip2)
                        elif groups[path]["object type"] == "PathExpression":
                            for path2 in groups[path]["Paths"]:
                                cgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(path2)
                else:
                    cgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(str("cannot process - skip"))
                        #cgw_rules[str(rule["sequence_number"])]["Destination(s)"][group].append(path)
        cgw_rules[str(rule["sequence_number"])]["Service(s)"] = {}
        for group in rule["services"]:
            if group == "ANY":
                cgw_rules[str(rule["sequence_number"])]["Service(s)"][group] = "ANY"
            else:
                cgw_rules[str(rule["sequence_number"])]["Service(s)"][group] = []
                for port in service_objects[group]["ports"]:
                    cgw_rules[str(rule["sequence_number"])]["Service(s)"][group].append(port)
        #print(json.dumps(rule,indent=4))
#print("-------------------------------------MGW Rules --------------------------------------------")
#print(mgw_rules)
#print("-----------------------------------CGW Rules--------------------------------------")
#print(cgw_rules)

## Get Source Distributed Firewall Rules ###
dfwresponse = requests.get(sdfwurl,headers=headers)
d = json.loads(dfwresponse.text)
cmaps = d["results"]
#print("DFW Rules")
dfw_rules = {}
for cmap in cmaps:
    dfw_rules[str(cmap["display_name"])]={}
    dfw_rules[str(cmap["display_name"])]["Precedence"] = str(cmap["precedence"])
    dfw_rules[str(cmap["display_name"])]["rules"] = {}
    #print("###############section##################")
    #print(str(cmap["id"]))
    #print(json.dumps(cmap,indent=4))
    #print("#################Section rules##################")
    sdfwsecurl = '%s/policy/api/v1/infra/domains/cgw/communication-maps/%s/communication-entries' %(srevproxyurl,str(cmap["id"]))
    dfwsecresponse = requests.get(sdfwsecurl,headers=headers)
    r = json.loads(dfwsecresponse.text)
    #print(s)
    rules =r["results"]
    for rule in rules:
        #print(json.dumps(rule,indent=4))
        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])] = {}
        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Display name"]=str(rule["display_name"])
        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Action"]=str(rule["action"])
        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"] = {} 
        for group in rule["source_groups"]:
            if group == "ANY":
                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group] = "ANY"
            else:
                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group] = []
                if group in groups.keys():
                    if groups[group]["object type"] == "IPAddressExpression":
                        for ip in groups[group]["IP Addresses"]:
                            dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(ip)
                    elif groups[group]["object type"] == "PathExpression":
                        for path in groups[group]["Paths"]:
                            if path in groups.keys():
                                if groups[path]["object type"] == "IPAddressExpression":
                                    for ip2 in groups[path]["IP Addresses"]:
                                        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(ip2)
                                elif groups[path]["object type"] == "PathExpression":
                                    print("FOUND A BUGGER! - DOUBLE NESTED OBJECT")
                                    print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                    print(path)
                                    for path2 in groups[path]["Paths"]:
                                        if path2 in groups.keys():
                                            if groups[path2]["object type"] == "IPAddressExpression":
                                                for ip3 in groups[path2]["IP Addresses"]:
                                                    dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(ip3)
                                            elif groups[path2]["object type"] == "PathExpression":
                                                print("FOUND A BUGGER! - TRIPLE NESTED OBJECT")
                                                print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                                print(path)
                                                for path3 in groups[path2]["Paths"]:
                                                    if path3 in groups.keys():
                                                        if groups[path3]["object type"] == "IPAddressExpression":
                                                            for ip4 in groups[path3]["IP Addresses"]:
                                                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(ip4)
                                                        elif groups[path3]["object type"] == "PathExpression":
                                                            print("FOUND A BUGGER! - QUADRUPLE NESTED OBJECT")
                                                            print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                                            print(path)
                                                            for path4 in groups[path3]["Paths"]:
                                                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(path4)
                                                    else:
                                                        print("??????????????????cant find this group4?????????????????")
                                                        print(path3)
                                                        print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                                        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(str("!!cannot 3 locate "+path3))
                                        else:
                                            print("??????????????????cant find this group3?????????????????")
                                            print(path2)
                                            print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                            dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(str("!!cannot 2 locate "+path2))
                            elif path in network_segments.keys():
                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(network_segments[path]["ip address"])
                            else:
                                
                                print("??????????????????cant find this group2?????????????????")
                                print(path)
                                print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(str("!!cannot 1 locate "+path))
                    else:
                        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group].append(str("cannot process - skip"))            
                else:

                    print("??????????????????cant find this group1?????????????????")
                    print(group)
                    print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                    dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Source(s)"][group] = "?????Cant find this Group?????"
        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"] = {} 
        for group in rule["destination_groups"]:
            if group == "ANY":
                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group] = "ANY"
            else:
                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group] = []
                if group in groups.keys():
                    if groups[group]["object type"] == "IPAddressExpression":
                        for ip in groups[group]["IP Addresses"]:
                            dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(ip)
                    elif groups[group]["object type"] == "PathExpression":
                        for path in groups[group]["Paths"]:
                            if path in groups.keys():
                                if groups[path]["object type"] == "IPAddressExpression":
                                    for ip2 in groups[path]["IP Addresses"]:
                                        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(ip2)
                                elif groups[path]["object type"] == "PathExpression":
                                    print("FOUND A BUGGER! - DOUBLE NESTED OBJECT")
                                    print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                    print(path)
                                    for path2 in groups[path]["Paths"]:
                                        if path2 in groups.keys():
                                            if groups[path2]["object type"] == "IPAddressExpression":
                                                for ip3 in groups[path2]["IP Addresses"]:
                                                    dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(ip3)
                                            elif groups[path2]["object type"] == "PathExpression":
                                                print("FOUND A BUGGER! - TRIPLE NESTED OBJECT")
                                                print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                                print(path)
                                                for path3 in groups[path2]["Paths"]:
                                                    if path3 in groups.keys():
                                                        if groups[path3]["object type"] == "IPAddressExpression":
                                                            for ip4 in groups[path3]["IP Addresses"]:
                                                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(ip4)
                                                        elif groups[path3]["object type"] == "PathExpression":
                                                            print("FOUND A BUGGER! - QUADRUPLE NESTED OBJECT")
                                                            print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                                            print(path)
                                                            for path4 in groups[path3]["Paths"]:
                                                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(path4)
                                                    else:
                                                        print("??????????????????cant find this group4?????????????????")
                                                        print(path3)
                                                        print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                                        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(str("!!cannot 3 locate "+path3))
                                        else:
                                            print("??????????????????cant find this group3?????????????????")
                                            print(path2)
                                            print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                            dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(str("!!cannot 2 locate "+path2))
                            elif path in network_segments.keys():
                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(network_segments[path]["ip address"])
                            else:
                                print("??????????????????cant find this group2?????????????????")
                                print(path)
                                print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(str("!!cannot 1 locate "+path))
                    else:
                        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group].append(str("cannot process - skip"))
                else:
                    print("??????????????????cant find this group1?????????????????")
                    print(group)
                    print(str(cmap["display_name"])+":"+str(rule["sequence_number"]))
                    dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Destination(s)"][group] = "?????Cant find this Group?????"
        dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Service(s)"] = {} 
        for group in rule["services"]:
            if group == "ANY":
                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Service(s)"][group] = "ANY"
            else:
                dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Service(s)"][group] = []
                for port in service_objects[group]["ports"]:
                    dfw_rules[str(cmap["display_name"])]["rules"][str(rule["sequence_number"])]["Service(s)"][group].append(port)
#print("###################################DFWS############################################")
#print(dfw_rules)


filepath = './outputs/dfws.json'
with open(filepath, "w") as outfile: 
    json.dump(dfw_rules, outfile)

filepath1 = './outputs/groups.json'
with open(filepath1, "w") as outfile: 
    json.dump(groups, outfile)

filepath2 = './outputs/services.json'
with open(filepath2, "w") as outfile: 
    json.dump(service_objects, outfile)

filepath3 = './outputs/cgwfw.json'
with open(filepath3, "w") as outfile:
    json.dump(cgw_rules, outfile)

filepath4 = './outputs/mgwfw.json'
with open(filepath4, "w") as outfile: 
    json.dump(mgw_rules, outfile)

filepath5 = './outputs/groups.json'
with open(filepath5, "w") as outfile: 
    json.dump(groups, outfile)

filepath6 = './outputs/services.json'
with open(filepath6, "w") as outfile: 
    json.dump(service_objects, outfile)

#dfw_order = ("Intra Segment","Temp","Rulebase","SDDC_Specific")
#
#dfw_rules_ordered={}
#for section in dfw_order:
#    dfw_rules_ordered[section] = dfw_rules[section]




templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "dfw_json_to_csv.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = dfw_rules)  # this is where to put args to the template renderer
file = "mrg_sddc_dfw.csv"
csv_file = open(file, "w")
csv_file.write(outputText)

TEMPLATE_FILE = "gw_json_to_csv.j2"
template = templateEnv.get_template(TEMPLATE_FILE)

outputText = template.render(data = mgw_rules)  # this is where to put args to the template renderer
file = "mrg_sddc_mgwfw.csv"
csv_file = open(file, "w")
csv_file.write(outputText)

outputText = template.render(data = cgw_rules)  # this is where to put args to the template renderer
file = "mrg_sddc_cgwfw.csv"
csv_file = open(file, "w")
csv_file.write(outputText)


