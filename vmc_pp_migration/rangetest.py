import re
groups = {}
mgroups = [{"display_name":"OCR","path":"OCRPATH","ip_addresses":"10.195.77.22-10.195.77.24"}]
for group in mgroups:
    #print(json.dumps(group,indent=4))
    #if group["_create_user"]!= "admin" and group["_create_user"]!="admin;admin":
    if "-" in group["ip_addresses"]:
        ipstart = re.match("(\d+\.\d+\.\d+\.)",group["ip_addresses"]).group(0)
        iprangestart = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["ip_addresses"]).group(1)
        iprangeend = re.match("\d+\.\d+\.\d+\.(\d+)\-\d+\.\d+\.\d+\.(\d+)",group["ip_addresses"]).group(2)
        iprange = int(iprangeend) - int(iprangestart) + 1
        octet = int(iprangestart)
        for x in range(iprange):
            curip = "{}{}".format(ipstart,octet)
            octet = octet+1