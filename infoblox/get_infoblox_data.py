import requests
import json
import jinja2

ext_atr_data = {}
extensible_attributes = ["Site","Environment","CardData"]
for extattr in extensible_attributes:
    url = f"https://sc1nsm01.williamhill.plc/wapi/v2.13.1/extensibleattributedef?name={extattr}&_return_fields=list_values,comment,name"

    payload = ""
    headers = {
      'Authorization': 'Basic ZGJ1cnRvbjpEYXZleWIxMzg=',
      'Cookie': 'ibapauth="group=Network%20and%20Security,ctime=1736262156,ip=192.168.12.20,auth=AD,client=API,su=1,timeout=2400,mtime=1736263899,user=dburton,uC2Puzv/Y5wRtT628/4gquYLpgc8famaWE0"'
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    data = response.json()
    ext_atr_data[extattr]=data
    

    
#site_list = ["888 Corporate - Gibraltar","888 Corporate - Israel","888 Corporate - Romania","888 Dublin Spectate","888 Production - AWS-RM","888 Production - Delaware","888 Production - Dublin","888 Production - Kiev","888 Production - NJ-Holdings","888 Production - QA","888 Production - Telx Holdings","DE-FR7 - Germany Frankfurt FR7 (Equinix)","EU-WEST-1 (Dublin)","EU-WEST-2 (London)","GI-MPL - Mount Pleasant DC, Gib","IE-DB2 - Ireland Dublin DB2 (Equinix)","IE-DB3 - Ireland Dublin DB3 (Equinix)","IT-ML2 - Italy Milan ML2 (Equinix)","IT-ROM - Sogei Rome","MT-HAN - Mr Green - Handaq Malta","MT-MSC - Malta SmartCity","MT-MSC2 - Mr Green - Malta SmartCity","MT-SLM - Mr Green - Sliema Malta","Network Backbone","PH-MNL - Manila Aseana Office","PL-KRK - Krakow Office, Poland","Retail LBO","Third Party / Off Net","UK-BFA - Bedford Avenue, London","UK-BRS - Birstall DC, Wakefield","UK-LD6 - Equinix LD6, Slough","UK-LDS - West Village, Leeds","UK-MA3 - MA3 DC, Manchester","UK-MAN - Equinix MA3, Manchester","UK-MDC - Media City","UK-MTK - Milton Keynes","UK-SC1 - SCC DC, Birmingham","UK-SOV - Sovereign House, London","UK-STJ - St Johns, Leeds","VMC SDDC","VMC-RETAIL-PRD-SDDC-EU2","VMC-SCC-NON-WHC-PROD-SDDC-EU1","VMC-SCC-WHC-PROD-SDDC-EU1","888 Production - Azure"]
#environment_list = ["Common Services","Corporate","Development","Disaster Recovery","Fairness","Lab","Performance Test Offshore","Performance Test Onshore","Pre-Prod Shared","Pre-Prod1","Pre-Prod2","Pre-Prod3","Production","Retail Estate","Retail Test 1","Retail Test 2","Retail Test 3","Retail Test Shared","Staging","System Test","Test Shared","Transit","Non Production","spare","Certification","888 Production","888 QA"]
#cde_list = ["cde","ncde","access"]

templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader, trim_blocks=True, lstrip_blocks=True)
TEMPLATE_FILE = "render_html.j2"
template = templateEnv.get_template(TEMPLATE_FILE)
outputText = template.render(ext_atr_data = ext_atr_data)  # this is where to put args to the template renderer

inv_file = open("network_request_form.html", "w")
inv_file.write(outputText)
