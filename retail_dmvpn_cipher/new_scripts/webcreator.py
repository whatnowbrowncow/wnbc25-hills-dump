import pandas as pd
from weasyprint import HTML
import os

# Example nested dictionary
data = {
    "Device1": {"Status": "OK", "Temperature": "35", "Online": "Yes"},
    "Device2": {"Status": "FAIL", "Temperature": "75", "Online": "No"},
    "Device3": {"Status": "OK", "Temperature": "50", "Online": "Yes"},
}

failed_hosts = {"mollison_router": "TCP connection to device failed.",
 "aintreeequestriancentre1(main)_router": "TCP connection to device failed.",
 "cheltenhamunit3suncentrecourse_router": "TCP connection to device failed.",
 "cheltenhamunit8bestmate_router": "TCP connection to device failed.",
 "cheltenhamunit9guinness_router": "TCP connection to device failed.",
 "exeter_router": "TCP connection to device failed.",
 "newmarketunit2rowleygrandstand_router": "TCP connection to device failed.",
 "newmarketunit3rowleygrandstand_router": "TCP connection to device failed.",
 "newmarketunit5julypaddock_router": "TCP connection to device failed.",
 "plumpton2_router": "TCP connection to device failed.",
 "pontefractunit2_router": "TCP connection to device failed.",
 "cardiffcityconcentrator1_router": "TCP connection to device failed.",
 "cardiffcityconcentrator2_router": "TCP connection to device failed.",
 "cardiffcitystadiumunit1_router": "TCP connection to device failed.",
 "cardiffcitystadiumunit2_router": "TCP connection to device failed.",
 "cardiffcitystadiumunit3_router": "TCP connection to device failed.",
 "cardiffcitystadiumunit4_router": "TCP connection to device failed.",
 "cardiffcitystadiumunit5_router": "TCP connection to device failed.",
 "celticparkunit3_router": "TCP connection to device failed.",
 "celticparkhospitalitybettingareaunit4_router": "TCP connection to device failed.",
 "rangersunit2_router": "Authentication to device failed.",
 "rangersunit10_router": "TCP connection to device failed.",
 "lightandwonder(oldham)(wasscientificgames)_router": "TCP connection to device failed.",
 "4gtestconnection1_router": "TCP connection to device failed.",
 "4gtestconnection2_router": "TCP connection to device failed.",
 "4gtestconnection3_router": "TCP connection to device failed.",
 "4gtestconnection4_router": "TCP connection to device failed.",
 "4gtestconnection5_router": "TCP connection to device failed.",
 "4gtestconnection6_router": "TCP connection to device failed.",
 "4gtestconnection7_router": "TCP connection to device failed."}
configs_aplied = {"birstall_router": ["ip multicast-routing distributed", "", "ip access-list standard acl-retail-ssm", "10 permit 239.0.0.0 0.0.0.255", "", "ip pim ssm range acl-retail-ssm", "", "int tunnel 11", "ip pim sparse-mode", "", "int tunnel 12", "ip pim sparse-mode", "Interface GigabitEthernet0/0/0.160", "ip pim sparse-mode", "ip igmp version 3", "", "end"], 
"anlaby_router": ["ip multicast-routing distributed", "", "ip access-list standard acl-retail-ssm", "10 permit 239.0.0.0 0.0.0.255", "", "ip pim ssm range acl-retail-ssm", "", "int tunnel 11", "ip pim sparse-mode", "", "int tunnel 12", "ip pim sparse-mode", "Interface GigabitEthernet0/0/0.160", "ip pim sparse-mode", "ip igmp version 3", "", "end"]}
# Function to get color for a value
def get_color(value):
    value = str(value).lower()
    if value in ["ok", "yes", "true", "on"]:
        return "green"
    elif value in ["fail", "no", "false", "off"]:
        return "red"
    try:
        return "green" if float(value) < 60 else "red"
    except ValueError:
        return "black"

# Generate HTML content
html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Device Status Report</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        details { margin-bottom: 15px; }
        summary { font-size: 1.2em; font-weight: bold; cursor: pointer; }
        table { border-collapse: collapse; width: 60%; margin-top: 10px; }
        th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        h1 { margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Device Status Report</h1>
"""

# Add each device as collapsible section
for device, attrs in configs_aplied.items():
    html += f"<details><summary>{device}</summary><table><tr><th>Config Applied</th></tr>"
    for value in attrs:
        color = "green"
        key = "Config Applied"
        if value != "":
            html += f"<tr><td style='color:{color}'>{value}</td></tr>"
    html += "</table></details>"
color="red"
html += "<h2>🚨 Failed Devices</h2>"
html += "<ul>"
html += "The following devices failed to complete:"
html += "<ul>"
for device, value in failed_hosts.items():
    html += f"<li><strong>{device}</strong>: <span class='failed'style='color:{color}'>{value}</span></li>"
html += "</ul>"
html += "</body></html>"

# Write HTML file
html_file = "device_report.html"
with open(html_file, "w", encoding="utf-8") as f:
    f.write(html)

print(f"✅ HTML report generated: {html_file}")

# Convert to PDF using WeasyPrint
pdf_file = "device_report.pdf"
HTML(string=html).write_pdf(pdf_file)
print(f"✅ PDF report generated: {pdf_file}")

## Convert to Excel using pandas
## Flatten nested dict
#rows = []
#for device, attributes in data.items():
#    row = {"Device": device}
#    row.update(attributes)
#    rows.append(row)
#
#df = pd.DataFrame(rows)
#excel_file = "device_report.xlsx"
#df.to_excel(excel_file, index=False, engine='openpyxl')
#print(f"✅ Excel report generated: {excel_file}")

# Optionally, open the HTML in a browser
#import webbrowser
#webbrowser.open('file://' + os.path.realpath(html_file))
