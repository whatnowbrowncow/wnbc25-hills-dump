import datetime
import os
import re
import requests
import json
from requests.auth import HTTPBasicAuth
import sys
sys.path.append('do-shared-python-functions/pipeline/')

from cryptography.fernet import Fernet

def decrypt_password(key, encrypted_password):
    key = bytes(key.encode(encoding="utf-8"))
    cipher_suite = Fernet(key)
    encrypted_password = encrypted_password.encode(encoding="utf-8")
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode(encoding="utf-8")
    return decrypted_password


def create_jira(issue_dict):
    create_task = requests.post(jira_issue_api_url, auth=HTTPBasicAuth(jira_username, jira_password), json=issue_dict)#, proxies=proxyDict)
    issue_key = create_task.json()['key']
    return issue_key


if __name__ == '__main__':
    decryption_key = 'mm12x59AehSx517oE2-MZIF8BUelnbio22PiaIPSUaA='
    #jira_username = 'svc_jiranetworks'
    #jira_encrypted_password = 'gAAAAABgv1-EHJ7zyvZ6ccsuMJdBPNQ6tNt7WWQ-V7kzQig3mU_RPf8crVQpU5x1GRJbNLv1EjEDMYxUbWMonlEG4XXV1goFmg=='
    #jira_password = decrypt_password(decryption_key,  jira_encrypted_password)
    jira_username = 'dburton'
    jira_password = 'blah blah blah'
    jira_base_url = 'https://jira.willhillatlas.com/'
    jira_issue_api_url = jira_base_url+'rest/api/2/issue/'
    project_key = 'NETWORKTM'
    epic = 'NETWORKTM-1726'
    issues_list = []
    ########################
    #  Create Racecourse Tickets
    ########################
    # List of users to process
    rc_lines = ["Newmarket UNIT 1 ROWLEY king Charles statue","Newmarket UNIT 2 ROWLEY grandstand","Newmarket UNIT 3 ROWLEY grandstand","Newmarket UNIT 4 JULY SHARPO BAR","Newmarket UNIT 6 JULY MARWELL BAR","Newton Abbot UNIT 1 BAR","Newton Abbot UNIT 2","Perth","Ripon 1","Ripon 2","Ripon 4","Thirsk (Shrimp & Stirrup)","Wetherby Unit 1 - Betting shop","Wetherby Unit 2","York 1 - Centre course","York 2","York 3 - Champagne lawn","York 4","York 5 - Main Hall","York 6 - Melrose","York 7 - Theakstons Bar"]
    tickets = ["Router / switch configuration","Site installation"] 
    for line in rc_lines:
        for ticket in tickets:
        # Loop through list 2 times to create week 1 and week 2 training tickets
        #for n in range(1,3):
            issue_title = '{} - {}'.format(ticket,line)
            issue_desc = '{} for {}'.format(ticket,line)
            issue_dict = {
                "fields": {
                        "assignee": {
                                "name": None
                        },
                        "reporter": {
                                "name": 'rmarsden'
                        },
                        "summary": issue_title,
                        "description": issue_desc,
                        "customfield_12120": epic,
                        "issuetype": {
                                "name": 'User Story'
                        },
                        "project": {
                                "key": project_key
                        }
                }
            }
            debug_output = json.dumps(issue_dict,indent=8)
            print(debug_output)
            issue_key = create_jira(issue_dict)
            issues_list.append(issue_key)
    print('The following tickets have been created:')
    for issue in issues_list:
        print('- https://jira.willhillatlas.com/browse/{}'.format(issue))