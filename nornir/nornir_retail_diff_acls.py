#! /usr/bin/env python
# Modules
import re
import json
from rich.console import Console
from rich.table import Table
from tokenize import String
import difflib
from pprint import pprint


# Variables
config_files = {'retail':"./config_files/retail_dmvpn_config.yaml",
                 'oob'  :"./config_files/oob_dmvpn_config.yaml"}

config_file = "./config_files/retail_config.yaml"

new_acls = {
    '102':'''access-list 102 remark Allow ICMP
access-list 102 permit icmp any any
access-list 102 remark Remote Store Subnets
access-list 102 deny   ip any 10.160.0.0 0.7.255.255
access-list 102 deny   ip any 10.93.0.0 0.0.255.255
access-list 102 deny   ip any 10.94.0.0 0.0.255.255
access-list 102 deny   ip any 10.95.0.0 0.0.255.255
access-list 102 deny   ip any 10.96.0.0 0.0.255.255
access-list 102 permit ip any any
''',
    '141':'''access-list 141 remark Allow ICMP
access-list 141 permit icmp any any
access-list 141 remark Store to Store Voip Calls
access-list 141 permit udp any 10.163.0.0 0.0.255.255 range 16384 32767
access-list 141 remark Remote Store Subnets
access-list 141 deny   ip any 10.160.0.0 0.7.255.255
access-list 141 deny   ip any 10.93.0.0 0.0.255.255
access-list 141 deny   ip any 10.94.0.0 0.0.255.255
access-list 141 deny   ip any 10.95.0.0 0.0.255.255
access-list 141 deny   ip any 10.96.0.0 0.0.255.255
access-list 141 permit ip any any
'''}

golden_config = {
    'sub_interfaces':['10','140','180'],
    'acls':{
        '101':{
        'vlans':['1','10'],
        'acl':'''access-list 101 remark Local Store Subnet
access-list 101 permit ip 10.94.247.96 0.0.0.31 10.94.247.96 0.0.0.31
access-list 101 remark Remote Store Subnets
access-list 101 deny   ip any 10.93.0.0 0.0.255.255
access-list 101 deny   ip any 10.94.0.0 0.0.255.255
access-list 101 deny   ip any 10.95.0.0 0.0.255.255
access-list 101 permit ip any any
'''},
        '140':{
        'vlans':['140'],
        'acl':'''access-list 140 permit udp any host 10.112.208.11 eq bootps
access-list 140 permit udp any host 10.120.193.235 eq bootps
access-list 140 permit udp any host 10.112.208.11 eq bootpc
access-list 140 permit udp any host 10.120.193.235 eq bootpc
access-list 140 permit udp any host 255.255.255.255 eq bootps
access-list 140 permit udp any host 255.255.255.255 eq bootpc
access-list 140 permit udp any host 10.112.208.11 eq domain
access-list 140 permit udp any host 10.112.208.12 eq domain
access-list 140 permit udp any host 10.120.193.235 eq domain
access-list 140 permit udp any host 10.120.193.236 eq domain
access-list 140 permit tcp any host 10.112.208.11 eq domain
access-list 140 permit tcp any host 10.112.208.12 eq domain
access-list 140 permit tcp any host 10.120.193.235 eq domain
access-list 140 permit tcp any host 10.120.193.236 eq domain
access-list 140 permit udp any host 10.120.194.70 eq tftp
access-list 140 permit udp any host 10.120.194.71 eq tftp
access-list 140 permit udp any host 10.210.194.71 eq tftp
access-list 140 permit tcp any host 10.120.194.70 eq 2443
access-list 140 permit tcp any host 10.120.194.71 eq 2443
access-list 140 permit tcp any host 10.210.194.71 eq 2443
access-list 140 permit tcp any host 10.120.194.70 eq 2445
access-list 140 permit tcp any host 10.120.194.71 eq 2445
access-list 140 permit tcp any host 10.210.194.71 eq 2445
access-list 140 permit tcp any host 10.120.194.70 eq 3804
access-list 140 permit tcp any host 10.120.194.71 eq 3804
access-list 140 permit tcp any host 10.210.194.71 eq 3804
access-list 140 permit tcp any host 10.120.194.70 eq 5060
access-list 140 permit tcp any host 10.120.194.71 eq 5060
access-list 140 permit tcp any host 10.210.194.71 eq 5060
access-list 140 permit tcp any host 10.120.194.70 eq 5061
access-list 140 permit tcp any host 10.120.194.71 eq 5061
access-list 140 permit tcp any host 10.210.194.71 eq 5061
access-list 140 permit udp any host 10.120.194.70 eq 5061
access-list 140 permit udp any host 10.120.194.71 eq 5061
access-list 140 permit udp any host 10.210.194.71 eq 5061
access-list 140 permit tcp any host 10.120.194.70 eq 6970
access-list 140 permit tcp any host 10.120.194.71 eq 6970
access-list 140 permit tcp any host 10.210.194.71 eq 6970
access-list 140 permit tcp any host 10.120.194.70 eq 8080
access-list 140 permit tcp any host 10.120.194.71 eq 8080
access-list 140 permit tcp any host 10.210.194.71 eq 8080
access-list 140 permit udp any host 10.120.194.70 range 16384 32767
access-list 140 permit udp any host 10.120.194.71 range 16384 32767
access-list 140 permit udp any host 10.210.194.71 range 16384 32767
access-list 140 permit tcp any host 10.120.194.70 eq 2000
access-list 140 permit tcp any host 10.120.194.71 eq 2000
access-list 140 permit tcp any host 10.210.194.71 eq 2000
access-list 140 permit udp any any range 16384 32767
access-list 140 permit tcp any any eq 5060
access-list 140 permit icmp any 10.120.194.64 0.0.0.63
access-list 140 permit tcp any eq 443 10.120.194.64 0.0.0.63
access-list 140 permit udp any host 10.19.2.140 eq tftp
access-list 140 permit tcp any host 10.19.2.140 eq 2443
access-list 140 permit tcp any host 10.19.2.140 eq 2445
access-list 140 permit tcp any host 10.19.2.140 eq 3804
access-list 140 permit tcp any host 10.19.2.140 eq 5060
access-list 140 permit tcp any host 10.19.2.140 eq 5061
access-list 140 permit udp any host 10.19.2.140 eq 5061
access-list 140 permit tcp any host 10.19.2.140 eq 6970
access-list 140 permit tcp any host 10.19.2.140 eq 8080
access-list 140 permit udp any host 10.19.2.140 range 16384 32767
access-list 140 permit tcp any host 10.19.2.140 eq 2000
access-list 140 permit udp any host 10.19.2.141 eq tftp
access-list 140 permit tcp any host 10.19.2.141 eq 2443
access-list 140 permit tcp any host 10.19.2.141 eq 2445
access-list 140 permit tcp any host 10.19.2.141 eq 3804
access-list 140 permit tcp any host 10.19.2.141 eq 5060
access-list 140 permit tcp any host 10.19.2.141 eq 5061
access-list 140 permit udp any host 10.19.2.141 eq 5061
access-list 140 permit tcp any host 10.19.2.141 eq 6970
access-list 140 permit tcp any host 10.19.2.141 eq 8080
access-list 140 permit udp any host 10.19.2.141 range 16384 32767
access-list 140 permit tcp any host 10.19.2.141 eq 2000
access-list 140 permit icmp any 192.168.0.0 0.0.15.255
access-list 140 permit icmp any 192.168.48.0 0.0.15.255
access-list 140 permit tcp any eq 443 192.168.0.0 0.0.15.255
access-list 140 permit tcp any eq 443 192.168.48.0 0.0.15.255
'''},
        '141':{
        'vlans':['140'],
        'acl':'''access-list 141 remark Allow ICMP
access-list 141 permit icmp any any
access-list 141 remark Store to Store Voip Calls
access-list 141 permit udp any 10.163.0.0 0.0.255.255 range 16384 32767
access-list 141 remark Remote Store Subnets
access-list 141 deny   ip any 10.160.0.0 0.7.255.255
access-list 141 deny   ip any 10.93.0.0 0.0.255.255
access-list 141 deny   ip any 10.94.0.0 0.0.255.255
access-list 141 deny   ip any 10.95.0.0 0.0.255.255
access-list 141 deny   ip any 10.96.0.0 0.0.255.255
access-list 141 permit ip any any
'''},
        '180':{
        'vlans':['180'],
        'acl':'''access-list 180 remark Guest WiFi ACL
access-list 180 permit udp any host 10.112.208.11 eq bootps
access-list 180 permit udp any host 10.120.193.235 eq bootps
access-list 180 permit udp any host 10.112.208.11 eq bootpc
access-list 180 permit udp any host 10.120.193.235 eq bootpc
access-list 180 permit udp any 10.167.0.0 0.0.255.255 eq bootps
access-list 180 permit udp any 10.167.0.0 0.0.255.255 eq bootpc
access-list 180 permit udp any host 255.255.255.255 eq bootps
access-list 180 permit udp any host 255.255.255.255 eq bootpc
access-list 180 permit udp any host 10.112.208.11 eq domain
access-list 180 permit udp any host 10.112.208.12 eq domain
access-list 180 permit udp any host 10.120.193.235 eq domain
access-list 180 permit udp any host 10.120.193.236 eq domain
access-list 180 permit tcp any host 10.112.208.11 eq domain
access-list 180 permit tcp any host 10.112.208.12 eq domain
access-list 180 permit tcp any host 10.120.193.235 eq domain
access-list 180 permit tcp any host 10.120.193.236 eq domain
access-list 180 permit udp any 109.144.192.128 0.0.0.63 eq 5246
access-list 180 permit udp any 109.144.192.128 0.0.0.63 eq 5247
access-list 180 permit udp any 217.39.0.128 0.0.0.63 eq 5246
access-list 180 permit udp any 217.39.0.128 0.0.0.63 eq 5247
'''}
}}

# Body
if __name__ == "__main__":
    ## Initiate Nornir
    

    #print('Diffing ACLs')
    #filepath = './unique_retail_acls.json'
    #with open(filepath) as json_file: 
    #    unique_acls=json.load(json_file)
    #    for acl in golden_config['acls'].keys():
    #        if acl != '101':
    #            #print('looking for ACL '+str(acl)+'.......')
    #            for group_acl,groups in unique_acls.items():
    #                if str(re.sub(' \[.*\]','',group_acl)) == acl:
    #                    for group in groups:
    #                        if str(re.sub(' \[.*\]','',group)) != 'not found on':
    #                            d = difflib.Differ()
    #                            diff = list(d.compare(golden_config['acls'][acl]['acl'].splitlines(),unique_acls[group_acl][group]['rules'].splitlines()))
    #                            diff = list(line for line in diff if not line.startswith(' '))
    #                            pprint(diff)




    print('Diffing ACLs')
    filepath = './lab_combined_data.json'
    with open(filepath) as json_file: 
        combined_data=json.load(json_file)

    print('Processing unique ACLs')
    unique_acls={}
    for acl in golden_config['acls'].keys():
        device_count = 0
        unique_acls[acl]={}
        unique_acls[acl]['not found on']=[]
        numberfound = 0
        for device,data in combined_data.items():
            acl_found = False
            for interface in data.keys():
                if data[interface]['acl'] != 'none configured' and acl in data[interface]['acl'].keys() and data[interface]['vlan'] in golden_config['acls'][acl]['vlans']:
                    device_count = device_count +1
                    acl_found = True
                    #try:
                    for item in unique_acls[acl]:
                        if item != 'not found on':
                            device_acl = data[interface]['acl'][str(acl+'-acl')].splitlines()
                            unique_acl = unique_acls[acl][item]['rules'].splitlines()
                            if set(device_acl)==set(unique_acl):
                                unique_acls[acl][item]['devices'].append(device)
                                break
                    else:
                            
                        #if rules not in unique_acls_list:
                        unique_acls[acl][str(numberfound+1)] = {}
                        unique_acls[acl][str(numberfound+1)]['rules'] = data[interface]['acl'][str(acl+'-acl')]
                        unique_acls[acl][str(numberfound+1)]['devices'] = []
                        unique_acls[acl][str(numberfound+1)]['devices'].append(device)
                        numberfound = numberfound + 1
                    #except:
                        #print('failed for '+str(device))
            if acl_found == False:
                #print('couldnt find '+ str(acl) + ' on '+str(device))
                unique_acls[acl]['not found on'].append(device)
        unique_acls[acl]['device_count'] = device_count
    
    
    
    unique_acls1 = {}
    for acl in unique_acls:
        aclname = str(acl)+' ['+str(unique_acls[acl]['device_count'])+' device(s)]'
        unique_acls1[aclname]={}
        for group in unique_acls[acl]:
            if group != 'device_count' and group != 'not found on':
                group_name = 'group '+str(group)+' ['+str(len(unique_acls[acl][group]['devices']))+' device(s)]' 
                unique_acls1[aclname][group_name] = {}
                unique_acls1[aclname][group_name]['devices'] = unique_acls[acl][group]['devices']
                unique_acls1[aclname][group_name]['rules'] = unique_acls[acl][group]['rules']
        not_found_name = 'not found on ['+str(len(unique_acls[acl]['not found on']))+' device(s)]'
        unique_acls1[aclname][not_found_name] = unique_acls[acl]['not found on']
    unique_acls = unique_acls1

    filepath = './unique_retail_test_acls.json'
    with open(filepath, "w") as outfile: 
        json.dump(unique_acls, outfile)


    for acl in golden_config['acls'].keys():
        if acl != '101':
            #print('looking for ACL '+str(acl)+'.......')
            for group_acl,groups in unique_acls.items():
                if str(re.sub(' \[.*\]','',group_acl)) == acl:
                    for group in groups:
                        if str(re.sub(' \[.*\]','',group)) != 'not found on':
                            print('checking '+group)
                            golden_list = golden_config['acls'][acl]['acl'].splitlines()
                            acl_list = unique_acls[group_acl][group]['rules'].splitlines()
                            if set(golden_list)==set(acl_list):
                                print('++++++++++++acls match even if not in correct order!!!++++++++++')
                            else:
                                print('--------------acls do not match even out of order!!!------------')
                                print('---------------------checking for differences-------------------')
                                for line in golden_list:
                                    if line not in acl_list:
                                        print('Line missing from device acl list: '+line)
                                for line in acl_list:
                                    if line not in golden_list:
                                        print('Line missing from golden acl list: '+line)

                                    #d = difflib.Differ()
                                    #diff = list(d.compare(golden_config['acls'][acl]['acl'].splitlines(),unique_acls[group_acl][group]['rules'].splitlines()))
                                    #diff = list(line for line in diff if not line.startswith(' '))
                                    #pprint(diff)
                                #except Exception as e:
                                    #print(e)
                            #else:
                            #    print(str(acl)+' not found on this device')

    
    
        
    
        #print(a)
    


    
