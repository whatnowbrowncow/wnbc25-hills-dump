#!/usr/bin/python3
import getopt
import re
import sys
import ruamel.yaml
from collections.abc import Iterable

yaml = ruamel.yaml.YAML()
yaml.preserve_quotes = True

def main(argv):
   inputfile = ''
   try:
      opts, args = getopt.getopt(argv,"i:",["ifile="])
   except getopt.GetoptError:
      print('test.py -i <inputfile>')
      sys.exit(2)
   for opt, arg in opts:
      if opt in ("-i", "--ifile"):
         inputfile = arg
   return inputfile

def convert_named_ports(yaml_file):
    with open(yaml_file) as fp:
        data = yaml.load(fp)
    dict = {'aol': '5190', 'bgp': '179', 'biff': '512', 'bootpc': '68', 'bootps': '67', 'chargen': '19', 'cifs': '3020', 'citrix-ica': '1494', 'cmd': '514', 'ctiqbe': '2748', 'daytime': '13', 'discard': '9', 'dnsix': '195', 'domain': '53', 'echo': '7', 'exec': '512', 'finger': '79', 'ftp': '21', 'ftp-data': '20', 'gopher': '70', 'h323': '1720', 'hostname': '101', 'http': '80', 'https': '443', 'ident': '113', 'imap4': '143', 'irc': '194', 'isakmp': '500', 'kerberos': '750', 'klogin': '543', 'kshell': '544', 'ldap': '389', 'ldaps': '636', 'login': '513', 'lotusnotes': '1352', 'lpd': '515', 'mobile-ip': '434', 'nameserver': '42', 'netbios-dgm': '138', 'netbios-ns': '137', 'netbios-ssn': '139', 'nfs': '2049', 'nntp': '119', 'ntp': '123', 'pcanywhere-data': '5631', 'pcanywhere-status': '5632', 'pim-auto-rp': '496', 'pop2': '109', 'pop3': '110', 'pptp': '1723', 'radius': '1645', 'radius-acct': '1646', 'rip': '520', 'rsh': '514', 'rtsp': '554', 'secureid-udp': '5510', 'sip': '5060', 'smtp': '25', 'snmp': '161', 'snmptrap': '162', 'sqlnet': '1521', 'ssh': '22', 'sunrpc': '111', 'syslog': '514', 'tacacs': '49', 'talk': '517', 'telnet': '23', 'tftp': '69', 'time': '37', 'uucp': '540', 'vxlan': '4789', 'who': '513', 'whois': '43', 'www': '80', 'xdmcp': '177'}
    for objects in data['resources']['port_obj_groups']:
        if ('port_obj' in objects.keys()) and (isinstance(objects['port_obj'], Iterable)):
            for object in objects['port_obj']:
                port = object['port']
                if port in dict:
                    key = port
                    object['port'] = dict[key]
                elif '@' in port:
                    p1 = port[:port.index('@')]
                    p2 = port[port.index('@')+1:]
                    if p1 in dict and p2 in dict:
                        p1 = dict[p1]
                        p2 = dict[p2]
                        object['port'] = p1+'-'+p2
                    elif p1 in dict:
                        p1 = dict[p1]
                        object['port'] = p1+'-'+p2
                    elif p2 in dict:
                        p2 = dict[p2]
                        object['port'] = p1+'-'+p2
                    else:
                        object['port'] = p1+'-'+p2
    
    # Create new file for conversions in the format - dfw_sddc_specific_ports_conv_test.yml
    #conversion_file = re.sub('.yml', '_conv_test.yml', yaml_file)

    with open(yaml_file, 'w') as order_yaml:
        yaml.dump(data, order_yaml)

if __name__ == "__main__":
   input_file = main(sys.argv[1:])
   convert_named_ports(input_file)
