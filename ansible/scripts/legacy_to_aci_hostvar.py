#!/usr/bin/python3

import sys, getopt
from pathlib import Path
import yaml
import ipaddress
import os

def get_network_addr(gateway,netmask):
    gateway_netmask = "{gateway}/{netmask}".format(gateway=gateway,netmask=netmask)
    #Pass in the gateway_netmask string, convert this to an IPv4Network, then access the network_address value
    network_addr = str(ipaddress.IPv4Interface(gateway_netmask).network.network_address)
    return network_addr

def get_cidr_prefix(gateway,netmask):
    gateway_netmask = "{gateway}/{netmask}".format(gateway=gateway,netmask=netmask)
    #Pass in the gateway_netmask string, convert this to an IPv4Network, then access the prefixlen value
    cidr_prefix = str(ipaddress.IPv4Interface(gateway_netmask).network.prefixlen)
    return cidr_prefix


def extract_yaml(yaml_file):
    ####
    # Add check for yml/yaml extension and/or whether the file actually contains yaml code
    ####
    try:
        with open(str(yaml_file), "r") as contents:
            yaml_contents = yaml.safe_load(contents)
            return yaml_contents
            return 0

    except Exception:
        print("Unable to open {}".format(yaml_file))
        #handleException("Unable to open {}".format(yaml_file))
        raise
        #return 1

def legacy_to_aci_yaml_print(yaml_contents,context_name):

    print("""#############################################
Printing the aci hostvar output for {}
#############################################""".format(context_name))
    print("""
  - app_prof: '{context}'
    tenant: 'production'
    vrf: '{context}'
    bds:""".format(context=context_name.split('_')[0]))
            #Loop over the contents of the yaml interfaces and output the formatted information

    #Create dictionary to add verified contents to
    checked_contents = dict()
    #List of required keys for a valid interface
    key_list = ['admin-state','interface','ip-add','mac-address','nameif','netmask','security-level']
    #Loop through the passed in loaded yaml contents and build checked_contents dict where there is the necessary info
    for interface in yaml_contents.keys():
        if all(keys in yaml_contents[interface].keys() for keys in key_list):
    #for interface in yaml_contents.keys():
    #    if "ip-add" in yaml_contents[interface].keys():
            #print(yaml_contents.[interface])
            checked_contents[interface] = yaml_contents[interface]
        else:
            print("Required key 'ip-add' not in {} information. Skipping conversion for this interface.".format(interface))

    for key, value in checked_contents.items():
        #Get the "network" from the ip-addr/netmask values to be used in the output
        network_addr = get_network_addr(value['ip-add'],value['netmask'])
        # Get the cidr prefix from the ip-addr/netmask values to be used in the output
        cidr_prefix = get_cidr_prefix(value['ip-add'],value['netmask'])
        # Get the encap id from the interface name (key) to be used in the output
        encap_id = key.split('.')[-1]
        print(
              """      - bd: '{name}'
        network: '{network}'
        gateway: '{gateway}'
        mask: '{netmask}'
        cidr_mask: '{cidrmask}'
        scope: 'shared'
        l3_ownership: firewall
        epgs:
          - epg: '{name}'
            encap_id: '{encap_id}'
            vcenter_dynamic_vlan: true""".format(name=value['nameif'],network=network_addr,gateway=value['ip-add'],netmask=value['netmask'],cidrmask=cidr_prefix,encap_id=encap_id))

def legacy_to_aci_yaml(yaml_contents,context_name,outdirectory):
    ##Function to output the ACI yaml to a file
    #output_dir = Path(outdirectory)
    output_dir = Path.cwd() / outdirectory
    output_file = Path(output_dir / "{}_aci_yaml.yml".format(context_name))
    print("Outputting to {}".format(output_file))

    #Create dictionary to add verified contents to
    checked_contents = dict()
    #List of required keys for a valid interface
    key_list = ['admin-state','interface','ip-add','nameif','netmask','security-level']
    #Loop through the passed in loaded yaml contents and build checked_contents dict where there is the necessary info
    for interface in yaml_contents.keys():
        if all(keys in yaml_contents[interface].keys() for keys in key_list):
    #for interface in yaml_contents.keys():
    #    if "ip-add" in yaml_contents[interface].keys():
            #print(yaml_contents.[interface])
            checked_contents[interface] = yaml_contents[interface]
        else:
            print("Required keys not in {} information. Skipping conversion for this interface.".format(interface))

    with open(str(output_file), "w") as newfile:
        newfile.write("""
  - app_prof: '{context}'
    tenant: 'production'
    vrf: '{context}'
    bds:""".format(context=context_name.split('_')[0]))

        ##Loop over the contents of the yaml interfaces and output the formatted information
        for key, value in checked_contents.items():
            #Get the "network" from the ip-addr/netmask values to be used in the output
            network_addr = get_network_addr(value['ip-add'],value['netmask'])
            # Get the cidr prefix from the ip-addr/netmask values to be used in the output
            cidr_prefix = get_cidr_prefix(value['ip-add'],value['netmask'])
            # Get the encap id from the interface name (key) to be used in the output
            encap_id = key.split('.')[-1]
            ##Write out to the file
            with open(str(output_file), "a") as new_file:
                newfile.write("""
      - bd: '{context}_{name}'
        network: '{network}'
        gateway: '{gateway}'
        mask: '{netmask}'
        cidr_mask: '{cidrmask}'
        scope: 'shared'
        l3_ownership: firewall
        epgs:
          - epg: '{context}_{name}'
            encap_id: '{encap_id}'
            vcenter_dynamic_vlan: true""".format(context=context_name.split('_')[0],name=value['nameif'],network=network_addr,gateway=value['ip-add'],netmask=value['netmask'],cidrmask=cidr_prefix,encap_id=encap_id))
    return


def main(argv):
    ##Testing variables and elements
    test_yaml = "Ethernet1/8: {admin-state: up, interface: Ethernet1/8, ip-add: 10.180.129.220, nameif: management, netmask: 255.255.255.0, security-level: '100'}"
    large_test_yaml = """Port-channel1.1650: {admin-state: up, interface: Port-channel1.1650, ip-add: 10.61.215.196,
  mac-address: 0200.0101.0501, nameif: internal-vrf, netmask: 255.255.255.248, security-level: '100'}
Port-channel1.2122: {admin-state: up, interface: Port-channel1.2122, ip-add: 10.61.10.1,
  mac-address: 0200.0101.0501, nameif: server-mgmt, netmask: 255.255.254.0, security-level: '100'}
Port-channel1.2123: {admin-state: up, interface: Port-channel1.2123, ip-add: 10.61.13.1,
  mac-address: 0200.0101.0501, nameif: mano, netmask: 255.255.255.0, security-level: '100'}
Port-channel1.2124: {admin-state: up, interface: Port-channel1.2124, ip-add: 10.61.12.1,
  mac-address: 0200.0101.0501, nameif: core-services, netmask: 255.255.255.0, security-level: '100'}
Port-channel1.2125: {admin-state: up, interface: Port-channel1.2125, ip-add: 10.61.15.1,
  mac-address: 0200.0101.0501, nameif: jumphosts, netmask: 255.255.255.0, security-level: '100'}
Port-channel1.30: {admin-state: ' shutdown', interface: Port-channel1.30, ip-add: 10.61.8.1,
  mac-address: 0200.0101.0501, nameif: vsphere, netmask: 255.255.254.0, security-level: '100'}"""
    #loaded_yaml = yaml.safe_load(large_test_yaml)
    #test_yaml_func()
    #loaded_yaml = extract_yaml("asaconfig_2_output.yml")
    #legacy_to_aci_yaml(loaded_yaml, "asaconfig")

    ##End fo Testing variables and elements


    # Gather options and arguments
    # The below is taken from URL: https://www.tutorialspoint.com/python/python_command_line_arguments.htm
    inputfile = ''
    directory = ''

    try:
        opts, args = getopt.getopt(argv, "hd:i:o:", ["indirectory=", "infile=", "outdirectory="])
    except getopt.GetoptError:
        print
        'legacy_to_aci_hostvar.py {-d <directory/path> | -i <inputfile> } -o <output directory/path>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print
            'legacy_to_aci_hostvar.py {-d <directory/path> | -i <inputfile> } -o <output directory/path>'
            sys.exit()
        elif opt in ("-i", "--infile"):
            inputfile = arg
        elif opt in ("-d", "--indirectory"):
            indirectory = arg
        elif opt in ("-o", "--outdirectory"):
            outdirectory = arg

    file_list = []

    if inputfile:
        ##Convert the inputfile to a Path
        input_full_path = Path(inputfile)
        ##Split the inputfile name from any directories using Path.parts
        input_filename = input_full_path.parts[-1]
        ##Split the directory from the file using Path.parent
        input_directory = input_full_path.parent
        file_list.append(input_filename)
        #print("The input filename is {}".format(input_filename))
        #print("The input directory path is {}".format(input_directory))


    elif indirectory:
        file_list = []
        input_directory = Path(indirectory)
        ##Search the directory for non-yml files and remove them from the list
        for r, d, f in os.walk(indirectory):
            for file in f:
                if '.yml' in file:
                    file_list.append(file)
        print("The identified yml files are: {}".format(file_list))
        print("The input directory path is {}".format(input_directory))
        dir_path = Path.cwd() / input_directory

    else:
        print("Unable to complete action")
        sys.exit(1)


    ##Get the full path to the folder with the yaml files in it
    dir_path = Path.cwd() / input_directory
    print(dir_path)

    ##Loop over the file_list to extract and convert the contents of each file
    for file in file_list:
        #print(file.split('_')[0])
        try:
            loaded_yaml = extract_yaml(dir_path / file)
        except:
            print("No accessible file to load yaml from.")
            continue

        ##Output the formatted ACI yaml to screen
        #legacy_to_aci_yaml_print(loaded_yaml, file.split('_')[0])

        ##Output the formatted ACI yaml to files
        legacy_to_aci_yaml(loaded_yaml, file.split('_')[0], outdirectory)


if __name__ == "__main__":
    # execute only if run as a script
    main(sys.argv[1:])