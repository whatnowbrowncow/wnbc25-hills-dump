#!/usr/bin/python3

import sys, getopt
import yaml, csv
from ciscoconfparse import CiscoConfParse
from pprint import pprint


def list_interfaces(config_lines):
    interface_list = list()
    for interface in CiscoConfParse(config_lines).find_objects(r"interface"):
        ##Clean up the output so that only the interface name is returned
        #print(interface.text.split()[1])
        interface_list.append(str(interface.text.split()[1]))

    return interface_list

def interface_info(interface_list, config_lines):
    interface_dict = dict()
    #print(interface_list)
    #print(config_lines)
    for interface in interface_list:
       interface_temp = CiscoConfParse(config_lines, factory=True).find_children(interface)
       sub_element = dict()
       sub_element.setdefault('admin-state', 'up')
       for info in interface_temp:
           #print(info.split())
           if len(info.split()) == 1:
               if info.split()[0] == 'shutdown':
                   print(info)
                   sub_element['admin-state'] = "{}".format(info)
               else:    
                   continue
           elif info.split()[0] == 'ip':
               sub_element['ip-add'] = "{}".format(info.split()[2])
               sub_element['netmask'] = "{}".format(info.split()[3])
           else:
               sub_element[info.split()[0]] = info.split()[1]
       interface_dict[interface] = sub_element

    return interface_dict

    
def main(argv):
    #Gather options and arguments
    # The below is taken from URL: https://www.tutorialspoint.com/python/python_command_line_arguments.htm
    inputfile = ''
    outputfile = ''

    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print
        'asa_interface_extraction.py -i <inputfile> -o <outputfile>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print
            'asa_interface_extraction.py  -i <inputfile> -o <outputfile>'
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg

    #Open inputfile
    asa_config = open(inputfile, "r")
    #Convert inputfile to a list for use by CiscoConfParse
    asa_config_lines = asa_config.read().splitlines()

    
    #Create list of interfaces on the system
    inter_list = list_interfaces(asa_config_lines)


    ##Create dictionary of interface information
    inter_dict = interface_info(inter_list, asa_config_lines)
    #pprint(inter_dict)

    
    ##Split the inputfile name of any directories
    input_name = inputfile.split('/')[-1]

 
    ##Define the keys we want information on in a list
    clean_key_list = ['admin-state', 'description', 'interface', 'ip-add', 'mac-address', 'nameif', 'netmask', 'security-level']

    
    ##Build a list of positions from the clean_key_list list to use later in the csv section
    x = 0
    key_positions = []
    while x < len(clean_key_list):
        key_positions.append(x)
        x += 1

        
    ##Define the output filename
    output_name = outputfile

    
    ##Output interface information to a yaml file
    output_yaml = output_name+".yml"
    output_csv = output_name+".csv"
    #output_yaml = inputfile+"_"+outputfile+".yml"
    with open(output_yaml, "w") as outputf:
            outputf.write(yaml.dump(inter_dict))


    ##Output to csv
    output_csv = output_name+".csv"
    with open(output_csv, 'w', newline='') as outputf:
        writer = csv.writer(outputf)
        ##Add a header line to the csv
        writer.writerow(clean_key_list)
        ##Add the interface info for each interface to the csv
        for interface in inter_dict.values():
            temp_list = []
            for index in key_positions:
                temp_list.append(interface.get(clean_key_list[index]))
            writer.writerow(temp_list)

    return inter_dict
    return 0

if __name__ == "__main__":
    # execute only if run as a script
    main(sys.argv[1:])
