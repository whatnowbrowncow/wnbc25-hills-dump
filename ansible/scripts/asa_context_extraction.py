#!/usr/bin/python3

import sys, getopt
import yaml, csv
from ciscoconfparse import CiscoConfParse
from pprint import pprint


def ListContexts(config_lines):
    context_list = list()
    for context in CiscoConfParse(config_lines).find_objects(r"^context"):
        ##Clean up the output so that only the context name is returned
        #print(context.text.split()[1])
        context_list.append(str(context.text.split()[1]))

    return context_list

def ContextInfoDict(context_list, config_lines):
    context_dict = dict()
    #print(context_list)
    #print(config_lines)
    for context in context_list:
       #print(context)
       context_temp = CiscoConfParse(config_lines, factory=True).find_children(context)
       sub_element = dict()
       for info in context_temp:
           #print(info)
           if len(info.split()) == 1:
               if info.split()[0] == 'admin-context':
                   sub_element['admin-state'] = "{}".format(info)
               else:
                   continue
           elif info.split()[0] == 'allocate-interface':
               sub_element.setdefault(info.split()[0], []).append(info.split()[1])
           else:
               sub_element[info.split()[0]] = info.split()[1]
       context_dict[context] = sub_element

    return context_dict


def main(argv):
    #Gather options and arguments
    # The below is taken from URL: https://www.tutorialspoint.com/python/python_command_line_arguments.htm
    inputfile = ''
    outputfile = ''

    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print
        'asa_context_extraction.py -i <inputfile> -o <outputfile>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print
            'asa_context_extraction.py  -i <inputfile> -o <outputfile>'
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg

    #Open inputfile
    asa_config = open(inputfile, "r")
    #Convert inputfile to a list for use by CiscoConfParse
    asa_config_lines = asa_config.read().splitlines()

    #Create list of contexts on the system
    context_list = ListContexts(asa_config_lines)


    ##Create dictionary of context information
    context_info_dict = ContextInfoDict(context_list, asa_config_lines)
    #pprint(context_info_dict)

    ##Define the keys we want information on in a list
    clean_key_list = ['context', 'allocate-interface', 'config-url', 'admin-context']

    ##Build a list of positions from the clean_key_list list to use later in the csv section
    x = 0
    key_positions = []
    while x < len(clean_key_list):
        key_positions.append(x)
        x += 1

    ##Define the output filename format
    #output_name = inputfile.split('.')[0]+"_"+outputfile
    output_name = outputfile

    ##Output context information to a yaml file
    output_yaml = output_name+".yml"
    output_csv = output_name+".csv"
    #output_yaml = inputfile+"_"+outputfile+".yml"
    with open(output_yaml, "w") as outputf:
            outputf.write(yaml.dump(context_info_dict))


    ##Output to csv
    output_csv = output_name+".csv"
    with open(output_csv, 'w', newline='') as outputf:
        writer = csv.writer(outputf)
        ##Add a header line to the csv
        writer.writerow(clean_key_list)
        ##Add the interface info for each interface to the csv
        for context in context_info_dict.values():
            temp_list = []
            for index in key_positions:
                temp_list.append(context.get(clean_key_list[index]))
            writer.writerow(temp_list)

    return context_info_dict
    return 0

if __name__ == "__main__":
    # execute only if run as a script
    main(sys.argv[1:])

