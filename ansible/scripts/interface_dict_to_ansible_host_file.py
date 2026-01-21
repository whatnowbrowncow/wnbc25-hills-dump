#!/usr/bin/python3

import sys, getopt
import yaml, csv
from os import listdir
from pprint import pprint



def main(argv):
    # Script to take in a yaml formatted file and output a yaml host file for use in ansible
    
    # Gather options and arguments
    # The below is taken from URL: https://www.tutorialspoint.com/python/python_command_line_arguments.htm
    inputfile = ''
    # directory = ''

    try:
        opts, args = getopt.getopt(argv, "hd:i:", ["idirectory=", "ifile="])
    except getopt.GetoptError:
        print
        'show_inventory_parser.py {-i <inputfile> | -d <directory/path>}'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print
            'show_inventory_parser.py  {-i <inputfile> | -d <directory/path>}'
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-d", "--idirectory"):
            directory = arg


    file_list = list()
    if inputfile:
        file_list.append(inputfile)
    elif directory:
        file_list = listdir(directory)
        path = directory+"/"
    else:
        print("Something went wrong, check the input filename or directory you passed in.")
    
    
    file for file in file_list if file.split(".")[-1] == "yml":
        try:
            loaded_yaml = yaml.load(file)
            pprint(loaded_yaml)
        except:
            print("Unabel to load the yaml file")
            return 1
    
    return 0
    
if __name__ == "__main__":
    main(sys.argv[1:])
