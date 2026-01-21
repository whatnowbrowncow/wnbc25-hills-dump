#!/usr/bin/python3

import sys, getopt
import csv
from os import listdir
from pprint import pprint


##Define the keys we want information on in a list for use in the csv functions
clean_key_list = ['HOSTNAME', 'DESCR', 'NAME', 'PID', 'SN', 'VID']

##Build a list of positions from the clean_key_list list for use in the csv functions
x = 0
key_positions = []
while x < len(clean_key_list):
    key_positions.append(x)
    x += 1
        

def create_raw_element_dict(raw_inventory_output):
    element_dict = dict()
    temp_element_list = list()
    for line in raw_inventory_output.readlines():
        if line == "\n":
            #clear the temp_element_list as there are no more elements in this set
            #print("Clearing the temp_element_list")
            temp_element_list = list()
        else:
            #print("This is the line value: {}".format(line))
            #Add the inventory elements to temp_element_list
            #split the line on commas
            for sub_element in line.split(','):
                #add the sub_element to the temp_element_list
                temp_element_list.append(sub_element)
                #Set the value of inv_name to be the that of "NAME"
                if temp_element_list[0].split(": ")[0].upper() == "NAME":
                    inv_name = temp_element_list[0].split(":")[1]
                    #print("The current inventory NAME is: {}".format(inv_name))
                else:
                    continue
        #print("This is the temp_element_list contents: {}".format(temp_element_list))
        #print("Adding {} as the value of {}".format(temp_element_list,inv_name))
        #Check if temp_element_list is populated and if so update the element_dict dictionary
        if temp_element_list:
            element_dict[inv_name] = temp_element_list
        else:
            continue
    
    return element_dict

    
def create_parsed_inventory_dict(raw_element_dict, hostname):
    #Clean up the element_dict dictionary so that the value of the key is a dictionary
    
    #Create a blank dictionary for the inventory information
    inventory_dict = dict()
    #print(raw_element_dict)
    for element in raw_element_dict.keys():
        temp_dict = dict()
        temp_sub_dict = dict()
        for orig_item in raw_element_dict[element]:
            item = orig_item.strip()
            #Set the first part of the filename as the "HOSTNAME" in the dictionary
            temp_dict["HOSTNAME"] = hostname
            
            #print("Printing the whitespaceless value for: {}".format(item))
            if item.split(": ")[0].upper() == "NAME":
                #print(item.split(": ")[1])
                temp_dict["NAME"] = item.split(": ")[1].strip('"')
            elif item.split(": ")[0] == "DESCR":
                #print(item.split(": ")[1])
                temp_dict["DESCR"] = item.split(": ")[1].strip('"')
            elif item.split(": ")[0] == "PID":
                #print(item.split(": ")[1])
                temp_dict["PID"] = item.split(": ")[1]
            elif item.split(":")[0] == "VID":
                if len(item.split(": ")) > 1:
                    #print(item.split(": ")[1])
                    temp_dict["VID"] = item.split(": ")[1]
                else:
                    #print("There is no VID")
                    temp_dict["VID"] = "none"
            elif item.split(":")[0] == "SN":
                ##Check for a none-blank serial number for a lack of serial number for an element
                if len(item.split(":")) > 1 and item.split(":")[-1] != "":
                    #print(item.split(":"))
                    striped_value = ""
                    striped_value = item.split(":")[-1].strip()
                    #temp_dict["SN"] = item.split(":")[-1]
                    temp_dict["SN"] = striped_value
                else:
                    #print("No serial number found, setting to 'none'")
                    temp_dict["SN"] = "none"
            else:
                #print("Skipping {} as I'm not sure what it is.".format(orig_item))
                continue
        inventory_dict[temp_dict["NAME"]] = temp_dict

    #print("Printing out the inventory: ")
    #pprint(inventory_dict)
    return inventory_dict
    
    
def output_to_csv(single_device_inventory_dict, output_csv):
    
    try:
        with open(output_csv, 'w', newline='') as outputf:
            writer = csv.writer(outputf)
            ##Add a header line to the csv
            writer.writerow(clean_key_list)
            ##Create a list of all the dictionary values
            device_inv_list = list(single_device_inventory_dict.values())
            ##Order the device inventory list by hostname, serial number, PID
            sorted_device_inv_list = sorted(device_inv_list, key = lambda i: (i['HOSTNAME'], i['SN'], i['NAME']))
            #print("Printing sorted single device inventory list:")
            #pprint(sorted_device_inv_list)
            ##Add the inventory info for each element to the csv
            #for inv_element in single_device_inventory_dict.values():
            for inv_element in sorted_device_inv_list:
                #print(inv_element)
                temp_list = []
                for index in key_positions:
                    #print("Looking for {}".format(clean_key_list[index]))
                    #print(inventory_dict.get(clean_key_list[index]))
                    temp_list.append(inv_element.get(clean_key_list[index]))
                #print(temp_list)
                writer.writerow(temp_list)
    except:
        print("Failed to write out the '{}' csv. The most likely reason is that you had the csv file open as python was trying to write to it. Close it and try again.".format(output_csv))



def master_to_csv(multi_device_inventory_dict, output_filename):
    ##Create a sorted list of the keys, which are the device hostnames, in the multi_device_inventory_dict
    sorted_inventory_keys = sorted(multi_device_inventory_dict.keys())
    #print("This is an ordered list of the device hostnames:")
    #print(sorted_inventory_keys)
 
    try:
        with open(output_filename, 'w', newline='') as outputf:
            writer = csv.writer(outputf)
            ##Add a header line to the csv
            writer.writerow(clean_key_list)
            ##Loop through each of the device inventory dictionaries in order using the sorted_inventory_keys list 
            for device_key in sorted_inventory_keys:
                #print("This is the value of {}".format(device_key))
                #print(multi_device_inventory_dict[device_key].values())
                 
                ##Order the device inventory list by hostname, serial number, PID
                sorted_device_inv_list = sorted(multi_device_inventory_dict[device_key].values(), key = lambda i: (i['HOSTNAME'], i['SN'], i['NAME']))
                #print("Printing sorted device inventory list:")
                #pprint(sorted_device_inv_list)

                ##Add the inventory info for each element to the csv
                for inv_element in sorted_device_inv_list:
                    #print(inv_element)
                    temp_list = []
                    for index in key_positions:
                        #print("Looking for {}".format(clean_key_list[index]))
                        #print(multi_device_inventory_dict.get(clean_key_list[index]))
                        temp_list.append(inv_element.get(clean_key_list[index]))
                    #print(temp_list)
                    writer.writerow(temp_list)
    except:
        print("Failed to write out the master csv. The most likely reason is that you had the csv file open as python was trying to write to it. Close it and try again.")



def main(argv):
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
    
    master_inventory_dict = dict()
    
    for file in file_list:
        #Set the hostname variable as the first part of the filename
        hostname = file.split('_inventory')[0]
        
        # Open inputfile
        try:
            if directory:
                inventory_output = open(path+file, "r")
            else:
                inventory_output = open(file, "r")
        except:
            print("Couldn't open: {}".format(file))
            return 1
        
        ##Pass the input file in for initial raw inventory extraction
        raw_element_dict = create_raw_element_dict(inventory_output)
        
        ##Parse the raw inventory dictionary to get a final clean inventory dictionary
        parsed_inventory_dict = create_parsed_inventory_dict(raw_element_dict,hostname)
        #print("Printing output for {}".format(hostname))
        #pprint(parsed_inventory_dict.keys())
        
        ##Define output filename
        #output_name = hostname+"_inventory_output"
        #output_csv = "script-outputs/inventory/"+output_name+".csv"
        #output_csv = "/home/vagrant/vagrant_data/ansible/script-outputs/inventory/"+output_name+".csv"
        
        ##Output to csv
        #final_output = output_to_csv(parsed_inventory_dict,output_csv)
        
        master_inventory_dict[hostname] = parsed_inventory_dict
        
    ##Output the master_inventory_dict to a csv
    master_output = master_to_csv(master_inventory_dict,"script-outputs/master_inventory.csv")
    
    return master_inventory_dict
    return 0
    
    
if __name__ == "__main__":
    main(sys.argv[1:])

