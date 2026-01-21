# **RAS OBJECT DATA PROCESSING SCRIPT**

|Version|Date|Summary|Current Version|
|:---:|:---:|:---:|:---:|
|1.0|02\/07\/2024|initial Build|Y|


## **Reason**

The RAS object scripts (ras-object-checks.py and ras-object-data-yaml.py) were designed to help construct the YMLs used within the RAS Ansible role.

The original reason for deploying the role and the scripts are to replace the cumbersome, complicated, and time-consuming manual process.

To update the RAS firewall rules, there is a requirement to add a rule to an ACL and then repeat the rule in the same place in all the related ACLs within the hierarchy. This then needed duplicating on the related ASA FW (Further details on this procedure can be found in this https://conf.willhillatlas.com/display/netsec/Applying+firewall+rules+to+the+Anyconnect+VPN+ACLs).

The issue was that we found after a short time, we started to experience configuration drift between both the hierarchical rules and the individual devices. Examples of this were missing rules between devices, missing rules between related ACLs, and rules in different orders between related rules.


## **Objectives**

The objective of the role and the script was to take a source of truth, such as a YML file, and then:

1. Identify the information that has changed.
2. Compile and check all objects/groups for duplicate names.
3. Compile and update the relevant related ACLs.
4. Perform some sanity checks to make sure the devices haven’t drifted.
5. If all is okay, update the primary device.
6. Update the secondary device via a Sync script overnight to allow fail over to a previous configuration if a deployment fails

---

**NOTE**

This script only looks at part of objective 2, as the other objectives are handled by the RAS Ansible role and the RAS ACL Script.

---

Another key objective is that there is a single point of truth for each of the ACLs, and this should be easy and simple to update by an engineer.

## **How does it work?**

### **Example**

An example of how you call the script is as follows:\
`python ras-object-data-yaml.py -i <Inventory> -l (optional)<Log Level> -lp (optional)<Log Path>`\
For instance:
`python ras-object-data-yaml.py -i /gitnet/test_network_inventory/environments/prod/ -l debug -lp ~/logfile.log`

After you run the script, it will take the inventory (-i), logging (-l) and log path (-lp) variables defined within the command line and pass both of these to the script as the inventory and log level variables respectively. The default variables (if none are specified) are:

|Variable | Data|
|:---:|:---:|
|-i or –-inventory |/gitnet/network_inventory/environments/dev/|
|-l or --level|notice|
|-lp or --logpath|logfile.log|


## **Walkthrough**


The script is ran from the ras-object-data-yaml.py file, which is broken down into several sections:

---
**NOTE:**

Within the code comments, each of the sections is titled with the comment:

`##################################################################### STAGE x #####################################################################`

---
### **Stage 1:  Importing Modules**
In this stage, the script imports all the required modules necessary for its execution. Most of these modules come from the WH Network Python Toolset. Here’s what happens:

Standard command-line arguments are imported which include.:
* Logging level
* Logging path

An additional command-line argument called “inventory” for specifying the location of the Ansible inventory is then imported.

These arguments are parsed and stored for later use.

The WH Network Standard Python logging module is added for producing Python script log files.

Finally, the WH Network Standard Python file functions module is included for processing YAML files.
### **Stage 2: Object Processing**
The next stage is defining of the object processing class that contains the modules used for processing of the object data and is split into 4 modules
* retrive_data:
    * This module retrieves data related to object processing. It does the following:
        * Uses the Git module to fetch commit data based on an inventory location argument.
        * Takes an object YAML file name as input.
        * Reads the YAML file and creates dictionaries:
        * If it’s old data, it retrieves data from the Git commit and stores it in a dictionary called olddata.
        * If it’s new data, it reads the YAML file and stores the data in a dictionary called newdata.

* find_dict_differences:
    * This module compares the old and new data dictionaries.
    * It loops through the data and identifies items that exist in the new data but not in the old data.
    * These differences are collected in a directory called diff.

* network_objects:
    * This module processes data into a format compatible with the Ansible Cisco asa_orgs module (used for managing ASA firewall object groups).
    * It takes both the newdata and olddata dictionaries.
    * For each host, subnet, and range within a group, it extracts changed network object group data.
    * Using a loop, it structures the data into a dictionary format that the Ansible module understands.
    * The processed data is then stored in a dictionary called yaml_data.
* svc_objects:
    * Similar to the network_objects module, this one is for processing service objects data.
    * It replaces host, subnet, and range references with objects, protocols, and services.
    * The resulting data is returned in a dictionary named yaml_data.


### **Stage 3**
Stage 3 is the meat and bones of the script and is where all the main processing starts

### **Stage 3.1: Network Objects Processing**
1. Initialization and Data Retrieval:
    * The script begins by calling a class called object_processing and passing the network object YAML location to it, this then sets up a variable called net_obj_process.
    * Using net_obj_process variable, it calls the retrieve_data function, which processes the data and extracts the new and old data to variables called olddata and newdata respectivly, after then returning it to the calling module.
2. Network Objects Processing:
    * The script then passes the olddata and newdata variables to the network_objects module. In this module, the data is further processed by discovering the object groups that exist in the new data and not in the old using the *find_dict_differences* module and the resulting data is stored in a variable called net_yaml_data.
3. File Saving:
    * The final step creates two variables called:
        * net_filename with the value ansible_network_object_data.yml
        * net_file_location with the value /gitnet/ras-processed/data
    * The script uses these variables to save the processed data (stored in net_yaml_data) to a YAML file in the specified location.
    * Finally, it informs the user that the file has been created.

### **Stage 3.2: Service Objects Processing**
1. Initialization and Data Retrieval (Similar to Stage 3.1):
    * Similar to the previous stage, the script calls the object_processing class, but this time being passed the service object yaml  file and setting up the svc_obj_process variable.
    * Using svc_obj_process variable, it calls the retrieve_data function, which processes the data and extracts the new and old data to variables called olddata and newdata respectivly, after then returning it to the calling module.
2. Service Objects Processing (Similar to Stage 3.1):
    * The script passes olddata and newdata to the svc_objects module, In this module, the data is further processed by discovering the object groups that exist in the new data and not in the old using the *find_dict_differences* module and the resulting data is stored in a variable called svc_yaml_data.
3. File Saving (Similar to Stage 3.1):
    * The final step creates two variables called:
        * svc_filename with the value ansible_service_object_data.yml
        * svc_file_location with the value /gitnet/ras-processed/data
    * The script saves the svc_yaml_data to a YAML file in the specified location.
    * It then reports back to the user that the file has been created.
### **Exception Handling:**
The entire main function is wrapped in a try-except block

If an exception occurs during execution, the script outputs an error message containing:

* Location of the error log
* File name where the error occurred
* Line number of the error
* Error message

The script then exits with an error status code of 1.