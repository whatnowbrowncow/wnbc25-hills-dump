# **RAS RULE UPDATE (RAS CONSTRUCTOR SCRIPT)**

|Version | Date|Summary|Current Version|
|:---:|:---:|:---:|:---:|
|0.1|26\/08\/2021| Intial Build|
|1.0|10\/08\/2021| Added Readme, Varible Updates, Submit for Production| 
|1.1|23\/06\/2022| Added Duplicate Object Detection|
|1.2|03\/01\/2023| Added check for addition of new acls,<br>Allow Deployment of multiple ACLs,<br>Detection of changed ACLs in same hierarchy,<br>Migration of Duplicate object detection to Object Role<br> |Y|

Testing Log for Script:
https://conf.willhillatlas.com/display/netsec/RAS+ACL+-+Ras+Constructor+Module+testing

## **Reason**

The RAS Rule Update script was designed to help construct the YMLs used within the RAS Ansible Role.

The original reason for deploying the Role and the script is to, replace the cumbersome, complicated and time-consuming manual process. 

In order to update the RAS firewall rules there was a requirement to add a rule to an ACL, then repeat the rule in the same place in all the related ACLs within the hierarchy, this then needed duplicating on the related ASA FW (Further details on this procedure can be found in https://conf.willhillatlas.com/display/netsec/Applying+firewall+rules+to+the+Anyconnect+VPN+ACLs).

The issue was that we found after a short time we started to experience configuration drift between both the hierarchal rules and the individual devices. Examples of this were missing Rules between devices, missing rules between related ACLs and rules in different order between related rules.

## **Objectives**

The objective of the role and the script was to take a source of truth, for example a YML file, and then with this information.

    1. Identify the information that has changed.
    2. Compile and update the relevant related ACLs.
    3. Perform some sanity checks to make sure the devices haven’t drifted, and the YML files are correct
    4. Then if all ok deploy the rules to both devices at the same time.

---

**NOTE**

This script only looks at objectives 1,2 and 3, as the other objectives are looked after by the RAS Ansible role

---
One of the other key objectives, is that there is a single point of truth for each of the ACLs and this should be easy and simple to update by an engineer.

## **How does it work?**

### **Example**

An example of how you call the script is as follows\
`python3 ras_acl_constructor.py -i <Inventory> -l (optional)<Log Level>`\
i.e. \
`python3 ras_acl_constructor.py -i /gitnet/test_network_inventory/environments/prod/ -l debug`

After you run the script, it will take the inventory (-i) and logging (-l) variables defined within the command line, and pass both these to the script as the inventory and log level variable respectively. The default variables, i.e. if none is specified, are

|Variable | Data|
|:---:|:---:|
|-i or –-inventory |/gitnet/network_inventory/environments/dev/|
|-l or --level|warn|

## **Walkthrough**


The script starts in ras_acl_constructor.py, which is broken down into several sections 

---
**NOTE:**

Within the code comments each of the sections are title with the comment 

`##################################################################### STAGE x #####################################################################`

---
### **Stage 1:**
Within stage 1, The script imports all the required modules in order for the script to excecute. After that it then defines, using classes, custom exceptions in order to pass any errors back to the calling user/ansible.

### **Stage 2:**
Stage 2 is where, after being passed the input variable's from the command line, it will take this and parse them out to obtain the relevant data. These are taken and stored in relevant variables to be used throughout the script

The next step is to retrieve the current location of the python script and the current working directory, this is used later in the script to define where to put the log file and then where to obtain the current git status information.
The final  step is to confirm that 3 key directories are created.

    1. <python location>/log (The location of the scripts log file)
    2. /gitnet/ras-processed (This will be the location of all the working data for the role)
    3. /gitnet/ras-processed/data - This is the location of the RAS data files to be used by the role after they are compiled
Finally, clear any existing log file, then define how and where any logging should be written to.

### **Stage 3**
Stage 3 is the meat and bones of the script and is where all the main processing starts

This stage is all compiled within a function called full_access_check, this function accepts a parameter called inventory which is the inventory passed via the command parameter (under `-i` or `--inventory`), and called from within main.

The whole function is called within a try exception, the idea of this is to allow the capturing and passing of exceptions to ansible, in order to prevent ansible from continuing within its play if the python script should fail, particularly becuase of no ACL yml files having being changed.

>**NOTE:** If the current branch is a release branch then no exception is raised if there are no RAS ACL yml files changed.

#### **Stage 3.1**
Stage 3.1 generally covers the setup and checks of the function.

The first part of the function defines the yaml formatting when creating or updating yaml files (This is done later on in the script)

A check is then done to confirm if the inventory variable has a / at the end. This is then used later when adding the group_vars/ras path.

The script then proceeds to examine the current directory structure, using the inventory parameter, to find the .git directory then stores this in a git dir variable. This is used to allow the script to run a git diff to find out what files have changed.

The script then proceeds to obtain a list of ras acls, these are detailed in `/<inventory>/group_vars/ras/ras.yml`, it is then imported into a dictionary called `ras_list` under a key called `ras_acl`.

The ACL details are then loaded from a yaml file of the same name, located in `/<inventory>/group_vars/ras/` directory. These details are then placed in a nested dictionary called `acl_data`, each ACL will then have a key within this pertaining to the acl name i.e `acl_yaml_data[ras-itops-filter]`

<details>

<summary markdown="span"> Click Here for an example the acl dictionary </summary> 

```json
Dictionary: acl_yaml_data[ras-datamgmt-filter]
{
    "ra_vpn_filters_ras_datamgmt_filter": [
        {
            "group_policy": "datamgmt_policy",
            "ra_vpn_filter": "ras-datamgmt-filter"
        }
    ],
    "ras_datamgmt_filter": [
        {
            "name": "ras-datamgmt-filter",
            "type": "extended",
            "version": 3,
            "parents": [
                "ras-general-user-filter"
            ],
            "children": null,
            "rules": [
                {
                    "line_no": "49",
                    "action": "permit",
                    "service": {
                        "name": "datamgmt-dev-services",
                        "type": "svc_obj_grp"
                    },
                    "source": {
                        "name": "ras-{{ dc }}-pool",
                        "type": "net_obj_grp"
                    },
```
</details>
<br>

A Git diff is then performed and extracts the file names of all files updated, if the file name starts with ras- than it adds it to a list called changed_files, providing it is not in the lineage.

The next part is to obtain the hierarchy for each of the acls, so it can be used later on in obtaining the relevant ACL Rules.

This is achieved by looping through all the acls in the ras_list dictionary, it then collates the ACLs rule information key by taking the ACL name then substituting the `-` for `_`. It will then retrieve the values from the children key and storing them in a list called **children**. It then retrieves the parent key store it in a variable called parent and stores it in a list called lineage.

The next task that is performed is to retrieve the parent of the parent acl and store this in the lineage list. This loop continues until it the parent value is empty.

The last step of stage 3.1 is to take the **lineage** list and **children** list and compile it into a dictionary called **hierarchy**. This is then added to the acl_yaml_data[\<acl\>] dictionary 

#### **Stage 3.2**

Stage 3.2 is mainly involved with checking the integrity of the ACL data and hierarchy.

The script then takes all the changed_files list and loop through it to perform a few checks.

    1. Confirm if this is a new ACL, it does this by retriving the files that are in master and scanning through all the entries listed in the changed_files directory to see if the file exists, if the file does exist in master then it sets a flag of FileinMaster to True.
    2. If the FileinMaster flag is set to True, then it retrives the data from the copy of the same file in master, and compares the Data and Version to confirm they have changed.
    3. Checks the lineage of the file to confirm there are no other files in that lineage have been changed, if one is found then a error is raised and the script is halted.    
    4. A check is then performed on the list to find out if there are 0 files in the list and the script is not performing this on a release branch, if so it raises the relevant exception, displays this to the user and ends the script. - See Note below.
    5. Then Obtain all the children, grandchildren and great-grandchildren of the acls that have changed.


>**NOTE:** If this is in a release branch it adds just the ACLs within the release_update_acls varible, which means all ACLs will be classed as changed

This data will be then stored in a variable called `acl_to_change`, and contains all acls that have changed and any that require changing due to hierarchy 

#### **Stage 3.3**

Stage 3.3 is initiated by calling a function called processing, this function takes several variables containing the acl_name, acl_yaml_data dictionary, acl_to_change dictionary, inventory variable,log level and repository location.

The processing function performs several tasks, these are located within the ras_data_processing.py file and is called via an import command within the ras_acl_constructor file. 

The processing file contains several functions in order to complete, these are
* yml_key - To produce the key from the acl or file name.
* load_yml - To import yaml files into memory
* combine_rules - This is the function that does the main of the processing by combining all the rules in the hierarchy together
* append_final_yaml - This adds the 3 generic rule to the end of the data yml, i.e. Implicit deny and allow all internet access
* rules_renumber - To renumber the rules into sequential order
* output_to_data - This is to create the data yaml file and update the user based yaml files with the renumbered rules and new version number
* processing - The main section that starts the processing

Like mentioned above, this section starts with the processing function 
#### **Stage 4**
As with the full_access_check function the whole function is called within a try exception, the idea of this is to allow the capturing and passing of exceptions to ansible, in order to prevent ansible from continuing within its play if the python script should fail

The first part of the function is to setup the logging directory and formatting.

It then takes the changed acl that was passed from the full_access_check function and appends it to the acl_hierarchy list.

After this, the script loops through the acls in the acl_ hierarchy list and performs the following steps
* creates a varible call yml_path which contains the **\<inventory\>/groups_vars/ras/\<acl\>.yml**
* calls the combine_rules function, passing the name of the acl to be changed, all dependent acls, acl_data dictionary and the inventory location and places them in a variable called acl_yaml
* Calls the append_final_yaml function, passing the name of the changed acl, dependent_acl list, combined rules variable (acl_yaml) from the previous command and the branch name of the inventory repository , it then places the output of this into a variable called full_data
* calls the output_to_data_file function passing the full_data created by the command above, the yml_path, variable which contains the file location of the user yaml, the full acl data and the repository branch name

**NOTE:**

If an exception is called while anypart of this scripts is running it will output an error message to the console containing
* Location of the error log
* The file name containing the code that errored
* The line number of the error
* The error messages

It then exits the script with a error status code of **1**

### **combine_rules function**
This function takes the following information
    
|Variable | Data|
|:---:|:---:|
|changed_acl|Name of Acl to be changed|
|dependent_acl_name|Name of the dependent ACL|
|acl_data|Full ACL Data|
|inventory|Inventory Location|

Then runs the following steps

1. Extracts all ACL data from the **acl_data** dictionary, pertaining to the acl to be changed, and places it in a dictionary called **acl_yaml_data**
2. Identifies the acls key by calling the **yml_key** function and passing it the **acl** variable and places it in a variable called **acl_yaml_acl_key**
3. Using the **acl** and the **acl_yaml_acl_key** variables, extracts the rules from the **acl_yaml_data** dictionary and places them in a dictionary called **acl_rules**
4. Repeats steps 1-3 above but with the **dependent_acl**  variable instead of the **acl** variable and place the rules in a dictionary called **child_rules**
5. Creates a dictionary called **lineagedata** and adds the **child_rules** dictionary to it
6. Then extracts the lineage data from the dependent acl using the hierarchy key within the acl_data dictionary
7. After that, it loops through the lineage data extracted above and obtains all the rules for each of the acls in the lineage using the **acl_data** dictionary and place it in the **lineagedata** dictionary
8. The Final steps are to add the **lineagedata** back to the dependent_acl rules within the dictionary, put it in a dictionary called **combined_data** and pass it back to the calling function

### **append_final_yaml function**
This function takes the following information
    
|Variable | Data|
|:---:|:---:|
|changed_acl|Name of changed ACL|
|yaml_data|Data of the ACL to be processed|
|yml_path|Path to yaml file|
|inventory|Inventory Location|
|repository|Branch Name of the repository| 

Then runs the following steps

1. Identifies the acls key by calling the **yml_key** function and passing it the **yml_path** variable and places it in a variable called **yaml_acl_key**
2. Using the **load_yml** function imports the final 3 rules into a varible called **final_yml**
3. Identifies the acl rules from the **yaml_data** using the **yaml_acl_key** variable and then adds the **final_yml** rules to the end
4. Takes the updated rules set in passes them through the **renumber_rules** function to renumber the acl line number sequentially and place them in a variable called **renumbered_rules**
5. Takes the **renumbered_rules** variable and replaces the relevant rules in the **yaml_data** dictionary.
6. If the inventory repository branch is not a **release** branch and the acl is a dependent acl then it updates the version key by 1. 
7. It then passes the data back to the calling function.

### **output_to_data_file function**
This function takes the following information
    
|Variable | Data|
|:---:|:---:|
|yaml_data|Data of the ACL to be processed|
|yml_path|File location of the user based yml|
|full_data|All of the RAS acl data|
|repository|Branch Name of the repository| 

Then runs the following steps
1. Sets the yaml formatting parameters.
2. Extracts the file and directory name from the **yml_path** variable and places it into the **dir_name** and **file_name** variables
3. Creates or opens a file called **/gitnet/ras-processed/data/ansible-data-\<file_name\>** and places it in a variable called **yaml_file**
4. Adds the data from the **yaml_data** variable into this file
5. Closes the file
6. Using the **load_yml** function, it loads the data from the file located in the **yml_path** variable and places it into a dictionary called **final_yaml_file**
7. Using the **yml_key** function it extracts the acls key from the **yml_path** variable and places it into a variable called **final_yaml_key**
8. Then using the **parents** value within the **final_yaml_file** dictionary, checks if there is a **parent** acl, and if not extracts the final **line_no** variable and increments by one and places it in a variable called **final_line_no**. If there is no **Parent** value then it sets **final_line_no** to 1. This process is to get the final ACL line number of the parent and incremented by 1 then placed in the child acl
9. The final steps, when the acl is not the changed acl, the script takes the **version** value from the ACL in the **final_yaml_file** dictionary and updates by one, then writes it back to the file located in the **yml_path** variable.
   >**NOTE FOR STEPS 8 and 9 Above:** If this is in a release branch these steps are skipped



