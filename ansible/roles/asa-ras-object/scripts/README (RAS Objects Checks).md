# **RAS OBJECT CHECK SCRIPT**

|Version | Date|Summary|Current Version|
|:---:|:---:|:---:|:---:|
|1.0|03\/01\/2023| Migration from RAS ACL role||
|1.1|03\/07\/2024| Update of Readme|Y|

Testing Log for Script (Completed as part of full ras deployment):
https://conf.willhillatlas.com/display/netsec/RAS+ACL+-+Ras+Constructor+Module+testing

## **Reason**

The RAS object scripts (ras-object-checks.py and ras-object-data-yaml.py) were designed to help construct the YMLs used within the RAS Ansible role.

The original reason for deploying the Role and the scripts are to, replace the cumbersome, complicated and time-consuming manual process.

In order to update the RAS firewall rules there is a requirement to add a rule to an ACL, then repeat the rule in the same place in all the related ACLs within the hierarchy, this then needed duplicating on the related ASA FW (Further details on this procedure can be found in https://conf.willhillatlas.com/display/netsec/Applying+firewall+rules+to+the+Anyconnect+VPN+ACLs).

The issue was that we found after a short time we started to experience configuration drift between both the hierarchal rules and the individual devices. Examples of this were missing Rules between devices, missing rules between related ACLs and rules in different order between related rules.

## **Objectives**

The objective of the role and the script was to take a source of truth, for example a YML file, and then with this information.


    1. Identify the information that has changed.
    2. Compile and check all objects/groups for duplicate names
    3. Compile and update the relevant related ACLs.
    3. Perform some sanity checks to make sure the devices haven’t drifted.
    4. Then if all ok deploy the rules to the active device (The Secondary device will have the Objects and ACLs deployed via a sync script over night).

---

**NOTE**

This script only looks at objectives 2, as the other objectives are looked after by the RAS Ansible role and the RAS ACL Script

---
One of the other key objectives, is that there is a single point of truth for each of the ACLs and this should be easy and simple to update by an engineer.

## **How does it work?**

### **Example**

An example of how you call the script is as follows\
`python3 ras-object-checks.py -i <Inventory> -l (optional)<Log Level>`\
i.e. \
`python3 ras-object-checks.py -i /gitnet/test_network_inventory/environments/prod/ -l debug`

After you run the script, it will take the inventory (-i) and logging (-l) variables defined within the command line, and pass both these to the script as the inventory and log level variable respectively. The default variables, i.e. if none is specified, are

|Variable | Data|
|:---:|:---:|
|-i or –-inventory |/gitnet/network_inventory/environments/dev/|
|-l or --level|warn|

## **Walkthrough**


The script starts in ras-object-checks.py, which is broken down into several sections

---
**NOTE:**

Within the code comments each of the sections are title with the comment

`##################################################################### STAGE x #####################################################################`

---
### **Stage 1:**
Within stage 1, The script imports all the required modules in order for the script to run, then defines, using classes, custom exceptions in order to pass them back to ansible so it is aware there has been an error.

### **Stage 2:**
Stage 2 is where, after being passed the input variable's from the command line, it will take this and parse them out to obtain the relevant data from them. These are taken and stored in relevant variables to be used throughout the script

The next step is to retrieve the current location of the python script and the current working directory, this is used later in the script to define where to put the log file and then where to obtain the current git status information
The final  step is to confirm that 3 key directories are created

    1. /gitnet/ras-processed (This will be the location of all the working data for the role)
    2. /gitnet/ras-processed/data - This is the location of the RAS data files to be used by the role after they are compiled

Finally, clear any existing log file, then define how and where any logging should be written to.

### **Stage 3**
Stage 3 is the meat and bones of the script and is where all the main processing starts

This stage is all compiled within a function called object_check, this function accepts a parameter called inventory which is the inventory passed via the command parameter (under `-i` or `--inventory`), and the call is located within the main function.

The whole function is called within a try exception (located in main), the idea of this is to allow the capturing and passing of exceptions to ansible, in order to prevent ansible from continuing within its play if the python script should fail.

#### **Stage 3.1**
Stage 3.1 generally covers the setup and checks of the function.

The first part of the function defines the yaml formatting when creating or updating yaml files (This is done later on in the script)

Then a check is done to confirm if the inventory variable has a / at the end. This is then used later when adding the group_vars/ras path.

#### **Stage 3.2**
Stage 3.2 is involved in checking for duplicate object names, The script compiles all the relevant objects that are located with relevant yaml files, and puts them into their own independent list.

This will then scan the objects and check if 1 or more of the same names appear, it will then place these in a separate list. The script then checks if the list has any members, if it does, it stops the script and calls an exception, resulting in a message passed back to the user detailing which object is duplicated and the file it is located in.

Below is an example of the code to achieve this.

```python
    svc_duplicates = [svc_object_name for svc_object_name in svc_objects_list if svc_objects_list.count(svc_objects_list) > 1]<br>
    if len(svc_duplicates) > 0:
        raise duplicate_objects(inventory + 'group_vars/ras/svc_objects.yml',svc_duplicates,"FOUND " + str(len(svc_duplicates)) + " DUPLICATE OBJECT   NAMES IN     - PLEASE REMOVE/RE-NAME THE DUPLICATES THEN RERUN " + "\n" + "DUPLICATE OBJECTS NAMES: " + str(set(svc_duplicates)))
```

>**NOTE** An example of the message passed back to the user<br><br>
####################################### ERROR #####################################<br>
SEE LOG /gitnet/ansible/roles/asa-ras-acl/scripts/ras_acl_constructor/log/ras_acl_constructor.log FOR FULL DETAILS<br>
ERROR IN FILE: /gitnet/ansible/roles/asa-ras-acl/scripts/ras_acl_constructor/ras_acl_constructor.py<br>
ERROR LINE: 199<br>
ERROR MESSAGE: FOUND 2 DUPLICATE OBJECT NAMES IN - PLEASE REMOVE/RE-NAME THE DUPLICATES THEN RERUN <br>
DUPLICATE OBJECTS NAMES: {'ipnetinfo'}<br>
PLEASE CORRECT FILE: /gitnet/network_inventory/environments/prod/group_vars/ras/svc_objects.yml<br>
###################################################################################<br>

**NOTE:**

If an exception is called while this function is running it will output an error message to the console containing
* Location of the error log
* The file name containing the code that errored
* The line number of the error
* The error messages

It then exits the script with a error status code of **1**
