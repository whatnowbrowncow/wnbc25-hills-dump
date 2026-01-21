# **RAS DST VALIDATION SCRIPT**

|Version | Date|Summary|Current Version|
|:---:|:---:|:---:|:---:|
|0.1|20\/09\/2021| Intial Build|
|1.0|01\/10\/2021| Added Readme, Varible Updates, Submit for Production|| 
|1.1|10\/08\/2022| Update to allow use of one DST file<br>Put domain validation in own function<br>Changed GIT comparison to Master from Head<br>Added Version Change Check |Y| 

## **Reason**

The DST validation script was designed to help construct the YMLs used within the RAS DST Ansible Role for the deployment of Dynamic Split Tunnel entries

The original reason for deploying the Role and the script is to, replace the cumbersome, complicated and time-consuming manual process. 

In order to update the RAS DST there was a requirement to add a entry to the relevant group in alphabetical order, this then needed duplicating on the related ASA FW. There is also a limit of 421 characters per configuration line and 5000 per group (Further details on this procedure can be found in https://conf.willhillatlas.com/display/ARCH/Anyconnect+Dynamic+Split+Tunnel+Configuration).

The issue was that we found after a short time we started to experience configuration drift between the individual devices. 

## **Objectives**

The objective of the role and script was to take a source of truth, for example a YML file, and then

1. Identify the information that has changed.
2. Peform the following checks on the new DST entrie, if any are true then the script ends
    1. DST already exist
    2. DSTs TLD already exist
    3. Subdomains exist is entrie is a TLD
    4. DST Data Changed but Version hasnt
    5. Version Changed but DST Data hasnt
    6. DST exceed 5000 charcters
3. Confirm the entries are not over the characters length
4. Compile and update the relevant related DST
5. Perform some sanity checks to make sure the devices haven't drifted.
6. Then if all ok, deploy the rules to both devices at the same time.

---

**NOTE**

This script only looks at objectives 1-4 as the other objectives are looked after by the RAS DST Ansible role

---
One of the other key objectives, is that there is a single point of truth for each of the DSTs and this should be easy and simple to update by an engineer.
## **How does it work?**
### **Example**

An example of how you call the script is as follows.

`python3 dst-validation.py -i <Inventory> -l (optional)<Log Level>`\
i.e. \
`python3 dst-validation.py -i /gitnet/network_inventory/environments/prod/ -l debug`

After you run the script, it will take the inventory (-i) and logging (-l) variables defined within the command line, and pass both these to the script as the inventory and log level variable respectively. The default variables, i.e. if none is specified, are

|Variable | Data|
|:---:|:---:|
|-i or –-inventory |/gitnet/network_inventory/environments/dev/|
|-l or --level|warn|

## **Walkthrough**


The script starts in dst-validation.py, which is broken down into several sections 

---
**NOTE:**

Within the code comments each of the sections are title with the comment 

`##################################################################### STAGE x #####################################################################`

---
### **Stage 1:**
Within stage 1, The script checks for and imports all the required modules in order for the script to run, then defines, using classes, custom exceptions in order to pass them back to ansible so it is aware there has been an error.

### **Stage 2:**
Stage 2 is where, after being passed the input variable's from the command line, it will take this and parse them out to obtain the relevant data from them. These are taken and stored in relevant variables to be used throughout the script

The next step is to retrieve the current location of the python script and the current working directory, this is used later in the script to define where to put the log file and then where to obtain the current git status information.

The final  step is to confirm that 3 key directories are created 

1. /gitnet/ras-processed (This will be the location of all the working data for the role)
2. /gitnet/ras-processed/data (This is the location of the RAS data files to be used by the role after they are compiled)

Finally, it clears any existing log file, then defines how and where any logging should be written to.

### **Stage 3**
Stage 3 is the meat and bones of the script and is where all the main processing starts

This stage starts within the *main* function, this function accepts a parameter called inventory which is the inventory passed via the command parameter (under `-i` or `--inventory`), and the call is located at the bottom of the file.

The whole function is called within a try exception, the idea of this is to allow the capturing and passing of exceptions to ansible, in order to prevent ansible from continuing within its play if the python script should fail, particularly becuase of, No DST yml files having changed.

The first part of the function defines the yaml formatting when creating or updating yaml files (This is done later on in the script)

The script then proceeds to examine the current directory structure, using the inventory parameter, to find the git repositry using the GitPython module. It will then store the repositry infomation in a varible called **repo**.

The next step it is to confirm if the inventory varible has a `/` at the end. This is then used later when adding the **group_vars/ras** path.

This is then passed to a function called **dst_check**, which does the following
* Identifies the files that have changed
* Check to confirm if the DST file modified is in master.
* Retrives the data from the updated files
* If the file is in master it completes the following tasks
    * Retrives the hash from the master of the updated file
    * Retrives the data within the master version of the file
    * Calls the **domain_validation** function, passing the previous data, current data, name and location of updated file, repo loction and a boolen value confirming the file exists in master
* If the file is not in master
    * Retrives the current data collected above and places it in a diffrent dict
    * Calls the **domain_validation** function, passing boths sets of current data, name and location of updated file, repo loction and a boolen value confirming the file does not exist in master

When the the above has been completed it the retrives the releivent version of data (if one exisits) and then calls the **domain_validation** function to complete the following
* Checks the data has changed from the previous version (where applicable), 
* Checks for any duplicates
* Checks for TLD entries for the new DST
* Check for subdomains if the domain is a TLD.

After that, using the **changed_files** list, it loops through all the entries and completes the following tasks

* Extracts the file name from the entry and places it in a varible called **tail**
* Retrives the data from the yaml file using the **load_yml** function and places it in a dictionary called **data_items**, details of the function can be found below
* Extracts the group name from the first key within the **data_items** dictionary
* Using the **data_items** dictionary, it extracts the data using the dst_data key, re-sorts it, and places it back within the dictionary
* If the current git branch is not a release branch then it writes the data back to the file, using the tail varible
* It then takes the data and passes it through a function called **dst_count_and_split**, to validate and segregate the data. Details of this function can be found below and then place it in a dictionary called **final_dst**
* Last step is to take the data in **final_dst** and write it to a file in **/gitnet/ras-processed/data/** called **ansible-data-\<dst\>-include.yml**

## load_yaml Function

This function takes the following information
    
|Variable | Data|
|:---:|:---:|
|filename|File location of the user based yml|

This function takes a file name varible and, using this, opens a file containing data in a yaml format, extracts it and place it into a dictionary. It then passes it back to the calling function


## output_to_file Function

This function takes the following information

|Variable | Data|
|:---:|:---:|
|yaml_data|Data of the DST to be processed|
|file_location|File location of the yml|
|file_name|The name of the file to be processed|


This function takes data passed from the calling function and places it in a varible called yaml_data, it then opens a file for writing using the file_location and file_name varibles. It will then write the data in the yaml_data varible to the file.



## changed_yamls Function

This function takes the following information

|Variable | Data|
|:---:|:---:|
|inventory|Current Inventory location|
|repo|The location of the current repositry to be processed|

This function checks which yaml files have been changed, it does this by
* Taking the path from the inventory varible
* Identifies the git repositry details using the *rev_parse* command
* Performs a git diff against *master* and exports the file names from the diff
* If the file name starts with *dst-* then it is appended to a list called *changed_files*
* if the *changed_files* list has no entries and this is not being performed on a release branch then an error is raised and the script is stopped
* Finally the *changed_files* list is passed back to the calling procedure



## dst_count_and_split Function

|Variable | Data|
|:---:|:---:|
|dst_data|Data of the DST to be processed|

The first step within this function is to extract the first key of the data that has been passed to via the calling function. It will then is to define the starting paremeter of varibles used within the function.

The next step is, if `-include' is in the group name, take each value within the *dst_data* dict and perform the following tasks


* A dictionary is created called **dstGroups[current dst key name]** which contains a list called **dstgroups\#** replacing **\#** with the value in the **currentdst_grp** varible
* It places the current availible character length within a varible called **avlbchar**
* This is done by adding the character length of the **dst_customer_attr_length** and the **fqdncount** varible together and minusing it from 421.
* It then calculates the character length of the value and adding it to a varible called **fqdnlength**
* It then takes the current total character length count of the current **dstGroup\#** and adds the length of the current value, it will then place it in a varible called **dst_customer_attr_length**. This will used to determine when a new group of entries need creating.
* It then takes the current value length, increases it by one (to account for the `,`) and adds it to a varible called **dstlength**.
* If the **dstlength** varible is > 5000, an exception is raised saying that the total DST length is too large and a new group needs creating
* The next step is, if the **fqdnlength** varible is less than the **AvlbChar** value then the following tasks are performed
    * The current value is appended to the **dstGroup#** currently defined within **currentdst_group** varible 
    * The length of this group is placed in the fqdncount varible
* If the **fqdnlength** varible > **AvlbChar** varible then 
    * The varible **currentdst_grp** varible is increased by 1
    * A group is created called **dstGroup\#** replacing \# with the value in the **currentdst_grp** varible
    * The varible **AvlbChar** is set to **421** - the value in the **fqdnlength** varible
    * The *fqdncount* is set to the current character length in the **dstGroup\#**
    * The varible **dst_customer_attr_length** is set to the value in the **fqdnlength** varible + 1
    * The current value is appended to the **dstGroup\#** currently defined within **currentdst_group** varible 
* Finally it takes the original data **dstGroups[current dst key name]** and places the **dst_data** dictionary into it (overwriting the original data) and passes it back to the calling function


## dst_check Function

|Variable | Data|
|:---:|:---:|
|inventory|Location of the Data to be processed|
|repo|Git Repo infomation containing the data|


First off a git diff is performed against master, by calling the **changed_yamls** function, and extracts the file names of all files updated, if the file name starts with dst- then it adds it to a list called changed_files and passes it back to the **dst_check** function.
* The next step is to check if the active branch of the inventory folder contains the name **release**. If it doesnt then it performs the following tasks, if it is in a **release** branch then it skips this function
    * It traverse through all the files in the master branch add them to a dict called masterfilelist
    * Then looping through all the files in the changedfiles dict
        * Retrive the current commit data of the current update file being processed
        * Removes the top `/gitnet/network_inventory/` path from the updated path string
        * Sets a boolen varible **Fileinmaster** by checking if the updated file is in the **masterfile** dict
        * It will then retrive the data from the updated files and place it into a varible called **currentdata** using the **load_yml** function and return the data to a dict called **currentdata**
        * It then retrives the group name of the file by extrating the first entry of the currentdata (Which becuase of the way the file is structed will always be the group name)
        * Next the script will run tasks depending on the value in the **fileinmaster** varible
            * If the **fileinmaster** is equal to **True**
                * Locate the git information of the updated file in master 
                * Using this it will extract the data from it and then plece it on a list called **previousdata**
                * it will then extract the data from the **group_name** value in **previousdata** list and then place it into a value called **previousgroupdata**
                * It will then call the **domain_validation** function
            * If the **fileinmaster** is equal to **False**
                * it will then extract the data from the **group_name** value in **currentdata** list and then place it into a value called **previousgroupdata**
                * It will then call the **domain_validation** function                

        
        
## domain_validation function        
        
* The first step is to define a set called **dupdomain** used later in the script
* The next step is that it will then retrive the data from the dst_data value within the **currentgroupdata** and **previousgroupdata**, and places it in a varible called **currentdstdata** 
and **previousdstdata** respectivly 
* It will then check the value of the **fileinmaster** varible
    * If the **fileinmaster** is set to **True**
        * It will check that the **currentdstdata** doesnt match the **previousdstdata**, if they do match then the check has failed and the script will call an exception called **nodstchanges** and stop the script.
            * If this check passes then it will check if the **version** varible of the **currentgroupdata** and the **previousgroupdata** match, if they do it will class this as a fail and then it will rasie a error by calling the **versionnotupdated** exception and stop the script
            * If the above has passed the check then it will loop through all the entries in the in the **currentdstdata** varible and if the entry has already been seen in the list adds it to the set **dupdomin** created earlier
            * The script then checks if the length of the **dupdomin** set is greater than 0, if it is the check has failed and an exception will be raised called **domainalreadyexists** and the script will stop
            * The next to steps are to convert the **currentdstdata** and the **previousdstdata** to as set with the respective same names.
            * The script will then compare the check what domains the 
            * **previousdstdata** has the **currentdstdata** doesn't and place them in a lit called **removaldomains***
            * **currentdstdata** has the **previousdstdata** doesn't and place them in a lit called **additiondomains***
            * Next it will compare both the **currentdstdata** and the **previousdstdata** in a **symmetric_difference** to produce a list of all affected domains and place them in a list called **domians**

            *********************** Up to line 277        ***********************


**currentdstdata** for each of the files changed
* After that it compares the **previousdstdata** and the **currentdstdata** to check if there are any matching entries
* It will then check for any TLD domain entries within the existing data for the DST that is being added
* It will then check for any subdomains to the DST being added, listing them

If any of the above checks are true, the script will end and pass back an exception containing an appropriate message, if they are false it will pass the **changed_files** back to the main function.

<details>

<summary markdown="span"> Click Here for an example the dst_data dictionary </summary> 

```json
Dictionary: dst_data[datamgmt-include]
{
        "name": "datamgmt-include",
        "policy": "datamgmt_policy",
        "dst_data": [
            "21nova.com",
            "admin.gib.casinarena.com",
            "admin.mraffiliate.com",
            "amazonworkspaces.com",
            "amswh.avature.net",
            "app.onionsack.eu",
            "blueprintgaming.com",
            "bo-prod-gib.yggdrasilgaming.com",
            "casinomodule.com",
            "custhelp.com",
            "customer-portal.lon.netverify.com",
            "dfwsftp.cadency.trintech.com",
            "dopamine-gaming.com",
            "eurogrand.com",
            "gameassists.co.uk",
            "helpdesk.iforium.com",
            "ims.ptdev.eu",
            "insight.accuity.com",
            "ipoker-it.com",
            "malmegas.com",
            "manager.esports-battle.com",
            "master.mrgreen.avengers.zone",
            "merchant.paysafe.com",
            "mrgreen.com",
            "mrgreen.es",
            "openbet.com",
            "p1.verveengine.co.uk",
            "paymentiq.io",
            "paymentservices.bacs.co.uk",
            "pegacloud.net",
            "playtech.com",
            "playtechgaming.com",
            "playzido.com",
            "pragmaticplay.net",
            "ptplatforms.com",
            "ptstaging.eu",
            "redtiger.cash",
            "redtiger.com",
            "reporting.datacash.com",
            "rgsgames.com",
            "secure.ecopayz.com",
            "sftp.alexmann.com",
            "sftp.safecharge.com",
            "skrill.com",
            "skylight-client-ds.eu-west-2.amazonaws.com",
            "squiz.cloud",
            "squiz.co.uk",
            "techonlinecorp.com",
            "virtuefusion.com",
            "wagerworks.com",
            "whbettingengine.com",
            "whsdpprod.cloud.databricks.com",
            "whsdpprod.eu-west-1.snowflakecomputing.com",
            "whsdpusprod.us-east-1.snowflakecomputing.com",
            "wiki.sgdigital.com",
            "williamhill-dev.com",
            "williamhill-nonprod.com",
            "williamhill-pp1.at",
            "williamhill-pp1.com",
            "williamhill-pp1.es",
            "williamhill-pp1.it",
            "williamhill-pp2.com",
            "williamhill-pp2.es",
            "williamhill-pp2.it",
            "williamhill-pp3.com",
            "williamhill-pp3.es",
            "williamhill-pp3.it",
            "williamhill-pt1.com",
            "williamhill-pt1.es",
            "williamhill-pt1.it",
            "williamhill.campaign.adobe.com",
            "williamhill.cloudsoftcat.com",
            "williamhill.com",
            "williamhill.de",
            "williamhill.es",
            "williamhill.it",
            "williamhillcasino.com",
            "ws-broker-service.eu-west-2.amazonaws.com",
            "www.factoring.scotiabank.com"
        ],
        "version": 4
}

```
</details>
<br>

