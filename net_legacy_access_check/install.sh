#/bin/bash
set -e
currentpath=$(pwd)
pip install --upgrade pip
pip install -r requirements.txt
if ! [ -L wh_net_python_toolset ]; then
    if ! [ -d /gitnet/automation-tools/wh_net_python_toolset ]; then
        echo "\n ************* ERROR: Please clone the tools directory into /gtnet/automation-tools from git@gitlab.com:williamhillplc/technical-services/networks/automation-tools/wh_net_python_toolset.git ************* \n"
        exit 2
    else
        echo "Mapping Tools Directory"
        ln -s /gitnet/automation-tools/wh_net_python_toolset
    fi
    cd wh_net_python_toolset
    echo "Getting Latest Version of tools"
    git pull
    cd $currentpath
else
   echo "Tools Directory Exist"
   cd wh_net_python_toolset
   echo "Getting Latest Version of tools"
   git pull
   cd $currentpath
fi
if ! [ -d /gitnet/do-shared-python-functions ]; then
        echo "\n ************* ERROR: Please clone the shared functions directory (Seach for do-shared-python-functions under the networks group in gitlab) ************* \n"
        exit 2
    else
        echo "Shared Functions Directory Exist"
fi
if ! [ -f ~/decryption_keys ]; then
   echo "\n ************* ERROR: decryption_keys not found, Please Create a decryption_keys file in your home  (~/) directory as with the details in Network Python encryption Key in last pass ************* \n"
   exit 2
else
   echo "Keys Exist"
fi