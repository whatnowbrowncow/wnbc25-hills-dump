##################################################################### STAGE 1 #####################################################################
# Import WH Network Tools
import wh_net_python_toolset.wh_python_toolset as wh_tools

# Import Required Nornir Modules
from nornir.core.task import Task, Result
import nornir_netmiko.tasks as netm_tasks
from nornir_netmiko.tasks import netmiko_send_command
import getpass

# Import formating modules
from tabulate import tabulate
from termcolor import colored
from tqdm import tqdm
import cmd



# Import System Modules
import os
import time

# Add Standard Arguments and Extra Command line Argument
args = wh_tools.import_std_arg()
parser = args.create_arg()
pypath = os.path.dirname(os.path.abspath(__file__))

parser.add_argument(
    "--dataonly",
    default=False,
    help=("produce Data files only, Do not show configuration output", "Example --dataonly"),
    action="store_true",
    dest="dataonly",
)

# Argument to run check mode
parser.add_argument(
    "--check",
    default=True,
    help=("Filter Devices " "Example --check"),
    action="store_true",
    dest="dry_run",
)

# Argument to run check mode
parser.add_argument(
    "--filter",
    default="=all",
    help=("Filter Devices" "Example --filter site=brs_lab, Default env=brs_lab"),
    action="store",
    dest="filter_data",
)
arg_items = parser.parse_args()

folder_list = {
    'root_folder': '/gitnet/processed_data/access_check',
    'log_folder': '/gitnet/processed_data/log/access_check/',
}
## Define Logging
logger = wh_tools.logging_define(
          arg_items.level, f"{folder_list['log_folder']}/access_check.log"
        )

for folder in folder_list.values():
    if not os.path.isdir(folder):
        os.makedirs(folder)

# Setup Required Folders
prog_logger = logger.logging_setup()
prog_logger.notice('Starting legacy_access_check')
prog_logger.debug(f'Parsed args: dataonly={arg_items.dataonly}, dry_run={arg_items.dry_run}, filter={arg_items.filter_data}')





##################################################################### STAGE 2 #####################################################################

def config_file_set():

        if os.environ.get("CONFIG_OPTION") is None:
            options=[
                [1,"William Hill"],[2,"888"]
            ]
            print(tabulate(options,headers=["Option","Environment"]))
            option_selected=int(input("Select Enviroment Option: "))
            if option_selected > len(options):
                raise Exception("OPTION NOT VAILD, PLEASE PICK VAILD OPTION")

        else:
            option_selected=int(os.environ.get("CONFIG_OPTION"))

        if option_selected == 1:
            config_file_local=f"{pypath}/WH_inv.yml"
        elif option_selected == 2:
            config_file_local=f"{pypath}/888_inv.yml"
        prog_logger.notice(f'Using inventory file: {config_file_local}')
        return config_file_local


def run_check_command(task: Task,check_command) -> Result:
    output = task.run(netmiko_send_command, command_string=check_command )
    return Result(host=task.host, result=output)


def main():
    try:

        prog_logger.info('Entering main()')
        start_time = time.time()
        ##################################################################### STAGE 3 #####################################################################
        display_size = wh_tools.Console_sizes()
        inv_data = wh_tools.nornir_tasks()
        config_file_local=config_file_set()
        # Get Users Creadentials
        if os.environ.get("UN") is None:
            username = input("Username: ")
        else:
             username=os.environ.get("UN")
        if os.environ.get("PASS") is None:
            password = getpass.getpass(prompt="Password: ")
        else:
            password=os.environ.get("PASS")
        ##################################################################### STAGE 4 #####################################################################
        target_hosts = inv_data.setup_hosts(config_file_local,pypath,arg_items.dry_run,arg_items.filter_data)
        prog_logger.info(f'Resolved hosts: {len(target_hosts.inventory.hosts)}')
        target_hosts.inventory.defaults.username=username
        target_hosts.inventory.defaults.password=password
        result_output = []
        ##################################################################### STAGE 5 #####################################################################
        tqdm.write(f'{display_size.return_half_width_Text(colored("Testing Access to Devices via Show version or equivlivent ", "yellow"),"=")}\n')
        with tqdm(
            total=len(target_hosts.inventory.hosts),
            desc=colored("Testing Access to device","yellow")
        ) as host_deploy_bar:

            for device_name, device_obj in target_hosts.inventory.hosts.items():
                tqdm.write(
                    display_size.return_half_width_Text(colored(f"checking device {device_name}", 'yellow'),"=")
                )

                current_host = target_hosts.filter(name=device_name)
                # Determine the check command from the group's data and log it (don't log credentials)
                check_command = current_host.inventory.groups[device_obj.platform].data['check_command']
                prog_logger.notice(f'Checking device {device_name} (platform: {device_obj.platform})')
                prog_logger.debug(f'Check command for {device_name}: {check_command}')

                # Run the check command if present
                if check_command:
                    result = current_host.run(
                        task=netm_tasks.netmiko_send_command,
                        command_string=check_command,
                        use_genie=True,
                        use_timing=True
                    )
                    if result.failed == False:
                        result_output.append([device_name,colored("Success","green"),""])
                    elif result.failed == True:
                        result_output.append([device_name,colored("Failed","red"),str(result[device_name].exception.args).split('\\n')[0].split('(\'')[1]])
                    else:
                        raise Exception(f"CANNOT GET RESULT OF {device_name} PLEASE CHECK")
                else:
                    prog_logger.warning(f'Skipping device {device_name} because no check_command defined')
                host_deploy_bar.update()
        ##################################################################### STAGE 6 #####################################################################
        prog_logger.notice(f"\nTEST RESULTS :\n{tabulate(result_output,headers=['DEVICE','STATUS','EXCEPTION'],tablefmt='fancy_grid')}")
        print(f"\nTEST RESULTS :\n{tabulate(result_output,headers=['DEVICE','STATUS','EXCEPTION'],tablefmt='fancy_grid')}")


    except Exception as err:
        # Log full exception with traceback
        prog_logger.exception('Unhandled exception in main')
        if not isinstance(err, wh_tools.CustomError):
            wh_tools.Error_define(err)


if __name__ == "__main__":
    main()

