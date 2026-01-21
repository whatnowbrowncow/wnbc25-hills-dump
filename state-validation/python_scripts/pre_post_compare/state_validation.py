import os
from shutil import copyfile
from datetime import datetime
from device_state_learn import device_state_learn
from device_state_learn_pre import device_state_learn_pre
from device_state_learn_post import device_state_learn_post
#from device_state_compare_snapshots import device_state_compare_snapshots
from rich.console import Console
from rich.panel import Panel
console = Console()

def number_of_routes():
    console.print('\n[italic dim]Please enter the maximum number of routes you would like to process per VRF (note that the more routes to process the longer the script will take to run)\n')
    max_routes = input('Number of routes(2000):')
    if max_routes == '':
        max_routes = 2000
    try:
        max_routes = int(max_routes)
    except Exception as e:
        console.print('[red]{}'.format(str(e)))
        print('max routes = ' +str(max_routes))
        print('Value needs to be an integer (number), please try again')
    return max_routes

def snapshot_type():
    #snapshots = {1:'curr',2:'pre',3:'post'}
    console.print(Panel('''
[italic dim]Please select the type of snapshot you wish to take:[/italic dim] \n
1: Take a current state snapshot
2: Take a pre change snapshot
3: Take a post change snapshot
''', title='Choose a snapshot type'))
    snapshot_choice = input('Option: ')  # ask the user for input
    if snapshot_choice not in snapshots.keys():
        console.print('[red]Value needs to be 1, 2 or 3, please try again')
    return snapshot_choice

snapshots = {'1':'curr','2':'pre','3':'post'}
console.print()
console.print()
console.print(Panel('''
[italic dim]Please select from the following options:[/italic dim] \n
1: Take a snapshot ([italic dim]pre change / post change / current state[/italic dim])
2: Compare snapshots ([italic dim]of two different devices[/italic dim])
3: Compare pre and post snapshots ([italic dim]of the same device[/italic dim])
4: [italic red]Compare pre and post snapshots using robot framework (Output to CLI and generate HTML report)[/italic red]
''', title='Network state validation tool'))
tool_choice = input('Option: ')  # ask the user for input

if tool_choice == '1':
    console.print(Panel('''\n[italic dim]Please enter the name of the device you wish to target, name must be an exact match to the device hostname\n''', title='Choose a device'))
    target_device = input('Device:')
    snapshot = snapshot_type()
    while snapshot not in snapshots.keys():
        snapshot = snapshot_type()
    snapshot = snapshots[snapshot]
    max_routes = number_of_routes()
    while type(max_routes) != int:
        max_routes = number_of_routes()
    device_state_learn(target_device,max_routes,snapshot)
elif tool_choice == '2':
    #console.print(Panel('''\n[italic dim]Please enter the name of the first device you wish to compare, name must be an exact match to the device hostname\n''', title='Choose a device'))
    #compare_device1 = input('Device 1:')
    #console.print(Panel('''\n[italic dim]Please enter the name of the second device you wish to compare, name must be an exact match to the device hostname\n''', title='Choose a device'))
    #compare_device2 = input('Device 2:')    
    import device_state_compare_snapshots
elif tool_choice == '3':
    import device_state_compare
####robot code coming soon####
#elif tool_choice == '4':
#    console.print('\n[italic dim] please enter the name of the device you wish to target, name must be an exact match to the device hostname\n')
#    target_device = input('Device:')
#    os.system('robot --outputdir robot/logs/'+target_device+' robot/device_state_compare.robot')
#    if not os.path.exists('/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/'+target_device+'/archive'):
#        os.makedirs('/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/'+target_device+'/archive')
#    curtime = str(datetime.now().strftime('%H_%M_%S_%d_%m_%Y'))
#    output = "/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/"+target_device+"/output.xml"
#    log = "/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/"+target_device+"/log.html"
#    report = "/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/"+target_device+"/report.html"
#    output_timestamp = "/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/"+target_device+"/archive/output-"+curtime+".xml"
#    log_timestamp = "/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/"+target_device+"/archive/log-"+curtime+".html"
#    report_timestamp = "/gitnet/state-validation/python_scripts/pre_post_compare/robot/logs/"+target_device+"/archive/report-"+curtime+".html"
#    copyfile(output, output_timestamp)
#    copyfile(log, log_timestamp)
#    copyfile(report, report_timestamp)
#    try:
#        if not os.path.exists('/mnt/c/Temp/robot_logs/'+target_device):
#            os.makedirs('/mnt/c/Temp/robot_logs/'+target_device)
#        copyfile(output,'/mnt/c/Temp/robot_logs/'+target_device+'/output.xml')
#        copyfile(log,'/mnt/c/Temp/robot_logs/'+target_device+'/log.html')
#        copyfile(report,'/mnt/c/Temp/robot_logs/'+target_device+'/report.html')
#        console.print('A copy of these log files can be found in [yellow]C:/Temp/[/yellow] for quick browsing')
#    except:
#        console.print('''[red]Copying robot log files to C:/Temp failed, this is probably because you aren't using Docker, copies of logs can still be found in the above locations''')
