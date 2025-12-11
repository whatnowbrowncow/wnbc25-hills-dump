#! /usr/bin/env python
# Modules
from nornir import InitNornir
from nornir_netmiko.tasks import netmiko_send_command
from nornir_netmiko.tasks import netmiko_send_config
from nornir.core.filter import F
from nornir.core.task import Task, Result
from nornir.core.filter import F
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
console = Console()
# Local artefacts
import retail_helper_functions as rhf

# Variables
config_file = "/dbdev/retail_dmvpn_cipher/config_files/retail_dmvpn.yaml"


tunneltablepre = Table(title='DMVPN Tunnel Summary',show_header=True, header_style="bold blue")
tunneltablepre.add_column('Device',justify='center')
tunneltablepre.add_column('Tunnel 11 interface status',justify='center')
tunneltablepre.add_column('Tunnel 11 protocol status',justify='center')
tunneltablepre.add_column('Tunnel 12 interface status',justify='center')
tunneltablepre.add_column('Tunnel 12 protocol status',justify='center')

tunneltablepost = Table(title='DMVPN Tunnel Summary',show_header=True, header_style="bold blue")
tunneltablepost.add_column('Device',justify='center')
tunneltablepost.add_column('Tunnel 11 interface status',justify='center')
tunneltablepost.add_column('Tunnel 11 protocol status',justify='center')
tunneltablepost.add_column('Tunnel 12 interface status',justify='center')
tunneltablepost.add_column('Tunnel 12 protocol status',justify='center')


# Body
if __name__ == "__main__":
    ## Initiate Nornir
    nr = InitNornir(config_file=config_file)
   
    ## Collect ARP from core
    #nr_devices = nr.filter(role="routers")
    nr_devices = nr.filter(F(role="hubs") | F(role="spokes"))
    nr_hubs = nr.filter(role="hubs")
    nr_spokes = nr.filter(role="spokes")


    def gatherfacts(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_command, command_string="show ip int brief | inc Tu", use_genie=True, use_timing=False)
    ### Calling the above function against a set of devices


        """
        This task takes two paramters that are in fact bars;
        napalm_get_bar and other_bar. When we want to tell
        to each respective bar that we are done and should update
        the progress we can do so with bar_name.update()
        """
        #task.run(task=gatherfacts)
        netmiko_bar.update()
    
   
    
    
    # we create the first bar named napalm_get_bar
    console.print("[blue]##################\nStep 1 of 4 - Gathering tunnel state before interface bounce ({} devices), this may take a while\n##################".format(len(nr_spokes.inventory.hosts)))
    with tqdm(
        total=len(nr_spokes.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            device_facts=nr_spokes.run(
                task=gatherfacts,
                netmiko_bar=netmiko_bar,
                
            )


    device_facts,failed_hosts=rhf.clean_facts(device_facts)
    spoke_tunnels_parsed = rhf.get_tunnel_interface_state(device_facts,1)

    for device, data in spoke_tunnels_parsed.items():
        try:
            if data['Tunnel11']['int_status'] == 'up':
                tu11int = "[green]UP"
            else:
                tu11int = "[red]DOWN"
            if data['Tunnel11']['protocol_status'] == 'up':
                tu11prot = "[green]UP"
            else:
                tu11prot = "[red]DOWN"
            if data['Tunnel12']['int_status'] == 'up':
                tu12int = "[green]UP"
            else:
                tu12int = "[red]DOWN"
            if data['Tunnel12']['protocol_status'] == 'up':
                tu12prot = "[green]UP"
            else:
                tu12prot = "[red]DOWN"
        except Exception as e:
            print(e)
        tunneltablepre.add_row(device,tu11int,tu11prot,tu12int,tu12prot)
    console.print(tunneltablepre)


    cfg_devices = nr_spokes.filter(F(name__any=list(device_facts)))
    def tunnel11_shutdown_config(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_config, config_commands=["interface tunnel 11","shutdown"])
        netmiko_bar.update()
    def tunnel11_no_shutdown_config(task:Task,netmiko_bar) -> Result:
        task.run(task=netmiko_send_config, config_commands=["interface tunnel 11","no shutdown"])
        netmiko_bar.update()
    
    console.print("[blue]##################\nStep 2 of 4 - shutting down tunnel 11 ({} devices), this may take a while\n##################".format(len(nr_spokes.inventory.hosts)))
    
    with tqdm(
        total=len(cfg_devices.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            tunnel11_shut_facts=nr_spokes.run(
                task=tunnel11_shutdown_config,
                netmiko_bar=netmiko_bar,
                
            )
    
    
    
    #clean config results
    tunnel11_shut_facts_clean,tunnel11_shut_facts_failed_hosts = rhf.clean_facts(tunnel11_shut_facts)

    


    #print('####################testing function#####################')
    tunnel11_shut_processed_results,tunnel11_shut_full_processed_results = rhf.process_update_results(tunnel11_shut_facts_clean)
    #print('#########################################')
    console.print("[blue]##################\nStep 3 of 4 - bringing up tunnel 11 ({} devices), this may take a while\n##################".format(len(nr_spokes.inventory.hosts)))
   
    with tqdm(
        total=len(cfg_devices.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            tunnel11_noshut_facts=nr_spokes.run(
                task=tunnel11_no_shutdown_config,
                netmiko_bar=netmiko_bar,
                
            )
    
    
    
    #clean config results
    tunnel11_noshut_facts_clean,tunnel11_noshut_facts_failed_hosts = rhf.clean_facts(tunnel11_noshut_facts)

    


    #print('####################testing function#####################')
    tunnel11_noshut_processed_results,tunnel11_noshut_full_processed_results = rhf.process_update_results(tunnel11_noshut_facts_clean)
    #print('#########################################')
    
    console.print("[blue]##################\nStep 4 of 4 - Gathering tunnel state after interface bounce ({} devices), this may take a while\n##################".format(len(nr_spokes.inventory.hosts)))
    with tqdm(
        total=len(cfg_devices.inventory.hosts), desc="progress",
    ) as netmiko_bar:

            # we call our grouped task passing both bars
            device_facts_post=cfg_devices.run(
                task=gatherfacts,
                netmiko_bar=netmiko_bar,
                
            )


    device_facts_post,failed_hosts_post=rhf.clean_facts(device_facts_post)
    spoke_tunnels_parsed_post = rhf.get_tunnel_interface_state(device_facts_post,1)

    for device, data in spoke_tunnels_parsed_post.items():
        try:
            if data['Tunnel11']['int_status'] == 'up':
                tu11int = "[green]UP"
            else:
                tu11int = "[red]DOWN"
            if data['Tunnel11']['protocol_status'] == 'up':
                tu11prot = "[green]UP"
            else:
                tu11prot = "[red]DOWN"
            if data['Tunnel12']['int_status'] == 'up':
                tu12int = "[green]UP"
            else:
                tu12int = "[red]DOWN"
            if data['Tunnel12']['protocol_status'] == 'up':
                tu12prot = "[green]UP"
            else:
                tu12prot = "[red]DOWN"
        except Exception as e:
            print(e)
        tunneltablepost.add_row(device,tu11int,tu11prot,tu12int,tu12prot)
    console.print(tunneltablepost)
    

    if len(failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed at stage 1:")
        for device,reason in failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    if len(tunnel11_shut_facts_failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed at stage 2:")
        for device,reason in tunnel11_shut_facts_failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    if len(tunnel11_noshut_facts_failed_hosts.items()) > 0:
        console.print("[bold italic red]The following devices have failed at stage 3:")
        for device,reason in tunnel11_noshut_facts_failed_hosts.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))
    if len(failed_hosts_post.items()) > 0:
        console.print("[bold italic red]The following devices have failed at stage 4:")
        for device,reason in failed_hosts_post.items():
            console.print('[red]{}[/red][bold red]:{}'.format(device,reason))