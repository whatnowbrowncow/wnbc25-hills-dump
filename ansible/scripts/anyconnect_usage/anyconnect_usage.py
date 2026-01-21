from genie.testbed import load
import re
import csv
from operator import itemgetter
from datetime import datetime
import time
import ipaddress
from difflib import get_close_matches


from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)


console = Console()
fw_list = []
final_dict = {}
i = 1
gig = 1024**3
meg = 1024**2


# load the testbed file
testbed = load('testbed.yaml')
pyats_anyconnect_parsed = {}


progress = Progress(
    TextColumn("[blue][progress.description]{task.description}:"),
    BarColumn(),
    "[progress.percentage]{task.percentage:>3.1f}%",
    "•",
    TimeElapsedColumn(),
    "•",
    "[cyan][progress.completed]{task.completed} Users[/cyan]"
)


# console.print(
#    "\nGathering [bold]Cisco AnyConnect[/] Sessions...\n")
console.log("Gathering [bold]Cisco AnyConnect[/] Sessions...\n")

with progress:
    for device in testbed.devices:
        try:
            fw_list.append(device)
            testbed.devices[device].connect(log_stdout=False)
            pyats_parsed = testbed.devices[device].parse(
                "show vpn-sessiondb anyconnect")
            pyats_unparsed = testbed.devices[device].execute(
                "show vpn-sessiondb detail anyconnect")
            pyats_anyconnect_parsed[device] = pyats_parsed
            site_key = list(pyats_anyconnect_parsed.keys())[-1]
            name_keys = pyats_anyconnect_parsed[site_key]['session_type']['AnyConnect']['username'].keys(
            )
            user_details = re.split('.*?(?=Username)', pyats_unparsed)
            task1 = progress.add_task(device, total=len(name_keys))
            for name in name_keys:
                index_id = list(
                    pyats_anyconnect_parsed[site_key]['session_type']['AnyConnect']['username'][name]['index'].keys())[0]
                user_dict = (
                    pyats_anyconnect_parsed[site_key]['session_type']['AnyConnect']['username'][name]['index'][index_id])
                user_dict['firewall'] = device
                if ipaddress.ip_address(user_dict['public_ip']).is_private:
                    user_dict['connection'] = "internal"
                else:
                    user_dict['connection'] = "external"
                if "0h:00m:00" in user_dict['inactivity']:
                    user_dict['status'] = "active"
                else:
                    user_dict['status'] = "inactive for " + \
                        user_dict['inactivity']
                user_dict['bytes']['tot'] = user_dict['bytes']['tx'] + \
                    user_dict['bytes']['rx']
                user_dict['traffic'] = {}
                if user_dict['bytes']['tot'] > gig:
                    user_dict['traffic']['total'] = str(
                        round(user_dict['bytes']['tot']/(gig), 2))+' GBytes'
                else:
                    user_dict['traffic']['total'] = str(
                        round(user_dict['bytes']['tot']/(meg), 2))+' MBytes'
                if user_dict['bytes']['tx'] > gig:
                    user_dict['traffic']['transmit'] = str(
                        round(user_dict['bytes']['tx']/(gig), 2))+' GBytes'
                else:
                    user_dict['traffic']['transmit'] = str(
                        round(user_dict['bytes']['tx']/(meg), 2))+' MBytes'
                if user_dict['bytes']['rx'] > gig:
                    user_dict['traffic']['receive'] = str(
                        round(user_dict['bytes']['rx']/(gig), 2))+' GBytes'
                else:
                    user_dict['traffic']['receive'] = str(
                        round(user_dict['bytes']['rx']/(meg), 2))+' MBytes'
                DTLS = "DTLS"
                SSL = "SSL"
                if DTLS in user_dict['protocol']:
                    user_dict['protocol'] = DTLS
                elif SSL in user_dict['protocol']:
                    user_dict['protocol'] = SSL
                else:
                    user_dict['protocol'] = "Parent Tunnel Only (Connection Idle)"
                for user in user_details:
                    username = [re.search('Username +: +(\S+)', x)[1]
                                for x in user.split('\n') if 'Username' in x]
                    if username != []:
                        username = username[0]
                        if username == name:
                            final_dict[name] = {}
                            lines = user.splitlines()
                            for line in lines:
                                if re.match('\A +Filter +Name', line):
                                    vpn_filter = line.split()[3]
                                    user_dict['vpn_filter'] = vpn_filter
                                if re.match('\A +Client +Ver', line):
                                    client_os = re.search(
                                        'Cisco AnyConnect VPN Agent for (\S.*) +', line)[1]
                                    user_dict['client_os'] = client_os
                                    client_ver = re.search(
                                        '(\d+\.?)+', line)[0]
                                    user_dict['client_ver'] = client_ver
                                if "vpn_filter" not in user_dict:
                                    user_dict['vpn_filter'] = "Not Found"
                                if "client_os" not in user_dict:
                                    user_dict['client_os'] = "Not Found"
                                if "client_ver" not in user_dict:
                                    user_dict['client_ver'] = "Not Found"
                            final_dict[name] = user_dict

            while not progress.finished:
                progress.update(task1, advance=1)
                time.sleep(0.02)

        except Exception as e:
            if 'Parser Output is empty' in str(e):
                name_keys = []
                task1 = progress.add_task(
                    device, total=len(name_keys))
                time.sleep(0.02)
                pass
            else:
                print('FATAL ERROR:')
                print(e)
                quit()


def closeMatches(user):
    name_list = []
    for name in final_dict:
        name_list.append(name.lower())
    matches = get_close_matches(user, name_list)
    if len(matches) > 0:
        console.print('\nUsername not found, similar user(s) connected:\n')
        console.print(*matches, sep="\n", style="bold")
    else:
        console.print('\nUser Not Found!', style="bold red")


def user_stats_2():
    user = input('\nEnter a username: ')
    return user.lower()


def user_stats(user):
    user_info = [{k: v} for (k, v) in final_dict.items() if user == k]
    if len(user_info) > 0:
        user_info = (user_info[0])
        name = (list(user_info.keys())[0])
        info = user_info[name]
        name = {'username': name}
        final_user_dict = {**name, **info}
        console.print('''
    [bold]General:[/bold]
        [dim]Client OS[/dim]          : {}
        [dim]AnyConnect Version[/dim] : {}
        [dim]Connected to[/dim]       : {}
        [dim]Connection[/dim]         : {}
        [dim]Public IP[/dim]          : {}
        [dim]Assigned IP[/dim]        : {}
    [bold]Policies:[/bold]
        [dim]Group Policy[/dim]       : {}
        [dim]VPN Filter[/dim]         : {}
    [bold]Tunnel:[/bold]
        [dim]Protocol[/dim]           : {}
        [dim]Login Time[/dim]         : {}
        [dim]Duration[/dim]           : {}
        [dim]Status[/dim]             : {}
    [bold]Traffic:[/bold]
        [dim]Sent[/dim]               : {}
        [dim]Received[/dim]           : {}
        [dim]Total[/dim]              : {}
        '''.format(final_user_dict['client_os'], final_user_dict['client_ver'], final_user_dict['firewall'], final_user_dict['connection'], final_user_dict['public_ip'], final_user_dict['assigned_ip'], final_user_dict['group_policy'], final_user_dict['vpn_filter'], final_user_dict['protocol'], final_user_dict['login_time'], final_user_dict['duration'], final_user_dict['status'], final_user_dict['traffic']['transmit'], final_user_dict['traffic']['receive'], final_user_dict['traffic']['total']))
    else:
        closeMatches(user)


def top_talkers():
    table = Table(title="Top-Talkers (Top 10 by Traffic Volume) Cisco AnyConnect Sessions",
                  header_style='bold magenta')
    table.add_column("No.", style='bold cyan')
    table.add_column("Username", style="dim green", no_wrap=True)
    table.add_column("Firewall")
    table.add_column("Connection", justify="center")
    table.add_column("Duration", justify="right")
    table.add_column("Transmit", style="dim", justify="right")
    table.add_column("Receive", style="dim", justify="right")
    table.add_column("Total", justify="right")

    i = 1
    userlist = []

    for user, info in final_dict.items():
        userstats = [user, info['firewall'], info['connection'], info['duration'],
                     info['traffic']['transmit'], info['traffic']['receive'], info['bytes']['tot']]
        userlist.append(userstats)

    sortedlist = sorted(userlist, key=itemgetter(6), reverse=True)

    for item in sortedlist[:10]:
        if item[6] > gig:
            table.add_row(str(i), item[0], item[1], item[2], item[3], item[4], item[5], str(
                round(item[6]/(gig), 2))+' GBytes')
        else:
            table.add_row(str(i), item[0], item[1], item[2], item[3], item[4], item[5], str(
                round(item[6]/(meg), 2))+' MBytes')
        i += 1

    console.print(table)


def all_users():
    userlist = []
    date = datetime.now().strftime("%Y%m%dT%H%M%S")
    filename = 'ac_usage_{}.csv'.format(date)

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Name", "Firewall", "Connection", "Public IP", "Assigned IP", "Client OS", "Client Ver",
                        "Group Policy", "VPN Filter", "Protocol", "Login Time", "Duration", "Sent", "Received", "Total", "Total (bytes)"])

        for user, info in final_dict.items():
            userstats = [user, info['firewall'], info['connection'], info['public_ip'], info['assigned_ip'], info['client_os'], info['client_ver'], info['group_policy'],
                         info['vpn_filter'], info['protocol'], info['login_time'], info['duration'], info['traffic']['transmit'], info['traffic']['receive'], info['traffic']['total'], info['bytes']['tot']]
            userlist.append(userstats)

        sortedlist = sorted(userlist, key=itemgetter(0))
        for item in sortedlist:
            writer.writerow(item)

    console.print(
        "\n[green]CSV file [italic]{}[/italic] generated[/green]".format(filename))


def main():
    while True:  # loop while we don't get a valid input
        console.print()
        console.print('''Please select from the following options: \n
        1: Specific-User Statistics ([italic dim]User Search[/italic dim])
        2: Top-Talkers Table ([italic dim]Top 10 by Traffic Volume[/italic dim])
        3: All-Users Statistics ([italic dim]Outputs to CSV[/italic dim])
        4: [italic red]Exit the program[/italic red]
        ''')
        user_input = input('Option: ')  # ask the user for input
        if user_input == '1':
            user_input = 'user_stats'
            username = user_stats_2()
            user_stats(username)
        if user_input == '2':
            user_input = 'top_talkers'
            top_talkers()
        if user_input == '3':
            user_input = 'all_users'
            all_users()
        if user_input == '4':
            quit()
        # if it exists...
        if user_input in globals() and callable(globals()[user_input]):
            # store a pointer to the function
            choice = globals()[user_input]
            main()
            break  # break out of the while loop since we have our valid input
        else:
            console.print('\nInvalid option, please try again...',
                          style="bold red")


if __name__ == "__main__":
    main()
