# anyconnect-usage

## Usage

Navigate to /gitnet/ansible/scripts/anyconnect_usage/ and issue the following command:

```bash
python3 anyconnect_usage.py
```

_\* Due to the number of users connected mid-day the program can take 2-3 minutes to parse all the connection data when you first run the command above. Once parsed, you can navigate the program options and inspect users instantaneously._

## The Challenge

Cisco AnyConnect is the remote access VPN solution we use for remote working and the client is available for both Windows and macOS users. At any one time we can have over one thousand users connected to the remote access VPN, each with their own custom home setup and AnyConnect group-policy. We are often tasked with troubleshooting access issues for remote workers as part of our support of the remote-access VPN solution. When troubleshooting an issue, engineers will first gather the following information from the Cisco ASAs that terminate the remote-access VPN.

### User Information Gathering

- Which DC is active for the remote-access VPN?
- Is the user connected?
- If so, how long has the user been connected?
- Is the user sending and receiving data?
- What OS is the user using?
- What AnyConnect client version is the user using?
- What Group-Policy and VPN-Filter is applied to the user?

### User Access Checks

When all of the above have been confirmed and noted the group-policy is then inspected. User access on the network is restricted based on which _"VPN"_ AD group the user belongs to. This AD group is then used by Cisco ISE to determine which group-policy on the Cisco ASA is applied to the user.

The following group-policy attributes set the network access available to a use. It defines what traffic gets tunnelled and if that traffic is to be permitted or denied.

```
group-policy {{ group-policy }} attributes
 split-tunnel-policy tunnelspecified                                             # only the networks specified will be tunnelled to the ASA
 split-tunnel-network-list value {{ split-tunnel access-list }}                  # identifies the access-list that enumerates the networks to tunnel
 vpn-filter value {{ vpn-filter-list }}                                          # identifies the access-list that permits or denies the tunnelled traffic
 anyconnect-custom dynamic-split-include-domains value {{ dynamic-domain-list }} # identifies the list of domains that will also be tunnelled
```

- Is the destination IP | Domain included in the split-tunnel access-list or dynamic-domain-list?

  - **Yes:** traffic is tunnelled across the remote access VPN.

    - Is the destination IP | Domain permitted in the vpn-filter list?

      - **Yes:** tunnelled traffic to the destination is permitted.
      - **No:** tunnelled traffic to the destination is denied.

  - **No:** traffic egresses locally on to the internet.

The time it takes to gather all of the user information and answer the user access checks on a daily basis can be time consuming.

## The Solution

By utilising Python and Cisco's pyATS parsers we have created "anyconnect_usage.py": a simple Python program for collecting and displaying detailed Cisco AnyConnect information within seconds.

### Workflow Diagram

![Workflow Diagram](./anyconnect_usage-workflow.png "Workflow Diagram")

### AnyConnect Usage Capabilities

- AnyConnect User Profile

[screenshot]

- AnyConnect Top-Talkers Table

[screenshot]

- AnyConnect All Stats Table

[screenshot]
