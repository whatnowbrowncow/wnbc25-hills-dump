# Legacy Access Check Script

|Version | Date| Summary| Current Version|
|:---:|:---:|:---:|:---:|
|1.0|20/11/2025| Initial Build||

## Reason

The Legacy Access Check script was designed to validate connectivity and access to network devices across an inventory by running a platform-specific "check" command (such as `show version`) using Nornir and Netmiko.

The original reason for creating this script is to provide a quick, reliable method to verify device accessibility across the entire estate without manual device-by-device testing. This helps identify connectivity issues, authentication problems, and device availability in an automated, repeatable manner.

## Objectives

The objective of the script is to:

* Accept a source of truth inventory file (WH_inv.yml or 888_inv.yml) with device definitions and platform-specific check commands
* Retrieve platform-specific check command results from each device in the target inventory
* Validate device accessibility and connectivity
* Compile results into a summary table
* Log detailed results for troubleshooting and audit purposes

        NOTE: One of the key objectives is that the script is simple to run, requires minimal credentials, and provides clear output indicating which devices are accessible and which are not.

---

## Dependencies

In order to run this script the following is required

**Python Versions**

 Minimum: 3.8
 Versions Tested:
 * 3.11.5

**Python Modules**

* nornir
* nornir_netmiko
* netmiko
* tqdm
* termcolor
* tabulate

NOTE: To install the above, run the script install.sh

**Custom Modules**
| Name| Git URL Location| Local File Location Required|
|---|---|---|
| wh_net_python_toolset| git@gitlab.com:williamhillplc/technical-services/networks/automation-tools/wh-net-python-toolset.git | /gitnet/Automation Tools/wh_net_python_toolset/|
| pipeline_password_encrypt| git@gitlab.com:williamhillplc/technical-services/networks/do-shared-python-functions.git| /gitnet/do-shared-python-functions/pipeline/|

**Installation Steps**
To install this on your machine clone the repo into the /gitnet directory

Before the first run, ensure dependencies are installed:

```bash
cd /gitnet/network-wip/legacy_access_check
./install.sh
```

---

## How does it work?

### Calling the script example

An example of how you call the script is as follows:

```bash
python legacy_access_check.py [--filter <filter>] [--check] [--dataonly]
```

Examples:

```bash
# Interactive selection and credentials prompt
python legacy_access_check.py

# Use environment variables to avoid interactive prompts
export UN=admin
export PASS=secret
export CONFIG_OPTION=1   # 1 => WH_inv.yml, 2 => 888_inv.yml
python legacy_access_check.py --filter site=brs_lab
```

### Command-line Parameters

The following parameters are available:

#### --filter

|Type| Example| Description|
|---|---|---|
|site| site=brs_lab| Filter by Site Name (as defined in the nornir inventory)|
|env| env=prod| Filter by Environment (as defined in the nornir inventory)|
|hosts| hosts=uk-sc1-cs01| Filter by Hostname (as defined in the nornir inventory). Multiple values separated by comma|
|groups| groups=brs_lab| Filter by Group Name. Multiple values separated by comma|
|platform| platform=ios| Filter by OS (as defined in the nornir inventory). Multiple values separated by comma|

#### --check

Run in check mode (default behavior). Sets `dest='dry_run'` in the parser.

#### --dataonly

Produce data files only; do not show configuration output.

#### Default Variables

|Variable | Data|
|:---:|:---:|
|--filter| =all|
|--check| True|
|--dataonly| False|

### Environment Variables

* **`CONFIG_OPTION`**: Numeric selection for inventory file: `1` = WH_inv.yml, `2` = 888_inv.yml. If not set, script prompts interactively.
* **`UN`**: Username for device authentication. If not set, script prompts.
* **`PASS`**: Password for device authentication. If not set, script prompts.

### Important Files & Paths

* **Main script**: `legacy_access_check.py`
* **Inventory files**: `WH_inv.yml`, `888_inv.yml` (next to the script)
* **Processed data**: `/gitnet/processed_data/net_access_check`
* **Log folder**: `/gitnet/processed_data/log`
* **Output folder**: `/gitnet/processed_data` (automatically created)

---

## Walkthrough

The script starts in `legacy_access_check.py`, which is broken down into several sections.

### Stage 1: Initialization and Setup

Within stage 1, the script:

* Imports all required modules (Nornir, Netmiko, wh_tools, etc.)
* Sets up global variables and configuration
* Creates the required folder structure in `/gitnet/processed_data` (log, net_access_check folders)
* Parses command-line arguments using the wh_tools standard argument parser
* Sets up logging via `wh_tools.logging_define()`

### Stage 2: Configuration Selection

Stage 2 determines which inventory file to use:

* If `CONFIG_OPTION` environment variable is not set, displays interactive menu to select between William Hill (1) or 888 (2) environments
* Loads the appropriate inventory file (`WH_inv.yml` or `888_inv.yml`)
* Logs the selected configuration for audit purposes

### Stage 3: Credential Management

Stage 3 handles credential collection:

* If `UN` environment variable is not set, prompts user for username
* If `PASS` environment variable is not set, prompts user for password (masked input via `getpass`)
* Applies credentials to the Nornir inventory defaults

### Stage 4: Inventory Setup and Filtering

Stage 4 processes the inventory:

* Calls `inv_data.setup_hosts()` to resolve the inventory using Nornir
* Applies filters (if specified via `--filter` parameter) to narrow down target devices
* Logs the number of resolved hosts for verification

### Stage 5: Device Access Check

Stage 5 is the main device testing loop:

* Iterates through each device in the filtered inventory
* Retrieves the platform-specific `check_command` from the inventory group data: `current_host.inventory.groups[device_obj.platform].data['check_command']`
* Executes the check command on each device using Nornir + Netmiko with `use_genie=True` and `use_timing=True`
* Tracks success/failure status for each device
* Displays progress using tqdm progress bar

### Stage 6: Results Compilation and Output

Stage 6 finalizes the run:

* Aggregates all device test results into a summary table
* Prints the formatted results table to console using `tabulate`
* Logs detailed results (success and failures) to files in `/gitnet/processed_data/log`
* Handles any exceptions and displays error messages to the user

---

### Other Documents and Information

If any issues are found please log at the repository issue tracker.

### Author Information

Script authors: Chris Stafford (2025).
README authors: Chris Stafford (2025).
