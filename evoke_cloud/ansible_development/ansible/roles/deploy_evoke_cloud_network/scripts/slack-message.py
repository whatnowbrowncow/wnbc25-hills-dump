# Author: A Gittins, C Stafford
# Version: 1.3

"""Slack Messaging for NS Pipelines

This script lists the files in the ansible directory, then looks for files
 that have "retry" in them, reads the contents to a variable and uses this
 variable as the text contents sent to the Network Services Slack webhook.
"""

import os
import sys
# Add the toolset directory to the Python path
sys.path.append(os.path.abspath('wh_net_python_toolset'))
from  wh_net_python_toolset import wh_python_toolset as wh_tools

# Import Standard Network Python Command Line Arguments
parser = wh_tools.import_std_arg()
parser = parser.create_arg()
# Add argument to force failure to make sure message always sent even on sucess
parser.add_argument(
    "--forcefail",
    default=False,
    help=("produce Data files only, Do not show configuration output", "Example --dataonly"),
    action="store_true",
    dest="forcefail",
)

# Add argument to specify the message detail to send to Slack
parser.add_argument(
    "--message_detail",
    default="Slack Message Sent",
    help=("produce Data files only, Do not show configuration output", "Example --message_detail 'This is the message to send"),
    action="store",
    dest="message_detail",
)

arg_items =  parser.parse_args()

# Setup Logger Using Logger Setup in WH Net Python Toolset
logger = wh_tools.logging_define(
          arg_items.level, arg_items.logpath )

prod_logger = logger.logging_setup()
prod_logger.debug("Created Logger")

# Define Slack Message Module and Accept the Channel ID and Bottoken from environment variables
slack_messages = wh_tools.SlackTools(
    channel_id=os.environ['NOTIFICATION_CHANNEL'],
    bottoken=os.environ['NS_SLACK_BOTTOKEN'],
    forcefail=arg_items.forcefail,
    message=arg_items.message_detail,
    allowSuccess=True
)

# Send the Message to the relevant Slack Channel Using Pipeline Variables
slack_messages.send_slack_message()