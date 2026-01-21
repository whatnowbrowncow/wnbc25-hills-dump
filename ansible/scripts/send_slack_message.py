import os
import sys
sys.path.append('/gitnet/automation-tools')
from  wh_net_python_toolset import wh_python_toolset as wh_tools

parser = wh_tools.import_std_arg()
parser = parser.create_arg()
parser.add_argument(
    "-c",
    default=False,
    help=("Channel ID", "Example -c 'ABCDE12345'"),
    action="store",
    dest="channel_id",
)

parser.add_argument(
    "-m",
    default=False,
    help=("Message Text", "Example -m 'This is a test'"),
    action="store",
    dest="message",
)

parser.add_argument(
    "-bt",
    default=False,
    help=("Bottoken", "Example -bt 'ABCDE12345'"),
    action="store",
    dest="bottoken",
)


arg_items =  parser.parse_args()
logger = wh_tools.logging_define(
          arg_items.level, arg_items.logpath )

prod_logger = logger.logging_setup()
prod_logger.debug("Created Logger")
slack_messages = wh_tools.SlackTools(channel_id=arg_items.channel_id,bottoken=arg_items.bottoken,message=arg_items.message)
slack_messages.send_slack_message()