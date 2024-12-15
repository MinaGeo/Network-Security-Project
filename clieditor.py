"""
    ## Extending Eran Ulas' Chatting Application
    ## Team 24
"""

from colorama import Fore, Style, init
from pyfiglet import Figlet
from rich import print as p
import re
import datetime

# Initialize colorama
init()


def activate_link(messageReceived):
    # Regular expression to match URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, messageReceived)

    # Replace each URL with a purple link
    for url in urls:
        messageReceived = messageReceived.replace(url, f'{Fore.MAGENTA}{url}{Style.RESET_ALL}')

    return messageReceived


def title(text):
    fig = Figlet(font='starwars', width=200)
    styled_text = f"{Fore.LIGHTWHITE_EX}{Style.BRIGHT}{fig.renderText(text)}{Style.RESET_ALL}"
    print(styled_text)


def green_message(message, color=Fore.LIGHTGREEN_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')


def red_message(message, color=Fore.LIGHTRED_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')


def green_message_formatted_chatroom(message, color=Fore.LIGHTGREEN_EX, style=Style.RESET_ALL):
    p(f"{style}{color}{message}{Style.RESET_ALL}")


def green_message_ok(message, color=Fore.LIGHTGREEN_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}")


def red_message_reject(message, color=Fore.LIGHTRED_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}")


def yellow_message(message, color=Fore.LIGHTYELLOW_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')


def blue_message(message, color=Fore.LIGHTBLUE_EX, style=Style.RESET_ALL):
    print(f"{style}{color}{message}{Style.RESET_ALL}", end='\n')


def green_message_without_space(message, color=Fore.LIGHTGREEN_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"


def yellow_message_without_space(message, color=Fore.LIGHTYELLOW_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"


def red_message_without_space(message, color=Fore.LIGHTRED_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"


def blue_message_without_space(message, color=Fore.LIGHTBLUE_EX, style=Style.RESET_ALL):
    return f"{style}{color}{message}{Style.RESET_ALL}"


def format_message(messageReceived):
    # Split the message into parts using ':' as the delimiter
    parts = messageReceived.split(':', 1)  # The second argument limits the number of splits to 1

    # Extract the username (if available)
    if len(parts) >= 1:
        username = parts[0].strip()  # Strip to remove leading and trailin
        # rest = parts[1].strip()

    if messageReceived.endswith("/B"):
        # Remove the last two characters "/B" and make the messageReceived bold
        p(username + ":" + "[bold]" + messageReceived[len(username) + 1:-2] + "[/bold]" + "  " + str(
            datetime.datetime.now().strftime('%H:%M')))

    elif messageReceived.endswith("/I"):
        # Remove the last two characters "/I" and make the messageReceived italic
        p(username + ":" + "[italic]" + messageReceived[len(username)+1:-2] + "[/italic]" + "  " + str(
            datetime.datetime.now().strftime('%H:%M')))
    else:
        # print it as is
        green_message(messageReceived + "  " + str(datetime.datetime.now().strftime('%H:%M')))