import colorama
import os
import time
import shutil
import getpass

def current_time():
    return time.strftime("%H:%M:%S")

def clear():
    os.system("clear")

def space(length=1):
    print("\n" * length)
    
def _input(input_type, prompt, return_type="value", options=None):
    colorama.init(autoreset=True)
    
    while True:
        if input_type == "password":
            user_input = getpass.getpass(f"{colorama.Fore.CYAN}{current_time()} Input  | {prompt} ")
        else:
            user_input = input(f"{colorama.Fore.CYAN}{current_time()} Input  | {prompt} ")

        if input_type == "int":
            if user_input.isdigit():
                return int(user_input)
            else:
                print(f"{colorama.Fore.RED}Error: Please enter a valid integer.")
                continue
        
        elif input_type == "str":
            return str(user_input)

        elif input_type == "option":
            if options is None:
                raise ValueError("Options must be provided for 'option' input type.")

            if isinstance(options, dict):
                if user_input in options:
                    return options[user_input] if return_type == "map" else user_input
                else:
                    print(f"{colorama.Fore.YELLOW}Invalid option! Choose one: {list(options.keys())}")
                    continue

            elif isinstance(options, list):
                if user_input in options:
                    return user_input
                else:
                    print(f"{colorama.Fore.YELLOW}Invalid option! Choose one: {options}")
                    continue
            else:
                raise TypeError("Options must be a list or dict.")

        else:
            return user_input

def _print(text, print_type, item_type="text"):
    colorama.init(autoreset=True)

    if item_type == "logo":
        logo = r"""
         _______                                                     __             ______                                                  
        |       \                                                   |  \           /      \                                                 
        | $$$$$$$\  ______    ______       __   ______    _______  _| $$_         |  $$$$$$\  ______   ______ ____   ______ ____    ______  
        | $$__/ $$ /      \  /      \     |  \ /      \  /       \|   $$ \        | $$ __\$$ |      \ |      \    \ |      \    \  |      \ 
        | $$    $$|  $$$$$$\|  $$$$$$\     \$$|  $$$$$$\|  $$$$$$$ \$$$$$$        | $$|    \  \$$$$$$\| $$$$$$\$$$$\| $$$$$$\$$$$\  \$$$$$$\
        | $$$$$$$ | $$   \$$| $$  | $$    |  \| $$    $$| $$        | $$ __       | $$ \$$$$ /      $$| $$ | $$ | $$| $$ | $$ | $$ /      $$
        | $$      | $$      | $$__/ $$    | $$| $$$$$$$$| $$_____   | $$|  \      | $$__| $$|  $$$$$$$| $$ | $$ | $$| $$ | $$ | $$|  $$$$$$$
        | $$      | $$       \$$    $$    | $$ \$$     \ \$$     \   \$$  $$       \$$    $$ \$$    $$| $$ | $$ | $$| $$ | $$ | $$ \$$    $$
         \$$       \$$        \$$$$$$__   | $$  \$$$$$$$  \$$$$$$$    \$$$$         \$$$$$$   \$$$$$$$ \$$  \$$  \$$ \$$  \$$  \$$  \$$$$$$$
                                    |  \__/ $$                                                                                              
                                     \$$    $$                                                                                              
                                      \$$$$$$                                                                                               
        """

        terminal_width = shutil.get_terminal_size().columns
        colored_logo = colorama.Fore.LIGHTYELLOW_EX + colorama.Style.BRIGHT + "\n".join(
            line.center(terminal_width) for line in logo.splitlines()
        )

        print(colored_logo + "\n")

    elif item_type == "app-info":
        application_data = text.split("&")

        for information in application_data:
            info_parts = information.split("%")

            _print(f"{info_parts[1]}: {info_parts[2]}", info_parts[0], "text")

    elif item_type == "text":
        if print_type == "info":
            print(f"{colorama.Fore.CYAN}{current_time()}  Info   | {text} ")

        elif print_type == "error":
            print(f"{colorama.Fore.RED}{current_time()}  Error  | {text} ")

        elif print_type == "warning":
                print(f"{colorama.Fore.YELLOW}{current_time()} Warning | {text} ")

        elif print_type == "success":
                print(f"{colorama.Fore.GREEN}{current_time()} Success | {text} ")

        else:
            print(f"{colorama.Fore.LIGHTBLACK_EX}{current_time()} | {text} ")