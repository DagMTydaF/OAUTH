import os
import sys
import time
import getpass
from colorama import Fore, Style, init

init(autoreset=True)

_LOGO_CACHE = None

def _fast_write_block(text):
    sys.stdout.write(text)
    sys.stdout.flush()

def clear():
    if sys.platform.startswith("win"):
        os.system("cls")
    else:
        sys.stdout.write("\033c")
        sys.stdout.flush()


def space(length=1):
    sys.stdout.write("\n" * (length if length > 0 else 1))
    sys.stdout.flush()


def _print(text="", print_type="", item_type="text"):
    global _LOGO_CACHE

    if item_type == "logo":
        if _LOGO_CACHE is None:
            _LOGO_CACHE = r"""
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
        """.rstrip("\n")

        _fast_write_block(Fore.YELLOW + _LOGO_CACHE + Style.RESET_ALL + "\n")
        return

    if item_type == "app-info":
        try:
            parts = text.split("&")
            for p in parts:
                if not p.strip():
                    continue
                kind, key, val = p.split("%", 2)
                if kind == "info":
                    color = Fore.GREEN
                elif kind == "error":
                    color = Fore.RED
                else:
                    color = Fore.WHITE
                _fast_write_block(f"{color}{key}: {val}{Style.RESET_ALL}\n")
        except Exception as e:
            _fast_write_block(Fore.RED + f"[APP-INFO ERROR] {e}\n" + Style.RESET_ALL)
        return

    if print_type == "error":
        color = Fore.RED
    elif print_type == "success":
        color = Fore.GREEN
    elif print_type == "warning":
        color = Fore.YELLOW
    else:
        color = Fore.WHITE

    if "\n" in text and (len(text) > 100 or text.count("\n") > 3):
        _fast_write_block(color + text + Style.RESET_ALL + "\n")
    else:
        sys.stdout.write(color + text + Style.RESET_ALL + "\n")
        sys.stdout.flush()

def _input(input_type="str", prompt="", options=None):
    options = options or []

    if input_type == "password":
        sys.stdout.write(Fore.CYAN + prompt + Style.RESET_ALL)
        sys.stdout.flush()

        return getpass.getpass("")

    resp = input(Fore.CYAN + prompt + Style.RESET_ALL)

    if options and str(resp) not in [str(o) for o in options]:
        sys.stdout.write(Fore.RED + "Invalid selection.\n" + Style.RESET_ALL)
        sys.stdout.flush()
        return _input(input_type, prompt, options)

    if input_type == "int":
        try:
            return int(resp)
        except Exception:
            return resp

    return resp
