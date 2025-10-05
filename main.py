import os
import sys
import time
import hmac
import pathlib
import importlib.util

MODULES_ROOT_PATH = "./oauth_modules"

def parse_functions(raw: str) -> dict:
    functions = {}
    for fn in raw.split("!"):
        fn = fn.strip()
        if not fn:
            continue

        parts = fn.split("&")
        name = parts[0]
        functions[name] = {"required": [], "optional": []}

        for arg in parts[1:]:
            if arg.startswith("*"):
                functions[name]["required"].append(arg[1:])
            else:
                functions[name]["optional"].append(arg)

    return functions

def detect_modules(modules_root_path: str) -> dict:
    root = pathlib.Path(modules_root_path)

    if not root.exists():
        return {
            "success": False,
            "error": {"text": "Modules Root Folder not Found.", "code": "6x04"},
            "modules": {}
        }

    module_files = list(root.glob("*.oauth_module"))
    if not module_files:
        return {
            "success": False,
            "error": {"text": "Modules Root Folder Empty.", "code": "6x05"},
            "modules": {}
        }

    modules_detected = {}
    for file in module_files:
        with open(file, "r") as f:
            lines = [line.strip().split("$", 1) for line in f]

        identity = {}
        for section in lines:
            key, value = section[0], section[1]

            if key == "functions":
                identity["functions"] = parse_functions(value)

            else:
                identity[key] = value.replace("%root%", str(root))

        modules_detected[file.stem] = identity

    if not modules_detected:
        return {
            "success": False,
            "error": {"text": "No Modules Found.", "code": "6x06"},
            "modules": {}
        }

    return {
        "success": True,
        "error": None,
        "modules": modules_detected
    }

def load_module(workfolder: str, runfile: str, module_name: str):
    file_path = pathlib.Path(workfolder) / runfile

    if not file_path.exists():
        raise FileNotFoundError(f"Runfile not found: {file_path}")

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return module

def call_function(module, func_name: str, **kwargs):
    if not hasattr(module, func_name):
        raise AttributeError(f"Function '{func_name}' not found in module.")
    
    func = getattr(module, func_name)

    return func(**kwargs)

def register(totp_code, register_user):
    username = input("USER: ")
    password = input("PASS: ")
    email = input("EMAIL: ")
    phone = input("PHO: ")
    totp = (False, "")

    while True:
        resp = call_function(register_user, "register", username=username, password=password, email=email, phone=phone, totp=totp)
        print(resp)

        if not resp["success"]:
            print(resp["error"]["text"])
            if resp["error"]["code"] == "8x01":
                username = input("USER: ")

            elif resp["error"]["code"]  == "8x02":
                secret = call_function(totp_code, "generate_secret")
                qrcode = call_function(totp_code, "generate_qrcode", secret=secret, accountname=email, issuer="PRGA-SECURITY")
                qrcode.print_ascii()

                while True:
                    code = input("TOTP: ")

                    if call_function(totp_code, "check_code", secret=secret, code=code):
                        break

                totp = (True, secret)

        else:
            break

def login(totp_code, login_user):
    totp = {"code": None, "complete": False}

    username = input("USER: ")
    passw = input("PASSW: ")

    while True:
        resp = call_function(login_user, "login", type="credentials", idenity={"username": username, "password": passw, "totp": totp})

        print(resp)

        if not resp["success"]:
            print(resp["error"]["text"])

            if resp["error"]["code"] in ["9x08", "9x09"]:
                code = input("TOTP CODE: ")

                totp["complete"] = call_function(totp_code, "check_code", secret=resp["idenity"]["totp_secret"], code=code)
                print(totp["complete"])
                totp["code"] = code

            else:
                break

if __name__ == "__main__":
    detected_modules = detect_modules(MODULES_ROOT_PATH)
    
    for module in detected_modules["modules"]:
        print(detected_modules["modules"][module])

    totp_module = detected_modules["modules"]["totp_code"]
    totp_code = load_module(totp_module["workfolder"], totp_module["runfile"], "totp_code")

    regiser_module = detected_modules["modules"]["register_system"]
    register_user = load_module(regiser_module["workfolder"], regiser_module["runfile"], "register_user")

    login_module = detected_modules["modules"]["login_system"]
    login_user = load_module(login_module["workfolder"], login_module["runfile"], "login_user")

    option = int(input("\n\n\n\nSELECT[1. Login/2. Register]> "))

    if option == 1:
        login(totp_code, login_user)

    elif option == 2:
        register(totp_code, register_user)

    else:
        raise(ValueError, "Invalid Option.")