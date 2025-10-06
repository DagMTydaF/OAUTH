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

def register(register_user, totp_code, email_system):
    username = input("USER: ")
    password = input("PASS: ")
    email = input("EMAIL: ")
    phone = input("PHO: ")
    totp = (False, "")
    email_otp =(False, "", "")

    while True:
        resp = call_function(register_user, "register", username=username, password=password, email=email, phone=phone, totp=totp, email_otp=email_otp)
        print(resp)

        if not resp["success"]:
            print(resp["error"]["text"])
            if resp["error"]["code"] == "8x01":
                username = input("USER: ")

            elif resp["error"]["code"] == "8x02":
                secret = call_function(totp_code, "generate_secret")
                qrcode = call_function(totp_code, "generate_qrcode", secret=secret, accountname=email, issuer="PRGA-SECURITY")
                qrcode.print_ascii()

                while True:
                    code = input("TOTP: ")

                    if call_function(totp_code, "check_code", secret=secret, code=code):
                        break

                totp = (True, secret)

            elif resp["error"]["code"] == "8x03":
                secret = call_function(totp_code, "generate_secret")
                otp_code = call_function(totp_code, "totp", secret=secret, interval=600)

                email_content = rf"""<!DOCTYPE html>
                    <html lang="en">
                      <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Your Verification Code</title>
                      </head>
                      <body style="margin:0; padding:0; background-color:#f4f7fb; font-family:Arial, Helvetica, sans-serif; color:#333333;">
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                          <tr>
                            <td align="center" style="padding: 24px 0;">
                              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:600px; background-color:#ffffff; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,0.05);">
                                <tr>
                                  <td align="center" style="padding: 32px 24px 16px 24px;">
                                    <h2 style="margin:0; font-size:22px; color:#0f172a;">Hello {username},</h2>
                                  </td>
                                </tr>

                                <tr>
                                  <td align="center" style="padding: 0 24px 24px 24px;">
                                    <p style="margin:8px 0 18px 0; font-size:16px; color:#475569; line-height:1.5;">
                                      Please use the verification code below to continue your request.
                                    </p>

                                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 0 auto;">
                                      <tr>
                                        <td align="center" bgcolor="#f8fafc" style="padding: 14px 28px; border-radius:8px; border:1px solid #e2e8f0;">
                                          <span style="font-size:28px; letter-spacing:6px; font-weight:bold; font-family: monospace; color:#0f172a;">
                                            {otp_code}
                                          </span>
                                        </td>
                                      </tr>
                                    </table>

                                    <p style="margin:20px 0 0 0; font-size:14px; color:#64748b;">
                                      This code is valid for <strong>10 minutes</strong>.
                                    </p>
                                  </td>
                                </tr>

                                <tr>
                                  <td align="center" style="padding: 24px 24px 16px 24px;">
                                    <p style="margin:0; font-size:14px; color:#94a3b8;">
                                      If you didn’t request this code, please ignore this message.
                                    </p>
                                  </td>
                                </tr>

                                <tr>
                                  <td align="center" bgcolor="#f1f5f9" style="padding: 16px 24px; border-bottom-left-radius:8px; border-bottom-right-radius:8px;">
                                    <p style="margin:0; font-size:13px; color:#94a3b8;">
                                      © 2025 Project-Gamma Security/Verification. All rights reserved.
                                    </p>
                                  </td>
                                </tr>
                              </table>
                            </td>
                          </tr>
                        </table>
                      </body>
                    </html>
                    """

                call_function(email_system, "send", to_email=email, from_email="no-reply-verification@project-gamma.dev", subject=f"Your Verification Code Is: [{otp_code}]", content=email_content, idenity={"use_default": True})

                while True:
                    code = input("TOTP: ")

                    if code == otp_code:
                        break

                email_otp = (True, secret)

        else:
            break

def login(login_user, totp_code, email_system):
    totp = {"code": None, "complete": False}
    email_otp = {"code": None, "complete": False}


    username = input("USER: ")
    passw = input("PASSW: ")

    while True:
        resp = call_function(login_user, "login", type="credentials", idenity={"username": username, "password": passw, "totp": totp, "email_otp": email_otp})

        print(resp)

        if not resp["success"]:
            print(resp["error"]["text"])

            if resp["error"]["code"] in ["9x08", "9x09"]:
                code = input("TOTP CODE: ")

                totp["complete"] = call_function(totp_code, "check_code", secret=resp["idenity"]["totp_secret"], code=code)
                totp["code"] = code

            elif resp["error"]["code"] in ["9x10", "9x11"]:
                offset = call_function(totp_code, "generate_secret")
                otp_code = call_function(totp_code, "totp", secret=resp["idenity"]["email_otp"]+offset, interval=600)
                
                email_content = rf"""<!DOCTYPE html>
                    <html lang="en">
                      <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Your Verification Code</title>
                      </head>
                      <body style="margin:0; padding:0; background-color:#f4f7fb; font-family:Arial, Helvetica, sans-serif; color:#333333;">
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                          <tr>
                            <td align="center" style="padding: 24px 0;">
                              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:600px; background-color:#ffffff; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,0.05);">
                                <tr>
                                  <td align="center" style="padding: 32px 24px 16px 24px;">
                                    <h2 style="margin:0; font-size:22px; color:#0f172a;">Hello {resp["idenity"]["username"]},</h2>
                                  </td>
                                </tr>

                                <tr>
                                  <td align="center" style="padding: 0 24px 24px 24px;">
                                    <p style="margin:8px 0 18px 0; font-size:16px; color:#475569; line-height:1.5;">
                                      Please use the verification code below to continue your request.
                                    </p>

                                    <table role="presentation" border="0" cellpadding="0" cellspacing="0" style="margin: 0 auto;">
                                      <tr>
                                        <td align="center" bgcolor="#f8fafc" style="padding: 14px 28px; border-radius:8px; border:1px solid #e2e8f0;">
                                          <span style="font-size:28px; letter-spacing:6px; font-weight:bold; font-family: monospace; color:#0f172a;">
                                            {otp_code}
                                          </span>
                                        </td>
                                      </tr>
                                    </table>

                                    <p style="margin:20px 0 0 0; font-size:14px; color:#64748b;">
                                      This code is valid for <strong>10 minutes</strong>.
                                    </p>
                                  </td>
                                </tr>

                                <tr>
                                  <td align="center" style="padding: 24px 24px 16px 24px;">
                                    <p style="margin:0; font-size:14px; color:#94a3b8;">
                                      If you didn’t request this code, please ignore this message.
                                    </p>
                                  </td>
                                </tr>

                                <tr>
                                  <td align="center" bgcolor="#f1f5f9" style="padding: 16px 24px; border-bottom-left-radius:8px; border-bottom-right-radius:8px;">
                                    <p style="margin:0; font-size:13px; color:#94a3b8;">
                                      © 2025 Project-Gamma Security/Verification. All rights reserved.
                                    </p>
                                  </td>
                                </tr>
                              </table>
                            </td>
                          </tr>
                        </table>
                      </body>
                    </html>
                    """

                call_function(email_system, "send", to_email=resp["idenity"]["email"], from_email="no-reply-verification@project-gamma.dev", subject=f"Your Verification Code Is: [{otp_code}]", content=email_content, idenity={"use_default": True})

                while True:
                    code = input("OTP: ")

                    if code == otp_code:
                        break

                email_otp = {"code": code, "offset": offset, "complete": True}

            else:
                break

if __name__ == "__main__":
    detected_modules = detect_modules(MODULES_ROOT_PATH)
    
    for module in detected_modules["modules"]:
        print(detected_modules["modules"][module])

    gui_module = detected_modules["modules"]["totp_code"]
    gui = load_module(gui_module["workfolder"], gui_module["runfile"], "gui")

    totp_module = detected_modules["modules"]["totp_code"]
    totp_code = load_module(totp_module["workfolder"], totp_module["runfile"], "totp_code")

    regiser_module = detected_modules["modules"]["register_system"]
    register_user = load_module(regiser_module["workfolder"], regiser_module["runfile"], "register_user")

    login_module = detected_modules["modules"]["login_system"]
    login_user = load_module(login_module["workfolder"], login_module["runfile"], "login_user")

    email_module = detected_modules["modules"]["mail_system"]
    email_system = load_module(email_module["workfolder"], email_module["runfile"], "email_system")

    option = int(input("\n\n\n\nSELECT[1. Login/2. Register]> "))

    if option == 1:
        login(login_user, totp_code, email_system)

    elif option == 2:
        register(register_user, totp_code, email_system)

    else:
        raise(ValueError, "Invalid Option.")