import os
import sys
import time
import hmac
import json
import base64
import hmac
import hashlib
import time
import uuid
import pathlib
import importlib.util
from flask import Flask, request, jsonify, redirect, url_for, render_template, make_response

MODULES_ROOT_PATH = "./oauth_modules"

def parse_functions(raw: str) -> dict:
    functions = {}
    for fn in raw.split("!"):
        fn = fn.strip()
        if not fn:
            continue

        parts = fn.split("&")
        name = parts[0]
        funcs = {"required": [], "optional": []}

        for arg in parts[1:]:
            if arg.startswith("*"):
                funcs["required"].append(arg[1:])
            else:
                funcs["optional"].append(arg)

        functions[name] = funcs
    return functions

def detect_modules(modules_root_path: str) -> dict:
    root = pathlib.Path(modules_root_path)

    if not root.exists():
        return {"success": False, "error": {"text": "Modules Root Folder not Found.", "code": "6x04"}, "modules": {}}

    module_files = list(root.glob("*.oauth_module"))
    if not module_files:
        return {"success": False, "error": {"text": "Modules Root Folder Empty.", "code": "6x05"}, "modules": {}}

    modules_detected = {}
    for file in module_files:
        try:
            with open(file, "r") as f:
                lines = [line.strip().split("$", 1) for line in f if "$" in line]
        except Exception as e:
            continue

        identity = {}
        for section in lines:
            key, value = section[0], section[1]
            if key == "functions":
                identity["functions"] = parse_functions(value)
            else:
                identity[key] = value.replace("%root%", str(root))

        modules_detected[file.stem] = identity

    if not modules_detected:
        return {"success": False, "error": {"text": "No Modules Found.", "code": "6x06"}, "modules": {}}

    return {"success": True, "error": None, "modules": modules_detected}

def load_module(workfolder: str, runfile: str, module_name: str):
    file_path = pathlib.Path(workfolder) / runfile
    if not file_path.exists():
        raise FileNotFoundError(f"Runfile not found: {file_path}")

    if module_name in sys.modules:  # ✅ Cache check
        return sys.modules[module_name]

    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

def call_function(module, func_name: str, **kwargs):
    cache = getattr(call_function, "_cache", None)
    if cache is None:
        cache = call_function._cache = {}

    key = (id(module), func_name)
    func = cache.get(key)

    if func is None:
        if not hasattr(module, func_name):
            raise AttributeError(f"Function '{func_name}' not found in module.")
        func = getattr(module, func_name)
        cache[key] = func

    return func(**kwargs)

def register(register_user, totp_code, email_system):
    username = call_function(gui, "_input", input_type="str", prompt="Username $> ")
    password = call_function(gui, "_input", input_type="password", prompt="Password (Hidden) $> ")
    email = call_function(gui, "_input", input_type="str", prompt="Email $> ")
    phone = call_function(gui, "_input", input_type="str", prompt="Phone $> ")

    totp = (False, "")
    email_otp = (False, "", "")

    user = {}

    while True:
        resp = call_function(register_user, "register",
                             username=username, password=password, email=email, phone=phone,
                             totp=totp, email_otp=email_otp)

        if not resp["success"]:
            err_code = resp["error"]["code"]

            if err_code == "8x01":
                call_function(gui, "space")
                call_function(gui, "_print", text="Username Taken", print_type="error", item_type="text")
                username = call_function(gui, "_input", input_type="str", prompt="Username $> ")

            elif err_code == "8x02":
                call_function(gui, "space")
                call_function(gui, "_print", text="Authenticator App Required.", print_type="warning", item_type="text")

                secret = call_function(totp_code, "generate_secret")
                qrcode = call_function(totp_code, "generate_qrcode", secret=secret, accountname=email, issuer="PRGA-SECURITY")
                qrcode.print_ascii()

                call_function(gui, "_print", text="Enter The 6 Digit Code Generated From Your Authenticator App Required.", print_type="warning", item_type="text")

                attempt = 0
                while True:
                    if attempt > 0:
                        call_function(gui, "space")
                        call_function(gui, "_print", text="The Entered 6 Digit Code Is Incorrect.", print_type="error", item_type="text")

                    code = call_function(gui, "_input", input_type="str", prompt="6 Digit Code (AUTHA)$> ")
                    if call_function(totp_code, "check_code", secret=secret, code=code):
                        call_function(gui, "_print", text="Authenticator App Successfully Added.", print_type="success", item_type="text")
                        break
                    attempt += 1

                totp = (True, secret)

            elif err_code == "8x03":
                call_function(gui, "space")
                call_function(gui, "_print", text="Email Verification Required.", print_type="warning", item_type="text")

                secret = call_function(totp_code, "generate_secret")
                otp_code = call_function(totp_code, "totp", secret=secret, interval=600)

                email_template = register._email_template.replace("{username}", username).replace("{otp_code}", otp_code)
                call_function(email_system, "send",
                              to_email=email,
                              from_email="no-reply-verification@project-gamma.dev",
                              subject=f"Your Verification Code Is: [{otp_code}]",
                              content=email_template,
                              idenity={"use_default": True})

                call_function(gui, "_print",
                              text=f"Enter The 6 Digit Code Sent to \"{email.split('@')[0][:2]}****@{email.split('@')[1]}\".",
                              print_type="", item_type="text")

                attempt = 0
                while True:
                    if attempt > 0:
                        call_function(gui, "space")
                        call_function(gui, "_print", text="The Entered 6 Digit Code Is Incorrect.", print_type="error", item_type="text")
                    code = call_function(gui, "_input", input_type="str", prompt="6 Digit Code (EMAIL)$> ")
                    if code == otp_code:
                        call_function(gui, "_print", text="Email Successfully Verified.", print_type="success", item_type="text")
                        break
                    attempt += 1

                email_otp = (True, secret)
        else:
            break

register._email_template = r"""<!DOCTYPE html>
<html lang="en">
  <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Your Verification Code</title></head>
  <body style="margin:0;padding:0;background-color:#f4f7fb;font-family:Arial,Helvetica,sans-serif;color:#333;">
  <table border="0" cellpadding="0" cellspacing="0" width="100%">
    <tr><td align="center" style="padding:24px 0;">
      <table width="100%" style="max-width:600px;background-color:#fff;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,0.05);">
        <tr><td align="center" style="padding:32px 24px 16px 24px;">
          <h2 style="margin:0;font-size:22px;color:#0f172a;">Hello {username},</h2>
        </td></tr>
        <tr><td align="center" style="padding:0 24px 24px 24px;">
          <p style="margin:8px 0 18px 0;font-size:16px;color:#475569;">Please use the verification code below to continue your request.</p>
          <div style="padding:14px 28px;border-radius:8px;border:1px solid #e2e8f0;display:inline-block;background:#f8fafc;">
            <span style="font-size:28px;letter-spacing:6px;font-weight:bold;font-family:monospace;color:#0f172a;">{otp_code}</span>
          </div>
          <p style="margin:20px 0 0 0;font-size:14px;color:#64748b;">This code is valid for <strong>10 minutes</strong>.</p>
        </td></tr>
        <tr><td align="center" bgcolor="#f1f5f9" style="padding:16px 24px;border-radius:0 0 8px 8px;">
          <p style="margin:0;font-size:13px;color:#94a3b8;">© 2025 Project-Gamma Security. All rights reserved.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
  </body>
</html>
"""

def login(login_user, totp_code, email_system):
    totp = {"code": None, "complete": False}
    email_otp = {"code": None, "complete": False}

    username = call_function(gui, "_input", input_type="str", prompt="Username $> ")
    password = call_function(gui, "_input", input_type="password", prompt="Password (Hidden) $> ")

    while True:
        resp = call_function(login_user, "login", type="credentials",
                             idenity={"username": username, "password": password, "totp": totp, "email_otp": email_otp})

        if not resp["success"]:
            err_code = resp["error"]["code"]

            if err_code in ("9x08", "9x09"):
                call_function(gui, "space")
                call_function(gui, "_print", text="Enter The 6 Digit Code Generated From Your Authenticator App.", print_type="", item_type="text")
                code = call_function(gui, "_input", input_type="str", prompt="6 Digit Code (AUTHA)$> ")
                totp["complete"] = call_function(totp_code, "check_code", secret=resp["idenity"]["totp_secret"], code=code)
                totp["code"] = code

            elif err_code in ("9x10", "9x11"):
                offset = call_function(totp_code, "generate_secret")
                otp_code = call_function(totp_code, "totp", secret=resp["idenity"]["email_otp"] + offset, interval=600)

                email_template = register._email_template.replace("{username}", resp["idenity"]["username"]).replace("{otp_code}", otp_code)
                call_function(email_system, "send",
                              to_email=resp["idenity"]["email"],
                              from_email="no-reply-verification@project-gamma.dev",
                              subject=f"Your Verification Code Is: [{otp_code}]",
                              content=email_template,
                              idenity={"use_default": True})

                attempt = 0
                while True:
                    if attempt == 0:
                        call_function(gui, "space")
                        call_function(gui, "_print",
                                      text=f"Enter The 6 Digit Code Sent to \"{resp['idenity']['email'].split('@')[0][:2]}****@{resp['idenity']['email'].split('@')[1]}\".",
                                      print_type="", item_type="text")
                    else:
                        call_function(gui, "space")
                        call_function(gui, "_print", text="The Entered 6 Digit Code Is Incorrect.", print_type="error", item_type="text")

                    code = call_function(gui, "_input", input_type="str", prompt="6 Digit Code (EMAIL)$> ")
                    if code == otp_code:
                        break
                    attempt += 1

                email_otp = {"code": code, "offset": offset, "complete": True}

            else:
                break
        else:
            return resp["idenity"]

def get_user(login_user, register_user, totp_code, email_system):
    call_function(gui, "space", length=2)
    call_function(gui, "_print", text="1. Login | 2. Register", print_type="", item_type="text")

    selection = call_function(gui, "_input", input_type="int", prompt="select $> ", options=["1", "2"])
    return login(login_user, totp_code, email_system) if selection == 1 else register(register_user, totp_code, email_system)

############################################################################################################################

login_sessions = {}
register_sessions = {}

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def generate_signature(header_b64, payload_b64, secret):
    message = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).digest()
    return base64url_encode(signature)


def generate_jwt_token(headers, payload, secret, expire_seconds = 3600):
    payload_copy = payload.copy()
    
    header_b64 = base64url_encode(json.dumps(headers, separators=(",", ":")).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload_copy, separators=(",", ":")).encode("utf-8"))
    signature_b64 = generate_signature(header_b64, payload_b64, secret)
    
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    return token

def delete_jwt_cookies():
    resp = make_response(redirect(url_for("home")))

    resp.delete_cookie("session_id")
    resp.delete_cookie("userprofile")
    resp.delete_cookie("expire")
    resp.delete_cookie("token")

    return resp

def verify_jwt_token_helper(token, session, secret):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid token format")

    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

    expected_signature = generate_signature(parts[0], parts[1], secret)

    if parts[2] != expected_signature or time.time() >= int(payload["expire"]) or int(payload["expire"]) != session["expire"] or payload["session"] != session["id"]:
        return False

    return True

def verify_jwt_token(token, session, secret):
    if not verify_jwt_token_helper(token, session, secret):
        return delete_jwt_cookies()

    return True

def generate_login_session(TTL=300):
    session_uuid = str(uuid.uuid4())
    step = 0
    auth_type = "username"
    error = ""
    error_text = ""
    error_code = ""

    login_sessions[session_uuid] = {
        "step": step,
        "auth_type": auth_type,
        "exp": time.time() + TTL,
        "username": None,
        "password": None,
        "email": None,
        "email_encrypted": None,
        "totp": {"code": None, "complete": False},
        "email_otp": {"code": None, "offset": None, "complete": False}
    }

    return {"session": session_uuid, "step": step, "auth_type": auth_type}

def generate_register_session(TTL=300):
    session_uuid = str(uuid.uuid4())
    step = 0
    auth_type = "username"
    error = ""
    error_text = ""
    error_code = ""

    register_sessions[session_uuid] = {
        "step": step,
        "auth_type": auth_type,
        "exp": time.time() + TTL,
        "username": None,
        "password": None,
        "email": None,
        "phone": None,
        "email_encrypted": None,
        "totp_url": None,
        "totp": {"code": None, "secret": None, "complete": False},
        "email_otp": {"code": None, "secret": None, "complete": False}
    }

    return {"session": session_uuid, "step": step, "auth_type": auth_type}

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login_post():
    session = request.form.get("session")

    if not login_sessions.get(session, {}):
        return url_for("login_get")

    step = int(request.form.get("step"))
    auth_type = request.form.get("auth_type")

    login_attempt = {}

    if login_sessions[session]["step"] == step == 0 and auth_type == login_sessions[session]["auth_type"]:
        login_sessions[session]["username"] = request.form.get("username")
        login_sessions[session]["password"] = request.form.get("password")

    elif login_sessions[session]["step"] == step == 1 and auth_type == login_sessions[session]["auth_type"]:
        login_sessions[session]["totp"]["code"] = request.form.get("code")
        login_sessions[session]["totp"]["complete"] = True

    elif login_sessions[session]["step"] == step == 2 and auth_type == login_sessions[session]["auth_type"]:
        login_sessions[session]["email_otp"]["code"] = request.form.get("code")
        login_sessions[session]["email_otp"]["complete"] = True

    else:
        args = {}

        args["session"] = session
        args["step"] = login_sessions[session]["step"]
        args["auth_type"] = login_sessions[session]["auth_type"]
        args["error"] = "true"
        args["error_code"] = "0x01"
        args["error_text"]  =  "Auto Redirect!"

        return redirect(url_for("login_get", **args))

    login_attempt = call_function(login_user, "login", type="credentials", idenity={"username": login_sessions[session]["username"], "password": login_sessions[session]["password"], "totp": login_sessions[session]["totp"], "email_otp": login_sessions[session]["email_otp"]})

    if not login_attempt["success"]:
        if login_attempt["error"]["code"] == "9x08":
            login_sessions[session]["step"] = step = 1
            login_sessions[session]["auth_type"] = auth_type = "2fa"

        elif login_attempt["error"]["code"] == "9x10":
            login_sessions[session]["email_otp"]["offset"] = call_function(totp_code, "generate_secret")
            otp_code = call_function(totp_code, "totp", secret=login_attempt["idenity"]["email_otp"] + login_sessions[session]["email_otp"]["offset"], interval=600)

            email_template = register._email_template.replace("{username}", login_sessions[session]["username"]).replace("{otp_code}", otp_code)
            call_function(email_system, "send", to_email=login_attempt["idenity"]["email"], from_email="no-reply-verification@project-gamma.dev", subject=f"Your Verification Code Is: [{otp_code}]", content=email_template, idenity={"use_default": True})

            login_sessions[session]["step"] = step = 2
            login_sessions[session]["auth_type"] = auth_type = "email"
            login_sessions[session]["email"] = login_attempt['idenity']['email']
            login_sessions[session]["email_encrypted"] = f"{login_attempt['idenity']['email'].split('@')[0][:2]}****@{login_attempt['idenity']['email'].split('@')[1]}"

        args = {}

        args["session"] = session
        args["step"] = step
        args["auth_type"] = auth_type
        args["error"] = "true"
        args["error_code"]  = login_attempt["error"]["code"]
        args["error_text"]  =  login_attempt["error"]["text"]

        return redirect(url_for("login_get", **args))

    login_sessions.pop(session, None)

    session_id = str(uuid.uuid4())

    expire = str(int(time.time()) + 7200)
    headers = {"alg": "HS256-V1", "type": "JWT"}
    payload = {"userid": str(login_attempt["idenity"]["userid"]), "session": session_id, "expire": expire}
    secret = "mF8Zqv7QyRk1pXJwN6TgHsV9aB3uL0cD5eKj2YhWfA"

    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session_id, max_age=3600, httponly=True, samesite="Lax")
    resp.set_cookie("userprofile", str(login_attempt["idenity"]["userid"]), max_age=7200, httponly=True, samesite="Lax")
    resp.set_cookie("expire", expire, max_age=7200, httponly=True, samesite="Lax")
    resp.set_cookie("token", generate_jwt_token(headers, payload, secret), max_age=3600, httponly=True, samesite="Lax")

    return resp

@app.route("/login", methods=["GET"])
def login_get():
    session = request.args.get("session")

    if "session" not in request.args or not login_sessions.get(session, {}):
        session_args = generate_login_session()
        return redirect(url_for("login_get", **session_args))

    auth_type = request.args.get("auth_type", "username")
    step = request.args.get("step")
    error = request.args.get("error")
    error_text = request.args.get("error_text")
    error_code = request.args.get("error_code")

    current_session = login_sessions[session]

    if auth_type == "email":
        return render_template("login_email.html", email=current_session["email_encrypted"], error_text=error_text, error_code=error_code)

    elif auth_type in ("authenticator", "2fa"):
        return render_template("login_authenticator.html", error_text=error_text, error_code=error_code)

    else:
        return render_template("login_credentials.html", error_text=error_text, error_code=error_code)

@app.route("/register", methods=["POST"])
def register_post():
    session = request.form.get("session")

    if not register_sessions.get(session, {}):
        return redirect(url_for("register_get"))

    step = int(request.form.get("step"))
    auth_type = request.form.get("auth_type")

    register_attempt = {}

    if (register_sessions[session]["step"] == step == 0 ) and auth_type == register_sessions[session]["auth_type"]:
        register_sessions[session]["username"] = request.form.get("username")
        register_sessions[session]["password"] = request.form.get("password")
        register_sessions[session]["email"] = request.form.get("email")
        register_sessions[session]["phone"] = request.form.get("phone")


    elif (register_sessions[session]["step"] == step == 1) and auth_type == register_sessions[session]["auth_type"]:
        register_sessions[session]["totp"]["code"] = request.form.get("code")
        register_sessions[session]["totp"]["complete"] = True

    elif (register_sessions[session]["step"] == step == 2 ) and auth_type == register_sessions[session]["auth_type"]:
        register_sessions[session]["email_otp"]["code"] = request.form.get("code")
        register_sessions[session]["email_otp"]["complete"] = True

    else:
        args = {}

        args["session"] = session
        args["step"] = login_sessions[session]["step"]
        args["auth_type"] = login_sessions[session]["auth_type"]
        args["error"] = "true"
        args["error_code"] = "0x01"
        args["error_text"]  =  "Auto Redirect!"

        return redirect(url_for("login_get", **args))

    register_attempt = call_function(register_user, "register",
                             username=register_sessions[session]["username"], password=register_sessions[session]["password"], email=register_sessions[session]["email"], phone=register_sessions[session]["phone"],
                             totp_mfa=register_sessions[session]["totp"], email_otp=register_sessions[session]["email_otp"])

    if not register_attempt["success"]:
        err_code = register_attempt["error"]["code"]

        if err_code == "8x02":
            register_sessions[session]["step"] = step = 1
            register_sessions[session]["auth_type"] = auth_type = "2fa"
            register_sessions[session]["totp"]["secret"] = call_function(totp_code, "generate_secret")
            register_sessions[session]["totp_url"] = f"otpauth://totp/Project-Gamma%20Security:{register_sessions[session]['email']}?secret={register_sessions[session]['totp']['secret']}&issuer=Project-Gamma%20Security"

        elif err_code == "8x03":
            register_sessions[session]["step"] = step = 2
            register_sessions[session]["auth_type"] = auth_type = "email"

            register_sessions[session]["email_otp"]["secret"] = secret = call_function(totp_code, "generate_secret")
            otp_code = call_function(totp_code, "totp", secret=secret, interval=600)

            register_sessions[session]["email_encrypted"] = f"{register_sessions[session]['email'].split('@')[0][:2]}****@{register_sessions[session]['email'].split('@')[1]}"

            email_template = register._email_template.replace("{username}", register_sessions[session]["username"]).replace("{otp_code}", otp_code)
            call_function(email_system, "send",
                          to_email=register_sessions[session]["email"],
                          from_email="no-reply-verification@project-gamma.dev",
                          subject=f"Your Verification Code Is: [{otp_code}]",
                          content=email_template,
                          idenity={"use_default": True})  

        args = {}

        args["session"] = session
        args["step"] = step
        args["auth_type"] = auth_type
        args["error"] = "true"
        args["error_code"]  = register_attempt["error"]["code"]
        args["error_text"]  =  register_attempt["error"]["text"]

        return redirect(url_for("register_get", **args))

    register_attempt.pop(session, None)

    session_id = str(uuid.uuid4())

    expire = str(int(time.time()) + 7200)
    headers = {"alg": "HS256-V1", "type": "JWT"}
    payload = {"userid": str(register_attempt["idenity"]["userid"]), "session": session_id, "expire": expire}
    secret = "mF8Zqv7QyRk1pXJwN6TgHsV9aB3uL0cD5eKj2YhWfA"

    resp = make_response(redirect(url_for("home")))
    resp.set_cookie("session_id", session_id, max_age=3600, httponly=True, samesite="Lax")
    resp.set_cookie("userprofile", str(register_attempt["idenity"]["userid"]), max_age=7200, httponly=True, samesite="Lax")
    resp.set_cookie("expire", expire, max_age=7200, httponly=True, samesite="Lax")
    resp.set_cookie("token", generate_jwt_token(headers, payload, secret), max_age=3600, httponly=True, samesite="Lax")

    return resp

@app.route("/register", methods=["GET"])
def register_get():
    session = request.args.get("session")

    if "session" not in request.args or not register_sessions.get(session, {}):
        session_args = generate_register_session()
        return redirect(url_for("register_get", **session_args))

    auth_type = request.args.get("auth_type", "username")
    step = request.args.get("step")
    error = request.args.get("error")
    error_text = request.args.get("error_text")
    error_code = request.args.get("error_code")

    current_session = register_sessions[session]

    if register_sessions[session]["auth_type"] == auth_type == "email":
        return render_template("register_email.html", email=current_session["email_encrypted"], error_text=error_text, error_code=error_code)

    elif register_sessions[session]["auth_type"] == auth_type == "2fa":
        return render_template("register_authenticator.html", auth_url=current_session["totp_url"], error_text=error_text, error_code=error_code)

    else:
        return render_template("register_credentials.html", error_text=error_text, error_code=error_code)

@app.route("/dash", methods=["GET"])
def dash():
    secret = "mF8Zqv7QyRk1pXJwN6TgHsV9aB3uL0cD5eKj2YhWfA"

    cookies = request.cookies.to_dict()

    if not cookies.get("token"):
        return redirect(url_for("login_get"))

    request_session = {
        "expire": int(cookies.get("expire", 0)),
        "id": cookies.get("session_id")
    }


    jwt_session = verify_jwt_token(cookies.get("token"), request_session, secret)

    if jwt_session is not True:
        return jwt_session

    return str(jwt_session)


@app.route("/", methods=["GET"])
def home():
    secret = "mF8Zqv7QyRk1pXJwN6TgHsV9aB3uL0cD5eKj2YhWfA"

    cookies = request.cookies.to_dict()

    if not cookies.get("token"):
        return redirect(url_for("login_get"))
        
    request_session = {
        "expire": int(cookies.get("expire", 0)),
        "id": cookies.get("session_id")
    }


    jwt_session = verify_jwt_token(cookies.get("token"), request_session, secret)

    if jwt_session is not True:
        return jwt_session

    return redirect(url_for("dash"))

@app.route("/account", methods=["GET"])
def account():
    cookies = request.cookies.to_dict()

    return jsonify(cookies)

if __name__ == '__main__':
    detected_modules = detect_modules(MODULES_ROOT_PATH)
    modules = detected_modules["modules"]

    totp_code = load_module(modules["totp_code"]["workfolder"], modules["totp_code"]["runfile"], "totp_code")
    register_user = load_module(modules["register_system"]["workfolder"], modules["register_system"]["runfile"], "register_user")
    login_user = load_module(modules["login_system"]["workfolder"], modules["login_system"]["runfile"], "login_user")
    email_system = load_module(modules["mail_system"]["workfolder"], modules["mail_system"]["runfile"], "email_system")

    app.run(debug=True, host="0.0.0.0", port=5541)

"""
if __name__ == "__main__":
    try:
        app_version = "1.06.8"
        app_author = "Project-Gamma DEV"
        running = True
        user = {}

        detected_modules = detect_modules(MODULES_ROOT_PATH)
        modules = detected_modules["modules"]

        gui = load_module(modules["gui_system"]["workfolder"], modules["gui_system"]["runfile"], "gui")
        totp_code = load_module(modules["totp_code"]["workfolder"], modules["totp_code"]["runfile"], "totp_code")
        register_user = load_module(modules["register_system"]["workfolder"], modules["register_system"]["runfile"], "register_user")
        login_user = load_module(modules["login_system"]["workfolder"], modules["login_system"]["runfile"], "login_user")
        email_system = load_module(modules["mail_system"]["workfolder"], modules["mail_system"]["runfile"], "email_system")


        while running:
            app_info = fr"info%App Version%{app_version}&info%App Author%{app_author}"

            if not user:
                app_info += r"&error%Login Status%not logged in!"

            else:
                app_info += fr"&info%Login Status%Logged In As {user['username']}"

            call_function(gui, "clear")
            call_function(gui, "_print", text="", print_type="", item_type="logo")
            call_function(gui, "_print", text=app_info, print_type="", item_type="app-info")

            if not user:
                user = get_user(login_user, register_user, totp_code, email_system)

            print(user)
            input()

    except KeyboardInterrupt:
        call_function(gui, "space", length=2)
        call_function(gui, "_print", text="USER EXITED/STOPPED!", print_type="error", item_type="text")
        sys.exit(0)"""