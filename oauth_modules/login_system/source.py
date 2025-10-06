import time
import mysql.connector
import random
import string
import base64
import struct
import hmac
import hashlib

MASTER_USER = "login_user"
MASTER_PASS = "kMm3DJRaTA$"

def totp(secret, digits=6, interval=30):
    secret = secret.strip().replace(" ", "").upper()
    key_bytes = base64.b32decode(secret, casefold=True)
    timestep = int(time.time() // interval)

    msg = struct.pack(">Q", timestep)
    h = hmac.new(key_bytes, msg, hashlib.sha1).digest()

    offset = h[-1] & 0x0F

    code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff) % (10 ** digits)

    return str(code).zfill(digits)

def login_with_token(idenity): 
    token = idenity["token"]

    conn = mysql.connector.connect(
        host="localhost",
        user=MASTER_USER,
        password=MASTER_PASS,
        database="OAUTH_SYSTEM"
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM login_user_view  WHERE tokenhash=%s", (hashlib.sha256(str(token).encode()).hexdigest(),))

    user = cursor.fetchone()

    if not user:
        return {
            "success": False,
            "error": {"text": "INVAILD IDENITY.", "code": "9x04"},
            "idenity": {}
        }

    if user["totp_status"] == 1 and not idenity["totp"]["complete"]:
        return {
            "success": False,
            "error": {"text": "TOTP REQUIRED.", "code": "9x08"},
            "idenity": {
                "totp_secret": user["totp_secret"]
            }
        }


    elif idenity["totp"]["complete"] and not idenity["email_otp"]["complete"]:
        if not (idenity["totp"]["code"] == totp(user["totp_secret"])):
            return {
                "success": False,
                "error": {"text": "TOTP REQUIRED.", "code": "9x09"},
                "idenity": {
                    "totp_secret": user["totp_secret"]
                }
            }

    elif not idenity["email_otp"]["complete"]:
        return {
                "success": False,
                "error": {"text": "EMAIL OTP REQUIRED.", "code": "9x10"},
                "idenity": {
                    "email_otp": user["email_otp"],
                    "email": user["email"]
                }
            }

    elif idenity["email_otp"]["complete"]:
        if not (idenity["email_otp"]["code"] == totp(user["email_otp"] + idenity["email_otp"]["offset"], interval=600)):
            return {
                "success": False,
                "error": {"text": "EMAIL OTP REQUIRED.", "code": "9x11"},
                "idenity": {
                    "email_otp": user["email_otp"],
                    "email": user["email"]
                }
            }

    cursor.close()
    conn.close()

    return {
        "success": True,
        "error": None,
        "idenity": {
            "username": user["username"],
            "userid": user["user_id"]
        }
    }

def login_with_credentials(idenity): 
    username = idenity["username"]
    password = idenity["password"]

    conn = mysql.connector.connect(
        host="localhost",
        user=MASTER_USER,
        password=MASTER_PASS,
        database="OAUTH_SYSTEM"
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM login_user_view  WHERE username=%s AND passwordhash=%s", (username, hashlib.sha256(str(password).encode()).hexdigest(),))

    user = cursor.fetchone()

    if not user:
        return {
            "success": False,
            "error": {"text": "INVAILD IDENITY.", "code": "9x04"},
            "idenity": {}
        }

    if user["totp_status"] == 1 and not idenity["totp"]["complete"]:
        return {
            "success": False,
            "error": {"text": "TOTP REQUIRED.", "code": "9x08"},
            "idenity": {
                "totp_secret": user["totp_secret"]
            }
        }

    elif idenity["totp"]["complete"] and not idenity["email_otp"]["complete"]:
        if not (idenity["totp"]["code"] == totp(user["totp_secret"])):
            return {
                "success": False,
                "error": {"text": "TOTP REQUIRED.", "code": "9x09"},
                "idenity": {
                    "totp_secret": user["totp_secret"]
                }
            }

    if not idenity["email_otp"]["complete"]:
        return {
                "success": False,
                "error": {"text": "EMAIL OTP REQUIRED.", "code": "9x10"},
                "idenity": {
                    "username": user["username"],
                    "email_otp": user["email_otp"],
                    "email": user["email"]
                }
            }

    elif idenity["email_otp"]["complete"]:
        if not (idenity["email_otp"]["code"] == totp(user["email_otp"] + idenity["email_otp"]["offset"], interval=600)):
            return {
                "success": False,
                "error": {"text": "EMAIL OTP REQUIRED.", "code": "9x11"},
                "idenity": {
                    "username": user["username"],
                    "email_otp": user["email_otp"],
                    "email": user["email"]
                }
            }

    cursor.close()
    conn.close()

    return {
        "success": True,
        "error": None,
        "idenity": {
            "username": user["username"],
            "userid": user["user_id"]
        }
    }

def login(type, idenity):
    if type.lower() == "token":
        return login_with_token(idenity)

    elif type.lower() == "credentials":
        return login_with_credentials(idenity)

    else:
        return {
            "success": False,
            "error": {"text": "INVAILD TYPE(TOKEN/CREDENTIALS).", "code": "9x05"},
            "idenity": {}
        }