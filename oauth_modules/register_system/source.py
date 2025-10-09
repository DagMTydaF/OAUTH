import base64
import struct
import hmac 
import time
import mysql.connector
from mysql.connector import pooling
import random
import hashlib
import string
from hashlib import sha256
from functools import lru_cache

MASTER_USER = "register_user"
MASTER_PASS = "kMm3DJRaTA$"
_DB_CONFIG = {
    "host": "localhost",
    "user": MASTER_USER,
    "password": MASTER_PASS,
    "database": "OAUTH_SYSTEM",
    "autocommit": False,
}

_conn_pool = None
try:
    _conn_pool = pooling.MySQLConnectionPool(pool_name="oauth_pool", pool_size=5, **_DB_CONFIG)
except Exception:
    _conn_pool = None 

def _decoded_key(secret_normalized: str):
    return base64.b32decode(secret_normalized, casefold=True)

def totp(secret, digits=6, interval=30):
    secret_norm = secret.strip().replace(" ", "").upper()
    key_bytes = _decoded_key(secret_norm)
    timestep = int(time.time() // interval)

    msg = struct.pack(">Q", timestep)
    h = hmac.new(key_bytes, msg, hashlib.sha1).digest()

    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)

def get_conn():
    if _conn_pool:
        return _conn_pool.get_connection()
    return mysql.connector.connect(**_DB_CONFIG)

def generate_token(length=12):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

@lru_cache(maxsize=512)
def username_exists_cached(username):
    conn = get_conn()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM register_user_view WHERE username=%s LIMIT 1", (username,))
        exists = cursor.fetchone() is not None
        cursor.close()
        return exists
    finally:
        conn.close()

def username_valid(username):
    return not username_exists_cached(username)

@lru_cache(maxsize=512)
def token_exists_cached(tokenhash):
    conn = get_conn()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM register_user_view WHERE tokenhash=%s LIMIT 1", (tokenhash,))
        exists = cursor.fetchone() is not None
        cursor.close()
        return exists
    finally:
        conn.close()

def token_valid(token):
    th = sha256(str(token).encode()).hexdigest()
    return not token_exists_cached(th)

@lru_cache(maxsize=512)
def user_id_exists_cached(user_id):
    conn = get_conn()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT 1 FROM register_user_view WHERE user_id=%s LIMIT 1", (user_id,))
        exists = cursor.fetchone() is not None
        cursor.close()
        return exists
    finally:
        conn.close()

def user_id_valid(user_id):
    return not user_id_exists_cached(user_id)

def generate_user_id(username, offset):
    timestamp = int(time.time() * 1000)
    combined = f"{username}{timestamp}{offset}"
    hash_bytes = sha256(combined.encode()).digest()
    user_id = int.from_bytes(hash_bytes[:8], "big")
    return user_id

def register(username, password, email, phone, totp_mfa={"code": None, "secret": None, "complete": False}, email_otp={"code": None, "secret": None, "complete": False}):
    unsecure_numbers = ("381", "7", "387")

    if not username_valid(username.lower()):
        return {
            "success": False,
            "error": {"text": "Username Taken.", "code": "8x01"},
            "identity": {}
        }

    if phone.startswith(unsecure_numbers) and not totp_mfa["complete"] and not email_otp["complete"]:
        return {
            "success": False,
            "error": {"text": "Authenticator App Required.", "code": "8x02"},
            "identity": {}
        }

    elif phone.startswith(unsecure_numbers) and totp_mfa["complete"] and not email_otp["complete"]:
        if not totp_mfa["code"] == totp(totp_mfa["secret"]):
             return {
                "success": False,
                "error": {"text": "Incorrect Code Entered.", "code": "8x08"},
                "identity": {}
            }

    while True:
        token = generate_token()
        if token_valid(token):
            break

    offset = 0
    while True:
        user_id = generate_user_id(username.lower(), offset)
        if user_id_valid(user_id):
            break
        offset += 1

    password_hash = sha256(password.encode()).hexdigest()
    rhash = sha256(f"{username.lower()}{email}".encode()).hexdigest()

    if not email_otp["complete"]:
        return {
            "success": False,
            "error": {"text": "Email Verification Required.", "code": "8x03"},
            "user": {}
        }

    elif not (email_otp["code"] == totp(email_otp["secret"], interval=600)):
        return {
            "success": False,
            "error": {"text": "Incorrect Code Enterd.", "code": "8x09"},
            "user": {}
        }

    conn = get_conn()
    try:
        cursor = conn.cursor(dictionary=True)
        sql = """
        INSERT INTO USERS
        (user_id, username, passwordhash, totp_status, totp_secret, email_otp, token, tokenhash, rhash, security, email, phone)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            user_id,
            username.lower(),
            password_hash,
            totp_mfa["complete"],
            totp_mfa["secret"] if totp_mfa["complete"] else "",
            email_otp["secret"],
            token,
            sha256(str(token).encode()).hexdigest(),
            rhash,
            "q1-high" if totp_mfa["complete"] else "q0-high",
            email,
            phone
        )
        cursor.execute(sql, values)
        conn.commit()

    finally:
        try:
            cursor.close()
        except Exception:
            pass
        conn.close()

    username_exists_cached.cache_clear()
    token_exists_cached.cache_clear()
    user_id_exists_cached.cache_clear()

    return {
        "success": True,
        "error": None,
        "idenity": {
            "userid": user_id,
            "username": username,
            "rhash": rhash,
            "token": token
        }
    }
