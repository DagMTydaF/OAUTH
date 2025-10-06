import time
import mysql.connector
import random
import string
from hashlib import sha256

MASTER_USER = "register_user"
MASTER_PASS = "kMm3DJRaTA$"

def generate_token(length=12):
    characters = string.ascii_letters + string.digits

    return ''.join(random.choice(characters) for _ in range(length))

def username_valid(username):
    conn = mysql.connector.connect(
        host="localhost",
        user=MASTER_USER,
        password=MASTER_PASS,
        database="OAUTH_SYSTEM"
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM register_user_view  WHERE username=%s", (username,))

    exists = cursor.fetchone() is not None

    cursor.close()
    conn.close()

    return not exists

def token_valid(token):
    conn = mysql.connector.connect(
        host="localhost",
        user=MASTER_USER,
        password=MASTER_PASS,
        database="OAUTH_SYSTEM"
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM register_user_view  WHERE tokenhash=%s", (sha256(str(token).encode()).hexdigest(),))

    exists = cursor.fetchone() is not None

    cursor.close()
    conn.close()

    return not exists

def user_id_valid(user_id):
    conn = mysql.connector.connect(
        host="localhost",
        user=MASTER_USER,
        password=MASTER_PASS,
        database="OAUTH_SYSTEM"
    )

    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM register_user_view  WHERE user_id=%s", (user_id,))

    exists = cursor.fetchone() is not None

    cursor.close()
    conn.close()

    return not exists

def generate_user_id(username, offset):
    timestamp = int(time.time() * 1000)
    combined = f"{username}{timestamp}{offset}"

    hash_bytes = sha256(combined.encode()).digest()

    user_id = int.from_bytes(hash_bytes[:8], "big")
    
    return user_id

def register(username, password, email, phone, totp=(False, ""), email_otp=(False, "", "")):
    unsecure_numbers = ("381", "7", "387")

    if not username_valid(username.lower()):
        return {
            "success": False,
            "error": {"text": "Username Taken.", "code": "8x01"},
            "user": {}
        }

    if phone.startswith(unsecure_numbers) and not totp[0]: 
        return {
            "success": False,
            "error": {"text": "TOTP REQUIRED.", "code": "8x02"},
            "user": {}
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

    if not email_otp[1]:
        return {
            "success": False,
            "error": {"text": "EMAIL OTP REQUIRED.", "code": "8x03"},
            "user": {}
        }

    conn = mysql.connector.connect(
        host="localhost",
        user=MASTER_USER,
        password=MASTER_PASS,
        database="OAUTH_SYSTEM"
    )
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
        totp[0],
        totp[1] if totp[0] else "",
        email_otp[1],
        token,
        sha256(str(token).encode()).hexdigest(),
        rhash,
        "q1-high" if totp[0] else "q0-high",
        email,
        phone
    )

    cursor.execute(sql, values)
    conn.commit()

    cursor.close()
    conn.close()

    return {
        "success": True,
        "error": None,
        "user": {
            "user_id": user_id,
            "rhash": rhash,
            "token": token
        }
    }