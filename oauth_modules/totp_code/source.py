import time
import hmac
import hashlib
import base64
import struct
import random
import qrcode

def generate_secret(length=32):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return ''.join(random.choice(chars) for _ in range(length))

def totp(secret, digits=6, interval=30):
    secret = secret.strip().replace(" ", "").upper()
    key_bytes = base64.b32decode(secret, casefold=True)
    timestep = int(time.time() // interval)

    msg = struct.pack(">Q", timestep)
    h = hmac.new(key_bytes, msg, hashlib.sha1).digest()

    offset = h[-1] & 0x0F

    code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff) % (10 ** digits)

    return str(code).zfill(digits)

def generate_qrcode(secret, accountname, issuer="PROJECT-GAMMA%20OAUTH"):
    uri = f"otpauth://totp/{issuer}:{accountname}?secret={secret}&issuer={issuer}"

    _qrcode = qrcode.QRCode()
    _qrcode.add_data(uri)

    return _qrcode

def check_code(secret, code, digits=6, interval=30):
    expected = totp(secret, digits, interval)
    
    return str(code) == expected