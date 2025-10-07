
import time
import hmac
import hashlib
import base64
import struct
import random
import qrcode
import secrets
from functools import lru_cache
import sys

def generate_secret(length=32):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    return ''.join(secrets.choice(chars) for _ in range(length))

@lru_cache(maxsize=1024)
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

class _QRCodeWrapper:
    def __init__(self, uri):
        qr = qrcode.QRCode(border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        self.matrix = qr.get_matrix()
        self._ascii = None

    def _render_ascii(self):
        if self._ascii is not None:
            return self._ascii

        lines = []
        for y in range(0, len(self.matrix), 2):
            upper = self.matrix[y]
            lower = self.matrix[y + 1] if y + 1 < len(self.matrix) else [0] * len(upper)

            line = "".join(
                "█" if u and l else
                "▀" if u and not l else
                "▄" if not u and l else
                " " 
                for u, l in zip(upper, lower)
            )
            
            lines.append(line)

        self._ascii = "\n" + "\n".join(lines) + "\n"
        return self._ascii

    def print_ascii(self):
        sys.stdout.write(self._render_ascii())
        sys.stdout.flush()

def generate_qrcode(secret, accountname, issuer="PROJECT-GAMMA%20OAUTH"):
    uri = f"otpauth://totp/{issuer}:{accountname}?secret={secret}&issuer={issuer}"
    return _QRCodeWrapper(uri)

def check_code(secret, code, digits=6, interval=30):
    expected = totp(secret, digits, interval)
    return str(code) == expected
