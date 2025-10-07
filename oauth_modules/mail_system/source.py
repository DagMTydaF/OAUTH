
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time
import threading

_smtp_cache = {
    "conn": None,
    "username": None,
    "password": None,
    "last_used": 0,
    "lock": threading.Lock()
}
_SMTP_KEEPALIVE_SECONDS = 300

def _ensure_smtp(username, password):
    from time import time
    with _smtp_cache["lock"]:
        conn = _smtp_cache["conn"]
        if conn:
            if _smtp_cache["username"] != username or _smtp_cache["password"] != password or (time() - _smtp_cache["last_used"]) > _SMTP_KEEPALIVE_SECONDS:
                try:
                    conn.quit()
                except Exception:
                    pass
                conn = None
                _smtp_cache["conn"] = None

        if conn is None:
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(username, password)
            _smtp_cache["conn"] = server
            _smtp_cache["username"] = username
            _smtp_cache["password"] = password

        _smtp_cache["last_used"] = time()
        return _smtp_cache["conn"]

def send(to_email, from_email, subject, content, idenity):
    if idenity["use_default"]:
        idenity = {
            "username": "project.gamma.service",
            "password": "ausrvxrrjnezozfc",
            "use_default": True
        }

    msg = MIMEMultipart("alternative")
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    part_html = MIMEText(content, "html")
    msg.attach(part_html)

    username = idenity["username"]
    password = idenity["password"]

    try:
        server = _ensure_smtp(username, password)
        server.send_message(msg)
        _smtp_cache["last_used"] = time.time()
    except Exception:
        try:
            with _smtp_cache["lock"]:
                try:
                    if _smtp_cache["conn"]:
                        _smtp_cache["conn"].quit()
                except Exception:
                    pass
                _smtp_cache["conn"] = None
            server = _ensure_smtp(username, password)
            server.send_message(msg)
            _smtp_cache["last_used"] = time.time()
        except Exception as e:
            raise
