import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage

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

    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    username = idenity["username"]
    password = idenity["password"]

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(msg)