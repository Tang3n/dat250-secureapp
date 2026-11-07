import smtplib
from email.mime.text import MIMEText
from app.config import MAILHOG_HOST, MAILHOG_PORT, BASE_URL


def send_reset_email(to_email: str, token: str):
    body = f"Use this reset link: {BASE_URL}/reset-password/{token}"
    msg = MIMEText(body)
    msg["Subject"] = "DAT250 Password Reset"
    msg["From"] = "noreply@dat250.local"
    msg["To"] = to_email

    # The token itself is never logged: anyone with log access could
    # otherwise take over the account.
    print(f"Sending password reset email to {to_email}")

    with smtplib.SMTP(MAILHOG_HOST, MAILHOG_PORT) as server:
        server.sendmail(msg["From"], [to_email], msg.as_string())
