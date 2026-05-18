"""
Email alert sender.
Credentials are read from environment variables or config.yaml.
Debug output no longer prints passwords to stdout.
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from utils.config_loader import load_config

logger = logging.getLogger(__name__)


def send_email(subject: str, body: str, config_path: str = None) -> bool:
    """
    Send an alert email.

    Returns True on success, False on failure.
    """
    config = load_config(config_path)
    email_cfg = config.get("email", {})

    sender_email = email_cfg.get("sender", "")
    password = email_cfg.get("password", "")
    receiver_email = email_cfg.get("receiver", "")

    if not all([sender_email, password, receiver_email]):
        logger.warning(
            "Email not configured — skipping alert. "
            "Set EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER in .env or config.yaml."
        )
        return False

    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.send_message(message)
        logger.info("Alert email sent to %s | Subject: %s", receiver_email, subject)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error(
            "Email authentication failed. Check EMAIL_SENDER / EMAIL_PASSWORD."
        )
    except Exception as e:
        logger.error("Failed to send email: %s", e)

    return False
