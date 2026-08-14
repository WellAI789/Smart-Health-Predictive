import os
import smtplib
import traceback
from pathlib import Path
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def send_email(
    recipient: str,
    subject: str,
    content: str,
    content_type: str = "plainText",
    inline_image_path: str = None,
    inline_image_cid: str = None
):
    """
    Sends an email using Brevo SMTP.

    :param recipient: Recipient email address.
    :param subject: Email subject.
    :param content: Email body.
    :param content_type: 'plainText' or 'html'.
    :param inline_image_path: Optional path to an image embedded in the email.
    :param inline_image_cid: Optional Content-ID used by the HTML image src.
    :return: True if sent successfully, otherwise None.
    """

    try:
        smtp_host = os.getenv("SMTP_HOST", "smtp-relay.brevo.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_username = os.getenv("SMTP_USERNAME")
        smtp_password = os.getenv("SMTP_PASSWORD")
        sender_email = os.getenv("SMTP_FROM_EMAIL")
        sender_name = os.getenv(
            "SMTP_FROM_NAME",
            "Ever AI Technologies"
        )

        if not smtp_username:
            raise ValueError("SMTP_USERNAME is not configured")

        if not smtp_password:
            raise ValueError("SMTP_PASSWORD is not configured")

        if not sender_email:
            raise ValueError("SMTP_FROM_EMAIL is not configured")

        # Use mixed when an inline image is attached.
        if inline_image_path:
            message = MIMEMultipart("mixed")

            # Alternative part contains plain text / HTML versions.
            alternative = MIMEMultipart("alternative")
            message.attach(alternative)

            if content_type.lower() == "html":
                alternative.attach(MIMEText(content, "html"))
            else:
                alternative.attach(MIMEText(content, "plain"))

            # Attach the image inline using Content-ID.
            image_path = Path(inline_image_path)

            if not image_path.exists():
                raise FileNotFoundError(
                    f"Inline image not found: {image_path}"
                )

            with open(image_path, "rb") as image_file:
                image = MIMEImage(image_file.read())

            image.add_header(
                "Content-ID",
                f"<{inline_image_cid}>"
            )
            image.add_header(
                "Content-Disposition",
                "inline",
                filename=image_path.name
            )

            message.attach(image)

        else:
            # Keep the existing behavior for normal emails.
            message = MIMEMultipart("alternative")

            if content_type.lower() == "html":
                message.attach(MIMEText(content, "html"))
            else:
                message.attach(MIMEText(content, "plain"))

        message["Subject"] = subject
        message["From"] = f"{sender_name} <{sender_email}>"
        message["To"] = recipient

        print("===== BREVO EMAIL =====")
        print(f"Sending email to: {recipient}")
        print(f"Subject: {subject}")
        print(f"From: {sender_email}")

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(
                sender_email,
                recipient,
                message.as_string()
            )

        print("Email sent successfully.")
        return True

    except Exception as ex:
        print("===== EMAIL ERROR =====")
        print(str(ex))
        traceback.print_exc()
        print("======================")
        return None