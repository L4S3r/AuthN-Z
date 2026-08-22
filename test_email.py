"""
Auth N&Z - SMTP Email Diagnostic CLI (test_email.py)
---------------------------------------------------
Tests and verifies your SMTP email server configuration live on your server.

Usage:
    python test_email.py recipient@example.com
"""

import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr
import os
import smtplib
import sys
from dotenv import load_dotenv

load_dotenv()


def test_smtp_connection(recipient: str):
    smtp_host = os.getenv("SMTP_HOST")
    port_env = os.getenv("SMTP_PORT", "587")
    try:
        smtp_port = int(port_env.strip()) if port_env and port_env.strip().isdigit() else 587
    except Exception:
        smtp_port = 587

    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", "TaskTracker Security <no-reply@l4s3r.site>")
    clean_recipient = parseaddr(recipient)[1] or recipient.strip()

    _, parsed_sender_email = parseaddr(smtp_from)
    envelope_from = parsed_sender_email if parsed_sender_email else smtp_from.strip()

    print("=" * 60)
    print("Auth N&Z SMTP Configuration Diagnostic")
    print("=" * 60)
    print(f"SMTP Host:      {smtp_host or 'NOT SET (Missing in .env)'}")
    print(f"SMTP Port:      {smtp_port}")
    print(f"SMTP User:      {smtp_user or 'NOT SET (Missing in .env)'}")
    print(f"SMTP Password:  {'*' * len(smtp_password) if smtp_password else 'NOT SET (Missing in .env)'}")
    print(f"SMTP From:      {smtp_from}")
    print(f"Envelope From:  {envelope_from}")
    print(f"Test Recipient: {clean_recipient}")
    print("=" * 60)

    if not smtp_host or not smtp_user or not smtp_password:
        print("\nERROR: SMTP environment variables are missing in your .env file!")
        print("\nTo send real emails to Gmail, Outlook, or work addresses:")
        print("\nOption A: Gmail SMTP (Free)")
        print("  SMTP_HOST=smtp.gmail.com")
        print("  SMTP_PORT=587")
        print("  SMTP_USER=your_email@gmail.com")
        print("  SMTP_PASSWORD=xxxx xxxx xxxx xxxx  (16-character App Password from Google Account)")
        print("  SMTP_FROM=TaskTracker <your_email@gmail.com>")
        print("\nOption B: Resend (Free 3,000 emails/mo, 1-minute setup)")
        print("  SMTP_HOST=smtp.resend.com")
        print("  SMTP_PORT=587")
        print("  SMTP_USER=resend")
        print("  SMTP_PASSWORD=re_123456789...")
        print("  SMTP_FROM=TaskTracker <onboarding@resend.dev>  (or your domain)")
        print("=" * 60)
        sys.exit(1)

    print("\nAttempting SMTP Handshake and Authentication...")
    server = None
    try:
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15.0)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15.0)
            server.starttls()

        server.login(smtp_user, smtp_password)
        print("SMTP Handshake and Authentication Successful!")

        sender_domain = envelope_from.split("@")[-1] if "@" in envelope_from else "l4s3r.site"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Auth N&Z - Test Email Diagnostic"
        msg["From"] = smtp_from
        msg["To"] = clean_recipient
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=sender_domain)
        msg["Auto-Submitted"] = "auto-generated"

        body_text = f"This is a test email sent from Auth N&Z on your server to verify SMTP delivery.\nRecipient: {clean_recipient}\nStatus: Delivered successfully."
        body_html = f"<div style='font-family:sans-serif;padding:20px;border:1px solid #e2e8f0;border-radius:10px;'><h2 style='color:#2563eb;'>Auth N&Z Email Test</h2><p>This email confirms that your SMTP service is correctly configured and transmitting emails across the internet.</p><p>Recipient: <strong>{clean_recipient}</strong></p></div>"

        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        print(f"Transmitting test message to {clean_recipient} (Envelope: {envelope_from})...")
        server.sendmail(envelope_from, [clean_recipient], msg.as_string())

        print(f"\nSUCCESS: Test email has been successfully sent to {clean_recipient}!")
        print("Check your inbox (and spam folder) for the confirmation message.")
    except Exception as exc:
        print(f"\nFAILURE: Could not send email via SMTP.")
        print(f"Error Details: {exc}")
        print("\nCommon Troubleshooting:")
        print("  1. If using Gmail: Enable 2-Step Verification and generate an App Password at https://myaccount.google.com/apppasswords")
        print("  2. If using port 465 vs 587: Check whether your provider requires SSL (465) or STARTTLS (587).")
        print("  3. Verify that your server firewall permits outgoing connections on port 587/465.")
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def main():
    parser = argparse.ArgumentParser(description="Test SMTP email delivery for Auth N&Z")
    parser.add_argument("recipient", help="Destination email address to receive test message")
    args = parser.parse_args()

    test_smtp_connection(args.recipient)


if __name__ == "__main__":
    main()
