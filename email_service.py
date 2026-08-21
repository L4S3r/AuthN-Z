"""
Auth N&Z - Email Notification Service (email_service.py)
--------------------------------------------------------
Dispatches transactional emails for workspace invitations, security alerts,
and credential recovery. Supports production SMTP and development logging fallback.
"""

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import os
import smtplib
from typing import Any, Dict, Optional

logger = logging.getLogger("auth_nz.email_service")


class EmailService:
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.smtp_from = os.getenv("SMTP_FROM", "TaskTracker Security <no-reply@l4s3r.site>")
        self.frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")

    def send_invitation_email(
        self,
        recipient_email: str,
        recipient_name: str,
        role: str,
        department: str,
        invited_by: str,
        invite_token: str,
    ) -> Dict[str, Any]:
        """Dispatch a branded workspace team invitation email."""
        invite_url = f"{self.frontend_url}/invite/accept?token={invite_token}"
        subject = f"You've been invited to join TaskTracker by {invited_by}"

        text_content = f"""Hello {recipient_name},

{invited_by} has invited you to join the TaskTracker workspace as an {role.capitalize()} in the {department} department.

To accept your invitation and set up your account credentials, click the link below:
{invite_url}

This invitation link is secure and will expire in 7 days.

If you were not expecting this invitation, you can safely ignore this email.

---
Auth N&Z Security Gateway
https://l4s3r.site
"""

        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 30px 15px; color: #0f172a;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="560" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
          <!-- Header -->
          <tr>
            <td style="padding: 32px 32px 20px; text-align: center; background-color: #0f172a;">
              <h1 style="color: #ffffff; font-size: 20px; font-weight: 700; margin: 0; letter-spacing: -0.5px;">TaskTracker Workspace</h1>
              <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0;">Zero-Trust Access & Identity Gateway</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding: 32px;">
              <h2 style="font-size: 18px; font-weight: 700; color: #0f172a; margin: 0 0 12px;">You've been invited to join the team!</h2>
              <p style="font-size: 14px; line-height: 1.6; color: #334155; margin: 0 0 20px;">
                Hello <strong>{recipient_name}</strong>,<br>
                <strong>{invited_by}</strong> has invited you to collaborate on the TaskTracker workspace with the following security clearance:
              </p>
              
              <!-- Role Box -->
              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f1f5f9; border-radius: 10px; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 16px;">
                    <div style="font-size: 11px; text-transform: uppercase; font-weight: 700; color: #64748b; margin-bottom: 4px;">Assigned Role & Department</div>
                    <div style="font-size: 15px; font-weight: 700; color: #0f172a;">{role.upper()} &bull; {department}</div>
                  </td>
                </tr>
              </table>

              <!-- CTA Button -->
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="center" style="padding: 10px 0 24px;">
                    <a href="{invite_url}" style="background-color: #2563eb; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-size: 14px; font-weight: 600; display: inline-block; box-shadow: 0 2px 6px rgba(37,99,235,0.3);">
                      Accept Invitation & Set Password &rarr;
                    </a>
                  </td>
                </tr>
              </table>

              <p style="font-size: 12px; line-height: 1.5; color: #64748b; margin: 0;">
                Or copy and paste this link into your browser:<br>
                <a href="{invite_url}" style="color: #2563eb; word-break: break-all;">{invite_url}</a>
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding: 20px 32px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center;">
              This invitation link is valid for 7 days. If you did not request this, you can ignore this message.<br>
              Powered by Auth N&Z Security Gateway.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""

        sent_via_smtp = False
        if self.smtp_host and self.smtp_user and self.smtp_password:
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = self.smtp_from
                msg["To"] = recipient_email
                msg.attach(MIMEText(text_content, "plain"))
                msg.attach(MIMEText(html_content, "html"))

                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10.0) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                    server.sendmail(self.smtp_from, [recipient_email], msg.as_string())
                sent_via_smtp = True
                logger.info("Successfully dispatched invitation email via SMTP to %s", recipient_email)
            except Exception as e:
                logger.warning("SMTP delivery failed (%s). Falling back to console logging.", e)

        if not sent_via_smtp:
            logger.info("--- TRANSACTIONAL INVITATION EMAIL LOG ---")
            logger.info("TO: %s | SUBJECT: %s", recipient_email, subject)
            logger.info("INVITATION LINK: %s", invite_url)
            logger.info("------------------------------------------")

        return {
            "delivered": sent_via_smtp,
            "recipient": recipient_email,
            "invite_url": invite_url,
        }
