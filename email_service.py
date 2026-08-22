"""
Auth N&Z - Email Notification Service (email_service.py)
--------------------------------------------------------
Dispatches transactional emails for workspace invitations, task assignments,
deadline reminders, and security alerts. Supports production SMTP with development logging fallback.
"""

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parseaddr
import html
import logging
import os
import smtplib
from typing import Any, Dict, Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("auth_nz.email_service")


class EmailService:
    def __init__(self):
        self.reload_config()

    def reload_config(self) -> None:
        """Reload configuration dynamically from environment variables with safe defaults."""
        try:
            load_dotenv(override=True)
            self.smtp_host = os.getenv("SMTP_HOST")
            port_env = os.getenv("SMTP_PORT", "587")
            try:
                self.smtp_port = int(port_env.strip()) if port_env and port_env.strip().isdigit() else 587
            except Exception:
                self.smtp_port = 587

            self.smtp_user = os.getenv("SMTP_USER")
            self.smtp_password = os.getenv("SMTP_PASSWORD")
            self.smtp_from = os.getenv("SMTP_FROM", "TaskTracker Security <no-reply@l4s3r.site>")
            self.frontend_url = (os.getenv("FRONTEND_URL") or "http://localhost:3000").rstrip("/")
        except Exception as exc:
            logger.warning("Error reloading email configuration: %s. Using default settings.", exc)
            self.smtp_host = None
            self.smtp_port = 587
            self.smtp_user = None
            self.smtp_password = None
            self.smtp_from = "TaskTracker Security <no-reply@l4s3r.site>"
            self.frontend_url = "http://localhost:3000"

    def _dispatch_mime_email(
        self,
        recipient_email: str,
        subject: str,
        text_content: str,
        html_content: str,
    ) -> Dict[str, Any]:
        """Internal helper to assemble RFC 5322 MIME messages and transmit via SMTP."""
        self.reload_config()
        sent_via_smtp = False
        error_detail = None
        server = None

        clean_recipient = parseaddr(recipient_email)[1] or recipient_email.strip()

        if self.smtp_host and self.smtp_user and self.smtp_password:
            try:
                # Derive bare envelope sender and domain for SPF/DKIM header alignment
                _, parsed_sender_email = parseaddr(self.smtp_from)
                envelope_from = parsed_sender_email if parsed_sender_email else self.smtp_from.strip()

                sender_domain = "l4s3r.site"
                if envelope_from and "@" in envelope_from:
                    sender_domain = envelope_from.split("@")[-1].strip()
                elif self.smtp_user and "@" in self.smtp_user:
                    sender_domain = self.smtp_user.split("@")[-1].strip()

                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = self.smtp_from
                msg["To"] = clean_recipient
                msg["Date"] = formatdate(localtime=True)
                msg["Message-ID"] = make_msgid(domain=sender_domain)
                msg["Reply-To"] = self.smtp_from
                msg["Auto-Submitted"] = "auto-generated"
                msg["X-Mailer"] = "AuthNZ-Gateway/1.0"
                msg.attach(MIMEText(text_content, "plain", "utf-8"))
                msg.attach(MIMEText(html_content, "html", "utf-8"))

                if self.smtp_port == 465:
                    server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=12.0)
                else:
                    server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=12.0)
                    server.starttls()

                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(envelope_from, [clean_recipient], msg.as_string())
                sent_via_smtp = True
                logger.info("Successfully dispatched email via SMTP to %s (Subject: %s)", clean_recipient, subject)
            except Exception as e:
                error_detail = str(e)
                logger.warning("SMTP delivery failed (%s). Falling back to console logging.", e)
            finally:
                if server is not None:
                    try:
                        server.quit()
                    except Exception:
                        try:
                            server.close()
                        except Exception:
                            pass
        else:
            error_detail = "SMTP credentials (SMTP_HOST, SMTP_USER, SMTP_PASSWORD) not configured in .env"

        if not sent_via_smtp:
            logger.info("--- TRANSACTIONAL EMAIL LOG (FALLBACK) ---")
            logger.info("TO: %s | SUBJECT: %s", clean_recipient, subject)
            logger.info("SMTP STATUS: %s", error_detail)
            logger.info("------------------------------------------")

        return {
            "delivered": sent_via_smtp,
            "recipient": clean_recipient,
            "error": error_detail if not sent_via_smtp else None,
        }

    def send_invitation_email(
        self,
        recipient_email: str,
        recipient_name: Optional[str] = None,
        role: Optional[str] = "viewer",
        department: Optional[str] = "General",
        invited_by: Optional[str] = "Workspace Admin",
        invite_token: str = "",
    ) -> Dict[str, Any]:
        """Dispatch a branded workspace team invitation email."""
        clean_recipient = (recipient_email or "").strip()
        safe_name = (recipient_name or clean_recipient.split("@")[0] or "Team Member").strip()
        safe_role = (role or "viewer").strip()
        safe_department = (department or "General").strip()
        safe_invited_by = (invited_by or "Workspace Admin").strip()
        safe_token = (invite_token or "").strip()

        invite_url = f"{self.frontend_url}/invite/accept?token={safe_token}"
        subject = f"You've been invited to join TaskTracker by {safe_invited_by}"

        text_content = f"""Hello {safe_name},

{safe_invited_by} has invited you to join the TaskTracker workspace as an {safe_role.capitalize()} in the {safe_department} department.

To accept your invitation and set up your account credentials, click the link below:
{invite_url}

This invitation link is secure and will expire in 7 days.

If you were not expecting this invitation, you can safely ignore this email.

---
Auth N&Z Security Gateway
https://l4s3r.site
"""

        escaped_subject = html.escape(subject)
        escaped_name = html.escape(safe_name)
        escaped_invited_by = html.escape(safe_invited_by)
        escaped_role = html.escape(safe_role.upper())
        escaped_department = html.escape(safe_department)
        escaped_url = html.escape(invite_url)

        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{escaped_subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 30px 15px; color: #0f172a;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="560" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
          <tr>
            <td style="padding: 32px 32px 20px; text-align: center; background-color: #0f172a;">
              <h1 style="color: #ffffff; font-size: 20px; font-weight: 700; margin: 0; letter-spacing: -0.5px;">TaskTracker Workspace</h1>
              <p style="color: #94a3b8; font-size: 12px; margin: 4px 0 0;">Zero-Trust Access & Identity Gateway</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px;">
              <h2 style="font-size: 18px; font-weight: 700; color: #0f172a; margin: 0 0 12px;">You've been invited to join the team!</h2>
              <p style="font-size: 14px; line-height: 1.6; color: #334155; margin: 0 0 20px;">
                Hello <strong>{escaped_name}</strong>,<br>
                <strong>{escaped_invited_by}</strong> has invited you to collaborate on the TaskTracker workspace with the following security clearance:
              </p>
              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f1f5f9; border-radius: 10px; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 16px;">
                    <div style="font-size: 11px; text-transform: uppercase; font-weight: 700; color: #64748b; margin-bottom: 4px;">Assigned Role & Department</div>
                    <div style="font-size: 15px; font-weight: 700; color: #0f172a;">{escaped_role} &bull; {escaped_department}</div>
                  </td>
                </tr>
              </table>
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="center" style="padding: 10px 0 24px;">
                    <a href="{escaped_url}" style="background-color: #2563eb; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-size: 14px; font-weight: 600; display: inline-block; box-shadow: 0 2px 6px rgba(37,99,235,0.3);">
                      Accept Invitation & Set Password &rarr;
                    </a>
                  </td>
                </tr>
              </table>
              <p style="font-size: 12px; line-height: 1.5; color: #64748b; margin: 0;">
                Or copy and paste this link into your browser:<br>
                <a href="{escaped_url}" style="color: #2563eb; word-break: break-all;">{escaped_url}</a>
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 20px 32px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center;">
              This invitation link is valid for 7 days. Powered by Auth N&Z Security Gateway.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
        res = self._dispatch_mime_email(clean_recipient, subject, text_content, html_content)
        res["invite_url"] = invite_url
        return res

    def send_task_assignment_email(
        self,
        recipient_email: str,
        recipient_name: Optional[str] = None,
        task_title: Optional[str] = "Untitled Task",
        task_description: Optional[str] = None,
        priority: Optional[str] = "medium",
        due_date: Optional[str] = None,
        assigned_by: Optional[str] = "Workspace Admin",
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch a notification email when a user is assigned a new task or deliverable."""
        clean_recipient = (recipient_email or "").strip()
        safe_name = (recipient_name or clean_recipient.split("@")[0] or "Team Member").strip()
        safe_title = (task_title or "Untitled Task").strip()
        safe_priority = (priority or "medium").strip().lower()
        safe_assigned_by = (assigned_by or "Workspace Admin").strip()
        safe_due_date = due_date.strip() if due_date else None
        safe_task_id = str(task_id).strip() if task_id else None

        board_url = f"{self.frontend_url}/?task={safe_task_id}" if safe_task_id else f"{self.frontend_url}/"
        subject = f"New Task Assigned: {safe_title}"

        priority_colors = {
            "urgent": "#ef4444",
            "high": "#f97316",
            "medium": "#3b82f6",
            "low": "#64748b",
        }
        priority_color = priority_colors.get(safe_priority, "#3b82f6")
        deadline_text = f"Due: {safe_due_date}" if safe_due_date else "No deadline set"

        text_content = f"""Hello {safe_name},

{safe_assigned_by} assigned you a new deliverable on TaskTracker:

Task: {safe_title}
Priority: {safe_priority.upper()}
Deadline: {deadline_text}

Description:
{task_description or 'No description provided.'}

View and update this task on your board:
{board_url}

---
TaskTracker Workspace Gateway
https://l4s3r.site
"""

        escaped_subject = html.escape(subject)
        escaped_name = html.escape(safe_name)
        escaped_assigned_by = html.escape(safe_assigned_by)
        escaped_title = html.escape(safe_title)
        escaped_priority = html.escape(safe_priority.upper())
        escaped_desc = html.escape(task_description) if task_description else '<em>No description provided.</em>'
        escaped_url = html.escape(board_url)
        escaped_due = html.escape(safe_due_date) if safe_due_date else None

        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{escaped_subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 30px 15px; color: #0f172a;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="560" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
          <!-- Header -->
          <tr>
            <td style="padding: 28px 32px 20px; background-color: #0f172a; text-align: left;">
              <div style="font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #94a3b8; margin-bottom: 4px;">TaskTracker Notification</div>
              <h1 style="color: #ffffff; font-size: 18px; font-weight: 700; margin: 0;">New Task Assigned</h1>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding: 32px;">
              <p style="font-size: 14px; line-height: 1.5; color: #334155; margin: 0 0 16px;">
                Hello <strong>{escaped_name}</strong>,<br>
                <strong>{escaped_assigned_by}</strong> assigned you to a new workspace task:
              </p>

              <!-- Task Card -->
              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 20px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                      <span style="background-color: {priority_color}; color: #ffffff; font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 3px 8px; border-radius: 6px;">
                        {escaped_priority} PRIORITY
                      </span>
                      {f'<span style="font-size: 12px; font-weight: 600; color: #dc2626;">Deadline: {escaped_due}</span>' if escaped_due else '<span style="font-size: 12px; color: #64748b;">No deadline</span>'}
                    </div>

                    <h2 style="font-size: 16px; font-weight: 700; color: #0f172a; margin: 10px 0 6px;">{escaped_title}</h2>
                    <p style="font-size: 13px; line-height: 1.6; color: #475569; margin: 0;">
                      {escaped_desc}
                    </p>
                  </td>
                </tr>
              </table>

              <!-- CTA Button -->
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="center" style="padding: 6px 0 20px;">
                    <a href="{escaped_url}" style="background-color: #2563eb; color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 10px; font-size: 13px; font-weight: 600; display: inline-block; box-shadow: 0 2px 6px rgba(37,99,235,0.3);">
                      Open Task on Board &rarr;
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 16px 32px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center;">
              You received this automated notification because you were assigned to this task on TaskTracker.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
        return self._dispatch_mime_email(clean_recipient, subject, text_content, html_content)

    def send_deadline_reminder_email(
        self,
        recipient_email: str,
        recipient_name: Optional[str] = None,
        task_title: Optional[str] = "Upcoming Task",
        due_date: Optional[str] = None,
        priority: Optional[str] = "medium",
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch an automated deadline reminder email for approaching deliverable dates."""
        clean_recipient = (recipient_email or "").strip()
        safe_name = (recipient_name or clean_recipient.split("@")[0] or "Team Member").strip()
        safe_title = (task_title or "Upcoming Task").strip()
        safe_priority = (priority or "medium").strip().lower()
        safe_due_date = (due_date or "Soon").strip()
        safe_task_id = str(task_id).strip() if task_id else None

        board_url = f"{self.frontend_url}/?task={safe_task_id}" if safe_task_id else f"{self.frontend_url}/"
        subject = f"Deadline Reminder: {safe_title} (Due: {safe_due_date})"

        text_content = f"""Hello {safe_name},

This is a reminder that the following deliverable is approaching its deadline:

Task: {safe_title}
Priority: {safe_priority.upper()}
Due Date: {safe_due_date}

Please make sure your progress is updated on the workspace board:
{board_url}

---
TaskTracker Workspace Gateway
https://l4s3r.site
"""

        escaped_subject = html.escape(subject)
        escaped_name = html.escape(safe_name)
        escaped_title = html.escape(safe_title)
        escaped_priority = html.escape(safe_priority.upper())
        escaped_due = html.escape(safe_due_date)
        escaped_url = html.escape(board_url)

        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{escaped_subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 30px 15px; color: #0f172a;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="560" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
          <tr>
            <td style="padding: 28px 32px 20px; background-color: #b91c1c; text-align: left;">
              <div style="font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #fecaca; margin-bottom: 4px;">TaskTracker Deadline Alert</div>
              <h1 style="color: #ffffff; font-size: 18px; font-weight: 700; margin: 0;">Approaching Task Deadline</h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px;">
              <p style="font-size: 14px; line-height: 1.5; color: #334155; margin: 0 0 16px;">
                Hello <strong>{escaped_name}</strong>,<br>
                A deliverable assigned to you is due soon:
              </p>
              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #fef2f2; border: 1px solid #fecaca; border-radius: 12px; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 20px;">
                    <div style="font-size: 12px; font-weight: 700; color: #dc2626; margin-bottom: 4px;">
                      DUE: {escaped_due} &bull; {escaped_priority} PRIORITY
                    </div>
                    <h2 style="font-size: 16px; font-weight: 700; color: #991b1b; margin: 6px 0 0;">{escaped_title}</h2>
                  </td>
                </tr>
              </table>
              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td align="center" style="padding: 6px 0 20px;">
                    <a href="{escaped_url}" style="background-color: #b91c1c; color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 10px; font-size: 13px; font-weight: 600; display: inline-block; box-shadow: 0 2px 6px rgba(185,28,28,0.3);">
                      Open Task & Update Status &rarr;
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding: 16px 32px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center;">
              TaskTracker Deadline Notification System.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
        return self._dispatch_mime_email(clean_recipient, subject, text_content, html_content)

    def send_security_alert_email(
        self,
        recipient_email: str,
        recipient_name: Optional[str] = None,
        event_name: str = "Security Event Detected",
        severity: str = "WARNING",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatch an urgent security alert notification email."""
        clean_recipient = (recipient_email or "").strip()
        safe_name = (recipient_name or clean_recipient.split("@")[0] or "User").strip()
        safe_event = (event_name or "Security Notification").strip()
        safe_severity = (severity or "WARNING").strip().upper()
        safe_ip = (ip_address or "Unknown IP").strip()

        subject = f"[{safe_severity}] Security Alert: {safe_event}"

        details_str = ""
        if details:
            for k, v in details.items():
                details_str += f"- {k}: {v}\n"
        if not details_str:
            details_str = "No additional details provided.\n"

        text_content = f"""Hello {safe_name},

A security event was recorded on your Auth N&Z account:

Event: {safe_event}
Severity: {safe_severity}
IP Address: {safe_ip}

Event Details:
{details_str}
If you did not perform this action, please reset your password immediately and contact your workspace administrator.

---
Auth N&Z Security Operations
https://l4s3r.site
"""

        escaped_subject = html.escape(subject)
        escaped_name = html.escape(safe_name)
        escaped_event = html.escape(safe_event)
        escaped_severity = html.escape(safe_severity)
        escaped_ip = html.escape(safe_ip)

        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{escaped_subject}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 30px 15px; color: #0f172a;">
  <table width="100%" border="0" cellspacing="0" cellpadding="0">
    <tr>
      <td align="center">
        <table width="560" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
          <tr>
            <td style="padding: 28px 32px 20px; background-color: #0f172a; text-align: left;">
              <div style="font-size: 11px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #f59e0b; margin-bottom: 4px;">Auth N&Z Security Alert</div>
              <h1 style="color: #ffffff; font-size: 18px; font-weight: 700; margin: 0;">Account Security Notification</h1>
            </td>
          </tr>
          <tr>
            <td style="padding: 32px;">
              <p style="font-size: 14px; line-height: 1.5; color: #334155; margin: 0 0 16px;">
                Hello <strong>{escaped_name}</strong>,<br>
                The following security-relevant activity occurred on your account:
              </p>
              <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #fffbeb; border: 1px solid #fde68a; border-radius: 12px; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 20px;">
                    <div style="font-size: 12px; font-weight: 700; color: #d97706; margin-bottom: 4px;">
                      SEVERITY: {escaped_severity} &bull; IP: {escaped_ip}
                    </div>
                    <h2 style="font-size: 16px; font-weight: 700; color: #92400e; margin: 6px 0 0;">{escaped_event}</h2>
                  </td>
                </tr>
              </table>
              <p style="font-size: 12px; line-height: 1.6; color: #64748b; margin: 0;">
                If you did not initiate this action, please secure your account immediately by resetting your password.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding: 16px 32px; background-color: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center;">
              Auth N&Z Automated Security Operations.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""
        return self._dispatch_mime_email(clean_recipient, subject, text_content, html_content)
