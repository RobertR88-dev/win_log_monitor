“””
win_log_monitor.py

Windows Security Event Log Monitor – Multi-Channel Alerting
Author : Robert Richardson 
GitHub : https://github.com/RobertR88-dev
Version : 2.0
Requires: Python 3.6+, Windows Server 2016 / 2019 / 2022 / 2025
pip install pywin32 requests twilio

Alert channels (each independently toggleable in CONFIG):

1. SMTP email – formatted HTML via any SMTP provider
1. Teams webhook – adaptive card via incoming webhook (plug and play)
1. Slack webhook – formatted message via incoming webhook (plug and play)
1. Custom webhook – JSON POST to any endpoint (SIEM, PagerDuty, OpsGenie,
LogicMonitor, Splunk, Datadog, etc.)
1. SMS via Twilio – text message for lockout events only

## Monitored event IDs:
4740 – Account lockout -> immediate alert on all enabled channels
4625 – Failed logon -> threshold alert + batched digest
4648 – Explicit credential logon -> batched digest
4771 – Kerberos pre-auth failure -> batched digest

“””

import win32evtlog
import win32evtlogutil
import pywintypes
import winerror
import smtplib
import socket
import logging
import time
import threading
import collections
import html
import json
import os
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dataclasses import dataclass, field
from typing import List, Dict, Optional

try:
import requests
REQUESTS_AVAILABLE = True
except ImportError:
REQUESTS_AVAILABLE = False

try:
from twilio.rest import Client as TwilioClient
TWILIO_AVAILABLE = True
except ImportError:
TWILIO_AVAILABLE = False

# ==============================================================================

# CONFIGURATION – replace all placeholder values before deploying

# ==============================================================================

CONFIG = {

```
# -- Channel toggles --------------------------------------------------------
"enable_smtp" : True,
"enable_teams" : True,
"enable_slack" : True,
"enable_webhook" : True,
"enable_sms" : True, # SMS fires on lockouts only

# -- SMTP -------------------------------------------------------------------
"smtp_host" : "smtp.office365.com",
"smtp_port" : 587, # 587=STARTTLS, 465=SSL
"smtp_user" : "alerter@yourdomain.com", # <- replace
"smtp_password" : "YOUR-SMTP-PASSWORD-HERE", # <- replace
"smtp_use_tls" : True,
"alert_from" : "SecurityMonitor@yourdomain.com", # <- replace
"alert_to" : [
"robertr88-dev@email.com", # <- replace
# "teammate@yourdomain.com", # add more as needed
],

# -- Microsoft Teams --------------------------------------------------------
# Teams Admin Center -> Apps -> Incoming Webhook -> create connector -> copy URL
"teams_webhook_url" : "https://yourtenant.webhook.office.com/webhookb2/YOUR-WEBHOOK-URL-HERE",

# -- Slack ------------------------------------------------------------------
# api.slack.com -> Your Apps -> Incoming Webhooks -> Add New Webhook -> copy URL
"slack_webhook_url" : "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK-HERE",

# -- Generic webhook --------------------------------------------------------
# Works with any tool accepting a JSON POST:
# PagerDuty, OpsGenie, LogicMonitor, Splunk HEC, Datadog, custom SIEM, etc.
# See send_webhook() for the payload structure.
"webhook_url" : "https://your-alerting-tool.com/webhook/YOUR-ENDPOINT",
"webhook_headers" : {
"Content-Type" : "application/json",
"Authorization" : "Bearer YOUR-API-KEY-HERE", # remove this line if not needed
},

# -- Twilio SMS (lockouts only) ---------------------------------------------
# twilio.com/console -> get Account SID, Auth Token, and a Twilio phone number
"twilio_account_sid" : "YOUR-TWILIO-ACCOUNT-SID-HERE",
"twilio_auth_token" : "YOUR-TWILIO-AUTH-TOKEN-HERE",
"twilio_from_number" : "+1YOUR-TWILIO-NUMBER", # must be a Twilio number
"twilio_to_numbers" : [
"+1YOUR-MOBILE-NUMBER", # <- replace
# "+1SECOND-NUMBER", # add more as needed
],

# -- Monitoring scope -------------------------------------------------------
"target_server" : "localhost", # hostname/IP or "localhost"
"log_name" : "Security",
"environment_label" : "PROD", # appears in all alert subjects

# -- Thresholds and timing --------------------------------------------------
"failed_login_threshold" : 5, # failed logins per account before alert
"failed_login_window_secs" : 300, # rolling window for threshold (5 min)
"batch_digest_interval_secs": 900, # how often digest fires (15 min)
"poll_interval_secs" : 10, # how often to poll event log
"max_events_per_poll" : 500,

# -- Misc -------------------------------------------------------------------
"send_digest_if_clean" : False, # skip digest email if nothing to report
"log_to_file" : True,
"log_file_path" : r"C:\Logs\WinLogMonitor\monitor.log",
```

}

# ==============================================================================

# EVENT DEFINITIONS

# ==============================================================================

EVENT_IDS = {
4740: {“name”: “Account Lockout”, “immediate”: True, “severity”: “CRITICAL”},
4625: {“name”: “Failed Logon”, “immediate”: False, “severity”: “WARNING”},
4648: {“name”: “Explicit Credential Logon”, “immediate”: False, “severity”: “WARNING”},
4771: {“name”: “Kerberos Pre-Auth Failure”, “immediate”: False, “severity”: “WARNING”},
}
MONITORED_IDS = set(EVENT_IDS.keys())

LOGON_TYPES = {
“2”: “Interactive”, “3”: “Network”, “4”: “Batch”, “5”: “Service”,
“7”: “Unlock”, “8”: “NetworkCleartext”, “9”: “NewCredentials”,
“10”: “RemoteInteractive”, “11”: “CachedInteractive”,
}

FAILURE_REASONS = {
“%%2304”: “Account locked out”, “%%2310”: “Wrong password”,
“%%2312”: “Account disabled”, “%%2313”: “Account expired”,
“0xC000006A”: “Wrong password”, “0xC0000064”: “User does not exist”,
“0xC000006D”: “Bad credentials”, “0xC000006E”: “Account restriction”,
“0xC000006F”: “Outside logon hours”,“0xC0000070”: “Workstation restriction”,
“0xC0000071”: “Password expired”, “0xC0000072”: “Account disabled”,
“0xC0000234”: “Account locked out”, “0xC0000193”: “Account expired”,
}

# ==============================================================================

# DATA STRUCTURES

# ==============================================================================

@dataclass
class SecurityEvent:
event_id : int
event_name : str
timestamp : datetime
subject_account : str
target_account : str
workstation : str
source_ip : str
logon_type : str
failure_reason : str
severity : str

@dataclass
class AlertState:
failed_logins : List[SecurityEvent] = field(default_factory=list)
explicit_creds : List[SecurityEvent] = field(default_factory=list)
kerberos_fails : List[SecurityEvent] = field(default_factory=list)
lockouts_sent : List[SecurityEvent] = field(default_factory=list)
last_digest_sent: datetime = field(default_factory=datetime.now)
lock : threading.Lock = field(default_factory=threading.Lock)

# ==============================================================================

# LOGGING SETUP

# ==============================================================================

def setup_logging():
handlers = [logging.StreamHandler()]
if CONFIG[“log_to_file”]:
os.makedirs(os.path.dirname(CONFIG[“log_file_path”]), exist_ok=True)
handlers.append(logging.FileHandler(CONFIG[“log_file_path”], encoding=“utf-8”))
logging.basicConfig(
level=logging.INFO,
format=”[%(asctime)s][%(levelname)s] %(message)s”,
datefmt=”%Y-%m-%d %H:%M:%S”,
handlers=handlers,
)

log = logging.getLogger(**name**)
HOSTNAME = socket.gethostname()

# ==============================================================================

# EVENT LOG READER

# ==============================================================================

class EventLogReader:
“””
Stateful Windows Security event log reader.
Seeks to end of log on open so only new events are returned on each poll.
Compatible with Windows Server 2016 / 2019 / 2022 / 2025 via win32evtlog.
“””

```
def __init__(self, server: str, log_name: str):
self.server = server
self.log_name = log_name
self._last_record = None
self._handle = None
self._open()

def _open(self):
self._handle = win32evtlog.OpenEventLog(self.server, self.log_name)
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
events = win32evtlog.ReadEventLog(self._handle, flags, 0)
self._last_record = events[0].RecordNumber if events else 0
log.info(f"Event log opened. Starting at record #{self._last_record}")

def read_new_events(self, max_events: int = 500) -> list:
raw = []
try:
flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
while True:
batch = win32evtlog.ReadEventLog(self._handle, flags, 0)
if not batch:
break
for evt in batch:
if self._last_record and evt.RecordNumber <= self._last_record:
continue
raw.append(evt)
if len(raw) >= max_events:
break
if len(raw) >= max_events:
break
if raw:
self._last_record = raw[-1].RecordNumber
except pywintypes.error as e:
if e.winerror != winerror.ERROR_HANDLE_EOF:
log.warning(f"Event log read error: {e}")
return raw

def close(self):
if self._handle:
win32evtlog.CloseEventLog(self._handle)
```

# ==============================================================================

# EVENT PARSER

# ==============================================================================

def _s(strings, i, default=””):
try:
return (strings[i] or default).strip() if strings and i < len(strings) else default
except (IndexError, TypeError):
return default

def parse_event(evt) -> Optional[SecurityEvent]:
if evt.EventID not in MONITORED_IDS:
return None
s = evt.StringInserts or []
eid = evt.EventID
ts = datetime(*evt.TimeGenerated.timetuple()[:6])

```
if eid == 4740:
return SecurityEvent(eid, EVENT_IDS[eid]["name"], ts,
_s(s,4), _s(s,0), _s(s,1), _s(s,2), "", "Account locked out", "CRITICAL")
if eid == 4625:
return SecurityEvent(eid, EVENT_IDS[eid]["name"], ts,
_s(s,0), _s(s,5), _s(s,13), _s(s,19),
LOGON_TYPES.get(_s(s,10), _s(s,10)),
FAILURE_REASONS.get(_s(s,8), _s(s,8)), "WARNING")
if eid == 4648:
return SecurityEvent(eid, EVENT_IDS[eid]["name"], ts,
_s(s,1), _s(s,5), _s(s,8), _s(s,12), "Explicit", "", "WARNING")
if eid == 4771:
return SecurityEvent(eid, EVENT_IDS[eid]["name"], ts,
"", _s(s,0), "", _s(s,6), "Kerberos",
FAILURE_REASONS.get(_s(s,4), _s(s,4)), "WARNING")
return None
```

# ==============================================================================

# SHARED HELPERS

# ==============================================================================

def _css():
return “””<style>
body{font-family:‘Segoe UI’,Arial,sans-serif;margin:0;background:#F1F5F9;color:#1E293B}
.wrap{max-width:740px;margin:24px auto;background:white;border-radius:10px;
overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)}
.hdr{padding:20px 28px;color:white}
.hdr h1{margin:0;font-size:1.2em}.hdr p{margin:5px 0 0;opacity:.8;font-size:.85em}
.body{padding:20px 28px}
.meta{background:#F8FAFC;border-radius:8px;padding:14px 18px;
margin-bottom:18px;font-size:.88em;line-height:1.9}
.meta strong{color:#1E40AF}
table{width:100%;border-collapse:collapse;margin-top:14px;font-size:.85em}
th{background:#1E40AF;color:white;padding:8px 12px;text-align:left}
td{padding:7px 12px;border-bottom:1px solid #E2E8F0;vertical-align:top}
tr:nth-child(even) td{background:#F8FAFC}
.crit{background:#FEE2E2;color:#991B1B;padding:2px 8px;border-radius:4px;
font-size:.78em;font-weight:700}
.warn{background:#FEF3C7;color:#92400E;padding:2px 8px;border-radius:4px;
font-size:.78em;font-weight:700}
.footer{padding:12px 28px;background:#F8FAFC;font-size:.75em;
color:#94A3B8;border-top:1px solid #E2E8F0}
</style>”””

def _footer_html():
return (f”WinLogMonitor v2.0 • {HOSTNAME} • “
f”robertr88-dev@email.com • github.com/RobertR88-dev”)

def _event_rows(events: list, badge: str) -> str:
if not events:
return (”<tr><td colspan='5' style='color:#94A3B8;"
"font-style:italic'>None this window.</td></tr>”)
rows = []
for e in events:
rows.append(
f”<tr><td>{e.timestamp.strftime(’%H:%M:%S’)}</td>”
f”<td><span class='{badge}'>{html.escape(e.event_name)}</span></td>”
f”<td>{html.escape(e.target_account)}</td>”
f”<td>{html.escape(e.source_ip or e.workstation or ‘N/A’)}</td>”
f”<td style='font-size:.82em;color:#64748B'>”
f”{html.escape(e.failure_reason or e.logon_type or ‘’)}</td></tr>”
)
return “\n”.join(rows)

# ==============================================================================

# CHANNEL 1: SMTP EMAIL

# ==============================================================================

def _send_smtp(msg: MIMEMultipart) -> bool:
try:
if CONFIG[“smtp_use_tls”]:
srv = smtplib.SMTP(CONFIG[“smtp_host”], CONFIG[“smtp_port”], timeout=30)
srv.ehlo(); srv.starttls(); srv.ehlo()
else:
srv = smtplib.SMTP_SSL(CONFIG[“smtp_host”], CONFIG[“smtp_port”], timeout=30)
srv.login(CONFIG[“smtp_user”], CONFIG[“smtp_password”])
srv.sendmail(CONFIG[“alert_from”], CONFIG[“alert_to”], msg.as_string())
srv.quit()
log.info(f”[SMTP] Sent: {msg[‘Subject’]}”)
return True
except smtplib.SMTPAuthenticationError:
log.error(”[SMTP] Authentication failed – check smtp_user and smtp_password.”)
except Exception as e:
log.error(f”[SMTP] Send failed: {e}”)
return False

def _make_email(subject: str, html_body: str) -> MIMEMultipart:
msg = MIMEMultipart(“alternative”)
msg[“Subject”] = subject
msg[“From”] = CONFIG[“alert_from”]
msg[“To”] = “, “.join(CONFIG[“alert_to”])
msg.attach(MIMEText(html_body, “html”))
return msg

# ==============================================================================

# CHANNEL 2: MICROSOFT TEAMS WEBHOOK

# ==============================================================================

def _send_teams(title: str, summary: str, color: str, facts: list,
body_text: str = “”) -> bool:
“””
Sends an Adaptive Card to a Teams channel via incoming webhook.
color: hex color string for the card accent e.g. “DC2626”
facts: list of {“name”: str, “value”: str} dicts
“””
if not REQUESTS_AVAILABLE:
log.warning(”[Teams] requests library not installed. pip install requests”)
return False

```
card = {
"type": "message",
"attachments": [{
"contentType": "application/vnd.microsoft.card.adaptive",
"content": {
"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
"type": "AdaptiveCard",
"version": "1.4",
"body": [
{
"type": "TextBlock",
"text": title,
"weight": "Bolder",
"size": "Medium",
"color": "Attention" if color in ("DC2626","991B1B") else "Warning",
"wrap": True,
},
{
"type": "TextBlock",
"text": f"{HOSTNAME} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
"isSubtle": True,
"size": "Small",
"wrap": True,
},
{
"type": "FactSet",
"facts": facts,
},
] + ([{
"type": "TextBlock",
"text": body_text,
"wrap": True,
"size": "Small",
"isSubtle": True,
}] if body_text else []),
"actions": [{
"type": "Action.OpenUrl",
"title": "View on GitHub",
"url": "https://github.com/RobertR88-dev",
}],
},
}],
}

try:
r = requests.post(CONFIG["teams_webhook_url"], json=card, timeout=15)
if r.status_code in (200, 202):
log.info(f"[Teams] Card sent: {title}")
return True
log.warning(f"[Teams] Unexpected response {r.status_code}: {r.text[:200]}")
except Exception as e:
log.error(f"[Teams] Send failed: {e}")
return False
```

# ==============================================================================

# CHANNEL 3: SLACK WEBHOOK

# ==============================================================================

def _send_slack(title: str, text: str, color: str) -> bool:
“””
Sends a formatted attachment message to Slack via incoming webhook.
color: hex color string e.g. “#DC2626”
“””
if not REQUESTS_AVAILABLE:
log.warning(”[Slack] requests library not installed. pip install requests”)
return False

```
payload = {
"attachments": [{
"color" : f"#{color}" if not color.startswith("#") else color,
"title" : title,
"text" : text,
"footer" : f"WinLogMonitor | {HOSTNAME} | github.com/RobertR88-dev",
"ts" : int(datetime.now().timestamp()),
"mrkdwn_in" : ["text"],
}]
}

try:
r = requests.post(CONFIG["slack_webhook_url"], json=payload, timeout=15)
if r.status_code == 200 and r.text == "ok":
log.info(f"[Slack] Message sent: {title}")
return True
log.warning(f"[Slack] Unexpected response {r.status_code}: {r.text[:200]}")
except Exception as e:
log.error(f"[Slack] Send failed: {e}")
return False
```

# ==============================================================================

# CHANNEL 4: GENERIC WEBHOOK

# ==============================================================================

def _send_webhook(event_type: str, severity: str, data: dict) -> bool:
“””
Sends a JSON POST to the configured webhook endpoint.
Compatible with PagerDuty, OpsGenie, LogicMonitor, Splunk HEC,
Datadog, custom SIEMs, or any endpoint accepting JSON.

```
Payload structure:
{
"source" : "WinLogMonitor",
"version" : "2.0",
"hostname" : "<server>",
"timestamp" : "<ISO8601>",
"event_type" : "<LOCKOUT|THRESHOLD|DIGEST>",
"severity" : "<CRITICAL|WARNING|INFO>",
"environment" : "<label from config>",
"data" : { ...event-specific fields... }
}
"""
if not REQUESTS_AVAILABLE:
log.warning("[Webhook] requests library not installed. pip install requests")
return False

payload = {
"source" : "WinLogMonitor",
"version" : "2.0",
"hostname" : HOSTNAME,
"timestamp" : datetime.now().isoformat(),
"event_type" : event_type,
"severity" : severity,
"environment" : CONFIG["environment_label"],
"data" : data,
}

try:
r = requests.post(
CONFIG["webhook_url"],
headers=CONFIG["webhook_headers"],
json=payload,
timeout=15,
)
if 200 <= r.status_code < 300:
log.info(f"[Webhook] Sent {event_type} to {CONFIG['webhook_url']}")
return True
log.warning(f"[Webhook] Response {r.status_code}: {r.text[:200]}")
except Exception as e:
log.error(f"[Webhook] Send failed: {e}")
return False
```

# ==============================================================================

# CHANNEL 5: SMS VIA TWILIO (lockouts only)

# ==============================================================================

def *send_sms(body: str) -> bool:
if not TWILIO_AVAILABLE:
log.warning(”[SMS] twilio library not installed. pip install twilio”)
return False
try:
client = TwilioClient(CONFIG[“twilio_account_sid”], CONFIG[“twilio_auth_token”])
for number in CONFIG[“twilio_to_numbers”]:
client.messages.create(
body=body,
from*=CONFIG[“twilio_from_number”],
to=number,
)
log.info(f”[SMS] Sent to {number}”)
return True
except Exception as e:
log.error(f”[SMS] Send failed: {e}”)
return False

# ==============================================================================

# ALERT DISPATCHER – sends to all enabled channels

# ==============================================================================

def dispatch_lockout(event: SecurityEvent):
“”“Fire immediate lockout alerts across all enabled channels.”””
env = CONFIG[“environment_label”]
ts = event.timestamp.strftime(”%Y-%m-%d %H:%M:%S”)

```
# 1. SMTP
if CONFIG["enable_smtp"]:
subj = f"[{env}] ACCOUNT LOCKOUT -- {event.target_account} on {HOSTNAME}"
body = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">{_css()}</head><body>
<div class="wrap">
<div class="hdr" style="background:linear-gradient(135deg,#991B1B,#DC2626)">
<h1>Account Lockout Detected</h1>
<p>{HOSTNAME} &bull; {ts}</p>
</div>
<div class="body">
<div class="meta">
<strong>Locked Account:</strong> {html.escape(event.target_account)}<br>
<strong>Triggered By:</strong> {html.escape(event.subject_account) or 'N/A'}<br>
<strong>Source Workstation:</strong> {html.escape(event.workstation) or 'N/A'}<br>
<strong>Source IP:</strong> {html.escape(event.source_ip) or 'N/A'}<br>
<strong>Server:</strong> {HOSTNAME}<br>
<strong>Timestamp:</strong> {ts}
</div>
<p style="font-size:.88em;color:#475569">Immediate alert. Investigate source
workstation and IP. If unexpected, reset the password and review
Entra ID sign-in logs.</p>
</div>
<div class="footer">{_footer_html()}</div>
</div></body></html>"""
_send_smtp(_make_email(subj, body))

# 2. Teams
if CONFIG["enable_teams"]:
_send_teams(
title = f"ACCOUNT LOCKOUT -- {event.target_account}",
summary = f"Lockout on {HOSTNAME}",
color = "DC2626",
facts = [
{"name": "Locked Account", "value": event.target_account},
{"name": "Triggered By", "value": event.subject_account or "N/A"},
{"name": "Source IP", "value": event.source_ip or "N/A"},
{"name": "Workstation", "value": event.workstation or "N/A"},
{"name": "Server", "value": HOSTNAME},
{"name": "Timestamp", "value": ts},
{"name": "Environment", "value": CONFIG["environment_label"]},
],
body_text="Investigate source workstation and IP. Reset password if unexpected.",
)

# 3. Slack
if CONFIG["enable_slack"]:
_send_slack(
title = f"LOCKOUT | {env} | {event.target_account} on {HOSTNAME}",
text = (
f"*Locked Account:* `{event.target_account}`\n"
f"*Triggered By:* `{event.subject_account or 'N/A'}`\n"
f"*Source IP:* `{event.source_ip or 'N/A'}`\n"
f"*Workstation:* `{event.workstation or 'N/A'}`\n"
f"*Server:* `{HOSTNAME}` | *Time:* `{ts}`"
),
color = "DC2626",
)

# 4. Webhook
if CONFIG["enable_webhook"]:
_send_webhook("LOCKOUT", "CRITICAL", {
"locked_account" : event.target_account,
"triggered_by" : event.subject_account,
"source_ip" : event.source_ip,
"workstation" : event.workstation,
"server" : HOSTNAME,
"event_id" : 4740,
"timestamp" : ts,
})

# 5. SMS
if CONFIG["enable_sms"]:
sms_body = (
f"[{env}] LOCKOUT ALERT\n"
f"Account: {event.target_account}\n"
f"Server: {HOSTNAME}\n"
f"IP: {event.source_ip or 'N/A'}\n"
f"Time: {ts}\n"
f"-- WinLogMonitor"
)
_send_sms(sms_body)
```

def dispatch_threshold(event: SecurityEvent, count: int):
“”“Fire threshold (brute-force) alerts across all enabled channels except SMS.”””
env = CONFIG[“environment_label”]
ts = event.timestamp.strftime(”%Y-%m-%d %H:%M:%S”)
win_mins = CONFIG[“failed_login_window_secs”] // 60
threshold = CONFIG[“failed_login_threshold”]

```
# 1. SMTP
if CONFIG["enable_smtp"]:
subj = f"[{env}] BRUTE FORCE -- {event.target_account} -- {count} failures on {HOSTNAME}"
body = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">{_css()}</head><body>
<div class="wrap">
<div class="hdr" style="background:linear-gradient(135deg,#92400E,#D97706)">
<h1>Failed Login Threshold Exceeded</h1>
<p>{HOSTNAME} &bull; {ts}</p>
</div>
<div class="body">
<div class="meta">
<strong>Target Account:</strong>
{html.escape(event.target_account)}<br>
<strong>Failure Count:</strong>
<span style="color:#DC2626;font-weight:700">
{count} in {win_mins} minutes
</span><br>
<strong>Threshold:</strong> {threshold} attempts<br>
<strong>Last Source IP:</strong> {html.escape(event.source_ip or 'N/A')}<br>
<strong>Workstation:</strong> {html.escape(event.workstation or 'N/A')}<br>
<strong>Failure Reason:</strong>{html.escape(event.failure_reason or 'N/A')}<br>
<strong>Server:</strong> {HOSTNAME}<br>
<strong>Timestamp:</strong> {ts}
</div>
<p style="font-size:.88em;color:#475569">Possible brute-force or password spray.
Review source IP in Proofpoint and Entra ID sign-in logs. Consider blocking
source IP at firewall or Conditional Access.</p>
</div>
<div class="footer">{_footer_html()}</div>
</div></body></html>"""
_send_smtp(_make_email(subj, body))

# 2. Teams
if CONFIG["enable_teams"]:
_send_teams(
title = f"BRUTE FORCE ALERT -- {event.target_account}",
summary = f"Threshold hit on {HOSTNAME}",
color = "D97706",
facts = [
{"name": "Target Account", "value": event.target_account},
{"name": "Failure Count", "value": f"{count} in {win_mins} minutes"},
{"name": "Threshold", "value": str(threshold)},
{"name": "Last Source IP", "value": event.source_ip or "N/A"},
{"name": "Failure Reason", "value": event.failure_reason or "N/A"},
{"name": "Server", "value": HOSTNAME},
{"name": "Environment", "value": CONFIG["environment_label"]},
],
body_text="Possible brute-force or password spray. Review source IP.",
)

# 3. Slack
if CONFIG["enable_slack"]:
_send_slack(
title = f"BRUTE FORCE | {env} | {event.target_account} -- {count} failures",
text = (
f"*Account:* `{event.target_account}`\n"
f"*Failures:* `{count}` in `{win_mins}` minutes (threshold: {threshold})\n"
f"*Source IP:* `{event.source_ip or 'N/A'}`\n"
f"*Reason:* `{event.failure_reason or 'N/A'}`\n"
f"*Server:* `{HOSTNAME}` | *Time:* `{ts}`"
),
color = "D97706",
)

# 4. Webhook
if CONFIG["enable_webhook"]:
_send_webhook("THRESHOLD", "WARNING", {
"target_account" : event.target_account,
"failure_count" : count,
"window_minutes" : win_mins,
"threshold" : threshold,
"source_ip" : event.source_ip,
"failure_reason" : event.failure_reason,
"server" : HOSTNAME,
"event_id" : 4625,
"timestamp" : ts,
})
```

def dispatch_digest(state: AlertState) -> bool:
“”“Send batched digest across SMTP, Teams, Slack, and webhook. No SMS for digest.”””
total = len(state.failed_logins) + len(state.explicit_creds) + len(state.kerberos_fails)
if total == 0 and not CONFIG[“send_digest_if_clean”]:
log.info(“Digest skipped – no events and send_digest_if_clean is False.”)
return False

```
env = CONFIG["environment_label"]
now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
win_mins = CONFIG["batch_digest_interval_secs"] // 60

all_batched = state.failed_logins + state.explicit_creds + state.kerberos_fails
top_accounts = collections.Counter(
e.target_account for e in all_batched if e.target_account
).most_common(5)
top_ips = collections.Counter(
e.source_ip for e in all_batched if e.source_ip and e.source_ip not in ("-", "")
).most_common(5)

score_color = "#16A34A" if total == 0 else ("#D97706" if total < 20 else "#DC2626")

# 1. SMTP
if CONFIG["enable_smtp"]:
subj = f"[{env}] Auth Digest -- {total} events -- {HOSTNAME}"

offender_rows = "".join(
f"<tr><td>{html.escape(a)}</td><td>{c}</td></tr>"
for a, c in top_accounts
) or "<tr><td colspan='2' style='color:#94A3B8'>None</td></tr>"

ip_rows = "".join(
f"<tr><td>{html.escape(ip)}</td><td>{c}</td></tr>"
for ip, c in top_ips
) or "<tr><td colspan='2' style='color:#94A3B8'>None</td></tr>"

body = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">{_css()}</head><body>
<div class="wrap">
<div class="hdr" style="background:linear-gradient(135deg,#1E40AF,#1D4ED8)">
<h1>Authentication Event Digest</h1>
<p>{HOSTNAME} &bull; Last {win_mins} minutes &bull; {now_str}</p>
</div>
<div class="body">
<div class="meta">
<strong>Failed Logons (4625):</strong>
<span style="color:{score_color};font-weight:700">
{len(state.failed_logins)}
</span><br>
<strong>Explicit Credentials (4648):</strong> {len(state.explicit_creds)}<br>
<strong>Kerberos Failures (4771):</strong> {len(state.kerberos_fails)}<br>
<strong>Lockouts this window:</strong> {len(state.lockouts_sent)}<br>
<strong>Total events:</strong>
<span style="font-weight:700;color:{score_color}">{total}</span>
</div>
<h3 style="font-size:.9em;color:#1E40AF;margin:16px 0 6px">
Top Targeted Accounts</h3>
<table><tr><th>Account</th><th>Count</th></tr>{offender_rows}</table>
<h3 style="font-size:.9em;color:#1E40AF;margin:16px 0 6px">
Top Source IPs</h3>
<table><tr><th>IP Address</th><th>Count</th></tr>{ip_rows}</table>
<h3 style="font-size:.9em;color:#1E40AF;margin:16px 0 6px">
Failed Logon Detail (4625)</h3>
<table>
<tr><th>Time</th><th>Event</th><th>Account</th>
<th>Source</th><th>Reason</th></tr>
{_event_rows(state.failed_logins[-25:], 'warn')}
</table>
<h3 style="font-size:.9em;color:#1E40AF;margin:16px 0 6px">
Explicit Credential Use (4648)</h3>
<table>
<tr><th>Time</th><th>Event</th><th>Account</th>
<th>Source</th><th>Type</th></tr>
{_event_rows(state.explicit_creds[-15:], 'warn')}
</table>
<h3 style="font-size:.9em;color:#1E40AF;margin:16px 0 6px">
Kerberos Failures (4771)</h3>
<table>
<tr><th>Time</th><th>Event</th><th>Account</th>
<th>Source</th><th>Reason</th></tr>
{_event_rows(state.kerberos_fails[-15:], 'warn')}
</table>
</div>
<div class="footer">{_footer_html()}</div>
</div></body></html>"""
_send_smtp(_make_email(subj, body))

# 2. Teams
if CONFIG["enable_teams"]:
top_acct_str = ", ".join(f"{a} ({c})" for a, c in top_accounts) or "None"
top_ip_str = ", ".join(f"{ip} ({c})" for ip, c in top_ips) or "None"
_send_teams(
title = f"Auth Digest -- {total} events in {win_mins} min",
summary = f"Digest from {HOSTNAME}",
color = "1D4ED8",
facts = [
{"name": "Failed Logons (4625)", "value": str(len(state.failed_logins))},
{"name": "Explicit Creds (4648)", "value": str(len(state.explicit_creds))},
{"name": "Kerberos Fails (4771)", "value": str(len(state.kerberos_fails))},
{"name": "Lockouts this window", "value": str(len(state.lockouts_sent))},
{"name": "Top Accounts", "value": top_acct_str},
{"name": "Top Source IPs", "value": top_ip_str},
{"name": "Server", "value": HOSTNAME},
{"name": "Environment", "value": env},
],
)

# 3. Slack
if CONFIG["enable_slack"]:
top_acct_str = "\n".join(f" `{a}` ({c} hits)" for a, c in top_accounts) or " None"
_send_slack(
title = f"Auth Digest | {env} | {total} events | {HOSTNAME}",
text = (
f"*Window:* Last {win_mins} minutes\n"
f"*Failed Logons:* `{len(state.failed_logins)}` "
f"*Explicit Creds:* `{len(state.explicit_creds)}` "
f"*Kerberos:* `{len(state.kerberos_fails)}` "
f"*Lockouts:* `{len(state.lockouts_sent)}`\n\n"
f"*Top Targeted Accounts:*\n{top_acct_str}"
),
color = "1D4ED8",
)

# 4. Webhook
if CONFIG["enable_webhook"]:
_send_webhook("DIGEST", "INFO", {
"window_minutes" : win_mins,
"failed_logins" : len(state.failed_logins),
"explicit_creds" : len(state.explicit_creds),
"kerberos_failures" : len(state.kerberos_fails),
"lockouts_sent" : len(state.lockouts_sent),
"total_events" : total,
"top_accounts" : [{"account": a, "count": c} for a, c in top_accounts],
"top_source_ips" : [{"ip": ip, "count": c} for ip, c in top_ips],
"server" : HOSTNAME,
"timestamp" : now_str,
})

return True
```

# ==============================================================================

# THRESHOLD TRACKER

# ==============================================================================

class FailedLoginTracker:
“””
Tracks failed logins per account in a rolling time window.
Fires once per account per window when threshold is crossed.
Prevents alert flooding on sustained attacks.
“””

```
def __init__(self, threshold: int, window_secs: int):
self.threshold = threshold
self.window_secs = window_secs
self._buckets: Dict[str, list] = collections.defaultdict(list)
self._alerted: Dict[str, datetime] = {}
self._lock = threading.Lock()

def record(self, event: SecurityEvent) -> bool:
account = event.target_account or "UNKNOWN"
now = datetime.now()
cutoff = now - timedelta(seconds=self.window_secs)
with self._lock:
self._buckets[account] = [t for t in self._buckets[account] if t > cutoff]
self._buckets[account].append(now)
count = len(self._buckets[account])
last = self._alerted.get(account)
if last and last > cutoff:
return False
if count >= self.threshold:
self._alerted[account] = now
log.warning(f"Threshold: {account} -- {count} failures in window")
return True
return False

def get_count(self, account: str) -> int:
cutoff = datetime.now() - timedelta(seconds=self.window_secs)
with self._lock:
return len([t for t in self._buckets.get(account, []) if t > cutoff])
```

# ==============================================================================

# DIGEST SCHEDULER

# ==============================================================================

def digest_scheduler(state: AlertState):
“”“Background thread – fires digest on configured interval then resets state.”””
while True:
time.sleep(CONFIG[“batch_digest_interval_secs”])
log.info(“Digest interval reached.”)
with state.lock:
dispatch_digest(state)
state.failed_logins = []
state.explicit_creds = []
state.kerberos_fails = []
state.lockouts_sent = []
state.last_digest_sent = datetime.now()

# ==============================================================================

# MAIN

# ==============================================================================

def run():
setup_logging()
log.info(”=” * 70)
log.info(“WinLogMonitor v2.0 starting”)
log.info(f”Author : Robert Richardson [robertr88-dev@email.com](mailto:robertr88-dev@email.com)”)
log.info(f”GitHub : https://github.com/RobertR88-dev”)
log.info(f”Server : {HOSTNAME}”)
log.info(f”Target : {CONFIG[‘target_server’]} – {CONFIG[‘log_name’]} log”)
log.info(f”Channels : “
f”SMTP={‘ON’ if CONFIG[‘enable_smtp’] else ‘OFF’} “
f”Teams={‘ON’ if CONFIG[‘enable_teams’] else ‘OFF’} “
f”Slack={‘ON’ if CONFIG[‘enable_slack’] else ‘OFF’} “
f”Webhook={‘ON’ if CONFIG[‘enable_webhook’] else ‘OFF’} “
f”SMS={‘ON’ if CONFIG[‘enable_sms’] else ‘OFF’}”)
log.info(f”Threshold : {CONFIG[‘failed_login_threshold’]} failures / “
f”{CONFIG[‘failed_login_window_secs’]}s window”)
log.info(f”Digest : every {CONFIG[‘batch_digest_interval_secs’] // 60} minutes”)
log.info(f”Poll : every {CONFIG[‘poll_interval_secs’]}s”)
log.info(”=” * 70)

```
reader = EventLogReader(CONFIG["target_server"], CONFIG["log_name"])
state = AlertState()
tracker = FailedLoginTracker(
CONFIG["failed_login_threshold"],
CONFIG["failed_login_window_secs"],
)

digest_thread = threading.Thread(
target=digest_scheduler, args=(state,), daemon=True, name="DigestScheduler"
)
digest_thread.start()
log.info("Digest scheduler started.")

try:
while True:
raw_events = reader.read_new_events(CONFIG["max_events_per_poll"])
if raw_events:
log.info(f"Read {len(raw_events)} new event(s)")

for raw in raw_events:
event = parse_event(raw)
if not event:
continue

log.info(
f"[{event.event_id}] {event.event_name} | "
f"Account: {event.target_account} | "
f"Source: {event.source_ip or event.workstation or 'N/A'}"
)

if event.event_id == 4740:
log.warning(f"LOCKOUT: {event.target_account}")
dispatch_lockout(event)
with state.lock:
state.lockouts_sent.append(event)

elif event.event_id == 4625:
crossed = tracker.record(event)
with state.lock:
state.failed_logins.append(event)
if crossed:
count = tracker.get_count(event.target_account)
dispatch_threshold(event, count)

elif event.event_id == 4648:
with state.lock:
state.explicit_creds.append(event)

elif event.event_id == 4771:
with state.lock:
state.kerberos_fails.append(event)

time.sleep(CONFIG["poll_interval_secs"])

except KeyboardInterrupt:
log.info("Shutdown -- sending final digest...")
with state.lock:
dispatch_digest(state)
reader.close()
log.info("WinLogMonitor stopped cleanly.")

except Exception as e:
log.critical(f"Unhandled exception: {e}", exc_info=True)
reader.close()
raise
```

if **name** == “**main**”:
run()