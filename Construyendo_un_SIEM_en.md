### Core Concepts
[[Alertas_en|Alerts]]
[[Eventos_en|Events]]
[[Logs]]
[[Exfiltración_en|Exfiltration]]
[[Bases de Ciberseguridad/Construyendo un siem desde 0/SIEM_en|SIEM]]

### I got my primary machine and the laptop server to communicate
Through [[SSH]].

## Conceptual steps to do it
### The specific goal

When someone attempts to log in via SSH and fails, Ubuntu already records that event in a system log. Your homemade SIEM needs to: read that log, detect when the same IP fails multiple times in a row (brute-force pattern), and alert you.

### Step 1: Understand where the log is located

First, I checked where Ubuntu Server stores the log file for authentication attempts (`auth.log`)

bash

```bash
sudo tail -f /var/log/auth.log
```

There you can see lines like:

```
Sep 9 14:32:01 miserver sshd[1234]: Failed password for invalid user admin from 45.33.22.11 port 51234 ssh2
```

The idea is to convert this raw log into a structured and normalized file that can be understood by the SIEM.

### Step 2: Generate test traffic 

I intentionally made several failed attempts from a remote machine to populate the log with failed logins.

bash

```bash
ssh nonexistent_user@your_vm_ip
```

### Step 3: Write the parser (extract IP and timestamp from each line)

I wrote a Python script that:
1. Reads the `/var/log/auth.log` file line by line
2. Identifies lines containing `"Failed password"`
3. Extracts the IP and timestamp of each failed attempt using a regular expression

> In practice, this is done by a SIEM's grok patterns or parser, but I am emulating it using this regular expression.

### Step 4: Store structured events in a database
Every time the parser finds a failed attempt, instead of leaving it as raw text, you store it in a structure like:

```
{ "ip": "45.33.22.11", "timestamp": "2026-09-09 14:32:01", "user": "admin" }
```

I used SQLite for storage.

This is literally the "normalization and storage" step of a real SIEM, except that instead of Elasticsearch (a very fast database), I used SQLite because the volume of data is small.
### Step 5: Write the correlation rule (the heart of the SIEM)

This is the part that actually "detects" the attack. The logic is simple:

> If the same IP has more than N failed attempts in the last X minutes → trigger an alert.

This translates into a database query like: "count how many events exist for this IP in the last 5 minutes", and if that number exceeds a threshold (e.g. 5), you trigger the alert.

**Key concept: time window and threshold.** This is the essence of almost all correlation rules in a real SIEM — the difference between "a failed login" (normal, happens all the time) and "ten failed logins in one minute from the same IP" (suspicious).

### Step 6: Decide how to run this continuously

Using [`cron`](cron.md), I scheduled a task that runs the script every 1 minute on the server. This parses the entire log file every 60 seconds and gives an alert if >= 10 attempts are detected.

### Step 7: The alert

When the rule is met, the script has to notify in some way. What I did was create a dedicated log file where it writes and logs that there were x attempts every minute.

I programmed another Python script that communicates with a bot I created on Telegram, and this bot sends messages each time the alert trigger fires. 

![[Pasted image 20260911125643.png]]
> The actual message is ALERT: ... the one above that says "Tu sistema es de prueba" was a test.

Python code:

```python
#!/usr/bin/env python3

"""Parse failed SSH password attempts from auth.log into SQLite."""

import argparse

from datetime import datetime

import re

import sqlite3

import time

from pathlib import Path

from telegram_app import send_alert


FAILED_PASSWORD_RE = re.compile(

r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\s+"

r"\S+\s+sshd(?:-session)?(?:\[\d+\])?:\s+Failed password for "

r"(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+"

r"(?P<ip>\S+)\s+port\s+\d+\b"

)

  

  

def parse_failed_passwords(log_path: Path) -> list[dict[str, str | int]]:

"""Return failed-password events found in *log_path*."""

events: list[dict[str, str | int]] = []

  

with log_path.open(encoding="utf-8", errors="replace") as log_file:

for line in log_file:

match = FAILED_PASSWORD_RE.search(line)

if match:

event = match.groupdict()

event_timestamp = datetime.fromisoformat(event["timestamp"])

event["event_time"] = int(event_timestamp.timestamp())

events.append(event)

  

return events

  

  

def save_events(events: list[dict[str, str | int]], database_path: Path) -> int:

"""Save events and return the number of newly inserted rows."""

with sqlite3.connect(database_path) as connection:

changes_before_insert = connection.total_changes

connection.execute(

"""

CREATE TABLE IF NOT EXISTS failed_passwords (

id INTEGER PRIMARY KEY,

ip TEXT NOT NULL,

timestamp TEXT NOT NULL,

user TEXT NOT NULL,

event_time INTEGER,

UNIQUE(ip, timestamp, user)

)

"""

)

columns = {

row[1] for row in connection.execute("PRAGMA table_info(failed_passwords)")

}

if "event_time" not in columns:

connection.execute("ALTER TABLE failed_passwords ADD COLUMN event_time INTEGER")

connection.executemany(

"""

INSERT OR IGNORE INTO failed_passwords (ip, timestamp, user, event_time)

VALUES (:ip, :timestamp, :user, :event_time)

""",

events,

)

return connection.total_changes - changes_before_insert

  

  

def count_recent_events(database_path: Path, window_seconds: int = 60) -> int:

"""Count events whose auth.log timestamp is within the last time window."""

with sqlite3.connect(database_path) as connection:

cutoff = int(time.time()) - window_seconds

return connection.execute(

"SELECT COUNT(*) FROM failed_passwords WHERE event_time >= ?",

(cutoff,),

).fetchone()[0]

  

  

def main() -> None:

parser = argparse.ArgumentParser(

description="Store failed SSH password attempts from auth.log in SQLite."

)

parser.add_argument(

"log_file",

nargs="?",

type=Path,

default=Path("/var/log/auth.log"),

help="Path to auth.log (default: /var/log/auth.log)",

)

parser.add_argument(

"--database",

type=Path,

default=Path("failed_passwords.sqlite3"),

help="SQLite database path (default: failed_passwords.sqlite3)",

)

parser.add_argument(

"--threshold",

type=int,

default=10,

help="Alert threshold for the last minute (default: 10)",

)

args = parser.parse_args()

  

events = parse_failed_passwords(args.log_file)

inserted = save_events(events, args.database)

recent_count = count_recent_events(args.database)

print(f"Found {len(events)} failed password attempts; inserted {inserted} new rows.")

print(f"Failed passwords in the last minute: {recent_count}")

if recent_count >= args.threshold:

alert_message = (

f"ALERT: {recent_count} failed SSH password attempts in the last minute."

)

print(f"{alert_message} Threshold: {args.threshold}.")

send_alert(alert_message)

if __name__ == "__main__":

main()
```

And the Telegram bot code:
```python
"""Send Telegram notifications using a Telethon user session."""

  

import os

from pathlib import Path

from dotenv import load_dotenv

import requests

  

load_dotenv(Path(__file__).with_name(".env"))

  

def send_alert(message: str) -> None:

try:

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

message = message

url = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT_ID}&text={message}"

print(requests.get(url).json())

except Exception as e:

print(f"Error sending alert: {e}")

if __name__ == "__main__":

send_alert("Working...")
```

## Troubleshooting

The issues I ran into while coding happened with the Telegram bot: I followed some code online that didn't work, so I switched to using a direct URL and a request from the Python library, which solved it. I also had to create a virtual environment [[venv]] on the virtual machine to install dependencies there and add its path to crontab. See [[error_externally-managed-environment]].




Next step: Build a visual dashboard with the log information.
![[Pasted image 20260910084545.png]]
