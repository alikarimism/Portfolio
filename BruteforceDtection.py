import win32evtlog
import time
from datetime import datetime, timedelta

# Event log source
SERVER = "localhost"
LOGTYPE = "Security"
EVENT_FAILED_LOGIN = 4625

# Read flags
FLAGS = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

# Thresholds
FAILURE_LIMIT = 5       # failed logins threshold
TIME_WINDOW = timedelta(hours=1)  # 1-hour window

# Logon types we care about
ALLOWED_LOGON_TYPES = {2, 3, 8, 10}


def query_eventlog(EventID):
    """Read Security log for all events with given EventID."""
    logs = []
    h = win32evtlog.OpenEventLog(SERVER, LOGTYPE)

    while True:
        events = win32evtlog.ReadEventLog(h, FLAGS, 0)
        if not events:
            break
        for event in events:
            if event.EventID == EventID:
                logs.append(event)
    return logs


def collect_failures():
    """Return dict of {account: [timestamps]} for failed logins."""
    failures = {}
    events = query_eventlog(EVENT_FAILED_LOGIN)

    for event in events:
        try:
            account = event.StringInserts[5]      # TargetUserName
            logon_type = int(event.StringInserts[10])  # LogonType
            timestamp = event.TimeGenerated

            if logon_type in ALLOWED_LOGON_TYPES:
                if account not in failures:
                    failures[account] = []
                failures[account].append(timestamp)

        except Exception:
            continue
    return failures


def analyze_failures(failures):
    """
    Detect brute force attacks using a 1-hour sliding window.
    Reports one consolidated alert per attack period.
    """
    alerts = []

    for account, timestamps in failures.items():
        timestamps.sort()
        start = 0
        in_attack = False
        attack_start = None

        for end in range(len(timestamps)):
            # shrink window if > 1h
            while timestamps[end] - timestamps[start] > TIME_WINDOW:
                start += 1

            window_size = end - start + 1

            if window_size > FAILURE_LIMIT and not in_attack:
                # entering an attack window
                in_attack = True
                attack_start = timestamps[start]

            if in_attack and (end == len(timestamps) - 1 or 
                              timestamps[end+1] - timestamps[start] > TIME_WINDOW):
                # leaving an attack window
                attack_end = timestamps[end]
                attack_size = end - start + 1
                alerts.append(
                    f"[ALERT] Account '{account}' had {attack_size} failed logins "
                    f"between {attack_start} and {attack_end}"
                )
                in_attack = False
                attack_start = None

    return alerts

def main():
    print("🔍 Inspecting Security logs for brute force attempts (past + live)...")

    # Historical scan
    failures = collect_failures()
    alerts = analyze_failures(failures)

    if alerts:
        print("\n--- Historical Brute Force Detections ---")
        for alert in alerts:
            print(alert)
    else:
        print("✅ No brute force patterns found in past logs.")

    Live monitoring
    print("\n--- Live Monitoring Started --- (Ctrl+C to stop)")
    seen = set()
    while True:
        failures = collect_failures()
        alerts = analyze_failures(failures)

        for alert in alerts:
            if alert not in seen:
                print(alert)
                seen.add(alert)

        time.sleep(60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped monitoring.")
