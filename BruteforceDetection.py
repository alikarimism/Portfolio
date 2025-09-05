# ==========================================================
# IMPORTS
# ==========================================================

# win32evtlog lets us read Windows Event Logs (Security, Application, etc.)
import win32evtlog  

# time lets us pause the program while monitoring live logs
import time          

# datetime is used to handle timestamps (e.g., "1 hour window")
from datetime import datetime, timedelta


# ==========================================================
# CONFIGURATION (SETTINGS)
# ==========================================================

# The machine where we want to read the logs from.
# "localhost" means the computer where this script is running.
SERVER = "localhost"             

# Which log we want to check. For brute force detection, we use "Security".
LOGTYPE = "Security"             

# Event ID 4625 = "An account failed to log on"
# This is the key event we care about.
EVENT_FAILED_LOGIN = 4625        

# Flags tell Python HOW to read the log:
# - EVENTLOG_FORWARDS_READ → read from oldest to newest
# - EVENTLOG_SEQUENTIAL_READ → read entries one by one
FLAGS = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

# Thresholds:
FAILURE_LIMIT = 5                  # More than 5 failures = suspicious
TIME_WINDOW = timedelta(hours=1)   # Look at failures inside a 1-hour window

# Which logon types matter to us (types of login attempts):
#   2 = Interactive (logging in at the physical computer)
#   3 = Network (accessing a shared folder over the network)
#   8 = NetworkCleartext (cleartext password over the network)
#   10 = RemoteInteractive (RDP - Remote Desktop Protocol)
ALLOWED_LOGON_TYPES = {2, 3, 8, 10}


# ==========================================================
# STEP 1: Reading Event Logs
# ==========================================================

def query_eventlog(EventID):
    """
    This function reads the Windows Security Log and
    collects all events that match the given EventID.
    
    Example: if EventID = 4625, it will return all failed login events.
    """
    logs = []
    
    # Open the Security log on the computer
    h = win32evtlog.OpenEventLog(SERVER, LOGTYPE)

    # Keep reading until there are no more events
    while True:
        # Read a "batch" of events
        events = win32evtlog.ReadEventLog(h, FLAGS, 0)
        
        # If no more events, stop the loop
        if not events:
            break
        
        # Otherwise, check each event in this batch
        for event in events:
            if event.EventID == EventID:
                logs.append(event)  # Save the event
    return logs


# ==========================================================
# STEP 2: Collect Failed Logins
# ==========================================================

def collect_failures():
    """
    Look through all Event ID 4625 events and store them in a dictionary:
    
    failures = {
        "username1": [(time1, logonType1), (time2, logonType2), ...],
        "username2": [...],
    }
    """
    failures = {}
    
    # Get ALL 4625 events
    events = query_eventlog(EVENT_FAILED_LOGIN)

    # Go through each failed login event
    for event in events:
        try:
            # Extract useful info from the event:
            account = event.StringInserts[5]        # The account that failed
            logon_type = int(event.StringInserts[10])  # Type of login attempt
            timestamp = event.TimeGenerated           # When it happened

            # We only care about specific logon types
            if logon_type in ALLOWED_LOGON_TYPES:
                if account not in failures:
                    failures[account] = []
                
                # Save timestamp + logon type
                failures[account].append((timestamp, logon_type))

        except Exception:
            # If something goes wrong (like missing data), skip that event
            continue
    
    return failures


# ==========================================================
# STEP 3: Analyze Failures
# ==========================================================

def analyze_failures(failures):
    """
    Look for brute force patterns in the failed login data.
    
    RULE:
    - If a user has more than FAILURE_LIMIT failed logins
      inside a TIME_WINDOW (1 hour), we raise an ALERT.
    
    This function returns a list of alert messages.
    """
    alerts = []

    # Check each account separately
    for account, entries in failures.items():
        # Sort all attempts by time
        entries.sort(key=lambda x: x[0])
        
        # Just the timestamps
        timestamps = [t for t, _ in entries]

        start = 0              # Start of sliding window
        in_attack = False      # Are we currently inside an attack window?
        attack_start = None    # First failed attempt of the attack

        # Slide through timestamps (like a moving 1-hour window)
        for end in range(len(timestamps)):
            # If the window is larger than 1 hour, move the start forward
            while timestamps[end] - timestamps[start] > TIME_WINDOW:
                start += 1

            window_size = end - start + 1  # Number of failures in this window

            # If we cross the failure limit, mark it as an attack
            if window_size > FAILURE_LIMIT and not in_attack:
                in_attack = True
                attack_start = timestamps[start]

            # If the attack window is ending
            if in_attack and (end == len(timestamps) - 1 or
                              timestamps[end+1] - timestamps[start] > TIME_WINDOW):
                attack_end = timestamps[end]
                attack_size = end - start + 1

                # Collect the logon types used during this attack
                window_logon_types = set(lt for ts, lt in entries[start:end+1])

                # Build an alert message
                alerts.append(
                    f"[ALERT] Account '{account}' had {attack_size} failed logins "
                    f"between {attack_start} and {attack_end} "
                    f"(LogonTypes={sorted(window_logon_types)})"
                )

                # Reset attack state
                in_attack = False
                attack_start = None

    return alerts


# ==========================================================
# STEP 4: Main Program
# ==========================================================

def main():
    print("🔍 Inspecting Security logs for brute force attempts (past + live)...")

    # ---- First, check ALL past logs (historical scan) ----
    failures = collect_failures()
    alerts = analyze_failures(failures)

    if alerts:
        print("\n--- Historical Brute Force Detections ---")
        for alert in alerts:
            print(alert)
    else:
        print("✅ No brute force patterns found in past logs.")

    # ---- Then, start live monitoring ----
    print("\n--- Live Monitoring Started --- (Ctrl+C to stop)")
    seen = set()  # Keep track of already-reported alerts

    while True:
        # Get the latest failures
        failures = collect_failures()
        alerts = analyze_failures(failures)

        # Print only new alerts
        for alert in alerts:
            if alert not in seen:
                print(alert)
                seen.add(alert)

        # Sleep for 60 seconds before checking again
        time.sleep(60)


# ==========================================================
# RUN PROGRAM
# ==========================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped monitoring.")
