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
FAILURE_LIMIT = 10                 # More than 10 failures = suspicious
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
    Analyze failed login events to detect brute force attacks.

    RULE:
    - If a user has more than FAILURE_LIMIT failed logins
      within a TIME_WINDOW (e.g. 1 hour), we consider it a brute force attack.

    INPUT:
    - failures: dictionary {account: [(timestamp, logon_type), ...]}
        Example:
        {
          "alice": [(2025-09-01 12:00, 3), (2025-09-01 12:05, 3), ...],
          "bob":   [(2025-09-01 14:00, 10), ...]
        }

    OUTPUT:
    - alerts: list of text messages describing detected brute force attacks
    """

    alerts = []  # we will fill this list with alert messages

    # 🔍 Process each user account separately
    for account, entries in failures.items():

        # Step 1: Sort events by timestamp (oldest → newest)
        # Why? Because brute force detection depends on time order.
        entries.sort(key=lambda x: x[0])

        # Extract only the timestamps (ignore logon_type for now)
        # Example: [(12:00, 3), (12:05, 3)] → [12:00, 12:05]
        timestamps = [t for t, _ in entries]

        # Sliding window pointers
        start = 0              # Left boundary of our "time window"
        in_attack = False      # Flag: are we currently inside an attack?
        attack_start = None    # When the current attack started

        # Step 2: Move through all timestamps using 'end' as the right boundary
        for end in range(len(timestamps)):

            # Step 2a: Shrink the window from the left
            # ---------------------------------------
            # If the time span between the newest event (end) and the oldest event (start)
            # is longer than TIME_WINDOW (e.g. 1 hour), then "start" is too far behind.
            # We move 'start' forward until the window fits inside 1 hour.
            while timestamps[end] - timestamps[start] > TIME_WINDOW:
                start += 1

            # Step 2b: Count the number of events inside the window
            # -----------------------------------------------------
            window_size = end - start + 1

            # Step 2c: Detect start of an attack
            # ----------------------------------
            # If there are more failures than allowed (FAILURE_LIMIT)
            # AND we are not already in an attack, then this marks the
            # beginning of a brute force attempt.
            if window_size > FAILURE_LIMIT and not in_attack:
                in_attack = True
                attack_start = timestamps[start]  # record when attack started

            # Step 2d: Detect end of an attack
            # --------------------------------
            # The attack ends in two cases:
            # 1. We are at the very last timestamp
            # 2. The next timestamp would push the window beyond 1 hour
            if in_attack and (
                end == len(timestamps) - 1 or
                timestamps[end+1] - timestamps[start] > TIME_WINDOW
            ):
                attack_end = timestamps[end]        # last timestamp in attack
                attack_size = end - start + 1       # how many failures happened

                # Step 2e: Collect logon types used during the attack
                # ---------------------------------------------------
                # entries[start:end+1] → all events in this window
                # lt = logon_type (second element of each tuple)
                window_logon_types = set(lt for ts, lt in entries[start:end+1])

                # Step 2f: Build a human-readable alert message
                alerts.append(
                    f"[ALERT] Account '{account}' had {attack_size} failed logins "
                    f"between {attack_start} and {attack_end} "
                    f"(LogonTypes={sorted(window_logon_types)})"
                )

                # Step 2g: Reset attack state
                # ---------------------------
                in_attack = False
                attack_start = None

    # Return all alerts found across all accounts
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
