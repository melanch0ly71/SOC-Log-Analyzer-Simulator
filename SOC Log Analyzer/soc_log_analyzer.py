import re
from datetime import datetime
import os
import warnings

# -----------------------------
# Suppress the specific deprecation warning
# -----------------------------
warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    message="Parsing dates involving a day of month without a year specified"
)

# -----------------------------
# Ensure alerts folder exists
# -----------------------------
os.makedirs("alerts", exist_ok=True)

# -----------------------------
# Parse a single log line
# -----------------------------
def parse_log_line(line):
    """
    Extract timestamp, status, username, and IP from auth logs.
    Supports:
        - Failed password
        - Accepted password
        - Invalid user
    """
    # Regex pattern for SSH auth logs
    pattern = (
        r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*'
        r'(Failed password|Accepted password) for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
    )
    match = re.search(pattern, line)

    if not match:
        return None

    # Determine status
    status_raw = match.group(2)
    status = "FAILED" if "Failed" in status_raw else "SUCCESS"

    # Parse timestamp and add current year
    timestamp_str = match.group("timestamp")
    timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
    timestamp = timestamp.replace(year=datetime.now().year)

    return {
        "status": status,
        "user": match.group("user"),
        "ip": match.group("ip"),
        "timestamp": timestamp
    }

# -----------------------------
# Analyze logs for brute force attacks
# -----------------------------
def analyze_logs(log_file):
    failed_attempts = {}
    alerts = []

    try:
        # Read logs line by line (safe for large files)
        with open(log_file, "r") as file:
            for line in file:
                event = parse_log_line(line)
                if not event:
                    continue

                # Print every parsed event
                print(f"[{event['timestamp']}] {event['status']} | User: {event['user']} | IP: {event['ip']}")

                # Track failed attempts per IP
                if event["status"] == "FAILED":
                    ip = event["ip"]
                    if ip not in failed_attempts:
                        failed_attempts[ip] = []
                    failed_attempts[ip].append(event["timestamp"])

        # -----------------------------
        # Detection logic
        # -----------------------------
        print("\n--- Detection Results ---\n")

        for ip, times in failed_attempts.items():
            if len(times) >= 3:  # Brute force threshold
                alert_msg = f"[ALERT] Possible brute force attack from {ip} ({len(times)} failed attempts)"
                print(alert_msg)
                alerts.append(f"{datetime.now()} {alert_msg}")  # Add timestamp for alert file

        # -----------------------------
        # Save alerts to file
        # -----------------------------
        if alerts:
            with open("alerts/alerts.txt", "a") as alert_file:
                for alert in alerts:
                    alert_file.write(alert + "\n")
            print("\nAlerts saved to alerts/alerts.txt")
        else:
            print("\nNo alerts detected.")

    except FileNotFoundError:
        print("Log file not found.")

# -----------------------------
# Main function
# -----------------------------
def main():
    log_path = "logs/sample_auth.log"
    analyze_logs(log_path)

if __name__ == "__main__":
    main()