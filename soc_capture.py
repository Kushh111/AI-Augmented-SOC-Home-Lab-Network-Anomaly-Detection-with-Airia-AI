"""
soc_capture.py
------------------------------------------------------------
Captures live network traffic on a chosen interface, flags any
source IP that crosses a packet-count threshold, builds a JSON
alert, and sends it to an Airia AI agent for SOC-style triage.

Setup:
    1. cp .env.example .env   and fill in your own values
    2. pip install -r requirements.txt
    3. sudo python3 soc_capture.py
       (tshark capture needs root / cap_net_raw on most distros)
------------------------------------------------------------
"""

import subprocess
import csv
import json
import os
import uuid
import requests
from collections import Counter
from dotenv import load_dotenv

load_dotenv()  # loads variables from a local .env file, if present

# ------------------------------------------------
# CONFIGURATION (env vars, with safe fallbacks)
# ------------------------------------------------

INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")          # check with: ip a
CAPTURE_DURATION = int(os.getenv("CAPTURE_DURATION", 100))  # seconds
THRESHOLD = int(os.getenv("PACKET_THRESHOLD", 40))          # packet threshold

PCAP_FILE = "traffic.pcap"
CSV_FILE = "traffic.csv"
ALERT_FILE = "alert.json"

# ---- Airia Agent Execution API ----
AIRIA_API_URL = os.getenv("AIRIA_API_URL")
AIRIA_API_KEY = os.getenv("AIRIA_API_KEY")

# ---- Metadata ----
DESTINATION_HOST = os.getenv("DESTINATION_HOST", "Internal-server")
DESTINATION_IP = os.getenv("DESTINATION_IP", "192.168.0.206")


# ------------------------------------------------
# HELPER
# ------------------------------------------------

def run_command(cmd, description):
    print(f"[+] {description}")
    subprocess.run(cmd, check=True)


# ------------------------------------------------
# STEP 1 - Capture Traffic
# ------------------------------------------------

def capture_traffic():
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    capture_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", f"icmp and dst host {DESTINATION_IP}",
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE
    ]

    run_command(capture_cmd, f"Capturing on {INTERFACE} for {CAPTURE_DURATION}s")

    if not os.path.exists(PCAP_FILE):
        raise RuntimeError("PCAP capture failed.")

    print(f"[+] Capture saved to {PCAP_FILE}")


# ------------------------------------------------
# STEP 2 - Convert to CSV
# ------------------------------------------------

def convert_to_csv():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    convert_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d"
    ]

    with open(CSV_FILE, "w", newline="") as outfile:
        subprocess.run(convert_cmd, stdout=outfile, check=True)

    print(f"[+] CSV created at {CSV_FILE}")


# ------------------------------------------------
# STEP 3 - Analyze Traffic
# ------------------------------------------------

def analyze_traffic():
    ip_counter = Counter()

    with open(CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            src_ip = (row.get("ip.src") or "").strip().strip('"')
            if src_ip:
                ip_counter[src_ip] += 1

    print("\n[+] Traffic volume per source IP:\n")
    for ip, count in ip_counter.items():
        print(f"{ip}: {count} packets")

    # Return first suspicious IP found
    for ip, count in ip_counter.items():
        if count > THRESHOLD:
            print(f"\n[!] Suspicious IP detected: {ip}")
            return ip, count

    print("\n[+] No suspicious activity detected.")
    return None, None


# ------------------------------------------------
# STEP 4 - Generate Alert JSON
# ------------------------------------------------

def generate_alert(ip, count):
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    alert = {
        "alert_id": alert_id,
        "alert_type": "Suspicious Network Volume",
        "indicator_type": "ip",
        "indicator_value": ip,
        "destination_host": DESTINATION_HOST,
        "destination_ip": DESTINATION_IP,
        "evidence": {
            "packet_count": count,
            "time_window_seconds": CAPTURE_DURATION,
            "data_source": os.path.basename(PCAP_FILE)
        },
        "analyst_question": "Is this expected activity or suspicious scanning/noise?"
    }

    with open(ALERT_FILE, "w") as f:
        json.dump(alert, f, indent=4)

    print(f"[+] Alert JSON written to {ALERT_FILE}")
    return alert


# ------------------------------------------------
# STEP 5 - Send to Airia API
# ------------------------------------------------

def send_to_airia(alert):
    if not AIRIA_API_URL or not AIRIA_API_KEY:
        raise RuntimeError(
            "AIRIA_API_URL / AIRIA_API_KEY are not set. "
            "Copy .env.example to .env and fill them in before running."
        )

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY": AIRIA_API_KEY
    }

    payload = {
        "userInput": json.dumps(alert),   # Convert alert dict into a JSON string
        "asyncOutput": False
    }

    print("[+] Sending alert to Airia Agent Execution API...")

    response = requests.post(
        AIRIA_API_URL,
        headers=headers,
        json=payload,
        timeout=100
    )

    response.raise_for_status()

    print(f"[+] Airia responded with status {response.status_code}")

    try:
        data = response.json()
        print("[+] Airia Response JSON:")
        print(json.dumps(data, indent=2))
    except Exception:
        print("[+] Airia response (raw text):")
        print(response.text)


# ------------------------------------------------
# MAIN
# ------------------------------------------------

def main():
    try:
        capture_traffic()
        convert_to_csv()
        ip, count = analyze_traffic()

        if ip:
            alert = generate_alert(ip, count)
            send_to_airia(alert)
        else:
            print("[+] No alert generated, nothing sent to Airia.")

        print("\n[+] Workflow complete.")

    except Exception as e:
        print(f"\n[!] Error: {e}")


if __name__ == "__main__":
    main()
