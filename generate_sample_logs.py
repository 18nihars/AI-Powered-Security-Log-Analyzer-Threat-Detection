"""
generate_sample_logs.py
------------------------
Creates a synthetic authentication/server log file so you can try out the
analyzer without needing real production logs.

Log line format:
    <timestamp> ip=<ip> user=<username> event=<login|access> status=<success|failed> port=<port>

Run:
    python generate_sample_logs.py
Output:
    data/sample_auth.log
"""

import random
from datetime import datetime, timedelta

random.seed(42)

OUTPUT_PATH = "data/sample_auth.log"

NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin"]
NORMAL_IPS = ["10.0.0.{}".format(i) for i in range(2, 12)]
ATTACKER_IPS_BRUTE = ["185.220.101.{}".format(i) for i in (5, 6)]
ATTACKER_IPS_SCAN = ["45.155.204.{}".format(i) for i in (9,)]
CRED_STUFFING_IP = "91.240.118.7"

COMMON_PORTS = [22, 443, 3389]
SCAN_PORTS = list(range(20, 90))

lines = []
start = datetime(2026, 9, 20, 0, 0, 0)


def add_line(ts, ip, user, event, status, port):
    lines.append(
        f"{ts.strftime('%Y-%m-%d %H:%M:%S')} ip={ip} user={user} event={event} status={status} port={port}"
    )


# 1. Normal daytime traffic across 5 days
cur = start
for day in range(5):
    day_start = start + timedelta(days=day)
    for _ in range(250):
        hour = random.choices(
            population=list(range(24)),
            weights=[1, 1, 1, 1, 1, 1, 2, 4, 6, 8, 8, 8, 8, 8, 8, 8, 8, 7, 6, 4, 3, 2, 1, 1],
        )[0]
        ts = day_start + timedelta(hours=hour, minutes=random.randint(0, 59), seconds=random.randint(0, 59))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(NORMAL_USERS)
        status = "success" if random.random() > 0.05 else "failed"  # occasional mistyped password
        port = random.choice(COMMON_PORTS)
        add_line(ts, ip, user, "login", status, port)

# 2. Brute-force attack: two IPs hammering the 'admin' account with failed logins in a short burst
burst_start = start + timedelta(days=1, hours=3, minutes=10)
for ip in ATTACKER_IPS_BRUTE:
    for i in range(80):
        ts = burst_start + timedelta(seconds=i * 4)
        add_line(ts, ip, "admin", "login", "failed", 22)
    # one lucky success at the end (simulates a compromised weak password)
    add_line(burst_start + timedelta(seconds=80 * 4 + 5), ip, "admin", "login", "success", 22)

# 3. Credential stuffing: one IP trying many different usernames, mostly failing
stuff_start = start + timedelta(days=2, hours=2, minutes=0)
for i in range(60):
    ts = stuff_start + timedelta(seconds=i * 7)
    user = f"user{random.randint(1000,9999)}"
    status = "failed" if random.random() > 0.03 else "success"
    add_line(ts, CRED_STUFFING_IP, user, "login", status, 22)

# 4. Port scan: one IP probing many ports in rapid succession
scan_start = start + timedelta(days=3, hours=4, minutes=45)
ip = ATTACKER_IPS_SCAN[0]
for i, port in enumerate(random.sample(SCAN_PORTS, 50)):
    ts = scan_start + timedelta(milliseconds=i * 300)
    add_line(ts, ip, "-", "access", "failed", port)

# 5. Unusual-hour login: legit user logging in at 3 AM from their normal IP (borderline anomaly)
odd_ts = start + timedelta(days=4, hours=3, minutes=12)
add_line(odd_ts, random.choice(NORMAL_IPS), "carol", "login", "success", 443)

# Shuffle everything together like a real interleaved log file, then sort by time
random.shuffle(lines)
parsed = sorted(lines, key=lambda l: l.split(" ")[0] + " " + l.split(" ")[1])

with open(OUTPUT_PATH, "w") as f:
    f.write("\n".join(parsed) + "\n")

print(f"Wrote {len(parsed)} log lines to {OUTPUT_PATH}")
