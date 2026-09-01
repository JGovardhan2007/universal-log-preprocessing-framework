import socket
import time
import argparse
import random
import os
import glob
import sys
from datetime import datetime, timezone

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5140

# Pre-compiled multi-vendor log templates for continuous synthetic generation
VENDORS = ["cisco_asa", "palo_alto", "fortinet", "checkpoint", "pfsense"]

SAMPLE_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_logs")


def generate_synthetic_log(vendor: str) -> str:
    now = datetime.utcnow()
    src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    dst_ip = f"198.51.{random.randint(1, 254)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 53, 3389, 8080, 8443, 445])
    proto = random.choice(["TCP", "UDP", "ICMP"])
    
    if vendor == "cisco_asa":
        action = random.choice(["Deny", "Built", "Teardown"])
        msg_id = random.choice([106023, 302013, 302014, 106001])
        return f"%ASA-4-{msg_id}: {action} {proto.lower()} src outside:{src_ip}/{src_port} dst inside:{dst_ip}/{dst_port} by access-group \"OUTSIDE-IN\" [0x0, 0x0]"

    elif vendor == "palo_alto":
        action = random.choice(["allow", "deny", "drop"])
        return f"1,{now.strftime('%Y/%m/%d %H:%M:%S')},001801000001,TRAFFIC,{action},1,{now.strftime('%Y/%m/%d %H:%M:%S')},{src_ip},{dst_ip},0.0.0.0,0.0.0.0,Rule-Policy,,,ssl,vsys1,untrust,trust,ethernet1/1,ethernet1/2,Log-Forwarder,{now.strftime('%Y/%m/%d %H:%M:%S')},12345,1,{src_port},{dst_port},0,0,0x0,{proto.lower()},{action},{random.randint(100, 5000)},{random.randint(100, 2500)},{random.randint(0, 2500)},1,{now.strftime('%Y/%m/%d %H:%M:%S')},0,any,0,0,0,0,,US,IN,0,1,0"

    elif vendor == "fortinet":
        action = random.choice(["accept", "deny", "close"])
        return f"date={now.strftime('%Y-%m-%d')} time={now.strftime('%H:%M:%S')} devname=\"FGT-HQ-01\" devid=\"FGT60D4614041234\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" level=\"notice\" vd=\"root\" srcip={src_ip} srcport={src_port} srcintf=\"port1\" dstip={dst_ip} dstport={dst_port} dstintf=\"port2\" proto={6 if proto == 'TCP' else 17} action=\"{action}\" policyid=1 service=\"HTTPS\" duration={random.randint(1, 120)} sentbyte={random.randint(60, 4000)} rcvdbyte={random.randint(60, 8000)}"

    elif vendor == "checkpoint":
        action = random.choice(["accept", "drop", "reject"])
        return f"time={int(now.timestamp())}|hostname=cp-fw01|product=VPN-1 & FireWall-1|action={action}|src={src_ip}|dst={dst_ip}|proto={proto.lower()}|s_port={src_port}|service={dst_port}|rule=12|reason=Policy match evaluation"

    elif vendor == "pfsense":
        act = random.choice(["pass", "block"])
        return f"{now.strftime('%b %d %H:%M:%S')} pfsense filterlog[28410]: 4,,,1000000103,igb0,match,{act},in,4,0x0,,64,0,0,DF,{6 if proto == 'TCP' else 17},{proto.lower()},60,{src_ip},{dst_ip},{src_port},{dst_port},0,S,12345678,,65535,,mss;sackOK;TS"

    return f"UNKNOWN_RAW_LOG timestamp={now.isoformat()} src={src_ip} dst={dst_ip} port={dst_port}"


def load_sample_logs(vendor: str = "all") -> list:
    logs = []
    if vendor == "all":
        pattern = os.path.join(SAMPLE_LOG_DIR, "*.log")
    else:
        pattern = os.path.join(SAMPLE_LOG_DIR, f"{vendor}.log")
    
    for filepath in glob.glob(pattern):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    logs.append(line)
    return logs


def send_logs(host: str, port: int, rate_eps: int, duration_sec: int, vendor: str, use_samples: bool):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"🚀 [Track 4] Starting UDP Log Streamer -> {host}:{port}")
    print(f"   Target Rate: {rate_eps} EPS | Duration: {duration_sec}s | Vendor Mode: {vendor}")
    
    sample_pool = load_sample_logs(vendor) if use_samples else []
    if use_samples and not sample_pool:
        print("⚠️ No static sample logs found; falling back to synthetic generator.")
        use_samples = False

    total_sent = 0
    total_bytes = 0
    start_time = time.time()
    next_report_time = start_time + 1.0
    current_sec_count = 0

    try:
        while True:
            elapsed = time.time() - start_time
            if duration_sec > 0 and elapsed >= duration_sec:
                break

            sec_start = time.time()
            batch_target = rate_eps
            for _ in range(batch_target):
                if use_samples:
                    raw_msg = random.choice(sample_pool)
                else:
                    v = random.choice(VENDORS) if vendor == "all" else vendor
                    raw_msg = generate_synthetic_log(v)

                data = raw_msg.encode("utf-8")
                sock.sendto(data, (host, port))
                total_sent += 1
                total_bytes += len(data)
                current_sec_count += 1

            sec_elapsed = time.time() - sec_start
            sleep_time = 1.0 - sec_elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

            now_time = time.time()
            if now_time >= next_report_time:
                real_eps = current_sec_count / (now_time - (next_report_time - 1.0))
                mb_sent = total_bytes / (1024 * 1024)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Sent: {total_sent:,} logs ({mb_sent:.2f} MB) | Current Rate: {real_eps:,.0f} EPS")
                current_sec_count = 0
                next_report_time = now_time + 1.0

    except KeyboardInterrupt:
        print("\n🛑 Stream stopped by user.")
    finally:
        total_time = max(0.001, time.time() - start_time)
        avg_eps = total_sent / total_time
        print(f"\n📊 Summary: {total_sent:,} total packets sent in {total_time:.2f}s (Avg: {avg_eps:,.0f} EPS)")
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ULPF UDP Multi-Vendor Log Streamer & Benchmark Tool")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help="Target UDP Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Target UDP Port (default: 5140)")
    parser.add_argument("--rate", type=int, default=500, help="Target Events Per Second (default: 500)")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds (0 for infinite, default: 10)")
    parser.add_argument("--vendor", type=str, default="all", choices=["all", "cisco_asa", "palo_alto", "fortinet", "checkpoint", "pfsense"], help="Target Vendor")
    parser.add_argument("--use-samples", action="store_true", help="Use static raw files from /sample_logs/")

    args = parser.parse_args()
    send_logs(args.host, args.port, args.rate, args.duration, args.vendor, args.use_samples)
