import ipaddress
from collections import defaultdict
from netflow import NetflowReader

def read_netflow_file(file_path):
    """
    Reads a netflow v5, v7, or v9 file and yields records as dicts with at least 'src_ip' and 'timestamp'.
    Uses the 'netflow' library for parsing.
    """
    records = []
    with open(file_path, "rb") as f:
        reader = NetflowReader(f)
        for flow in reader:
            # Try to extract IPv4 or IPv6 source address and timestamp
            try:
                src_ip = flow.src_addr if hasattr(flow, "src_addr") else flow.src_ipv6
                # Convert to string for uniformity
                src_ip = str(src_ip)
                # Use flow.start or flow.first_switched as timestamp (seconds since epoch)
                if hasattr(flow, "first_switched"):
                    timestamp = int(flow.first_switched)
                elif hasattr(flow, "start"):
                    timestamp = int(flow.start)
                else:
                    continue  # skip if no timestamp
                records.append({"src_ip": src_ip, "timestamp": timestamp})
            except Exception:
                continue
    return records

def parse_ip_address(ip):
    """
    Validates and parses an IP address (IPv4 or IPv6).
    Returns the canonical string representation or raises ValueError.
    """
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise

def check_periodicity(packet_timestamps, interval):
    """
    Efficiently checks if there is at least one packet in every interval bucket.
    packet_timestamps: sorted list of UNIX timestamps (ints or floats).
    interval: interval in minutes.
    Returns True if every interval bucket has at least one packet, else False.
    """
    if not packet_timestamps:
        return False
    interval_seconds = interval * 60
    min_ts = min(packet_timestamps)
    max_ts = max(packet_timestamps)
    # Compute bucket indices for all timestamps
    buckets = set((ts - min_ts) // interval_seconds for ts in packet_timestamps)
    total_buckets = ((max_ts - min_ts) // interval_seconds) + 1
    # If every bucket has at least one packet, it's periodic
    return len(buckets) == total_buckets

def aggregate_beacon_traffic(records, interval):
    """
    Aggregates records by src_ip and interval buckets.
    Returns a dict: {src_ip: [timestamps]}
    """
    ip_buckets = defaultdict(list)
    for record in records:
        src_ip = parse_ip_address(record["src_ip"])
        ip_buckets[src_ip].append(record["timestamp"])
    return ip_buckets