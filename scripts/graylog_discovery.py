"""
Graylog API Discovery Script for ThreatBridge

Tests the Graylog Search API and discovers firewall log field names.
This is a throwaway discovery script — not for production use.

Usage:
    python graylog_discovery.py --url https://graylog.example.com --token YOUR_TOKEN
    python graylog_discovery.py --url https://graylog.example.com --user admin --password secret
"""

import argparse
import json
import sys
from datetime import datetime

import requests
import urllib3

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def make_session(args):
    """Create a requests session with auth configured."""
    session = requests.Session()
    session.verify = False  # Many Graylog installs use self-signed certs
    session.headers["Accept"] = "application/json"
    session.headers["X-Requested-By"] = "ThreatBridge-Discovery"

    if args.token:
        session.headers["Authorization"] = f"Bearer {args.token}"
    elif args.user and args.password:
        session.auth = (args.user, args.password)
    else:
        print("ERROR: Provide --token OR --user/--password")
        sys.exit(1)

    return session


def test_connectivity(session, base_url):
    """Test basic API connectivity and print server info."""
    print("=" * 60)
    print("1. CONNECTIVITY TEST")
    print("=" * 60)

    try:
        resp = session.get(f"{base_url}/api/system", timeout=10)
        if resp.status_code == 200:
            info = resp.json()
            print(f"  Status:    CONNECTED")
            print(f"  Version:   {info.get('version', 'unknown')}")
            print(f"  Cluster:   {info.get('cluster_id', 'unknown')}")
            print(f"  Node:      {info.get('hostname', 'unknown')}")
            return True
        elif resp.status_code == 401:
            print(f"  Status:    AUTH FAILED (401)")
            print(f"  Check your token or credentials.")
            return False
        else:
            print(f"  Status:    HTTP {resp.status_code}")
            print(f"  Body:      {resp.text[:200]}")
            return False
    except requests.ConnectionError as e:
        print(f"  Status:    CONNECTION FAILED")
        print(f"  Error:     {e}")
        return False
    except Exception as e:
        print(f"  Status:    ERROR")
        print(f"  Error:     {e}")
        return False


def list_streams(session, base_url):
    """List all available streams."""
    print()
    print("=" * 60)
    print("2. AVAILABLE STREAMS")
    print("=" * 60)

    try:
        resp = session.get(f"{base_url}/api/streams", timeout=10)
        if resp.status_code != 200:
            print(f"  Failed to list streams: HTTP {resp.status_code}")
            return []

        data = resp.json()
        streams = data.get("streams", [])
        print(f"  Found {len(streams)} streams:\n")

        for s in streams:
            disabled = " [DISABLED]" if s.get("disabled") else ""
            print(f"  - {s['title']}{disabled}")
            print(f"    ID: {s['id']}")
            print(f"    Description: {s.get('description', 'N/A')}")
            print()

        return streams
    except Exception as e:
        print(f"  Error: {e}")
        return []


def list_indices(session, base_url):
    """List index sets to understand data organization."""
    print()
    print("=" * 60)
    print("3. INDEX SETS")
    print("=" * 60)

    try:
        resp = session.get(f"{base_url}/api/system/indices/index_sets", timeout=10)
        if resp.status_code != 200:
            print(f"  Failed to list index sets: HTTP {resp.status_code}")
            return

        data = resp.json()
        for idx_set in data.get("index_sets", []):
            print(f"  - {idx_set.get('title', 'N/A')}")
            print(f"    Prefix: {idx_set.get('index_prefix', 'N/A')}")
            print(f"    Description: {idx_set.get('description', 'N/A')}")
            print()
    except Exception as e:
        print(f"  Error: {e}")


def search_ip(session, base_url, ip, stream_id=None, time_range=86400):
    """Search for an IP across all messages in the given time range."""
    print()
    print("=" * 60)
    print(f"4. SEARCH FOR IP: {ip} (last {time_range // 3600}h)")
    print("=" * 60)

    query = ip
    params = {
        "query": query,
        "range": time_range,
        "limit": 5,
        "sort": "timestamp:desc",
        "decorate": "true",
    }
    if stream_id:
        params["filter"] = f"streams:{stream_id}"

    try:
        resp = session.get(
            f"{base_url}/api/search/universal/relative",
            params=params,
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"  Search failed: HTTP {resp.status_code}")
            print(f"  Body: {resp.text[:500]}")
            return None

        data = resp.json()
        total = data.get("total_results", 0)
        messages = data.get("messages", [])

        print(f"  Total results: {total}")
        print(f"  Showing first {len(messages)} messages\n")

        if not messages:
            print("  No messages found. Try a different IP or wider time range.")
            return data

        # Display each message with all fields
        for i, msg_wrapper in enumerate(messages):
            msg = msg_wrapper.get("message", {})
            print(f"  --- Message {i + 1} ---")
            print(f"  Timestamp: {msg.get('timestamp', 'N/A')}")
            print(f"  Source:    {msg.get('source', 'N/A')}")

            # Print the raw message if available
            raw = msg.get("message", msg.get("full_message", ""))
            if raw:
                print(f"  Message:   {raw[:200]}")

            print()

        return data

    except Exception as e:
        print(f"  Error: {e}")
        return None


def extract_fields(session, base_url, ip, stream_id=None, time_range=86400):
    """Extract all unique field names from messages matching the IP."""
    print()
    print("=" * 60)
    print(f"5. FIELD DISCOVERY FOR: {ip}")
    print("=" * 60)

    query = ip
    params = {
        "query": query,
        "range": time_range,
        "limit": 20,
        "sort": "timestamp:desc",
        "decorate": "true",
    }
    if stream_id:
        params["filter"] = f"streams:{stream_id}"

    try:
        resp = session.get(
            f"{base_url}/api/search/universal/relative",
            params=params,
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"  Search failed: HTTP {resp.status_code}")
            return

        data = resp.json()
        messages = data.get("messages", [])

        if not messages:
            print("  No messages to analyze for fields.")
            return

        # Collect all unique fields and sample values
        field_samples = {}
        for msg_wrapper in messages:
            msg = msg_wrapper.get("message", {})
            for key, value in msg.items():
                if key.startswith("gl2_") or key.startswith("_"):
                    continue  # Skip Graylog internal fields
                if key not in field_samples:
                    field_samples[key] = []
                if value and str(value).strip() and len(field_samples[key]) < 3:
                    field_samples[key].append(str(value)[:100])

        # Sort and display
        print(f"  Found {len(field_samples)} unique fields across {len(messages)} messages:\n")

        # Categorize fields that look firewall-related
        fw_keywords = [
            "port", "nat", "rule", "action", "policy", "src", "dst",
            "source", "dest", "protocol", "proto", "firewall", "fw",
            "interface", "zone", "session", "bytes", "packets", "hit",
            "allow", "deny", "drop", "accept", "reject", "forward",
            "inbound", "outbound", "direction", "vlan", "translated",
        ]

        firewall_fields = {}
        other_fields = {}

        for field, samples in sorted(field_samples.items()):
            is_fw = any(kw in field.lower() for kw in fw_keywords)
            if is_fw:
                firewall_fields[field] = samples
            else:
                other_fields[field] = samples

        if firewall_fields:
            print("  ** LIKELY FIREWALL-RELATED FIELDS **")
            print("  " + "-" * 50)
            for field, samples in sorted(firewall_fields.items()):
                sample_str = " | ".join(samples[:3])
                print(f"  {field}")
                print(f"    Samples: {sample_str}")
                print()

        print("  ** OTHER FIELDS **")
        print("  " + "-" * 50)
        for field, samples in sorted(other_fields.items()):
            sample_str = " | ".join(samples[:3])
            print(f"  {field}")
            print(f"    Samples: {sample_str}")
            print()

    except Exception as e:
        print(f"  Error: {e}")


def dump_raw_message(session, base_url, ip, stream_id=None, time_range=86400):
    """Dump one complete raw message as JSON for inspection."""
    print()
    print("=" * 60)
    print(f"6. RAW MESSAGE DUMP (first match for {ip})")
    print("=" * 60)

    params = {
        "query": ip,
        "range": time_range,
        "limit": 1,
        "sort": "timestamp:desc",
        "decorate": "true",
    }
    if stream_id:
        params["filter"] = f"streams:{stream_id}"

    try:
        resp = session.get(
            f"{base_url}/api/search/universal/relative",
            params=params,
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"  Failed: HTTP {resp.status_code}")
            return

        data = resp.json()
        messages = data.get("messages", [])

        if not messages:
            print("  No messages found.")
            return

        msg = messages[0].get("message", {})
        # Pretty-print the full message, excluding internal fields
        filtered = {k: v for k, v in msg.items() if not k.startswith("gl2_")}
        print(json.dumps(filtered, indent=2, default=str))

    except Exception as e:
        print(f"  Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Graylog API Discovery for ThreatBridge"
    )
    parser.add_argument("--url", required=True, help="Graylog base URL (e.g., https://graylog.example.com)")
    parser.add_argument("--token", help="Graylog API token")
    parser.add_argument("--user", help="Graylog username (basic auth)")
    parser.add_argument("--password", help="Graylog password (basic auth)")
    parser.add_argument("--ip", default=None, help="IP address to search for (e.g., 195.184.76.167)")
    parser.add_argument("--stream", default=None, help="Stream ID to filter search (optional)")
    parser.add_argument("--hours", type=int, default=24, help="Time range in hours (default: 24)")

    args = parser.parse_args()

    # Normalize URL
    args.url = args.url.rstrip("/")

    print(f"ThreatBridge - Graylog API Discovery")
    print(f"Target: {args.url}")
    print(f"Time:   {datetime.now().isoformat()}")
    print()

    session = make_session(args)

    # Step 1: Test connectivity
    if not test_connectivity(session, args.url):
        print("\nCannot proceed without connectivity. Fix auth/URL and retry.")
        sys.exit(1)

    # Step 2: List streams
    list_streams(session, args.url)

    # Step 3: List index sets
    list_indices(session, args.url)

    # Steps 4-6: Search for IP if provided
    if args.ip:
        time_range = args.hours * 3600
        search_ip(session, args.url, args.ip, args.stream, time_range)
        extract_fields(session, args.url, args.ip, args.stream, time_range)
        dump_raw_message(session, args.url, args.ip, args.stream, time_range)
    else:
        print("\n  Skipping IP search (no --ip provided).")
        print("  Re-run with --ip 195.184.76.167 to discover firewall log fields.")

    print()
    print("=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    print("  1. Identify the stream that contains firewall logs")
    print("  2. Re-run with --stream <stream_id> --ip <known_ip>")
    print("  3. From the field list, identify mappings for:")
    print("     - Firewall rule name")
    print("     - External/source port")
    print("     - NAT/translated IP")
    print("     - Internal/destination port")
    print("     - Action (allow/deny/drop)")
    print("  4. Share the output with the design session")


if __name__ == "__main__":
    main()
