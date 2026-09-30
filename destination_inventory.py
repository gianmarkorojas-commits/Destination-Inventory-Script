#!/usr/bin/env python3
"""
destination_inventory.py - RoboLab CGI-112 Destination Inventory Parser

Reads a packet capture (.pcap) OR Zeek log files (conn.log, dns.log, ssl.log)
and produces a structured summary table showing:
  - Source Device IP
  - Destination IP
  - Resolved Hostname / DNS / SNI (if known)
  - Protocol & Destination Port
  - Total Packet Count
  - Total Bytes Transferred

Key Design Rules (per RoboLab CGI-112 Guidelines):
  1. Header-Aware Parsing: Dynamically parses Zeek `#fields` headers rather than
     hard-coding column indices.
  2. Pure Python standard library implementation: Requires no third-party network C-libraries.
  3. Keyed by Connection/Device logic.
"""

import sys
import os
import struct
import socket
import argparse
from collections import defaultdict
from typing import Dict, Tuple, Optional

# --- ZEEK LOG PARSER ---

def parse_zeek_log(filepath: str) -> Tuple[list, list]:
    """
    Parses a Zeek TSV log file by reading the `#fields` header line.
    Returns (field_names, data_rows).
    """
    fields = []
    rows = []
    if not os.path.exists(filepath):
        return fields, rows

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split('\t')[1:]
            elif not line.startswith("#"):
                parts = line.split('\t')
                rows.append(parts)
    return fields, rows


def process_zeek_logs(log_dir_or_file: str) -> list:
    """
    Processes Zeek logs (conn.log, and optionally dns.log / ssl.log) from a directory
    or single conn.log file.
    """
    if os.path.isdir(log_dir_or_file):
        conn_path = os.path.join(log_dir_or_file, "conn.log")
        dns_path = os.path.join(log_dir_or_file, "dns.log")
        ssl_path = os.path.join(log_dir_or_file, "ssl.log")
    else:
        conn_path = log_dir_or_file
        parent_dir = os.path.dirname(log_dir_or_file) or "."
        dns_path = os.path.join(parent_dir, "dns.log")
        ssl_path = os.path.join(parent_dir, "ssl.log")

    # 1. Build UID -> Hostname maps from dns.log and ssl.log
    uid_to_host = {}
    ip_to_host = {}

    # Parse dns.log if available
    dns_fields, dns_rows = parse_zeek_log(dns_path)
    if dns_fields:
        uid_idx = dns_fields.index("uid") if "uid" in dns_fields else -1
        query_idx = dns_fields.index("query") if "query" in dns_fields else -1
        resp_h_idx = dns_fields.index("id.resp_h") if "id.resp_h" in dns_fields else -1
        answers_idx = dns_fields.index("answers") if "answers" in dns_fields else -1

        for r in dns_rows:
            query = r[query_idx] if query_idx != -1 and query_idx < len(r) else "-"
            if query and query != "-":
                if uid_idx != -1 and uid_idx < len(r):
                    uid_to_host[r[uid_idx]] = query
                # Also associate query with answer IPs if present
                if answers_idx != -1 and answers_idx < len(r):
                    ans_list = r[answers_idx].split(',')
                    for ip in ans_list:
                        ip = ip.strip()
                        if ip and ip != "-":
                            ip_to_host[ip] = query

    # Parse ssl.log if available
    ssl_fields, ssl_rows = parse_zeek_log(ssl_path)
    if ssl_fields:
        uid_idx = ssl_fields.index("uid") if "uid" in ssl_fields else -1
        sni_idx = ssl_fields.index("server_name") if "server_name" in ssl_fields else -1
        resp_h_idx = ssl_fields.index("id.resp_h") if "id.resp_h" in ssl_fields else -1

        for r in ssl_rows:
            sni = r[sni_idx] if sni_idx != -1 and sni_idx < len(r) else "-"
            if sni and sni != "-":
                if uid_idx != -1 and uid_idx < len(r):
                    uid_to_host[r[uid_idx]] = sni
                if resp_h_idx != -1 and resp_h_idx < len(r):
                    ip_to_host[r[resp_h_idx]] = sni

    # 2. Parse conn.log
    conn_fields, conn_rows = parse_zeek_log(conn_path)
    if not conn_fields:
        print(f"[!] Warning: No #fields header found in {conn_path}", file=sys.stderr)
        return []

    # Map column names dynamically
    orig_h_idx = conn_fields.index("id.orig_h") if "id.orig_h" in conn_fields else -1
    resp_h_idx = conn_fields.index("id.resp_h") if "id.resp_h" in conn_fields else -1
    resp_p_idx = conn_fields.index("id.resp_p") if "id.resp_p" in conn_fields else -1
    proto_idx = conn_fields.index("proto") if "proto" in conn_fields else -1
    service_idx = conn_fields.index("service") if "service" in conn_fields else -1
    orig_pkts_idx = conn_fields.index("orig_pkts") if "orig_pkts" in conn_fields else -1
    resp_pkts_idx = conn_fields.index("resp_pkts") if "resp_pkts" in conn_fields else -1
    orig_bytes_idx = conn_fields.index("orig_bytes") if "orig_bytes" in conn_fields else -1
    resp_bytes_idx = conn_fields.index("resp_bytes") if "resp_bytes" in conn_fields else -1
    uid_idx = conn_fields.index("uid") if "uid" in conn_fields else -1

    aggregated = defaultdict(lambda: {"pkts": 0, "bytes": 0})

    for r in conn_rows:
        if orig_h_idx == -1 or resp_h_idx == -1 or orig_h_idx >= len(r) or resp_h_idx >= len(r):
            continue

        src_ip = r[orig_h_idx]
        dst_ip = r[resp_h_idx]
        dst_port = r[resp_p_idx] if resp_p_idx != -1 and resp_p_idx < len(r) else "-"
        proto = r[proto_idx] if proto_idx != -1 and proto_idx < len(r) else "tcp"
        service = r[service_idx] if service_idx != -1 and service_idx < len(r) else "-"
        uid = r[uid_idx] if uid_idx != -1 and uid_idx < len(r) else ""

        # Calculate Packets
        opkts = int(r[orig_pkts_idx]) if orig_pkts_idx != -1 and orig_pkts_idx < len(r) and r[orig_pkts_idx].isdigit() else 0
        rpkts = int(r[resp_pkts_idx]) if resp_pkts_idx != -1 and resp_pkts_idx < len(r) and r[resp_pkts_idx].isdigit() else 0
        total_pkts = opkts + rpkts
        if total_pkts == 0:
            total_pkts = 1  # count session if pkts missing

        # Calculate Bytes
        obytes = int(r[orig_bytes_idx]) if orig_bytes_idx != -1 and orig_bytes_idx < len(r) and r[orig_bytes_idx].isdigit() else 0
        rbytes = int(r[resp_bytes_idx]) if resp_bytes_idx != -1 and resp_bytes_idx < len(r) and r[resp_bytes_idx].isdigit() else 0
        total_bytes = obytes + rbytes

        # Determine Hostname
        hostname = uid_to_host.get(uid) or ip_to_host.get(dst_ip) or (service if service != "-" else "-")

        key = (src_ip, dst_ip, hostname, f"{proto.upper()}/{dst_port}")
        aggregated[key]["pkts"] += total_pkts
        aggregated[key]["bytes"] += total_bytes

    results = []
    for (src_ip, dst_ip, host, proto_port), stats in aggregated.items():
        results.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "hostname": host,
            "proto_port": proto_port,
            "pkts": stats["pkts"],
            "bytes": stats["bytes"]
        })

    return results


# --- NATIVE PCAP PARSER ---

def parse_pcap(pcap_path: str) -> list:
    """
    Parses a raw binary .pcap file in pure Python.
    Extracts IPv4/TCP/UDP packets and DNS queries to resolve hostnames.
    """
    aggregated = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    dns_map = {}

    with open(pcap_path, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            print("[!] Error: File too short to be a valid pcap.", file=sys.stderr)
            return []

        magic = global_header[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            endian = '<'  # Little-endian
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian = '>'  # Big-endian
        elif magic in (b'\n\r\r\n', b'\x0a\x0d\x0d\x0a'):
            print("[!] Note: pcapng format detected. Parsing records...", file=sys.stderr)
            # Basic pcapng parsing logic handled below or via fallback
            return parse_pcapng(pcap_path)
        else:
            print("[!] Unrecognized PCAP magic bytes. Trying fallback...", file=sys.stderr)
            return []

        link_type = struct.unpack(f"{endian}I", global_header[20:24])[0]

        # Process packet headers
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            # Ethernet header (14 bytes)
            if link_type == 1:  # LINKTYPE_ETHERNET
                if len(pkt_data) < 14:
                    continue
                eth_type = struct.unpack(">H", pkt_data[12:14])[0]
                ip_data = pkt_data[14:]
            else:
                ip_data = pkt_data  # Raw IP or bridge

            # Check IPv4 (0x0800)
            if eth_type == 0x0800 and len(ip_data) >= 20:
                ip_hdr = ip_data[:20]
                version_ihl = ip_hdr[0]
                ihl = (version_ihl & 0x0F) * 4
                total_len = struct.unpack(">H", ip_hdr[2:4])[0]
                protocol = ip_hdr[9]
                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                dst_ip = socket.inet_ntoa(ip_hdr[16:20])

                payload = ip_data[ihl:]
                dst_port = 0
                proto_str = "IP"

                if protocol == 6 and len(payload) >= 20:  # TCP
                    proto_str = "TCP"
                    dst_port = struct.unpack(">H", payload[2:4])[0]
                elif protocol == 17 and len(payload) >= 8:  # UDP
                    proto_str = "UDP"
                    dst_port = struct.unpack(">H", payload[2:4])[0]
                    # Check DNS (port 53)
                    src_port = struct.unpack(">H", payload[0:2])[0]
                    if src_port == 53 or dst_port == 53:
                        udp_data = payload[8:]
                        dns_qname = extract_dns_name(udp_data)
                        if dns_qname:
                            dns_map[dst_ip] = dns_qname
                            dns_map[src_ip] = dns_qname
                elif protocol == 1:  # ICMP
                    proto_str = "ICMP"

                proto_port_str = f"{proto_str}/{dst_port}" if dst_port else proto_str
                key = (src_ip, dst_ip, proto_port_str)
                aggregated[key]["pkts"] += 1
                aggregated[key]["bytes"] += orig_len

    results = []
    for (src_ip, dst_ip, proto_port), stats in aggregated.items():
        hostname = dns_map.get(dst_ip, dns_map.get(src_ip, "-"))
        results.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "hostname": hostname,
            "proto_port": proto_port,
            "pkts": stats["pkts"],
            "bytes": stats["bytes"]
        })

    return results


def parse_pcapng(pcapng_path: str) -> list:
    """Fallback pcapng parser for block-based captures."""
    aggregated = defaultdict(lambda: {"pkts": 0, "bytes": 0})
    dns_map = {}

    with open(pcapng_path, 'rb') as f:
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", hdr)
            if block_len < 12:
                break
            body = f.read(block_len - 8)

            # Enhanced Packet Block (0x00000006)
            if block_type == 0x00000006 and len(body) >= 20:
                cap_len, pkt_len = struct.unpack("<II", body[12:20])
                pkt_data = body[20:20 + cap_len]

                if len(pkt_data) >= 14:
                    eth_type = struct.unpack(">H", pkt_data[12:14])[0]
                    if eth_type == 0x0800 and len(pkt_data) >= 34:  # IPv4
                        ip_data = pkt_data[14:]
                        ihl = (ip_data[0] & 0x0F) * 4
                        protocol = ip_data[9]
                        src_ip = socket.inet_ntoa(ip_data[12:16])
                        dst_ip = socket.inet_ntoa(ip_data[16:20])
                        payload = ip_data[ihl:]

                        dst_port = 0
                        proto_str = "IP"
                        if protocol == 6 and len(payload) >= 4:
                            proto_str = "TCP"
                            dst_port = struct.unpack(">H", payload[2:4])[0]
                        elif protocol == 17 and len(payload) >= 4:
                            proto_str = "UDP"
                            dst_port = struct.unpack(">H", payload[2:4])[0]

                        proto_port_str = f"{proto_str}/{dst_port}" if dst_port else proto_str
                        key = (src_ip, dst_ip, proto_port_str)
                        aggregated[key]["pkts"] += 1
                        aggregated[key]["bytes"] += pkt_len

    results = []
    for (src_ip, dst_ip, proto_port), stats in aggregated.items():
        hostname = dns_map.get(dst_ip, "-")
        results.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "hostname": hostname,
            "proto_port": proto_port,
            "pkts": stats["pkts"],
            "bytes": stats["bytes"]
        })
    return results


def extract_dns_name(udp_data: bytes) -> Optional[str]:
    """Helper to extract QNAME from raw UDP DNS payload."""
    try:
        if len(udp_data) < 12:
            return None
        qdcount = struct.unpack(">H", udp_data[4:6])[0]
        if qdcount == 0:
            return None

        idx = 12
        labels = []
        while idx < len(udp_data):
            length = udp_data[idx]
            if length == 0:
                break
            if length >= 192:  # Compression pointer
                break
            idx += 1
            labels.append(udp_data[idx:idx + length].decode('ascii', errors='ignore'))
            idx += length

        if labels:
            return ".".join(labels)
    except Exception:
        pass
    return None


# --- FORMATTING & OUTPUT ---

def format_table(records: list) -> str:
    """Formats records into a clean, markdown-style destination inventory table."""
    if not records:
        return "No connection entries found."

    # Sort records by total bytes descending
    sorted_records = sorted(records, key=lambda x: x["bytes"], reverse=True)

    header = f"| {'Source Device':<15} | {'Destination IP':<15} | {'Resolved Hostname / DNS':<30} | {'Protocol/Port':<12} | {'Packets':<8} | {'Total Bytes':<12} |"
    divider = f"|{'-'*17}|{'-'*17}|{'-'*32}|{'-'*14}|{'-'*10}|{'-'*14}|"

    lines = [
        "### RoboLab CGI-112 Destination Inventory",
        f"Total unique flows/destinations identified: {len(sorted_records)}\n",
        header,
        divider
    ]

    for r in sorted_records:
        src = r["src_ip"]
        dst = r["dst_ip"]
        host = r["hostname"] if r["hostname"] and r["hostname"] != "-" else "Unknown / IP only"
        proto = r["proto_port"]
        pkts = f"{r['pkts']:,}"
        b = f"{r['bytes']:,} B"

        lines.append(f"| {src:<15} | {dst:<15} | {host:<30} | {proto:<12} | {pkts:>8} | {b:>12} |")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="RoboLab Destination Inventory Parser")
    parser.add_argument("input_path", help="Path to pcap file, conn.log, or directory containing Zeek logs")
    args = parser.parse_args()

    target = args.input_path

    if not os.path.exists(target):
        print(f"[!] Error: Path '{target}' does not exist.", file=sys.stderr)
        sys.exit(1)

    records = []

    # Check if target is Zeek log or directory
    if os.path.isdir(target) or target.endswith(".log") or "conn" in target:
        records = process_zeek_logs(target)
    elif target.endswith(".pcap") or target.endswith(".pcapng") or target.endswith(".cap"):
        records = parse_pcap(target)
    else:
        # Fallback: attempt Zeek log first, then pcap
        records = process_zeek_logs(target)
        if not records:
            records = parse_pcap(target)

    output = format_table(records)
    print(output)


if __name__ == "__main__":
    main()
