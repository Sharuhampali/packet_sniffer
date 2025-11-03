#!/usr/bin/env python3
"""
sniffer_ai.py
Lightweight packet sniffer + AI classifier.

Usage:
  sudo python3 sniffer_ai.py --iface eth0 --ai-url https://your-api.example/classify --ai-key AIzaSyASgk1OlPu8ASl1Bd0uguhMPa4o3sHp-_I
Or test on loopback:
  sudo python3 sniffer_ai.py --iface lo --no-ai

Note: sniffing requires root privileges on most systems.
"""

import argparse
import base64
import json
import time
import threading
from collections import deque

import requests
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR

# ---------------------------
# Configuration & constants
# ---------------------------
MAX_PAYLOAD_BYTES = 256  # how many payload bytes to include in the AI prompt
AI_TIMEOUT = 8  # seconds for the AI HTTP request
AI_CONCURRENCY = 2  # max outstanding AI requests


# ---------------------------
# Simple local rule-based classifier (fast)
# ---------------------------
def rule_classify(pkt):
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(TCP):
        # Simple heuristics for HTTP, TLS, SSH
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if sport in (80, 8080) or dport in (80, 8080):
            return "HTTP (TCP port 80/8080)"
        if sport in (443,) or dport in (443,):
            return "TLS/HTTPS (TCP port 443)"
        if sport in (22,) or dport in (22,):
            return "SSH (TCP port 22)"
        return "TCP"
    if pkt.haslayer(UDP):
        # DNS common port
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if sport == 53 or dport == 53 or pkt.haslayer(DNS):
            return "DNS (UDP/53)"
        return "UDP"
    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        return "IP"
    return "Other"


# ---------------------------
# Build compact packet summary
# ---------------------------
def build_summary(pkt):
    summary = {}
    # Timestamp
    summary["ts"] = time.time()

    # Layers / basic addresses
    if pkt.haslayer(IP):
        ip = pkt[IP]
        summary["src_ip"] = ip.src
        summary["dst_ip"] = ip.dst
        summary["version"] = 4
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        summary["src_ip"] = ip6.src
        summary["dst_ip"] = ip6.dst
        summary["version"] = 6
    else:
        # ARP or other
        summary["src_ip"] = getattr(pkt, "src", None)
        summary["dst_ip"] = getattr(pkt, "dst", None)
        summary["version"] = None

    # Transport
    if pkt.haslayer(TCP):
        summary["proto"] = "TCP"
        summary["sport"] = pkt[TCP].sport
        summary["dport"] = pkt[TCP].dport
        summary["flags"] = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        summary["proto"] = "UDP"
        summary["sport"] = pkt[UDP].sport
        summary["dport"] = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        summary["proto"] = "ICMP"
    elif pkt.haslayer(ARP):
        summary["proto"] = "ARP"
    else:
        summary["proto"] = pkt.lastlayer().name if pkt.lastlayer() is not None else "Unknown"

    # Length
    try:
        summary["len"] = len(pkt)
    except Exception:
        summary["len"] = None

    # Grab a short payload snippet if present, base64-encoded to keep transport safe
    raw_bytes = b""
    if pkt.haslayer(Raw):
        raw_bytes = bytes(pkt[Raw].load)
    if raw_bytes:
        snippet = raw_bytes[:MAX_PAYLOAD_BYTES]
        summary["payload_b64"] = base64.b64encode(snippet).decode("ascii")
        # also a printable-ASCII snippet for quick console review, replace nonprintable
        printable = (
            "".join((chr(b) if 32 <= b <= 126 else ".") for b in snippet)
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
        summary["payload_preview"] = printable
    else:
        summary["payload_b64"] = None
        summary["payload_preview"] = None

    # Add rule-based quick classification
    summary["rule_class"] = rule_classify(pkt)

    return summary


# ---------------------------
# AI Sender worker (limited concurrency)
# ---------------------------
class AiSender:
    def __init__(self, ai_url=None, ai_key=None, timeout=AI_TIMEOUT, max_concurrent=AI_CONCURRENCY):
        self.ai_url = ai_url
        self.ai_key = ai_key
        self.timeout = timeout
        self.semaphore = threading.Semaphore(max_concurrent)
        self.session = requests.Session()

    def is_configured(self):
        return bool(self.ai_url)

    def send_for_classification(self, summary):
        """Send summary to AI endpoint in a new thread (non-blocking).
        The AI endpoint is expected to accept JSON and return JSON with
        a 'classification' and/or 'analysis' field.
        """
        if not self.is_configured():
            return

        # Fire-and-forget but bounded concurrency
        def worker(s):
            acquired = self.semaphore.acquire(timeout=1)
            if not acquired:
                print("[AI] busy, skipping AI classification for this packet.")
                return
            try:
                payload = {
                    "packet_summary": s,
                    "instructions": (
                        "Classify the packet and provide a short human-readable analysis. "
                        "Return a JSON object containing at least 'classification' and 'explanation'. "
                        "Be concise (one or two sentences)."
                    ),
                }
                headers = {"Content-Type": "application/json"}
                if self.ai_key:
                    headers["Authorization"] = f"Bearer {self.ai_key}"

                resp = self.session.post(self.ai_url, json=payload, headers=headers, timeout=self.timeout)
                try:
                    data = resp.json()
                except Exception:
                    print(f"[AI] invalid JSON response (status {resp.status_code}). Raw: {resp.text[:200]}")
                    return

                # Print nicely if present
                classification = data.get("classification") or data.get("label") or data.get("category")
                explanation = data.get("explanation") or data.get("analysis") or data.get("message")
                if classification or explanation:
                    print(f"[AI] classification: {classification}")
                    if explanation:
                        print(f"[AI] explanation: {explanation}")
                else:
                    print(f"[AI] response JSON but no classification keys. Raw: {json.dumps(data)[:400]}")
            except requests.RequestException as e:
                print(f"[AI] request failed: {e}")
            finally:
                self.semaphore.release()

        t = threading.Thread(target=worker, args=(summary,),)
        t.start()


# ---------------------------
# Packet callback
# ---------------------------
def packet_callback(pkt, ai_sender=None, show_summary=True):
    summary = build_summary(pkt)
    # Print quick console line
    if show_summary:
        ts = time.strftime("%H:%M:%S", time.localtime(summary["ts"]))
        src = summary.get("src_ip") or "-"
        dst = summary.get("dst_ip") or "-"
        proto = summary.get("proto") or summary.get("rule_class")
        rclass = summary.get("rule_class")
        pay_preview = summary.get("payload_preview")
        if pay_preview:
            pay_preview = pay_preview[:60] + ("..." if len(pay_preview) > 60 else "")
        print(f"[{ts}] {src}:{summary.get('sport','-')} -> {dst}:{summary.get('dport','-')}\t{proto}\t(rule:{rclass})\tlen={summary.get('len')} payload='{pay_preview}'")

    # Immediately print the rule-based class (fast)
    print(f" -> Rule-based: {summary['rule_class']}")

    # Hand off to AI sender if configured
    if ai_sender and ai_sender.is_configured():
        ai_sender.send_for_classification(summary)


# ---------------------------
# CLI and main
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Packet sniffer + AI classification (educational use only).")
    parser.add_argument("--iface", "-i", default=None, help="Network interface to sniff (e.g., eth0, wlan0, lo). Required.")
    parser.add_argument("--ai-url", default=None, help="AI classification endpoint URL (POST JSON). Optional.")
    parser.add_argument("--ai-key", default=None, help="API key for AI endpoint (will be put in Authorization: Bearer). Optional.")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI API calls (only local classification).")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite).")
    parser.add_argument("--filter", "-f", default=None, help="BPF filter string (e.g., 'tcp and port 80'). Optional.")
    args = parser.parse_args()

    if not args.iface:
        parser.error("Please specify --iface (e.g., lo or eth0).")

    # Create AI sender
    ai_sender = None
    if not args.no_ai and args.ai_url:
        ai_sender = AiSender(ai_url=args.ai_url, ai_key=args.ai_key)
        print(f"[AI] configured to send packet summaries to: {args.ai_url}")
    else:
        print("[AI] AI disabled or not configured. Using local rule-based classification only.")

    print(f"Starting sniff on interface {args.iface} (count={args.count}, filter='{args.filter}')")
    try:
        sniff(iface=args.iface, prn=lambda p: packet_callback(p, ai_sender=ai_sender), store=False, count=args.count, filter=args.filter)
    except PermissionError:
        print("Permission error: try running with sudo/root.")
    except Exception as e:
        print(f"Sniffer error: {e}")


if __name__ == "__main__":
    main()
