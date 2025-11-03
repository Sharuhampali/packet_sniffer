# # #!/usr/bin/env python3
# # """
# # sniffer_ai.py
# # Lightweight packet sniffer + AI classifier.

# # This version is modified to run as a Flask-SocketIO web dashboard.
# # """

# # import argparse
# # import base64
# # import json
# # import time
# # import threading
# # import uuid  # <-- NEW: for unique packet IDs
# # from collections import deque

# # import requests
# # from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw, ARP, DNS, DNSQR

# # # --- NEW: Flask and SocketIO imports ---
# # from flask import Flask, render_template
# # from flask_socketio import SocketIO

# # # ---------------------------
# # # Configuration & constants
# # # ---------------------------
# # MAX_PAYLOAD_BYTES = 256
# # AI_TIMEOUT = 8
# # AI_CONCURRENCY = 2

# # # --- NEW: Global web app and socketio instances ---
# # app = Flask(__name__)
# # app.config['SECRET_KEY'] = 'your-very-secret-key-change-this' # You should change this
# # socketio = SocketIO(app, async_mode='threading')

# # # ---------------------------
# # # Simple local rule-based classifier (fast)
# # # ---------------------------
# # def rule_classify(pkt):
# #     # (This function is unchanged from your original)
# #     if pkt.haslayer(ARP):
# #         return "ARP"
# #     if pkt.haslayer(ICMP):
# #         return "ICMP"
# #     if pkt.haslayer(TCP):
# #         sport = pkt[TCP].sport
# #         dport = pkt[TCP].dport
# #         if sport in (80, 8080) or dport in (80, 8080):
# #             return "HTTP (TCP port 80/8080)"
# #         if sport in (443,) or dport in (443,):
# #             return "TLS/HTTPS (TCP port 443)"
# #         if sport in (22,) or dport in (22,):
# #             return "SSH (TCP port 22)"
# #         return "TCP"
# #     if pkt.haslayer(UDP):
# #         sport = pkt[UDP].sport
# #         dport = pkt[UDP].dport
# #         if sport == 53 or dport == 53 or pkt.haslayer(DNS):
# #             return "DNS (UDP/53)"
# #         return "UDP"
# #     if pkt.haslayer(IP) or pkt.haslayer(IPv6):
# #         return "IP"
# #     return "Other"


# # # ---------------------------
# # # Build compact packet summary
# # # ---------------------------
# # def build_summary(pkt):
# #     summary = {}
# #     # --- NEW: Add a unique ID to track this packet in the UI ---
# #     summary["id"] = str(uuid.uuid4())
# #     summary["ts"] = time.time()

# #     # (The rest of this function is unchanged)
# #     if pkt.haslayer(IP):
# #         ip = pkt[IP]
# #         summary["src_ip"] = ip.src
# #         summary["dst_ip"] = ip.dst
# #         summary["version"] = 4
# #     elif pkt.haslayer(IPv6):
# #         ip6 = pkt[IPv6]
# #         summary["src_ip"] = ip6.src
# #         summary["dst_ip"] = ip6.dst
# #         summary["version"] = 6
# #     else:
# #         summary["src_ip"] = getattr(pkt, "src", None)
# #         summary["dst_ip"] = getattr(pkt, "dst", None)
# #         summary["version"] = None

# #     if pkt.haslayer(TCP):
# #         summary["proto"] = "TCP"
# #         summary["sport"] = pkt[TCP].sport
# #         summary["dport"] = pkt[TCP].dport
# #         summary["flags"] = str(pkt[TCP].flags)
# #     elif pkt.haslayer(UDP):
# #         summary["proto"] = "UDP"
# #         summary["sport"] = pkt[UDP].sport
# #         summary["dport"] = pkt[UDP].dport
# #     elif pkt.haslayer(ICMP):
# #         summary["proto"] = "ICMP"
# #     elif pkt.haslayer(ARP):
# #         summary["proto"] = "ARP"
# #     else:
# #         summary["proto"] = pkt.lastlayer().name if pkt.lastlayer() is not None else "Unknown"

# #     try:
# #         summary["len"] = len(pkt)
# #     except Exception:
# #         summary["len"] = None

# #     raw_bytes = b""
# #     if pkt.haslayer(Raw):
# #         raw_bytes = bytes(pkt[Raw].load)
# #     if raw_bytes:
# #         snippet = raw_bytes[:MAX_PAYLOAD_BYTES]
# #         summary["payload_b64"] = base64.b64encode(snippet).decode("ascii")
# #         printable = (
# #             "".join((chr(b) if 32 <= b <= 126 else ".") for b in snippet)
# #             .replace("\n", "\\n")
# #             .replace("\r", "\\r")
# #         )
# #         summary["payload_preview"] = printable
# #     else:
# #         summary["payload_b64"] = None
# #         summary["payload_preview"] = None

# #     summary["rule_class"] = rule_classify(pkt)
# #     return summary


# # # ---------------------------
# # # AI Sender worker (modified)
# # # ---------------------------
# # class AiSender:
# #     # --- MODIFIED: Added socketio param ---
# #     def __init__(self, ai_url=None, ai_key=None, timeout=AI_TIMEOUT, max_concurrent=AI_CONCURRENCY, socketio=None):
# #         self.ai_url = ai_url
# #         self.ai_key = ai_key
# #         self.timeout = timeout
# #         self.semaphore = threading.Semaphore(max_concurrent)
# #         self.session = requests.Session()
# #         self.socketio = socketio # <-- NEW: store socketio instance

# #     def is_configured(self):
# #         return bool(self.ai_url)

# #     def send_for_classification(self, summary):
# #         if not self.is_configured():
# #             return

# #         def worker(s):
# #             acquired = self.semaphore.acquire(timeout=1)
# #             if not acquired:
# #                 print("[AI] busy, skipping AI classification for this packet.")
# #                 return
# #             try:
# #                 payload = {
# #                     "packet_summary": s,
# #                     "instructions": (
# #                         "Classify the packet and provide a short human-readable analysis. "
# #                         "Return a JSON object containing at least 'classification' and 'explanation'. "
# #                         "Be concise (one or two sentences)."
# #                     ),
# #                 }
# #                 headers = {"Content-Type": "application/json"}
# #                 if self.ai_key:
# #                     headers["Authorization"] = f"Bearer {self.ai_key}"

# #                 resp = self.session.post(self.ai_url, json=payload, headers=headers, timeout=self.timeout)
# #                 try:
# #                     data = resp.json()
# #                 except Exception:
# #                     print(f"[AI] invalid JSON response (status {resp.status_code}). Raw: {resp.text[:200]}")
# #                     return

# #                 classification = data.get("classification") or data.get("label") or data.get("category")
# #                 explanation = data.get("explanation") or data.get("analysis") or data.get("message")
                
# #                 # --- NEW: Emit the AI result back to the dashboard ---
# #                 if (classification or explanation) and self.socketio:
# #                     ai_result = {
# #                         "id": s["id"], # <-- The unique ID
# #                         "classification": classification,
# #                         "explanation": explanation
# #                     }
# #                     self.socketio.emit('ai_result', ai_result)
# #                     print(f"[AI] Sent to dashboard: {classification}") # (for server logs)
# #                 else:
# #                     print(f"[AI] response JSON but no classification keys. Raw: {json.dumps(data)[:400]}")
# #             except requests.RequestException as e:
# #                 print(f"[AI] request failed: {e}")
# #             finally:
# #                 self.semaphore.release()

# #         t = threading.Thread(target=worker, args=(summary,),)
# #         t.start()


# # # ---------------------------
# # # Packet callback (modified)
# # # ---------------------------
# # # --- MODIFIED: Added socketio param, removed printing ---
# # def packet_callback(pkt, ai_sender=None, socketio=None):
# #     summary = build_summary(pkt)
    
# #     # --- NEW: Emit the packet summary to the dashboard ---
# #     if socketio:
# #         socketio.emit('new_packet', summary)

# #     # Hand off to AI sender if configured
# #     if ai_sender and ai_sender.is_configured():
# #         ai_sender.send_for_classification(summary)


# # # ---------------------------
# # # CLI and main (modified for Flask)
# # # ---------------------------

# # # --- NEW: Flask web routes ---
# # @app.route('/')
# # def index():
# #     """Serve the main dashboard HTML page."""
# #     return render_template('index.html')

# # @socketio.on('connect')
# # def handle_connect():
# #     print('[Server] Client connected')

# # # --- NEW: Function to run Scapy in a separate thread ---
# # def start_sniffer(iface, pkt_filter, count, ai_sender):
# #     """Target function for the sniffer thread."""
# #     print(f"Starting sniff on interface {iface} (count={count}, filter='{pkt_filter}')")
# #     try:
# #         # We pass the ai_sender and socketio instances to the callback
# #         sniff(
# #             iface=iface, 
# #             prn=lambda p: packet_callback(p, ai_sender=ai_sender, socketio=socketio), 
# #             store=False, 
# #             count=count, 
# #             filter=pkt_filter
# #         )
# #     except PermissionError:
# #         print("\n--- PERMISSION ERROR ---")
# #         print("Sniffing requires root privileges. Try running with 'sudo'.")
# #         print("Stopping server.")
# #         socketio.stop() # Stops the Flask server
# #     except Exception as e:
# #         print(f"\n--- SNIFFER ERROR ---")
# #         print(f"An error occurred: {e}")
# #         print("Stopping server.")
# #         socketio.stop() # Stops the Flask server

# # def main():
# #     parser = argparse.ArgumentParser(description="Packet sniffer + AI classification DASHBOARD.")
# #     parser.add_argument("--iface", "-i", default=None, help="Network interface to sniff (e.g., eth0, wlan0, lo). Required.")
# #     parser.add_argument("--ai-url", default=None, help="AI classification endpoint URL (POST JSON). Optional.")
# #     parser.add_argument("--ai-key", default=None, help="API key for AI endpoint (will be put in Authorization: Bearer). Optional.")
# #     parser.add_argument("--no-ai", action="store_true", help="Disable AI API calls (only local classification).")
# #     parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite).")
# #     parser.add_argument("--filter", "-f", default=None, help="BPF filter string (e.g., 'tcp and port 80'). Optional.")
# #     # --- NEW: Args for the web server ---
# #     parser.add_argument("--host", default="127.0.0.1", help="Host to run the web server on (default: 127.0.0.1).")
# #     parser.add_argument("--port", type=int, default=5001, help="Port to run the web server on (default: 5001).")
# #     args = parser.parse_args()

# #     if not args.iface:
# #         parser.error("Please specify --iface (e.g., lo or eth0).")

# #     # Create AI sender
# #     ai_sender = None
# #     if not args.no_ai and args.ai_url:
# #         # --- MODIFIED: Pass the socketio instance to the sender ---
# #         ai_sender = AiSender(ai_url=args.ai_url, ai_key=args.ai_key, socketio=socketio)
# #         print(f"[AI] configured to send packet summaries to: {args.ai_url}")
# #     else:
# #         print("[AI] AI disabled or not configured. Using local rule-based classification only.")

# #     # --- NEW: Start the sniffer in a background thread ---
# #     # We use daemon=True so the thread exits when the main app exits
# #     sniffer_thread = threading.Thread(
# #         target=start_sniffer, 
# #         args=(args.iface, args.filter, args.count, ai_sender),
# #         daemon=True
# #     )
# #     sniffer_thread.start()

# #     # --- NEW: Run the Flask web server (this blocks the main thread) ---
# #     print(f"\n--- Dashboard running at http://{args.host}:{args.port}/ ---")
# #     try:
# #         socketio.run(app, host=args.host, port=args.port, allow_unsafe_werkzeug=True)
# #     except Exception as e:
# #         print(f"Failed to start web server: {e}")

# # if __name__ == "__main__":
# #     main()
# import argparse
# import threading
# import time
# from flask import Flask, render_template
# from flask_socketio import SocketIO
# from scapy.all import sniff, IP
# import socket

# app = Flask(__name__)
# socketio = SocketIO(app, cors_allowed_origins="*")

# capturing = True
# local_ip = socket.gethostbyname(socket.gethostname())

# def get_packet_direction(src_ip, dst_ip):
#     """Determine if the packet is incoming or outgoing relative to host."""
#     if src_ip == local_ip:
#         return "Outgoing"
#     elif dst_ip == local_ip:
#         return "Incoming"
#     else:
#         return "Other"

# def packet_callback(pkt):
#     global capturing
#     if not capturing:
#         return

#     if IP in pkt:
#         src_ip = pkt[IP].src
#         dst_ip = pkt[IP].dst
#         proto = pkt[IP].proto
#         direction = get_packet_direction(src_ip, dst_ip)
#         pkt_data = {
#             "ts": time.time(),
#             "src_ip": src_ip,
#             "dst_ip": dst_ip,
#             "proto": proto,
#             "len": len(pkt),
#             "direction": direction,
#             "payload_preview": str(bytes(pkt)[:60])
#         }
#         socketio.emit('new_packet', pkt_data)

# @app.route('/')
# def index():
#     return render_template('dashboard.html')

# def start_sniff(iface, bpf_filter=None):
#     sniff(iface=iface, prn=packet_callback, store=False, filter=bpf_filter)

# @socketio.on('toggle_capture')
# def toggle_capture(data):
#     global capturing
#     capturing = data.get("capture", True)
#     socketio.emit('capture_status', {"capturing": capturing})
#     print(f"[INFO] Capture {'resumed' if capturing else 'paused'} by user.")

# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description="Packet Sniffer Dashboard (no AI).")
#     parser.add_argument('--iface', required=True, help="Network interface to sniff on (e.g., Wi-Fi, eth0, lo)")
#     parser.add_argument('--filter', default=None, help="Optional BPF filter (e.g., 'tcp or udp')")
#     parser.add_argument('--host', default='0.0.0.0')
#     parser.add_argument('--port', type=int, default=5000)
#     args = parser.parse_args()

#     print(f"[+] Starting sniffer on interface: {args.iface}")
#     threading.Thread(target=start_sniff, args=(args.iface, args.filter), daemon=True).start()
#     socketio.run(app, host=args.host, port=args.port)
import argparse
import threading
import time
from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import socket

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

capturing = True
local_ip = socket.gethostbyname(socket.gethostname())

def get_packet_direction(src_ip, dst_ip):
    if src_ip == local_ip:
        return "Outgoing"
    elif dst_ip == local_ip:
        return "Incoming"
    else:
        return "Other"

def get_proto_name(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    elif pkt.haslayer(ARP):
        return "ARP"
    elif IP in pkt:
        return f"IP (v{pkt[IP].version})"
    else:
        return "Other"

def packet_callback(pkt):
    global capturing
    if not capturing:
        return

    if IP in pkt or ARP in pkt:
        src_ip = pkt[IP].src if IP in pkt else pkt.psrc
        dst_ip = pkt[IP].dst if IP in pkt else pkt.pdst
        proto = get_proto_name(pkt)
        direction = get_packet_direction(src_ip, dst_ip)
        pkt_data = {
            "ts": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "len": len(pkt),
            "direction": direction,
            "payload_preview": str(bytes(pkt)[:80]),
        }
        socketio.emit("new_packet", pkt_data)

@app.route("/")
def index():
    return render_template("dashboard.html")

def start_sniff(iface, bpf_filter=None):
    sniff(iface=iface, prn=packet_callback, store=False, filter=bpf_filter)

@socketio.on("toggle_capture")
def toggle_capture(data):
    global capturing
    capturing = data.get("capture", True)
    socketio.emit("capture_status", {"capturing": capturing})
    print(f"[INFO] Capture {'resumed' if capturing else 'paused'} by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer Dashboard with Filters (no AI).")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on (e.g., Wi-Fi, eth0, lo)")
    parser.add_argument("--filter", default=None, help="Optional BPF filter (e.g., 'tcp or udp')")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()

    print(f"[+] Starting sniffer on interface: {args.iface}")
    threading.Thread(target=start_sniff, args=(args.iface, args.filter), daemon=True).start()
    socketio.run(app, host=args.host, port=args.port)
