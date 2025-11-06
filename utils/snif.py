"""
snif_scapy.py - Real-time IDS packet sniffer (Light Version)
Compatible with Scapy-captured data and 10-feature ML model

Requirements:
    pip install scapy joblib pandas
Run as root/admin.
"""

import os
import time
import joblib
import pandas as pd
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP

# ----------------- Config -----------------
MODEL_PATH = "nids_scapy_model.pkl"
WINDOW_SECONDS = 120
MAX_FLOW_HISTORY = 1000

# Columns used by trained model
COLUMNS = [
    'duration','protocol_type','service','flag',
    'src_bytes','dst_bytes','count','srv_count',
    'same_srv_rate','diff_srv_rate'
]

# ----------------- Load Model -----------------
try:
    model = joblib.load(MODEL_PATH)
    print(f"✅ Loaded model: {MODEL_PATH}")
except Exception as e:
    raise SystemExit(f"❌ Failed to load model '{MODEL_PATH}': {e}")

# ----------------- Protocol and Service Maps -----------------
protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
PORT_SERVICE_MAP = {80: 'http', 443: 'https', 21: 'ftp', 25: 'smtp', 53: 'mDNS', 22: 'ssh'}
service_map = {'https': 3, 'ftp': 1, 'smtp': 2, 'mDNS': 3, 'ssh': 4, 'other': 5}
flag_map = {'SF': 0, 'S0': 1, 'REJ': 2, 'OTH': 3}

# ----------------- Helper Functions -----------------
def detect_service(pkt):
    if TCP in pkt:
        port = pkt[TCP].dport if pkt[TCP].dport in PORT_SERVICE_MAP else pkt[TCP].sport
    elif UDP in pkt:
        port = pkt[UDP].dport if pkt[UDP].dport in PORT_SERVICE_MAP else pkt[UDP].sport
    else:
        return 'other'
    return PORT_SERVICE_MAP.get(port, 'other')

def detect_flag(pkt):
    if TCP in pkt:
        fl = str(pkt[TCP].flags)
        for k in flag_map.keys():
            if k in fl:
                return k
        return 'OTH'
    return 'OTH'

# ----------------- State (for temporal features) -----------------
flows = defaultdict(lambda: {'pkts': deque(maxlen=MAX_FLOW_HISTORY)})
hosts = defaultdict(lambda: {'flows': deque()})

def trim_host_window(dst_ip):
    """Keep only recent host flows"""
    now = time.time()
    dq = hosts[dst_ip]['flows']
    while dq and (now - dq[0][0] > WINDOW_SECONDS):
        dq.popleft()

# ----------------- Feature Computation -----------------
def compute_features(pkt):
    feat = {c: 0 for c in COLUMNS}

    if IP not in pkt:
        return feat

    ip = pkt[IP]
    src, dst = ip.src, ip.dst
    proto = 'tcp' if TCP in pkt else 'udp' if UDP in pkt else 'icmp'
    service = detect_service(pkt)
    flag = detect_flag(pkt)
    sport = pkt.sport if hasattr(pkt, 'sport') else 0
    dport = pkt.dport if hasattr(pkt, 'dport') else 0

    flow_key = (src, dst, sport, dport, proto)
    host_key = dst

    f = flows[flow_key]
    now = time.time()
    f['pkts'].append(now)

    hosts[host_key]['flows'].append((now, service))
    trim_host_window(host_key)

    # --- Derived features ---
    feat['duration'] = (f['pkts'][-1] - f['pkts'][0]) if len(f['pkts']) > 1 else 0
    feat['protocol_type'] = protocol_map.get(proto, 2)
    feat['service'] = service_map.get(service, 5)
    feat['flag'] = flag_map.get(flag, 3)
    feat['src_bytes'] = len(pkt)
    feat['dst_bytes'] = len(pkt)
    feat['count'] = len(f['pkts'])
    feat['srv_count'] = len([1 for (_, s) in hosts[host_key]['flows'] if s == service])
    feat['same_srv_rate'] = feat['srv_count'] / len(hosts[host_key]['flows']) if hosts[host_key]['flows'] else 0
    feat['diff_srv_rate'] = 1 - feat['same_srv_rate']

    return feat

# ----------------- Packet Callback -----------------
def on_packet(pkt):
    features = compute_features(pkt)
    df = pd.DataFrame([features])[COLUMNS].astype(float)

    # after df = pd.DataFrame([features])[COLUMNS].astype(float)
    # DEBUG: print feature vector
    print("DEBUG features:", df.to_dict(orient='records')[0])

    # DEBUG: get probabilities (if supported)
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(df)[0]
            print("DEBUG proba:", probs)
        else:
            print("DEBUG: model has no predict_proba()")
    except Exception as e:
        print("DEBUG predict_proba error:", e)

    # original prediction
    try:
        pred = model.predict(df)[0]
    except Exception as e:
        print(f"[Prediction Error] {e}")
        return

    try:
        pred = model.predict(df)[0]
        label = "🚨 Malicious" if pred != 0 else "✅ Normal"
    except Exception as e:
        print(f"[Prediction Error] {e}")
        return

    ts = time.strftime("%H:%M:%S", time.localtime())
    print(f"[{ts}] {label} | proto={features['protocol_type']} "
          f"svc={features['service']} bytes={features['src_bytes']} count={features['count']}")
    print(pkt)

# ----------------- Main -----------------
if __name__ == "__main__":
    print("🕵️ Starting real-time sniffing (Scapy IDS)... Press Ctrl+C to stop.")
    sniff(filter="ip", prn=on_packet, store=False)



