import streamlit as st
import random
import math
import time
import uuid
from datetime import datetime, timedelta
from statistics import mean, pstdev

# ---------------- Page ----------------
st.set_page_config(page_title="Agentic Cyber AI — Simulation", layout="wide")
st.title("🛡️ Agentic Cyber AI — Simulation (Demo Only)")
st.markdown(
    "Continuous monitoring · adaptive defenses · privacy-aware · federated coordination\n\n"
    "**Note:** This is a *simulation/demo*. Do not use it as-is for real enforcement. "
    "Integrate with hardened infrastructure, legal review, and production telemetry for real deployments."
)

# ---------------- Utilities ----------------
def anon_ip(ip):
    # privacy-preserving IP anonymization (mask last octet)
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["0"])
    return ip

def now_ts():
    return datetime.utcnow().isoformat() + "Z"

def gen_src_ip(prefix=None):
    if prefix:
        base = prefix.split(".")[:3]
        return ".".join(base + [str(random.randint(2, 250))])
    return f"192.0.{random.randint(0,255)}.{random.randint(2,250)}"

# ---------------- Simulated streaming traffic generator (incremental) ----------------
def gen_traffic_batch(batch_size=40, inject=None, time_base=None):
    """Return a list of event dicts."""
    if time_base is None:
        time_base = datetime.utcnow()
    events = []
    for i in range(batch_size):
        ts = time_base - timedelta(seconds=i * random.randint(1, 3))
        src = gen_src_ip()
        dst = random.choice(["10.0.0.5","10.0.1.10","10.0.99.10","10.0.2.20","10.0.3.30"])
        proto = random.choices(["HTTPS","HTTP","SSH","FTP","DNS","SMTP","TCP"], weights=[35,25,10,4,15,5,6])[0]
        size = max(10, int(random.gauss(120, 40)))
        dur = max(1, int(random.gauss(60, 25)))
        fail = 0
        tx = 0.0
        ua = random.choice(["Mozilla/5.0","curl/7.68","botnet-client","mobile-app","tor-client","dark-window","nmap","ssh-scanner"])
        label = "normal"
        events.append({
            "ts": ts,
            "src": src,
            "dst": dst,
            "proto": proto,
            "size": size,
            "dur": dur,
            "fail_logins": fail,
            "tx_amt": tx,
            "user_agent": ua,
            "label": label
        })

    # Inject scenarios (lightweight, incremental)
    if inject == "ddos":
        ip = f"203.0.113.{random.randint(2,250)}"
        for _ in range(30):
            events.append({"ts": time_base, "src": ip, "dst": "10.0.0.5", "proto": "HTTP", "size":1500, "dur":1, "fail_logins":0, "tx_amt":0.0, "user_agent":"botnet-client", "label":"ddos"})
    if inject == "bruteforce":
        ip = f"198.51.100.{random.randint(2,250)}"
        for _ in range(20):
            events.append({"ts": time_base, "src": ip, "dst": "10.0.1.10", "proto":"SSH", "size":60, "dur":10, "fail_logins":1, "tx_amt":0.0, "user_agent":"ssh-scanner", "label":"bruteforce"})
    if inject == "bank_robbery":
        ip = f"203.0.113.{random.randint(2,250)}"
        for _ in range(6):
            events.append({"ts": time_base, "src": ip, "dst":"10.0.99.10", "proto":"HTTPS", "size":500, "dur":120, "fail_logins":2, "tx_amt":100000.0, "user_agent":"mobile-app", "label":"bank_robbery_attempt"})
    if inject == "c2_beacon":
        ip = f"198.51.100.{random.randint(2,250)}"
        for t in range(12):
            events.append({"ts": time_base - timedelta(seconds=t*60), "src": ip, "dst":"10.0.3.30", "proto":"DNS", "size":80, "dur":5, "fail_logins":0, "tx_amt":0.0, "user_agent":"botnet-client", "label":"c2_beacon"})
    if inject == "port_scan":
        ip = f"203.0.113.{random.randint(2,250)}"
        for p in range(40):
            events.append({"ts": time_base, "src": ip, "dst": f"10.0.{p%10}.{random.randint(2,250)}", "proto":"TCP", "size":40, "dur":2, "fail_logins":0, "tx_amt":0.0, "user_agent":"nmap", "label":"port_scan"})
    if inject == "dark_window":
        ip = f"45.77.{random.randint(0,255)}.{random.randint(2,250)}"
        for _ in range(10):
            events.append({"ts": time_base, "src": ip, "dst":"10.0.2.20", "proto":"HTTPS", "size":300, "dur":50, "fail_logins":0, "tx_amt":0.0, "user_agent":"dark-window", "label":"dark_window"})
    return events

# ---------------- Aggregation ----------------
def aggregate_events(all_events):
    """Return dict keyed by src IP with aggregated metrics."""
    agg = {}
    for e in all_events:
        ip = e["src"]
        if ip not in agg:
            agg[ip] = {
                "src": ip,
                "count": 0,
                "sizes": [],
                "durs": [],
                "fail_logins": 0,
                "total_tx": 0.0,
                "uas": set(),
                "labels": set(),
                "last_seen": e["ts"]
            }
        a = agg[ip]
        a["count"] += 1
        a["sizes"].append(e["size"])
        a["durs"].append(e["dur"])
        a["fail_logins"] += e.get("fail_logins", 0)
        a["total_tx"] += e.get("tx_amt", 0.0)
        a["uas"].add(e.get("user_agent",""))
        if isinstance(e["ts"], datetime) and e["ts"] > a["last_seen"]:
            a["last_seen"] = e["ts"]
        a["labels"].add(e.get("label",""))
    # finalize
    out = []
    for ip, a in agg.items():
        out.append({
            "src": ip,
            "count": a["count"],
            "avg_size": (mean(a["sizes"]) if a["sizes"] else 0),
            "avg_dur": (mean(a["durs"]) if a["durs"] else 0),
            "fail_logins": a["fail_logins"],
            "total_tx": a["total_tx"],
            "ua_types": " ".join(sorted(a["uas"])),
            "labels": " ".join(sorted(a["labels"])),
            "last_seen": a["last_seen"]
        })
    return out

# ---------------- Simple anomaly scoring (no external libs) ----------------
def compute_anomaly_scores(agg_list):
    # use count and avg_size to compute z-scores; robust to small N
    counts = [a["count"] for a in agg_list] or [0]
    sizes = [a["avg_size"] for a in agg_list] or [0]
    try:
        c_mean, c_std = mean(counts), pstdev(counts) if len(counts) > 1 else 0
    except:
        c_mean, c_std = mean(counts), 0
    try:
        s_mean, s_std = mean(sizes), pstdev(sizes) if len(sizes) > 1 else 0
    except:
        s_mean, s_std = mean(sizes), 0

    scores = {}
    for a in agg_list:
        zc = (a["count"] - c_mean) / (c_std if c_std > 0 else max(1.0, c_mean))
        zs = (a["avg_size"] - s_mean) / (s_std if s_std > 0 else max(1.0, s_mean))
        # combine with weights
        score = 0.6 * zc + 0.4 * zs
        scores[a["src"]] = score
    return scores

# ---------------- Threat classification ----------------
def detect_beacon_pattern(a):
    u = a["ua_types"]
    lbls = a["labels"]
    if "c2_beacon" in lbls or ("botnet-client" in u and a["count"] >= 10 and a["avg_size"] < 120):
        return True
    return False

def classify(a, iso_score):
    # returns (threat_label, severity 0-5)
    if "bank_robbery_attempt" in a["labels"] or a["total_tx"] > 50000:
        return ("Financial Fraud / Bank Robbery Attempt", 5)
    if "dark_window" in a["ua_types"] or "dark-window" in a["ua_types"] or "tor" in a["ua_types"]:
        return ("Dark-Web / Tor Access (suspicious)", 4)
    if "ddos" in a["labels"] or (a["count"] > 60 and a["avg_size"] > 700):
        return ("DDoS / Flooding", 5)
    if "bruteforce" in a["labels"] or a["fail_logins"] >= 8:
        return ("Brute-Force Login Attempts", 4)
    if "port_scan" in a["labels"] or (a["count"] > 100 and a["avg_size"] < 100):
        return ("Port Scanning / Reconnaissance", 3)
    if "c2_beacon" in a["labels"] or detect_beacon_pattern(a):
        return ("C2 Beaconing / Malware Callback", 5)
    if a["total_tx"] > 10000 or (a["avg_size"] > 800 and a["count"] < 20):
        return ("Data Exfiltration / Large Transfer", 5)
    if "nmap" in a["ua_types"] or "scanner" in a["ua_types"]:
        return ("Recon / Scanning Tool", 3)
    if iso_score < -0.8:
        return ("Anomalous Traffic (unknown)", 3)
    return ("Normal", 0)

# ---------------- Simulated Global Threat Intel Ingestion ----------------
def ingest_global_intel():
    # simulate receiving a threat feed: list of indicators (anonymized)
    feeds = [
        {"id": "INTEL-001", "type":"bad_ua", "value":"botnet-client", "confidence":0.9, "source":"GlobalFeedA"},
        {"id": "INTEL-002", "type":"malicious_ip_prefix", "value":"198.51.100.0/24", "confidence":0.8, "source":"CommunityX"},
        {"id": "INTEL-003", "type":"scanner_ua", "value":"nmap", "confidence":0.75, "source":"VendorY"},
        {"id": "INTEL-004", "type":"tor_marker", "value":"tor-client", "confidence":0.7, "source":"TorWatch"}
    ]
    # provide rotating feed by random sampling to simulate updates
    return random.sample(feeds, k=random.randint(1, len(feeds)))

# ---------------- Federated coordination simulation ----------------
def federated_coordination(action, ip, severity):
    # produce a simulated coordination message you'd send to partners
    msg = {
        "coord_id": str(uuid.uuid4()),
        "time": now_ts(),
        "action": action,
        "ip": ip,
        "severity": severity,
        "note": "Simulated message — would use secure channel (e.g. MISP, STIX/TAXII) in production"
    }
    return msg

# ---------------- Auto-defense (simulated, privacy-preserving) ----------------
def auto_defense(threat_type, ip, severity, intel_matches=None):
    # decide action tiers
    if severity >= 5:
        action = f"Isolate host + block {anon_ip(ip)} (sim)"
    elif severity == 4:
        action = f"Rate-limit + block {anon_ip(ip)} (sim)"
    elif severity == 3:
        action = f"Flag for investigation + monitor {anon_ip(ip)}"
    else:
        action = f"No action; log and monitor {anon_ip(ip)}"
    decision = {
        "time": now_ts(),
        "ip": ip,
        "anon_ip": anon_ip(ip),
        "threat": threat_type,
        "severity": severity,
        "action": action,
        "intel_matches": intel_matches or []
    }
    return decision

# ---------------- Session state init ----------------
if "running" not in st.session_state:
    st.session_state.running = False
if "events" not in st.session_state:
    st.session_state.events = []  # raw events
if "blocked" not in st.session_state:
    st.session_state.blocked = set()
if "actions" not in st.session_state:
    st.session_state.actions = []
if "coord_msgs" not in st.session_state:
    st.session_state.coord_msgs = []
if "intel_cache" not in st.session_state:
    st.session_state.intel_cache = []

# ---------------- Controls ----------------
col1, col2, col3 = st.columns([2,2,2])
with col1:
    scenario = st.selectbox("Simulate scenario", ["none","ddos","bruteforce","bank_robbery","dark_window","c2_beacon","port_scan"])
with col2:
    run_toggle = st.radio("Agent State", ["Paused", "Running"], index=0)
with col3:
    cycle_delay = st.slider("Cycle Delay (s)", 1, 5, 2)

if run_toggle == "Running":
    st.session_state.running = True
else:
    st.session_state.running = False

if st.button("Reset Simulation"):
    st.session_state.events = []
    # blocked is a set
    st.session_state.blocked.clear()
    st.session_state.actions.clear()
    st.session_state.coord_msgs.clear()
    st.session_state.intel_cache.clear()
    st.success("Simulation reset.")

# ---------------- Main agent loop (runs only while user keeps 'Running') ----------------
placeholder = st.empty()
monitor_cols = st.columns([3,2,2])

# single run / tick function
def agent_cycle():
    # ingest a simulated global feed occasionally
    if random.random() < 0.6:
        new_intel = ingest_global_intel()
        st.session_state.intel_cache.extend(new_intel)
        # keep small cache
        st.session_state.intel_cache = st.session_state.intel_cache[-20:]

    # generate incremental traffic
    batch = gen_traffic_batch(batch_size=random.randint(30,60), inject=(scenario if scenario!="none" else None))
    st.session_state.events = (st.session_state.events + batch)[-5000:]  # rolling window

    # aggregate
    agg_list = aggregate_events(st.session_state.events)
    # anomaly scoring
    scores = compute_anomaly_scores(agg_list)
    # classify & decide
    threats = []
    for a in agg_list:
        iso_score = scores.get(a["src"], 0.0)
        threat_label, severity = classify(a, iso_score)
        if threat_label != "Normal":
            # check intel matches
            intel_matches = []
            for intel in st.session_state.intel_cache:
                if intel["type"] == "bad_ua" and intel["value"] in a["ua_types"]:
                    intel_matches.append(intel["id"])
                if intel["type"] == "malicious_ip_prefix" and a["src"].startswith(intel["value"].split("/")[0].rsplit(".",1)[0]):
                    intel_matches.append(intel["id"])
            threats.append((a, iso_score, threat_label, severity, intel_matches))

    # actions (auto-defend high severity)
    for a, iso_score, threat_label, severity, intel_matches in threats:
        ip = a["src"]
        # privacy: store full IP in actions only for audit, show anonymized in UI
        if severity >= 4 and ip not in st.session_state.blocked:
            st.session_state.blocked.add(ip)
            decision = auto_defense(threat_label, ip, severity, intel_matches)
            st.session_state.actions.append(decision)
            # federated coordination simulated
            coord = federated_coordination(decision["action"], decision["anon_ip"], severity)
            st.session_state.coord_msgs.append(coord)
        elif severity >= 3:
            # log monitor actions
            decision = auto_defense(threat_label, ip, severity, intel_matches)
            st.session_state.actions.append(decision)

    # prepare display slices
    top_threats = sorted(threats, key=lambda t: (t[3], -t[1]), reverse=True)[:20]  # severity then score
    # build display row list (anonymized)
    display_rows = []
    for a, iso_score, threat_label, severity, intel_matches in top_threats:
        display_rows.append({
            "Anon Src": anon_ip(a["src"]),
            "Count": a["count"],
            "Avg Size": f"{a['avg_size']:.1f}",
            "Fails": a["fail_logins"],
            "Total Tx": f"{a['total_tx']:.2f}",
            "Last Seen": a["last_seen"].isoformat() if isinstance(a["last_seen"], datetime) else str(a["last_seen"]),
            "UA Types": a["ua_types"],
            "Threat": threat_label,
            "Severity": severity,
            "Anom Score": f"{iso_score:.3f}",
            "Intel": ", ".join(intel_matches) if intel_matches else ""
        })

    # return values for UI
    return {
        "num_srcs": len(agg_list),
        "num_threats": len(display_rows),
        "high_sev": sum(1 for d in display_rows if d["Severity"] >= 4),
        "blocked_count": len(st.session_state.blocked),
        "display_rows": display_rows,
        "recent_events": st.session_state.events[-40:],
        "actions": st.session_state.actions[-20:],
        "coord_msgs": st.session_state.coord_msgs[-10:],
        "intel_cache": st.session_state.intel_cache[-10:]
    }

# run a single tick when running
if st.session_state.running:
    with placeholder.container():
        st.markdown("### Agent Running — live simulation")
        # run for one cycle and update; user remains in control via UI (no background threads)
        res = agent_cycle()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Source IPs", res["num_srcs"])
        c2.metric("Threat IPs (detected)", res["num_threats"])
        c3.metric("High-Severity", res["high_sev"])
        c4.metric("Blocked (sim)", res["blocked_count"])

        st.markdown("#### Top Detected Threats (anonymized)")
        if res["display_rows"]:
            st.table(res["display_rows"])
        else:
            st.info("No threats detected this cycle.")

        st.markdown("#### Recent Defense Actions (simulated, audit log)")
        if res["actions"]:
            st.table([{"time": a["time"], "anon_ip": a["anon_ip"], "threat": a["threat"], "action": a["action"]} for a in res["actions"]])
        else:
            st.info("No actions taken yet.")

        st.markdown("#### Federated Coordination Messages (simulated)")
        if res["coord_msgs"]:
            st.table(res["coord_msgs"])
        else:
            st.info("No coordination messages sent.")

        st.markdown("#### Ingested Threat Intel (recent)")
        if res["intel_cache"]:
            st.table(res["intel_cache"])
        else:
            st.info("No intel in cache yet.")

        st.markdown("#### Example Recent Raw Events (anonymized)")
        # anonymize displayed events
        recent = []
        for e in res["recent_events"]:
            recent.append({
                "ts": e["ts"].isoformat() if isinstance(e["ts"], datetime) else str(e["ts"]),
                "src": anon_ip(e["src"]),
                "dst": e["dst"],
                "proto": e["proto"],
                "size": e["size"],
                "ua": e["user_agent"],
                "label": e["label"]
            })
        st.table(recent[::-1])

        # pause for user-selected delay to simulate streaming cycle
        time.sleep(cycle_delay)
        # perform one rerun cycle automatically so long as the UI is left running
        # Use compatibility: prefer st.rerun() (stable) and fall back to experimental one if present.
        try:
            st.rerun()
        except AttributeError:
            # older Streamlit versions
            try:
                st.experimental_rerun()
            except Exception:
                # if rerun isn't available for some reason, continue without crashing
                pass

else:
    # show paused state + recent state
    st.markdown("### Agent Paused — Snapshot")
    agg_list = aggregate_events(st.session_state.events)
    scores = compute_anomaly_scores(agg_list)
    threats = []
    for a in agg_list:
        iso_score = scores.get(a["src"], 0.0)
        threat_label, severity = classify(a, iso_score)
        if threat_label != "Normal":
            threats.append((a, iso_score, threat_label, severity))
    st.write(f"Total tracked events: {len(st.session_state.events)} (rolling window)")
    st.write(f"Unique source IPs: {len(agg_list)}")
    st.write(f"Cached intel items: {len(st.session_state.intel_cache)}")
    if threats:
        st.markdown("#### Detected threats (snapshot, anonymized)")
        rows = []
        for a, iso_score, threat_label, severity in sorted(threats, key=lambda t: (-t[3], t[1]))[:20]:
            rows.append({
                "Anon Src": anon_ip(a["src"]),
                "Count": a["count"],
                "Avg Size": f"{a['avg_size']:.1f}",
                "Threat": threat_label,
                "Severity": severity,
                "Anom Score": f"{iso_score:.3f}"
            })
        st.table(rows)
    else:
        st.info("No active threats in snapshot.")

# ---------------- Sidebar / Manual Controls ----------------
st.sidebar.header("Manual Controls & Governance")
ip_manual = st.sidebar.text_input("Manual Block IP (full IP)")
if st.sidebar.button("Block IP manually"):
    if ip_manual:
        st.session_state.blocked.add(ip_manual)
        decision = {
            "time": now_ts(),
            "ip": ip_manual,
            "anon_ip": anon_ip(ip_manual),
            "threat": "Manual Block",
            "severity": 5,
            "action": f"Manually blocked {anon_ip(ip_manual)}"
        }
        st.session_state.actions.append(decision)
        st.sidebar.success(f"Blocked {anon_ip(ip_manual)} (sim)")

ip_un = st.sidebar.text_input("Manual Unblock IP (full IP)", key="unblock")
if st.sidebar.button("Unblock IP"):
    if ip_un and ip_un in st.session_state.blocked:
        st.session_state.blocked.remove(ip_un)
        decision = {
            "time": now_ts(),
            "ip": ip_un,
            "anon_ip": anon_ip(ip_un),
            "threat": "Manual Unblock",
            "severity": 0,
            "action": f"Manually unblocked {anon_ip(ip_un)}"
        }
        st.session_state.actions.append(decision)
        st.sidebar.success(f"Unblocked {anon_ip(ip_un)} (sim)")

st.sidebar.markdown("---")
st.sidebar.markdown("**Privacy & Governance**")
st.sidebar.write(
    "• Shows anonymized IPs in UI (last octet masked).\n"
    "• Keeps raw IPs in audit logs (simulation) — in production this must be stored encrypted and access-controlled.\n"
    "• Federated coordination messages are simulated; in production use secure standards (STIX/TAXII, MISP) and legal agreements."
)

# ---------------- Final notes ----------------
st.markdown("---")
st.caption("This app demonstrates core concepts: continuous monitoring cycles, adaptive defenses, intel ingestion, federated coordination, privacy-first display, and audit logging — all in a simulated environment without external ML libraries.")
