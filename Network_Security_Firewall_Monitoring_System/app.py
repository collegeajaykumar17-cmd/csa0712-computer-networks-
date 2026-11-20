from flask import Flask, render_template, request, redirect, url_for, jsonify
from datetime import datetime
import random, threading, time

app = Flask(__name__)

rules = [
    {"id": 1, "source": "ANY", "port": "80", "protocol": "TCP", "action": "ALLOW", "description": "HTTP traffic"},
    {"id": 2, "source": "ANY", "port": "443", "protocol": "TCP", "action": "ALLOW", "description": "HTTPS traffic"},
    {"id": 3, "source": "192.168.1.100", "port": "22", "protocol": "TCP", "action": "BLOCK", "description": "Blocked SSH source"},
]
logs = []
alerts = []
stats = {"total": 0, "allowed": 0, "blocked": 0, "suspicious": 0}
next_rule_id = 4
lock = threading.Lock()

def is_private_or_demo(ip):
    return ip.startswith(("192.168.", "10.", "172.16.")) or ip in ("127.0.0.1", "localhost")

def evaluate_traffic(src, dst, port, protocol):
    # Demo firewall: explicit matching rule wins; otherwise deny by default.
    matching = [r for r in rules if (r["source"] == "ANY" or r["source"] == src)
                and r["port"] == str(port) and r["protocol"] == protocol]
    action = matching[-1]["action"] if matching else "BLOCK"
    suspicious = (int(port) in (21, 22, 23, 3389) and action == "BLOCK") or not is_private_or_demo(src)
    reason = "Matched firewall rule" if matching else "No matching rule (default deny)"
    if suspicious:
        reason += " | Suspicious source/port activity"
    record = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": src, "destination": dst, "port": int(port),
        "protocol": protocol, "action": action, "reason": reason,
        "suspicious": suspicious
    }
    with lock:
        logs.insert(0, record)
        logs[:] = logs[:500]
        stats["total"] += 1
        stats[action.lower()] += 1
        if suspicious:
            stats["suspicious"] += 1
            alerts.insert(0, record.copy())
            alerts[:] = alerts[:100]
    return record

@app.route("/")
def dashboard():
    return render_template("index.html", rules=rules, logs=logs[:20], alerts=alerts[:10], stats=stats)

@app.route("/traffic", methods=["POST"])
def traffic():
    src = request.form.get("source", "192.168.1.10").strip()
    dst = request.form.get("destination", "192.168.1.1").strip()
    port = request.form.get("port", "80").strip()
    protocol = request.form.get("protocol", "TCP").upper()
    if not src or not dst or not port.isdigit() or not (1 <= int(port) <= 65535) or protocol not in ("TCP", "UDP"):
        return jsonify({"error": "Please enter valid IP fields, port (1-65535), and TCP/UDP."}), 400
    rec = evaluate_traffic(src, dst, port, protocol)
    return jsonify(rec)

@app.route("/simulate", methods=["POST"])
def simulate():
    sample = [
        ("192.168.1.10", "192.168.1.1", 80, "TCP"),
        ("192.168.1.20", "192.168.1.1", 443, "TCP"),
        ("192.168.1.100", "192.168.1.1", 22, "TCP"),
        ("203.0.113.55", "192.168.1.1", 8080, "TCP"),
        ("10.0.0.5", "192.168.1.1", 53, "UDP"),
        ("198.51.100.23", "192.168.1.1", 3389, "TCP"),
        ("192.168.1.30", "192.168.1.1", 443, "TCP"),
        ("192.168.1.40", "192.168.1.1", 23, "TCP"),
    ]
    for item in sample:
        evaluate_traffic(*item)
    return redirect(url_for("dashboard"))

@app.route("/rules/add", methods=["POST"])
def add_rule():
    global next_rule_id
    source = request.form.get("source", "ANY").strip() or "ANY"
    port = request.form.get("port", "").strip()
    protocol = request.form.get("protocol", "TCP").upper()
    action = request.form.get("action", "ALLOW").upper()
    desc = request.form.get("description", "").strip()
    if not port.isdigit() or not 1 <= int(port) <= 65535 or protocol not in ("TCP", "UDP") or action not in ("ALLOW", "BLOCK"):
        return redirect(url_for("dashboard"))
    rules.append({"id": next_rule_id, "source": source, "port": port, "protocol": protocol,
                  "action": action, "description": desc or "Custom rule"})
    next_rule_id += 1
    return redirect(url_for("dashboard"))

@app.route("/rules/delete/<int:rule_id>", methods=["POST"])
def delete_rule(rule_id):
    rules[:] = [r for r in rules if r["id"] != rule_id]
    return redirect(url_for("dashboard"))

@app.route("/logs/clear", methods=["POST"])
def clear_logs():
    with lock:
        logs.clear()
        alerts.clear()
        for key in stats:
            stats[key] = 0
    return redirect(url_for("dashboard"))

@app.route("/api/state")
def state():
    return jsonify({"stats": stats, "logs": logs[:20], "alerts": alerts[:10], "rules": rules})

if __name__ == "__main__":
    print("Network Security Firewall Monitor running at http://127.0.0.1:5000")
    app.run(debug=False, host="127.0.0.1", port=5000)
