# app.py - FINAL CLEAN WORKING VERSION (with logs support and test data)
from flask import Flask, render_template, jsonify, request
import os
import json
from datetime import datetime, timedelta
import datetime as dt

app = Flask(__name__, template_folder='templates', static_folder='static')

# ----------------------------#
# PATHS
# ----------------------------#
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

TOPO_FILE = os.path.join(DATA_DIR, "topology.json")
METRICS_FILE = os.path.join(DATA_DIR, "metrics.json")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")
LOGS_FILE = os.path.join(DATA_DIR, "logs.json")

# store last pushed status (optional)
CURRENT_STATUS = {"hosts": [], "servers": []}

# Live stats with initial dummy data
live_stats = []

LOG_DIR = "/home/vboxuser/mini-cloud/ryu_logs"

# ----------------------------#
# TEST DATA
# ----------------------------#
TEST_HOSTS = [
    {"id": "h1", "ip": "10.0.0.1", "type": "client", "status": "UP"},
    {"id": "h2", "ip": "10.0.0.2", "type": "client", "status": "UP"},
    {"id": "h3", "ip": "10.0.0.3", "type": "client", "status": "DOWN"}
]

TEST_SERVERS = [
    {"id": "s1", "ip": "10.0.1.1", "status": "UP"},
    {"id": "s2", "ip": "10.0.1.2", "status": "UP"}
]

TEST_EVENTS = [
    {"ts": datetime.utcnow().isoformat() + "Z", "msg": "Server s1 came online"},
    {"ts": datetime.utcnow().isoformat() + "Z", "msg": "Host h1 connected"},
    {"ts": datetime.utcnow().isoformat() + "Z", "msg": "High bandwidth detected on link 1"},
]

# ----------------------------#
# HELPER FUNCTIONS
# ----------------------------#
def read_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def get_latest_log_file():
    if not os.path.exists(LOG_DIR):
        return None
    # List only .log files inside folder
    files = [
        os.path.join(LOG_DIR, f)
        for f in os.listdir(LOG_DIR)
        if f.startswith("controller_log_") and f.endswith(".log")
    ]
    if not files:
        return None
    # Pick the newest log file by modified timestamp
    latest_file = max(files, key=os.path.getmtime)
    return latest_file

# ----------------------------#
# ROUTES: MAIN PAGES
# ----------------------------#
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/topology")
def topology_page():
    return render_template("topology.html")

@app.route("/hosts")
def hosts_page():
    return render_template("hosts.html")

@app.route("/logs")
def logs_page():
    return render_template("logs.html")

# ----------------------------#
# API: TOPOLOGY
# ----------------------------#
@app.route("/api/topology")
def api_topology():
    data = read_json(TOPO_FILE, default={"nodes": [], "links": []})
    return jsonify(data)

# ----------------------------#
# API: METRICS
# ----------------------------#
@app.route("/api/metrics")
def api_metrics():
    global CURRENT_STATUS
    return jsonify(CURRENT_STATUS)

@app.route("/api/active-hosts")
def api_active_hosts():
    data = read_json(METRICS_FILE, default={"hosts": [], "servers": []})
    hosts = data.get("hosts", [])
    
    # If Ryu hasn't pushed data yet, return test data
    if not hosts:
        return jsonify(TEST_HOSTS)
    
    return jsonify(hosts)

@app.route("/api/active-servers")
def api_active_servers():
    data = read_json(METRICS_FILE, default={"hosts": [], "servers": []})
    servers = data.get("servers", [])
    
    # If Ryu hasn't pushed data yet, return test data
    if not servers:
        return jsonify(TEST_SERVERS)
    
    return jsonify(servers)

# ----------------------------#
# API: LOGS
# ----------------------------#
@app.route("/api/logs")
def api_logs():
    logs = []
    if os.path.exists(LOG_DIR):
        # get all .log files sorted by modified time descending
        log_files = sorted(
            [f for f in os.listdir(LOG_DIR) if f.endswith(".log")],
            key=lambda x: os.path.getmtime(os.path.join(LOG_DIR, x)),
            reverse=True
        )
        if log_files:  # if any logs exist
            latest_file = log_files[0]
            path = os.path.join(LOG_DIR, latest_file)
            with open(path) as file:
                content = file.read()
            logs.append({
                "name": latest_file,
                "timestamp": dt.datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
                "content": content
            })
    return jsonify(logs)

@app.route('/api/events')
def api_events():
    logs = read_json(LOGS_FILE, default=[])
    if not logs:
        # If no real events, return test events
        return jsonify(TEST_EVENTS)
    return jsonify(logs[-10:])  # Last 10 events

# ----------------------------#
# API: RYU → DASHBOARD live push
# ----------------------------#
@app.route('/update_status', methods=['POST'])
def update_status():
    global CURRENT_STATUS
    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "no json payload"}), 400
    
    payload['ts'] = datetime.utcnow().isoformat() + "Z"
    CURRENT_STATUS = payload
    
    # Save to metrics.json file
    write_json(METRICS_FILE, payload)
    
    # Optional: accept inline events array and add to logs
    events = payload.get("events", [])
    if events:
        existing_logs = read_json(LOGS_FILE, default=[])
        existing_logs.extend(events)
        write_json(LOGS_FILE, existing_logs)
    
    print(f"✅ Received update from Ryu: {len(payload.get('hosts', []))} hosts, {len(payload.get('servers', []))} servers")
    return jsonify({"status": "ok"})

# ----------------------------#
# API: LINK/TRAFFIC STATS
# ----------------------------#
@app.route("/api/stats")
def api_stats():
    # Replace this dummy logic with actual stored stats when ready
    now = datetime.utcnow()
    stats = []
    for i in range(10):
        ts = (now - timedelta(seconds=(9 - i) * 5)).isoformat() + "Z"
        stats.append({
            "ts": ts,
            "requests": 10 + i,  # placeholder
            "bandwidth": 5 + i   # placeholder
        })
    return jsonify(stats)

@app.route('/api/get-stats')
def get_stats():
    global live_stats
    
    # Generate dummy stats if empty
    if not live_stats:
        now = datetime.utcnow()
        for i in range(10):
            ts = (now - timedelta(seconds=(9 - i) * 5)).isoformat() + "Z"
            live_stats.append({
                "ts": ts,
                "requests": 10 + i * 2,
                "bandwidth": 5 + i * 3
            })
    
    # Return the latest stats list
    return jsonify(live_stats)

# ----------------------------#
# START APP
# ----------------------------#
if __name__ == "__main__":
    print("🚀 Starting Flask Dashboard on http://0.0.0.0:5000")
    print("📊 Dashboard will be available at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
