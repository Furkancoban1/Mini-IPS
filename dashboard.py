from flask import Flask, render_template, jsonify, request
import sqlite3
import json
import os

app = Flask(__name__)

CONFIG_FILE = 'config.json'

# --- Ensure Config Exists ---
if not os.path.exists(CONFIG_FILE):
    default_config = {
        "syn_threshold": 150, "time_limit": 1, "port_threshold": 15,
        "port_window": 5, "honeypot": 23, "behavior_timeout": 10, "ban_duration": 300
    }
    with open(CONFIG_FILE, 'w') as f:
        json.dump(default_config, f)

# --- Database Connection ---
def get_db_connection():
    conn = sqlite3.connect('ips_logs.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    # API endpoint for dynamic settings
    if request.method == 'POST':
        new_config = request.json
        with open(CONFIG_FILE, 'w') as f:
            json.dump(new_config, f)
        return jsonify({"status": "success"})
    else:
        with open(CONFIG_FILE, 'r') as f:
            return jsonify(json.load(f))

@app.route('/api/logs')
def get_logs():
    try:
        conn = get_db_connection()
        logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50').fetchall()
        total_blocks = conn.execute('SELECT COUNT(*) FROM logs WHERE action="BLOCK"').fetchone()[0]
        attack_counts = conn.execute('SELECT attack, COUNT(*) FROM logs GROUP BY attack').fetchall()
        conn.close()

        log_list = [{"ip": row["ip"], "attack": row["attack"], "action": row["action"], "timestamp": row["timestamp"]}
                    for row in logs]
        stats_list = [{"attack": row[0], "count": row[1]} for row in attack_counts]

        return jsonify({
            "logs": log_list,
            "total_blocks": total_blocks,
            "stats": stats_list
        })
    except Exception:
        return jsonify({"logs": [], "total_blocks": 0, "stats": []})

if __name__ == '__main__':
    app.run(port=5000)