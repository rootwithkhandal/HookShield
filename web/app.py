import os
import sys
import sqlite3
import datetime
from flask import Flask, jsonify, send_from_directory, request
import psutil

# Add parent directory to path so we can import utils if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = Flask(__name__, static_folder='static')
db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "logs.db"))

def get_db():
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/sysinfo')
def sysinfo():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        boot = datetime.datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.datetime.now() - boot
        hours, rem = divmod(int(uptime.total_seconds()), 3600)
        mins = rem // 60
        return jsonify({
            "cpu": cpu,
            "ram": mem.percent,
            "uptime": f"{hours}h {mins}m"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
def stats():
    try:
        with get_db() as db:
            cur = db.cursor()
            
            # Use basic error handling for empty tables
            try:
                cur.execute("SELECT count(*) as count FROM threat_history")
                total_threats = cur.fetchone()["count"]
            except:
                total_threats = 0
                
            try:
                cur.execute("SELECT count(*) as count FROM threat_history WHERE resolved=0")
                unresolved = cur.fetchone()["count"]
            except:
                unresolved = 0
                
            try:
                cur.execute("SELECT threat_type, count(*) as count FROM threat_history GROUP BY threat_type")
                threats_by_type = {row["threat_type"]: row["count"] for row in cur.fetchall()}
            except:
                threats_by_type = {}
                
            try:
                cur.execute("SELECT count(*) as count FROM logs")
                scanned_files = cur.fetchone()["count"] # Approximate from logs
            except:
                scanned_files = 0
                
            try:
                cur.execute("SELECT count(DISTINCT source_ip) as count FROM network_ip")
                network_connections = cur.fetchone()["count"]
            except:
                network_connections = 0

            # Log volume over time (last 7 days)
            try:
                cur.execute("""
                    SELECT date(timestamp) as date, count(*) as count 
                    FROM logs 
                    GROUP BY date(timestamp) 
                    ORDER BY date(timestamp) DESC 
                    LIMIT 7
                """)
                log_volume = [{"date": row["date"], "count": row["count"]} for row in cur.fetchall()]
                log_volume.reverse() # chronological order
            except:
                log_volume = []
            
            return jsonify({
                "total_threats": total_threats,
                "unresolved": unresolved,
                "active_processes": len(psutil.pids()),
                "scanned_files": scanned_files,
                "network_connections": network_connections,
                "threats_by_type": threats_by_type,
                "log_volume": log_volume
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs')
def logs():
    try:
        limit = request.args.get('limit', 100, type=int)
        with get_db() as db:
            cur = db.cursor()
            cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(row) for row in cur.fetchall()]
            return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/network')
def network():
    try:
        limit = request.args.get('limit', 100, type=int)
        with get_db() as db:
            cur = db.cursor()
            cur.execute("SELECT * FROM network_ip ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(row) for row in cur.fetchall()]
            return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/threats')
def threats():
    try:
        limit = request.args.get('limit', 100, type=int)
        with get_db() as db:
            cur = db.cursor()
            cur.execute("SELECT * FROM threat_history ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(row) for row in cur.fetchall()]
            return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
def settings():
    from dotenv import set_key, dotenv_values
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".config"))
    
    if request.method == 'GET':
        try:
            # If .config doesn't exist, dotenv_values returns empty dict, which is fine
            config = dotenv_values(env_path)
            return jsonify({
                "vt_api_key": config.get("VIRUS_TOTAL_API_KEY", ""),
                "email_sender": config.get("EMAIL_SENDER", ""),
                "email_password": config.get("EMAIL_PASSWORD", ""),
                "email_receiver": config.get("EMAIL_RECEIVER", ""),
                "output_mode": config.get("OUTPUT_MODE", "both"),
                "syslog_host": config.get("SYSLOG_HOST", "127.0.0.1"),
                "syslog_port": config.get("SYSLOG_PORT", "514"),
                "abuseipdb_key": config.get("ABUSEIPDB_API_KEY", ""),
                "malwarebazaar_key": config.get("MALWARE_BAZAAR_API_KEY", "")
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500
            
    if request.method == 'POST':
        try:
            data = request.json
            if not os.path.exists(env_path):
                open(env_path, 'a').close()
            
            set_key(env_path, "VIRUS_TOTAL_API_KEY", data.get("vt_api_key", ""))
            set_key(env_path, "EMAIL_SENDER", data.get("email_sender", ""))
            set_key(env_path, "EMAIL_PASSWORD", data.get("email_password", ""))
            set_key(env_path, "EMAIL_RECEIVER", data.get("email_receiver", ""))
            set_key(env_path, "OUTPUT_MODE", data.get("output_mode", "both"))
            set_key(env_path, "SYSLOG_HOST", data.get("syslog_host", "127.0.0.1"))
            set_key(env_path, "SYSLOG_PORT", str(data.get("syslog_port", "514")))
            set_key(env_path, "ABUSEIPDB_API_KEY", data.get("abuseipdb_key", ""))
            set_key(env_path, "MALWARE_BAZAAR_API_KEY", data.get("malwarebazaar_key", ""))
            
            return jsonify({"status": "success"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/api/export/<table_name>')
def export_csv(table_name):
    import csv
    from io import StringIO
    from flask import Response
    
    allowed_tables = ['logs', 'network_ip', 'threat_history']
    if table_name not in allowed_tables:
        return "Invalid table", 400
        
    try:
        with get_db() as db:
            cur = db.cursor()
            cur.execute(f"SELECT * FROM {table_name} ORDER BY id DESC")
            rows = cur.fetchall()
            
            if not rows:
                return "No data to export", 404
                
            si = StringIO()
            cw = csv.writer(si)
            
            # Write headers
            cw.writerow(rows[0].keys())
            
            # Write data
            for row in rows:
                cw.writerow(row)
                
            output = si.getvalue()
            return Response(
                output,
                mimetype="text/csv",
                headers={"Content-disposition": f"attachment; filename={table_name}.csv"}
            )
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
