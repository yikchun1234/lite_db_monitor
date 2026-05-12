from flask import Flask, jsonify, request, render_template
import json
import pyodbc

app = Flask(__name__)

# Load configurations
with open('config.json') as config_file:
    db_configs = json.load(config_file)

@app.route('/')
def index():
    return render_template('index.html') # Serves your HTML page

@app.route('/api/databases', methods=['GET'])
def get_databases():
    # Returns just the names for the dropdown
    return jsonify(list(db_configs.keys()))

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    db_name = request.args.get('db')
    if db_name not in db_configs:
        return jsonify({"error": "Database not found"}), 404

    config = db_configs[db_name]
    
    # --- IMPORTANT ---
    # Here is where you use your database library (psycopg2, pyodbc, cx_Oracle) 
    # to connect using the details in 'config' and run your queries.
    # For demonstration, returning mock data:
    
    mock_data = {
        "status": "Healthy",
        "datafile_size": "250 GB",
        "index_details": "All indexes optimized. No fragmentation > 10%.",
        "alerts": ["Warning: High CPU usage at 2 AM", "Info: Backup completed successfully"]
    }
    
    return jsonify(mock_data)

if __name__ == '__main__':
    # Runs a lightweight local server
    app.run(host='0.0.0.0', port=5000)

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    db_name = request.args.get('db')
    if db_name not in db_configs:
        return jsonify({"error": "Database not found"}), 404

    config = db_configs[db_name]
    
    # Check if the requested database is MSSQL
    if config['type'] == 'sqlserver':
        try:
            # 1. Build the connection string
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={config['host']};"
                f"DATABASE={config['database']};"
                f"UID={config['user']};"
                f"PWD={config['password']}"
            )
            
            # Connect to the database
            conn = pyodbc.connect(conn_str, timeout=5) # 5 second timeout so it doesn't hang
            cursor = conn.cursor()

            # 2. Get Database Status (Lightning fast)
            cursor.execute("SELECT state_desc FROM sys.databases WHERE name = DB_NAME();")
            status = cursor.fetchone()[0]

            # 3. Get Datafile Size in MB (Queries metadata, very fast)
            cursor.execute("SELECT SUM(size * 8.0 / 1024) FROM sys.master_files WHERE database_id = DB_ID();")
            size_mb = round(cursor.fetchone()[0], 2)

            # 4. Get Active Alerts: Long running queries (Over 30 seconds)
            # Uses NOLOCK to ensure zero interference with production
            alert_query = """
                SELECT session_id, total_elapsed_time / 1000 AS seconds_running 
                FROM sys.dm_exec_requests WITH (NOLOCK)
                WHERE total_elapsed_time > 30000 AND session_id <> @@SPID;
            """
            cursor.execute(alert_query)
            long_queries = cursor.fetchall()
            alerts = []
            if long_queries:
                for row in long_queries:
                    alerts.append(f"Warning: Session {row.session_id} has been running for {row.seconds_running} seconds.")
            else:
                alerts.append("No long-running queries detected.")

            conn.close()

            # Return the real data to your HTML frontend
            return jsonify({
                "status": status,
                "datafile_size": f"{size_mb} MB",
                "index_details": "Index check skipped for performance (Requires heavy scan).",
                "alerts": alerts
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Unsupported database type"})
