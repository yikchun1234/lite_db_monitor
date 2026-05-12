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
    server_name = request.args.get('server')
    
    # Read the config live
    with open('config.json') as config_file:
        live_configs = json.load(config_file)

    if server_name not in live_configs:
        return jsonify({"error": "Server not found"}), 404

    config = live_configs[server_name]
    
    if config['type'] == 'sqlserver':
        try:
            # 1. Connect to the 'master' database to view all databases
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={config['host']};"
                f"DATABASE=master;" # Always connect to master
                f"UID={config['user']};"
                f"PWD={config['password']}"
            )
            conn = pyodbc.connect(conn_str, timeout=5)
            cursor = conn.cursor()

            # 2. Query to get ALL databases, their status, and their sizes at once!
            # The 'WHERE d.database_id > 4' hides the system databases (master, tempdb, etc.)
            db_query = """
                SELECT 
                    d.name AS DatabaseName, 
                    d.state_desc AS Status, 
                    ISNULL(SUM(mf.size * 8.0 / 1024), 0) AS Size_in_MB
                FROM sys.databases d
                LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id
                WHERE d.database_id > 4 
                GROUP BY d.name, d.state_desc;
            """
            cursor.execute(db_query)
            
            # 3. Format the results
            all_databases = []
            for row in cursor.fetchall():
                all_databases.append({
                    "name": row.DatabaseName,
                    "status": row.Status,
                    "size_mb": round(row.Size_in_MB, 2)
                })

            conn.close()

            # Return the list of all databases to the frontend
            return jsonify({
                "server_level_alerts": ["No active server alerts"],
                "databases": all_databases
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Unsupported database type"})
