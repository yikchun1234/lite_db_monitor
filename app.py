from flask import Flask, jsonify, request, render_template
import json
import pyodbc

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html') 

@app.route('/api/databases', methods=['GET'])
def get_databases():
    with open('config.json') as config_file:
        live_configs = json.load(config_file)
    return jsonify(list(live_configs.keys()))

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    server_name = request.args.get('server')
    
    with open('config.json') as config_file:
        live_configs = json.load(config_file)

    if server_name not in live_configs:
        return jsonify({"error": "Server not found"}), 404

    config = live_configs[server_name]
    
    if config['type'] == 'sqlserver':
        try:
	    # Safely format the server address
            server_address = config['host'].replace(':', ',').strip(',')
            
            # Only append the port if it actually has a value!
            if config.get('port') and str(config['port']).strip() != '' and ',' not in server_address:
                server_address = f"{server_address},{config['port']}"
                
            # --- THE FIX IS HERE ---
            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server_address};"
                f"DATABASE=master;"
                f"UID={config['user']};"
                f"PWD={{{config['password']}}};"  # <-- The triple brackets protect passwords with special characters!
                f"Encrypt=yes;"
                f"TrustServerCertificate=yes;"
            )
            
            # --- DEBUGGING TOOL ---
            safe_conn_str = conn_str.replace(config['password'], '********')
            print(f"\n--- DEBUG: ATTEMPTING CONNECTION ---")
            print(safe_conn_str)
            print(f"------------------------------------\n")

            conn = pyodbc.connect(conn_str, timeout=5)
            cursor = conn.cursor()

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
            
            all_databases = []
            for row in cursor.fetchall():
                all_databases.append({
                    "name": row.DatabaseName,
                    "status": row.Status,
                    "size_mb": round(row.Size_in_MB, 2)
                })

            conn.close()

            return jsonify({
                "server_level_alerts": ["No active server alerts"],
                "databases": all_databases
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Unsupported database type"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
