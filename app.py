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
            server_address = config['host']
            if config.get('port') and str(config['port']).strip() != '':
                server_address = f"{server_address},{config['port']}"

            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server_address};"
                f"DATABASE=master;"
                f"UID={config['user']};"
                f"PWD={{{config['password']}}};"
                f"Encrypt=yes;"
                f"TrustServerCertificate=yes;"
            )
            
            conn = pyodbc.connect(conn_str, timeout=5)
            cursor = conn.cursor()

            # ---------- 1. GET DRIVES & SPACE ----------
            drive_query = """
                SELECT DISTINCT
                    vs.volume_mount_point AS DriveLetter,
                    CAST(vs.available_bytes AS FLOAT) / CAST(vs.total_bytes AS FLOAT) * 100 AS FreeSpacePercent,
                    CAST(vs.available_bytes / 1048576.0 / 1024.0 AS DECIMAL(10,2)) AS FreeSpaceGB,
                    CAST(vs.total_bytes / 1048576.0 / 1024.0 AS DECIMAL(10,2)) AS TotalSpaceGB
                FROM sys.master_files AS f
                CROSS APPLY sys.dm_os_volume_stats(f.database_id, f.file_id) AS vs;
            """
            cursor.execute(drive_query)
            all_drives = []
            for row in cursor.fetchall():
                all_drives.append({
                    "letter": row.DriveLetter,
                    "free_percent": round(row.FreeSpacePercent, 2),
                    "free_gb": float(row.FreeSpaceGB),
                    "total_gb": float(row.TotalSpaceGB)
                })

            # ---------- 2. GET DATABASES & BACKUP STATUS ----------
            db_query = """
                WITH BackupCTE AS (
                    SELECT database_name, MAX(backup_finish_date) as LastBackup
                    FROM msdb.dbo.backupset
                    WHERE type = 'D'
                    GROUP BY database_name
                )
                SELECT 
                    d.name AS DatabaseName, 
                    d.state_desc AS Status, 
                    ISNULL(SUM(mf.size * 8.0 / 1024), 0) AS Size_in_MB,
                    CASE 
                        WHEN d.name = 'tempdb' THEN 'N/A'
                        WHEN b.LastBackup >= DATEADD(hh, -24, GETDATE()) THEN 'OK'
                        ELSE 'MISSING'
                    END AS BackupStatus
                FROM sys.databases d
                LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id
                LEFT JOIN BackupCTE b ON d.name = b.database_name
                WHERE d.database_id > 4 
                GROUP BY d.name, d.state_desc, b.LastBackup;
            """
            cursor.execute(db_query)
            all_databases = []
            for row in cursor.fetchall():
                all_databases.append({
                    "name": row.DatabaseName,
                    "status": row.Status,
                    "size_mb": round(row.Size_in_MB, 2),
                    "backup_status": row.BackupStatus
                })

            alerts = []

            # ---------- 3. LOG FILE CHECK ----------
            log_query = """
                SELECT RTRIM(instance_name) AS DatabaseName, cntr_value AS LogUsedPercent
                FROM sys.dm_os_performance_counters 
                WHERE counter_name = 'Percent Log Used' 
                  AND instance_name NOT IN ('master', 'tempdb', 'model', 'msdb', '_Total')
                  AND cntr_value > 50; 
            """
            cursor.execute(log_query)
            for row in cursor.fetchall():
                alerts.append(f"⚠️ Warning: Transaction Log for '{row.DatabaseName}' is {row.LogUsedPercent}% full!")

            # ---------- 4. BLOCKING & LONG QUERY CHECK WITH SQL TEXT ----------
            # Added CROSS APPLY to get the exact query text and filtered out sleeping/background tasks
            blocking_query = """
                SELECT 
                    r.session_id, 
                    r.blocking_session_id, 
                    DB_NAME(r.database_id) AS DatabaseName, 
                    r.total_elapsed_time / 1000 AS SecondsRunning,
                    t.text AS QueryText
                FROM sys.dm_exec_requests r
                CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
                WHERE r.session_id > 50 
                  AND r.status NOT IN ('background', 'sleeping')
                  AND (r.blocking_session_id <> 0 OR r.total_elapsed_time > 60000);
            """
            cursor.execute(blocking_query)
            
            long_queries = []
            for row in cursor.fetchall():
                if row.blocking_session_id != 0:
                    alerts.append(f"🚨 CRITICAL: Session {row.session_id} on '{row.DatabaseName}' is BLOCKED by Session {row.blocking_session_id}!")
                elif row.SecondsRunning > 60:
                    alerts.append(f"⚠️ Warning: A query on '{row.DatabaseName}' has been running for {row.SecondsRunning} seconds.")
                
                # Protect against massive queries crashing the UI by slicing to 300 characters
                safe_query_text = str(row.QueryText) if row.QueryText else "N/A"
                if len(safe_query_text) > 300:
                    safe_query_text = safe_query_text[:300] + " ... [TRUNCATED]"

                long_queries.append({
                    "session_id": row.session_id,
                    "database": row.DatabaseName,
                    "seconds": row.SecondsRunning,
                    "query_text": safe_query_text
                })

            if len(alerts) == 0:
                alerts.append("No active server alerts")

            conn.close()

            return jsonify({
                "server_level_alerts": alerts,
                "drives": all_drives,
                "databases": all_databases,
                "long_queries": long_queries
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Unsupported database type"})

# ---------- PRODUCTION-SAFE INDEX CHECKING ----------
@app.route('/api/indexes', methods=['GET'])
def get_indexes():
    server_name = request.args.get('server')
    db_name = request.args.get('db')
    with open('config.json') as config_file: live_configs = json.load(config_file)
    if server_name not in live_configs: return jsonify({"error": "Server not found"}), 404
    config = live_configs[server_name]
    
    if config['type'] == 'sqlserver':
        try:
            server_address = config['host']
            if config.get('port') and str(config['port']).strip() != '': server_address = f"{server_address},{config['port']}"
            conn_str = (f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server_address};DATABASE={db_name};UID={config['user']};PWD={{{config['password']}}};Encrypt=yes;TrustServerCertificate=yes;")
            conn = pyodbc.connect(conn_str, timeout=10)
            cursor = conn.cursor()
            index_query = """
                SELECT OBJECT_NAME(ips.OBJECT_ID) AS TableName, i.name AS IndexName, ROUND(ips.avg_fragmentation_in_percent, 2) AS Fragmentation, ips.page_count AS PageCount
                FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ips
                INNER JOIN sys.indexes i ON ips.object_id = i.object_id AND ips.index_id = i.index_id
                WHERE ips.avg_fragmentation_in_percent > 10.0 AND ips.page_count > 1000 AND i.name IS NOT NULL
                ORDER BY ips.avg_fragmentation_in_percent DESC;
            """
            cursor.execute(index_query)
            indexes = [{"table": row.TableName, "index": row.IndexName, "fragmentation": row.Fragmentation, "pages": row.PageCount} for row in cursor.fetchall()]
            conn.close()
            return jsonify({"indexes": indexes})
        except Exception as e: return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Unsupported database type"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
