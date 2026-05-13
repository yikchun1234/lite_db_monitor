from flask import Flask, jsonify, request, render_template, session
from functools import wraps
from cryptography.fernet import Fernet
import json
import pyodbc
import os

app = Flask(__name__)
# A secret key is required to keep client-side sessions secure
app.secret_key = os.urandom(24) 

# ==========================================
# 🔐 ADMIN CREDENTIALS (CHANGE THESE!)
# ==========================================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin123!"

# ==========================================
# 🔐 ENCRYPTION ENGINE SETUP
# ==========================================
KEY_FILE = 'encryption.key'

# If no key exists, generate a new secure key
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as f:
        f.write(Fernet.generate_key())

# Load the key into the Cipher Suite
with open(KEY_FILE, 'rb') as f:
    cipher_suite = Fernet(f.read())

def encrypt_password(plain_text):
    if not plain_text: return ""
    return cipher_suite.encrypt(plain_text.encode('utf-8')).decode('utf-8')

def decrypt_password(cipher_text):
    if not cipher_text: return ""
    try:
        return cipher_suite.decrypt(cipher_text.encode('utf-8')).decode('utf-8')
    except:
        # SMART FALLBACK: If decryption fails, assume it's an old plaintext password!
        return cipher_text

# ==========================================
# 🔐 SECURITY DECORATOR (LOCKS ROUTES)
# ==========================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({"error": "Unauthorized access. Please log in."}), 401
        return f(*args, **kwargs)
    return decorated_function


# ==========================================
# 🌐 ROUTES
# ==========================================
@app.route('/')
def index():
    # We pass the session status to the frontend so HTML knows whether to show the Login Screen or Dashboard
    return render_template('index.html', logged_in=session.get('logged_in', False))

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
        session['logged_in'] = True
        return jsonify({"success": True})
    return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route('/api/databases', methods=['GET'])
@login_required
def get_databases():
    if os.path.exists('config.json'):
        with open('config.json', 'r') as config_file:
            live_configs = json.load(config_file)
        return jsonify(list(live_configs.keys()))
    return jsonify([])


# ---------- 1. ADD SERVER (ENCRYPTED) ----------
@app.route('/api/servers/add', methods=['POST'])
@login_required
def add_server():
    try:
        new_server = request.json
        alias = new_server.get('alias')
        
        if not alias: return jsonify({"error": "Server Alias Name is required"}), 400
            
        config_entry = {
            "host": new_server.get("host", ""),
            "port": new_server.get("port", ""),
            "type": new_server.get("type", "sqlserver"),
            "user": new_server.get("user", ""),
            "password": encrypt_password(new_server.get("password", "")) # ENCRYPTED!
        }
        
        live_configs = {}
        if os.path.exists('config.json'):
            with open('config.json', 'r') as config_file:
                live_configs = json.load(config_file)
            
        live_configs[alias] = config_entry
        
        with open('config.json', 'w') as config_file:
            json.dump(live_configs, config_file, indent=4)
            
        return jsonify({"success": True, "message": f"Server '{alias}' added successfully and password encrypted!"})
    except Exception as e: return jsonify({"error": str(e)}), 500


# ---------- 2. GET SERVER DETAILS FOR EDITING ----------
@app.route('/api/servers/detail', methods=['GET'])
@login_required
def get_server_detail():
    alias = request.args.get('server')
    if not alias: return jsonify({"error": "No server provided"}), 400
    if os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            configs = json.load(f)
        if alias in configs:
            s = configs[alias]
            return jsonify({"host": s.get("host",""), "port": s.get("port",""), "user": s.get("user","")})
    return jsonify({"error": "Server not found"}), 404


# ---------- 3. EDIT SERVER (ENCRYPTED) ----------
@app.route('/api/servers/edit', methods=['POST'])
@login_required
def edit_server():
    try:
        data = request.json
        original_alias = data.get('original_alias')
        new_alias = data.get('alias')
        
        if not original_alias or not new_alias: 
            return jsonify({"error": "Server Alias Name is required"}), 400
        
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                configs = json.load(f)
            
            if original_alias in configs:
                if original_alias != new_alias:
                    if new_alias in configs:
                        return jsonify({"error": f"A server named '{new_alias}' already exists!"}), 400
                    configs[new_alias] = configs.pop(original_alias)
                
                configs[new_alias]['host'] = data.get('host', configs[new_alias]['host'])
                configs[new_alias]['port'] = data.get('port', configs[new_alias]['port'])
                configs[new_alias]['user'] = data.get('user', configs[new_alias]['user'])
                
                # Only overwrite and encrypt the password if the user actually typed a new one
                if data.get('password') and data.get('password').strip() != "":
                    configs[new_alias]['password'] = encrypt_password(data['password'])
                
                with open('config.json', 'w') as f:
                    json.dump(configs, f, indent=4)
                    
                return jsonify({"success": True, "message": f"Server '{new_alias}' updated successfully!"})
                
        return jsonify({"error": "Server not found in config.json"}), 404
    except Exception as e: return jsonify({"error": str(e)}), 500


# ---------- 4. DELETE SERVER ----------
@app.route('/api/servers/delete', methods=['POST'])
@login_required
def delete_server():
    try:
        alias = request.json.get('alias')
        if os.path.exists('config.json'):
            with open('config.json', 'r') as f:
                configs = json.load(f)
            if alias in configs:
                del configs[alias]
                with open('config.json', 'w') as f:
                    json.dump(configs, f, indent=4)
                return jsonify({"success": True, "message": "Server deleted successfully."})
        return jsonify({"error": "Server not found"}), 404
    except Exception as e: return jsonify({"error": str(e)}), 500


@app.route('/api/metrics', methods=['GET'])
@login_required
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
                
            # DECRYPT THE PASSWORD TO CONNECT
            real_password = decrypt_password(config['password'])

            conn_str = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={server_address};"
                f"DATABASE=master;"
                f"UID={config['user']};"
                f"PWD={{{real_password}}};"
                f"Encrypt=yes;"
                f"TrustServerCertificate=yes;"
            )
            
            conn = pyodbc.connect(conn_str, timeout=5)
            cursor = conn.cursor()
            alerts = []

            # 1. DRIVES
            drive_query = """
                SELECT DISTINCT vs.volume_mount_point AS DriveLetter, CAST(vs.available_bytes AS FLOAT) / CAST(vs.total_bytes AS FLOAT) * 100 AS FreeSpacePercent, CAST(vs.available_bytes / 1048576.0 / 1024.0 AS DECIMAL(10,2)) AS FreeSpaceGB, CAST(vs.total_bytes / 1048576.0 / 1024.0 AS DECIMAL(10,2)) AS TotalSpaceGB
                FROM sys.master_files AS f CROSS APPLY sys.dm_os_volume_stats(f.database_id, f.file_id) AS vs;
            """
            cursor.execute(drive_query)
            all_drives = [{"letter": r.DriveLetter, "free_percent": round(r.FreeSpacePercent, 2), "free_gb": float(r.FreeSpaceGB), "total_gb": float(r.TotalSpaceGB)} for r in cursor.fetchall()]

            # 2. DATABASES, BACKUP, AUTO-SHRINK
            db_query = """
                WITH BackupCTE AS (SELECT database_name, MAX(backup_finish_date) as LastBackup FROM msdb.dbo.backupset WHERE type = 'D' GROUP BY database_name)
                SELECT d.name AS DatabaseName, d.state_desc AS Status, ISNULL(SUM(mf.size * 8.0 / 1024), 0) AS Size_in_MB, d.log_reuse_wait_desc AS LogWait, d.is_auto_shrink_on AS IsAutoShrink, CASE WHEN d.name = 'tempdb' THEN 'N/A' WHEN b.LastBackup >= DATEADD(hh, -24, GETDATE()) THEN 'OK' ELSE 'MISSING' END AS BackupStatus
                FROM sys.databases d LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id LEFT JOIN BackupCTE b ON d.name = b.database_name
                WHERE d.database_id > 4 GROUP BY d.name, d.state_desc, d.log_reuse_wait_desc, d.is_auto_shrink_on, b.LastBackup;
            """
            cursor.execute(db_query)
            all_databases = []
            for row in cursor.fetchall():
                all_databases.append({
                    "name": row.DatabaseName, "status": row.Status, "size_mb": round(row.Size_in_MB, 2), "log_wait": row.LogWait, "backup_status": row.BackupStatus, "auto_shrink": True if row.IsAutoShrink == 1 else False, "log_used_pct": 0 
                })

            # 3. AG SYNC HEALTH
            ag_query = """
                SELECT DB_NAME(drs.database_id) AS DatabaseName, ar.replica_server_name AS SecondaryServer, drs.synchronization_state_desc AS SyncState, CAST(ISNULL(drs.log_send_queue_size, 0) / 1024.0 AS DECIMAL(18,2)) AS LogSendQueueMB, CAST(ISNULL(drs.redo_queue_size, 0) / 1024.0 AS DECIMAL(18,2)) AS RedoQueueMB
                FROM sys.dm_hadr_database_replica_states drs WITH (nolock) JOIN sys.availability_replicas ar WITH (nolock) ON drs.replica_id = ar.replica_id WHERE drs.is_local = 0;
            """
            cursor.execute(ag_query)
            ag_sync = []
            for row in cursor.fetchall():
                ag_sync.append({"database": row.DatabaseName, "secondary": row.SecondaryServer, "state": row.SyncState, "log_queue_mb": float(row.LogSendQueueMB), "redo_queue_mb": float(row.RedoQueueMB)})
                if float(row.LogSendQueueMB) > 500: alerts.append(f"🚨 CRITICAL: AG Replica '{row.SecondaryServer}' has a Log Send Queue of {row.LogSendQueueMB}MB for '{row.DatabaseName}'!")

            # 4. LOG FILE USAGE
            log_query = "SELECT RTRIM(instance_name) AS DatabaseName, cntr_value AS LogUsedPercent FROM sys.dm_os_performance_counters WHERE counter_name = 'Percent Log Used' AND instance_name NOT IN ('master', 'tempdb', 'model', 'msdb', '_Total');"
            cursor.execute(log_query)
            log_usage_dict = {row.DatabaseName: row.LogUsedPercent for row in cursor.fetchall()}
            for db in all_databases:
                if db['name'] in log_usage_dict: db['log_used_pct'] = log_usage_dict[db['name']]

            # 5. MEMORY HEALTH
            ple_query = "SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Page life expectancy' AND object_name LIKE '%Buffer Manager%';"
            cursor.execute(ple_query)
            ple_row = cursor.fetchone()
            if ple_row and ple_row.cntr_value < 300: alerts.append(f"🚨 CRITICAL: Memory Health (Page Life Expectancy) is dangerously low at {ple_row.cntr_value} seconds!")

            # 6. FAILED JOBS
            jobs_query = """
                WITH LatestRuns AS (
                    SELECT j.name AS JobName, h.run_status, msdb.dbo.agent_datetime(h.run_date, h.run_time) AS RunDateTime, h.message AS ErrorMessage, ROW_NUMBER() OVER(PARTITION BY j.job_id ORDER BY h.run_date DESC, h.run_time DESC) as rn
                    FROM msdb.dbo.sysjobhistory h WITH (nolock) JOIN msdb.dbo.sysjobs j WITH (nolock) ON h.job_id = j.job_id
                    WHERE h.step_id = 0 AND msdb.dbo.agent_datetime(h.run_date, h.run_time) >= DATEADD(hour, -24, GETDATE())
                )
                SELECT JobName, CONVERT(VARCHAR, RunDateTime, 120) AS FailDate, ErrorMessage FROM LatestRuns WHERE rn = 1 AND run_status = 0 ORDER BY RunDateTime DESC;
            """
            cursor.execute(jobs_query)
            failed_jobs = [{"job_name": r.JobName, "fail_date": r.FailDate, "error_message": r.ErrorMessage} for r in cursor.fetchall()]

            # 7. BLOCKING & LONG QUERIES
            blocking_query = """
                SELECT r.session_id, r.blocking_session_id, DB_NAME(r.database_id) AS DatabaseName, r.total_elapsed_time / 1000 AS SecondsRunning, t.text AS QueryText
                FROM sys.dm_exec_requests r CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t
                WHERE r.session_id > 50 AND r.status NOT IN ('background', 'sleeping') AND (r.blocking_session_id <> 0 OR r.total_elapsed_time > 60000);
            """
            cursor.execute(blocking_query)
            long_queries = []
            for row in cursor.fetchall():
                if row.blocking_session_id != 0: alerts.append(f"🚨 CRITICAL: Session {row.session_id} on '{row.DatabaseName}' is BLOCKED by Session {row.blocking_session_id}!")
                safe_query_text = str(row.QueryText) if row.QueryText else "N/A"
                if len(safe_query_text) > 300: safe_query_text = safe_query_text[:300] + " ... [TRUNCATED]"
                long_queries.append({"session_id": row.session_id, "database": row.DatabaseName, "seconds": row.SecondsRunning, "query_text": safe_query_text})

            # 8. SLEEPING TRANSACTIONS
            sleep_query = """
                SELECT st.session_id, DB_NAME(s.database_id) AS DatabaseName, DATEDIFF(SECOND, tat.transaction_begin_time, GETDATE()) AS SecondsRunning, t.text AS QueryText
                FROM sys.dm_tran_active_transactions tat WITH (nolock) INNER JOIN sys.dm_tran_session_transactions st WITH (nolock) ON tat.transaction_id = st.transaction_id
                INNER JOIN sys.dm_exec_sessions s WITH (nolock) ON s.session_id = st.session_id INNER JOIN sys.dm_exec_connections c WITH (nolock) ON c.session_id = st.session_id CROSS APPLY sys.dm_exec_sql_text(c.most_recent_sql_handle) t
                WHERE st.is_user_transaction = 1 AND s.status = 'sleeping' AND DATEDIFF(MINUTE, tat.transaction_begin_time, GETDATE()) > 5;
            """
            cursor.execute(sleep_query)
            for row in cursor.fetchall():
                if not any(q['session_id'] == row.session_id for q in long_queries):
                    alerts.append(f"🚨 CRITICAL: Session {row.session_id} on '{row.DatabaseName}' is SLEEPING with an open transaction for {row.SecondsRunning}s!")
                    safe_query_text = str(row.QueryText) if row.QueryText else "N/A"
                    if len(safe_query_text) > 300: safe_query_text = safe_query_text[:300] + " ... [TRUNCATED]"
                    long_queries.append({"session_id": row.session_id, "database": f"{row.DatabaseName} [SLEEPING]", "seconds": row.SecondsRunning, "query_text": safe_query_text})

            # 9. SYSADMIN AUDIT
            sysadmin_query = """
                SELECT sp.name AS LoginName, sp.type_desc AS LoginType, sp.is_disabled AS IsDisabled
                FROM sys.server_principals sp JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
                JOIN sys.server_principals spr ON srm.role_principal_id = spr.principal_id
                WHERE spr.name = 'sysadmin' AND sp.name NOT LIKE '##%';
            """
            cursor.execute(sysadmin_query)
            sysadmins = [{"login_name": r.LoginName, "login_type": r.LoginType, "is_disabled": r.IsDisabled} for r in cursor.fetchall()]

            # 10. RECENT RESTORES
            restore_query = """
                SELECT TOP 50 destination_database_name AS DatabaseName, CONVERT(VARCHAR, restore_date, 120) AS RestoreDate, user_name AS RestoredBy
                FROM msdb.dbo.restorehistory WHERE restore_date >= DATEADD(day, -7, GETDATE()) ORDER BY restore_date DESC;
            """
            cursor.execute(restore_query)
            recent_restores = [{"database": r.DatabaseName, "restore_date": r.RestoreDate, "restored_by": r.RestoredBy} for r in cursor.fetchall()]

            if len(alerts) == 0: alerts.append("✅ System is entirely healthy. No active alerts.")

            conn.close()

            return jsonify({
                "server_level_alerts": alerts, "drives": all_drives, "databases": all_databases, 
                "long_queries": long_queries, "ag_sync": ag_sync, "failed_jobs": failed_jobs,
                "sysadmins": sysadmins, "recent_restores": recent_restores
            })

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return jsonify({"error": "Unsupported database type"})

# ---------- POST-RESTORE SECURITY VALIDATOR ----------
@app.route('/api/security', methods=['GET'])
@login_required
def get_security():
    server_name = request.args.get('server')
    db_name = request.args.get('db')
    with open('config.json') as config_file: live_configs = json.load(config_file)
    if server_name not in live_configs: return jsonify({"error": "Server not found"}), 404
    config = live_configs[server_name]
    
    if config['type'] == 'sqlserver':
        try:
            server_address = config['host']
            if config.get('port') and str(config['port']).strip() != '': server_address = f"{server_address},{config['port']}"
            real_password = decrypt_password(config['password']) # DECRYPTED
            conn_str = (f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server_address};DATABASE={db_name};UID={config['user']};PWD={{{real_password}}};Encrypt=yes;TrustServerCertificate=yes;")
            conn = pyodbc.connect(conn_str, timeout=10)
            cursor = conn.cursor()
            
            orphaned_query = "SELECT dp.name AS UserName, dp.type_desc AS UserType FROM sys.database_principals dp LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid WHERE sp.sid IS NULL AND dp.type IN ('S', 'U', 'G') AND dp.principal_id > 4 AND dp.name NOT IN ('dbo', 'guest', 'sys', 'INFORMATION_SCHEMA');"
            cursor.execute(orphaned_query)
            orphaned_users = [{"user": r.UserName, "type": r.UserType} for r in cursor.fetchall()]

            owner_query = "SELECT dp.name AS UserName, dp.type_desc AS UserType FROM sys.database_role_members drm JOIN sys.database_principals dp ON drm.member_principal_id = dp.principal_id JOIN sys.database_principals rp ON drm.role_principal_id = rp.principal_id WHERE rp.name = 'db_owner' AND dp.name <> 'dbo';"
            cursor.execute(owner_query)
            db_owners = [{"user": r.UserName, "type": r.UserType} for r in cursor.fetchall()]
            
            conn.close()
            return jsonify({"orphaned": orphaned_users, "owners": db_owners})
        except Exception as e: return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Unsupported database type"})


# ---------- FETCH TABLES ----------
@app.route('/api/tables', methods=['GET'])
@login_required
def get_tables():
    server_name = request.args.get('server')
    db_name = request.args.get('db')
    with open('config.json') as config_file: live_configs = json.load(config_file)
    if server_name not in live_configs: return jsonify({"error": "Server not found"}), 404
    config = live_configs[server_name]
    
    if config['type'] == 'sqlserver':
        try:
            server_address = config['host']
            if config.get('port') and str(config['port']).strip() != '': server_address = f"{server_address},{config['port']}"
            real_password = decrypt_password(config['password']) # DECRYPTED
            conn_str = (f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server_address};DATABASE={db_name};UID={config['user']};PWD={{{real_password}}};Encrypt=yes;TrustServerCertificate=yes;")
            conn = pyodbc.connect(conn_str, timeout=10)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sys.tables WHERE is_ms_shipped = 0 ORDER BY name;")
            tables = [row.name for row in cursor.fetchall()]
            conn.close()
            return jsonify({"tables": tables})
        except Exception as e: return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Unsupported database type"})


# ---------- INDEX CHECKING ----------
@app.route('/api/indexes', methods=['GET'])
@login_required
def get_indexes():
    server_name = request.args.get('server')
    db_name = request.args.get('db')
    table_name = request.args.get('table', 'all')
    
    with open('config.json') as config_file: live_configs = json.load(config_file)
    if server_name not in live_configs: return jsonify({"error": "Server not found"}), 404
    config = live_configs[server_name]
    
    if config['type'] == 'sqlserver':
        try:
            server_address = config['host']
            if config.get('port') and str(config['port']).strip() != '': server_address = f"{server_address},{config['port']}"
            real_password = decrypt_password(config['password']) # DECRYPTED
            conn_str = (f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={server_address};DATABASE={db_name};UID={config['user']};PWD={{{real_password}}};Encrypt=yes;TrustServerCertificate=yes;")
            conn = pyodbc.connect(conn_str, timeout=10)
            cursor = conn.cursor()
            
            table_filter = ""
            params = []
            if table_name and table_name != 'all':
                table_filter = " AND OBJECT_NAME(i.object_id) = ? "
                params.append(table_name)

            index_query = f"""
                WITH LargeIndexes AS (
                    SELECT i.object_id, i.index_id, i.name AS IndexName, SUM(ps.used_page_count) AS TotalPages
                    FROM sys.indexes i WITH (NOLOCK) INNER JOIN sys.dm_db_partition_stats ps WITH (NOLOCK) ON i.object_id = ps.object_id AND i.index_id = ps.index_id
                    WHERE i.name IS NOT NULL {table_filter}
                    GROUP BY i.object_id, i.index_id, i.name
                    HAVING SUM(ps.used_page_count) > 1000
                )
                SELECT OBJECT_NAME(li.object_id) AS TableName, li.IndexName, ROUND(ips.avg_fragmentation_in_percent, 2) AS Fragmentation, ips.page_count AS PageCount
                FROM LargeIndexes li CROSS APPLY sys.dm_db_index_physical_stats(DB_ID(), li.object_id, li.index_id, NULL, 'LIMITED') ips
                WHERE ips.avg_fragmentation_in_percent > 10.0 ORDER BY ips.avg_fragmentation_in_percent DESC;
            """
            
            if params: cursor.execute(index_query, params)
            else: cursor.execute(index_query)
                
            indexes = [{"table": row.TableName, "index": row.IndexName, "fragmentation": row.Fragmentation, "pages": row.PageCount} for row in cursor.fetchall()]
            conn.close()
            return jsonify({"indexes": indexes})
        except Exception as e: return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Unsupported database type"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
