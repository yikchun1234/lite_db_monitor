from flask import Flask, jsonify, request, render_template, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.pool import NullPool
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps
from cryptography.fernet import Fernet
import json
import pyodbc
import os
import datetime
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ==========================================
# ⚙️ ARCHITECTURE: SQLITE LOCAL DATABASE
# ==========================================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class ServerConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(100), unique=True, nullable=False)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.String(10))
    type = db.Column(db.String(50), default="sqlserver")
    user = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(500), nullable=False)

class IndexCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_alias = db.Column(db.String(100), index=True)
    db_name = db.Column(db.String(100), index=True)
    table_name = db.Column(db.String(200))
    index_name = db.Column(db.String(200))
    fragmentation = db.Column(db.Float)
    page_count = db.Column(db.Integer)
    last_scanned = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class TableStatsCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server_alias = db.Column(db.String(100), index=True)
    db_name = db.Column(db.String(100))
    schema_name = db.Column(db.String(100))
    table_name = db.Column(db.String(200))
    total_rows = db.Column(db.BigInteger)
    cleanup_status = db.Column(db.String(100))
    last_update = db.Column(db.String(50))
    last_scan = db.Column(db.String(50))
    last_seek = db.Column(db.String(50))
    last_scanned = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# ==========================================
# 🔐 ADMIN CREDENTIALS & ENCRYPTION
# ==========================================
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin123!"
KEY_FILE = 'encryption.key'

if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as f:
        f.write(Fernet.generate_key())

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
        return cipher_text

# ==========================================
# 🔌 CONNECTION MANAGEMENT (NULL POOL)
# ==========================================
target_engines = {}

def get_target_engine(alias):
    if alias in target_engines:
        return target_engines[alias]
    
    server = ServerConfig.query.filter_by(alias=alias).first()
    if not server:
        return None
        
    pwd = decrypt_password(server.password)
    host_str = f"{server.host},{server.port}" if server.port else server.host
    
    conn_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={host_str};DATABASE=master;UID={server.user};PWD={pwd};Encrypt=yes;TrustServerCertificate=yes;"
    conn_url = URL.create("mssql+pyodbc", query={"odbc_connect": conn_str})
    
    engine = create_engine(conn_url, poolclass=NullPool)
    target_engines[alias] = engine
    return engine

# ==========================================
# ⏱️ BACKGROUND SCANNER LOGIC
# ==========================================
def perform_table_scan(server, engine, force=False):
    """Executes the cross-database Ghost Table query and updates the SQLite cache."""
    if not force:
        latest_cache = TableStatsCache.query.filter_by(server_alias=server.alias).order_by(TableStatsCache.last_scanned.desc()).first()
        if latest_cache:
            time_since_scan = datetime.datetime.utcnow() - latest_cache.last_scanned
            if time_since_scan.total_seconds() < (167 * 3600): 
                print(f"     [⏭️] Skipping Ghost Table Scan for: {server.alias} (Cache is under 7 days old)")
                return

    try:
        with engine.connect() as conn:
            safe_dbs_query = text("SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' AND database_id > 4 AND HAS_DBACCESS(name) = 1;")
            safe_dbs = [row['name'] for row in conn.execute(safe_dbs_query).mappings()]
            
            if not safe_dbs:
                return
                
            union_queries = []
            for db_name in safe_dbs:
                union_queries.append(f"""
                SELECT '{db_name}' COLLATE DATABASE_DEFAULT AS DatabaseName,
                       s.name COLLATE DATABASE_DEFAULT AS SchemaName,
                       t.name COLLATE DATABASE_DEFAULT AS TableName,
                       SUM(p.rows) AS TotalRows,
                       MAX(ius.last_user_update) AS LastUserUpdate,
                       MAX(ius.last_user_scan) AS LastUserScan,
                       MAX(ius.last_user_seek) AS LastUserSeek
                FROM [{db_name}].sys.tables t WITH (NOLOCK)
                INNER JOIN [{db_name}].sys.schemas s WITH (NOLOCK) ON t.schema_id = s.schema_id
                INNER JOIN [{db_name}].sys.partitions p WITH (NOLOCK) ON t.object_id = p.object_id AND p.index_id IN (0, 1)
                LEFT JOIN sys.dm_db_index_usage_stats ius WITH (NOLOCK) ON t.object_id = ius.object_id AND ius.database_id = DB_ID('{db_name}')
                WHERE t.is_ms_shipped = 0
                GROUP BY s.name, t.name
                """)
            
            final_query = " UNION ALL ".join(union_queries)
            
            wrapper_query = text(f"""
            WITH AllTables AS (
                {final_query}
            ),
            CategorizedTables AS (
                SELECT DatabaseName, SchemaName, TableName, TotalRows, LastUserUpdate, LastUserScan, LastUserSeek,
                CASE 
                    WHEN (LastUserUpdate IS NULL OR LastUserUpdate <= '2024-12-31') AND (LastUserScan IS NULL OR LastUserScan <= '2024-12-31') AND (LastUserSeek IS NULL OR LastUserSeek <= '2024-12-31') THEN 'SAFE TO PURGE: Dead Table'
                    WHEN (LastUserUpdate IS NULL OR LastUserUpdate <= '2024-12-31') AND (LastUserScan > '2024-12-31' OR LastUserSeek > '2024-12-31') THEN 'LOOK CLOSER: Read-Only / Lookup Table'
                    WHEN LastUserUpdate > '2024-12-31' THEN 'ACTIVE: Do Not Touch'
                    ELSE 'REVIEW: Unknown State' 
                END AS CleanupStatus
                FROM AllTables
                WHERE TotalRows > 0
            )
            SELECT TOP 300 
                DatabaseName, SchemaName, TableName, TotalRows, CleanupStatus,
                CONVERT(VARCHAR, LastUserUpdate, 120) AS LastUpdate,
                CONVERT(VARCHAR, LastUserScan, 120) AS LastScan,
                CONVERT(VARCHAR, LastUserSeek, 120) AS LastSeek
            FROM CategorizedTables
            WHERE CleanupStatus != 'ACTIVE: Do Not Touch'
            ORDER BY 
                CASE CleanupStatus
                    WHEN 'SAFE TO PURGE: Dead Table' THEN 1
                    WHEN 'LOOK CLOSER: Read-Only / Lookup Table' THEN 2
                    WHEN 'REVIEW: Unknown State' THEN 3
                END,
                DatabaseName, TotalRows DESC;
            """)
            
            results = conn.execute(wrapper_query).mappings()
            
            TableStatsCache.query.filter_by(server_alias=server.alias).delete()
            current_time = datetime.datetime.utcnow()
            
            for r in results:
                new_stat = TableStatsCache(
                    server_alias=server.alias,
                    db_name=r['DatabaseName'],
                    schema_name=r['SchemaName'],
                    table_name=r['TableName'],
                    total_rows=int(r['TotalRows'] or 0),
                    cleanup_status=r['CleanupStatus'],
                    last_update=r['LastUpdate'] or 'Never',
                    last_scan=r['LastScan'] or 'Never',
                    last_seek=r['LastSeek'] or 'Never',
                    last_scanned=current_time
                )
                db.session.add(new_stat)

            db.session.commit()
            
    except Exception as e:
        print(f"     [!] Error processing tables for {server.alias}: {str(e)}")
        db.session.rollback()

def perform_index_scan(server, engine):
    """Executes the throttled Index Fragmentation scan and updates the SQLite cache."""
    try:
        with engine.connect() as conn:
            dbs = conn.execute(text("SELECT name FROM sys.databases WHERE database_id > 4 AND state_desc = 'ONLINE'")).mappings()
            
            for db_row in dbs:
                db_name = db_row['name']
                
                latest_cache = IndexCache.query.filter_by(server_alias=server.alias, db_name=db_name).order_by(IndexCache.last_scanned.desc()).first()
                if latest_cache:
                    time_since_scan = datetime.datetime.utcnow() - latest_cache.last_scanned
                    if time_since_scan.total_seconds() < (167 * 3600):
                        print(f"     [⏭️] Skipping Index Scan for: {db_name} (Cache is active)")
                        continue

                print(f"     [🔎] Scanning Indexes: {db_name} (Throttled Mode)...")
                try:
                    pwd = decrypt_password(server.password)
                    host_str = f"{server.host},{server.port}" if server.port else server.host
                    raw_conn_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={host_str};DATABASE={db_name};UID={server.user};PWD={pwd};Encrypt=yes;TrustServerCertificate=yes;"
                    
                    with pyodbc.connect(raw_conn_str, timeout=30) as raw_conn:
                        cursor = raw_conn.cursor()
                        cursor.execute("SET DEADLOCK_PRIORITY LOW; SET LOCK_TIMEOUT 2000;")
                        
                        target_query = """
                        SELECT i.object_id, i.index_id, OBJECT_NAME(i.object_id) AS TableName, i.name AS IndexName
                        FROM sys.indexes i WITH (NOLOCK)
                        INNER JOIN sys.dm_db_partition_stats ps WITH (NOLOCK) ON i.object_id = ps.object_id AND i.index_id = ps.index_id
                        WHERE i.name IS NOT NULL
                        GROUP BY i.object_id, i.index_id, i.name, OBJECT_NAME(i.object_id)
                        HAVING SUM(ps.used_page_count) > 1000
                        """
                        cursor.execute(target_query)
                        targets = cursor.fetchall()
                        
                        IndexCache.query.filter_by(server_alias=server.alias, db_name=db_name).delete()
                        db.session.commit()
                        
                        current_time = datetime.datetime.utcnow()
                        found_fragmentation = False
                        
                        for t in targets:
                            try:
                                scan_query = f"""
                                SELECT ROUND(avg_fragmentation_in_percent, 2) AS Fragmentation, page_count AS PageCount
                                FROM sys.dm_db_index_physical_stats(DB_ID(), {t.object_id}, {t.index_id}, NULL, 'LIMITED')
                                WHERE avg_fragmentation_in_percent > 10.0;
                                """
                                cursor.execute(scan_query)
                                res = cursor.fetchone()
                                
                                if res:
                                    found_fragmentation = True
                                    new_idx = IndexCache(server_alias=server.alias, db_name=db_name, table_name=t.TableName, index_name=t.IndexName, fragmentation=res.Fragmentation, page_count=res.PageCount, last_scanned=current_time)
                                    db.session.add(new_idx)
                                    db.session.commit()
                                time.sleep(1.5)
                            except pyodbc.Error:
                                print(f"     [!] Skipped index {t.IndexName} due to locking.")
                                continue
                            except Exception as e:
                                print(f"     [!] Error processing {db_name}: {str(e)}")
                                db.session.rollback()
                                continue
                                
                        if not found_fragmentation:
                            clean_marker = IndexCache(
                                server_alias=server.alias, 
                                db_name=db_name, 
                                table_name="[System_Clean]", 
                                index_name="[No_Fragmentation]", 
                                fragmentation=0.0, 
                                page_count=0, 
                                last_scanned=current_time
                            )
                            db.session.add(clean_marker)
                            db.session.commit()
                                
                except Exception as e:
                    print(f"  [!] Error connecting to {server.alias}: {str(e)}")
    except Exception as e:
        print(f"  [!] Error connecting to {server.alias}: {str(e)}")

def master_background_scan():
    print(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🚀 STARTING MASTER BACKGROUND SCANS (TABLES -> INDEXES)...")
    with app.app_context():
        servers = ServerConfig.query.all()
        for server in servers:
            print(f"  -> Connecting to Server: {server.alias}...")
            engine = get_target_engine(server.alias)
            if not engine: continue
            
            print(f"     [1/2] Updating Ghost Table Cache...")
            perform_table_scan(server, engine)
            
            print(f"     [2/2] Updating Index Fragmentation Cache...")
            perform_index_scan(server, engine)
            
    print(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ✅ MASTER BACKGROUND SCAN COMPLETE.\n")

# ==========================================
# 🔐 SECURITY DECORATOR
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
    servers = ServerConfig.query.all()
    return jsonify([s.alias for s in servers])

@app.route('/api/servers/add', methods=['POST'])
@login_required
def add_server():
    try:
        new_server = request.json
        alias = new_server.get('alias')
        if not alias: return jsonify({"error": "Server Alias Name is required"}), 400
        if ServerConfig.query.filter_by(alias=alias).first(): return jsonify({"error": f"Server '{alias}' already exists!"}), 400
        
        server = ServerConfig(
            alias=alias, host=new_server.get("host", ""), port=new_server.get("port", ""), 
            type=new_server.get("type", "sqlserver"), user=new_server.get("user", ""), 
            password=encrypt_password(new_server.get("password", ""))
        )
        db.session.add(server)
        db.session.commit()
        return jsonify({"success": True, "message": f"Server '{alias}' added successfully!"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/servers/detail', methods=['GET'])
@login_required
def get_server_detail():
    alias = request.args.get('server')
    if not alias: return jsonify({"error": "No server provided"}), 400
    server = ServerConfig.query.filter_by(alias=alias).first()
    if server: return jsonify({"host": server.host, "port": server.port, "user": server.user})
    return jsonify({"error": "Server not found"}), 404

@app.route('/api/servers/edit', methods=['POST'])
@login_required
def edit_server():
    try:
        data = request.json
        original_alias = data.get('original_alias')
        new_alias = data.get('alias')
        
        if not original_alias or not new_alias: return jsonify({"error": "Server Alias Name is required"}), 400
        server = ServerConfig.query.filter_by(alias=original_alias).first()
        if not server: return jsonify({"error": "Server not found"}), 404
        if original_alias != new_alias and ServerConfig.query.filter_by(alias=new_alias).first(): return jsonify({"error": f"A server named '{new_alias}' already exists!"}), 400
        
        if original_alias != new_alias and original_alias in target_engines:
            del target_engines[original_alias]
        elif original_alias in target_engines:
            del target_engines[original_alias]

        server.alias = new_alias
        server.host = data.get('host', server.host)
        server.port = data.get('port', server.port)
        server.user = data.get('user', server.user)
        if data.get('password') and data.get('password').strip() != "":
            server.password = encrypt_password(data['password'])
            
        db.session.commit()
        return jsonify({"success": True, "message": f"Server '{new_alias}' updated!"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/servers/delete', methods=['POST'])
@login_required
def delete_server():
    try:
        alias = request.json.get('alias')
        server = ServerConfig.query.filter_by(alias=alias).first()
        if server:
            if alias in target_engines: del target_engines[alias]
            IndexCache.query.filter_by(server_alias=alias).delete()
            TableStatsCache.query.filter_by(server_alias=alias).delete()
            db.session.delete(server)
            db.session.commit()
            return jsonify({"success": True, "message": "Server deleted successfully."})
        return jsonify({"error": "Server not found"}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/metrics', methods=['GET'])
@login_required
def get_metrics():
    server_name = request.args.get('server')
    engine = get_target_engine(server_name)
    
    if not engine:
        return jsonify({"error": "Server not found or connection string invalid"}), 404

    try:
        with engine.connect() as conn:
            alerts = []
            
            drive_query = text("SELECT DISTINCT vs.volume_mount_point AS DriveLetter, CAST(vs.available_bytes AS FLOAT) / CAST(vs.total_bytes AS FLOAT) * 100 AS FreeSpacePercent, CAST(vs.available_bytes / 1048576.0 / 1024.0 AS DECIMAL(10,2)) AS FreeSpaceGB, CAST(vs.total_bytes / 1048576.0 / 1024.0 AS DECIMAL(10,2)) AS TotalSpaceGB FROM sys.master_files AS f CROSS APPLY sys.dm_os_volume_stats(f.database_id, f.file_id) AS vs;")
            all_drives = [{"letter": r['DriveLetter'], "free_percent": round(r['FreeSpacePercent'], 2), "free_gb": float(r['FreeSpaceGB']), "total_gb": float(r['TotalSpaceGB'])} for r in conn.execute(drive_query).mappings()]
            
            db_query = text("WITH BackupCTE AS (SELECT database_name, MAX(backup_finish_date) as LastBackup FROM msdb.dbo.backupset WHERE type = 'D' GROUP BY database_name) SELECT d.name AS DatabaseName, d.state_desc AS Status, ISNULL(SUM(mf.size * 8.0 / 1024), 0) AS Size_in_MB, d.log_reuse_wait_desc AS LogWait, d.is_auto_shrink_on AS IsAutoShrink, CASE WHEN d.name = 'tempdb' THEN 'N/A' WHEN b.LastBackup >= DATEADD(hh, -24, GETDATE()) THEN 'OK' ELSE 'MISSING' END AS BackupStatus FROM sys.databases d LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id LEFT JOIN BackupCTE b ON d.name = b.database_name WHERE d.database_id > 4 GROUP BY d.name, d.state_desc, d.log_reuse_wait_desc, d.is_auto_shrink_on, b.LastBackup;")
            all_databases = [{"name": row['DatabaseName'], "status": row['Status'], "size_mb": round(row['Size_in_MB'], 2), "log_wait": row['LogWait'], "backup_status": row['BackupStatus'], "auto_shrink": True if row['IsAutoShrink'] == 1 else False, "log_used_pct": 0} for row in conn.execute(db_query).mappings()]
            
            ag_query = text("SELECT DB_NAME(drs.database_id) AS DatabaseName, ar.replica_server_name AS SecondaryServer, drs.synchronization_state_desc AS SyncState, CAST(ISNULL(drs.log_send_queue_size, 0) / 1024.0 AS DECIMAL(18,2)) AS LogSendQueueMB, CAST(ISNULL(drs.redo_queue_size, 0) / 1024.0 AS DECIMAL(18,2)) AS RedoQueueMB FROM sys.dm_hadr_database_replica_states drs WITH (nolock) JOIN sys.availability_replicas ar WITH (nolock) ON drs.replica_id = ar.replica_id WHERE drs.is_local = 0;")
            ag_sync = [{"database": r['DatabaseName'], "secondary": r['SecondaryServer'], "state": r['SyncState'], "log_queue_mb": float(r['LogSendQueueMB']), "redo_queue_mb": float(r['RedoQueueMB'])} for r in conn.execute(ag_query).mappings()]
            
            log_query = text("SELECT RTRIM(instance_name) AS DatabaseName, cntr_value AS LogUsedPercent FROM sys.dm_os_performance_counters WHERE counter_name = 'Percent Log Used' AND instance_name NOT IN ('master', 'tempdb', 'model', 'msdb', '_Total');")
            log_usage_dict = {row['DatabaseName']: row['LogUsedPercent'] for row in conn.execute(log_query).mappings()}
            for db in all_databases:
                if db['name'] in log_usage_dict:
                    db['log_used_pct'] = log_usage_dict[db['name']]
                    
            ple_query = text("SELECT cntr_value FROM sys.dm_os_performance_counters WHERE counter_name = 'Page life expectancy' AND object_name LIKE '%Buffer Manager%';")
            ple_row = conn.execute(ple_query).mappings().first()
            if ple_row and ple_row['cntr_value'] < 300:
                alerts.append(f"🚨 CRITICAL: Memory Health (Page Life Expectancy) is dangerously low at {ple_row['cntr_value']} seconds!")
                
            jobs_query = text("WITH LatestRuns AS (SELECT j.name AS JobName, h.run_status, msdb.dbo.agent_datetime(h.run_date, h.run_time) AS RunDateTime, h.message AS ErrorMessage, ROW_NUMBER() OVER(PARTITION BY j.job_id ORDER BY h.run_date DESC, h.run_time DESC) as rn FROM msdb.dbo.sysjobhistory h WITH (nolock) JOIN msdb.dbo.sysjobs j WITH (nolock) ON h.job_id = j.job_id WHERE h.step_id = 0 AND msdb.dbo.agent_datetime(h.run_date, h.run_time) >= DATEADD(hour, -24, GETDATE())) SELECT JobName, CONVERT(VARCHAR, RunDateTime, 120) AS FailDate, ErrorMessage FROM LatestRuns WHERE rn = 1 AND run_status = 0 ORDER BY RunDateTime DESC;")
            failed_jobs = [{"job_name": r['JobName'], "fail_date": r['FailDate'], "error_message": r['ErrorMessage']} for r in conn.execute(jobs_query).mappings()]
            
            blocking_query = text("SELECT r.session_id, r.blocking_session_id, DB_NAME(r.database_id) AS DatabaseName, r.total_elapsed_time / 1000 AS SecondsRunning, t.text AS QueryText FROM sys.dm_exec_requests r CROSS APPLY sys.dm_exec_sql_text(r.sql_handle) t WHERE r.session_id > 50 AND r.status NOT IN ('background', 'sleeping') AND (r.blocking_session_id <> 0 OR r.total_elapsed_time > 60000);")
            long_queries = []
            for row in conn.execute(blocking_query).mappings():
                safe_query_text = str(row['QueryText']) if row['QueryText'] else "N/A"
                if len(safe_query_text) > 300: safe_query_text = safe_query_text[:300] + " ... [TRUNCATED]"
                long_queries.append({"session_id": row['session_id'], "database": row['DatabaseName'], "seconds": row['SecondsRunning'], "query_text": safe_query_text})
                
            sysadmin_query = text("SELECT sp.name AS LoginName, sp.type_desc AS LoginType, sp.is_disabled AS IsDisabled FROM sys.server_principals sp JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id JOIN sys.server_principals spr ON srm.role_principal_id = spr.principal_id WHERE spr.name = 'sysadmin' AND sp.name NOT LIKE '##%';")
            sysadmins = [{"login_name": r['LoginName'], "login_type": r['LoginType'], "is_disabled": r['IsDisabled']} for r in conn.execute(sysadmin_query).mappings()]
            
            restore_query = text("SELECT TOP 50 destination_database_name AS DatabaseName, CONVERT(VARCHAR, restore_date, 120) AS RestoreDate, user_name AS RestoredBy FROM msdb.dbo.restorehistory WHERE restore_date >= DATEADD(day, -7, GETDATE()) ORDER BY restore_date DESC;")
            recent_restores = [{"database": r['DatabaseName'], "restore_date": r['RestoreDate'], "restored_by": r['RestoredBy']} for r in conn.execute(restore_query).mappings()]
            
            cpu_query = text("SELECT TOP (1) record.value('(./Record/SchedulerMonitorEvent/SystemHealth/ProcessUtilization)[1]', 'int') AS SQL_CPU, record.value('(./Record/SchedulerMonitorEvent/SystemHealth/SystemIdle)[1]', 'int') AS SystemIdle_CPU FROM (SELECT CAST(record AS xml) AS record FROM sys.dm_os_ring_buffers WITH (NOLOCK) WHERE ring_buffer_type = N'RING_BUFFER_SCHEDULER_MONITOR' AND record LIKE '%<SystemHealth>%') AS x ORDER BY record.value('(./Record/@id)[1]', 'int') DESC;")
            cpu_row = conn.execute(cpu_query).mappings().first()
            cpu_stats = {"sql_cpu": int(cpu_row['SQL_CPU']) if cpu_row else 0, "idle_cpu": int(cpu_row['SystemIdle_CPU']) if cpu_row else 0}
            if cpu_stats["sql_cpu"] > 90: alerts.append(f"🚨 CRITICAL: SQL Server CPU is dangerously high at {cpu_stats['sql_cpu']}%!")
            
            wait_query = text("WITH Waits AS (SELECT wait_type, CAST(wait_time_ms / 1000.0 AS DECIMAL(12,2)) AS WaitTime_Sec, CAST((wait_time_ms * 100.0) / SUM(wait_time_ms) OVER() AS DECIMAL(5,2)) AS Percentage FROM sys.dm_os_wait_stats WITH (NOLOCK) WHERE wait_type NOT IN ('CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'RESOURCE_QUEUE', 'SLEEP_TASK', 'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH', 'WAITFOR', 'LOGMGR_QUEUE', 'CHECKPOINT_QUEUE', 'REQUEST_FOR_DEADLOCK_SEARCH', 'XE_TIMER_EVENT', 'BROKER_TO_FLUSH', 'BROKER_TASK_STOP', 'CLR_MANUAL_EVENT', 'CLR_AUTO_EVENT', 'DISPATCHER_QUEUE_SEMAPHORE', 'FT_IFTS_SCHEDULER_IDLE_WAIT', 'XE_DISPATCHER_WAIT', 'XE_DISPATCHER_JOIN', 'DIRTY_PAGE_POLL', 'SP_SERVER_DIAGNOSTICS_SLEEP', 'HADR_FILESTREAM_IOMGR_IOCOMPLETION', 'QDS_PERSIST_TASK_MAIN_LOOP_SLEEP', 'QDS_ASYNC_QUEUE', 'VDI_CLIENT_OTHER') AND wait_time_ms > 0) SELECT TOP 5 wait_type, WaitTime_Sec, Percentage FROM Waits ORDER BY WaitTime_Sec DESC;")
            wait_stats = [{"wait_type": r['wait_type'], "wait_time_sec": float(r['WaitTime_Sec']), "percentage": float(r['Percentage'])} for r in conn.execute(wait_query).mappings()]
            
            tempdb_query = text("SELECT CAST(SUM(user_object_reserved_page_count) * 8.0 / 1024 AS DECIMAL(10,2)) AS UserObjects_MB, CAST(SUM(internal_object_reserved_page_count) * 8.0 / 1024 AS DECIMAL(10,2)) AS InternalObjects_MB, CAST(SUM(version_store_reserved_page_count) * 8.0 / 1024 AS DECIMAL(10,2)) AS VersionStore_MB, CAST(SUM(unallocated_extent_page_count) * 8.0 / 1024 AS DECIMAL(10,2)) AS FreeSpace_MB FROM tempdb.sys.dm_db_file_space_usage WITH (NOLOCK);")
            t_row = conn.execute(tempdb_query).mappings().first()
            contention_row = conn.execute(text("SELECT COUNT(*) AS Active_Tasks FROM sys.dm_os_waiting_tasks WITH (NOLOCK) WHERE resource_description LIKE '2:%' AND wait_type LIKE 'PAGE%LATCH%';")).mappings().first()
            tempdb_health = {"user_mb": float(t_row['UserObjects_MB']) if t_row else 0, "internal_mb": float(t_row['InternalObjects_MB']) if t_row else 0, "version_mb": float(t_row['VersionStore_MB']) if t_row else 0, "free_mb": float(t_row['FreeSpace_MB']) if t_row else 0, "contention_tasks": int(contention_row['Active_Tasks']) if contention_row else 0}
            if tempdb_health["contention_tasks"] > 10: alerts.append(f"⚠️ WARNING: TempDB Contention! {tempdb_health['contention_tasks']} tasks are bottlenecked waiting for allocations.")
            
            suspect_pages = [{"db_name": r['DBName'], "file_id": r['file_id'], "page_id": r['page_id'], "event_type": r['event_type'], "errors": r['error_count']} for r in conn.execute(text("SELECT DB_NAME(database_id) as DBName, file_id, page_id, event_type, error_count FROM msdb.dbo.suspect_pages WITH (NOLOCK) WHERE event_type IN (1, 2, 3);")).mappings()]
            if len(suspect_pages) > 0: alerts.append(f"🚨 CRITICAL: Database corruption detected! Found {len(suspect_pages)} corrupted pages.")
            
            uptime_query = text("SELECT sqlserver_start_time, DATEDIFF(DAY, sqlserver_start_time, GETDATE()) AS UptimeDays, @@VERSION AS Version FROM sys.dm_os_sys_info WITH (NOLOCK);")
            u_row = conn.execute(uptime_query).mappings().first()
            server_info = {"start_time": u_row['sqlserver_start_time'].strftime('%Y-%m-%d %H:%M') if u_row and u_row['sqlserver_start_time'] else 'Unknown', "uptime_days": u_row['UptimeDays'] if u_row else 0, "version": u_row['Version'].split('\n')[0] if u_row else 'Unknown'}
            
            conn_query = text("SELECT DB_NAME(dbid) as DatabaseName, COUNT(dbid) as ConnectionCount, loginame as LoginName FROM sys.sysprocesses WITH (NOLOCK) WHERE dbid > 4 GROUP BY dbid, loginame ORDER BY ConnectionCount DESC;")
            active_connections = [{"database": r['DatabaseName'], "count": r['ConnectionCount'], "login": r['LoginName']} for r in conn.execute(conn_query).mappings() if r['DatabaseName']]
            
            missing_idx_query = text("SELECT TOP 5 DB_NAME(mid.database_id) AS DatabaseName, mid.statement AS TableName, CAST(migs.avg_user_impact AS DECIMAL(5,2)) AS ImprovementPercent, 'CREATE INDEX IX_Suggested ON ' + mid.statement + ' (' + ISNULL(mid.equality_columns, '') + CASE WHEN mid.equality_columns IS NOT NULL AND mid.inequality_columns IS NOT NULL THEN ', ' ELSE '' END + ISNULL(mid.inequality_columns, '') + ')' + ISNULL(' INCLUDE (' + mid.included_columns + ')', '') AS CreateIndexStatement FROM sys.dm_db_missing_index_group_stats migs WITH (NOLOCK) INNER JOIN sys.dm_db_missing_index_groups mig WITH (NOLOCK) ON migs.group_handle = mig.index_group_handle INNER JOIN sys.dm_db_missing_index_details mid WITH (NOLOCK) ON mig.index_handle = mid.index_handle WHERE migs.avg_user_impact > 50.0 ORDER BY migs.avg_user_impact DESC;")
            missing_indexes = [{"database": r['DatabaseName'], "table": r['TableName'], "impact": float(r['ImprovementPercent']), "script": r['CreateIndexStatement']} for r in conn.execute(missing_idx_query).mappings()]
            
            ram_usage = []
            
            running_jobs_query = text("SELECT j.name AS JobName, ja.start_execution_date AS StartTime, DATEDIFF(MINUTE, ja.start_execution_date, GETDATE()) AS MinutesRunning FROM msdb.dbo.sysjobactivity ja WITH (NOLOCK) JOIN msdb.dbo.sysjobs j WITH (NOLOCK) ON ja.job_id = j.job_id WHERE ja.start_execution_date IS NOT NULL AND ja.stop_execution_date IS NULL AND ja.session_id = (SELECT TOP 1 session_id FROM msdb.dbo.syssessions ORDER BY agent_start_date DESC);")
            running_jobs = [{"job_name": r['JobName'], "start_time": r['StartTime'].strftime('%Y-%m-%d %H:%M:%S') if r['StartTime'] else '', "minutes_running": int(r['MinutesRunning']) if r['MinutesRunning'] else 0} for r in conn.execute(running_jobs_query).mappings()]
            
            io_query = text("""
            WITH IOLatency AS (
                SELECT DB_NAME(vfs.database_id) AS DatabaseName, LEFT(mf.physical_name, 2) AS Drive, 
                SUM(CAST(vfs.io_stall_read_ms AS BIGINT)) AS TotalReadStall, SUM(CAST(vfs.num_of_reads AS BIGINT)) AS TotalReads, 
                SUM(CAST(vfs.io_stall_write_ms AS BIGINT)) AS TotalWriteStall, SUM(CAST(vfs.num_of_writes AS BIGINT)) AS TotalWrites 
                FROM sys.dm_io_virtual_file_stats(NULL, NULL) AS vfs JOIN sys.master_files AS mf WITH (NOLOCK) ON vfs.database_id = mf.database_id AND vfs.file_id = mf.file_id 
                GROUP BY DB_NAME(vfs.database_id), LEFT(mf.physical_name, 2)
            ) 
            SELECT TOP 10 DatabaseName, Drive, CASE WHEN TotalReads = 0 THEN 0 ELSE (TotalReadStall / TotalReads) END AS ReadLatency_ms, CASE WHEN TotalWrites = 0 THEN 0 ELSE (TotalWriteStall / TotalWrites) END AS WriteLatency_ms FROM IOLatency ORDER BY ((CASE WHEN TotalReads = 0 THEN 0 ELSE (TotalReadStall / TotalReads) END) + (CASE WHEN TotalWrites = 0 THEN 0 ELSE (TotalWriteStall / TotalWrites) END)) DESC;
            """)
            io_latency = [{"database": r['DatabaseName'], "drive": r['Drive'], "read_ms": int(r['ReadLatency_ms']), "write_ms": int(r['WriteLatency_ms'])} for r in conn.execute(io_query).mappings() if r['DatabaseName']]

            try:
                error_logs = [{"log_date": r[0].strftime('%Y-%m-%d %H:%M:%S') if r[0] else '', "process": r[1], "message": r[2]} for r in conn.execute(text("DECLARE @ts DATETIME = DATEADD(hh, -4, GETDATE()); EXEC xp_readerrorlog 0, 1, N'Error', NULL, @ts;")).fetchall()][:10]
            except Exception:
                error_logs = [{"log_date": "N/A", "process": "Access Denied", "message": "Monitoring account requires VIEW SERVER STATE or SecurityAdmin to read error logs."}]
                
            try:
                brute_force_logs = [{"log_date": r[0].strftime('%Y-%m-%d %H:%M:%S') if r[0] else '', "process": r[1], "message": r[2]} for r in conn.execute(text("DECLARE @ts DATETIME = DATEADD(hh, -4, GETDATE()); EXEC xp_readerrorlog 0, 1, N'Login failed', NULL, @ts;")).fetchall()][:10]
                if len(brute_force_logs) > 5: alerts.append(f"⚠️ SECURITY WARNING: Detected multiple 'Login failed' errors in the last 4 hours. Check for misconfigured apps or brute-force attempts.")
            except Exception:
                brute_force_logs = []

            # --- 🚀 NEW: LIVE, ULTRA-FAST DATABASE PURGE METRICS ---
            db_purge_live_query = text("""
            WITH AggregateUsage AS (
                SELECT 
                    database_id, 
                    MAX(last_user_seek) AS MaxSeek, 
                    MAX(last_user_scan) AS MaxScan, 
                    MAX(last_user_lookup) AS MaxLookup, 
                    MAX(last_user_update) AS MaxUpdate
                FROM sys.dm_db_index_usage_stats 
                GROUP BY database_id
            )
            SELECT 
                d.name AS DatabaseName,
                ISNULL(CONVERT(VARCHAR, u.MaxUpdate, 120), 'Never') AS LastWrite,
                ISNULL(CONVERT(VARCHAR, (SELECT MAX(v) FROM (VALUES (u.MaxSeek), (u.MaxScan), (u.MaxLookup)) AS value(v)), 120), 'Never') AS LastRead,
                CASE 
                    WHEN (u.MaxUpdate IS NULL OR u.MaxUpdate <= '2024-12-31') 
                     AND (u.MaxScan IS NULL OR u.MaxScan <= '2024-12-31') 
                     AND (u.MaxSeek IS NULL OR u.MaxSeek <= '2024-12-31') 
                     AND (u.MaxLookup IS NULL OR u.MaxLookup <= '2024-12-31') 
                    THEN 'SAFE TO RENAME/DETACH (Monitor 1-2 Weeks)'
                    ELSE 'ACTIVE: DB has activity'
                END AS ActionPlan
            FROM sys.databases d
            LEFT JOIN AggregateUsage u ON d.database_id = u.database_id
            WHERE d.database_id > 4 AND d.state_desc = 'ONLINE' AND d.name NOT IN ('ReportServer', 'ReportServerTempDB')
            ORDER BY ActionPlan DESC, d.name;
            """)
            db_purge_stats = [{"database": r['DatabaseName'], "last_read": r['LastRead'], "last_write": r['LastWrite'], "action_plan": r['ActionPlan']} for r in conn.execute(db_purge_live_query).mappings()]


            # --- FETCH GHOST TABLES FROM SQLITE CACHE ---
            cached_tables = TableStatsCache.query.filter_by(server_alias=server_name).all()
            table_stats = []
            table_cache_time = "Never"
            
            if cached_tables:
                time_diff = datetime.datetime.utcnow() - cached_tables[0].last_scanned
                hours_ago = int(time_diff.total_seconds() / 3600)
                if hours_ago < 1: table_cache_time = "Just now"
                elif hours_ago < 24: table_cache_time = f"{hours_ago} hour(s) ago"
                else: table_cache_time = f"{hours_ago // 24} day(s) ago"
                
                for ts in cached_tables:
                    table_stats.append({
                        "database": ts.db_name, "schema": ts.schema_name, "table": ts.table_name,
                        "rows": ts.total_rows, "status": ts.cleanup_status, "last_update": ts.last_update,
                        "last_scan": ts.last_scan, "last_seek": ts.last_seek
                    })
            
            if len(alerts) == 0: alerts.append("✅ System is entirely healthy. No active alerts.")

            return jsonify({
                "server_level_alerts": alerts, "server_info": server_info, "drives": all_drives,
                "databases": all_databases, "long_queries": long_queries, "ag_sync": ag_sync,
                "failed_jobs": failed_jobs, "sysadmins": sysadmins, "recent_restores": recent_restores,
                "cpu_stats": cpu_stats, "wait_stats": wait_stats, "tempdb_health": tempdb_health,
                "suspect_pages": suspect_pages, "active_connections": active_connections, 
                "missing_indexes": missing_indexes, "error_logs": error_logs, "ram_usage": ram_usage, 
                "running_jobs": running_jobs, "io_latency": io_latency, "brute_force": brute_force_logs,
                "table_usage_stats": table_stats, "table_cache_time": table_cache_time,
                "db_purge_stats": db_purge_stats
            })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/tables/refresh_cache', methods=['POST'])
@login_required
def refresh_table_cache():
    server_alias = request.json.get('server')
    if not server_alias: return jsonify({"error": "No server specified"}), 400
    
    server = ServerConfig.query.filter_by(alias=server_alias).first()
    engine = get_target_engine(server_alias)
    if not server or not engine: return jsonify({"error": "Server connection invalid"}), 400
    
    perform_table_scan(server, engine, force=True) 
    return jsonify({"success": True})

# ---------- FETCH TABLES ----------
@app.route('/api/tables', methods=['GET'])
@login_required
def get_tables():
    server_name = request.args.get('server')
    db_name = request.args.get('db')
    
    engine = get_target_engine(server_name)
    if not engine: return jsonify({"error": "Server not found"}), 404
    
    try:
        with engine.connect() as conn:
            conn.execute(text(f"USE [{db_name}]"))
            tables = [row['name'] for row in conn.execute(text("SELECT name FROM sys.tables WHERE is_ms_shipped = 0 ORDER BY name;")).mappings()]
            return jsonify({"tables": tables})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------- CACHED INDEX CHECKING ----------
@app.route('/api/indexes', methods=['GET'])
@login_required
def get_indexes():
    server_name = request.args.get('server')
    db_name = request.args.get('db')
    table_name = request.args.get('table', 'all')
    
    query = IndexCache.query.filter_by(server_alias=server_name, db_name=db_name)
    if table_name and table_name != 'all': query = query.filter_by(table_name=table_name)
    cached_results = query.all()
    
    if cached_results:
        indexes = [{"table": r.table_name, "index": r.index_name, "fragmentation": r.fragmentation, "pages": r.page_count} for r in cached_results if r.table_name != "[System_Clean]"]
        return jsonify({"indexes": indexes, "cached": True})
        
    engine = get_target_engine(server_name)
    if not engine: return jsonify({"error": "Server not found"}), 404
    
    try:
        with engine.connect() as conn:
            conn.execute(text(f"USE [{db_name}]"))
            table_filter = " AND OBJECT_NAME(i.object_id) = :t_name " if table_name and table_name != 'all' else ""
            
            index_query = text(f"WITH LargeIndexes AS (SELECT i.object_id, i.index_id, i.name AS IndexName, SUM(ps.used_page_count) AS TotalPages FROM sys.indexes i WITH (NOLOCK) INNER JOIN sys.dm_db_partition_stats ps WITH (NOLOCK) ON i.object_id = ps.object_id AND i.index_id = ps.index_id WHERE i.name IS NOT NULL {table_filter} GROUP BY i.object_id, i.index_id, i.name HAVING SUM(ps.used_page_count) > 1000) SELECT OBJECT_NAME(li.object_id) AS TableName, li.IndexName, ROUND(ips.avg_fragmentation_in_percent, 2) AS Fragmentation, ips.page_count AS PageCount FROM LargeIndexes li CROSS APPLY sys.dm_db_index_physical_stats(DB_ID(), li.object_id, li.index_id, NULL, 'LIMITED') ips WHERE ips.avg_fragmentation_in_percent > 10.0 ORDER BY ips.avg_fragmentation_in_percent DESC;")
            
            indexes = []
            params = {"t_name": table_name} if table_name and table_name != 'all' else {}
            for row in conn.execute(index_query, params).mappings():
                indexes.append({"table": row['TableName'], "index": row['IndexName'], "fragmentation": row['Fragmentation'], "pages": row['PageCount']})
            return jsonify({"indexes": indexes, "cached": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------- POST-RESTORE SECURITY VALIDATOR ----------
@app.route('/api/security', methods=['GET'])
@login_required
def get_security():
    server_name = request.args.get('server')
    db_name = request.args.get('db')
    
    engine = get_target_engine(server_name)
    if not engine: return jsonify({"error": "Server not found"}), 404
        
    try:
        with engine.connect() as conn:
            conn.execute(text(f"USE [{db_name}]"))
            orphaned = [{"user": r['UserName'], "type": r['UserType']} for r in conn.execute(text("SELECT dp.name AS UserName, dp.type_desc AS UserType FROM sys.database_principals dp LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid WHERE sp.sid IS NULL AND dp.type IN ('S', 'U', 'G') AND dp.principal_id > 4 AND dp.name NOT IN ('dbo', 'guest', 'sys', 'INFORMATION_SCHEMA');")).mappings()]
            owners = [{"user": r['UserName'], "type": r['UserType']} for r in conn.execute(text("SELECT dp.name AS UserName, dp.type_desc AS UserType FROM sys.database_role_members drm JOIN sys.database_principals dp ON drm.member_principal_id = dp.principal_id JOIN sys.database_principals rp ON drm.role_principal_id = rp.principal_id WHERE rp.name = 'db_owner' AND dp.name <> 'dbo';")).mappings()]
            return jsonify({"orphaned": orphaned, "owners": owners})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 🚀 INITIALIZATION & MIGRATION
# ==========================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
    if os.path.exists('config.json'):
        try:
            with open('config.json', 'r') as f:
                old_configs = json.load(f)
            for alias, c in old_configs.items():
                if not ServerConfig.query.filter_by(alias=alias).first():
                    server = ServerConfig(alias=alias, host=c.get("host"), port=c.get("port"), type=c.get("type", "sqlserver"), user=c.get("user"), password=c.get("password"))
                    db.session.add(server)
            db.session.commit()
            os.rename('config.json', 'config.json.backup_migrated')
            print("✅ Successfully migrated config.json to SQLite database.")
        except Exception as e:
            print(f"Migration error: {e}")

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=master_background_scan, trigger="interval", days=7, next_run_time=datetime.datetime.now())
    scheduler.start()

    app.run(host='0.0.0.0', port=5000, threaded=True)
