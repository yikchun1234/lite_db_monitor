<div align="center">
  <h1>📊 Lite DB Health Monitor (MSSQL)</h1>
  <p><i>A lightweight, zero-footprint web dashboard for real-time monitoring of SQL Server health, security, and performance.</i></p>

  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/SQL_Server-CC292B?style=for-the-badge&logo=microsoft-sql-server&logoColor=white" alt="SQL Server">
  <img src="https://img.shields.io/badge/License-Non--Commercial-red?style=for-the-badge" alt="License">
  
  <br>
  
  <img src="https://img.shields.io/badge/Flask-black?style=for-the-badge&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite">
  <img src="https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="Windows">

  <br><br>

  <img src="https://img.shields.io/github/last-commit/yikchun1234/lite_db_health_monitor_mssql?style=for-the-badge" alt="Last Commit">
  <img src="https://img.shields.io/github/repo-size/yikchun1234/lite_db_health_monitor_mssql?style=for-the-badge" alt="Repo Size">
</div>

---

### 🚀 Key Features

* **⚡ Live Performance Metrics:** Monitor CPU utilization, Wait Statistics, and TempDB contention in real-time.
* **💽 Disk & I/O Tracking:** Automated tracking of drive space and aggregated physical disk I/O latency.
* **🛡️ Security Auditing:** Detect brute-force login attempts, orphaned users, and sysadmin logins instantly.
* **🔎 Smart Index Scanner:** Background-cached index fragmentation analysis with **Zero-Impact** on production performance.
* **👻 Ghost Table Hunter:** Automatically categorizes tables based on last read/write timestamps to safely identify dead tables for archiving.
* **⏱️ Active Queries:** Identify long-running, blocked, or high-resource sessions at a glance.

---

### 📋 Prerequisites

Before running the application, ensure you have the following installed:

1. **Python 3.x:** [Download here](https://www.python.org/downloads/)
2. **ODBC Driver 17 for SQL Server:** Necessary for the Python-to-SQL connection.

---

### 🛠️ Installation & Setup

**1. Clone the Repository:**

    git clone https://github.com/yikchun1234/lite_db_health_monitor_mssql.git
    cd lite_db_health_monitor_mssql

**2. Install Dependencies:**

    pip install -r requirements.txt

**3. Configure Environment:**
* Open `.env.example` and fill in your desired Admin credentials.
* **Rename** `.env.example` to `.env`.

**4. Launch the Dashboard:**
* Simply double-click `start_dashboard.bat` (or run `python app.py`).

---

### 🖥️ How to Use

1. **Access the UI:** Open your browser to `http://localhost:5000`.
2. **Login:** Use the credentials defined in your `.env` file.
3. **Add Servers:** Use the **"+"** button to securely register your SQL Server instances (Passwords are encrypted locally in SQLite).
4. **Refresh:** Select your server and click **Refresh Dashboard** for live data.

> [!CAUTION]
> **Security Warning:** Never upload your `monitor.db` or `encryption.key` to public repositories. These files contain your encrypted server credentials and are blocked by the `.gitignore` file included in this repo.

---

### 📄 License & Usage

* **Non-Commercial Use Only:** This project is strictly for personal, educational, and non-commercial use. You may not use this application or its source code for any business, commercial, or monetized purposes.
* **Forks & Attribution:** You are welcome to fork, modify, and experiment with this code for your own personal projects! However, if you share your forked version, **you must provide proper citation** to the original author (Amos) and include a direct link back to this repository.

---

<div align="center">
  <b>Designed and Developed by Amos</b><br>
  <i>Protecting production one query at a time.</i>
</div>
