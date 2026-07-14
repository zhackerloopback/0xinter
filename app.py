import time
import secrets
import re
import ipaddress
import os
import hashlib
import socket

import exifread
import sqlite3
import whois
import dns.resolver
import csv
import requests
import pycountry
import yara
import ast
import json 
import shodan
from dotenv import load_dotenv

VT_API_KEY = os.getenv(
    "VT_API_KEY"
)

OTX_API_KEY = os.getenv(
    "OTX_API_KEY"
)

SHODAN_API_KEY = os.getenv(
    "SHODAN_API_KEY"
)
ABUSE_API_KEY = os.getenv(
    "ABUSE_API_KEY"
)


load_dotenv()

from config import SHODAN_API_KEY
from flask import send_from_directory
from email.parser import Parser


from itsdangerous import (
    URLSafeTimedSerializer
)



from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import ABUSE_API_KEY
from config import VT_API_KEY
from config import OTX_API_KEY
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash,
    jsonify
    
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet
from flask import send_file
from datetime import datetime
from werkzeug.utils import secure_filename
from PIL import Image
from datetime import timedelta


# =========================
# MITRE ATT&CK DATABASE
# =========================

MITRE_ATTACK = {

    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversary sends phishing emails."
    },

    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Uses HTTP, DNS or other protocols for C2."
    },

    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": "User executes malicious file."
    },

    "T1583": {
        "name": "Acquire Infrastructure",
        "tactic": "Resource Development",
        "description": "Attacker acquires domains or servers."
    }

}

app = Flask(__name__)

# Secret Key
app.secret_key = secrets.token_hex(32)

from flask_wtf.csrf import (
    CSRFProtect,
    generate_csrf
)

csrf = CSRFProtect(app)

# =========================
# EVIDENCE FOLDER
# =========================

EVIDENCE_FOLDER = "evidence"

os.makedirs(
    EVIDENCE_FOLDER,
    exist_ok=True
)

app.config["EVIDENCE_FOLDER"] = EVIDENCE_FOLDER



@app.context_processor
def inject_csrf_token():
    return dict(
        csrf_token=generate_csrf
    )



app.permanent_session_lifetime = timedelta(
    days=30
)
serializer = URLSafeTimedSerializer(
    app.secret_key
)



# =========================
# DATABASE INIT
# =========================

def init_db():

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    # =========================
    # PHISHING CAMPAIGNS
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS phishing_campaigns (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        sender TEXT,

        subject TEXT,

        source_ip TEXT,

        country TEXT,

        threat_score INTEGER,

        created_at TEXT

    )
    """)

    # ========================
    # Threat feed 
    # ========================
    cursor.execute("""

    CREATE TABLE IF NOT EXISTS threat_feed (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

            threat_type TEXT,

            indicator TEXT,

            severity TEXT,

            source TEXT,

            created_at TEXT

    )
    """)

    # =========================
    # INVESTIGATIONS TABLE
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS investigations (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        module TEXT,
        target TEXT,
        result TEXT,
        timestamp TEXT

    )
    """)

    # =========================
    # USERS TABLE
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT UNIQUE,
        password TEXT,

        role TEXT DEFAULT 'user',

        reset_token TEXT,
        reset_expiry TEXT

    )
    """)

    # =========================
    # CASE INVESTIGATIONS
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS case_investigations (


    id INTEGER PRIMARY KEY AUTOINCREMENT,

    case_id INTEGER,

    investigation_id INTEGER


    )
    """)

    # =========================
    # MITRE MAPPINGS
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mitre_mappings (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        indicator_type TEXT,

        indicator_value TEXT,

        tactic TEXT,

        technique_id TEXT,

        technique_name TEXT,

        description TEXT

    )
    """)



    # =========================
    # ADD EMAIL COLUMN IF MISSING
    # =========================

    try:

        cursor.execute("""

        ALTER TABLE users

        ADD COLUMN email TEXT

        """)

        print(
            "[+] Email column added"
        )

    except:

        pass

    # =========================
    # ADD failed_attempts
    # =========================

    try:
        cursor.execute("""
        ALTER TABLE users
        ADD COLUMN failed_attempts INTEGER DEFAULT 0
        """)
        print("[+] failed_attempts column added")
    except:
        pass

    # =========================
    # ADD last_login
    # =========================

    try:
        cursor.execute("""
        ALTER TABLE users
        ADD COLUMN last_login TEXT
        """)
        print("[+] last_login column added")
    except:
        pass

    # =========================
    # ADD is_active
    # =========================

    try:
        cursor.execute("""
        ALTER TABLE users
        ADD COLUMN is_active INTEGER DEFAULT 1
        """)
        print("[+] is_active column added")
    except:
        pass


    # =========================

    try:

        cursor.execute("""

        ALTER TABLE investigations

        ADD COLUMN is_important INTEGER DEFAULT 0

        """)

    except:

        pass

    try:

        cursor.execute("""

        ALTER TABLE investigations

        ADD COLUMN is_pinned INTEGER DEFAULT 0

        """)

    except:

        pass

    # =========================
    # ADD CREATED_AT
    # =========================

    try:

        cursor.execute("""

        ALTER TABLE users

        ADD COLUMN created_at TEXT

        """)

        print("[+] created_at column added")

    except:

        pass


    try:

        cursor.execute("""
        ALTER TABLE evidence
        ADD COLUMN case_id INTEGER
        """)

        print("[+] case_id added")

    except:

        pass

    try:
        cursor.execute("""
        ALTER TABLE evidence
        ADD COLUMN filename TEXT
        """)
    except:
        pass

    try:
        cursor.execute("""
        ALTER TABLE evidence
        ADD COLUMN filepath TEXT
        """)
    except:
        pass

    try:
        cursor.execute("""
        ALTER TABLE evidence
        ADD COLUMN uploaded_by TEXT
        """)
    except:
        pass

    try:
        cursor.execute("""
        ALTER TABLE evidence
        ADD COLUMN uploaded_at TEXT
        """)
    except:
        pass
    # =========================
    # DEFAULT ADMIN USER
    # =========================

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE username=?
        """,
        ("admin",)
    )

    admin_exists = cursor.fetchone()

    if admin_exists is None:

        admin_password = generate_password_hash(
            "admin123"
        )

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                password,
                role
            )
            VALUES
            (
                ?, ?, ?
            )
            """,
            (
                "admin",
                admin_password,
                "admin"
            )
        )

        print(
            "[+] Default admin user created"
        )

    # =========================
    # AUDIT LOGS TABLE
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user TEXT,
        action TEXT,
        ip TEXT,
        timestamp TEXT

    )
    """)

    # =========================
    # CASES TABLE
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cases (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    title TEXT,

    target TEXT,

    module TEXT,

    priority TEXT DEFAULT 'Medium',

    status TEXT DEFAULT 'Open',

    assigned_to TEXT,

    notes TEXT,

    created_at TEXT

    )
    """)

    # =========================
    # EVIDENCE TABLE
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS evidence (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        case_id INTEGER,

        filename TEXT,

        filepath TEXT,

        uploaded_by TEXT,

        uploaded_at TEXT

    )
    """)

    # =========================
    # CASE TIMELINE
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS case_timeline (


    id INTEGER PRIMARY KEY AUTOINCREMENT,

    case_id INTEGER,

    username TEXT,

    action TEXT,

    timestamp TEXT


    )
    """)

    # =========================
    # CASE COMMENTS
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS case_comments (


    id INTEGER PRIMARY KEY AUTOINCREMENT,

    case_id INTEGER,

    username TEXT,

    comment TEXT,

    created_at TEXT


    )
    """)

    # =========================
    # ANALYST NOTES
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyst_notes (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        title TEXT,

        note TEXT,

        created_by TEXT,

        created_at TEXT

    )
    """)

    # =========================
    # WATCHLIST
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS watchlists (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        indicator TEXT,

        indicator_type TEXT,

        severity TEXT,

        notes TEXT,

        created_by TEXT,

        created_at TEXT

    )
    """)

    # =========================
    # SAVED SEARCHES
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS saved_searches (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        name TEXT,

        search_type TEXT,

        query TEXT,

        description TEXT,

        created_by TEXT,

        created_at TEXT

    )
    """)

    # =========================
    # THREAT HUNTS
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_hunts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        hunt_name TEXT,

        hunt_type TEXT,

        results TEXT,

        created_by TEXT,

        created_at TEXT

    )
    """)

    # =========================
    # USER DASHBOARDS
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_dashboards (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT,

        dashboard_type TEXT,

        created_at TEXT

    )
    """)

    conn.commit()
    conn.close()


# =========================
# RUN DATABASE INIT
# =========================

init_db()


# =========================
# SAVE FUNCTION
# =========================

def save_investigation(
        module,
        target,
        result):


    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute("""

        INSERT INTO investigations

        (module,target,result,timestamp)

        VALUES (?,?,?,?)

    """, (

        module,
        target,
        str(result),
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    ))


 

    conn.commit()
    conn.close()

def valid_domain(domain):
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, domain)


# =========================
# CONFIG
# =========================

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

REPORT_FOLDER = "reports"

os.makedirs(
    REPORT_FOLDER,
    exist_ok=True
)

limiter = Limiter(
    get_remote_address,
    app=app
)


# ========================
# Timeline Helper Function
# ========================

def add_case_timeline(
        case_id,
        action
        ):

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO case_timeline
            (
                case_id,
                username,
                action,
                timestamp
            )
            VALUES
            (?, ?, ?, ?)
            """,
            (
                case_id,
                session.get(
                    'user',
                    'system'
                ),
                action,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )
 

        conn.commit()
        conn.close()

# =========================
# calculate_threat_score
# =========================

def calculate_threat_score(intel):

    score = 0

    # AbuseIPDB

    try:

        abuse_score = intel.get(
            "abuseip",
            {}
        ).get(
            "data",
            {}
        ).get(
            "abuseConfidenceScore",
            0
        )

        score += abuse_score

    except:

        pass

    # VirusTotal

    try:

        malicious = intel.get(
            "virustotal",
            {}
        ).get(
            "data",
            {}
        ).get(
            "attributes",
            {}
        ).get(
            "last_analysis_stats",
            {}
        ).get(
            "malicious",
            0
        )

        score += malicious * 5

    except:

        pass

    if score > 100:

        score = 100

    return score

def get_risk_level(score):

    if score >= 76:

        return "Critical"

    elif score >= 51:

        return "High"

    elif score >= 26:

        return "Medium"

    return "Low"

# =========================
# MITRE MAPPING 
# =========================

def get_mitre_mapping(indicator_type):

    mappings = {

        "EMAIL": {

            "tactic":
            "Initial Access",

            "technique_id":
            "T1566",

            "technique_name":
            "Phishing"
        },

        "IOC": {

            "tactic":
            "Command and Control",

            "technique_id":
            "T1071",

            "technique_name":
            "Application Layer Protocol"
        },

        "MALWARE_INTEL": {

            "tactic":
            "Execution",

            "technique_id":
            "T1204",

            "technique_name":
            "User Execution"
        },

        "DOMAIN_INTEL": {

            "tactic":
            "Command and Control",

            "technique_id":
            "T1583",

            "technique_name":
            "Acquire Infrastructure"
        }

    }

    return mappings.get(
        indicator_type,
        {

            "tactic":
            "Unknown",

            "technique_id":
            "N/A",

            "technique_name":
            "Unknown"

        }
    )

#  Alert Helper Funtion 

def create_alert(

    title,

    description,

    severity="Medium"

):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO alerts
        (
            title,
            description,
            severity,
            created_at
        )
        VALUES
        (?, ?, ?, ?)
        """,
        (
            title,
            description,
            severity,
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    conn.commit()

    conn.close()

# =========================
# HOME PAGE
# =========================

@app.route('/')
def home():

    if 'user' not in session:

        return redirect('/login')

    # Temporary Default Values

    critical_threats = 0
    ip_count = 0
    email_count = 0
    malware_count = 0
    hunt_count = 0
    dashboard = None

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()



    # Alerts


    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        title TEXT,

        description TEXT,

        severity TEXT,

        status TEXT DEFAULT 'Open',

        created_at TEXT

    )
    """)

    #  Dashboard Alert Widget

    cursor.execute("""
    SELECT COUNT(*)
    FROM alerts
    WHERE status='Open'
    """)

    open_alerts =cursor.fetchone()[0]


    # Trend Chart map

    cursor.execute("""
    SELECT DATE(created_at),
        COUNT(*)
    FROM threat_feed
    GROUP BY DATE(created_at)
    ORDER BY DATE(created_at) DESC
    LIMIT 7
    """)

    trend_rows = cursor.fetchall()

    trend_rows.reverse()

    trend_labels = []
    trend_values = []

    for row in trend_rows:

        trend_labels.append(row[0])

        trend_values.append(row[1])
    

    # Recent Threats

    cursor.execute("""
    SELECT *
    FROM threat_feed
    ORDER BY id DESC
    LIMIT 5
    """)

    threats = cursor.fetchall()


    # Recent Cases

    cursor.execute("""
    SELECT *
    FROM cases
    ORDER BY id DESC
    LIMIT 5
    """)

    recent_cases = cursor.fetchall()

    # Open Cases

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM cases
    WHERE status != 'Closed'
    """
    )

    open_cases = cursor.fetchone()[0]

    # Critical Threats

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM threat_feed
    WHERE severity='Critical'
    """
    )

    critical_threats = cursor.fetchone()[0]

    # Watchlist Count

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM watchlists
    """
    )

    watchlist_count = cursor.fetchone()[0]

    # Malicious IPs

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM threat_feed
    WHERE threat_type='IP'
    """
    )

    ip_count = cursor.fetchone()[0]

    # =========================
    # Dashboard Loader
    # =========================

    cursor.execute(
        """
        SELECT dashboard_type
        FROM user_dashboards
        WHERE username=?
        """,
        (
            session.get('user'),
        )
    )

    dashboard = cursor.fetchone()

    # =========================
    # Dashboard Satatics
    # =========================

    cursor.execute(
    '''
    SELECT COUNT(*)
    FROM threat_hunts
    '''
    )

    hunt_count = cursor.fetchone()[0]


    # =========================
    # THREAT FEED
    # =========================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_feed (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        threat_type TEXT,

        indicator TEXT,

        severity TEXT,

        source TEXT,

        created_at TEXT

    )
    """)

    # malware intel 

    cursor.execute(
    '''
    SELECT COUNT(*)
    FROM investigations
    WHERE module='MALWARE_INTEL'
    '''
    )

    malware_count = cursor.fetchone()[0]

    # =========================
    # Investigation Statistics
    # =========================

    cursor.execute(
        "SELECT COUNT(*) FROM investigations"
    )
    total = cursor.fetchone()[0]

    modules = [
        "WHOIS",
        "DNS",
        "HASH",
        "METADATA",
        "GEOIP",
        "VIRUSTOTAL",
        "EMAIL",
        "IOC",
        "YARA"
    ]

    counts = {}

    for module in modules:

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM investigations
            WHERE module=?
            """,
            (module,)
        )

        counts[module] = cursor.fetchone()[0]

    # =========================
    # User Statistics
    # =========================

    cursor.execute(
        "SELECT COUNT(*) FROM users"
    )

    total_users = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE role='admin'
        """
    )

    admin_users = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE is_active=1
        """
    )

    active_users = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE is_active=0
        """
    )

    disabled_users = cursor.fetchone()[0]

# =========================
# RECENT ACTIVITY
# =========================

    if session.get("role") == "admin":

        cursor.execute(
            """
            SELECT
                user,
                action,
                ip,
                timestamp
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 10
            """
        )

    else:

        cursor.execute(
            """
            SELECT
                user,
                action,
                ip,
                timestamp
            FROM audit_logs
            WHERE user=?
            ORDER BY id DESC
            LIMIT 10
            """,
            (
                session.get("user"),
            )
        )

    recent_logs = cursor.fetchall()

    # =========================
    # SYSTEM HEALTH
    # =========================

    # Database Status
    db_status = "🟢 Online"

    # Internet Status
    
    try:

        sock = socket.create_connection(
            ("8.8.8.8", 53),
            timeout=2
        )

        sock.close()

        internet_status = "🟢 Online"

    except Exception:

        internet_status = "🔴 Offline"

    # VirusTotal API
    vt_status = (
        "🟢 Configured"
        if VT_API_KEY
        else "🔴 Missing"
    )

    # AbuseIPDB API
    abuse_status = (
        "🟢 Configured"
        if ABUSE_API_KEY
        else "🔴 Missing"
    )

    # Database Size
    db_size = round(

        os.path.getsize(
            "investigations.db"
        ) / 1024,

        2

    )

    # Current Time
    current_time = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    # =========================
    # RECENT INVESTIGATIONS
    # =========================

    cursor.execute(
        """
        SELECT
            module,
            target,
            timestamp
        FROM investigations
        ORDER BY id DESC
        LIMIT 10
        """
    )

    recent_investigations = cursor.fetchall()

    #=========================
    #SECURITY ALERTS
    #=========================

    alerts = []

    #Disabled Accounts

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM users
    WHERE is_active=0
    """
    )

    disabled = cursor.fetchone()[0]

    if disabled > 0:

        alerts.append({
            "level": "warning",
            "title": "Disabled Accounts",
            "message": f"{disabled} disabled account(s) detected."
        })
    #Failed Login Attempts

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM users
    WHERE failed_attempts >= 5
    """
    )

    locked = cursor.fetchone()[0]

    if locked > 0:

        alerts.append({
            "level": "danger",
            "title": "Locked Accounts",
            "message": f"{locked} account(s) exceeded login attempts."
        })
    #VirusTotal Activity

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM investigations
    WHERE module='VIRUSTOTAL'
    """
    )

    vt_scans = cursor.fetchone()[0]

    if vt_scans > 10:

        alerts.append({
            "level": "info",
            "title": "VirusTotal Usage",
            "message": f"{vt_scans} VirusTotal scans performed."
        })
    #IOC Activity

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM investigations
    WHERE module='IOC'
    """
    )

    ioc_scans = cursor.fetchone()[0]

    if ioc_scans > 10:

        alerts.append({
            "level": "info",
            "title": "IOC Activity",
            "message": f"{ioc_scans} IOC investigations completed."
        })

    


    #=========================
    #DASHBOARD INSIGHTS
    #=========================
    #Most Used Module

    cursor.execute(
    """
    SELECT module,
    COUNT(*) AS total
    FROM investigations
    GROUP BY module
    ORDER BY total DESC
    LIMIT 1
    """
    )

    most_used_module = cursor.fetchone()

    if most_used_module:

        most_module = most_used_module[0]
        most_module_count = most_used_module[1]

    else:

        most_module = "N/A"
        most_module_count = 0
    #Most Investigated Target

    cursor.execute(
    """
    SELECT target,
    COUNT(*) AS total
    FROM investigations
    GROUP BY target
    ORDER BY total DESC
    LIMIT 1
    """
    )

    most_target = cursor.fetchone()

    if most_target:

        top_target = most_target[0]
        top_target_count = most_target[1]

    else:

        top_target = "N/A"
        top_target_count = 0
    #Today's Investigations

    today = datetime.now().strftime("%Y-%m-%d")

    cursor.execute(
    """
    SELECT COUNT(*)
    FROM investigations
    WHERE timestamp LIKE ?
    """,
    (today + "%",)
    )

    today_count = cursor.fetchone()[0]

    #Most Active User

    cursor.execute(
    """
    SELECT user,
    COUNT(*) AS total
    FROM audit_logs
    GROUP BY user
    ORDER BY total DESC
    LIMIT 1
    """
    )

    top_user = cursor.fetchone()

    if top_user:

        active_user = top_user[0]
        active_user_actions = top_user[1]

    else:

        active_user = "N/A"
        active_user_actions = 0


    # =========================
    # SOC DASHBOARD STATS
    # =========================

    # Open Cases

    try:

        cursor.execute(
        """
        SELECT COUNT(*)
        FROM cases
        WHERE status != 'Closed'
        """
        )

        open_cases = cursor.fetchone()[0]

    except:

        open_cases = 0


    # Critical Threats

    try:

        cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_feed
        WHERE severity='Critical'
        """
        )

        critical_threats = cursor.fetchone()[0]

    except:

        critical_threats = 0


    # Watchlist Count

    try:

        cursor.execute(
        """
        SELECT COUNT(*)
        FROM watchlists
        """
        )

        watchlist_count = cursor.fetchone()[0]

    except:

        watchlist_count = 0


    # Malicious IP Count

    try:

        cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_feed
        WHERE threat_type='IP'
        """
        )

        ip_count = cursor.fetchone()[0]

    except:

        ip_count = 0

    conn.close()

    chart_data = {

        "WHOIS": counts["WHOIS"],

        "DNS": counts["DNS"],

        "HASH": counts["HASH"],

        "METADATA": counts["METADATA"],

        "GEOIP": counts["GEOIP"],

        "VirusTotal": counts["VIRUSTOTAL"],

        "Email": counts["EMAIL"],

        "IOC": counts["IOC"],

        "YARA": counts["YARA"]

    }

    mitre_data = {

        "Initial Access": 15,

        "Execution": 21,

        "Persistence": 8,

        "Privilege Esc.": 4,

        "Command and Control": 18

    }

    return render_template(

        "index.html",

        total=total,

        total_users=total_users,

        admin_users=admin_users,

        active_users=active_users,

        disabled_users=disabled_users,

        whois_count=counts["WHOIS"],

        dns_count=counts["DNS"],

        hash_count=counts["HASH"],

        metadata_count=counts["METADATA"],

        geoip_count=counts["GEOIP"],

        vt_count=counts["VIRUSTOTAL"],

        email_count=counts["EMAIL"],

        ioc_count=counts["IOC"],

        yara_count=counts["YARA"],

        chart_data=chart_data,

        recent_logs=recent_logs,

        db_status=db_status,

        internet_status=internet_status,
        
        vt_status=vt_status,
        
        abuse_status=abuse_status,
        
        db_size=db_size,
        
        current_time=current_time,

        recent_investigations=recent_investigations,

        alerts=alerts,

        most_module=most_module,
        most_module_count=most_module_count,

        top_target=top_target,
        top_target_count=top_target_count,

        today_count=today_count,

        active_user=active_user,
        active_user_actions=active_user_actions,

        malware_count=malware_count,

        dashboard=dashboard,
        hunt_count=hunt_count,

        open_cases=open_cases,

        critical_threats=critical_threats,

        watchlist_count=watchlist_count,

        ip_count=ip_count,

        threats=threats,

        recent_cases=recent_cases,

        trend_labels=trend_labels,

        trend_values=trend_values,

        mitre_data=mitre_data,

        open_alerts=open_alerts




    )



    
# =========================
# WHOIS LOOKUP
# =========================
@limiter.limit("20 per minute")
@app.route('/whois', methods=['GET', 'POST'])
def whois_lookup():

    

    result = None

    target = request.args.get(
        'target',
        ''
    )

    if request.method == 'POST':

        target = request.form.get(
            'target'
        )

        domain = request.form.get(
            'domain',
            ''
        ).strip()

        try:

            data = whois.whois(domain)

            result = {

                "domain_name":
                    data.get(
                        "domain_name",
                        "N/A"
                    ),

                "registrar":
                    data.get(
                        "registrar",
                        "N/A"
                    ),

                "creation_date":
                    data.get(
                        "creation_date",
                        "N/A"
                    ),

                "expiration_date":
                    data.get(
                        "expiration_date",
                        "N/A"
                    )

            }

            # list handle
            if isinstance(
                result["domain_name"],
                list
            ):
                result["domain_name"] = result["domain_name"][0]

            if isinstance(
                result["creation_date"],
                list
            ):
                result["creation_date"] = result["creation_date"][0]

            if isinstance(
                result["expiration_date"],
                list
            ):
                result["expiration_date"] = result["expiration_date"][0]

            save_investigation(
                "WHOIS",
                domain,
                str(result)
            )

        except Exception as e:

            result = {
                "error": str(e)
            }

    return render_template(
        "whois.html",
        target=target,
        result=result
    )


# =========================
# DNS LOOKUP
# =========================
@limiter.limit("20 per minute")
@app.route('/dns', methods=['GET', 'POST'])
def dns_lookup():

    records = {}

    if request.method == 'POST':

        domain = request.form['domain']

        try:

            record_types = [
                'A',
                'AAAA',
                'MX',
                'NS',
                'TXT'
            ]

            for record_type in record_types:

                try:

                    answers = dns.resolver.resolve(
                        domain,
                        record_type
                    )

                    records[record_type] = [
                        str(answer)
                        for answer in answers
                    ]

                except:

                    records[record_type] = []

            
            save_investigation(
                "DNS",
                domain,
                records
            )
            audit_log(
                session['user'],
                f"DNS:{domain}",
                request.remote_addr
            )

        except Exception as e:

            records["ERROR"] = [str(e)]

    return render_template(
        'dns.html',
        records=records
    )


# =========================
# HASH ANALYZER
# =========================

@app.route('/hash', methods=['GET', 'POST'])
def hash_analyzer():

    hashes = None

    if request.method == 'POST':

        uploaded_file = request.files.get('file')

        if uploaded_file:

            filename = secure_filename(
                uploaded_file.filename
            )

            filepath = os.path.join(
                app.config['UPLOAD_FOLDER'],
                filename
            )

            uploaded_file.save(filepath)

            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()

            with open(filepath, "rb") as file:

                while True:

                    chunk = file.read(4096)

                    if not chunk:
                        break

                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            hashes = {
                "filename": filename,
                "filepath": filepath,
                "md5": md5_hash.hexdigest(),
                "sha1": sha1_hash.hexdigest(),
                "sha256": sha256_hash.hexdigest()
            }

            # 👇 YAHAN ADD KARNA HAI
            save_investigation(
                "HASH",
                filename,
                hashes
            )

            audit_log(
                session.get('user', 'Guest'),
                "HASH ANALYSIS",
                filename
            )

    return render_template(
        'hash.html',
        hashes=hashes
    )


# =========================
# metadata
# =========================

@app.route('/metadata', methods=['GET', 'POST'])
def metadata_analyzer():

    metadata = {}

    if request.method == 'POST':

        uploaded_file = request.files.get('file')

        if uploaded_file:

            filename = secure_filename(uploaded_file.filename)

            filepath = os.path.join(
                app.config['UPLOAD_FOLDER'],
                filename
            )

            uploaded_file.save(filepath)

            try:

                metadata["Filename"] = filename
                metadata["File Size"] = os.path.getsize(filepath)

                image = Image.open(filepath)

                metadata["Format"] = image.format
                metadata["Width"] = image.width
                metadata["Height"] = image.height

                with open(filepath, 'rb') as f:

                    tags = exifread.process_file(f)

                    if tags:

                        for tag in tags:
                            metadata[tag] = str(tags[tag])

                    else:
                        metadata["EXIF"] = "No EXIF metadata found"

                # 👇 YAHAN ADD KARNA HAI
                save_investigation(
                    "METADATA",
                    filename,
                    str(metadata)[:5000]
                )

                audit_log(
                    session['user'],
                    "METADATA ANALYSIS",
                    filename
                )

            except Exception as e:

                metadata["Error"] = str(e)

    return render_template(
        'metadata.html',
        metadata=metadata
    )

# =========================
# History
# =========================

@app.route('/history')
def history():

    q = request.args.get(
        'q',
        ''
    )

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    if q:

        cursor.execute(
            '''
            SELECT *
            FROM investigations
            WHERE target LIKE ?
            ORDER BY id DESC
            ''',
            ('%' + q + '%',)
        )

    else:

        cursor.execute(
            '''
            SELECT *
            FROM investigations
            ORDER BY id DESC
            '''
        )

    rows = cursor.fetchall()

    conn.close()

    return render_template(
        'history.html',
        rows=rows
    )

# =========================
# REPORT
# =========================

@app.route('/report/<int:id>')
def generate_report(id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM investigations
        WHERE id=?
        """,
        (id,)
    )

    row = cursor.fetchone()

    conn.close()

    if not row:
        return "Record Not Found"

    report_path = os.path.join(
        REPORT_FOLDER,
        f"report_{id}.pdf"
    )

    doc = SimpleDocTemplate(
        report_path
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "OSINT & Forensics Report",
            styles['Title']
        )
    )

    content.append(
        Spacer(1,12)
    )

    content.append(
        Paragraph(
            f"<b>ID:</b> {row[0]}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Module:</b> {row[1]}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Target:</b> {row[2]}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Timestamp:</b> {row[4]}",
            styles['BodyText']
        )
    )

    content.append(
        Spacer(1,10)
    )

    content.append(
        Paragraph(
            str(row[3]),
            styles['BodyText']
        )
    )

    doc.build(content)

    audit_log(
        session.get('user', 'Unknown User'),
        f"PDF_REPORT:{id}",
        request.remote_addr
    )

    return send_file(
        report_path,
        as_attachment=True
    )


# =========================
# IVESTIGATION
# =========================

@app.route('/investigation/<int:id>')
def investigation_details(id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT *
        FROM investigations
        WHERE id=?
        ''',
        (id,)
    )

    row = cursor.fetchone()

    conn.close()

    return render_template(
        'investigation.html',
        row=row
    )

# =========================
# register
# =========================

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form.get(
            'username',
            ''
        ).strip()

        email = request.form.get(
            'email',
            ''
        ).strip().lower()

        password = request.form.get(
            'password',
            ''
        )

        confirm_password = request.form.get(
            'confirm_password',
            ''
        )

        # Username Validation
        if len(username) < 3:

            flash(
                "Username must be at least 3 characters."
            )

            return redirect(
                url_for('register')
            )

        if not re.match(
            r'^[A-Za-z0-9_.-]+$',
            username
        ):

            flash(
                "Username contains invalid characters."
            )

            return redirect(
                url_for('register')
            )

        # Email Validation
        if not re.match(
            r'^[^@]+@[^@]+\.[^@]+$',
            email
        ):

            flash(
                "Enter a valid email address."
            )

            return redirect(
                url_for('register')
            )

        # Password Validation
        if len(password) < 8:

            flash(
                "Password must be at least 8 characters."
            )

            return redirect(
                url_for('register')
            )

        if password != confirm_password:

            flash(
                "Passwords do not match."
            )

            return redirect(
                url_for('register')
            )

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        # Username Exists
        cursor.execute(
            "SELECT id FROM users WHERE username=?",
            (username,)
        )

        if cursor.fetchone():

            conn.close()

            flash(
                "Username already exists."
            )

            return redirect(
                url_for('register')
            )

        # Email Exists
        cursor.execute(
            "SELECT id FROM users WHERE email=?",
            (email,)
        )

        if cursor.fetchone():

            conn.close()

            flash(
                "Email already registered."
            )

            return redirect(
                url_for('register')
            )

        hashed_password = generate_password_hash(
            password
        )

        cursor.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password,
                role
            )
            VALUES
            (?, ?, ?, ?)
            """,
            (
                username,
                email,
                hashed_password,
                "user"
            )
        )

        conn.commit()
        conn.close()

        flash(
            "Registration successful. Please login."
        )

        return redirect(
            url_for('login')
        )

    return render_template(
        'register.html'
    )

# =========================
# Login
# =========================

@limiter.limit("5 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form.get(
            'username',
            ''
        ).strip()

        password = request.form.get(
            'password',
            ''
        )

        remember = request.form.get(
            'remember'
        )

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM users
            WHERE username=?
            """,
            (username,)
        )

        user = cursor.fetchone()

        if not user:

            conn.close()

            flash(
                "Invalid username or password",
                "danger"
            )

            return redirect(
                url_for('login')
            )

        # Account Disabled
        if len(user) >= 9:

            if user[8] == 0:

                conn.close()

                flash(
                    "Account has been disabled."
                )

                return redirect(
                    url_for('login')
                )

        # Too many failed attempts
        if len(user) >= 8:

            if user[7] >= 5:

                conn.close()

                flash(
                    "Account locked after multiple failed logins."
                )

                return redirect(
                    url_for('login')
                )

        # Password Correct
        if check_password_hash(
            user[2],
            password
        ):

            cursor.execute(
                """
                UPDATE users
                SET failed_attempts=0,
                    last_login=?
                WHERE username=?
                """,
                (
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    username
                )
            )

            conn.commit()

            session.permanent = bool(
                remember
            )

            session['user'] = user[1]

            session['role'] = user[3]

            audit_log(
                username,
                "LOGIN SUCCESS",
                request.remote_addr
            )

            conn.close()

            flash(
                "Welcome back!",
                "success"
            )

            return redirect('/')

        # Wrong Password

        cursor.execute(
            """
            UPDATE users
            SET failed_attempts =
                failed_attempts + 1
            WHERE username=?
            """,
            (username,)
        )

        conn.commit()

        audit_log(
            username,
            "LOGIN FAILED",
            request.remote_addr
        )

        conn.close()

        flash(
            "Invalid username or password",
            "danger"
        )

        return redirect(
            url_for('login')
        )

    return render_template(
        'login.html'
    )

# =========================
# Logout
# =========================

@app.route('/logout')
def logout():

    if 'user' in session:

        audit_log(
            session['user'],
            "LOGOUT",
            request.remote_addr
        )

    session.clear()
    flash(
        "Logged Out Successfully",
        "info"
    )
    return redirect('/login')

# =========================
# CSV
# =========================
@app.route('/export/csv')
def export_csv():

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT *
        FROM investigations
        '''
    )

    rows = cursor.fetchall()

    conn.close()

    csv_file = "investigations.csv"

    with open(
        csv_file,
        'w',
        newline='',
        encoding='utf-8'
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            'ID',
            'MODULE',
            'TARGET',
            'RESULT',
            'TIMESTAMP'
        ])

        writer.writerows(rows)

        audit_log(
            session['user'],
            "EXPORT_CSV",
            request.remote_addr
        )

    return send_file(
        csv_file,
        as_attachment=True
    )

# =========================
# all pdf
# =========================

@app.route('/export/allpdf')
def export_all_pdf():

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT *
        FROM investigations
        '''
    )

    rows = cursor.fetchall()

    conn.close()

    pdf_file = "all_reports.pdf"

    doc = SimpleDocTemplate(
        pdf_file
    )

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "All Investigations",
            styles['Title']
        )
    )

    for row in rows:

        content.append(
            Paragraph(
                f"""
                ID:{row[0]}
                Module:{row[1]}
                Target:{row[2]}
                Time:{row[4]}
                """,
                styles['BodyText']
            )
        )

        content.append(
            Spacer(1,10)
        )

    doc.build(content)
    audit_log(
        session['user'],
        "EXPORT_ALL_PDF",
        request.remote_addr
    )
    return send_file(
        pdf_file,
        as_attachment=True
    )

# =========================
# GEOIP
# =========================

@app.route('/geoip', methods=['GET', 'POST'])
def geoip():

    result = None

    if request.method == 'POST':

        ip = request.form['ip']

        try:

            response = requests.get(
                f"http://ip-api.com/json/{ip}"
            )

            result = response.json()

            save_investigation(
                "GEOIP",
                ip,
                result
            )

        except Exception as e:

            result = {
                "error": str(e)
            }

    return render_template(
        'geoip.html',
        result=result
    )

# =========================
# VirusTotal Lookup
# =========================


@app.route('/virustotal/<target>')
def virustotal_lookup(target):

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        # IP Address

        try:

            ipaddress.ip_address(target)

            url = (
                f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            )

            lookup_type = "IP"

        except ValueError:

            # Domain

            if "." in target and len(target) < 255:

                url = (
                    f"https://www.virustotal.com/api/v3/domains/{target}"
                )

                lookup_type = "DOMAIN"

            else:

                # File Hash

                url = (
                    f"https://www.virustotal.com/api/v3/files/{target}"
                )

                lookup_type = "HASH"

        response = requests.get(
            url,
            headers=headers
        )

        if response.status_code == 404:

            return render_template(
                "virustotal.html",
                error="VirusTotal report not found."
            )

        if response.status_code != 200:

            return render_template(
                "virustotal.html",
                error=f"VirusTotal API Error: {response.status_code}"
            )

        data = response.json()

        save_investigation(
            "VIRUSTOTAL",
            target,
            str(data)[:5000]
        )

        audit_log(
            session.get(
                'user',
                'anonymous'
            ),
            f"VT_LOOKUP:{target}",
            request.remote_addr
        )

        return render_template(
            "virustotal.html",
            data=data,
            lookup_type=lookup_type
        )

    except Exception as e:

        return str(e)
    
# =========================
# VirusTotal Upload
# =========================

@app.route('/vt-upload', methods=['POST'])
def vt_upload():

    filepath = request.form.get(
        'filepath'
    )

    if not filepath:

        return "No filepath received"

    if not os.path.exists(filepath):

        return f"File not found: {filepath}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        with open(filepath, "rb") as f:

            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files={
                    "file": f
                }
            )

        data = response.json()

        if "data" not in data:

            return render_template(
                "vt_analysis.html",
                data=data
            )

        analysis_id = data["data"]["id"]

        save_investigation(
            "VT_UPLOAD",
            filepath,
            str(data)[:5000]
        )
        audit_log(
            session['user'],
            "VT_UPLOAD",
            request.remote_addr
        )

        return redirect(
            url_for(
                "vt_analysis",
                analysis_id=analysis_id
            )
        )

    except Exception as e:

        return str(e)

# =========================
# VirusTotal Analysis
# =========================

@app.route('/vt-analysis/<analysis_id>')
def vt_analysis(analysis_id):

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    data = response.json()

    status = data.get(
        "data",
        {}
    ).get(
        "attributes",
        {}
    ).get(
        "status"    
    
    )

    return render_template(
    "vt_analysis.html",
    data=data,
    status=status
    )

# =========================
# ABUSEIP
# =========================

@app.route('/abuseip', methods=['GET', 'POST'])
def abuseip():

    result = None

    if request.method == 'POST':

        ip = request.form.get('ip', '').strip()

        if not ip:

            result = {
                "error": "Please enter an IP address"
            }

            return render_template(
                'abuseip.html',
                result=result
            )

        try:

            url = "https://api.abuseipdb.com/api/v2/check"

            headers = {

                "Key": ABUSE_API_KEY,
                "Accept": "application/json"

            }

            params = {

                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""

            }

            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=15
            )

            response.raise_for_status()

            result = response.json()

            # Country Name Conversion

            if (
                result
                and "data" in result
                and result["data"]
            ):

                country_code = result["data"].get(
                    "countryCode"
                )

                if country_code:

                    country = pycountry.countries.get(
                        alpha_2=country_code
                    )

                    if country:

                        result["data"][
                            "countryName"
                        ] = country.name

                    else:

                        result["data"][
                            "countryName"
                        ] = country_code

            # Save History

            save_investigation(
                "ABUSEIPDB",
                ip,
                str(result)
            )
            audit_log(
                session['user'],
                f"ABUSEIP:{ip}",
                request.remote_addr
            )

        except requests.exceptions.HTTPError as e:

            result = {
                "error":
                f"HTTP Error: {str(e)}"
            }

        except requests.exceptions.ConnectionError:

            result = {
                "error":
                "Unable to connect to AbuseIPDB"
            }

        except requests.exceptions.Timeout:

            result = {
                "error":
                "Request timed out"
            }

        except Exception as e:

            result = {
                "error": str(e)
            }

    return render_template(
        'abuseip.html',
        result=result
    )

# =========================
# ADMIN
# =========================

@app.route('/admin')
def admin_panel():

    if 'user' not in session:
        return redirect('/login')

    if session.get('role') != 'admin':

        return "Access Denied"

    return render_template(
        'admin.html'
    )

# =========================
# AUDIT 
# =========================

@app.route('/audit')
def audit_history():
    
    # Admin check
    if session.get('role') != 'admin':
        return "Access Denied"
    
    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute("""

        SELECT *

        FROM audit_logs

        ORDER BY id DESC

    """)

    logs = cursor.fetchall()

    conn.close()

    return render_template(
        'audit.html',
        logs=logs
    )


# =========================
# audit log
# =========================

def audit_log(user, action, ip):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO audit_logs
        (
            user,
            action,
            ip,
            timestamp
        )
        VALUES
        (
            ?, ?, ?, ?
        )
        """,
        (
            user,
            action,
            ip,
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    conn.commit()
    conn.close()

# =========================
# forget-password and reset
# =========================

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':

        username = request.form['username']

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT username, role
            FROM users
            WHERE username=?
            ''',
            (username,)
        )

        user = cursor.fetchone()

        conn.close()

        if not user:
            return "User not found"

        # Admin password reset disabled
        if user[1] == "admin":
            return "Admin password reset is disabled"

        # Token generate
        token = serializer.dumps(username)

        # Reset URL generate
        reset_link = url_for(
            'reset_password',
            token=token,
            _external=True
        )

        # Development mode
        return f"""
        <h3>Password Reset Link</h3>

        <a href="{reset_link}">
            {reset_link}
        </a>
        """

    return render_template(
        'forgot_password.html'
    )


@app.route(
    '/reset/<token>',
    methods=['GET', 'POST']
)
def reset_password(token):

    error = None

    try:

        username = serializer.loads(
            token,
            max_age=3600
        )

    except:

        return "Invalid or Expired Token"

    if request.method == 'POST':

        password = request.form[
            'password'
        ]

        confirm_password = request.form[
            'confirm_password'
        ]

        if password != confirm_password:

            error = (
                "Passwords do not match"
            )

            return render_template(
                'reset_password.html',
                error=error
            )

        new_hash = generate_password_hash(
            password
        )

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            '''
            UPDATE users
            SET password=?
            WHERE username=?
            ''',
            (
                new_hash,
                username
            )
        )

        conn.commit()
        conn.close()

        return '''
        Password Updated Successfully
        <br><br>
        <a href="/login">
        Login
        </a>
        '''

    return render_template(
        'reset_password.html'
    )

# =========================
# ERROR HANDLER
# =========================

@app.errorhandler(404)
def not_found(error):

    return """
    <h1>404</h1>
    <h3>Page Not Found</h3>
    """, 404

# =========================
# API WHOIS
# =========================

@app.route('/api/whois/<domain>')
def api_whois(domain):

    if 'user' not in session:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    try:

        data = whois.whois(domain)

        result = {

            "domain": str(data.domain_name),

            "registrar": str(data.registrar),

            "creation_date": str(data.creation_date),

            "expiration_date": str(data.expiration_date)

        }

        return jsonify(result)

    except Exception as e:

        return jsonify({
            "error": str(e)
        })
    
# =========================
# API DNS
# =========================

@app.route('/api/dns/<domain>')
def api_dns(domain):

    if 'user' not in session:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    records = {}

    try:

        for record_type in [
            'A',
            'AAAA',
            'MX',
            'NS',
            'TXT'
        ]:

            try:

                answers = dns.resolver.resolve(
                    domain,
                    record_type
                )

                records[record_type] = [
                    str(x)
                    for x in answers
                ]

            except:

                records[record_type] = []

        return jsonify(records)

    except Exception as e:

        return jsonify({
            "error": str(e)
        })
    
# =========================
# API HISTORY
# =========================

@app.route('/api/history')
def api_history():

    if 'user' not in session:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT *
        FROM investigations
        ORDER BY id DESC
        '''
    )

    rows = cursor.fetchall()

    conn.close()

    results = []

    for row in rows:

        results.append({

            "id": row[0],

            "module": row[1],

            "target": row[2],

            "result": row[3],

            "timestamp": row[4]

        })

    return jsonify(results)

# =========================
# API STATS
# =========================

@app.route('/api/stats')
def api_stats():

    if 'user' not in session:

        return jsonify({
            "error": "Unauthorized"
        }), 401
    
    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    stats = {}

    cursor.execute(
        '''
        SELECT COUNT(*)
        FROM investigations
        '''
    )

    stats["total"] = cursor.fetchone()[0]

    for module in [

        "WHOIS",
        "DNS",
        "HASH",
        "METADATA",
        "GEOIP"

    ]:
    
    

        cursor.execute(
            '''
            SELECT COUNT(*)
            FROM investigations
            WHERE module=?
            ''',
            (module,)
        )

        stats[module] = cursor.fetchone()[0]

    conn.close()

    return jsonify(stats)


#==========================
# change password
#==========================

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():

    if 'user' not in session:
        return redirect('/login')

    if request.method == 'POST':

        current_password = request.form['current_password']
        new_password = request.form['new_password']

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT password
            FROM users
            WHERE username=?
            ''',
            (session['user'],)
        )

        user = cursor.fetchone()

        if not user:
            conn.close()
            return "User not found"

        if not check_password_hash(
            user[0],
            current_password
        ):
            conn.close()
            return "Current password incorrect"

        new_hash = generate_password_hash(
            new_password
        )

        cursor.execute(
            '''
            UPDATE users
            SET password=?
            WHERE username=?
            ''',
            (
                new_hash,
                session['user']
            )
        )

        conn.commit()
        conn.close()

        return "Password updated successfully"

    return render_template(
        'change_password.html'
    )


# =========================
#YARA-rules
# =========================

@app.route('/yara', methods=['GET', 'POST'])
def yara_scan():

    results = []

    if request.method == 'POST':

        uploaded_file = request.files.get('file')

        if uploaded_file:

            filename = secure_filename(
                uploaded_file.filename
            )

            filepath = os.path.join(
                app.config['UPLOAD_FOLDER'],
                filename
            )

            uploaded_file.save(filepath)

            try:

                rules = yara.compile(
                    filepath='rules/malware_rules.yar'
                )

                matches = rules.match(filepath)

                for match in matches:

                    results.append({

                        "rule": match.rule,

                        "description":
                            match.meta.get(
                                "description",
                                "No Description"
                            )

                    })

                try:

                    image = Image.open(filepath)

                    results.append({

                        "rule": "IMAGE_INFO",

                        "description":
                            f"{image.format} | "
                            f"{image.width}x{image.height}"

                    })

                except Exception:
                    pass

                if len(results) == 0:

                    results.append({

                        "rule": "NO_MATCH",

                        "description":
                            "No YARA signatures detected"

                    })

                save_investigation(
                    "YARA",
                    filename,
                    results
                )

            except Exception as e:

                results.append({

                    "rule": "ERROR",

                    "description": str(e)

                })

    return render_template(
        'yara.html',
        results=results
    )

# =========================
# Email
# =========================

@csrf.exempt
@app.route('/email', methods=['GET', 'POST'])
def email_analyzer():

    result = None

    if request.method == 'POST':

        header = request.form.get(
            'header',
            ''
        )

        parsed = Parser().parsestr(
            header
        )

        received_headers = parsed.get_all(
            'Received'
        ) or []

        # =========================
        # Source IP Extraction
        # =========================

        source_ip = "Not Found"

        for item in received_headers:

            match = re.search(
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                item
            )

            if match:

                source_ip = match.group()

                break

        # =========================
        # SPF
        # =========================

        spf_match = re.search(
            r'spf=(pass|fail|softfail|neutral)',
            header,
            re.IGNORECASE
        )

        spf_result = (
            spf_match.group(1).upper()
            if spf_match
            else "Not Found"
        )

        # =========================
        # DKIM
        # =========================

        dkim_match = re.search(
            r'dkim=(pass|fail)',
            header,
            re.IGNORECASE
        )

        dkim_result = (
            dkim_match.group(1).upper()
            if dkim_match
            else "Not Found"
        )

        # =========================
        # DMARC
        # =========================

        dmarc_match = re.search(
            r'dmarc=(pass|fail|bestguesspass|none)',
            header,
            re.IGNORECASE
        )

        dmarc_result = (
            dmarc_match.group(1).upper()
            if dmarc_match
            else "Not Found"
        )

        # =========================
        # Main Result
        # =========================

        result = {

            "from":
                parsed.get(
                    'From',
                    'Not Found'
                ),

            "to":
                parsed.get(
                    'To',
                    'Not Found'
                ),

            "subject":
                parsed.get(
                    'Subject',
                    'Not Found'
                ),

            "source_ip":
                source_ip,

            "spf":
                spf_result,

            "dkim":
                dkim_result,

            "dmarc":
                dmarc_result,

            "received":
                received_headers,

            "timestamp":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "analyst":
                session.get(
                    "user",
                    "Unknown"
                )

        }

        # =========================
        # GeoIP
        # =========================

        try:

            if source_ip != "Not Found":

                geo = requests.get(
                    f"http://ip-api.com/json/{source_ip}",
                    timeout=10
                )

                result["geoip"] = geo.json()

            else:

                result["geoip"] = {}

        except Exception:

            result["geoip"] = {}

        # =========================
        # AbuseIPDB
        # =========================

        try:

            if source_ip != "Not Found":

                headers = {

                    "Key": ABUSE_API_KEY,

                    "Accept": "application/json"

                }

                params = {

                    "ipAddress": source_ip,

                    "maxAgeInDays": 90

                }

                abuse = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                    timeout=15
                )

                result["abuse"] = abuse.json()

            else:

                result["abuse"] = {}

        except Exception:

            result["abuse"] = {}

        session["email_report"] = result

        save_investigation(
            "EMAIL",
            result["from"],
            str(result)[:5000]
        )

    return render_template(
        'email.html',
        result=result
    )

# =========================
# Email report
# =========================

@app.route('/email-report')
def email_report():

    data = session.get(
        'email_report'
    )

    if not data:

        return "No Email Analysis Found"

    pdf_file = f"email_report_{int(time.time())}.pdf"

    doc = SimpleDocTemplate(
        pdf_file
    )

    styles = getSampleStyleSheet()

    content = []

    # =====================
    # TITLE
    # =====================

    content.append(
        Paragraph(
            "Email Investigation Report",
            styles['Title']
        )
    )

    content.append(
        Spacer(1,12)
    )

    # =====================
    # ANALYST
    # =====================

    content.append(
        Paragraph(
            f"<b>Analyst:</b> {data.get('analyst','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Timestamp:</b> {data.get('timestamp','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Spacer(1,10)
    )

    # =====================
    # EMAIL DETAILS
    # =====================

    content.append(
        Paragraph(
            "Email Details",
            styles['Heading2']
        )
    )

    content.append(
        Paragraph(
            f"<b>From:</b> {data.get('from','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>To:</b> {data.get('to','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Subject:</b> {data.get('subject','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Source IP:</b> {data.get('source_ip','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Spacer(1,10)
    )

    # =====================
    # AUTHENTICATION
    # =====================

    content.append(
        Paragraph(
            "Authentication Results",
            styles['Heading2']
        )
    )

    content.append(
        Paragraph(
            f"SPF: {data.get('spf','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"DKIM: {data.get('dkim','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"DMARC: {data.get('dmarc','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Spacer(1,10)
    )

    # =====================
    # GEOIP
    # =====================

    geo = data.get(
        "geoip",
        {}
    )

    content.append(
        Paragraph(
            "GeoIP Information",
            styles['Heading2']
        )
    )

    content.append(
        Paragraph(
            f"Country: {geo.get('country','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Region: {geo.get('regionName','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"City: {geo.get('city','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"ZIP: {geo.get('zip','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"ISP: {geo.get('isp','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"ASN: {geo.get('as','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Spacer(1,10)
    )

    # =====================
    # ABUSEIPDB
    # =====================

    abuse = data.get(
        "abuse",
        {}
    )

    abuse_data = abuse.get(
        "data",
        {}
    )

    content.append(
        Paragraph(
            "AbuseIPDB Reputation",
            styles['Heading2']
        )
    )

    content.append(
        Paragraph(
            f"Abuse Score: {abuse_data.get('abuseConfidenceScore','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Country: {abuse_data.get('countryCode','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Usage Type: {abuse_data.get('usageType','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"ISP: {abuse_data.get('isp','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Domain: {abuse_data.get('domain','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Total Reports: {abuse_data.get('totalReports','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"Last Reported: {abuse_data.get('lastReportedAt','N/A')}",
            styles['BodyText']
        )
    )

    content.append(
        Spacer(1,10)
    )

    # =====================
    # RECEIVED HEADERS
    # =====================

    content.append(
        Paragraph(
            "Received Headers",
            styles['Heading2']
        )
    )

    for item in data.get(
        "received",
        []
    ):

        content.append(
            Paragraph(
                item,
                styles['BodyText']
            )
        )

        content.append(
            Spacer(1,5)
        )

    # =====================
    # BUILD PDF
    # =====================

    doc.build(content)

    audit_log(
        session.get(
            'user',
            'Unknown'
        ),
        "EMAIL_REPORT_EXPORT",
        request.remote_addr
    )

    return send_file(
        pdf_file,
        as_attachment=True
    )


# =========================
# IOC page
# =========================

@app.route('/ioc', methods=['GET', 'POST'])
def ioc():

    result = None

    risk_level = "Low"

    threat_score = 0

    if request.method == 'POST':

        indicator = request.form.get(
            'indicator',
            ''
        ).strip()

        ioc_type = "Unknown"

        intel = {}

        # =========================
        # IOC TYPE DETECTION
        # =========================

        try:

            ipaddress.ip_address(
                indicator
            )

            ioc_type = "IP Address"

        except:

            pass

        if re.match(
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            indicator
        ):
            ioc_type = "Domain"

        if indicator.startswith(
            'http'
        ):
            ioc_type = "URL"

        if '@' in indicator:
            ioc_type = "Email"

        if re.match(
            r'^[A-Fa-f0-9]{32,64}$',
            indicator
        ):
            ioc_type = "Hash"



        # =========================
        # IP LOOKUP
        # =========================

        if ioc_type == "IP Address":

            try:

                geo = requests.get(
                    f"http://ip-api.com/json/{indicator}"
                ).json()

                intel["geoip"] = geo

            except:

                intel["geoip"] = {}

            try:

                url = (
                    "https://api.abuseipdb.com/api/v2/check"
                )

                headers = {

                    "Key": ABUSE_API_KEY,

                    "Accept":
                    "application/json"

                }

                params = {

                    "ipAddress":
                    indicator,

                    "maxAgeInDays":
                    90

                }

                abuse = requests.get(

                    url,

                    headers=headers,

                    params=params

                ).json()

                intel["abuseip"] = abuse

            except:

                intel["abuseip"] = {}

        # =========================
        # DOMAIN LOOKUP
        # =========================

        elif ioc_type == "Domain":

            try:

                intel["whois"] = str(
                    whois.whois(
                        indicator
                    )
                )

            except:

                intel["whois"] = "Failed"

            try:

                answers = dns.resolver.resolve(
                    indicator,
                    'A'
                )

                intel["dns"] = [

                    str(x)

                    for x in answers

                ]

            except:

                intel["dns"] = []

        # =========================
        # HASH LOOKUP
        # =========================

        elif ioc_type == "Hash":

            try:

                headers = {

                    "x-apikey":
                    VT_API_KEY

                }

                vt = requests.get(

                    f"https://www.virustotal.com/api/v3/files/{indicator}",

                    headers=headers

                ).json()

                intel["virustotal"] = vt

            except:

                intel["virustotal"] = {}

        # =========================
        # THREAT SCORE
        # =========================

        threat_score = calculate_threat_score(
            intel
        )

        risk_level = get_risk_level(
            threat_score
        )

        # =====================
        # WATCHLIST CHECK
        # =====================

        conn = sqlite3.connect(
            "investigations.db"
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM watchlists
            WHERE indicator=?
            """,
            (indicator,)
        )

        watchlist_match = cursor.fetchone()

        if watchlist_match:

            create_alert(

                "Watchlist Match",

                f"{indicator} matched watchlist",

                "Critical"

            )

        # conn.close()


        mitre = get_mitre_mapping(
            "IOC"
        )

        # =========================
        # Risk Based Mapping
        # =========================

        if risk_level == "Critical":

            mitre = {

                "technique_id": "T1071",

                "name": "Application Layer Protocol",

                "tactic": "Command and Control"

            }

        elif risk_level == "High":

            mitre = {

                "technique_id": "T1583",

                "name": "Acquire Infrastructure",

                "tactic": "Resource Development"

            }

        else:

            mitre = {

                "technique_id": "N/A",

                "name": "Unknown",

                "tactic": "Unknown"

            }

        # =====================
        # THREAT FEED INSERT
        # =====================

        if risk_level in [
            "High",
            "Critical"
        ]:

            conn = sqlite3.connect(
                "investigations.db"
            )

            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO threat_feed
                (
                    threat_type,
                    indicator,
                    severity,
                    source,
                    created_at
                )
                VALUES
                (?, ?, ?, ?, ?)
                """,
                (
                    "IP",
                    indicator,
                    risk_level,
                    "IOC Analyzer",
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )
            )



        # IOC Intergrstion 

        if risk_level == "Critical":

            create_alert(

                "Critical IOC Detected",

                f"Indicator: {indicator}",

                "Critical"

            )



        conn.commit()

        conn.close()

        # =========================
        # RESULT
        # =========================

        result = {

            "indicator":
            indicator,

            "type":
            ioc_type,

            "intel":
            intel,

            "threat_score":
            threat_score,

            "risk_level":
            risk_level,

            "mitre": mitre,

            

        }

        result["mitre"] = mitre

        save_investigation(

            "IOC",

            indicator,

            str(result)[:5000]

        )

    return render_template(

        'ioc.html',

        result=result
        

    )

# =========================
# admin/users
# =========================

@app.route('/admin/users')
def admin_users():

    if session.get("role") != "admin":

        flash(
            "Access Denied"
        )

        return redirect("/")

    conn = sqlite3.connect(
        "investigations.db"
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""

    SELECT *

    FROM users

    ORDER BY username

    """)

    users = cursor.fetchall()

    conn.close()

    return render_template(

        "admin_users.html",

        users=users

    )

# =========================
# manage user
# =========================

@app.route('/manage_user/<int:user_id>')
def manage_user(user_id):

    if session.get("role") != "admin":

        flash("Access Denied")

        return redirect('/')

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE id=?
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    conn.close()

    if not user:

        flash("User not found")

        return redirect(
            url_for('admin_users')
        )

    return render_template(
        'manage_user.html',
        user=user
    )
# =========================
#Delete user
# =========================

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):

    if session.get("role") != "admin":

        flash("Access Denied", "danger")

        return redirect(url_for("home"))

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    # Admin account delete hone se roko
    cursor.execute(
        "SELECT username FROM users WHERE id=?",
        (user_id,)
    )

    user = cursor.fetchone()

    if not user:

        conn.close()

        flash(
            "User not found",
            "warning"
        )

        return redirect(
            url_for("admin_users")
        )

    if user[0] == "admin":

        conn.close()

        flash(
            "Default admin cannot be deleted.",
            "danger"
        )

        return redirect(
            url_for("admin_users")
        )

    cursor.execute(
        "DELETE FROM users WHERE id=?",
        (user_id,)
    )

    conn.commit()

    conn.close()

    audit_log(
        session.get("user"),
        f"Deleted user ID {user_id}",
        request.remote_addr
    )

    flash(
        "User deleted successfully.",
        "success"
    )

    return redirect(
        url_for("admin_users")
    )

# =========================
#toggle User 
# =========================

@app.route('/toggle_user/<int:user_id>')
def toggle_user(user_id):

    if session.get("role") != "admin":

        flash("Access Denied")

        return redirect("/")

    conn = sqlite3.connect(
        "investigations.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT is_active
        FROM users
        WHERE id=?
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    if not user:

        conn.close()

        flash("User not found")

        return redirect(
            url_for("admin_users")
        )

    new_status = 0 if user[0] else 1

    cursor.execute(
        """
        UPDATE users
        SET is_active=?
        WHERE id=?
        """,
        (
            new_status,
            user_id
        )
    )

    conn.commit()

    conn.close()

    audit_log(
        session.get("user"),
        f"Changed active status of user {user_id}",
        request.remote_addr
    )

    flash(
        "User status updated"
    )

    return redirect(
        url_for("manage_user", user_id=user_id)
    )


# =========================
# Change role 
# =========================

@app.route('/change_role/<int:user_id>')
def change_role(user_id):

    if session.get("role") != "admin":

        flash("Access Denied")

        return redirect("/")

    conn = sqlite3.connect(
        "investigations.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT role
        FROM users
        WHERE id=?
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    if not user:

        conn.close()

        flash("User not found")

        return redirect(
            url_for("admin_users")
        )

    new_role = (
        "admin"
        if user[0] == "user"
        else "user"
    )

    cursor.execute(
        """
        UPDATE users
        SET role=?
        WHERE id=?
        """,
        (
            new_role,
            user_id
        )
    )

    conn.commit()

    conn.close()

    audit_log(
        session.get("user"),
        f"Changed role of user {user_id} to {new_role}",
        request.remote_addr
    )

    flash(
        "Role updated"
    )

    return redirect(
        url_for(
            "manage_user",
            user_id=user_id
        )
    )

# =========================
# reset user 
# =========================

@app.route('/reset_user/<int:user_id>')
def reset_user(user_id):

    if session.get("role") != "admin":

        flash("Access Denied")

        return redirect("/")

    conn = sqlite3.connect(
        "investigations.db"
    )

    cursor = conn.cursor()

    new_password = generate_password_hash(
        "Password@123"
    )

    cursor.execute(
        """
        UPDATE users
        SET password=?
        WHERE id=?
        """,
        (
            new_password,
            user_id
        )
    )

    conn.commit()

    conn.close()

    audit_log(
        session.get("user"),
        f"Reset password for user {user_id}",
        request.remote_addr
    )

    flash(
        "Password reset successfully. Temporary password: Password@123"
    )

    return redirect(
        url_for(
            "manage_user",
            user_id=user_id
        )
    )


# =========================
# export report 
# =========================

@app.route('/report/<int:investigation_id>')
def export_report(investigation_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM investigations
        WHERE id=?
        """,
        (investigation_id,)
    )

    investigation = cursor.fetchone()

    conn.close()

    if not investigation:

        flash(
            "Investigation not found"
        )

        return redirect('/history')

    pdf_file = f"report_{investigation_id}.pdf"

    doc = SimpleDocTemplate(
        pdf_file
    )

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "OSINT Investigation Report",
            styles['Title']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            f"<b>Module:</b> {investigation[1]}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"<b>Target:</b> {investigation[2]}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"<b>Timestamp:</b> {investigation[4]}",
            styles['Normal']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "<b>Result</b>",
            styles['Heading2']
        )
    )

    elements.append(
        Paragraph(
            str(investigation[3]),
            styles['Normal']
        )
    )

    doc.build(elements)

    return send_file(
        pdf_file,
        as_attachment=True
    )

# =========================
# Investigation page 
# =========================

@app.route('/investigation/<int:investigation_id>')
def investigation_detail(investigation_id):

    if 'user' not in session:
        return redirect('/login')

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM investigations
        WHERE id=?
        """,
        (investigation_id,)
    )

    investigation = cursor.fetchone()

    conn.close()

    if not investigation:

        flash(
            "Investigation not found"
        )

        return redirect(
            url_for('history')
        )

    return render_template(
        'investigation_detail.html',
        investigation=investigation
    )


# =========================
# investigation api
# =========================



@app.route('/investigation_api/<int:investigation_id>')
def investigation_api(investigation_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM investigations
        WHERE id=?
        """,
        (investigation_id,)
    )

    investigation = cursor.fetchone()

    conn.close()

    if not investigation:

        return jsonify({
            "error": "Not Found"
        })

    return jsonify({

        "id": investigation[0],

        "module": investigation[1],

        "target": investigation[2],

        "result": investigation[3],

        "timestamp": investigation[4]

    })

# =========================
# Pin Investigation Route
# =========================
@app.route('/pin_investigation/<int:investigation_id>')
def pin_investigation(investigation_id):

    try:

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE investigations
            SET is_pinned =
            CASE
                WHEN is_pinned = 1
                THEN 0
                ELSE 1
            END
            WHERE id=?
            """,
            (investigation_id,)
        )

        conn.commit()

        conn.close()

        return jsonify({

            "success": True,

            "message": "Pinned status updated"

        })

    except Exception as e:

        return jsonify({

            "success": False,

            "error": str(e)

        })

# =========================
# Important Route
# =========================

@app.route('/important_investigation/<int:investigation_id>')
def important_investigation(investigation_id):

    try:

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE investigations
            SET is_important =
            CASE
                WHEN is_important = 1
                THEN 0
                ELSE 1
            END
            WHERE id=?
            """,
            (investigation_id,)
        )

        conn.commit()

        conn.close()

        return jsonify({

            "success": True,

            "message": "Important status updated"

        })

    except Exception as e:

        return jsonify({

            "success": False,

            "error": str(e)

        })
# =========================
# Delete Investigation Route
# =========================

@app.route('/delete_investigation/<int:investigation_id>')
def delete_investigation(investigation_id):

    try:

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM investigations
            WHERE id=?
            """,
            (investigation_id,)
        )

        conn.commit()

        conn.close()

        return jsonify({

            "success": True,

            "message": "Investigation deleted"

        })

    except Exception as e:

        return jsonify({

            "success": False,

            "error": str(e)

        })
    
# =========================
# JSON Export Route
# =========================

@app.route('/export/json')
def export_json():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM investigations
        """
    )

    investigations = cursor.fetchall()

    conn.close()

    data = []

    for row in investigations:

        data.append({

            "id": row["id"],

            "module": row["module"],

            "target": row["target"],

            "result": row["result"],

            "timestamp": row["timestamp"]

        })

    return app.response_class(

        response=json.dumps(
            data,
            indent=4
        ),

        mimetype='application/json'
    )


# =========================
# executive_report
# =========================

@app.route('/executive_report')
def executive_report():
  
    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    # Total Investigations

    cursor.execute(
        "SELECT COUNT(*) FROM investigations"
    )

    total_investigations = cursor.fetchone()[0]

    # Total Users

    cursor.execute(
        "SELECT COUNT(*) FROM users"
    )

    total_users = cursor.fetchone()[0]

    # Most Used Module

    cursor.execute(
        """
        SELECT module,
            COUNT(*) as total
        FROM investigations
        GROUP BY module
        ORDER BY total DESC
        LIMIT 1
        """
    )

    module = cursor.fetchone()

    # Top Target

    cursor.execute(
        """
        SELECT target,
            COUNT(*) as total
        FROM investigations
        GROUP BY target
        ORDER BY total DESC
        LIMIT 1
        """
    )

    target = cursor.fetchone()

    # Recent Activity

    cursor.execute(
        """
        SELECT user,
            action,
            timestamp
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 20
        """
    )

    recent_logs = cursor.fetchall()

    conn.close()

    filename = "executive_report.pdf"

    doc = SimpleDocTemplate(
        filename
    )

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "Executive Security Report",
            styles['Title']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            f"Total Investigations: {total_investigations}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Total Users: {total_users}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Most Used Module: {module[0] if module else 'N/A'}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Top Target: {target[0] if target else 'N/A'}",
            styles['Normal']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "Recent Activity",
            styles['Heading2']
        )
    )

    for log in recent_logs:

        elements.append(
            Paragraph(
                f"{log[0]} - {log[1]} - {log[2]}",
                styles['Normal']
            )
        )

    doc.build(elements)

    return send_file(
        filename,
        as_attachment=True
    )

# =========================
# dashboard_report
# =========================

@app.route('/dashboard_report')
def dashboard_report():

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    # =========================
    # STATS
    # =========================

    cursor.execute(
        "SELECT COUNT(*) FROM investigations"
    )

    total_investigations = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM users"
    )

    total_users = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE role='admin'
        """
    )

    admin_users = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE is_active=1
        """
    )

    active_users = cursor.fetchone()[0]

    # =========================
    # MOST USED MODULE
    # =========================

    cursor.execute(
        """
        SELECT module,
            COUNT(*) AS total
        FROM investigations
        GROUP BY module
        ORDER BY total DESC
        LIMIT 1
        """
    )

    module = cursor.fetchone()

    # =========================
    # TOP TARGET
    # =========================

    cursor.execute(
        """
        SELECT target,
            COUNT(*) AS total
        FROM investigations
        GROUP BY target
        ORDER BY total DESC
        LIMIT 1
        """
    )

    target = cursor.fetchone()

    # =========================
    # RECENT ACTIVITY
    # =========================

    cursor.execute(
        """
        SELECT user,
            action,
            timestamp
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 10
        """
    )

    logs = cursor.fetchall()

    conn.close()

    filename = "dashboard_report.pdf"

    doc = SimpleDocTemplate(
        filename
    )

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "OSINT Dashboard Report",
            styles['Title']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "Dashboard Statistics",
            styles['Heading2']
        )
    )

    elements.append(
        Paragraph(
            f"Total Investigations: {total_investigations}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Total Users: {total_users}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Admin Users: {admin_users}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Active Users: {active_users}",
            styles['Normal']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "Analytics",
            styles['Heading2']
        )
    )

    elements.append(
        Paragraph(
            f"Most Used Module: {module[0] if module else 'N/A'}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Top Target: {target[0] if target else 'N/A'}",
            styles['Normal']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "Recent Activity",
            styles['Heading2']
        )
    )

    for log in logs:

        elements.append(
            Paragraph(
                f"{log[0]} | {log[1]} | {log[2]}",
                styles['Normal']
            )
        )

    doc.build(elements)

    return send_file(
        filename,
        as_attachment=True
    )

# =========================
# create_case
# =========================

@app.route('/create_case', methods=['GET','POST'])
def create_case():

    if request.method == 'POST':

        title = request.form['title']

        target = request.form['target']

        module = request.form['module']

        priority = request.form['priority']

        assigned_to = request.form['assigned_to']

        notes = request.form['notes']

        conn = sqlite3.connect(
            'investigations.db'
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO cases
            (
                title,
                target,
                module,
                priority,
                assigned_to,
                notes,
                created_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                target,
                module,
                priority,
                assigned_to,
                notes,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()
        conn.close()

        flash(
            "Case Created Successfully"
        )

        return redirect(
            url_for('cases')
        )

    return render_template(
        'create_case.html'
    )

# =========================
# Cases List
# =========================

@app.route('/cases')
def cases():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM cases
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return render_template(
        'cases.html',
        rows=rows
    )

# =========================
# Case Detail Route
# =========================

@app.route('/case/<int:case_id>')
def case_detail(case_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    # Case Fetch

    cursor.execute(
        """
        SELECT *
        FROM cases
        WHERE id=?
        """,
        (case_id,)
    )

    case = cursor.fetchone()

    # Evidence Fetch

    cursor.execute(
        """
        SELECT *
        FROM evidence
        WHERE case_id=?
        """,
        (case_id,)
    )

    evidence = cursor.fetchall()

    # COMMENTS

    cursor.execute(
    """
    SELECT *
    FROM case_comments
    WHERE case_id=?
    ORDER BY id DESC
    """,
    (case_id,)
    )

    comments = cursor.fetchall()

    # TIMELINE

    cursor.execute(
    """
    SELECT *
    FROM case_timeline
    WHERE case_id=?
    ORDER BY id DESC
    """,
    (case_id,)
    )

    timeline = cursor.fetchall()


    for row in evidence:
        print(dict(row))

    print("Evidence Data:", evidence)

    # Available Investigations

    cursor.execute(
    """
    SELECT id,
    module,
    target
    FROM investigations
    ORDER BY id DESC
    """
    )

    investigations = cursor.fetchall()

# Linked Investigations

    cursor.execute(
    """
    SELECT
    investigations.id,
    investigations.module,
    investigations.target,
    investigations.timestamp


    FROM investigations

    JOIN case_investigations

    ON investigations.id =
    case_investigations.investigation_id

    WHERE case_investigations.case_id=?
    """,
    (case_id,)


    )

    linked_investigations = cursor.fetchall()


    conn.close()

    if not case:

        flash(
            "Case not found"
        )

        return redirect(
            url_for('cases')
        )

    return render_template(
        'case_detail.html',
        case=case,
        evidence=evidence,
        investigations=investigations,
        linked_investigations=linked_investigations,
        comments=comments,
        timeline=timeline
    )

# =========================
# Status Update Route
# =========================

@app.route('/update_case_status/<int:case_id>/<status>')
def update_case_status(
    case_id,
    status
):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE cases
        SET status=?
        WHERE id=?
        """,
        (
            status,
            case_id
        )
    )

    conn.commit()

    conn.close()

    flash(
        "Case status updated"
    )

    add_case_timeline(

        case_id,

        f"Status changed to {status}"

    )

    

    return redirect(
        url_for(
            'case_detail',
            case_id=case_id
        )
    )

# =========================
# Delete Case Route
# =========================

@app.route('/delete_case/<int:case_id>')
def delete_case(case_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM cases
        WHERE id=?
        """,
        (case_id,)
    )

    conn.commit()

    conn.close()

    flash(
        "Case deleted"
    )

    return redirect(
        url_for('cases')
    )

# =========================
# Upload Evidence Route
# =========================

@app.route('/upload_evidence/<int:case_id>', methods=['POST'])
def upload_evidence(case_id):

    if 'file' not in request.files:

        flash(
            "No file selected"
        )

        return redirect(
            url_for(
                'case_detail',
                case_id=case_id
            )
        )

    file = request.files['file']

    if file.filename == '':

        flash(
            "No file selected"
        )

        return redirect(
            url_for(
                'case_detail',
                case_id=case_id
            )
        )

    filename = secure_filename(
        file.filename
    )

    filepath = os.path.join(
        app.config['EVIDENCE_FOLDER'],
        filename
    )

    file.save(filepath)

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO evidence
        (
            case_id,
            filename,
            filepath,
            uploaded_by,
            uploaded_at
        )
        VALUES
        (?, ?, ?, ?, ?)
        """,
        (
            case_id,
            filename,
            filepath,
            session.get(
                'user'
            ),
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    conn.commit()

    conn.close()

    flash(
        "Evidence uploaded"
    )

    add_case_timeline(

        case_id,

        f"Uploaded evidence: {filename}"

    )

    return redirect(
        url_for(
            'case_detail',
            case_id=case_id
        )
    )

# =========================
# Evidence Download Route
# =========================

@app.route('/evidence/<path:filename>')
def download_evidence(filename):

    return send_from_directory(
        app.config['EVIDENCE_FOLDER'],
        filename
    )

# =========================
# Link Route
# =========================

@app.route(
    '/link_investigation/<int:case_id>',
    methods=['POST']
)
def link_investigation(case_id):

    investigation_id = request.form.get(
        'investigation_id'
    )

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO case_investigations
        (
            case_id,
            investigation_id
        )
        VALUES
        (?, ?)
        """,
        (
            case_id,
            investigation_id
        )
    )

    conn.commit()

    conn.close()

    flash(
        "Investigation linked"
    )

    add_case_timeline(

        case_id,

        f"Linked investigation #{investigation_id}"

    )

    return redirect(
        url_for(
            'case_detail',
            case_id=case_id
        )
    )

# =========================
# Comment Route
# =========================
#@csrf.exempt
@app.route(
'/add_case_comment/<int:case_id>',
methods=['POST']
)
def add_case_comment(case_id):

    comment = request.form.get(
        'comment'
    )

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO case_comments
        (
            case_id,
            username,
            comment,
            created_at
        )
        VALUES
        (?, ?, ?, ?)
        """,
        (
            case_id,
            session.get('user'),
            comment,
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    conn.commit()
    conn.close()

    add_case_timeline(
        case_id,
        f"Added comment"
    )

    flash(
        "Comment added"
    )

    return redirect(
        url_for(
            'case_detail',
            case_id=case_id
        )
    )

# =========================
# Case Report 
# =========================

@app.route('/case_report/<int:case_id>')
def case_report(case_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    # Case

    cursor.execute(
        """
        SELECT *
        FROM cases
        WHERE id=?
        """,
        (case_id,)
    )

    case = cursor.fetchone()

    if not case:

        conn.close()

        flash(
            "Case not found"
        )

        return redirect(
            url_for('cases')
        )

    # Evidence

    cursor.execute(
        """
        SELECT filename
        FROM evidence
        WHERE case_id=?
        """,
        (case_id,)
    )

    evidence = cursor.fetchall()

    # Linked Investigations

    cursor.execute(
        """
        SELECT
            investigations.module,
            investigations.target

        FROM investigations

        JOIN case_investigations

        ON investigations.id =
        case_investigations.investigation_id

        WHERE case_investigations.case_id=?
        """,
        (case_id,)
    )

    linked = cursor.fetchall()

    # Comments

    cursor.execute(
        """
        SELECT
            username,
            comment
        FROM case_comments
        WHERE case_id=?
        """,
        (case_id,)
    )

    comments = cursor.fetchall()

    # Timeline

    cursor.execute(
        """
        SELECT
            username,
            action,
            timestamp
        FROM case_timeline
        WHERE case_id=?
        ORDER BY id DESC
        """,
        (case_id,)
    )

    timeline = cursor.fetchall()

    conn.close()

    filename = f"case_{case_id}_report.pdf"

    doc = SimpleDocTemplate(
        filename
    )

    styles = getSampleStyleSheet()

    elements = []

    # Title

    elements.append(
        Paragraph(
            f"Case Report #{case[0]}",
            styles['Title']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    # Case Details

    elements.append(
        Paragraph(
            "Case Information",
            styles['Heading2']
        )
    )

    elements.append(
        Paragraph(
            f"Title: {case[1]}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Target: {case[2]}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Module: {case[3]}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Priority: {case[4]}",
            styles['Normal']
        )
    )

    elements.append(
        Paragraph(
            f"Status: {case[5]}",
            styles['Normal']
        )
    )

    elements.append(
        Spacer(1,12)
    )

    # Evidence

    elements.append(
        Paragraph(
            "Evidence",
            styles['Heading2']
        )
    )

    for item in evidence:

        elements.append(
            Paragraph(
                f"- {item[0]}",
                styles['Normal']
            )
        )

    # Investigations

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "Linked Investigations",
            styles['Heading2']
        )
    )

    for inv in linked:

        elements.append(
            Paragraph(
                f"{inv[0]} | {inv[1]}",
                styles['Normal']
            )
        )

    # Comments

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "Comments",
            styles['Heading2']
        )
    )

    for comment in comments:

        elements.append(
            Paragraph(
                f"{comment[0]}: {comment[1]}",
                styles['Normal']
            )
        )

    # Timeline

    elements.append(
        Spacer(1,12)
    )

    elements.append(
        Paragraph(
            "Timeline",
            styles['Heading2']
        )
    )

    for item in timeline:

        elements.append(
            Paragraph(
                f"{item[2]} | {item[0]} | {item[1]}",
                styles['Normal']
            )
        )

    doc.build(elements)

    return send_file(
        filename,
        as_attachment=True
    )

# =========================
# reputation
# =========================

@app.route(
    '/reputation',
    methods=['GET', 'POST']
)
def reputation():

    result = None

    if request.method == 'POST':

        indicator = request.form.get(
            'indicator',
            ''
        ).strip()

        intel = {}

        score = 0

        verdict = "Unknown"

        # =====================
        # IP CHECK
        # =====================

        try:

            ipaddress.ip_address(
                indicator
            )

            geo = requests.get(
                f"http://ip-api.com/json/{indicator}"
            ).json()

            intel["geoip"] = geo

            url = (
                "https://api.abuseipdb.com/api/v2/check"
            )

            headers = {

                "Key":
                    ABUSE_API_KEY,

                "Accept":
                    "application/json"
            }

            params = {

                "ipAddress":
                    indicator,

                "maxAgeInDays":
                    90
            }

            abuse = requests.get(

                url,

                headers=headers,

                params=params

            ).json()

            intel["abuse"] = abuse

            score = abuse.get(
                "data",
                {}
            ).get(
                "abuseConfidenceScore",
                0
            )

        except:
            pass

        # =====================
        # HASH CHECK
        # =====================

        if re.match(
            r'^[A-Fa-f0-9]{32,64}$',
            indicator
        ):

            try:

                headers = {

                    "x-apikey":
                        VT_API_KEY
                }

                vt = requests.get(

                    f"https://www.virustotal.com/api/v3/files/{indicator}",

                    headers=headers

                ).json()

                intel["virustotal"] = vt

                malicious = vt.get(
                    "data",
                    {}
                ).get(
                    "attributes",
                    {}
                ).get(
                    "last_analysis_stats",
                    {}
                ).get(
                    "malicious",
                    0
                )

                score += malicious * 5

            except:
                pass

        # =====================
        # DOMAIN CHECK
        # =====================

        if re.match(
            r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            indicator
        ):

            try:

                intel["whois"] = str(
                    whois.whois(
                        indicator
                    )
                )

            except:
                pass

        # =====================
        # RISK
        # =====================

        if score >= 76:

            verdict = "Malicious"

        elif score >= 51:

            verdict = "High Risk"

        elif score >= 26:

            verdict = "Suspicious"

        else:

            verdict = "Benign"

        result = {

            "indicator":
                indicator,

            "score":
                score,

            "verdict":
                verdict,

            "intel":
                intel
        }

    return render_template(

        'reputation.html',

        result=result
    )

# =========================
# domain_intel
# =========================

@app.route(
    '/domain_intel',
    methods=['GET', 'POST']
)
def domain_intel():

    result = None

    if request.method == 'POST':

        domain = request.form.get(
            'domain',
            ''
        ).strip()

        intel = {}

        score = 0

        verdict = "Benign"

        try:

            w = whois.whois(domain)

            intel["registrar"] = str(
                w.registrar
            )

            intel["creation_date"] = str(
                w.creation_date
            )

            intel["expiration_date"] = str(
                w.expiration_date
            )

            intel["name_servers"] = str(
                w.name_servers
            )

        except Exception as e:

            intel["whois_error"] = str(e)

        try:

            a_records = dns.resolver.resolve(
                domain,
                'A'
            )

            intel["a_records"] = [

                str(x)

                for x in a_records

            ]

        except:

            intel["a_records"] = []

        try:

            mx_records = dns.resolver.resolve(
                domain,
                'MX'
            )

            intel["mx_records"] = [

                str(x.exchange)

                for x in mx_records

            ]

        except:

            intel["mx_records"] = []

        # Domain Age Risk

        try:

            creation = w.creation_date

            if isinstance(
                creation,
                list
            ):
                creation = creation[0]

            age_days = (
                datetime.now()
                -
                creation
            ).days

            intel["domain_age"] = age_days

            if age_days < 30:

                score += 40

            elif age_days < 90:

                score += 20

        except:

            intel["domain_age"] = "Unknown"

        # Verdict

        if score >= 70:

            verdict = "Malicious"

        elif score >= 40:

            verdict = "Suspicious"

        else:

            verdict = "Benign"

        result = {

            "domain": domain,

            "score": score,

            "verdict": verdict,

            "intel": intel

        }

        save_investigation(

            "DOMAIN_INTEL",

            domain,

            str(result)

        )

    return render_template(

        "domain_intel.html",

        result=result

    )

# =========================
# Email intel 
# =========================

@app.route(
    '/email_intel',
    methods=['GET','POST']
)
def email_intel():

    result = None

    if request.method == 'POST':

        header = request.form.get(
            'header',
            ''
        )

        parsed = Parser().parsestr(
            header
        )

        score = 0

        verdict = "Benign"

        intel = {}

        intel["from"] = parsed.get(
            "From"
        )

        intel["to"] = parsed.get(
            "To"
        )

        intel["subject"] = parsed.get(
            "Subject"
        )

        # SPF

        spf = parsed.get(
            "Received-SPF",
            ""
        )

        intel["spf"] = spf

        if "fail" in spf.lower():

            score += 30

        # DKIM

        dkim = parsed.get(
            "DKIM-Signature"
        )

        intel["dkim"] = bool(
            dkim
        )

        if not dkim:

            score += 20

        # DMARC

        auth = parsed.get(
            "Authentication-Results",
            ""
        )

        intel["dmarc"] = auth

        if "dmarc=fail" in auth.lower():

            score += 30

        # Source IP

        received = parsed.get_all(
            "Received",
            []
        )

        source_ip = None

        for item in received:

            ips = re.findall(

                r'(?:\d{1,3}\.){3}\d{1,3}',

                item

            )

            if ips:

                source_ip = ips[0]

                break

        intel["source_ip"] = source_ip

        # GeoIP

        if source_ip:

            try:

                geo = requests.get(

                    f"http://ip-api.com/json/{source_ip}"

                ).json()

                intel["geoip"] = geo

            except:

                intel["geoip"] = {}
# 
            country = geo.get(
                "country",
                "Unknown"
            )

            intel["country"] = country


        # Auto Campaign Creation

        if verdict in [
            "Suspicious",
            "Malicious"
        ]:

            cursor.execute(
                """
                INSERT INTO phishing_campaigns
                (
                    sender,
                    subject,
                    source_ip,
                    country,
                    threat_score,
                    created_at
                )
                VALUES
                (?, ?, ?, ?, ?, ?)
                """,
                (
                    intel.get("from"),
                    intel.get("subject"),
                    intel.get("source_ip"),
                    intel.get("country"),
                    score,
                    datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )
            )

            conn.commit()

        # AbuseIPDB

        if source_ip:

            try:

                url = (
                    "https://api.abuseipdb.com/api/v2/check"
                )

                headers = {

                    "Key":
                    ABUSE_API_KEY,

                    "Accept":
                    "application/json"

                }

                params = {

                    "ipAddress":
                    source_ip,

                    "maxAgeInDays":
                    90

                }

                abuse = requests.get(

                    url,

                    headers=headers,

                    params=params

                ).json()

                intel["abuse"] = abuse

                score += abuse.get(
                    "data",
                    {}
                ).get(
                    "abuseConfidenceScore",
                    0
                )

            except:

                pass

        if score > 100:

            score = 100

        if score >= 75:

            verdict = "Malicious"

        elif score >= 40:

            verdict = "Suspicious"

        else:

            verdict = "Benign"

        # =====================
        # THREAT FEED
        # =====================

        if verdict in [
            "Malicious",
            "Suspicious"
        ]:

            severity = (
                "Critical"
                if verdict == "Malicious"
                else "Medium"
            )

            try:

                conn = sqlite3.connect(
                    "investigations.db"
                )

                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO threat_feed
                    (
                        threat_type,
                        indicator,
                        severity,
                        source,
                        created_at
                    )
                    VALUES
                    (?, ?, ?, ?, ?)
                    """,
                    (
                        "EMAIL",
                        intel.get(
                            "from",
                            "Unknown"
                        ),
                        severity,
                        "Email Threat Intel",
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                )

                conn.commit()

                conn.close()

            except Exception as e:

                print(e)



        # =====================
        # RESULT
        # =====================


        result = {

            "score": score,

            "verdict": verdict,

            "intel": intel

        }

        # Alert Integration

        if verdict == "Malicious":

                create_alert(

                    "Phishing Email Detected",

                    f"Sender: {intel.get('from')} | Subject: {intel.get('subject')}",

                    "High"

                )


        save_investigation(

            "EMAIL_INTEL",

            intel.get(
                "from",
                "unknown"
            ),

            str(result)

        )


    return render_template(

        'email_intel.html',

        result=result

    )

# =========================
# Malware intel
# =========================

@app.route(
    '/malware_intel',
    methods=['GET','POST']
)
def malware_intel():

    result = None

    if request.method == 'POST':

        file_hash = request.form.get(
            'hash'
        ).strip()

        intel = {}

        score = 0

        verdict = "Benign"

        try:

            headers = {

                "x-apikey":
                VT_API_KEY

            }

            vt = requests.get(

                f"https://www.virustotal.com/api/v3/files/{file_hash}",

                headers=headers

            ).json()

            intel["vt"] = vt

            stats = vt.get(
                "data",
                {}
            ).get(
                "attributes",
                {}
            ).get(
                "last_analysis_stats",
                {}
            )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )

            harmless = stats.get(
                "harmless",
                0
            )

            score += malicious * 5

            score += suspicious * 3

            family = vt.get(
                "data",
                {}
            ).get(
                "attributes",
                {}
            ).get(
                "popular_threat_classification",
                {}
            ).get(
                "suggested_threat_label",
                "Unknown"
            )

            intel["family"] = family

            intel["malicious"] = malicious

            intel["suspicious"] = suspicious

            intel["harmless"] = harmless

        except:

            intel["error"] = (
                "VirusTotal lookup failed"
            )

        if score > 100:

            score = 100

        if score >= 75:

            verdict = "Malicious"

        elif score >= 40:

            verdict = "Suspicious"

        else:

            verdict = "Benign"

        if verdict == "Malicious":

            create_alert(

                "Malware Detected",

                file_hash,

                "High"

            )

        # =====================
        # THREAT FEED
        # =====================

        if verdict in [
            "Malicious",
            "Suspicious"
        ]:

            severity = (
                "Critical"
                if verdict == "Malicious"
                else "Medium"
            )

            try:

                conn = sqlite3.connect(
                    "investigations.db"
                )

                cursor = conn.cursor()

                cursor.execute(
                    """
                    INSERT INTO threat_feed
                    (
                        threat_type,
                        indicator,
                        severity,
                        source,
                        created_at
                    )
                    VALUES
                    (?, ?, ?, ?, ?)
                    """,
                    (
                        "HASH",
                        file_hash,
                        severity,
                        "Malware Intelligence",
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                )

                conn.commit()

                conn.close()

            except Exception as e:

                print(
                    "Threat Feed Error:",
                    e
                )

        result = {

            "hash": file_hash,

            "score": score,

            "verdict": verdict,

            "intel": intel

        }

        save_investigation(

            "MALWARE_INTEL",

            file_hash,

            str(result)

        )

    return render_template(

        "malware_intel.html",

        result=result

    )

# =============================
# Mitre Lookup
# =============================

@app.route(
    '/mitre_lookup',
    methods=['GET','POST']
)
def mitre_lookup():

    result = None

    if request.method == 'POST':

        indicator_type = request.form.get(
            'indicator_type'
        )

        mapping = get_mitre_mapping(
            indicator_type
        )

        result = mapping

    return render_template(

        'mitre_lookup.html',

        result=result

    )

# =========================
# Threat Feed
# =========================

@app.route('/threat_feed')
def threat_feed():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM threat_feed
        ORDER BY id DESC
        LIMIT 100
        """
    )

    feeds = cursor.fetchall()

    # Statistics

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_feed
        WHERE severity='Critical'
        """
    )

    critical_count = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_feed
        WHERE threat_type='IP'
        """
    )

    ip_count = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_feed
        WHERE threat_type='HASH'
        """
    )

    hash_count = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_feed
        WHERE threat_type='EMAIL'
        """
    )

    email_count = cursor.fetchone()[0]

    conn.close()

    return render_template(

        "threat_feed.html",

        feeds=feeds,

        critical_count=critical_count,

        ip_count=ip_count,

        hash_count=hash_count,

        email_count=email_count
    )

# =========================
# Notes route
# =========================

@app.route(
    '/notes',
    methods=['GET','POST']
)
def notes():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    if request.method == 'POST':

        title = request.form.get(
            'title'
        )

        note = request.form.get(
            'note'
        )

        cursor.execute(
            """
            INSERT INTO analyst_notes
            (
                title,
                note,
                created_by,
                created_at
            )
            VALUES
            (?, ?, ?, ?)
            """,
            (
                title,
                note,
                session.get('user'),
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

        flash(
            "Note saved"
        )

    cursor.execute(
        """
        SELECT *
        FROM analyst_notes
        ORDER BY id DESC
        """
    )

    notes = cursor.fetchall()

    conn.close()

    return render_template(

        "notes.html",

        notes=notes

    )

# Delete mptes route 

@app.route('/delete_note/<int:note_id>')
def delete_note(note_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM analyst_notes
        WHERE id=?
        """,
        (note_id,)
    )

    conn.commit()

    conn.close()

    flash(
        "Note deleted successfully"
    )

    return redirect(
        url_for('notes')
    )
# =========================
# Watchlists route 
# =========================

@app.route(
    '/watchlists',
    methods=['GET','POST']
)
def watchlists():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    if request.method == 'POST':

        indicator = request.form.get(
            'indicator'
        )

        indicator_type = request.form.get(
            'indicator_type'
        )

        severity = request.form.get(
            'severity'
        )

        notes = request.form.get(
            'notes'
        )

        cursor.execute(
            """
            INSERT INTO watchlists
            (
                indicator,
                indicator_type,
                severity,
                notes,
                created_by,
                created_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?)
            """,
            (
                indicator,
                indicator_type,
                severity,
                notes,
                session.get('user'),
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

        flash(
            "Watchlist item added"
        )

    cursor.execute(
        """
        SELECT *
        FROM watchlists
        ORDER BY id DESC
        """
    )

    items = cursor.fetchall()

    conn.close()

    return render_template(
        "watchlists.html",
        items=items
    )

# =========================
# Delete Watchlist route
# =========================

@app.route(
    '/delete_watchlist/<int:item_id>'
)
def delete_watchlist(item_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM watchlists
        WHERE id=?
        """,
        (item_id,)
    )

    conn.commit()

    conn.close()

    flash(
        "Watchlist item deleted"
    )

    return redirect(
        url_for(
            'watchlists'
        )
    )

# =========================
# Saved Searches
# =========================

@app.route(
    '/saved_searches',
    methods=['GET', 'POST']
)
def saved_searches():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    if request.method == 'POST':

        name = request.form.get(
            'name'
        )

        search_type = request.form.get(
            'search_type'
        )

        query = request.form.get(
            'query'
        )

        description = request.form.get(
            'description'
        )

        cursor.execute(
            """
            INSERT INTO saved_searches
            (
                name,
                search_type,
                query,
                description,
                created_by,
                created_at
            )
            VALUES
            (?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                search_type,
                query,
                description,
                session.get('user'),
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

        flash(
            "Search saved successfully"
        )

    cursor.execute(
        """
        SELECT *
        FROM saved_searches
        ORDER BY id DESC
        """
    )

    searches = cursor.fetchall()

    conn.close()

    return render_template(
        "saved_searches.html",
        searches=searches
    )

# =========================
# Delete search route 
# =========================

@app.route(
    '/delete_saved_search/<int:search_id>'
)
def delete_saved_search(search_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM saved_searches
        WHERE id=?
        """,
        (search_id,)
    )

    conn.commit()

    conn.close()

    flash(
        "Saved search deleted"
    )

    return redirect(
        url_for(
            'saved_searches'
        )
    )

# =========================
# Run Saved Route 
# =========================

@app.route('/run_saved_search/<int:search_id>')
def run_saved_search(search_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        '''
        SELECT *
        FROM saved_searches
        WHERE id=?
        ''',
        (search_id,)
    )

    search = cursor.fetchone()

    conn.close()

    if not search:

        flash("Search not found")

        return redirect(
            url_for('saved_searches')
        )

    search_type = search["search_type"]
    query = search["query"]

    if search_type == "DOMAIN":

        return redirect(
            f"/domain_intel?target={query}"
        )

    elif search_type == "IOC":

        return redirect(
            f"/ioc?target={query}"
        )

    elif search_type == "EMAIL":

        return redirect(
            f"/email_intel?target={query}"
        )

    elif search_type == "MALWARE":

        return redirect(
            f"/malware_intel?target={query}"
        )

    return redirect(
        url_for('saved_searches')
    )

# =========================
# Threat hunting route 

@app.route(
    '/threat_hunting',
    methods=['GET','POST']
)
def threat_hunting():

    hunt_results = []

    if request.method == 'POST':

        hunt_type = request.form.get(
            'hunt_type'
        )

        conn = sqlite3.connect(
            'investigations.db'
        )

        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        # =====================
        # HIGH RISK THREATS
        # =====================

        if hunt_type == "critical":

            cursor.execute(
                """
                SELECT *
                FROM threat_feed
                WHERE severity='Critical'
                ORDER BY id DESC
                """
            )

            hunt_results = cursor.fetchall()

        # =====================
        # MALWARE
        # =====================

        elif hunt_type == "malware":

            cursor.execute(
                """
                SELECT *
                FROM investigations
                WHERE module='MALWARE_INTEL'
                ORDER BY id DESC
                """
            )

            hunt_results = cursor.fetchall()

        # =====================
        # EMAIL
        # =====================

        elif hunt_type == "phishing":

            cursor.execute(
                """
                SELECT *
                FROM investigations
                WHERE module='EMAIL_INTEL'
                ORDER BY id DESC
                """
            )

            hunt_results = cursor.fetchall()

        # =====================
        # DOMAIN
        # =====================

        elif hunt_type == "domain":

            cursor.execute(
                """
                SELECT *
                FROM investigations
                WHERE module='DOMAIN_INTEL'
                ORDER BY id DESC
                """
            )

            hunt_results = cursor.fetchall()

        # =====================
        # WATCHLIST MATCHES
        # =====================

        elif hunt_type == "watchlist":

            cursor.execute(
                """
                SELECT *
                FROM watchlists
                ORDER BY id DESC
                """
            )

            hunt_results = cursor.fetchall()

            cursor.execute(
            """
            INSERT INTO threat_hunts
            (
                hunt_name,
                hunt_type,
                results,
                created_by,
                created_at
            )
            VALUES
            (?, ?, ?, ?, ?)
            """,
            (
                f"{hunt_type} Hunt",
                hunt_type,
                str(hunt_results)[:5000],
                session.get('user'),
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

        conn.close()

    return render_template(
        "threat_hunting.html",
        hunt_results=hunt_results
    )

# =========================
# Hunt History 
# =========================

@app.route('/hunt_history')
def hunt_history():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM threat_hunts
        ORDER BY id DESC
        """
    )

    hunts = cursor.fetchall()

    conn.close()

    return render_template(
        "hunt_history.html",
        hunts=hunts
    )

# =========================
# Workbench Route
# =========================

@app.route('/workbench')
def workbench():

    if 'user' not in session:

        return redirect('/login')

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    # =========================
    # Recent Cases
    # =========================

    try:

        cursor.execute(
            '''
            SELECT *
            FROM cases
            ORDER BY rowid DESC
            LIMIT 10
            '''
        )

        cases = cursor.fetchall()

    except:

        cases = []

    # =========================
    # Recent Evidence
    # =========================

    try:

        cursor.execute(
            '''
            SELECT *
            FROM evidence
            ORDER BY rowid DESC
            LIMIT 10
            '''
        )

        evidence = cursor.fetchall()

    except:

        evidence = []

    # =========================
    # Analyst Notes
    # =========================

    try:

        cursor.execute(
            '''
            SELECT *
            FROM analyst_notes
            ORDER BY rowid DESC
            LIMIT 10
            '''
        )

        notes = cursor.fetchall()

    except:

        notes = []

    # =========================
    # Threat Feed
    # =========================

    try:

        cursor.execute(
            '''
            SELECT *
            FROM threat_feed
            ORDER BY rowid DESC
            LIMIT 10
            '''
        )

        threats = cursor.fetchall()

    except:

        threats = []

    # =========================
    # Recent Investigations
    # =========================

    try:

        cursor.execute(
            '''
            SELECT *
            FROM investigations
            ORDER BY rowid DESC
            LIMIT 10
            '''
        )

        investigations = cursor.fetchall()

    except:

        investigations = []

    # =========================
    # Critical Threat Count
    # =========================

    try:

        cursor.execute(
            '''
            SELECT COUNT(*)
            FROM threat_feed
            WHERE severity='Critical'
            '''
        )

        critical_threats = cursor.fetchone()[0]

    except:

        critical_threats = 0

    # =========================
    # Total Counts
    # =========================

    try:

        cursor.execute(
            '''
            SELECT COUNT(*)
            FROM cases
            '''
        )

        total_cases = cursor.fetchone()[0]

    except:

        total_cases = 0

    try:

        cursor.execute(
            '''
            SELECT COUNT(*)
            FROM evidence
            '''
        )

        total_evidence = cursor.fetchone()[0]

    except:

        total_evidence = 0

    try:

        cursor.execute(
            '''
            SELECT COUNT(*)
            FROM investigations
            '''
        )

        total_investigations = cursor.fetchone()[0]

    except:

        total_investigations = 0

    try:

        cursor.execute(
            '''
            SELECT COUNT(*)
            FROM threat_feed
            '''
        )

        total_threats = cursor.fetchone()[0]

    except:

        total_threats = 0

    conn.close()

    return render_template(

        'workbench.html',

        cases=cases,

        evidence=evidence,

        notes=notes,

        threats=threats,

        investigations=investigations,

        critical_threats=critical_threats,

        total_cases=total_cases,

        total_evidence=total_evidence,

        total_investigations=total_investigations,

        total_threats=total_threats

    )

# =========================
# Dashboard
# =========================

@app.route(
    '/dashboards',
    methods=['GET','POST']
)
def dashboards():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    username = session.get(
        'user'
    )

    if request.method == 'POST':

        dashboard_type = request.form.get(
            'dashboard_type'
        )

        cursor.execute(
            """
            DELETE FROM user_dashboards
            WHERE username=?
            """,
            (username,)
        )

        cursor.execute(
            """
            INSERT INTO user_dashboards
            (
                username,
                dashboard_type,
                created_at
            )
            VALUES
            (?, ?, ?)
            """,
            (
                username,
                dashboard_type,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        conn.commit()

        flash(
            "Dashboard updated"
        )

    cursor.execute(
        """
        SELECT dashboard_type
        FROM user_dashboards
        WHERE username=?
        """,
        (username,)
    )

    selected = cursor.fetchone()

    conn.close()

    return render_template(

        "dashboards.html",

        selected=selected

    )

# =========================
# Threat Map Route 
# =========================

@app.route('/threat_map')
def threat_map():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
    SELECT indicator
    FROM threat_feed
    WHERE threat_type='IP'
    LIMIT 50
    """)

    ips = cursor.fetchall()

    markers = []

    for item in ips:

        try:

            geo = requests.get(
                f"http://ip-api.com/json/{item['indicator']}"
            ).json()

            markers.append({

                "ip": item['indicator'],

                "lat": geo.get("lat"),

                "lon": geo.get("lon"),

                "country": geo.get("country")

            })

        except:

            pass

    conn.close()

    return render_template(
        "threat_map.html",
        markers=markers
    )

# =========================
# Malware Dashboard
# =========================

@app.route('/malware_dashboard')
def malware_dashboard():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM investigations
    WHERE module='MALWARE_INTEL'
    ORDER BY id DESC
    LIMIT 20
    """)

    malware_logs = cursor.fetchall()

    total_malware = len(
        malware_logs
    )

    conn.close()

    return render_template(

        'malware_dashboard.html',

        malware_logs=malware_logs,

        total_malware=total_malware
    )

# =========================
# Phishing Dashboard 
# =========================

@app.route('/phishing_dashboard')
def phishing_dashboard():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    # Total Email Intel

    cursor.execute("""
    SELECT COUNT(*)
    FROM investigations
    WHERE module='EMAIL_INTEL'
    """)

    total_emails = cursor.fetchone()[0]

    # SPF Failures

    cursor.execute("""
    SELECT COUNT(*)
    FROM investigations
    WHERE module='EMAIL_INTEL'
    AND result LIKE '%fail%'
    """)

    spf_failures = cursor.fetchone()[0]

    # Recent Emails

    cursor.execute("""
    SELECT *
    FROM investigations
    WHERE module='EMAIL_INTEL'
    ORDER BY id DESC
    LIMIT 10
    """)

    recent_emails = cursor.fetchall()

    conn.close()

    return render_template(

        'phishing_dashboard.html',

        total_emails=total_emails,

        spf_failures=spf_failures,

        recent_emails=recent_emails

    )

# =========================
# IOC Correlation 
# =========================

@app.route(
    '/ioc_correlation',
    methods=['GET','POST']
)
def ioc_correlation():

    result = None

    if request.method == 'POST':

        indicator = request.form.get(
            'indicator'
        ).strip()

        conn = sqlite3.connect(
            'investigations.db'
        )

        conn.row_factory = sqlite3.Row

        cursor = conn.cursor()

        # =====================
        # Investigations
        # =====================

        cursor.execute(
            """
            SELECT *
            FROM investigations
            WHERE target LIKE ?
            """,
            (
                f"%{indicator}%",
            )
        )

        investigations = cursor.fetchall()

        # =====================
        # Cases
        # =====================

        cursor.execute(
            """
            SELECT *
            FROM cases
            WHERE target LIKE ?
            """,
            (
                f"%{indicator}%",
            )
        )

        cases = cursor.fetchall()

        # =====================
        # Watchlists
        # =====================

        cursor.execute(
            """
            SELECT *
            FROM watchlists
            WHERE indicator LIKE ?
            """,
            (
                f"%{indicator}%",
            )
        )

        watchlists = cursor.fetchall()

        # =====================
        # Threat Feed
        # =====================

        cursor.execute(
            """
            SELECT *
            FROM threat_feed
            WHERE indicator LIKE ?
            """,
            (
                f"%{indicator}%",
            )
        )

        threats = cursor.fetchall()

        # =====================
        # Phishing Campaigns
        # =====================

        cursor.execute(
            """
            SELECT *
            FROM phishing_campaigns
            WHERE sender LIKE ?
            OR source_ip LIKE ?
            """,
            (
                f"%{indicator}%",
                f"%{indicator}%"
            )
        )

        campaigns = cursor.fetchall()

        conn.close()

        correlation_score = (

            len(investigations) * 10 +

            len(cases) * 15 +

            len(watchlists) * 20 +

            len(threats) * 20 +

            len(campaigns) * 15

        )

        if correlation_score > 100:

            correlation_score = 100

        result = {

            "indicator":
                indicator,

            "score":
                correlation_score,

            "investigations":
                investigations,

            "cases":
                cases,

            "watchlists":
                watchlists,

            "threats":
                threats,

            "campaigns":
                campaigns

        }

    return render_template(

        "ioc_correlation.html",

        result=result
    )

# =========================
#  Alert Center Route 
# =========================

@app.route('/alerts')
def alerts():

    conn = sqlite3.connect(
        'investigations.db'
    )

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM alerts
        ORDER BY id DESC
        """
    )

    alerts = cursor.fetchall()

    conn.close()

    return render_template(

        'alerts.html',

        alerts=alerts

    )

# =========================
#  Alert Aknowledge Route 
# ========================

@app.route(
'/ack_alert/<int:alert_id>'
)
def ack_alert(alert_id):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE alerts
        SET status='Closed'
        WHERE id=?
        """,
        (alert_id,)
    )

    conn.commit()

    conn.close()

    return redirect(
        url_for(
            'alerts'
        )
    )

# =========================
# Shodan Route 
# =========================

@app.route(
    '/shodan_lookup',
    methods=['GET', 'POST']
)
def shodan_lookup():

    result = None

    if request.method == 'POST':

        ip = request.form.get(
            'ip'
        )

        try:

            api = shodan.Shodan(
                SHODAN_API_KEY
            )

            host = api.host(ip)

            whois_result = None

            try:

                domain = None

                if host.get("domains"):

                    domain = host["domains"][0]

                elif host.get("hostnames"):

                    domain = host["hostnames"][0]

                if domain:

                    whois_result = whois.whois(
                        domain
                    )

            except Exception as e:

                whois_result = str(e)

            ports = host.get("ports", [])

            risk_score = 0

            if 21 in ports:
                risk_score += 10

            if 22 in ports:
                risk_score += 5

            if 23 in ports:
                risk_score += 25

            if 3389 in ports:
                risk_score += 25

            if 445 in ports:
                risk_score += 30

            if 5900 in ports:
                risk_score += 20

            if risk_score <= 20:

                verdict = "🟢 Low Risk"

            elif risk_score <= 50:

                verdict = "🟡 Medium Risk"

            elif risk_score <= 80:

                verdict = "🟠 High Risk"

            else:

                verdict = "🔴 Critical Risk"

            ssl_info = None

            for item in host.get("data", []):

                if item.get("ssl"):

                    cert = item["ssl"].get(
                        "cert",
                        {}
                    )

                    ssl_info = {

                        "subject":
                        cert.get(
                            "subject",
                            {}
                        ).get(
                            "CN",
                            "N/A"
                        ),

                        "issuer":
                        cert.get(
                            "issuer",
                            {}
                        ).get(
                            "CN",
                            "N/A"
                        ),

                        "expires":
                        cert.get(
                            "expires",
                            "N/A"
                        )

                    }

                    break

            services = []

            for item in host.get(
                "data",
                []
            ):

                services.append({

                    "port":
                    item.get(
                        "port",
                        "N/A"
                    ),

                    "transport":
                    item.get(
                        "transport",
                        "N/A"
                    ),

                    "product":
                    item.get(
                        "product",
                        "Unknown"
                    ),

                    "version":
                    item.get(
                        "version",
                        ""
                    )

                })

            result = {

                # Basic

                "ip":
                host.get(
                    "ip_str",
                    "N/A"
                ),

                "org":
                host.get(
                    "org",
                    "N/A"
                ),

                "isp":
                host.get(
                    "isp",
                    "N/A"
                ),

                "asn":
                host.get(
                    "asn",
                    "N/A"
                ),

                # Geo

                "country":
                host.get(
                    "country_name",
                    "N/A"
                ),

                "country_code":
                host.get(
                    "country_code",
                    "N/A"
                ),

                "city":
                host.get(
                    "city",
                    "N/A"
                ),

                "latitude":
                host.get(
                    "latitude",
                    "N/A"
                ),

                "longitude":
                host.get(
                    "longitude",
                    "N/A"
                ),

                # DNS

                "hostname":
                ", ".join(
                    host.get(
                        "hostnames",
                        []
                    )
                ),

                "domains":
                ", ".join(
                    host.get(
                        "domains",
                        []
                    )
                ),

                # System

                "os":
                host.get(
                    "os",
                    "Unknown"
                ),

                "tags":
                ", ".join(
                    host.get(
                        "tags",
                        []
                    )
                ),

                # Services

                "ports":
                ports,

                "services":
                services,

                # SSL

                "ssl":
                ssl_info,

                # Misc

                "last_update":
                host.get(
                    "last_update",
                    "N/A"
                ),

                # Risk

                "risk_score":
                risk_score,

                "verdict":
                verdict

                

            }

            
            result["whois"] = whois_result

            save_investigation(

                "SHODAN",

                ip,

                str(result)

            )

        except Exception as e:

            result = {

                "error":
                str(e)

            }

    raw_data = json.dumps(
        result,
        indent=4,
        default=str
    )

    return render_template(
        "shodan_lookup.html",
        result=result,
        raw_data=raw_data
    )

# Shodan Action routes
# virus total
@app.route('/virustotal/<ip>')
def virustotal_ip(ip):

    # yahan ip already mil jayega

    return redirect(
        url_for(
            'virustotal_lookup',
            target=ip
        )
    )

# corealtion 

@app.route(
    '/ioc_correlation/<indicator>'
)
def ioc_correlation_auto(
    indicator
):

    # indicator directly use karo

    return render_template(
        'ioc_correlation.html',
        indicator=indicator
    )

# IOC 

@app.route('/ioc/<indicator>')
def ioc_auto(indicator):

    return render_template(
        "ioc_redirect.html",
        indicator=indicator
    )

# create case

@app.route(
    '/create_case_from_shodan/<ip>'
)
def create_case_from_shodan(ip):

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO cases
        (
            title,
            target,
            created_by,
            created_at
        )
        VALUES
        (?, ?, ?, ?)
        """,
        (
            f"Shodan Investigation - {ip}",
            ip,
            session.get('user'),
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )
    )

    conn.commit()
    conn.close()

    flash(
        "Case created successfully"
    )

    return redirect(
        url_for(
            'cases'
        )
    )

# Whois

@app.route(
    '/whois/<domain>'
)
def whois_auto(domain):

    return redirect(
        url_for(
            'whois_lookup',
            target=domain
        )
    )

# SHodan Report 
from reportlab.lib import colors

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)
from reportlab.platypus import Preformatted
import json

@app.route(
    '/shodan_report/<ip>'
)
def shodan_report(ip):

    try:

        api = shodan.Shodan(
            SHODAN_API_KEY
        )

        host = api.host(ip)

        ports = host.get(
            "ports",
            []
        )

        risk_score = 0

        if 21 in ports:
            risk_score += 10

        if 22 in ports:
            risk_score += 5

        if 23 in ports:
            risk_score += 25

        if 3389 in ports:
            risk_score += 25

        if 445 in ports:
            risk_score += 30

        if 5900 in ports:
            risk_score += 20

        if risk_score <= 20:

            verdict = "Low Risk"

        elif risk_score <= 50:

            verdict = "Medium Risk"

        elif risk_score <= 80:

            verdict = "High Risk"

        else:

            verdict = "Critical Risk"

        pdf_file = (
            f"reports/shodan_{ip}.pdf"
        )

        doc = SimpleDocTemplate(
            pdf_file
        )

        styles = (
            getSampleStyleSheet()
        )

        title_style = ParagraphStyle(

            'CustomTitle',

            parent=styles['Title'],

            fontSize=22,

            textColor=colors.HexColor(
                "#2563EB"
            ),

            spaceAfter=20

        )

        heading_style = ParagraphStyle(

            'CustomHeading',

            parent=styles['Heading2'],

            fontSize=14,

            textColor=colors.HexColor(
                "#0F172A"
            ),

            spaceBefore=10,

            spaceAfter=8

        )

        body_style = ParagraphStyle(

            'CustomBody',

            parent=styles['BodyText'],

            fontSize=10,

            leading=14

        )

        footer_style = ParagraphStyle(

            'Footer',

            parent=styles['Italic'],

            fontSize=8,

            textColor=colors.grey

        )

        content = []

        # Report header

        content.append(

            Paragraph(

                "🌐 SHODAN INTELLIGENCE REPORT",

                title_style

            )

        )

        content.append(
            Spacer(1,12)
        )

        # Basic information section

        content.append(

            Paragraph(

                "📌 Basic Information",

                heading_style

            )

        )

        content.append(

            Paragraph(

                f"<b>IP Address:</b> {host.get('ip_str','N/A')}",

                body_style

            )

        )

        content.append(

            Paragraph(

                f"<b>Organization:</b> {host.get('org','N/A')}",

                body_style

            )

        )

        content.append(

            Paragraph(

                f"<b>ISP:</b> {host.get('isp','N/A')}",

                body_style

            )

        )

        content.append(

            Paragraph(

                f"<b>ASN:</b> {host.get('asn','N/A')}",

                body_style

            )

        )

        # Geolocation 
        content.append(
            Spacer(1,10)
        )

        content.append(

            Paragraph(

                "🌍 Geolocation",

                heading_style

            )

        )

        content.append(

            Paragraph(

                f"<b>Country:</b> {host.get('country_name','N/A')}",

                body_style

            )

        )

        content.append(

            Paragraph(

                f"<b>City:</b> {host.get('city','N/A')}",

                body_style

            )

        )

        content.append(

            Paragraph(

                f"<b>Coordinates:</b> {host.get('latitude')} , {host.get('longitude')}",

                body_style

            )

        )

        # Service table

        content.append(
            Spacer(1,10)
        )

        content.append(

            Paragraph(

                "📡 Detected Services",

                heading_style

            )

        )

        data = [

            [

                "Port",

                "Protocol",

                "Product"

            ]

        ]

        for item in host.get(
            "data",
            []
        ):

            data.append([

                str(
                    item.get(
                        "port",
                        ""
                    )
                ),

                str(
                    item.get(
                        "transport",
                        ""
                    )
                ),

                str(
                    item.get(
                        "product",
                        "Unknown"
                    )
                )

            ])

        table = Table(
            data
        )

        table.setStyle(

            TableStyle([

                (

                    'BACKGROUND',

                    (0,0),

                    (-1,0),

                    colors.HexColor(
                        "#2563EB"
                    )

                ),

                (

                    'TEXTCOLOR',

                    (0,0),

                    (-1,0),

                    colors.white

                ),

                (

                    'FONTNAME',

                    (0,0),

                    (-1,0),

                    'Helvetica-Bold'

                ),

                (

                    'GRID',

                    (0,0),

                    (-1,-1),

                    1,

                    colors.black

                ),

                (

                    'ROWBACKGROUNDS',

                    (0,1),

                    (-1,-1),

                    [

                        colors.whitesmoke,

                        colors.lightgrey

                    ]

                )

            ])

        )

        content.append(
            table
        )

        # Risk Assesment 

        content.append(
            Spacer(1,10)
        )

        content.append(

            Paragraph(

                "🚨 Risk Assessment",

                heading_style

            )

        )

        content.append(

            Paragraph(

                f"<b>Risk Score:</b> {risk_score}/100",

                body_style

            )

        )

        content.append(

            Paragraph(

                f"<b>Verdict:</b> {verdict}",

                body_style

            )

        )

        # footer 

        content.append(
            Spacer(1,20)
        )

        content.append(

            Paragraph(

                f"""

                Generated By:
                {session.get('user')}

                <br/>

                Platform:
                OSINT Dashboard

                <br/>

                Report Type:
                Shodan Intelligence

                <br/>

                Classification:
                Internal Use

                """,

                footer_style

            )

        )

        content.append(
            Paragraph(
                "🌐 SHODAN INTELLIGENCE REPORT",
                styles['Title']
            )
        )

        content.append(
            Spacer(1, 12)
        )

        # =====================
        # BASIC INFO
        # =====================

        content.append(
            Paragraph(
                "<b>Basic Information</b>",
                styles['Heading2']
            )
        )

        content.append(
            Paragraph(
                f"IP Address: {host.get('ip_str','N/A')}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"Organization: {host.get('org','N/A')}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"ISP: {host.get('isp','N/A')}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"ASN: {host.get('asn','N/A')}",
                styles['BodyText']
            )
        )

        # =====================
        # LOCATION
        # =====================

        content.append(
            Spacer(1,10)
        )

        content.append(
            Paragraph(
                "<b>Geolocation</b>",
                styles['Heading2']
            )
        )

        content.append(
            Paragraph(
                f"Country: {host.get('country_name','N/A')}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"City: {host.get('city','N/A')}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"Latitude: {host.get('latitude','N/A')}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"Longitude: {host.get('longitude','N/A')}",
                styles['BodyText']
            )
        )

        # =====================
        # DNS
        # =====================

        content.append(
            Spacer(1,10)
        )

        content.append(
            Paragraph(
                "<b>DNS Information</b>",
                styles['Heading2']
            )
        )

        content.append(
            Paragraph(
                f"Hostnames: {', '.join(host.get('hostnames', []))}",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"Domains: {', '.join(host.get('domains', []))}",
                styles['BodyText']
            )
        )

        # =====================
        # PORTS
        # =====================

        content.append(
            Spacer(1,10)
        )

        content.append(
            Paragraph(
                "<b>Open Ports</b>",
                styles['Heading2']
            )
        )

        for port in host.get(
            "ports",
            []
        ):

            content.append(
                Paragraph(
                    str(port),
                    styles['BodyText']
                )
            )

        # =====================
        # SERVICES
        # =====================

        content.append(
            Spacer(1,10)
        )

        content.append(
            Paragraph(
                "<b>Detected Services</b>",
                styles['Heading2']
            )
        )

        for item in host.get(
            "data",
            []
        ):

            content.append(
                Paragraph(
                    f"""
                    Port:
                    {item.get('port')}

                    |
                    Protocol:
                    {item.get('transport')}

                    |
                    Product:
                    {item.get('product','Unknown')}

                    |
                    Version:
                    {item.get('version','')}
                    """,
                    styles['BodyText']
                )
            )

        # =====================
        # SSL
        # =====================

        for item in host.get(
            "data",
            []
        ):

            if item.get("ssl"):

                cert = item["ssl"].get(
                    "cert",
                    {}
                )

                content.append(
                    Spacer(1,10)
                )

                content.append(
                    Paragraph(
                        "<b>SSL Certificate</b>",
                        styles['Heading2']
                    )
                )

                content.append(
                    Paragraph(
                        f"<b>Subject:</b> {cert.get('subject',{}).get('CN','N/A')}",
                        body_style
                    )
                )

                content.append(
                    Paragraph(
                        f"<b>Issuer:</b> {cert.get('issuer',{}).get('CN','N/A')}",
                        body_style
                    )
                )

                content.append(
                    Paragraph(
                        f"<b>Expires:</b> {cert.get('expires','N/A')}",
                        body_style
                    )
                )

                break

        # =====================
        # LAST SEEN
        # =====================

        content.append(
            Spacer(1,10)
        )

        content.append(
            Paragraph(
                "<b>Last Seen</b>",
                styles['Heading2']
            )
        )

        content.append(
            Paragraph(
                str(
                    host.get(
                        'last_update',
                        'N/A'
                    )
                ),
                styles['BodyText']
            )
        )

        # =====================
        # RISK
        # =====================

        ports = host.get(
            "ports",
            []
        )

        risk_score = 0

        if 23 in ports:
            risk_score += 25

        if 3389 in ports:
            risk_score += 25

        if 445 in ports:
            risk_score += 30

        if 21 in ports:
            risk_score += 10

        if risk_score <= 20:

            verdict = "Low Risk"

        elif risk_score <= 50:

            verdict = "Medium Risk"

        elif risk_score <= 80:

            verdict = "High Risk"

        else:

            verdict = "Critical Risk"

        content.append(
            Spacer(1,10)
        )

        content.append(
            Paragraph(
                "<b>Risk Assessment</b>",
                styles['Heading2']
            )
        )

        content.append(
            Paragraph(
                f"Risk Score: {risk_score}/100",
                styles['BodyText']
            )
        )

        content.append(
            Paragraph(
                f"Verdict: {verdict}",
                styles['BodyText']
            )
        )

        # =====================
        # RAW SHODAN DATA
        # =====================

        content.append(
            Spacer(1,10)
        )

        data = [
            ["Port", "Protocol", "Product"]
        ]

        for item in host.get("data", []):

            data.append([
                str(item.get("port","")),
                str(item.get("transport","")),
                str(item.get("product","Unknown"))
            ])

        table = Table(
            data,
            colWidths=[70,70,250]
        )

        content.append(table)

        # content.append(
        #     Paragraph(
        #         "<b>Raw Intelligence Data</b>",
        #         styles['Heading2']
        #     )
        # )

        raw_json = json.dumps(
            host,
            indent=2,
            default=str
        )

        # content.append(
        #     Preformatted(
        #         raw_json[:10000],
        #         styles['Code']
        #     )
        # )

        content.append(
            Spacer(1,20)
        )

        content.append(
            Paragraph(
                f"""
                Generated By:
                {session.get('user')}

                <br/>

                Generated From:
                OSINT Dashboard

                <br/>

                Report Type:
                SHODAN Intelligence Report
                """,
                styles['Italic']
            )
        )
        doc.build(content)

        return send_file(
            pdf_file,
            as_attachment=True
        )

    except Exception as e:

        return str(e)
    

# =========================
# fix cases table 
# =========================

@app.route('/fix_cases_table')
def fix_cases_table():

    conn = sqlite3.connect(
        'investigations.db'
    )

    cursor = conn.cursor()

    try:
        cursor.execute("""
        ALTER TABLE cases
        ADD COLUMN created_by TEXT
        """)
    except:
        pass

    try:
        cursor.execute("""
        ALTER TABLE cases
        ADD COLUMN created_at TEXT
        """)
    except:
        pass

    conn.commit()
    conn.close()

    return "Cases table fixed successfully"

# =========================
# OTX Route
# =========================

from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

# from config import OTX_API_KEY
# import ipaddress

# # =========================
# # OTX Route
# # =========================

@app.route(
    '/otx_lookup',
    methods=['GET', 'POST']
)
def otx_lookup():

    result = None

    indicator = ""

    pulse_count = 0

    reputation = "Unknown"

    country = "Unknown"

    tags = []

    summary = {

        "indicator": "",

        "pulse_count": 0,

        "country": "Unknown",

        "reputation": "Unknown",

        "tag_count": 0,

        "risk_level": "Low"

    }

    if request.method == 'POST':

        indicator = request.form.get(
            'indicator',
            ''
        ).strip()

        try:

            otx = OTXv2(
                OTX_API_KEY
            )

            # =====================
            # Detect Indicator Type
            # =====================

            try:

                ipaddress.ip_address(
                    indicator
                )

                indicator_type = (
                    IndicatorTypes.IPv4
                )

            except ValueError:

                if (
                    indicator.startswith(
                        "http://"
                    )
                    or
                    indicator.startswith(
                        "https://"
                    )
                ):

                    indicator_type = (
                        IndicatorTypes.URL
                    )

                elif len(indicator) == 64:

                    indicator_type = (
                        IndicatorTypes.FILE_HASH_SHA256
                    )

                elif len(indicator) == 40:

                    indicator_type = (
                        IndicatorTypes.FILE_HASH_SHA1
                    )

                elif len(indicator) == 32:

                    indicator_type = (
                        IndicatorTypes.FILE_HASH_MD5
                    )

                else:

                    indicator_type = (
                        IndicatorTypes.DOMAIN
                    )

            # =====================
            # OTX Lookup
            # =====================

            pulse_info = (
                otx.get_indicator_details_full(
                    indicator_type,
                    indicator
                )
            )

            if not pulse_info:

                pulse_info = {}

            result = pulse_info

            # =====================
            # Extract Data
            # =====================

            general = pulse_info.get(
                "general",
                {}
            )

            pulse_count = (
                general
                .get(
                    "pulse_info",
                    {}
                )
                .get(
                    "count",
                    0
                )
            )

            reputation = str(
                general.get(
                    "reputation",
                    "Unknown"
                )
            )

            country = (

                general.get(
                    "country_name"
                )

                or

                general.get(
                    "country"
                )

                or

                "Unknown"

            )

            pulse_data = (
                general
                .get(
                    "pulse_info",
                    {}
                )
                .get(
                    "pulses",
                    []
                )
            )

            tags = []

            for pulse in pulse_data:

                pulse_tags = pulse.get(
                    "tags",
                    []
                )

                if pulse_tags:

                    tags.extend(
                        pulse_tags
                    )

            tags = list(
                set(tags)
            )
            summary = {
                "indicator": indicator,
                "pulse_count": pulse_count,
                "country": country,
                "reputation": reputation,
                "tag_count": len(tags),
                "risk_level": (
                    "High" if pulse_count > 50
                    else "Medium" if pulse_count > 10
                    else "Low"
                )
            }
            # =====================
            # Save Investigation
            # =====================

            try:

                save_investigation(

                    "OTX",

                    indicator,

                    str(pulse_info)

                )

            except Exception:

                pass

        except Exception as e:

            result = {

                "error":
                str(e)

            }

    return render_template(

        'otx_lookup.html',

        result=result,

        indicator=indicator,

        pulse_count=pulse_count,

        reputation=reputation,

        country=country,

        tags=tags,

        summary=summary

    )
# =========================
# RUN APP
# =========================

if __name__ == '__main__':

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
