from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from functools import wraps
import sqlite3, os, json, hashlib, uuid
from datetime import datetime
from werkzeug.utils import secure_filename
import requests

app = Flask(__name__)
app.secret_key = 'nistcsf-audit-platform-2024'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

OLLAMA_URL = 'http://localhost:11434/api/generate'
MODEL_NAME = 'phi3:mini'

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt', 'docx', 'xlsx', 'json', 'conf'}

def get_db():
    db = sqlite3.connect('instance/audit.db')
    db.row_factory = sqlite3.Row
    return db

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get('role') not in roles:
                flash('Access denied.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS organization (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            industry TEXT,
            size TEXT,
            description TEXT,
            contact_email TEXT,
            exposure_level TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            asset_type TEXT,
            description TEXT,
            owner TEXT,
            location TEXT,
            confidentiality INTEGER DEFAULT 1,
            integrity INTEGER DEFAULT 1,
            availability INTEGER DEFAULT 1,
            criticality_score REAL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            vuln_code TEXT,
            vuln_name TEXT,
            category TEXT,
            likelihood INTEGER,
            impact INTEGER,
            risk_score REAL,
            risk_level TEXT,
            notes TEXT,
            FOREIGN KEY(asset_id) REFERENCES assets(id)
        );
        CREATE TABLE IF NOT EXISTS controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            function_name TEXT,
            category TEXT,
            subcategory TEXT,
            control_id TEXT,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control_id INTEGER,
            status TEXT DEFAULT 'Not Assessed',
            notes TEXT,
            auditor_id INTEGER,
            assessed_at TEXT,
            FOREIGN KEY(control_id) REFERENCES controls(id)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_result_id INTEGER,
            filename TEXT,
            original_name TEXT,
            file_type TEXT,
            uploaded_by INTEGER,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(audit_result_id) REFERENCES audit_results(id)
        );
        CREATE TABLE IF NOT EXISTS generated_checklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER,
            vuln_code TEXT,
            vuln_name TEXT,
            checklist_item TEXT,
            nist_ref TEXT,
            status TEXT DEFAULT 'Pending',
            notes TEXT,
            FOREIGN KEY(asset_id) REFERENCES assets(id)
        );
        CREATE TABLE IF NOT EXISTS vuln_explanations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_name TEXT UNIQUE NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            issue TEXT,
            risk_level TEXT,
            affected_asset TEXT,
            recommendation TEXT,
            control_ref TEXT,
            vuln_ref TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    
    admin_exists = db.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if not admin_exists:
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        db.execute('INSERT INTO users (username, password, role, full_name, email) VALUES (?,?,?,?,?)',
                   ('admin', pw, 'admin', 'System Administrator', 'admin@university.edu'))
        pw2 = hashlib.sha256('auditor123'.encode()).hexdigest()
        db.execute('INSERT INTO users (username, password, role, full_name, email) VALUES (?,?,?,?,?)',
                   ('auditor', pw2, 'auditor', 'Lead Auditor', 'auditor@university.edu'))
        pw3 = hashlib.sha256('auditee123'.encode()).hexdigest()
        db.execute('INSERT INTO users (username, password, role, full_name, email) VALUES (?,?,?,?,?)',
                   ('auditee', pw3, 'auditee', 'IT Department', 'it@university.edu'))

    controls_exist = db.execute('SELECT COUNT(*) FROM controls').fetchone()[0]
    if controls_exist == 0:
        nist_controls = [
            ('Identify','Asset Management','Asset Inventory','ID.AM-1','Physical devices and systems within the organization are inventoried'),
            ('Identify','Asset Management','Software Inventory','ID.AM-2','Software platforms and applications within the organization are inventoried'),
            ('Identify','Asset Management','Data Flows','ID.AM-3','Organizational communication and data flows are mapped'),
            ('Identify','Asset Management','External Systems','ID.AM-4','External information systems are catalogued'),
            ('Identify','Asset Management','Resource Priority','ID.AM-5','Resources are prioritized based on their classification, criticality, and business value'),
            ('Identify','Business Environment','Role Definition','ID.BE-1','Organization\'s role in the supply chain is identified and communicated'),
            ('Identify','Business Environment','Critical Services','ID.BE-3','Priorities for organizational mission, objectives, and activities are established'),
            ('Identify','Governance','Policy','ID.GV-1','Organizational cybersecurity policy is established and communicated'),
            ('Identify','Governance','Legal Requirements','ID.GV-3','Legal and regulatory requirements regarding cybersecurity are understood'),
            ('Identify','Risk Assessment','Risk Process','ID.RA-1','Asset vulnerabilities are identified and documented'),
            ('Identify','Risk Assessment','Threat Intelligence','ID.RA-2','Cyber threat intelligence is received from information sharing forums'),
            ('Identify','Risk Assessment','Risk Register','ID.RA-5','Threats, vulnerabilities, likelihoods, and impacts are used to determine risk'),
            ('Identify','Risk Management Strategy','Risk Tolerance','ID.RM-1','Risk management processes are established and agreed to by organizational stakeholders'),
            ('Protect','Access Control','Identity Management','PR.AC-1','Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices and users'),
            ('Protect','Access Control','Physical Access','PR.AC-2','Physical access to assets is managed and protected'),
            ('Protect','Access Control','Remote Access','PR.AC-3','Remote access is managed'),
            ('Protect','Access Control','Least Privilege','PR.AC-4','Access permissions and authorizations are managed, incorporating least privilege'),
            ('Protect','Access Control','Network Segmentation','PR.AC-5','Network integrity is protected, incorporating network segregation where appropriate'),
            ('Protect','Awareness Training','User Training','PR.AT-1','All users are informed and trained'),
            ('Protect','Awareness Training','Privileged Users','PR.AT-2','Privileged users understand their roles and responsibilities'),
            ('Protect','Data Security','Data at Rest','PR.DS-1','Data-at-rest is protected'),
            ('Protect','Data Security','Data in Transit','PR.DS-2','Data-in-transit is protected'),
            ('Protect','Data Security','Asset Management','PR.DS-3','Assets are formally managed throughout removal, transfers, and disposition'),
            ('Protect','Data Security','Data Integrity','PR.DS-6','Integrity checking mechanisms are used to verify software, firmware, and information integrity'),
            ('Protect','Information Protection','Baseline Configuration','PR.IP-1','A baseline configuration of information technology is created and maintained'),
            ('Protect','Information Protection','Change Management','PR.IP-3','Configuration change control processes are in place'),
            ('Protect','Information Protection','Backup','PR.IP-4','Backups of information are conducted, maintained, and tested'),
            ('Protect','Information Protection','Policy Update','PR.IP-7','Protection processes are improved'),
            ('Protect','Maintenance','Maintenance Policy','PR.MA-1','Maintenance and repair of organizational assets is performed and logged'),
            ('Protect','Protective Technology','Audit Logs','PR.PT-1','Audit/log records are determined, documented, implemented, and reviewed'),
            ('Protect','Protective Technology','Removable Media','PR.PT-2','Removable media is protected and its use restricted according to policy'),
            ('Protect','Protective Technology','Communications Protection','PR.PT-4','Communications and control networks are protected'),
            ('Detect','Anomalies and Events','Baseline','DE.AE-1','A baseline of network operations and expected data flows is established'),
            ('Detect','Anomalies and Events','Alert Thresholds','DE.AE-3','Event data are collected and correlated from multiple sources'),
            ('Detect','Security Continuous Monitoring','Network Monitoring','DE.CM-1','The network is monitored to detect potential cybersecurity events'),
            ('Detect','Security Continuous Monitoring','Physical Environment','DE.CM-2','The physical environment is monitored to detect potential cybersecurity events'),
            ('Detect','Security Continuous Monitoring','Personnel Activity','DE.CM-3','Personnel activity is monitored to detect potential cybersecurity events'),
            ('Detect','Security Continuous Monitoring','Malicious Code','DE.CM-4','Malicious code is detected'),
            ('Detect','Security Continuous Monitoring','Unauthorized Code','DE.CM-5','Unauthorized mobile code is detected'),
            ('Detect','Security Continuous Monitoring','External Providers','DE.CM-6','External service provider activity is monitored'),
            ('Detect','Detection Process','Detection Roles','DE.DP-1','Roles and responsibilities for detection are well defined'),
            ('Respond','Response Planning','Response Plan','RS.RP-1','Response plan is executed during or after an incident'),
            ('Respond','Communications','Information Sharing','RS.CO-2','Incidents are reported consistent with established criteria'),
            ('Respond','Analysis','Investigation','RS.AN-1','Notifications from detection systems are investigated'),
            ('Respond','Analysis','Impact Understanding','RS.AN-2','The impact of the incident is understood'),
            ('Respond','Mitigation','Incident Containment','RS.MI-1','Incidents are contained'),
            ('Respond','Mitigation','Incident Mitigation','RS.MI-2','Incidents are mitigated'),
            ('Respond','Improvements','Lessons Learned','RS.IM-1','Response plans incorporate lessons learned'),
            ('Recover','Recovery Planning','Recovery Plan','RC.RP-1','Recovery plan is executed during or after a cybersecurity incident'),
            ('Recover','Improvements','Recovery Improvement','RC.IM-1','Recovery plans incorporate lessons learned'),
            ('Recover','Communications','Recovery Communication','RC.CO-3','Recovery activities are communicated to internal and external stakeholders'),
        ]
        db.executemany('INSERT INTO controls (function_name, category, subcategory, control_id, description) VALUES (?,?,?,?,?)', nist_controls)
    
    db.commit()
    db.close()

OWASP_VULNS = [
    {
        'code': 'INJ-001', 'name': 'SQL Injection', 'category': 'Injection',
        'default_likelihood': 4, 'default_impact': 5,
        'impact_description': 'Database theft — attacker can read, modify, or delete all university data including student records and credentials.',
        'checklist_item': 'Verify input validation and parameterized queries are enforced on all database-facing fields.',
        'nist_control': 'PR.DS-2',
    },
    {
        'code': 'INJ-002', 'name': 'Command Injection', 'category': 'Injection',
        'default_likelihood': 3, 'default_impact': 5,
        'impact_description': 'Full server compromise — attacker executes arbitrary OS commands, potentially taking over the server.',
        'checklist_item': 'Verify system commands are never constructed from user-supplied input; use safe API alternatives.',
        'nist_control': 'PR.DS-2',
    },
    {
        'code': 'INJ-003', 'name': 'LDAP Injection', 'category': 'Injection',
        'default_likelihood': 2, 'default_impact': 4,
        'impact_description': 'Directory traversal — attacker manipulates LDAP queries to bypass authentication or expose directory data.',
        'checklist_item': 'Verify LDAP queries use proper escaping and input sanitization before directory lookups.',
        'nist_control': 'PR.AC-1',
    },
    {
        'code': 'AUTH-001', 'name': 'Weak Password Policy', 'category': 'Broken Authentication',
        'default_likelihood': 5, 'default_impact': 4,
        'impact_description': 'Account takeover — weak passwords allow brute-force or dictionary attacks against student and staff accounts.',
        'checklist_item': 'Verify password policy enforces minimum 8 characters, complexity rules, and history restrictions.',
        'nist_control': 'PR.AC-1',
    },
    {
        'code': 'AUTH-002', 'name': 'No Account Lockout', 'category': 'Broken Authentication',
        'default_likelihood': 4, 'default_impact': 4,
        'impact_description': 'Brute-force exposure — unlimited login attempts allow attackers to guess credentials without restriction.',
        'checklist_item': 'Verify account lockout is enforced after 5 consecutive failed login attempts with appropriate cooldown.',
        'nist_control': 'PR.AC-1',
    },
    {
        'code': 'AUTH-003', 'name': 'Session Hijacking', 'category': 'Broken Authentication',
        'default_likelihood': 3, 'default_impact': 4,
        'impact_description': 'Unauthorized access — attacker steals a valid session token to impersonate a legitimate user.',
        'checklist_item': 'Verify session tokens are regenerated on login, transmitted over HTTPS only, and expire after inactivity.',
        'nist_control': 'PR.PT-4',
    },
    {
        'code': 'DATA-001', 'name': 'No HTTPS / TLS', 'category': 'Sensitive Data Exposure',
        'default_likelihood': 4, 'default_impact': 4,
        'impact_description': 'Data interception — credentials and personal data transmitted in plaintext can be captured on the network.',
        'checklist_item': 'Verify TLS certificate is installed, HTTPS is enforced site-wide, and HTTP is redirected to HTTPS.',
        'nist_control': 'PR.DS-2',
    },
    {
        'code': 'DATA-002', 'name': 'Weak Encryption', 'category': 'Sensitive Data Exposure',
        'default_likelihood': 3, 'default_impact': 4,
        'impact_description': 'Data exposure — use of weak algorithms (MD5, DES) means encrypted data can be cracked to reveal passwords or PII.',
        'checklist_item': 'Verify data at rest uses AES-256 or equivalent; passwords hashed with bcrypt/Argon2; no MD5 or SHA-1 for sensitive data.',
        'nist_control': 'PR.DS-1',
    },
    {
        'code': 'DATA-003', 'name': 'Exposed Database Backup', 'category': 'Sensitive Data Exposure',
        'default_likelihood': 3, 'default_impact': 5,
        'impact_description': 'Full data breach — backup files accessible via web expose entire database contents including student records.',
        'checklist_item': 'Verify database backups are stored outside web root, access-controlled, and encrypted.',
        'nist_control': 'PR.IP-4',
    },
    {
        'code': 'ACC-001', 'name': 'IDOR (Insecure Direct Object Reference)', 'category': 'Access Control Failures',
        'default_likelihood': 4, 'default_impact': 4,
        'impact_description': 'Unauthorized data access — users manipulate IDs in URLs to access other students\' records or grades.',
        'checklist_item': 'Verify all object references are validated server-side against the authenticated user\'s authorization.',
        'nist_control': 'PR.AC-4',
    },
    {
        'code': 'ACC-002', 'name': 'Privilege Escalation', 'category': 'Access Control Failures',
        'default_likelihood': 3, 'default_impact': 5,
        'impact_description': 'Unauthorized admin access — attacker gains elevated permissions beyond their role, potentially controlling the system.',
        'checklist_item': 'Verify role-based access control is enforced server-side and privilege boundaries cannot be crossed by parameter manipulation.',
        'nist_control': 'PR.AC-4',
    },
    {
        'code': 'CONF-001', 'name': 'Default Credentials', 'category': 'Security Misconfiguration',
        'default_likelihood': 4, 'default_impact': 5,
        'impact_description': 'Immediate system compromise — unchanged default usernames/passwords allow trivial unauthorized access to admin panels.',
        'checklist_item': 'Verify all default vendor credentials have been changed on every system, service, and device.',
        'nist_control': 'PR.AC-1',
    },
    {
        'code': 'CONF-002', 'name': 'Directory Listing Enabled', 'category': 'Security Misconfiguration',
        'default_likelihood': 3, 'default_impact': 3,
        'impact_description': 'Information disclosure — web server reveals file and directory structure, aiding attacker reconnaissance.',
        'checklist_item': 'Verify directory browsing/listing is disabled on all web servers and no sensitive files are web-accessible.',
        'nist_control': 'PR.IP-1',
    },
    {
        'code': 'CONF-003', 'name': 'Exposed Admin Panel', 'category': 'Security Misconfiguration',
        'default_likelihood': 3, 'default_impact': 4,
        'impact_description': 'Targeted attack surface — publicly accessible admin interfaces allow brute-force and exploitation attempts.',
        'checklist_item': 'Verify admin interfaces are restricted by IP allowlist, require MFA, and are not accessible from the public internet.',
        'nist_control': 'PR.AC-3',
    },
    {
        'code': 'CONF-004', 'name': 'Open Unnecessary Ports', 'category': 'Security Misconfiguration',
        'default_likelihood': 3, 'default_impact': 3,
        'impact_description': 'Expanded attack surface — unnecessary open ports expose services that may be unpatched or misconfigured.',
        'checklist_item': 'Verify firewall rules follow least-privilege; only required ports are open and all others are blocked.',
        'nist_control': 'PR.PT-4',
    },
    {
        'code': 'XSS-001', 'name': 'Cross-Site Scripting (XSS)', 'category': 'Cross-Site Attacks',
        'default_likelihood': 4, 'default_impact': 3,
        'impact_description': 'Account hijacking — malicious scripts injected into web pages steal session cookies or redirect users to phishing sites.',
        'checklist_item': 'Verify all user-supplied output is HTML-encoded; Content Security Policy (CSP) headers are implemented.',
        'nist_control': 'PR.DS-2',
    },
    {
        'code': 'XSS-002', 'name': 'Cross-Site Request Forgery (CSRF)', 'category': 'Cross-Site Attacks',
        'default_likelihood': 3, 'default_impact': 3,
        'impact_description': 'Unauthorized transactions — victim\'s browser is tricked into submitting actions (e.g., changing email/password) without consent.',
        'checklist_item': 'Verify CSRF tokens are included and validated on all state-changing requests (POST/PUT/DELETE).',
        'nist_control': 'PR.DS-2',
    },
    {
        'code': 'LOG-001', 'name': 'No Audit Logs', 'category': 'Logging & Monitoring Failure',
        'default_likelihood': 4, 'default_impact': 3,
        'impact_description': 'Incident undetected — without logging, security breaches go unnoticed and forensic investigation is impossible.',
        'checklist_item': 'Verify audit logging is enabled for all authentication events, data access, and administrative actions.',
        'nist_control': 'PR.PT-1',
    },
    {
        'code': 'PATCH-001', 'name': 'Outdated Server Software', 'category': 'Dependency & Software Issues',
        'default_likelihood': 4, 'default_impact': 4,
        'impact_description': 'Remote exploit — unpatched servers contain known CVEs that can be exploited with publicly available tools.',
        'checklist_item': 'Verify a patch management process exists; OS and application software is updated within 30 days of critical patch release.',
        'nist_control': 'PR.IP-3',
    },
]

def get_risk_level(score):
    if score <= 4: return 'Low'
    if score <= 9: return 'Medium'
    if score <= 15: return 'High'
    return 'Critical'

def get_exposure_level(size, industry):
    high_risk_industries = ['finance', 'healthcare', 'government', 'education']
    score = 0
    if industry and industry.lower() in high_risk_industries: score += 2
    if size == 'large': score += 2
    elif size == 'medium': score += 1
    if score >= 3: return 'High'
    if score >= 1: return 'Medium'
    return 'Low'

def generate_explanation(vulnerability_name):
    db = get_db()
    cached = db.execute('SELECT explanation FROM vuln_explanations WHERE vulnerability_name=?', (vulnerability_name,)).fetchone()
    if cached:
        db.close()
        return cached['explanation'], True

    prompt = f"""You are a cybersecurity audit assistant.

Explain the vulnerability: {vulnerability_name}

Structure the answer like this:

1. What it is:
2. Business Impact:
3. Example in a university:
4. Recommended Control:

Keep it simple.
Limit to 200 words.
Avoid technical jargon.
"""
    try:
        response = requests.post(OLLAMA_URL, json={'model': MODEL_NAME, 'prompt': prompt, 'stream': False}, timeout=90)
        response.raise_for_status()
        explanation = response.json()['response']
        db.execute('INSERT OR REPLACE INTO vuln_explanations (vulnerability_name, explanation) VALUES (?,?)', (vulnerability_name, explanation))
        db.commit()
        db.close()
        return explanation, False
    except Exception as e:
        db.close()
        raise e

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password)).fetchone()
        db.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    assets_count = db.execute('SELECT COUNT(*) FROM assets').fetchone()[0]
    vulns_count = db.execute('SELECT COUNT(*) FROM vulnerabilities').fetchone()[0]
    controls_count = db.execute('SELECT COUNT(*) FROM controls').fetchone()[0]
    assessed = db.execute("SELECT COUNT(*) FROM audit_results WHERE status != 'Not Assessed'").fetchone()[0]
    compliant = db.execute("SELECT COUNT(*) FROM audit_results WHERE status = 'Compliant'").fetchone()[0]
    total_assessed = db.execute("SELECT COUNT(*) FROM audit_results WHERE status IN ('Compliant','Partially Compliant','Non Compliant')").fetchone()[0]
    compliance_pct = round((compliant / total_assessed * 100), 1) if total_assessed > 0 else 0
    findings_count = db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
    critical_vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE risk_level='Critical'").fetchone()[0]
    high_vulns = db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE risk_level='High'").fetchone()[0]
    org = db.execute('SELECT * FROM organization ORDER BY id DESC LIMIT 1').fetchone()
    recent_findings = db.execute('SELECT * FROM findings ORDER BY created_at DESC LIMIT 5').fetchall()
    risk_distribution = db.execute("SELECT risk_level, COUNT(*) as cnt FROM vulnerabilities GROUP BY risk_level").fetchall()
    function_compliance = db.execute("""
        SELECT c.function_name, 
               COUNT(ar.id) as assessed,
               SUM(CASE WHEN ar.status='Compliant' THEN 1 ELSE 0 END) as compliant_count
        FROM controls c
        LEFT JOIN audit_results ar ON c.id = ar.control_id
        WHERE ar.status IN ('Compliant','Partially Compliant','Non Compliant')
        GROUP BY c.function_name
    """).fetchall()
    db.close()
    return render_template('dashboard.html', 
        assets_count=assets_count, vulns_count=vulns_count,
        controls_count=controls_count, assessed=assessed,
        compliance_pct=compliance_pct, findings_count=findings_count,
        critical_vulns=critical_vulns, high_vulns=high_vulns,
        org=org, recent_findings=recent_findings,
        risk_distribution=risk_distribution, function_compliance=function_compliance)

@app.route('/users', methods=['GET','POST'])
@login_required
@role_required('admin')
def users():
    db = get_db()
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        role = request.form['role']
        full_name = request.form['full_name']
        email = request.form['email']
        try:
            db.execute('INSERT INTO users (username,password,role,full_name,email) VALUES (?,?,?,?,?)',
                       (username, password, role, full_name, email))
            db.commit()
            flash('User created successfully.', 'success')
        except:
            flash('Username already exists.', 'error')
        db.close()
        return redirect(url_for('users'))
    all_users = db.execute('SELECT id,username,role,full_name,email,created_at FROM users').fetchall()
    db.close()
    return render_template('users.html', users=all_users)

@app.route('/users/delete/<int:uid>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(uid):
    if uid == session['user_id']:
        flash('Cannot delete yourself.', 'error')
        return redirect(url_for('users'))
    db = get_db()
    db.execute('DELETE FROM users WHERE id=?', (uid,))
    db.commit()
    db.close()
    flash('User deleted.', 'success')
    return redirect(url_for('users'))

@app.route('/organization', methods=['GET','POST'])
@login_required
@role_required('admin','auditor')
def organization():
    db = get_db()
    if request.method == 'POST':
        name = request.form['name']
        industry = request.form['industry']
        size = request.form['size']
        description = request.form['description']
        contact_email = request.form['contact_email']
        exposure = get_exposure_level(size, industry)
        db.execute('DELETE FROM organization')
        db.execute('INSERT INTO organization (name,industry,size,description,contact_email,exposure_level) VALUES (?,?,?,?,?,?)',
                   (name, industry, size, description, contact_email, exposure))
        db.commit()
        flash(f'Organization profile saved. Exposure level determined: {exposure}', 'success')
        db.close()
        return redirect(url_for('organization'))
    org = db.execute('SELECT * FROM organization ORDER BY id DESC LIMIT 1').fetchone()
    db.close()
    return render_template('organization.html', org=org)

@app.route('/assets', methods=['GET','POST'])
@login_required
def assets():
    db = get_db()
    if request.method == 'POST' and session['role'] in ('admin','auditor'):
        name = request.form['name']
        asset_type = request.form['asset_type']
        description = request.form['description']
        owner = request.form['owner']
        location = request.form['location']
        c = int(request.form['confidentiality'])
        i = int(request.form['integrity'])
        a = int(request.form['availability'])
        criticality = round((c + i + a) / 3 * (max(c,i,a) / 5), 2)
        db.execute('INSERT INTO assets (name,asset_type,description,owner,location,confidentiality,integrity,availability,criticality_score) VALUES (?,?,?,?,?,?,?,?,?)',
                   (name, asset_type, description, owner, location, c, i, a, criticality))
        db.commit()
        flash('Asset registered successfully.', 'success')
        db.close()
        return redirect(url_for('assets'))
    all_assets = db.execute('SELECT * FROM assets ORDER BY criticality_score DESC').fetchall()
    db.close()
    return render_template('assets.html', assets=all_assets)

@app.route('/assets/delete/<int:aid>', methods=['POST'])
@login_required
@role_required('admin','auditor')
def delete_asset(aid):
    db = get_db()
    db.execute('DELETE FROM vulnerabilities WHERE asset_id=?', (aid,))
    db.execute('DELETE FROM assets WHERE id=?', (aid,))
    db.commit()
    db.close()
    flash('Asset deleted.', 'success')
    return redirect(url_for('assets'))

@app.route('/vulnerabilities', methods=['GET','POST'])
@login_required
@role_required('admin','auditor')
def vulnerabilities():
    db = get_db()
    if request.method == 'POST':
        asset_id = request.form.get('asset_id')
        selected_codes = request.form.getlist('vuln_codes')
        notes = request.form.get('notes', '')
        added = 0
        skipped = 0

        for vuln_code in selected_codes:
            vuln_data = next((v for v in OWASP_VULNS if v['code'] == vuln_code), None)
            if not vuln_data:
                continue
            already = db.execute(
                'SELECT id FROM vulnerabilities WHERE asset_id=? AND vuln_code=?',
                (asset_id, vuln_code)
            ).fetchone()
            if already:
                skipped += 1
                continue

            likelihood = vuln_data['default_likelihood']
            impact = vuln_data['default_impact']
            risk_score = likelihood * impact
            risk_level = get_risk_level(risk_score)
            db.execute(
                'INSERT INTO vulnerabilities (asset_id,vuln_code,vuln_name,category,likelihood,impact,risk_score,risk_level,notes) VALUES (?,?,?,?,?,?,?,?,?)',
                (asset_id, vuln_code, vuln_data['name'], vuln_data['category'], likelihood, impact, risk_score, risk_level, notes)
            )

            checklist_text = vuln_data.get('checklist_item', '')
            nist_ref = vuln_data.get('nist_control', '')
            if checklist_text:
                existing_checklist = db.execute(
                    'SELECT id FROM generated_checklist WHERE asset_id=? AND vuln_code=?',
                    (asset_id, vuln_code)
                ).fetchone()
                if not existing_checklist:
                    asset_name = db.execute('SELECT name FROM assets WHERE id=?', (asset_id,)).fetchone()
                    asset_label = asset_name['name'] if asset_name else f'Asset #{asset_id}'
                    db.execute(
                        'INSERT INTO generated_checklist (asset_id, vuln_code, vuln_name, checklist_item, nist_ref, status) VALUES (?,?,?,?,?,?)',
                        (asset_id, vuln_code, vuln_data['name'], checklist_text, nist_ref, 'Pending')
                    )
            added += 1

        db.commit()
        if added:
            flash(f'{added} vulnerability/vulnerabilities added. Audit checklist items auto-created.', 'success')
        if skipped:
            flash(f'{skipped} already mapped to this asset (skipped).', 'error')
        db.close()
        return redirect(url_for('vulnerabilities'))

    all_vulns = db.execute('''
        SELECT v.*, a.name as asset_name FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        ORDER BY v.risk_score DESC
    ''').fetchall()
    assets_list = db.execute('SELECT id, name FROM assets').fetchall()

    selected_asset_id = request.args.get('asset_id')
    already_mapped = set()
    if selected_asset_id:
        rows = db.execute('SELECT vuln_code FROM vulnerabilities WHERE asset_id=?', (selected_asset_id,)).fetchall()
        already_mapped = {r['vuln_code'] for r in rows}

    grouped_vulns = {}
    for v in OWASP_VULNS:
        cat = v['category']
        if cat not in grouped_vulns:
            grouped_vulns[cat] = []
        grouped_vulns[cat].append(v)

    db.close()
    return render_template('vulnerabilities.html',
        vulns=all_vulns, assets=assets_list,
        owasp_vulns=OWASP_VULNS, grouped_vulns=grouped_vulns,
        selected_asset_id=selected_asset_id, already_mapped=already_mapped)

@app.route('/vulnerabilities/delete/<int:vid>', methods=['POST'])
@login_required
@role_required('admin','auditor')
def delete_vuln(vid):
    db = get_db()
    vuln = db.execute('SELECT * FROM vulnerabilities WHERE id=?', (vid,)).fetchone()
    if vuln:
        db.execute('DELETE FROM generated_checklist WHERE asset_id=? AND vuln_code=?', (vuln['asset_id'], vuln['vuln_code']))
    db.execute('DELETE FROM vulnerabilities WHERE id=?', (vid,))
    db.commit()
    db.close()
    flash('Vulnerability removed and associated checklist item deleted.', 'success')
    return redirect(url_for('vulnerabilities'))

@app.route('/generated-checklist', methods=['GET','POST'])
@login_required
def generated_checklist():
    db = get_db()
    if request.method == 'POST' and session['role'] in ('admin','auditor'):
        item_id = request.form['item_id']
        status = request.form['status']
        notes = request.form.get('notes','')
        db.execute('UPDATE generated_checklist SET status=?, notes=? WHERE id=?', (status, notes, item_id))
        db.commit()
        flash('Checklist item updated.', 'success')
        db.close()
        return redirect(url_for('generated_checklist'))

    items = db.execute('''
        SELECT gc.*, a.name as asset_name
        FROM generated_checklist gc
        JOIN assets a ON gc.asset_id = a.id
        ORDER BY a.name, gc.vuln_name
    ''').fetchall()

    total = len(items)
    compliant = sum(1 for i in items if i['status'] == 'Compliant')
    partial = sum(1 for i in items if i['status'] == 'Partially Compliant')
    non_compliant = sum(1 for i in items if i['status'] == 'Non Compliant')
    assessed = compliant + partial + non_compliant
    pct = round(compliant / assessed * 100, 1) if assessed > 0 else 0

    grouped = {}
    for item in items:
        aname = item['asset_name']
        if aname not in grouped:
            grouped[aname] = []
        grouped[aname].append(item)

    db.close()
    return render_template('generated_checklist.html', grouped=grouped,
        total=total, compliant=compliant, partial=partial,
        non_compliant=non_compliant, assessed=assessed, pct=pct)

@app.route('/risk-assessment')
@login_required
def risk_assessment():
    db = get_db()
    vulns = db.execute('''
        SELECT v.*, a.name as asset_name, a.criticality_score
        FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id
        ORDER BY v.risk_score DESC
    ''').fetchall()
    risk_counts = {'Critical':0,'High':0,'Medium':0,'Low':0}
    for v in vulns:
        if v['risk_level'] in risk_counts:
            risk_counts[v['risk_level']] += 1
    db.close()
    return render_template('risk_assessment.html', vulns=vulns, risk_counts=risk_counts)

@app.route('/audit-checklist', methods=['GET','POST'])
@login_required
def audit_checklist():
    db = get_db()
    if request.method == 'POST' and session['role'] in ('admin','auditor'):
        control_id = request.form['control_id']
        status = request.form['status']
        notes = request.form.get('notes','')
        existing = db.execute('SELECT id FROM audit_results WHERE control_id=?', (control_id,)).fetchone()
        if existing:
            db.execute('UPDATE audit_results SET status=?, notes=?, auditor_id=?, assessed_at=? WHERE control_id=?',
                       (status, notes, session['user_id'], datetime.now().isoformat(), control_id))
        else:
            db.execute('INSERT INTO audit_results (control_id,status,notes,auditor_id,assessed_at) VALUES (?,?,?,?,?)',
                       (control_id, status, notes, session['user_id'], datetime.now().isoformat()))
        db.commit()
        flash('Control assessment saved.', 'success')
        db.close()
        return redirect(url_for('audit_checklist'))
    
    controls = db.execute('SELECT * FROM controls ORDER BY function_name, category').fetchall()
    results = db.execute('SELECT * FROM audit_results').fetchall()
    result_map = {r['control_id']: r for r in results}
    
    grouped = {}
    for c in controls:
        fn = c['function_name']
        if fn not in grouped:
            grouped[fn] = {}
        cat = c['category']
        if cat not in grouped[fn]:
            grouped[fn][cat] = []
        grouped[fn][cat].append((c, result_map.get(c['id'])))
    
    total = len(controls)
    compliant = sum(1 for r in results if r['status'] == 'Compliant')
    partial = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant = sum(1 for r in results if r['status'] == 'Non Compliant')
    na = sum(1 for r in results if r['status'] == 'Not Applicable')
    assessed_total = compliant + partial + non_compliant
    compliance_pct = round((compliant / assessed_total * 100), 1) if assessed_total > 0 else 0
    
    db.close()
    return render_template('audit_checklist.html', grouped=grouped, result_map=result_map,
                           total=total, compliant=compliant, partial=partial,
                           non_compliant=non_compliant, na=na, compliance_pct=compliance_pct)

@app.route('/evidence/<int:control_id>', methods=['GET','POST'])
@login_required
def evidence(control_id):
    db = get_db()
    if request.method == 'POST' and session['role'] in ('admin','auditor'):
        audit_result = db.execute('SELECT id FROM audit_results WHERE control_id=?', (control_id,)).fetchone()
        if not audit_result:
            flash('Please assess this control before uploading evidence.', 'error')
            db.close()
            return redirect(url_for('audit_checklist'))
        if 'file' not in request.files:
            flash('No file selected.', 'error')
        else:
            file = request.files['file']
            if file and allowed_file(file.filename):
                original_name = secure_filename(file.filename)
                ext = original_name.rsplit('.', 1)[1].lower()
                unique_name = f"{uuid.uuid4().hex}.{ext}"
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
                db.execute('INSERT INTO evidence (audit_result_id,filename,original_name,file_type,uploaded_by) VALUES (?,?,?,?,?)',
                           (audit_result['id'], unique_name, original_name, ext, session['user_id']))
                db.commit()
                flash('Evidence uploaded successfully.', 'success')
            else:
                flash('File type not allowed.', 'error')
    
    control = db.execute('SELECT * FROM controls WHERE id=?', (control_id,)).fetchone()
    audit_result = db.execute('SELECT * FROM audit_results WHERE control_id=?', (control_id,)).fetchone()
    evidence_files = []
    if audit_result:
        evidence_files = db.execute('SELECT e.*, u.full_name FROM evidence e LEFT JOIN users u ON e.uploaded_by=u.id WHERE e.audit_result_id=?', (audit_result['id'],)).fetchall()
    db.close()
    return render_template('evidence.html', control=control, audit_result=audit_result, evidence_files=evidence_files)

@app.route('/evidence/delete/<int:eid>', methods=['POST'])
@login_required
@role_required('admin','auditor')
def delete_evidence(eid):
    db = get_db()
    ev = db.execute('SELECT * FROM evidence WHERE id=?', (eid,)).fetchone()
    if ev:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], ev['filename']))
        except:
            pass
        audit_result = db.execute('SELECT control_id FROM audit_results WHERE id=?', (ev['audit_result_id'],)).fetchone()
        db.execute('DELETE FROM evidence WHERE id=?', (eid,))
        db.commit()
        db.close()
        flash('Evidence deleted.', 'success')
        if audit_result:
            return redirect(url_for('evidence', control_id=audit_result['control_id']))
    db.close()
    return redirect(url_for('audit_checklist'))

@app.route('/compliance')
@login_required
def compliance():
    db = get_db()
    results = db.execute('SELECT * FROM audit_results').fetchall()
    controls = db.execute('SELECT * FROM controls').fetchall()
    
    compliant = sum(1 for r in results if r['status'] == 'Compliant')
    partial = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant = sum(1 for r in results if r['status'] == 'Non Compliant')
    na = sum(1 for r in results if r['status'] == 'Not Applicable')
    assessed = compliant + partial + non_compliant
    compliance_pct = round((compliant / assessed * 100), 1) if assessed > 0 else 0
    
    function_stats = db.execute("""
        SELECT c.function_name,
               COUNT(DISTINCT c.id) as total_controls,
               SUM(CASE WHEN ar.status='Compliant' THEN 1 ELSE 0 END) as compliant_count,
               SUM(CASE WHEN ar.status='Partially Compliant' THEN 1 ELSE 0 END) as partial_count,
               SUM(CASE WHEN ar.status='Non Compliant' THEN 1 ELSE 0 END) as non_count,
               SUM(CASE WHEN ar.status='Not Applicable' THEN 1 ELSE 0 END) as na_count
        FROM controls c
        LEFT JOIN audit_results ar ON c.id = ar.control_id
        GROUP BY c.function_name
        ORDER BY c.function_name
    """).fetchall()
    
    db.close()
    return render_template('compliance.html', 
        compliant=compliant, partial=partial, non_compliant=non_compliant,
        na=na, assessed=assessed, compliance_pct=compliance_pct,
        total_controls=len(controls), function_stats=function_stats)

@app.route('/findings', methods=['GET','POST'])
@login_required
@role_required('admin','auditor')
def findings():
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'generate':
            non_compliant_controls = db.execute("""
                SELECT c.control_id, c.description, c.function_name, c.category, ar.notes
                FROM audit_results ar JOIN controls c ON ar.control_id = c.id
                WHERE ar.status IN ('Non Compliant', 'Partially Compliant')
            """).fetchall()
            high_vulns = db.execute("""
                SELECT v.*, a.name as asset_name FROM vulnerabilities v
                JOIN assets a ON v.asset_id = a.id
                WHERE v.risk_level IN ('Critical','High')
            """).fetchall()
            
            for ctrl in non_compliant_controls:
                existing = db.execute('SELECT id FROM findings WHERE control_ref=?', (ctrl['control_id'],)).fetchone()
                if not existing:
                    rec = f"Implement {ctrl['description']} as required by NIST CSF {ctrl['function_name']} function."
                    db.execute('INSERT INTO findings (title,issue,risk_level,affected_asset,recommendation,control_ref) VALUES (?,?,?,?,?,?)',
                               (f"Control Gap: {ctrl['control_id']}",
                                f"Control '{ctrl['description']}' is not fully compliant. Notes: {ctrl['notes'] or 'None'}",
                                'High', ctrl['category'], rec, ctrl['control_id']))
            
            for vuln in high_vulns:
                existing = db.execute('SELECT id FROM findings WHERE vuln_ref=?', (vuln['vuln_code'],)).fetchone()
                if not existing:
                    db.execute('INSERT INTO findings (title,issue,risk_level,affected_asset,recommendation,vuln_ref) VALUES (?,?,?,?,?,?)',
                               (f"Vulnerability: {vuln['vuln_name']}",
                                f"{vuln['vuln_name']} detected on asset '{vuln['asset_name']}' with risk score {vuln['risk_score']}.",
                                vuln['risk_level'], vuln['asset_name'],
                                f"Remediate {vuln['vuln_name']} ({vuln['vuln_code']}) by implementing appropriate security controls and patching.",
                                vuln['vuln_code']))
            
            db.commit()
            flash('Findings generated automatically.', 'success')
        elif action == 'add':
            db.execute('INSERT INTO findings (title,issue,risk_level,affected_asset,recommendation) VALUES (?,?,?,?,?)',
                       (request.form['title'], request.form['issue'], request.form['risk_level'],
                        request.form['affected_asset'], request.form['recommendation']))
            db.commit()
            flash('Finding added.', 'success')
        elif action == 'delete':
            db.execute('DELETE FROM findings WHERE id=?', (request.form['finding_id'],))
            db.commit()
            flash('Finding deleted.', 'success')
        db.close()
        return redirect(url_for('findings'))
    
    all_findings = db.execute('SELECT * FROM findings ORDER BY CASE risk_level WHEN "Critical" THEN 1 WHEN "High" THEN 2 WHEN "Medium" THEN 3 ELSE 4 END').fetchall()
    db.close()
    return render_template('findings.html', findings=all_findings)

@app.route('/ai-explainer', methods=['GET','POST'])
@login_required
def ai_explainer():
    db = get_db()
    assets_list = db.execute('SELECT id, name FROM assets').fetchall()
    vulns = db.execute('''SELECT v.*, a.name as asset_name FROM vulnerabilities v 
                          JOIN assets a ON v.asset_id=a.id ORDER BY v.risk_score DESC''').fetchall()
    explanation = None
    selected_vuln = None
    error = None
    from_cache = False

    if request.method == 'POST':
        vuln_id = request.form.get('vuln_id')
        vuln = db.execute('SELECT v.*, a.name as asset_name FROM vulnerabilities v JOIN assets a ON v.asset_id=a.id WHERE v.id=?', (vuln_id,)).fetchone()
        if vuln:
            selected_vuln = vuln
            vuln_label = f"{vuln['vuln_name']} ({vuln['vuln_code']}) on {vuln['asset_name']}"
            try:
                explanation, from_cache = generate_explanation(vuln_label)
            except requests.exceptions.ConnectionError:
                error = "Cannot connect to Ollama. Make sure Ollama is running (`ollama serve`) and phi3:mini is installed (`ollama list`)."
            except Exception as e:
                error = f"AI service error: {str(e)}"
    db.close()
    return render_template('ai_explainer.html', vulns=vulns, explanation=explanation,
                           selected_vuln=selected_vuln, error=error,
                           from_cache=from_cache, assets=assets_list)

@app.route('/report')
@login_required
def report():
    db = get_db()
    org = db.execute('SELECT * FROM organization ORDER BY id DESC LIMIT 1').fetchone()
    assets = db.execute('SELECT * FROM assets ORDER BY criticality_score DESC').fetchall()
    vulns = db.execute('''SELECT v.*, a.name as asset_name FROM vulnerabilities v 
                          JOIN assets a ON v.asset_id=a.id ORDER BY v.risk_score DESC''').fetchall()
    findings = db.execute('''SELECT * FROM findings ORDER BY 
                             CASE risk_level WHEN "Critical" THEN 1 WHEN "High" THEN 2 WHEN "Medium" THEN 3 ELSE 4 END''').fetchall()
    
    results = db.execute('SELECT * FROM audit_results').fetchall()
    compliant = sum(1 for r in results if r['status'] == 'Compliant')
    partial = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant = sum(1 for r in results if r['status'] == 'Non Compliant')
    assessed = compliant + partial + non_compliant
    compliance_pct = round((compliant / assessed * 100), 1) if assessed > 0 else 0
    
    function_stats = db.execute("""
        SELECT c.function_name,
               COUNT(DISTINCT c.id) as total,
               SUM(CASE WHEN ar.status='Compliant' THEN 1 ELSE 0 END) as compliant_c
        FROM controls c LEFT JOIN audit_results ar ON c.id=ar.control_id
        GROUP BY c.function_name ORDER BY c.function_name
    """).fetchall()
    
    critical_count = sum(1 for v in vulns if v['risk_level'] == 'Critical')
    high_count = sum(1 for v in vulns if v['risk_level'] == 'High')

    evidence_files = db.execute('''
        SELECT e.*, c.control_id as ctrl_ref, c.description as ctrl_desc,
               ar.status as ctrl_status, u.full_name
        FROM evidence e
        JOIN audit_results ar ON e.audit_result_id = ar.id
        JOIN controls c ON ar.control_id = c.id
        LEFT JOIN users u ON e.uploaded_by = u.id
        ORDER BY c.control_id, e.uploaded_at
    ''').fetchall()

    # Build AI recommendations
    ai_recs = []
    seen_vulns = set()
    for v in vulns:
        if v['risk_level'] in ('Critical', 'High') and v['vuln_name'] not in seen_vulns:
            seen_vulns.add(v['vuln_name'])
            ai_recs.append({
                'level': v['risk_level'],
                'title': f"Remediate {v['vuln_name']} on {v['asset_name']}",
                'body': (f"Vulnerability {v['vuln_name']} ({v['vuln_code']}) detected on {v['asset_name']}. "
                         f"Risk Score: {int(v['risk_score'])} (Likelihood {v['likelihood']} × Impact {v['impact']}). "
                         f"Recommended Action: Apply vendor patches, enforce input validation, and implement "
                         f"NIST CSF security controls to mitigate exposure."),
            })
    for f in findings:
        if f['control_ref'] and f['risk_level'] in ('Critical', 'High', 'Medium'):
            ai_recs.append({
                'level': f['risk_level'],
                'title': f['title'],
                'body': f"Issue: {f['issue']} | Affected Asset: {f['affected_asset'] or 'N/A'} | Recommendation: {f['recommendation']}",
            })
    if compliance_pct < 80:
        ai_recs.append({
            'level': 'High' if compliance_pct < 60 else 'Medium',
            'title': 'Improve Overall NIST CSF Compliance',
            'body': (f"Current compliance is {compliance_pct}%. Priority actions: (1) Address all Non-Compliant "
                     f"controls in the Protect and Detect functions first. (2) Assign control owners and set "
                     f"remediation deadlines. (3) Schedule a follow-up audit within 90 days."),
        })
    sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    ai_recs.sort(key=lambda x: sev_order.get(x['level'], 4))

    if compliance_pct >= 80 and critical_count == 0:
        final_opinion = 'Secure'
        opinion_class = 'success'
    elif compliance_pct >= 60 and critical_count <= 2:
        final_opinion = 'Acceptable Risk'
        opinion_class = 'warning'
    else:
        final_opinion = 'Needs Immediate Action'
        opinion_class = 'danger'
    
    db.close()
    return render_template('report.html', org=org, assets=assets, vulns=vulns,
                           findings=findings, compliance_pct=compliance_pct,
                           compliant=compliant, partial=partial, non_compliant=non_compliant,
                           assessed=assessed, function_stats=function_stats,
                           final_opinion=final_opinion, opinion_class=opinion_class,
                           report_date=datetime.now().strftime('%B %d, %Y'),
                           critical_count=critical_count, high_count=high_count,
                           evidence_files=evidence_files, ai_recs=ai_recs)

@app.route('/report/export-pdf')
@login_required
def export_report_pdf():
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, HRFlowable, PageBreak, KeepTogether)
    from reportlab.platypus.flowables import HRFlowable

    db = get_db()
    org = db.execute('SELECT * FROM organization ORDER BY id DESC LIMIT 1').fetchone()
    assets = db.execute('SELECT * FROM assets ORDER BY criticality_score DESC').fetchall()
    vulns = db.execute('''SELECT v.*, a.name as asset_name FROM vulnerabilities v
                          JOIN assets a ON v.asset_id=a.id ORDER BY v.risk_score DESC''').fetchall()
    findings = db.execute('''SELECT * FROM findings ORDER BY
                             CASE risk_level WHEN "Critical" THEN 1 WHEN "High" THEN 2 WHEN "Medium" THEN 3 ELSE 4 END''').fetchall()
    results = db.execute('SELECT * FROM audit_results').fetchall()
    compliant = sum(1 for r in results if r['status'] == 'Compliant')
    partial = sum(1 for r in results if r['status'] == 'Partially Compliant')
    non_compliant = sum(1 for r in results if r['status'] == 'Non Compliant')
    assessed = compliant + partial + non_compliant
    compliance_pct = round((compliant / assessed * 100), 1) if assessed > 0 else 0
    function_stats = db.execute("""
        SELECT c.function_name, COUNT(DISTINCT c.id) as total,
               SUM(CASE WHEN ar.status='Compliant' THEN 1 ELSE 0 END) as compliant_c,
               SUM(CASE WHEN ar.status='Partially Compliant' THEN 1 ELSE 0 END) as partial_c,
               SUM(CASE WHEN ar.status='Non Compliant' THEN 1 ELSE 0 END) as non_c
        FROM controls c LEFT JOIN audit_results ar ON c.id=ar.control_id
        GROUP BY c.function_name ORDER BY c.function_name
    """).fetchall()
    critical_count = sum(1 for v in vulns if v['risk_level'] == 'Critical')
    high_count = sum(1 for v in vulns if v['risk_level'] == 'High')
    # Fetch evidence grouped by control
    evidence_rows = db.execute('''
        SELECT e.*, c.control_id as ctrl_ref, c.description as ctrl_desc,
               ar.status as ctrl_status, u.full_name
        FROM evidence e
        JOIN audit_results ar ON e.audit_result_id = ar.id
        JOIN controls c ON ar.control_id = c.id
        LEFT JOIN users u ON e.uploaded_by = u.id
        ORDER BY c.control_id, e.uploaded_at
    ''').fetchall()
    db.close()

    if compliance_pct >= 80 and critical_count == 0:
        final_opinion = 'Secure'
    elif compliance_pct >= 60 and critical_count <= 2:
        final_opinion = 'Acceptable Risk'
    else:
        final_opinion = 'Needs Immediate Action'

    report_date = datetime.now().strftime('%B %d, %Y')
    org_name = org['name'] if org else 'University IT System'

    # ── Color palette ──────────────────────────────────────────────
    NAVY       = colors.HexColor('#0f1729')
    BLUE       = colors.HexColor('#2563eb')
    LIGHT_BLUE = colors.HexColor('#eff6ff')
    GRAY_BG    = colors.HexColor('#f6f7fb')
    GRAY_LINE  = colors.HexColor('#e4e7ef')
    GRAY_TEXT  = colors.HexColor('#4b5573')
    GRAY_MUTED = colors.HexColor('#8b92a8')
    RED        = colors.HexColor('#dc2626')
    ORANGE     = colors.HexColor('#ea580c')
    YELLOW     = colors.HexColor('#ca8a04')
    GREEN      = colors.HexColor('#16a34a')
    RED_BG     = colors.HexColor('#fee2e2')
    ORANGE_BG  = colors.HexColor('#ffedd5')
    YELLOW_BG  = colors.HexColor('#fef9c3')
    GREEN_BG   = colors.HexColor('#dcfce7')
    WHITE      = colors.white
    BLACK      = colors.HexColor('#0f1729')

    def risk_color(level):
        return {'Critical': RED, 'High': ORANGE, 'Medium': YELLOW, 'Low': GREEN}.get(level, GRAY_TEXT)

    def risk_bg(level):
        return {'Critical': RED_BG, 'High': ORANGE_BG, 'Medium': YELLOW_BG, 'Low': GREEN_BG}.get(level, GRAY_BG)

    # ── Styles ─────────────────────────────────────────────────────
    base = getSampleStyleSheet()

    def S(name, **kw):
        return ParagraphStyle(name, **kw)

    sTitle = S('sTitle', fontName='Helvetica-Bold', fontSize=26, textColor=WHITE,
               leading=32, alignment=TA_LEFT, spaceAfter=6)
    sSubtitle = S('sSubtitle', fontName='Helvetica', fontSize=12, textColor=colors.HexColor('#93c5fd'),
                  leading=16, alignment=TA_LEFT, spaceAfter=4)
    sMeta = S('sMeta', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#94a3b8'),
              leading=14, alignment=TA_LEFT)

    sH1 = S('sH1', fontName='Helvetica-Bold', fontSize=13, textColor=NAVY,
            leading=18, spaceBefore=18, spaceAfter=6, borderPadding=(0,0,4,0))
    sH2 = S('sH2', fontName='Helvetica-Bold', fontSize=10, textColor=BLUE,
            leading=14, spaceBefore=10, spaceAfter=4)
    sBody = S('sBody', fontName='Helvetica', fontSize=9, textColor=GRAY_TEXT,
              leading=14, spaceAfter=6, alignment=TA_JUSTIFY)
    sBold = S('sBold', fontName='Helvetica-Bold', fontSize=9, textColor=BLACK, leading=14)
    sSmall = S('sSmall', fontName='Helvetica', fontSize=8, textColor=GRAY_MUTED, leading=12)
    sTableH = S('sTableH', fontName='Helvetica-Bold', fontSize=8, textColor=WHITE, leading=11)
    sTableB = S('sTableB', fontName='Helvetica', fontSize=8, textColor=GRAY_TEXT, leading=11)
    sTableBold = S('sTableBold', fontName='Helvetica-Bold', fontSize=8, textColor=BLACK, leading=11)
    sOpinion = S('sOpinion', fontName='Helvetica-Bold', fontSize=18, textColor=WHITE,
                 leading=24, alignment=TA_CENTER)
    sOpinionSub = S('sOpinionSub', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#cbd5e1'),
                    leading=14, alignment=TA_CENTER)
    sCenter = S('sCenter', fontName='Helvetica', fontSize=9, textColor=GRAY_TEXT,
                leading=12, alignment=TA_CENTER)
    sCenterBold = S('sCenterBold', fontName='Helvetica-Bold', fontSize=9, textColor=BLACK,
                    leading=12, alignment=TA_CENTER)
    sFindingTitle = S('sFindingTitle', fontName='Helvetica-Bold', fontSize=9, textColor=BLACK, leading=13)
    sFindingBody = S('sFindingBody', fontName='Helvetica', fontSize=8.5, textColor=GRAY_TEXT,
                     leading=13, spaceAfter=3)

    W, H = A4
    MARGIN = 2.2 * cm
    CONTENT_W = W - 2 * MARGIN

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=MARGIN, rightMargin=MARGIN,
                            topMargin=MARGIN, bottomMargin=MARGIN,
                            title=f'Cybersecurity Audit Report — {org_name}')

    # ── Page template with header/footer ──────────────────────────
    def on_page(canvas, doc):
        canvas.saveState()
        page_num = doc.page
        if page_num == 1:
            canvas.restoreState()
            return
        # Header bar
        canvas.setFillColor(NAVY)
        canvas.rect(MARGIN, H - 1.4*cm, CONTENT_W, 0.55*cm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 7)
        canvas.drawString(MARGIN + 4, H - 1.08*cm, 'CYBERSECURITY AUDIT REPORT')
        canvas.setFont('Helvetica', 7)
        canvas.drawRightString(W - MARGIN - 4, H - 1.08*cm, org_name.upper())
        # Footer
        canvas.setFillColor(GRAY_LINE)
        canvas.rect(MARGIN, 1.1*cm, CONTENT_W, 0.03*cm, fill=1, stroke=0)
        canvas.setFillColor(GRAY_MUTED)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(MARGIN, 0.75*cm, f'NIST Cybersecurity Framework 2.0  |  {report_date}  |  CONFIDENTIAL')
        canvas.drawRightString(W - MARGIN, 0.75*cm, f'Page {page_num}')
        canvas.restoreState()

    story = []

    # ══════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════
    def cover_page(canvas, doc):
        on_page(canvas, doc)
        if doc.page != 1:
            return
        canvas.saveState()
        # Full navy background
        canvas.setFillColor(NAVY)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        # Blue accent bar top
        canvas.setFillColor(BLUE)
        canvas.rect(0, H - 0.6*cm, W, 0.6*cm, fill=1, stroke=0)
        # Decorative rectangle
        canvas.setFillColor(colors.HexColor('#1e3a5f'))
        canvas.rect(0, H * 0.38, W, H * 0.52, fill=1, stroke=0)
        # Side accent line
        canvas.setFillColor(BLUE)
        canvas.rect(MARGIN, H * 0.20, 0.18*cm, H * 0.68, fill=1, stroke=0)
        # Organization label
        canvas.setFillColor(colors.HexColor('#1e3a5f'))
        canvas.rect(MARGIN + 0.5*cm, H * 0.82, CONTENT_W * 0.7, 0.7*cm, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor('#93c5fd'))
        canvas.setFont('Helvetica', 8)
        canvas.drawString(MARGIN + 0.9*cm, H * 0.845, 'PREPARED FOR')
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 11)
        canvas.drawString(MARGIN + 0.9*cm, H * 0.835 - 8, org_name)
        # Main title
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 30)
        canvas.drawString(MARGIN + 0.5*cm, H * 0.66, 'Cybersecurity')
        canvas.setFont('Helvetica', 28)
        canvas.drawString(MARGIN + 0.5*cm, H * 0.60, 'Audit Report')
        # Framework badge
        canvas.setFillColor(BLUE)
        canvas.roundRect(MARGIN + 0.5*cm, H * 0.535, 5.5*cm, 0.55*cm, 4, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica-Bold', 8)
        canvas.drawString(MARGIN + 0.9*cm, H * 0.555, 'NIST Cybersecurity Framework 2.0')
        # Date & classification row
        canvas.setFillColor(GRAY_MUTED)  # use HexColor
        canvas.setFillColor(colors.HexColor('#94a3b8'))
        canvas.setFont('Helvetica', 8)
        canvas.drawString(MARGIN + 0.5*cm, H * 0.49, f'Report Date: {report_date}')
        canvas.drawString(MARGIN + 0.5*cm, H * 0.465, 'Classification: Confidential')
        # Opinion box
        op_colors = {'Secure': (GREEN, GREEN_BG), 'Acceptable Risk': (YELLOW, YELLOW_BG), 'Needs Immediate Action': (RED, RED_BG)}
        op_col, op_bg = op_colors.get(final_opinion, (BLUE, LIGHT_BLUE))
        canvas.setFillColor(op_col)
        canvas.roundRect(MARGIN + 0.5*cm, H * 0.25, CONTENT_W * 0.55, 1.6*cm, 6, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont('Helvetica', 7)
        canvas.drawString(MARGIN + 1.0*cm, H * 0.25 + 1.15*cm, 'FINAL AUDIT OPINION')
        canvas.setFont('Helvetica-Bold', 16)
        canvas.drawString(MARGIN + 1.0*cm, H * 0.25 + 0.45*cm, final_opinion)
        # KPI boxes bottom
        kpis = [
            (str(len(assets)), 'Assets'),
            (str(len(vulns)), 'Vulnerabilities'),
            (f'{compliance_pct}%', 'Compliance'),
            (str(len(findings)), 'Findings'),
        ]
        box_w = CONTENT_W / 4 - 0.2*cm
        for i, (val, lbl) in enumerate(kpis):
            x = MARGIN + i * (box_w + 0.27*cm)
            canvas.setFillColor(colors.HexColor('#1e2a42'))
            canvas.roundRect(x, 1.8*cm, box_w, 1.6*cm, 5, fill=1, stroke=0)
            canvas.setFillColor(BLUE)
            canvas.setFont('Helvetica-Bold', 18)
            canvas.drawCentredString(x + box_w/2, 2.75*cm, val)
            canvas.setFillColor(colors.HexColor('#94a3b8'))
            canvas.setFont('Helvetica', 7.5)
            canvas.drawCentredString(x + box_w/2, 2.25*cm, lbl.upper())
        canvas.restoreState()

    story.append(Spacer(1, H - 4*MARGIN))  # fill cover page
    story.append(PageBreak())

    # ══════════════════════════════════════════════════
    # SECTION HELPER
    # ══════════════════════════════════════════════════
    def section_title(num, title):
        elems = []
        elems.append(Spacer(1, 0.3*cm))
        elems.append(HRFlowable(width=CONTENT_W, thickness=0.5, color=GRAY_LINE, spaceAfter=6))
        elems.append(Paragraph(f'<font color="#2563eb">{num}.</font>  {title}', sH1))
        elems.append(HRFlowable(width=CONTENT_W, thickness=2, color=BLUE, spaceBefore=2, spaceAfter=10))
        return elems

    def kpi_table(data):
        col_w = CONTENT_W / len(data)
        header_row = [Paragraph(str(v), ParagraphStyle('kpiv', fontName='Helvetica-Bold',
                        fontSize=20, textColor=BLUE, leading=24, alignment=TA_CENTER)) for v, _ in data]
        label_row = [Paragraph(l, ParagraphStyle('kpil', fontName='Helvetica', fontSize=7.5,
                        textColor=GRAY_MUTED, leading=11, alignment=TA_CENTER)) for _, l in data]
        t = Table([header_row, label_row], colWidths=[col_w]*len(data), rowHeights=[1.0*cm, 0.45*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), GRAY_BG),
            ('ROWBACKGROUND', (0,0), (-1,0), LIGHT_BLUE),
            ('INNERGRID', (0,0), (-1,-1), 0.5, GRAY_LINE),
            ('BOX', (0,0), (-1,-1), 0.5, GRAY_LINE),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('ROUNDEDCORNERS', [4]),
        ]))
        return t

    def table_style(has_header=True):
        style = [
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('LEADING', (0,0), (-1,-1), 11),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 7),
            ('RIGHTPADDING', (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, GRAY_BG]),
            ('LINEBELOW', (0,0), (-1,-1), 0.3, GRAY_LINE),
            ('BOX', (0,0), (-1,-1), 0.5, GRAY_LINE),
        ]
        if has_header:
            style += [
                ('BACKGROUND', (0,0), (-1,0), NAVY),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('TEXTCOLOR', (0,0), (-1,0), WHITE),
                ('FONTSIZE', (0,0), (-1,0), 8),
            ]
        return TableStyle(style)

    # ══════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════
    story += section_title('1', 'Executive Summary')
    story.append(Paragraph(
        f'This report presents the findings of a cybersecurity audit conducted on <b>{org_name}</b> '
        f'using the <b>NIST Cybersecurity Framework (CSF) 2.0</b>. The audit assessed the '
        f'organization\'s information security posture across the five core functions: '
        f'Identify, Protect, Detect, Respond, and Recover.',
        sBody))
    story.append(Paragraph(
        f'The assessment evaluated <b>{len(assets)} information assets</b>, identified '
        f'<b>{len(vulns)} vulnerabilities</b>, and assessed <b>{assessed} security controls</b>. '
        f'The overall compliance score is <b>{compliance_pct}%</b>, with <b>{len(findings)} audit findings</b> '
        f'identified including {critical_count} critical and {high_count} high severity items.',
        sBody))
    story.append(Spacer(1, 0.3*cm))
    story.append(kpi_table([
        (str(len(assets)), 'Total Assets'),
        (str(len(vulns)), 'Vulnerabilities'),
        (f'{compliance_pct}%', 'Compliance Score'),
        (str(len(findings)), 'Audit Findings'),
        (str(critical_count), 'Critical Risks'),
    ]))
    story.append(Spacer(1, 0.4*cm))

    # Opinion box
    op_col = {'Secure': GREEN, 'Acceptable Risk': YELLOW, 'Needs Immediate Action': RED}.get(final_opinion, BLUE)
    op_desc = {
        'Secure': f'The organization demonstrates strong security posture with {compliance_pct}% NIST CSF compliance and no critical vulnerabilities.',
        'Acceptable Risk': f'The organization shows acceptable security posture. Identified risks should be addressed in a structured remediation plan within 90 days.',
        'Needs Immediate Action': f'The organization requires immediate improvements. {compliance_pct}% compliance and {critical_count} critical risks demand prompt remediation.',
    }.get(final_opinion, '')

    op_data = [[
        Paragraph('FINAL AUDIT OPINION', ParagraphStyle('ol', fontName='Helvetica-Bold', fontSize=7,
                  textColor=WHITE, leading=10, alignment=TA_CENTER)),
        Paragraph(final_opinion, ParagraphStyle('ov', fontName='Helvetica-Bold', fontSize=14,
                  textColor=WHITE, leading=18, alignment=TA_CENTER)),
        Paragraph(op_desc, ParagraphStyle('od', fontName='Helvetica', fontSize=8,
                  textColor=WHITE, leading=12, alignment=TA_LEFT)),
    ]]
    op_t = Table(op_data, colWidths=[3.5*cm, 4.5*cm, CONTENT_W - 8*cm])
    op_t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), op_col),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('LINEAFTER', (0,0), (1,-1), 0.5, colors.HexColor('#ffffff44')),
    ]))
    story.append(op_t)

    # ══════════════════════════════════════════════════
    # 2. SCOPE
    # ══════════════════════════════════════════════════
    story += section_title('2', 'Scope of Audit')
    scope_rows = [
        [Paragraph('Organization', sBold), Paragraph(org_name, sBody)],
        [Paragraph('Industry Sector', sBold), Paragraph((org['industry'] or 'N/A').title() if org else 'N/A', sBody)],
        [Paragraph('Organization Size', sBold), Paragraph((org['size'] or 'N/A').title() if org else 'N/A', sBody)],
        [Paragraph('Exposure Level', sBold), Paragraph((org['exposure_level'] or 'N/A') if org else 'N/A', sBody)],
        [Paragraph('Audit Date', sBold), Paragraph(report_date, sBody)],
        [Paragraph('Framework', sBold), Paragraph('NIST Cybersecurity Framework (CSF) 2.0', sBody)],
        [Paragraph('Audit Scope', sBold), Paragraph('University IT infrastructure, systems, applications, and associated security controls', sBody)],
        [Paragraph('Classification', sBold), Paragraph('Confidential — For Authorized Personnel Only', sBody)],
    ]
    scope_t = Table(scope_rows, colWidths=[4*cm, CONTENT_W - 4*cm])
    scope_t.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [GRAY_BG, WHITE]),
        ('LINEBELOW', (0,0), (-1,-1), 0.3, GRAY_LINE),
        ('BOX', (0,0), (-1,-1), 0.5, GRAY_LINE),
    ]))
    story.append(scope_t)

    # ══════════════════════════════════════════════════
    # 3. METHODOLOGY
    # ══════════════════════════════════════════════════
    story += section_title('3', 'Audit Methodology')
    story.append(Paragraph(
        'This audit follows the structured workflow of the NIST Cybersecurity Framework (CSF) 2.0, '
        'assessing security posture across five core functions. The methodology comprises the following phases:',
        sBody))
    story.append(Spacer(1, 0.2*cm))

    method_steps = [
        ('1', 'Asset Inventory', 'All information assets registered with CIA (Confidentiality, Integrity, Availability) ratings. Criticality score calculated as: avg(C,I,A) × max(C,I,A) / 5.'),
        ('2', 'Vulnerability Identification', 'OWASP-based vulnerabilities mapped to each asset. System automatically assigned likelihood and impact values from a pre-defined rule library.'),
        ('3', 'Risk Assessment', 'Risk Score = Likelihood × Impact. Classified as: Low (1–4), Medium (5–9), High (10–15), Critical (16–25).'),
        ('4', 'Security Control Audit', 'Controls assessed against NIST CSF core functions using four-point scale: Compliant, Partially Compliant, Non Compliant, Not Applicable.'),
        ('5', 'Compliance Scoring', 'Compliance % = (Number of Compliant Controls ÷ Total Assessed Controls) × 100.'),
        ('6', 'Findings Generation', 'Audit findings automatically generated from non-compliant controls and high-risk vulnerabilities.'),
    ]
    for num, title, desc in method_steps:
        row_data = [[
            Paragraph(num, ParagraphStyle('mn', fontName='Helvetica-Bold', fontSize=10,
                      textColor=WHITE, leading=13, alignment=TA_CENTER)),
            Paragraph(f'<b>{title}</b><br/><font color="#4b5573">{desc}</font>',
                      ParagraphStyle('md', fontName='Helvetica', fontSize=8.5, leading=13)),
        ]]
        mt = Table(row_data, colWidths=[0.7*cm, CONTENT_W - 0.7*cm])
        mt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), BLUE),
            ('BACKGROUND', (1,0), (1,-1), WHITE),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (0,-1), 4),
            ('LEFTPADDING', (1,0), (1,-1), 10),
            ('LINEBELOW', (0,0), (-1,-1), 0.3, GRAY_LINE),
            ('BOX', (0,0), (-1,-1), 0.5, GRAY_LINE),
        ]))
        story.append(mt)

    # ══════════════════════════════════════════════════
    # 4. ASSET INVENTORY
    # ══════════════════════════════════════════════════
    story.append(PageBreak())
    story += section_title('4', 'Asset Inventory')
    story.append(Paragraph(
        f'A total of {len(assets)} information assets were registered and assessed. '
        'Each asset was assigned a CIA triad rating (1–5 scale) from which the criticality score was derived.',
        sBody))
    story.append(Spacer(1, 0.2*cm))

    if assets:
        asset_headers = [
            Paragraph('Asset Name', sTableH),
            Paragraph('Type', sTableH),
            Paragraph('Owner', sTableH),
            Paragraph('C', sTableH),
            Paragraph('I', sTableH),
            Paragraph('A', sTableH),
            Paragraph('Criticality', sTableH),
        ]
        asset_rows = [asset_headers]
        for a in assets:
            score = a['criticality_score'] or 0
            asset_rows.append([
                Paragraph(a['name'], sTableB),
                Paragraph(a['asset_type'] or '—', sTableB),
                Paragraph(a['owner'] or '—', sTableB),
                Paragraph(str(a['confidentiality']), sCenter),
                Paragraph(str(a['integrity']), sCenter),
                Paragraph(str(a['availability']), sCenter),
                Paragraph(f'{score:.2f}', sCenterBold),
            ])
        at = Table(asset_rows, colWidths=[4.5*cm, 2.5*cm, 3*cm, 0.8*cm, 0.8*cm, 0.8*cm, 1.5*cm],
                   repeatRows=1)
        at.setStyle(table_style())
        story.append(at)
    else:
        story.append(Paragraph('No assets have been registered.', sSmall))

    # ══════════════════════════════════════════════════
    # 5. RISK ASSESSMENT RESULTS
    # ══════════════════════════════════════════════════
    story.append(PageBreak())
    story += section_title('5', 'Risk Assessment Results')

    risk_counts = {'Critical': critical_count, 'High': high_count,
                   'Medium': sum(1 for v in vulns if v['risk_level']=='Medium'),
                   'Low': sum(1 for v in vulns if v['risk_level']=='Low')}

    story.append(Paragraph(
        f'Risk assessment was performed using the formula <b>Risk Score = Likelihood × Impact</b>. '
        f'A total of {len(vulns)} vulnerabilities were identified across {len(assets)} assets.',
        sBody))
    story.append(Spacer(1, 0.2*cm))

    risk_summary_data = [[
        Paragraph(str(risk_counts['Critical']), ParagraphStyle('rv', fontName='Helvetica-Bold',
                  fontSize=18, textColor=RED, alignment=TA_CENTER, leading=22)),
        Paragraph(str(risk_counts['High']), ParagraphStyle('rv', fontName='Helvetica-Bold',
                  fontSize=18, textColor=ORANGE, alignment=TA_CENTER, leading=22)),
        Paragraph(str(risk_counts['Medium']), ParagraphStyle('rv', fontName='Helvetica-Bold',
                  fontSize=18, textColor=YELLOW, alignment=TA_CENTER, leading=22)),
        Paragraph(str(risk_counts['Low']), ParagraphStyle('rv', fontName='Helvetica-Bold',
                  fontSize=18, textColor=GREEN, alignment=TA_CENTER, leading=22)),
    ],[
        Paragraph('Critical', ParagraphStyle('rl', fontName='Helvetica', fontSize=7.5,
                  textColor=RED, alignment=TA_CENTER, leading=10)),
        Paragraph('High', ParagraphStyle('rl', fontName='Helvetica', fontSize=7.5,
                  textColor=ORANGE, alignment=TA_CENTER, leading=10)),
        Paragraph('Medium', ParagraphStyle('rl', fontName='Helvetica', fontSize=7.5,
                  textColor=YELLOW, alignment=TA_CENTER, leading=10)),
        Paragraph('Low', ParagraphStyle('rl', fontName='Helvetica', fontSize=7.5,
                  textColor=GREEN, alignment=TA_CENTER, leading=10)),
    ]]
    rst = Table(risk_summary_data, colWidths=[CONTENT_W/4]*4, rowHeights=[1.0*cm, 0.4*cm])
    rst.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), GRAY_BG),
        ('INNERGRID', (0,0), (-1,-1), 0.5, GRAY_LINE),
        ('BOX', (0,0), (-1,-1), 0.5, GRAY_LINE),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,0), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('BACKGROUND', (0,0), (0,-1), RED_BG),
        ('BACKGROUND', (1,0), (1,-1), ORANGE_BG),
        ('BACKGROUND', (2,0), (2,-1), YELLOW_BG),
        ('BACKGROUND', (3,0), (3,-1), GREEN_BG),
    ]))
    story.append(rst)
    story.append(Spacer(1, 0.4*cm))

    if vulns:
        vuln_headers = [
            Paragraph('Vulnerability', sTableH),
            Paragraph('Code', sTableH),
            Paragraph('Asset', sTableH),
            Paragraph('Likelihood', sTableH),
            Paragraph('Impact', sTableH),
            Paragraph('Score', sTableH),
            Paragraph('Level', sTableH),
        ]
        vuln_rows = [vuln_headers]
        for v in vulns:
            level = v['risk_level']
            level_p = Paragraph(level, ParagraphStyle('rl2', fontName='Helvetica-Bold', fontSize=7.5,
                                textColor=risk_color(level), alignment=TA_CENTER, leading=11))
            vuln_rows.append([
                Paragraph(v['vuln_name'], sTableB),
                Paragraph(v['vuln_code'], sSmall),
                Paragraph(v['asset_name'], sTableB),
                Paragraph(str(v['likelihood']), sCenter),
                Paragraph(str(v['impact']), sCenter),
                Paragraph(str(int(v['risk_score'])), sCenterBold),
                level_p,
            ])
        vt = Table(vuln_rows, colWidths=[4*cm, 2*cm, 3.2*cm, 1.3*cm, 1.1*cm, 1.1*cm, 1.5*cm],
                   repeatRows=1)
        vt.setStyle(table_style())
        # Color level column rows
        for i, v in enumerate(vulns, start=1):
            vt.setStyle(TableStyle([('BACKGROUND', (6,i), (6,i), risk_bg(v['risk_level']))]))
        story.append(vt)
    else:
        story.append(Paragraph('No vulnerabilities have been recorded.', sSmall))

    # ══════════════════════════════════════════════════
    # 6. COMPLIANCE RESULTS
    # ══════════════════════════════════════════════════
    story.append(PageBreak())
    story += section_title('6', 'Compliance Assessment Results')
    story.append(Paragraph(
        f'<b>Overall Compliance Score: {compliance_pct}%</b>  '
        f'({compliant} compliant / {assessed} assessed controls)',
        sBody))
    story.append(Spacer(1, 0.2*cm))

    comp_summary = [[
        Paragraph(str(compliant), ParagraphStyle('cv', fontName='Helvetica-Bold', fontSize=16,
                  textColor=GREEN, alignment=TA_CENTER, leading=20)),
        Paragraph(str(partial), ParagraphStyle('cv', fontName='Helvetica-Bold', fontSize=16,
                  textColor=YELLOW, alignment=TA_CENTER, leading=20)),
        Paragraph(str(non_compliant), ParagraphStyle('cv', fontName='Helvetica-Bold', fontSize=16,
                  textColor=RED, alignment=TA_CENTER, leading=20)),
        Paragraph(str(len(results) - assessed), ParagraphStyle('cv', fontName='Helvetica-Bold', fontSize=16,
                  textColor=GRAY_MUTED, alignment=TA_CENTER, leading=20)),
    ],[
        Paragraph('Compliant', ParagraphStyle('cl', fontName='Helvetica', fontSize=7.5,
                  textColor=GREEN, alignment=TA_CENTER, leading=10)),
        Paragraph('Partially Compliant', ParagraphStyle('cl', fontName='Helvetica', fontSize=7.5,
                  textColor=YELLOW, alignment=TA_CENTER, leading=10)),
        Paragraph('Non Compliant', ParagraphStyle('cl', fontName='Helvetica', fontSize=7.5,
                  textColor=RED, alignment=TA_CENTER, leading=10)),
        Paragraph('Not Assessed', ParagraphStyle('cl', fontName='Helvetica', fontSize=7.5,
                  textColor=GRAY_MUTED, alignment=TA_CENTER, leading=10)),
    ]]
    cst = Table(comp_summary, colWidths=[CONTENT_W/4]*4, rowHeights=[0.9*cm, 0.4*cm])
    cst.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), GREEN_BG),
        ('BACKGROUND', (1,0), (1,-1), YELLOW_BG),
        ('BACKGROUND', (2,0), (2,-1), RED_BG),
        ('BACKGROUND', (3,0), (3,-1), GRAY_BG),
        ('INNERGRID', (0,0), (-1,-1), 0.5, GRAY_LINE),
        ('BOX', (0,0), (-1,-1), 0.5, GRAY_LINE),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,0), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(cst)
    story.append(Spacer(1, 0.4*cm))

    fn_headers = [
        Paragraph('NIST CSF Function', sTableH),
        Paragraph('Total Controls', sTableH),
        Paragraph('Compliant', sTableH),
        Paragraph('Partial', sTableH),
        Paragraph('Non Compliant', sTableH),
        Paragraph('Compliance %', sTableH),
    ]
    fn_rows = [fn_headers]
    for fs in function_stats:
        fn_assessed = (fs['compliant_c'] or 0) + (fs['partial_c'] or 0) + (fs['non_c'] or 0)
        fn_pct = round((fs['compliant_c'] or 0) / fn_assessed * 100, 1) if fn_assessed > 0 else 0.0
        pct_col = GREEN if fn_pct >= 80 else (YELLOW if fn_pct >= 60 else RED)
        fn_rows.append([
            Paragraph(fs['function_name'], sTableBold),
            Paragraph(str(fs['total']), sCenter),
            Paragraph(str(fs['compliant_c'] or 0), ParagraphStyle('gc', fontName='Helvetica-Bold',
                      fontSize=8, textColor=GREEN, alignment=TA_CENTER, leading=11)),
            Paragraph(str(fs['partial_c'] or 0), ParagraphStyle('yc', fontName='Helvetica-Bold',
                      fontSize=8, textColor=YELLOW, alignment=TA_CENTER, leading=11)),
            Paragraph(str(fs['non_c'] or 0), ParagraphStyle('rc', fontName='Helvetica-Bold',
                      fontSize=8, textColor=RED, alignment=TA_CENTER, leading=11)),
            Paragraph(f'{fn_pct}%', ParagraphStyle('pc', fontName='Helvetica-Bold',
                      fontSize=8, textColor=pct_col, alignment=TA_CENTER, leading=11)),
        ])
    fnt = Table(fn_rows, colWidths=[4*cm, 2.5*cm, 2*cm, 1.8*cm, 2.5*cm, 2.2*cm], repeatRows=1)
    fnt.setStyle(table_style())
    story.append(fnt)

    # ══════════════════════════════════════════════════
    # 7. AUDIT FINDINGS
    # ══════════════════════════════════════════════════
    story.append(PageBreak())
    story += section_title('7', 'Audit Findings')
    story.append(Paragraph(
        f'A total of {len(findings)} audit findings were identified. Findings are presented in order of '
        f'severity from Critical to Low. Each finding includes the issue description, affected asset, '
        f'risk rating, and recommended remediation action.',
        sBody))
    story.append(Spacer(1, 0.2*cm))

    if findings:
        for idx, f in enumerate(findings, 1):
            level = f['risk_level']
            fc = risk_color(level)
            fbg = risk_bg(level)

            finding_block = [
                [
                    Paragraph(f'Finding {idx:02d}', ParagraphStyle('fn', fontName='Helvetica-Bold',
                              fontSize=7, textColor=WHITE, leading=10)),
                    Paragraph(level.upper(), ParagraphStyle('fl', fontName='Helvetica-Bold',
                              fontSize=7, textColor=WHITE, leading=10, alignment=TA_RIGHT)),
                ],
                [
                    Paragraph(f['title'], ParagraphStyle('ft', fontName='Helvetica-Bold',
                              fontSize=9.5, textColor=BLACK, leading=13)),
                    Paragraph(f['control_ref'] or '', ParagraphStyle('fr', fontName='Helvetica',
                              fontSize=7.5, textColor=BLUE, leading=10, alignment=TA_RIGHT)),
                ],
                [
                    Paragraph(f'<b>Issue:</b> {f["issue"]}', sFindingBody),
                    Paragraph('', sFindingBody),
                ],
                [
                    Paragraph(f'<b>Affected Asset:</b> {f["affected_asset"] or "—"}', sFindingBody),
                    Paragraph('', sFindingBody),
                ],
                [
                    Paragraph(f'<b>Recommendation:</b> {f["recommendation"]}', sFindingBody),
                    Paragraph('', sFindingBody),
                ],
            ]

            ft = Table(finding_block, colWidths=[CONTENT_W * 0.65, CONTENT_W * 0.35])
            ft.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), fc),
                ('BACKGROUND', (0,1), (-1,1), LIGHT_BLUE),
                ('BACKGROUND', (0,2), (-1,-1), WHITE),
                ('SPAN', (0,2), (-1,2)),
                ('SPAN', (0,3), (-1,3)),
                ('SPAN', (0,4), (-1,4)),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
                ('BOX', (0,0), (-1,-1), 0.8, fc),
                ('LINEBELOW', (0,0), (-1,0), 0, WHITE),
                ('LINEBELOW', (0,1), (-1,1), 0.5, GRAY_LINE),
                ('LINEBELOW', (0,2), (-1,2), 0.3, GRAY_LINE),
                ('LINEBELOW', (0,3), (-1,3), 0.3, GRAY_LINE),
            ]))
            story.append(KeepTogether([ft, Spacer(1, 0.3*cm)]))
    else:
        story.append(Paragraph('No findings have been recorded.', sSmall))

    # ══════════════════════════════════════════════════
    # 8. AUDIT EVIDENCE
    # ══════════════════════════════════════════════════
    story.append(PageBreak())
    story += section_title('8', 'Audit Evidence')
    story.append(Paragraph(
        'The following evidence files were collected and uploaded during the audit to support '
        'control assessments. Image evidence is displayed inline; other file types are listed by name.',
        sBody))
    story.append(Spacer(1, 0.2*cm))

    if evidence_rows:
        import os as _os
        # Group by control
        ctrl_groups = {}
        for ev in evidence_rows:
            key = ev['ctrl_ref']
            if key not in ctrl_groups:
                ctrl_groups[key] = {'desc': ev['ctrl_desc'], 'status': ev['ctrl_status'], 'files': []}
            ctrl_groups[key]['files'].append(ev)

        for ctrl_ref, grp in ctrl_groups.items():
            hdr_data = [[
                Paragraph(ctrl_ref, ParagraphStyle('ek', fontName='Helvetica-Bold', fontSize=8,
                          textColor=WHITE, leading=11)),
                Paragraph(grp['status'] or '', ParagraphStyle('es', fontName='Helvetica', fontSize=8,
                          textColor=WHITE, leading=11, alignment=TA_RIGHT)),
            ]]
            ht = Table(hdr_data, colWidths=[CONTENT_W * 0.6, CONTENT_W * 0.4])
            ht.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), NAVY),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(ht)
            story.append(Paragraph(grp['desc'] or '', ParagraphStyle('edesc', fontName='Helvetica',
                         fontSize=8, textColor=GRAY_TEXT, leading=12, leftIndent=8, spaceAfter=4)))

            for ev in grp['files']:
                ftype = (ev['file_type'] or '').lower()
                fname = ev['original_name'] or ev['filename']
                uploaded_by = ev['full_name'] or 'Unknown'
                uploaded_at = (ev['uploaded_at'] or '')[:10]

                if ftype in ('png', 'jpg', 'jpeg'):
                    img_path = _os.path.join('static', 'uploads', ev['filename'])
                    if _os.path.exists(img_path):
                        try:
                            from reportlab.platypus import Image as RLImage
                            img = RLImage(img_path, width=CONTENT_W * 0.7, height=5*cm,
                                          kind='proportional')
                            ev_block = [
                                Paragraph(f'📎 {fname}', ParagraphStyle('efn', fontName='Helvetica-Bold',
                                          fontSize=8, textColor=BLACK, leading=11, leftIndent=8)),
                                Paragraph(f'Uploaded by {uploaded_by} on {uploaded_at}',
                                          ParagraphStyle('emd', fontName='Helvetica', fontSize=7.5,
                                          textColor=GRAY_MUTED, leading=11, leftIndent=8, spaceAfter=4)),
                                img,
                                Spacer(1, 0.2*cm),
                            ]
                            story += ev_block
                        except Exception:
                            story.append(Paragraph(
                                f'📎 {fname} — image could not be rendered',
                                ParagraphStyle('efn2', fontName='Helvetica', fontSize=8,
                                               textColor=GRAY_MUTED, leading=11, leftIndent=8, spaceAfter=4)))
                    else:
                        story.append(Paragraph(
                            f'📎 {fname} — file not found on server',
                            ParagraphStyle('efn3', fontName='Helvetica', fontSize=8,
                                           textColor=GRAY_MUTED, leading=11, leftIndent=8, spaceAfter=4)))
                else:
                    story.append(Paragraph(
                        f'📄 {fname}  ({ftype.upper() if ftype else "FILE"})  — uploaded by {uploaded_by} on {uploaded_at}',
                        ParagraphStyle('efn4', fontName='Helvetica', fontSize=8,
                                       textColor=GRAY_TEXT, leading=12, leftIndent=8, spaceAfter=4)))
            story.append(Spacer(1, 0.3*cm))
    else:
        story.append(Paragraph('No evidence files have been uploaded for this audit.', sSmall))

    story.append(Spacer(1, 0.3*cm))

    # ══════════════════════════════════════════════════
    # 9. AI RECOMMENDATIONS
    # ══════════════════════════════════════════════════
    story.append(PageBreak())
    story += section_title('9', 'AI Recommendations')
    story.append(Paragraph(
        'The following recommendations were generated by the AI Auditor Assistant based on '
        'identified vulnerabilities and non-compliant controls. Recommendations are ordered by severity.',
        sBody))
    story.append(Spacer(1, 0.2*cm))

    # Pull cached AI explanations for vulns that appear in findings
    ai_recs = []
    # 1. Add cached AI explanations for high/critical vulns
    seen_vulns = set()
    for v in vulns:
        if v['risk_level'] in ('Critical', 'High') and v['vuln_name'] not in seen_vulns:
            seen_vulns.add(v['vuln_name'])
            label = f"{v['vuln_name']} ({v['vuln_code']}) on {v['asset_name']}"
            ai_recs.append({
                'level': v['risk_level'],
                'title': f"Remediate {v['vuln_name']} on {v['asset_name']}",
                'body': f"Vulnerability: {v['vuln_name']} ({v['vuln_code']}) detected on {v['asset_name']}. "
                        f"Risk Score: {int(v['risk_score'])} (Likelihood {v['likelihood']} × Impact {v['impact']}). "
                        f"Recommended Action: Apply vendor patches, enforce input validation, and implement security controls "
                        f"per NIST CSF to mitigate exposure. Verify remediation with a follow-up scan.",
            })
    # 2. Add rule-based recommendations from non-compliant controls
    for f in findings:
        if f['control_ref'] and f['risk_level'] in ('Critical', 'High', 'Medium'):
            ai_recs.append({
                'level': f['risk_level'],
                'title': f['title'],
                'body': f"Issue: {f['issue']}  Affected Asset: {f['affected_asset'] or 'N/A'}.  "
                        f"AI Recommendation: {f['recommendation']}",
            })
    # 3. Overall posture recommendation
    if compliance_pct < 80:
        ai_recs.append({
            'level': 'High' if compliance_pct < 60 else 'Medium',
            'title': 'Improve Overall NIST CSF Compliance',
            'body': f"Current compliance is {compliance_pct}%. Priority actions: (1) Address all Non-Compliant controls "
                    f"in the Protect and Detect functions first. (2) Assign control owners and set remediation deadlines. "
                    f"(3) Schedule a follow-up audit within 90 days to verify improvement.",
        })
    # Sort by severity
    sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    ai_recs.sort(key=lambda x: sev_order.get(x['level'], 4))

    if ai_recs:
        for idx, rec in enumerate(ai_recs, 1):
            level = rec['level']
            rc = risk_color(level)
            rbg = risk_bg(level)
            ai_block = [
                [
                    Paragraph(f'#{idx}  {rec["title"]}', ParagraphStyle('ait', fontName='Helvetica-Bold',
                              fontSize=9, textColor=WHITE, leading=13)),
                    Paragraph(level, ParagraphStyle('ail', fontName='Helvetica-Bold', fontSize=8,
                              textColor=WHITE, leading=13, alignment=TA_RIGHT)),
                ],
                [
                    Paragraph(rec['body'], ParagraphStyle('aib', fontName='Helvetica', fontSize=8.5,
                              textColor=GRAY_TEXT, leading=13, spaceAfter=2)),
                    Paragraph('', sSmall),
                ],
            ]
            at2 = Table(ai_block, colWidths=[CONTENT_W * 0.72, CONTENT_W * 0.28])
            at2.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), rc),
                ('BACKGROUND', (0,1), (-1,1), rbg),
                ('SPAN', (0,1), (-1,1)),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 10),
                ('BOX', (0,0), (-1,-1), 0.5, rc),
                ('LINEBELOW', (0,0), (-1,0), 0.3, colors.HexColor('#ffffff44')),
            ]))
            story.append(KeepTogether([at2, Spacer(1, 0.25*cm)]))
    else:
        story.append(Paragraph('No AI recommendations are available. Run the AI Explainer on identified vulnerabilities to generate recommendations.', sSmall))

    story.append(Spacer(1, 0.3*cm))

    # ══════════════════════════════════════════════════
    # 10. FINAL OPINION
    # ══════════════════════════════════════════════════
    story += section_title('10', 'Final Audit Opinion')
    story.append(Paragraph(
        'Based on the risk assessment findings and compliance evaluation conducted against the '
        'NIST Cybersecurity Framework 2.0, the following final opinion is issued:',
        sBody))
    story.append(Spacer(1, 0.3*cm))

    op_desc_full = {
        'Secure': (
            GREEN,
            f'The organization demonstrates a strong and mature cybersecurity posture. '
            f'With {compliance_pct}% NIST CSF compliance and no critical vulnerabilities, '
            f'current security controls are operating effectively. The organization is recommended '
            f'to maintain current controls, continue regular assessments, and monitor for emerging threats.'
        ),
        'Acceptable Risk': (
            YELLOW,
            f'The organization shows an acceptable level of security with {compliance_pct}% NIST CSF compliance. '
            f'While the overall posture is manageable, {len(findings)} findings require attention. '
            f'A structured remediation plan addressing identified gaps within 90 days is recommended, '
            f'prioritizing high-severity vulnerabilities and partially compliant controls.'
        ),
        'Needs Immediate Action': (
            RED,
            f'The organization\'s current security posture presents significant risk. '
            f'With {compliance_pct}% compliance and {critical_count} critical vulnerabilities, '
            f'immediate remediation is required. Senior management should be briefed on the risks '
            f'and an emergency response plan activated. All critical findings must be resolved within 30 days.'
        ),
    }
    op_color_final, op_text_final = op_desc_full.get(final_opinion, (BLUE, ''))

    opinion_data = [[
        Paragraph(final_opinion, ParagraphStyle('fop', fontName='Helvetica-Bold', fontSize=22,
                  textColor=WHITE, leading=26, alignment=TA_CENTER)),
    ],[
        Paragraph(op_text_final, ParagraphStyle('fod', fontName='Helvetica', fontSize=9,
                  textColor=WHITE, leading=14, alignment=TA_JUSTIFY)),
    ]]
    fot = Table(opinion_data, colWidths=[CONTENT_W])
    fot.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), op_color_final),
        ('TOPPADDING', (0,0), (-1,0), 16),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('TOPPADDING', (0,1), (-1,1), 10),
        ('BOTTOMPADDING', (0,1), (-1,1), 16),
        ('LEFTPADDING', (0,0), (-1,-1), 20),
        ('RIGHTPADDING', (0,0), (-1,-1), 20),
        ('LINEBELOW', (0,0), (-1,0), 0.5, colors.HexColor('#ffffff44')),
        ('BOX', (0,0), (-1,-1), 1, op_color_final),
    ]))
    story.append(fot)
    story.append(Spacer(1, 0.5*cm))

    # ── Build PDF ─────────────────────────────────────
    doc.build(story, onFirstPage=cover_page, onLaterPages=on_page)
    buffer.seek(0)
    filename = f"Audit_Report_{org_name.replace(' ','_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/pdf')

@app.route('/api/vuln-info/<code>')
@login_required
def vuln_info(code):
    vuln = next((v for v in OWASP_VULNS if v['code'] == code), None)
    if vuln:
        return jsonify(vuln)
    return jsonify({}), 404

@app.route('/explain/<path:vuln_name>')
@login_required
def explain(vuln_name):
    try:
        explanation, from_cache = generate_explanation(vuln_name)
        return jsonify({'explanation': explanation, 'cached': from_cache})
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'Cannot connect to Ollama. Make sure Ollama is running: run `ollama serve` in a terminal, then ensure phi3:mini is available via `ollama list`.'}), 503
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    os.makedirs('instance', exist_ok=True)
    os.makedirs('static/uploads', exist_ok=True)
    with app.app_context():
        init_db()
    app.run(debug=True, port=5000)
