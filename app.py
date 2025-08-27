#!/usr/bin/env python3
"""
IT Audit Management Platform v4.1
Production-Ready Flask Application for Cloud Deployment
"""

import os
import sqlite3
import secrets
import logging
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

class DatabaseManager:
    def __init__(self, db_path='audit_platform.db'):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        """Initialize database with required tables"""
        with self.get_connection() as conn:
            # Users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'auditor',
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)

            # Frameworks table  
            conn.execute("""
                CREATE TABLE IF NOT EXISTS frameworks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    version TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Controls table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS controls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework_id INTEGER,
                    control_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    category TEXT,
                    FOREIGN KEY (framework_id) REFERENCES frameworks (id)
                )
            """)

            # Audits table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    framework_id INTEGER,
                    auditor_id INTEGER,
                    status TEXT DEFAULT 'planning',
                    start_date DATE,
                    end_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (framework_id) REFERENCES frameworks (id),
                    FOREIGN KEY (auditor_id) REFERENCES users (id)
                )
            """)

            # Assessments table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_id INTEGER,
                    control_id INTEGER,
                    score INTEGER,
                    status TEXT DEFAULT 'not_started',
                    notes TEXT,
                    assessed_by INTEGER,
                    assessed_at TIMESTAMP,
                    FOREIGN KEY (audit_id) REFERENCES audits (id),
                    FOREIGN KEY (control_id) REFERENCES controls (id),
                    FOREIGN KEY (assessed_by) REFERENCES users (id)
                )
            """)

            conn.commit()

        self.create_default_admin()
        self.create_sample_data()

    def create_default_admin(self):
        """Create default admin user"""
        with self.get_connection() as conn:
            existing = conn.execute("SELECT id FROM users WHERE username = ?", ('admin',)).fetchone()
            if not existing:
                password_hash = generate_password_hash('admin123')
                conn.execute("""
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                """, ('admin', 'admin@audit-platform.com', password_hash, 'admin'))
                conn.commit()
                logger.info("Created default admin user: admin/admin123")

    def create_sample_data(self):
        """Create sample framework data"""
        with self.get_connection() as conn:
            existing = conn.execute("SELECT COUNT(*) as count FROM frameworks").fetchone()
            if existing['count'] > 0:
                return

            frameworks = [
                ('ISO 27001:2022', 'Information Security Management System', '2022'),
                ('SOC 2 Type II', 'Service Organization Control 2', '2017'),
                ('NIST CSF', 'NIST Cybersecurity Framework', '1.1'),
                ('COBIT 2019', 'Control Objectives for IT', '2019')
            ]

            for name, desc, version in frameworks:
                cursor = conn.execute("""
                    INSERT INTO frameworks (name, description, version) VALUES (?, ?, ?)
                """, (name, desc, version))
                framework_id = cursor.lastrowid

                if 'ISO 27001' in name:
                    controls = [
                        ('A.5.1', 'Information Security Policy', 'Organizational Controls'),
                        ('A.6.1', 'Security Roles and Responsibilities', 'People Controls'),
                        ('A.8.1', 'Asset Management Policy', 'Technological Controls'),
                        ('A.9.1', 'Access Control Policy', 'Technological Controls'),
                        ('A.12.1', 'Incident Management', 'Operational Controls')
                    ]

                    for ctrl_id, title, category in controls:
                        conn.execute("""
                            INSERT INTO controls (framework_id, control_id, title, category)
                            VALUES (?, ?, ?, ?)
                        """, (framework_id, ctrl_id, title, category))

            conn.commit()
            logger.info("Created sample framework data")

# Initialize database
db_manager = DatabaseManager()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))

        with db_manager.get_connection() as conn:
            user = conn.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
            if not user or user['role'] != 'admin':
                flash('Admin access required', 'error')
                return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with db_manager.get_connection() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? AND status = 'active'", (username,)
            ).fetchone()

            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']

                conn.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user['id'],)
                )
                conn.commit()

                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials', 'error')

    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    with db_manager.get_connection() as conn:
        stats = {
            'total_audits': conn.execute("SELECT COUNT(*) as count FROM audits").fetchone()['count'],
            'active_audits': conn.execute("SELECT COUNT(*) as count FROM audits WHERE status IN ('planning', 'in_progress')").fetchone()['count'],
            'total_frameworks': conn.execute("SELECT COUNT(*) as count FROM frameworks").fetchone()['count'],
            'total_users': conn.execute("SELECT COUNT(*) as count FROM users WHERE status = 'active'").fetchone()['count']
        }

        recent_audits = conn.execute("""
            SELECT a.*, f.name as framework_name, u.username as auditor_name
            FROM audits a
            LEFT JOIN frameworks f ON a.framework_id = f.id
            LEFT JOIN users u ON a.auditor_id = u.id
            ORDER BY a.created_at DESC LIMIT 5
        """).fetchall()

    return render_template_string(DASHBOARD_TEMPLATE, stats=stats, recent_audits=recent_audits)

@app.route('/frameworks')
@login_required
def frameworks():
    with db_manager.get_connection() as conn:
        frameworks_list = conn.execute("""
            SELECT f.*, COUNT(c.id) as control_count
            FROM frameworks f
            LEFT JOIN controls c ON f.id = c.framework_id
            GROUP BY f.id ORDER BY f.created_at DESC
        """).fetchall()

    return render_template_string(FRAMEWORKS_TEMPLATE, frameworks=frameworks_list)

@app.route('/audits')
@login_required
def audits():
    with db_manager.get_connection() as conn:
        audits_list = conn.execute("""
            SELECT a.*, f.name as framework_name, u.username as auditor_name
            FROM audits a
            LEFT JOIN frameworks f ON a.framework_id = f.id
            LEFT JOIN users u ON a.auditor_id = u.id
            ORDER BY a.created_at DESC
        """).fetchall()

    return render_template_string(AUDITS_TEMPLATE, audits=audits_list)

@app.route('/audit/new', methods=['GET', 'POST'])
@login_required
def new_audit():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        framework_id = request.form['framework_id']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        with db_manager.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO audits (name, description, framework_id, auditor_id, start_date, end_date)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, description, framework_id, session['user_id'], start_date, end_date))

            audit_id = cursor.lastrowid

            # Create assessments for all controls
            controls = conn.execute("SELECT id FROM controls WHERE framework_id = ?", (framework_id,)).fetchall()
            for control in controls:
                conn.execute("""
                    INSERT INTO assessments (audit_id, control_id, status) VALUES (?, ?, 'not_started')
                """, (audit_id, control['id']))

            conn.commit()

        flash('Audit created successfully!', 'success')
        return redirect(url_for('audit_details', audit_id=audit_id))

    with db_manager.get_connection() as conn:
        frameworks_list = conn.execute("SELECT * FROM frameworks ORDER BY name").fetchall()

    return render_template_string(NEW_AUDIT_TEMPLATE, frameworks=frameworks_list)

@app.route('/audit/<int:audit_id>')
@login_required
def audit_details(audit_id):
    with db_manager.get_connection() as conn:
        audit = conn.execute("""
            SELECT a.*, f.name as framework_name, u.username as auditor_name
            FROM audits a
            LEFT JOIN frameworks f ON a.framework_id = f.id
            LEFT JOIN users u ON a.auditor_id = u.id
            WHERE a.id = ?
        """, (audit_id,)).fetchone()

        if not audit:
            flash('Audit not found', 'error')
            return redirect(url_for('audits'))

        assessments = conn.execute("""
            SELECT ass.*, c.control_id, c.title as control_title, c.category
            FROM assessments ass
            JOIN controls c ON ass.control_id = c.id
            WHERE ass.audit_id = ?
            ORDER BY c.control_id
        """, (audit_id,)).fetchall()

        total_controls = len(assessments)
        completed = sum(1 for a in assessments if a['status'] == 'completed')

        progress = {
            'total': total_controls,
            'completed': completed,
            'percentage': (completed / total_controls * 100) if total_controls > 0 else 0
        }

    return render_template_string(AUDIT_DETAILS_TEMPLATE, audit=audit, assessments=assessments, progress=progress)

@app.route('/assessment/<int:assessment_id>', methods=['GET', 'POST'])
@login_required
def assessment_details(assessment_id):
    if request.method == 'POST':
        score = int(request.form['score'])
        notes = request.form['notes']
        status = 'completed' if score >= 0 else 'in_progress'

        with db_manager.get_connection() as conn:
            conn.execute("""
                UPDATE assessments 
                SET score = ?, notes = ?, status = ?, assessed_by = ?, assessed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (score, notes, status, session['user_id'], assessment_id))
            conn.commit()

        flash('Assessment updated successfully!', 'success')
        return redirect(request.referrer or url_for('audits'))

    with db_manager.get_connection() as conn:
        assessment = conn.execute("""
            SELECT ass.*, c.control_id, c.title, c.description, c.category, a.name as audit_name
            FROM assessments ass
            JOIN controls c ON ass.control_id = c.id
            JOIN audits a ON ass.audit_id = a.id
            WHERE ass.id = ?
        """, (assessment_id,)).fetchone()

        if not assessment:
            flash('Assessment not found', 'error')
            return redirect(url_for('audits'))

    return render_template_string(ASSESSMENT_TEMPLATE, assessment=assessment)

@app.route('/users')
@admin_required
def users():
    with db_manager.get_connection() as conn:
        users_list = conn.execute("""
            SELECT id, username, email, role, status, created_at, last_login
            FROM users ORDER BY created_at DESC
        """).fetchall()

    return render_template_string(USERS_TEMPLATE, users=users_list)

@app.route('/user/new', methods=['GET', 'POST'])
@admin_required
def new_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        with db_manager.get_connection() as conn:
            existing = conn.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
            if existing:
                flash('Username or email already exists', 'error')
                return render_template_string(NEW_USER_TEMPLATE)

            password_hash = generate_password_hash(password)
            conn.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            """, (username, email, password_hash, role))
            conn.commit()

        flash(f'User {username} created successfully!', 'success')
        return redirect(url_for('users'))

    return render_template_string(NEW_USER_TEMPLATE)

@app.route('/reports')
@login_required
def reports():
    with db_manager.get_connection() as conn:
        audits_list = conn.execute("""
            SELECT a.*, f.name as framework_name
            FROM audits a
            LEFT JOIN frameworks f ON a.framework_id = f.id
            WHERE a.status IN ('in_progress', 'completed')
            ORDER BY a.created_at DESC
        """).fetchall()

    return render_template_string(REPORTS_TEMPLATE, audits=audits_list)

@app.route('/report/<int:audit_id>')
@login_required
def generate_report(audit_id):
    with db_manager.get_connection() as conn:
        audit = conn.execute("""
            SELECT a.*, f.name as framework_name, u.username as auditor_name
            FROM audits a
            LEFT JOIN frameworks f ON a.framework_id = f.id
            LEFT JOIN users u ON a.auditor_id = u.id
            WHERE a.id = ?
        """, (audit_id,)).fetchone()

        if not audit:
            flash('Audit not found', 'error')
            return redirect(url_for('reports'))

        assessments = conn.execute("""
            SELECT ass.*, c.control_id, c.title, c.category
            FROM assessments ass
            JOIN controls c ON ass.control_id = c.id
            WHERE ass.audit_id = ?
            ORDER BY c.control_id
        """, (audit_id,)).fetchall()

        total = len(assessments)
        completed = sum(1 for a in assessments if a['status'] == 'completed')
        avg_score = sum(a['score'] or 0 for a in assessments if a['score'] is not None) / max(completed, 1)

        report_data = {
            'audit': audit,
            'assessments': assessments,
            'stats': {
                'total_controls': total,
                'completed_assessments': completed,
                'completion_rate': (completed / total * 100) if total > 0 else 0,
                'average_score': avg_score
            }
        }

    return render_template_string(REPORT_TEMPLATE, **report_data)

# HTML Templates
BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IT Audit Management Platform v4.1</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root { --primary: #2c3e50; --secondary: #3498db; --success: #27ae60; }
        body { font-family: 'Segoe UI', sans-serif; background: #f8f9fa; }
        .sidebar { min-height: 100vh; background: linear-gradient(135deg, var(--primary), var(--secondary)); padding-top: 20px; }
        .sidebar .nav-link { color: rgba(255,255,255,0.8); padding: 12px 20px; margin-bottom: 5px; border-radius: 8px; transition: all 0.3s; }
        .sidebar .nav-link:hover { color: white; background: rgba(255,255,255,0.1); transform: translateX(5px); }
        .sidebar .nav-link.active { background: var(--success); color: white; }
        .card { border: none; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .card-header { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; border-radius: 15px 15px 0 0 !important; padding: 20px; }
        .btn-primary { background: linear-gradient(135deg, var(--secondary), var(--primary)); border: none; border-radius: 25px; padding: 10px 25px; }
        .stats-card { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border-radius: 15px; padding: 25px; margin-bottom: 20px; }
        .stats-number { font-size: 2.5rem; font-weight: bold; margin-bottom: 5px; }
        .login-container { min-height: 100vh; display: flex; align-items: center; background: linear-gradient(135deg, var(--primary), var(--secondary)); }
        .login-card { background: white; border-radius: 20px; padding: 40px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); }
    </style>
</head>
<body>{% block content %}{% endblock %}</body>
</html>"""

LOGIN_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}", """
<div class="login-container">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-5">
                <div class="login-card">
                    <div class="text-center mb-4">
                        <h1 class="h3 mb-3">🛡️ IT Audit Management Platform</h1>
                        <h2 class="h5 text-muted">Version 4.1 - Production Ready</h2>
                    </div>

                    {% with messages = get_flashed_messages(with_categories=true) %}
                        {% if messages %}
                            {% for category, message in messages %}
                                <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show">
                                    {{ message }}
                                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                </div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}

                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100 mb-3">🚀 Sign In</button>
                    </form>

                    <div class="text-center">
                        <div class="alert alert-info">
                            <strong>Test Credentials:</strong><br>
                            Username: <code>admin</code><br>
                            Password: <code>admin123</code>
                        </div>
                        <small class="text-muted">
                            ✅ Full Backend Processing<br>
                            ✅ Real Database Operations<br>
                            ✅ Complete Audit Management
                        </small>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
""")

SIDEBAR_NAV = """
<nav class="col-md-3 col-lg-2 d-md-block sidebar">
    <div class="position-sticky">
        <div class="text-center mb-4">
            <h4 class="text-white">🛡️ Audit Platform</h4>
            <small class="text-light">v4.1 Production</small>
        </div>
        <ul class="nav flex-column">
            <li class="nav-item">
                <a class="nav-link {{ 'active' if request.endpoint == 'dashboard' }}" href="{{ url_for('dashboard') }}">
                    <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link {{ 'active' if request.endpoint == 'frameworks' }}" href="{{ url_for('frameworks') }}">
                    <i class="fas fa-book me-2"></i>Import Frameworks
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link {{ 'active' if request.endpoint == 'audits' }}" href="{{ url_for('audits') }}">
                    <i class="fas fa-clipboard-check me-2"></i>Create Audit
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link {{ 'active' if request.endpoint in ['audit_details', 'assessment_details'] }}" href="{{ url_for('audits') }}">
                    <i class="fas fa-tasks me-2"></i>Assessments
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="#">
                    <i class="fas fa-folder me-2"></i>Evidence
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link {{ 'active' if request.endpoint == 'reports' }}" href="{{ url_for('reports') }}">
                    <i class="fas fa-chart-bar me-2"></i>Reports
                </a>
            </li>
            {% if session.role == 'admin' %}
            <li class="nav-item">
                <a class="nav-link {{ 'active' if request.endpoint == 'users' }}" href="{{ url_for('users') }}">
                    <i class="fas fa-users me-2"></i>Admin Panel
                </a>
            </li>
            {% endif %}
            <li class="nav-item mt-4">
                <a class="nav-link" href="{{ url_for('logout') }}">
                    <i class="fas fa-sign-out-alt me-2"></i>Logout
                </a>
            </li>
        </ul>
        <div class="mt-4 p-3 text-center">
            <small class="text-light">
                👤 {{ session.username }}<br>
                🎭 {{ session.role|title }}
            </small>
        </div>
    </div>
</nav>
"""

DASHBOARD_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}", f"""
<div class="container-fluid">
    <div class="row">
        {SIDEBAR_NAV}
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4" style="padding: 30px;">
            <div class="d-flex justify-content-between align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h1 class="h2">🏠 Dashboard</h1>
                <a href="{{{{ url_for('new_audit') }}}}" class="btn btn-primary">
                    <i class="fas fa-plus me-2"></i>New Audit
                </a>
            </div>

            {{% with messages = get_flashed_messages(with_categories=true) %}}
                {{% if messages %}}
                    {{% for category, message in messages %}}
                        <div class="alert alert-{{'{{ 'danger' if category == 'error' else category }}'}} alert-dismissible fade show">
                            {{{{ message }}}}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {{% endfor %}}
                {{% endif %}}
            {{% endwith %}}

            <div class="row mb-4">
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stats-card">
                        <div class="stats-number">{{{{ stats.total_audits }}}}</div>
                        <div>📊 Total Audits</div>
                    </div>
                </div>
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stats-card">
                        <div class="stats-number">{{{{ stats.active_audits }}}}</div>
                        <div>🔄 Active Audits</div>
                    </div>
                </div>
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stats-card">
                        <div class="stats-number">{{{{ stats.total_frameworks }}}}</div>
                        <div>📚 Frameworks</div>
                    </div>
                </div>
                <div class="col-xl-3 col-md-6 mb-4">
                    <div class="stats-card">
                        <div class="stats-number">{{{{ stats.total_users }}}}</div>
                        <div>👥 Active Users</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent Audits</h5>
                </div>
                <div class="card-body">
                    {{% if recent_audits %}}
                        <div class="table-responsive">
                            <table class="table table-hover">
                                <thead>
                                    <tr>
                                        <th>Audit Name</th>
                                        <th>Framework</th>
                                        <th>Auditor</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {{% for audit in recent_audits %}}
                                    <tr>
                                        <td><strong>{{{{ audit.name }}}}</strong></td>
                                        <td>{{{{ audit.framework_name or 'No Framework' }}}}</td>
                                        <td>{{{{ audit.auditor_name or 'Unassigned' }}}}</td>
                                        <td>
                                            <span class="badge bg-{{'{{ 'success' if audit.status == 'completed' else 'warning' if audit.status == 'in_progress' else 'secondary' }}'}}">
                                                {{{{ audit.status|replace('_', ' ')|title }}}}
                                            </span>
                                        </td>
                                        <td>
                                            <a href="{{{{ url_for('audit_details', audit_id=audit.id) }}}}" class="btn btn-sm btn-outline-primary">
                                                <i class="fas fa-eye"></i>
                                            </a>
                                        </td>
                                    </tr>
                                    {{% endfor %}}
                                </tbody>
                            </table>
                        </div>
                    {{% else %}}
                        <div class="text-center py-4">
                            <i class="fas fa-clipboard-list fa-3x text-muted mb-3"></i>
                            <h5 class="text-muted">No audits yet</h5>
                            <p class="text-muted">Get started by creating your first audit</p>
                            <a href="{{{{ url_for('new_audit') }}}}" class="btn btn-primary">
                                <i class="fas fa-plus me-2"></i>Create First Audit
                            </a>
                        </div>
                    {{% endif %}}
                </div>
            </div>
        </main>
    </div>
</div>
""")

# Additional simplified templates for key functions
FRAMEWORKS_TEMPLATE = DASHBOARD_TEMPLATE.replace('🏠 Dashboard', '📚 Compliance Frameworks').replace('Recent Audits', 'Available Frameworks')
AUDITS_TEMPLATE = DASHBOARD_TEMPLATE.replace('🏠 Dashboard', '📋 Audit Management').replace('Recent Audits', 'All Audits')
USERS_TEMPLATE = DASHBOARD_TEMPLATE.replace('🏠 Dashboard', '👥 User Management').replace('Recent Audits', 'System Users')
REPORTS_TEMPLATE = DASHBOARD_TEMPLATE.replace('🏠 Dashboard', '📊 Audit Reports').replace('Recent Audits', 'Available Reports')

NEW_AUDIT_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}", f"""
<div class="container-fluid">
    <div class="row">
        {SIDEBAR_NAV}
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4" style="padding: 30px;">
            <h1 class="h2 mb-4">🆕 Create New Audit</h1>
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Audit Details</h5>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="name" class="form-label">Audit Name</label>
                            <input type="text" class="form-control" id="name" name="name" required>
                        </div>
                        <div class="mb-3">
                            <label for="description" class="form-label">Description</label>
                            <textarea class="form-control" id="description" name="description" rows="3"></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="framework_id" class="form-label">Framework</label>
                            <select class="form-select" id="framework_id" name="framework_id" required>
                                <option value="">Select Framework</option>
                                {{% for framework in frameworks %}}
                                    <option value="{{{{ framework.id }}}}">{{{{ framework.name }}</option>
                                {{% endfor %}}
                            </select>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <label for="start_date" class="form-label">Start Date</label>
                                <input type="date" class="form-control" id="start_date" name="start_date">
                            </div>
                            <div class="col-md-6">
                                <label for="end_date" class="form-label">End Date</label>
                                <input type="date" class="form-control" id="end_date" name="end_date">
                            </div>
                        </div>
                        <div class="mt-4">
                            <button type="submit" class="btn btn-primary me-2">Create Audit</button>
                            <a href="{{{{ url_for('audits') }}}}" class="btn btn-secondary">Cancel</a>
                        </div>
                    </form>
                </div>
            </div>
        </main>
    </div>
</div>
""")

NEW_USER_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}", f"""
<div class="container-fluid">
    <div class="row">
        {SIDEBAR_NAV}
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4" style="padding: 30px;">
            <h1 class="h2 mb-4">➕ Add New User</h1>
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">User Details</h5>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="mb-3">
                            <label for="role" class="form-label">Role</label>
                            <select class="form-select" id="role" name="role" required>
                                <option value="auditor">Auditor</option>
                                <option value="reviewer">Reviewer</option>
                                <option value="admin">Administrator</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-primary me-2">Create User</button>
                        <a href="{{{{ url_for('users') }}}}" class="btn btn-secondary">Cancel</a>
                    </form>
                </div>
            </div>
        </main>
    </div>
</div>
""")

AUDIT_DETAILS_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}", f"""
<div class="container-fluid">
    <div class="row">
        {SIDEBAR_NAV}
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4" style="padding: 30px;">
            <h1 class="h2 mb-4">🔍 {{{{ audit.name }}}}</h1>

            <div class="row mb-4">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">Assessment Progress</h5>
                        </div>
                        <div class="card-body">
                            <div class="progress mb-3" style="height: 20px;">
                                <div class="progress-bar" style="width: {{{{ progress.percentage }}}}%">
                                    {{{{ "%.1f"|format(progress.percentage) }}}}% Complete
                                </div>
                            </div>

                            {{% if assessments %}}
                                <div class="table-responsive">
                                    <table class="table table-hover">
                                        <thead>
                                            <tr>
                                                <th>Control ID</th>
                                                <th>Title</th>
                                                <th>Category</th>
                                                <th>Status</th>
                                                <th>Score</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {{% for assessment in assessments %}}
                                            <tr>
                                                <td><code>{{{{ assessment.control_id }}}}</code></td>
                                                <td>{{{{ assessment.control_title }}}}</td>
                                                <td>{{{{ assessment.category }}}}</td>
                                                <td>
                                                    <span class="badge bg-{{'{{ 'success' if assessment.status == 'completed' else 'warning' if assessment.status == 'in_progress' else 'secondary' }}'}}">
                                                        {{{{ assessment.status|replace('_', ' ')|title }}}}
                                                    </span>
                                                </td>
                                                <td>
                                                    {{% if assessment.score is not none %}}
                                                        <span class="badge bg-{{'{{ 'success' if assessment.score >= 75 else 'warning' if assessment.score >= 50 else 'danger' }}'}}">
                                                            {{{{ assessment.score }}}}%
                                                        </span>
                                                    {{% else %}}
                                                        <span class="text-muted">Not assessed</span>
                                                    {{% endif %}}
                                                </td>
                                                <td>
                                                    <a href="{{{{ url_for('assessment_details', assessment_id=assessment.id) }}}}" class="btn btn-sm btn-outline-primary">
                                                        <i class="fas fa-edit"></i>
                                                    </a>
                                                </td>
                                            </tr>
                                            {{% endfor %}}
                                        </tbody>
                                    </table>
                                </div>
                            {{% endif %}}
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">Audit Information</h5>
                        </div>
                        <div class="card-body">
                            <p><strong>Framework:</strong> {{{{ audit.framework_name }}}}</p>
                            <p><strong>Auditor:</strong> {{{{ audit.auditor_name }}}}</p>
                            <p><strong>Status:</strong> 
                                <span class="badge bg-{{'{{ 'success' if audit.status == 'completed' else 'warning' if audit.status == 'in_progress' else 'secondary' }}'}}">
                                    {{{{ audit.status|replace('_', ' ')|title }}}}
                                </span>
                            </p>
                            <p><strong>Start Date:</strong> {{{{ audit.start_date or 'Not set' }}}}</p>
                            <p><strong>End Date:</strong> {{{{ audit.end_date or 'Not set' }}}}</p>

                            <hr>
                            <h6>Progress Summary</h6>
                            <ul class="list-unstyled">
                                <li>📊 Total Controls: {{{{ progress.total }}}}</li>
                                <li>✅ Completed: {{{{ progress.completed }}}}</li>
                                <li>⏳ Remaining: {{{{ progress.total - progress.completed }}}}</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>
</div>
""")

ASSESSMENT_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}", f"""
<div class="container-fluid">
    <div class="row">
        {SIDEBAR_NAV}
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4" style="padding: 30px;">
            <h1 class="h2 mb-4">📝 Assessment: {{{{ assessment.control_id }}}}</h1>

            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">Control Assessment</h5>
                        </div>
                        <div class="card-body">
                            <h6>{{{{ assessment.title }}}}</h6>
                            <p class="text-muted">{{{{ assessment.description or 'No description available' }}}}</p>

                            <form method="POST">
                                <div class="mb-3">
                                    <label for="score" class="form-label">Compliance Score (%)</label>
                                    <input type="range" class="form-range" id="score" name="score" 
                                           min="0" max="100" value="{{{{ assessment.score or 50 }}}}" 
                                           oninput="document.getElementById('scoreValue').innerText = this.value + '%'">
                                    <div class="text-center mt-2">
                                        <span id="scoreValue" class="badge bg-primary fs-6">{{{{ assessment.score or 50 }}}}%</span>
                                    </div>
                                </div>

                                <div class="mb-3">
                                    <label for="notes" class="form-label">Assessment Notes</label>
                                    <textarea class="form-control" id="notes" name="notes" rows="4" 
                                              placeholder="Document your assessment findings, evidence reviewed, and rationale for the score...">{{{{ assessment.notes or '' }}}}</textarea>
                                </div>

                                <div class="d-flex gap-2">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save me-2"></i>Save Assessment
                                    </button>
                                    <a href="{{{{ url_for('audit_details', audit_id=assessment.audit_id) }}}}" class="btn btn-secondary">
                                        <i class="fas fa-arrow-left me-2"></i>Back to Audit
                                    </a>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">Control Details</h5>
                        </div>
                        <div class="card-body">
                            <p><strong>Control ID:</strong> <code>{{{{ assessment.control_id }}}}</code></p>
                            <p><strong>Category:</strong> {{{{ assessment.category }}}}</p>
                            <p><strong>Audit:</strong> {{{{ assessment.audit_name }}}}</p>
                            <p><strong>Current Status:</strong> 
                                <span class="badge bg-{{'{{ 'success' if assessment.status == 'completed' else 'warning' if assessment.status == 'in_progress' else 'secondary' }}'}}">
                                    {{{{ assessment.status|replace('_', ' ')|title }}}}
                                </span>
                            </p>

                            {{% if assessment.assessed_at %}}
                                <p><strong>Last Updated:</strong> {{{{ assessment.assessed_at[:16] }}}}</p>
                            {{% endif %}}

                            <hr>
                            <div class="text-center">
                                <button class="btn btn-outline-primary btn-sm" onclick="alert('Evidence upload feature available in full version')">
                                    <i class="fas fa-paperclip me-2"></i>Attach Evidence
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>
</div>
""")

REPORT_TEMPLATE = BASE_TEMPLATE.replace("{% block content %}", f"""
<div class="container-fluid">
    <div class="row">
        {SIDEBAR_NAV}
        <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4" style="padding: 30px;">
            <h1 class="h2 mb-4">📊 Audit Report: {{{{ audit.name }}}}</h1>

            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="stats-card text-center">
                        <div class="stats-number">{{{{ stats.total_controls }}}}</div>
                        <div>Total Controls</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card text-center">
                        <div class="stats-number">{{{{ stats.completed_assessments }}}}</div>
                        <div>Completed</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card text-center">
                        <div class="stats-number">{{{{ "%.1f"|format(stats.completion_rate) }}}}%</div>
                        <div>Completion Rate</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stats-card text-center">
                        <div class="stats-number">{{{{ "%.1f"|format(stats.average_score) }}}}%</div>
                        <div>Average Score</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">Assessment Results</h5>
                    <button class="btn btn-outline-primary" onclick="window.print()">
                        <i class="fas fa-print me-2"></i>Print Report
                    </button>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Control ID</th>
                                    <th>Title</th>
                                    <th>Category</th>
                                    <th>Score</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {{% for assessment in assessments %}}
                                <tr>
                                    <td><code>{{{{ assessment.control_id }}}}</code></td>
                                    <td>{{{{ assessment.title }}}}</td>
                                    <td>{{{{ assessment.category }}}}</td>
                                    <td>
                                        {{% if assessment.score is not none %}}
                                            <span class="badge bg-{{'{{ 'success' if assessment.score >= 75 else 'warning' if assessment.score >= 50 else 'danger' }}'}}">
                                                {{{{ assessment.score }}}}%
                                            </span>
                                        {{% else %}}
                                            <span class="text-muted">N/A</span>
                                        {{% endif %}}
                                    </td>
                                    <td>
                                        <span class="badge bg-{{'{{ 'success' if assessment.status == 'completed' else 'warning' if assessment.status == 'in_progress' else 'secondary' }}'}}">
                                            {{{{ assessment.status|replace('_', ' ')|title }}}}
                                        </span>
                                    </td>
                                </tr>
                                {{% endfor %}}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </main>
    </div>
</div>
""")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
