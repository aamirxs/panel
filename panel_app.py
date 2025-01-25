import os
import subprocess
import time
import psutil
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, Response, flash, jsonify, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import logging
from functools import wraps
from datetime import datetime, timedelta
import json
import socket
from collections import deque
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
import shutil
import zipfile
import sqlite3
import ipaddress

# Add rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Configuration
BASE_DIR = Path(os.getenv('BASE_DIR', Path.home() / 'python-projects'))
LOG_DIR = BASE_DIR / 'logs'
ALLOWED_EXTENSIONS = {'py', 'txt', 'md', 'env', 'sh'}

# Authentication
ADMIN_USER = os.getenv('PANEL_USER')
ADMIN_PASS = generate_password_hash(os.getenv('PANEL_PASS'))

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username != ADMIN_USER:
        return
    user = User()
    user.id = ADMIN_USER
    return user

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Add rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Improved logging
logging.basicConfig(
    filename=str(LOG_DIR / 'app.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Add security middleware
def check_path_traversal(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        path = request.args.get('path', str(BASE_DIR))
        try:
            resolved_path = Path(path).resolve()
            if not str(resolved_path).startswith(str(BASE_DIR)):
                flash('Access denied: Invalid path', 'error')
                return redirect(url_for('dashboard'))
        except Exception:
            flash('Invalid path', 'error')
            return redirect(url_for('dashboard'))
        return func(*args, **kwargs)
    return decorated_function

# Enhanced system stats with error handling
def get_system_stats():
    return {
        'cpu': psutil.cpu_percent(),
        'memory': psutil.virtual_memory().percent,
        'disk': psutil.disk_usage('/').percent
    }

@app.context_processor
def inject_vars():
    return {'stats': get_system_stats()}

# Add historical data storage
cpu_history = deque(maxlen=60)  # Store last 60 data points
memory_history = deque(maxlen=60)
network_history = deque(maxlen=60)

# New system monitoring functions
def get_detailed_system_info():
    try:
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        
        return {
            'hostname': socket.gethostname(),
            'cpu': {
                'usage': psutil.cpu_percent(interval=1),
                'cores': psutil.cpu_count(),
                'freq_current': round(cpu_freq.current, 2) if cpu_freq else 0,
                'freq_max': round(cpu_freq.max, 2) if cpu_freq else 0,
                'temperature': get_cpu_temperature()
            },
            'memory': {
                'total': memory.total,
                'used': memory.used,
                'free': memory.free,
                'percent': memory.percent
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            },
            'processes': len(psutil.pids()),
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        logging.error(f"Error getting system info: {e}")
        return {}

def get_cpu_temperature():
    try:
        temps = psutil.sensors_temperatures()
        if temps and 'coretemp' in temps:
            return round(sum(temp.current for temp in temps['coretemp']) / len(temps['coretemp']), 1)
        return 0
    except:
        return 0

def get_process_list():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
        try:
            pinfo = proc.info
            processes.append({
                'pid': pinfo['pid'],
                'name': pinfo['name'],
                'cpu': round(pinfo['cpu_percent'], 1),
                'memory': round(pinfo['memory_percent'], 1),
                'status': pinfo['status']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return sorted(processes, key=lambda x: x['cpu'], reverse=True)

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USER and check_password_hash(ADMIN_PASS, password):
            user = User()
            user.id = username
            login_user(user)
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/files')
@login_required
def file_manager():
    path = request.args.get('path', str(BASE_DIR))
    try:
        files = []
        parent_dir = os.path.dirname(path)
        for entry in os.listdir(path):
            entry_path = os.path.join(path, entry)
            stats = os.stat(entry_path)
            files.append({
                'name': entry,
                'is_dir': os.path.isdir(entry_path),
                'size': stats.st_size,
                'modified': time.ctime(stats.st_mtime)
            })
        return render_template('file_manager.html', 
                            files=files,
                            current_dir=path,
                            parent_dir=parent_dir)
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    path = request.form.get('path', str(BASE_DIR))
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(path, filename))
    return redirect(url_for('file_manager', path=path))

@app.route('/logs')
@login_required
def log_viewer():
    return render_template('logs.html')

@app.route('/log-stream')
@login_required
def log_stream():
    def generate():
        log_file = BASE_DIR / 'app.log'
        with open(log_file, 'r') as f:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                yield f"data: {line}\n\n"
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(get_system_stats())

@app.route('/system')
@login_required
def system_monitor():
    return render_template('system.html', info=get_detailed_system_info())

@app.route('/processes')
@login_required
def process_manager():
    return render_template('processes.html', processes=get_process_list())

@app.route('/api/process/<int:pid>', methods=['POST'])
@login_required
def manage_process(pid):
    action = request.form.get('action')
    try:
        process = psutil.Process(pid)
        if action == 'stop':
            process.terminate()
        elif action == 'restart':
            process.restart()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/system/history')
@login_required
def system_history():
    return jsonify({
        'cpu': list(cpu_history),
        'memory': list(memory_history),
        'network': list(network_history)
    })

# Configure scheduler
jobstores = {
    'default': SQLAlchemyJobStore(url='sqlite:///jobs.sqlite')
}
scheduler = BackgroundScheduler(jobstores=jobstores)
scheduler.start()

# Backup functionality
def create_backup(name=None):
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = name or f'backup_{timestamp}'
        backup_dir = BASE_DIR / 'backups'
        backup_dir.mkdir(exist_ok=True)
        
        backup_path = backup_dir / f'{backup_name}.zip'
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(BASE_DIR):
                if 'backups' in root:
                    continue
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, str(BASE_DIR))
                    zipf.write(file_path, arcname)
        
        # Cleanup old backups (keep last 5)
        backups = sorted(backup_dir.glob('*.zip'))
        if len(backups) > 5:
            for backup in backups[:-5]:
                backup.unlink()
                
        return True, backup_path.name
    except Exception as e:
        logging.error(f"Backup error: {e}")
        return False, str(e)

# Task scheduling
def execute_task(task_id, command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        with sqlite3.connect('tasks.db') as conn:
            conn.execute('''
                UPDATE tasks 
                SET last_run = ?, status = ?, output = ?
                WHERE id = ?
            ''', (
                datetime.now().isoformat(),
                'success' if result.returncode == 0 else 'failed',
                result.stdout + result.stderr,
                task_id
            ))
            
    except Exception as e:
        logging.error(f"Task execution error: {e}")
        with sqlite3.connect('tasks.db') as conn:
            conn.execute('''
                UPDATE tasks 
                SET last_run = ?, status = ?, output = ?
                WHERE id = ?
            ''', (
                datetime.now().isoformat(),
                'failed',
                str(e),
                task_id
            ))

# New routes
@app.route('/backups')
@login_required
def backup_manager():
    backup_dir = BASE_DIR / 'backups'
    backup_dir.mkdir(exist_ok=True)
    backups = []
    
    for backup in backup_dir.glob('*.zip'):
        stats = backup.stat()
        backups.append({
            'name': backup.name,
            'size': stats.st_size,
            'created': datetime.fromtimestamp(stats.st_ctime)
        })
    
    return render_template('backups.html', backups=sorted(backups, key=lambda x: x['created'], reverse=True))

@app.route('/api/backup', methods=['POST'])
@login_required
def create_backup_api():
    name = request.form.get('name')
    success, message = create_backup(name)
    return jsonify({'success': success, 'message': message})

@app.route('/api/backup/<filename>')
@login_required
def download_backup(filename):
    backup_path = BASE_DIR / 'backups' / filename
    if backup_path.exists():
        return send_file(backup_path, as_attachment=True)
    return 'Backup not found', 404

@app.route('/tasks')
@login_required
def task_manager():
    with sqlite3.connect('tasks.db') as conn:
        conn.row_factory = sqlite3.Row
        tasks = conn.execute('SELECT * FROM tasks ORDER BY created_at DESC').fetchall()
    return render_template('tasks.html', tasks=tasks)

@app.route('/api/task', methods=['POST'])
@login_required
def create_task():
    try:
        name = request.form['name']
        command = request.form['command']
        schedule = request.form['schedule']
        
        with sqlite3.connect('tasks.db') as conn:
            cursor = conn.execute('''
                INSERT INTO tasks (name, command, schedule, created_at)
                VALUES (?, ?, ?, ?)
            ''', (name, command, schedule, datetime.now().isoformat()))
            task_id = cursor.lastrowid
            
        # Add task to scheduler
        scheduler.add_job(
            execute_task,
            'cron',
            args=[task_id, command],
            **parse_schedule(schedule),
            id=f'task_{task_id}'
        )
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def parse_schedule(schedule):
    """Convert user-friendly schedule to cron format"""
    parts = schedule.split()
    if len(parts) == 2:
        value, unit = parts
        value = int(value)
        if unit in ['minutes', 'hours', 'days']:
            if unit == 'minutes':
                return {'minute': f'*/{value}'}
            elif unit == 'hours':
                return {'hour': f'*/{value}'}
            else:
                return {'day': f'*/{value}'}
    return {'minute': '0', 'hour': '0'}  # Default to daily at midnight

# Initialize database
def init_db():
    with sqlite3.connect('tasks.db') as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                command TEXT NOT NULL,
                schedule TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_run TEXT,
                status TEXT,
                output TEXT
            )
        ''')

# Initialize database on startup
init_db()

# Update IP whitelist check
def check_ip_whitelist():
    if os.getenv('ALLOWED_IPS') == '*':
        return True  # Allow all IPs
    allowed_ips = os.getenv('ALLOWED_IPS', '127.0.0.1').split(',')
    client_ip = request.remote_addr
    
    for allowed in allowed_ips:
        if allowed.strip() == '*':
            return True
        if '/' in allowed:  # CIDR notation
            if ipaddress.ip_address(client_ip) in ipaddress.ip_network(allowed.strip()):
                return True
        elif client_ip == allowed.strip():
            return True
    return False

if __name__ == '__main__':
    BASE_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    app.run(host='0.0.0.0', port=5000)