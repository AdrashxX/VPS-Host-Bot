import os
import sys
import subprocess
import shutil
import psutil
import socket
import json
import logging
import re
from datetime import datetime
from config import (
    UPLOAD_DIR, LOG_DIR, INSTALL_TIMEOUT_SECONDS, 
    NODEJS_AVAILABLE, BASE_DIR
)
from database import get_db_connection

logger = logging.getLogger("AdvancedHostingBot")

running_processes = {}
process_monitors = {}

# ===== STREAMING_CHUNK: Designing VPS command terminal executors... =====
# ===== VPS TERMINAL SYSTEM CONTROLLER =====
def execute_vps_shell(command, timeout=30):
    """Execute arbitrary terminal commands on host system safely with timeout rules"""
    try:
        res = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=BASE_DIR
        )
        return {
            "status": "success",
            "code": res.returncode,
            "stdout": res.stdout or "(No stdout output)",
            "stderr": res.stderr or ""
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "code": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds."
        }
    except Exception as e:
        return {
            "status": "error",
            "code": -2,
            "stdout": "",
            "stderr": f"Error initiating host subshell: {str(e)}"
        }

def hot_reboot_bot():
    """Trigger safe hot-restart by executing new binary configuration over active process space"""
    logger.info("⚡ Hot restart initiated. Overwriting current script process space...")
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        logger.error(f"❌ Failed to replace process space: {e}")
        sys.exit(1)

def manage_systemd_unit(service_name, action):
    """Directly start, stop, or restart VPS systemd services using host access rules"""
    allowed_actions = ["start", "stop", "restart", "status"]
    if action not in allowed_actions:
        return False, "Invalid action"
    
    cmd = f"sudo systemctl {action} {service_name}"
    res = execute_vps_shell(cmd, timeout=10)
    
    if res["code"] == 0:
        return True, res["stdout"] if action == "status" else f"Service {service_name} {action}ed successfully."
    else:
        return False, res["stderr"]

# ===== STREAMING_CHUNK: Managing isolated system workspaces... =====
# ===== FILE & ENVIRONMENT SETUP =====
def user_folder(uid):
    path = os.path.join(UPLOAD_DIR, str(uid))
    os.makedirs(path, exist_ok=True)
    return path

def project_folder(uid, project_name):
    path = os.path.join(user_folder(uid), project_name)
    os.makedirs(path, exist_ok=True)
    return path

def create_sandbox_environment(project_path, env_vars_dict=None):
    """Generate isolation bounds for code security execution parameters"""
    try:
        os.makedirs(os.path.join(project_path, 'logs'), exist_ok=True)
        os.makedirs(os.path.join(project_path, 'temp'), exist_ok=True)
        os.chmod(project_path, 0o755)
        
        gitignore_content = "# Auto-generated Sandbox Isolation\n.env\n*.log\ntemp/\n__pycache__/\nnode_modules/\n*.pyc\n"
        with open(os.path.join(project_path, '.gitignore'), 'w') as f:
            f.write(gitignore_content)
            
        # Write .env variables file inside service sandbox
        if env_vars_dict:
            env_file_path = os.path.join(project_path, '.env')
            with open(env_file_path, 'w') as ef:
                for k, v in env_vars_dict.items():
                    ef.write(f"{k}={v}\n")
            
        logger.info(f"✅ Sandbox environment created for {project_path}")
        return True
    except Exception as e:
        logger.error(f"❌ Sandbox creation failed: {e}")
        return False

# ===== STREAMING_CHUNK: Running dynamic host network bindings... =====
# ===== PORT RESOLUTION =====
def find_available_port(start_port=8000, max_attempts=100):
    """Find a secure bindable local port for micro-service web apps"""
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return None

# ===== STREAMING_CHUNK: Running live service execution checks... =====
# ===== PROCESS CHECKS =====
def is_running(project_id):
    """Check if process is active in systems manager"""
    if project_id in running_processes:
        pid = running_processes[project_id]
        return psutil.pid_exists(pid)
    return False

def get_process_info(project_id):
    """Obtain system-level hardware consumption statistics for active deployments"""
    if project_id not in running_processes:
        return None
    try:
        pid = running_processes[project_id]
        process = psutil.Process(pid)
        return {
            'pid': pid,
            'status': process.status(),
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'memory_mb': process.memory_info().rss / 1024 / 1024,
            'create_time': process.create_time(),
            'num_threads': process.num_threads()
        }
    except psutil.NoSuchProcess:
        return None

def stop_process(project_id):
    """Terminate parent process loops along with all nested children trees safely"""
    if project_id not in running_processes:
        return False
    
    pid = running_processes.pop(project_id)
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        
        for child in children:
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        
        gone, alive = psutil.wait_procs(children, timeout=5)
        for p in alive:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
                
        parent.terminate()
        parent.wait(timeout=5)
        
        logger.info(f"✅ Process {project_id} (PID: {pid}) stopped successfully")
        
        with get_db_connection() as conn:
            conn.execute("UPDATE projects SET status = 'stopped' WHERE id = ?", (project_id,))
            conn.execute("DELETE FROM process_monitoring WHERE project_id = ?", (project_id,))
            conn.commit()
        return True
    except psutil.NoSuchProcess:
        logger.warning(f"⚠️ Process {project_id} (PID: {pid}) already terminated in-system")
        return True
    except Exception as e:
        logger.error(f"❌ Error stopping process {project_id}: {e}")
        return False

# ===== STREAMING_CHUNK: Scanning project directories for descriptors... =====
# ===== RECURSIVE METADATA EXTRACTION =====
def find_main_file(directory):
    """Heuristic directory lookup logic searching prioritised executable entrypoints"""
    priority_files = [
        "main.py", "bot.py", "app.py", "server.py", "run.py", "start.py",
        "index.js", "server.js", "app.js", "bot.js", "main.js", "start.js",
        "main.ts", "server.ts", "app.ts", "bot.ts", "index.ts",
        "main.go", "main.rs", "main.java", "index.php", "manage.py"
    ]
    
    for fname in priority_files:
        if os.path.exists(os.path.join(directory, fname)):
            return fname
            
    if os.path.exists(os.path.join(directory, "package.json")):
        try:
            with open(os.path.join(directory, "package.json"), 'r') as f:
                pdata = json.load(f)
                if 'main' in pdata and os.path.exists(os.path.join(directory, pdata['main'])):
                    return pdata['main']
                elif 'scripts' in pdata and 'start' in pdata['scripts']:
                    script_val = pdata['scripts']['start']
                    match = re.search(r'node\s+(\S+)', script_val)
                    if match and os.path.exists(os.path.join(directory, match.group(1))):
                        return match.group(1)
        except Exception:
            pass
            
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file in priority_files:
                return os.path.relpath(os.path.join(root, file), directory)
                
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith((".py", ".js", ".ts")):
                return os.path.relpath(os.path.join(root, file), directory)
    return None

def find_requirements_txt(directory):
    for root, dirs, files in os.walk(directory):
        if "requirements.txt" in files:
            return os.path.join(root, "requirements.txt")
    return None

def detect_project_type(directory, main_file):
    types = set()
    try:
        if main_file:
            m_path = os.path.join(directory, main_file)
            if os.path.exists(m_path):
                with open(m_path, 'r', encoding='utf-8', errors='ignore') as f:
                    src = f.read().lower()
                    if 'telegram' in src or 'telebot' in src: types.add('telegram')
                    if 'discord' in src: types.add('discord')
                    if 'flask' in src: types.add('flask')
                    if 'fastapi' in src: types.add('fastapi')
                    if 'express' in src: types.add('express')
                    if 'django' in src: types.add('django')
                    
        if os.path.exists(os.path.join(directory, 'package.json')): types.add('nodejs')
        if find_requirements_txt(directory): types.add('python')
    except Exception as e:
        logger.warning(f"⚠️ Project framework checking alert: {e}")
    return list(types)

# ===== STREAMING_CHUNK: Installing code library dependencies... =====
def install_dependencies(project_dir, framework):
    """Setup safe installer shells isolating and writing run configuration reports"""
    report = f"Dependency Installation Report\nProject: {os.path.basename(project_dir)}\nTimestamp: {datetime.now()}\n\n"
    req_file = find_requirements_txt(project_dir)
    
    if req_file and framework.lower() in ['python', 'telegram-bot', 'discord-bot', 'flask', 'fastapi', 'django']:
        try:
            with open(req_file, 'r') as f:
                pkgs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            report += f"Processing requirements: {len(pkgs)} packages identified\n"
        except Exception as e:
            return False, f"Requirements parsing error: {e}"
            
        try:
            cmd = [sys.executable, "-m", "pip", "install", "-r", req_file]
            res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=INSTALL_TIMEOUT_SECONDS)
            return True, "Python dependencies fully configured"
        except Exception:
            try:
                cmd = ["pip3", "install", "-r", req_file]
                res = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=INSTALL_TIMEOUT_SECONDS)
                return True, "Python dependencies loaded via pip3 backup"
            except Exception as e:
                report += f"Installer failures: {e}\n"
                return False, f"Failed deployment build pipeline: {str(e)[:250]}"
                
    package_file = None
    for root, dirs, files in os.walk(project_dir):
        if 'package.json' in files:
            package_file = os.path.join(root, 'package.json')
            break
            
    if package_file and framework.lower() in ['node.js', 'nodejs']:
        if not NODEJS_AVAILABLE:
            return False, "Required Node.js engine is absent on target VPS"
        try:
            cmd = ["npm", "install"]
            subprocess.run(cmd, cwd=os.path.dirname(package_file), check=True, capture_output=True, text=True, timeout=INSTALL_TIMEOUT_SECONDS)
            return True, "npm packages resolved successfully"
        except Exception as e:
            return False, f"npm install error: {str(e)[:250]}"
            
    return True, "No package descriptors identified"
