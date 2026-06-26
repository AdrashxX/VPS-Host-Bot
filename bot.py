import os
import sys
import threading
import time
import asyncio
import io
import html
import shutil
import zipfile
import re
import json
import sqlite3
import urllib.request
import urllib.parse
import http.client
import http.server
import socketserver
import base64
from datetime import datetime, timedelta
import psutil
import subprocess

# Safe dynamic guard checking and installing of core library dependencies
try:
    from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
    from telegram.constants import ParseMode
    from telegram.error import BadRequest, Conflict, InvalidToken, NetworkError
    from telegram.request import HTTPXRequest
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "python-telegram-bot==20.7"], check=True)
    from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
    from telegram.constants import ParseMode
    from telegram.error import BadRequest, Conflict, InvalidToken, NetworkError
    from telegram.request import HTTPXRequest

# Internal imports from modular structures
from config import (
    BOT_TOKEN, OWNER_ID, OWNER_USERNAME, LOG_DIR, TEMP_DIR,
    MAX_FILE_SIZE, MAX_FILE_SIZE_MB, NODEJS_AVAILABLE, 
    PYTHON_VERSIONS, check_single_instance, setup_advanced_logging, BASE_DIR
)
from database import (
    init_advanced_database, get_db_connection, has_access, is_admin,
    get_user_limit, get_regular_project_count
)
from process_manager import (
    running_processes, is_running, get_process_info, stop_process,
    project_folder, create_sandbox_environment, find_available_port,
    find_main_file, find_requirements_txt, detect_project_type,
    execute_vps_shell, hot_reboot_bot, manage_systemd_unit
)

logger = setup_advanced_logging()

# User navigation tracking states
user_states = {}
broadcast_states = {}

# Cached Public IP Address of VPS
VPS_PUBLIC_IP = "YOUR_VPS_IP"

# Web Dashboard Session Tokens Storage
# Schema: { token: { "user_id": int, "expires": datetime, "username": str } }
dashboard_tokens = {}
WEB_DASHBOARD_PORT = 9999

def resolve_vps_public_ip():
    """Detect and cache the public IP address of the VPS for building API endpoints"""
    global VPS_PUBLIC_IP
    try:
        # Fast remote resolution using standard utility
        req = urllib.request.Request("https://api.ipify.org", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            VPS_PUBLIC_IP = response.read().decode('utf-8').strip()
            logger.info(f"🌍 VPS Network Routing Active. Resolved Public IP: {VPS_PUBLIC_IP}")
    except Exception as e:
        logger.warning(f"⚠️ Remote IP resolution failed: {e}. Attempting local interface fallback...")
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            VPS_PUBLIC_IP = s.getsockname()[0]
            s.close()
            logger.info(f"🌍 Fallback Local IP interface detected: {VPS_PUBLIC_IP}")
        except Exception:
            VPS_PUBLIC_IP = "127.0.0.1"

def generate_dashboard_token(user_id, username):
    """Generate a high-entropy short-lived authentication token for web console access"""
    import secrets
    token = secrets.token_hex(24)
    expiry = datetime.now() + timedelta(minutes=30)
    dashboard_tokens[token] = {
        "user_id": user_id,
        "username": username or f"Client_{user_id}",
        "expires": expiry
    }
    # Periodically clean up expired tokens to save memory
    expired = [t for t, d in dashboard_tokens.items() if d["expires"] < datetime.now()]
    for t in expired:
        dashboard_tokens.pop(t, None)
    return token

# ===== DATABASE STRUCTURAL MIGRATION SAFEGUARDS =====
def apply_schema_migrations():
    """Ensure database schema matches the advanced environment variables and settings requirements"""
    try:
        with get_db_connection() as conn:
            # Migration 1: env_vars column
            try:
                conn.execute("ALTER TABLE projects ADD COLUMN env_vars TEXT DEFAULT '{}'")
            except sqlite3.OperationalError:
                pass  # Already exists
                
            # Migration 2: Discovered services supervision table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discovered_services (
                    pid INTEGER PRIMARY KEY,
                    name TEXT,
                    cmdline TEXT,
                    reason TEXT,
                    ports TEXT,
                    status TEXT DEFAULT 'running',
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            logger.info("🗄️ Database migrations and schema checks executed successfully.")
    except Exception as e:
        logger.error(f"⚠️ Non-critical schema migration check warning: {e}")

# ===== STATIC ANALYSIS IMPORT PARSERS (AUTO-PREVENT CRASHES) =====
def parse_python_imports(p_dir):
    """Scan all Python files in the workspace and identify missing third-party packages to install"""
    std_libs = {
        "os", "sys", "time", "re", "math", "random", "json", "sqlite3", "asyncio", "logging", 
        "datetime", "shutil", "urllib", "hashlib", "socket", "threading", "glob", "pathlib", 
        "uuid", "inspect", "base64", "io", "collections", "ctypes", "platform", "traceback", 
        "atexit", "select", "struct", "abc", "contextlib", "subprocess", "typing", "functools", 
        "itertools", "pickle", "weakref", "tempfile", "signal", "errno", "xml", "csv", 
        "argparse", "getopt", "http", "socketserver", "configparser", "pdb", "timeit", 
        "multiprocessing", "queue", "concurrent", "uuid"
    }
    pip_mappings = {
        "telegram": "python-telegram-bot",
        "telebot": "pyTelegramBotAPI",
        "discord": "discord.py",
        "bs4": "beautifulsoup4",
        "dotenv": "python-dotenv",
        "PIL": "Pillow",
        "yaml": "PyYAML",
        "mysql": "mysql-connector-python",
        "fitz": "PyMuPDF",
        "requests": "requests",
        "aiogram": "aiogram",
        "pyrogram": "pyrogram",
        "pyromod": "pyromod",
        "flask": "flask",
        "fastapi": "fastapi",
        "django": "django",
        "uvicorn": "uvicorn"
    }
    detected = set()
    import_pattern = re.compile(r'^\s*(?:import|from)\s+([a-zA-Z0-9_]+)')
    
    for root, _, files in os.walk(p_dir):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            match = import_pattern.match(line)
                            if match:
                                module = match.group(1)
                                if module not in std_libs:
                                    pkg = pip_mappings.get(module, module.lower())
                                    detected.add(pkg)
                except Exception as e:
                    logger.error(f"Error parsing python imports in {file_path}: {e}")
    return list(detected)

def parse_nodejs_imports(p_dir):
    """Scan Node.js project directory for require and ES6 ES import statements"""
    std_nodes = {
        "fs", "path", "http", "https", "crypto", "os", "util", "events", "child_process", 
        "querystring", "url", "stream", "dns", "zlib", "readline", "net", "tls", "assert", 
        "cluster", "dgram", "vm", "v8"
    }
    detected = set()
    require_pattern = re.compile(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)')
    import_pattern = re.compile(r'from\s+[\'"]([^\'"]+)[\'"]')
    import_direct_pattern = re.compile(r'import\s+[\'"]([^\'"]+)[\'"]')
    
    for root, _, files in os.walk(p_dir):
        if "node_modules" in root:
            continue
        for file in files:
            if file.endswith(('.js', '.ts', '.mjs')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            # match require
                            for match in require_pattern.finditer(line):
                                pkg = match.group(1)
                                if not pkg.startswith(('.', '/')) and pkg not in std_nodes:
                                    top_pkg = pkg.split('/')[0] if not pkg.startswith('@') else '/'.join(pkg.split('/')[:2])
                                    detected.add(top_pkg)
                            # match imports
                            for match in import_pattern.finditer(line):
                                pkg = match.group(1)
                                if not pkg.startswith(('.', '/')) and pkg not in std_nodes:
                                    top_pkg = pkg.split('/')[0] if not pkg.startswith('@') else '/'.join(pkg.split('/')[:2])
                                    detected.add(top_pkg)
                            for match in import_direct_pattern.finditer(line):
                                pkg = match.group(1)
                                if not pkg.startswith(('.', '/')) and pkg not in std_nodes:
                                    top_pkg = pkg.split('/')[0] if not pkg.startswith('@') else '/'.join(pkg.split('/')[:2])
                                    detected.add(top_pkg)
                except Exception as e:
                    logger.error(f"Error parsing node imports in {file_path}: {e}")
    return list(detected)

def parse_requirements_txt_packages(req_file_path):
    """Parse requirements.txt to collect listed packages for exclusion from dynamic installation"""
    packages = set()
    if os.path.exists(req_file_path):
        try:
            with open(req_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        match = re.match(r'^([a-zA-Z0-9_\-]+)', line)
                        if match:
                            pkg_name = match.group(1).lower().replace('_', '-')
                            packages.add(pkg_name)
        except Exception as e:
            logger.error(f"Error parsing requirements.txt: {e}")
    return packages

def parse_package_json_packages(package_json_path):
    """Parse package.json to collect listed dependencies for exclusion from dynamic installation"""
    packages = set()
    if os.path.exists(package_json_path):
        try:
            with open(package_json_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                    if dep_type in data:
                        for pkg in data[dep_type].keys():
                            packages.add(pkg.lower())
        except Exception as e:
            logger.error(f"Error parsing package.json: {e}")
    return packages

# ===== AUTO-PROVISION SYSTEM DEPENDENCIES (PHP, NPM, ETC) =====
async def run_auto_provisioner_async(bot_obj: Bot):
    """Checks the host VPS for node, npm, php, composer, and installs missing packages in background natively"""
    await asyncio.sleep(5)  # Wait for polling server to start up cleanly
    missing = []
    
    # Checking executable presence
    if shutil.which("node") is None or shutil.which("npm") is None:
        missing.append("nodejs")
        missing.append("npm")
    if shutil.which("php") is None:
        missing.append("php")
        missing.append("php-cli")
    if shutil.which("composer") is None:
        missing.append("composer")
    if shutil.which("unzip") is None:
        missing.append("unzip")
        
    if not missing:
        logger.info("✅ All essential system compilers and web engines present on host.")
        return

    # Notify Owner HmGamer that system provisioning has started natively
    try:
        await bot_obj.send_message(
            OWNER_ID,
            f"⚙️ <b>VPS AUTO-PROVISIONER INITIATED</b>\n\n"
            f"The system detected missing dependencies on your VPS: <code>{', '.join(missing)}</code>.\n"
            f"⏳ Installing components via apt-get in the background...",
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        logger.error(f"Failed to alert owner of provisioning: {e}")

    try:
        # Upgrade package index using asynchronous thread delegation (prevents freezing polling loop)
        await asyncio.to_thread(subprocess.run, ["sudo", "apt-get", "update", "-y"], capture_output=True, check=True)
        
        # Install NodeSource repositories if nodejs is missing
        if "nodejs" in missing:
            await asyncio.to_thread(subprocess.run, "curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -", shell=True, check=True)
            
        # Direct installations
        install_cmd = ["sudo", "apt-get", "install", "-y", "unzip", "sqlite3"]
        if "nodejs" in missing:
            install_cmd.extend(["nodejs"])
        if "php" in missing:
            install_cmd.extend(["php", "php-cli", "php-mbstring"])
            
        await asyncio.to_thread(subprocess.run, install_cmd, capture_output=True, check=True)
        
        # Auto install PHP composer if missing
        if "composer" in missing:
            setup_composer_cmd = "curl -sS https://getcomposer.org/installer | php && sudo mv composer.phar /usr/local/bin/composer"
            await asyncio.to_thread(subprocess.run, setup_composer_cmd, shell=True, check=True)

        # Reload environment variable detections
        global NODEJS_AVAILABLE
        from config import check_nodejs_installation
        NODEJS_AVAILABLE = check_nodejs_installation()

        await bot_obj.send_message(
            OWNER_ID,
            f"✅ <b>VPS AUTO-PROVISIONING COMPLETE</b>\n\n"
            f"All requested components (NodeJS, PHP, Composer, SQLite, Unzip) are now installed and ready to use!",
            parse_mode=ParseMode.HTML
        )
        logger.info("✅ System provisioning complete.")
    except Exception as e:
        logger.error(f"Failed during background auto-provisioning: {e}")
        try:
            await bot_obj.send_message(
                OWNER_ID,
                f"❌ <b>VPS PROVISIONING EXCEPTION CRASH</b>\n\n"
                f"Error encountered: <code>{html.escape(str(e))}</code>",
                parse_mode=ParseMode.HTML
            )
        except:
            pass

# ===== VPS ACTIVE PORTS & PROCESS SCANNER (FOREIGN BOTS/APIs) =====
def scan_vps_for_foreign_services():
    """Scans all active processes for external bots or web APIs, saving metadata to the database"""
    discovered_projects = []
    try:
        # Get our own script PID to ignore it
        self_pid = os.getpid()
        
        # Retrieve all currently running bot PIDs
        registered_pids = set(running_processes.values())
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd']):
            try:
                pid = proc.pid
                if pid == self_pid or pid in registered_pids:
                    continue
                    
                cmdline = proc.info['cmdline']
                if not cmdline:
                    continue
                    
                cmd_str = " ".join(cmdline).lower()
                cwd = proc.info['cwd'] or "Unknown"
                
                is_foreign = False
                reason = ""
                framework = "Unknown"
                
                # Heuristic scanning signatures for Bots and Web APIs
                if any(x in cmd_str for x in ["bot.py", "telebot", "discord", "aiogram", "pyrogram", "telegraf", "discord.js", "node-telegram-bot-api"]):
                    is_foreign = True
                    reason = "Foreign Bot Service"
                    framework = "Node.js" if "node" in cmd_str else "Python"
                elif any(x in cmd_str for x in ["uvicorn", "gunicorn", "flask", "fastapi", "django", "express", "nodemon", "pm2", "php -s"]):
                    is_foreign = True
                    reason = "Web API Server"
                    framework = "PHP" if "php" in cmd_str else "Node.js" if "node" in cmd_str else "Python"
                elif ("python" in cmd_str or "node" in cmd_str or "php" in cmd_str) and any(x in cmd_str for x in ["api", "server", "app", "main"]):
                    is_foreign = True
                    reason = "Generic Executable"
                    framework = "PHP" if "php" in cmd_str else "Node.js" if "node" in cmd_str else "Python"

                if is_foreign:
                    # Attempt to fetch network listening port
                    ports = []
                    try:
                        connections = proc.connections(kind='inet')
                        for conn in connections:
                            if conn.status == 'LISTEN':
                                ports.append(str(conn.laddr.port))
                    except Exception:
                        pass
                        
                    ports_str = ",".join(ports) if ports else "N/A"
                    
                    # Store safely in databases
                    with get_db_connection() as conn:
                        conn.execute("""
                            INSERT OR REPLACE INTO process_monitoring (project_id, pid, start_time, cpu_usage, memory_usage)
                            VALUES (?, ?, CURRENT_TIMESTAMP, 0, 0)
                        """, (99000 + pid, pid)) # Use highly spaced custom project IDs for raw system tasks
                        
                    discovered_project = {
                        "id": 900000 + pid, # Safe out-of-bounds database ID allocation
                        "user_id": OWNER_ID,
                        "project_name": f"SYSTEM_PROC_{pid}_{proj_clean_name(proc.info['name'])}",
                        "main_file": cmdline[-1] if len(cmdline) > 0 else "Unknown",
                        "framework": f"External ({framework})",
                        "project_type": reason,
                        "port": ports[0] if ports else None,
                        "status": "running",
                        "real_pid": pid,
                        "cwd": cwd,
                        "cmdline": " ".join(cmdline)
                    }
                    discovered_projects.append(discovered_project)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as e:
        logger.error(f"Host VPS security scanning encountered an issue: {e}")
    return discovered_projects

def proj_clean_name(val):
    return re.sub(r'[^a-zA-Z0-9_-]', '', val)[:15]

# ===== GENERAL HELPER UI FUNCTIONS =====
def get_performance_color(percent):
    if percent < 50: return "🟢"
    elif percent < 80: return "🟡"
    return "🔴"

def get_display_username(user):
    try:
        if hasattr(user, 'username') and user.username:
            return f"@{user.username}"
        elif isinstance(user, dict) and user.get('username'):
            return f"@{user['username']}"
        return "N/A"
    except Exception:
        return "N/A"

async def send_response(update: Update, text: str, reply_markup=None, parse_mode=ParseMode.HTML):
    try:
        if update.callback_query:
            if reply_markup:
                await update.callback_query.edit_message_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
            else:
                await update.callback_query.edit_message_text(text, parse_mode=parse_mode)
        else:
            await update.message.reply_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
    except BadRequest as e:
        if "Message is not modified" not in str(e):
            raise e

# ===== TELEGRAM COMMAND ROUTINES =====
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = update.effective_user.username
    username_display = get_display_username(update.effective_user)

    with get_db_connection() as conn:
        existing_user = conn.execute("SELECT user_id FROM users WHERE user_id = ?", (user_id,)).fetchone()
        is_new = existing_user is None
        
        limit_val = -1 if user_id == OWNER_ID else 0
        conn.execute("""
            INSERT INTO users (user_id, username, last_active, file_limit) 
            VALUES (?, ?, CURRENT_TIMESTAMP, ?)
            ON CONFLICT(user_id) DO UPDATE SET 
                username = excluded.username,
                last_active = CURRENT_TIMESTAMP
        """, (user_id, username, limit_val))
        conn.commit()
        
        if is_new and user_id != OWNER_ID:
            try:
                alert = (
                    f"🚨 <b>UNAUTHORIZED REGISTRATION ALERT</b>\n\n"
                    f"👤 User: {username_display}\n"
                    f"🆔 ID: <code>{user_id}</code>\n"
                    f"Whitelist: <code>/limit {user_id} [limit]</code>"
                )
                await context.bot.send_message(OWNER_ID, alert, parse_mode=ParseMode.HTML)
            except Exception as e:
                logger.error(f"Owner notification failure: {e}")

    buttons = [
        ["🚀 HOST BOT", "📊 MY PROJECTS"],
        ["🖥️ VPS CONTROLS", "⚙️ SELF-MGMT"],
        ["📢 BROADCAST", "📋 BOT LOGS"],
        ["🖥️ SYSTEM STATUS", "👥 USER MANAGEMENT"],
        ["🖥️ WEB DASHBOARD", "🧹 CLEAR LOGS"]
    ] if is_admin(user_id) else [
        ["🚀 HOST BOT", "📊 MY PROJECTS"],
        ["🖥️ WEB DASHBOARD"]
    ]
    
    kb = ReplyKeyboardMarkup(buttons, resize_keyboard=True)
    promo = (
        f"😈 <b>VPS ORCHESTRATOR & SERVICE MASTER</b>\n"
        f"─────────────────────────────\n"
        f"⚡ <b>Enterprise Capabilities Enabled:</b>\n"
        f"• Isolated execution sandboxes\n"
        f"• Live process supervisors & API binding\n"
        f"• Dynamic terminal command ports\n"
        f"• Support: Python, Node.js, PHP, HTML\n"
        f"• Automated cluster state recovery\n"
        f"• 🖥️ Premium Web Controller Panel Included\n\n"
        f"🔒 Whitelisted Administrators Only\n"
        f"👤 Developer: HmGamer (@EliteHM)"
    )
            
    await update.message.reply_text(promo, parse_mode=ParseMode.HTML)
    
    if not has_access(user_id):
        await update.message.reply_text(
            f"❌ <b>Access Denied</b>\n"
            f"Your account must be whitelisted by @EliteHM.\n"
            f"🆔 Your ID: <code>{user_id}</code>",
            reply_markup=kb, parse_mode=ParseMode.HTML
        )
        return

    welcome = (
        f"📊 <b>VPS HOSTING DASHBOARD ACTIVE</b>\n"
        f"─────────────────────────────\n"
        f"Welcome back, <b>{username_display}</b>!\n\n"
        f"📈 <b>Class Allocation Parameters:</b>\n"
        f"• Account Limit: <code>{get_user_limit(user_id)}</code>\n"
        f"• Authorization Level: <code>{'👑 Owner' if user_id == OWNER_ID else '🔧 Admin' if is_admin(user_id) else '✅ Premium Client'}</code>\n"
        f"• Web Dashboard Port: <code>{WEB_DASHBOARD_PORT}</code>"
    )
              
    await update.message.reply_text(welcome, reply_markup=kb, parse_mode=ParseMode.HTML)

async def bot_host_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not has_access(user_id):
        await update.message.reply_text("❌ Access Denied. Contact Admin.", parse_mode=ParseMode.HTML)
        return
        
    with get_db_connection() as conn:
        user = conn.execute("SELECT file_limit FROM users WHERE user_id = ?", (user_id,)).fetchone()
        regular_count = get_regular_project_count(user_id)
        
    if user and user['file_limit'] != -1 and regular_count >= user['file_limit']:
        await update.message.reply_text(f"❌ <b>Deployment limit reached!</b> Limit: {user['file_limit']}", parse_mode=ParseMode.HTML)
        return
        
    user_states[user_id] = {"awaiting_zip": True, "hosting_type": "zip"}
    
    py_versions = "".join([f"• {k}: ✅ {v}\n" for k, v in PYTHON_VERSIONS.items()])
    nodejs_info = "✅ System Engine Active" if NODEJS_AVAILABLE else "❌ Missing dependency"
    
    await update.message.reply_text(
        f"🚀 <b>VPS ENVIRONMENT DEPLOYMENT MANAGER</b>\n"
        f"─────────────────────────────\n"
        f"Please upload your code as a single script file (<code>.py</code>, <code>.js</code>, <code>.php</code>, <code>.html</code>) or a packaged <code>.zip</code> archive.\n\n"
        f"📋 <b>Deployment Architectures:</b>\n"
        f"• <b>Python</b>: main.py/bot.py + requirements\n"
        f"• <b>Node.js</b>: index.js/main.js + package.json\n"
        f"• <b>PHP</b>: Direct Web-daemon or CLI worker\n"
        f"• <b>Static HTML</b>: Deployed automatically\n\n"
        f"💡 <i>Web APIs (FastAPI, Flask, Express, etc.) will automatically bind to a live VPS port.</i>\n\n"
        f"⚙️ Supported Runtimes:\n"
        f"{py_versions}"
        f"• Node.js: {nodejs_info}\n\n"
        f"📤 <b>Send your ZIP or code file now:</b>",
        parse_mode=ParseMode.HTML
    )

# ===== CONSOLE-DRIVEN MY PROJECTS UI =====
async def list_bots_command(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 1):
    user_id = update.effective_user.id
    if not has_access(user_id):
        await send_response(update, "❌ Access Denied")
        return
        
    is_admin_flag = is_admin(user_id)
    PER_PAGE = 8  # Mobile-optimized rows
    
    with get_db_connection() as conn:
        if is_admin_flag:
            total_count = conn.execute("SELECT COUNT(*) as count FROM projects").fetchone()['count']
            projects = conn.execute("""
                SELECT id, project_name, framework, status FROM projects 
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (PER_PAGE, (page-1)*PER_PAGE)).fetchall()
        else:
            total_count = conn.execute("SELECT COUNT(*) as count FROM projects WHERE user_id = ?", (user_id,)).fetchone()['count']
            projects = conn.execute("""
                SELECT id, project_name, framework, status FROM projects 
                WHERE user_id = ? 
                ORDER BY created_at DESC LIMIT ? OFFSET ?
            """, (user_id, PER_PAGE, (page-1)*PER_PAGE)).fetchall()

    total_pages = max(1, (total_count + PER_PAGE - 1) // PER_PAGE)
    if not projects and page == 1:
        await send_response(
            update, 
            f"📁 <b>BOT PORTFOLIO MANAGER</b>\n"
            f"─────────────────────────────\n"
            f"Account limit: <code>{get_user_limit(user_id)}</code>\n"
            f"Deployments: <code>0</code>\n\n"
            f"🚀 Press <b>'HOST BOT'</b> to deploy codes."
        )
        return

    header = f"👑 <b>ADMIN SYSTEM CONSOLE BOARD</b>" if is_admin_flag else f"📁 <b>YOUR DEPLOYED SERVICES</b>"
    text = (
        f"{header}\n"
        f"─────────────────────────────\n"
        f"Select a service workspace below to access its console, change environments, or manage APIs:\n\n"
    )
    
    buttons = []
    for p in projects:
        running = is_running(p['id'])
        status_emoji = "🟢" if running else "🔴"
        label = f"{status_emoji} {p['project_name']} [{p['framework']}]"
        buttons.append([InlineKeyboardButton(label, callback_data=f"viewproj_{p['id']}")])
        
    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"portfolio_page_{page-1}"))
    nav.append(InlineKeyboardButton(f"📄 {page}/{total_pages}", callback_data="current"))
    if page < total_pages:
        nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"portfolio_page_{page+1}"))
    buttons.append(nav)
    
    buttons.append([InlineKeyboardButton("🔄 REFRESH PORTFOLIO", callback_data="refresh_projects")])
    
    if is_admin_flag:
        buttons.append([InlineKeyboardButton("🔍 VPS SECURITY PROCESS SCAN", callback_data="sys_scan_proc")])
        
    await send_response(update, text, reply_markup=InlineKeyboardMarkup(buttons))

async def show_project_console(update: Update, context: ContextTypes.DEFAULT_TYPE, project_id: int):
    """Render a dedicated cloud control panel dashboard for individual projects"""
    user_id = update.effective_user.id if update.effective_user else update.callback_query.from_user.id
    
    with get_db_connection() as conn:
        proj_row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj_row:
        await send_response(update, "❌ Project not found.")
        return
        
    proj = dict(proj_row)
    if not is_admin(user_id) and proj['user_id'] != user_id:
        await send_response(update, "❌ Authorization signature invalid.")
        return
        
    running = is_running(project_id)
    status_label = "🟢 ACTIVE" if running else "🔴 OFFLINE"
    
    stats_text = ""
    if running:
        info = get_process_info(project_id)
        if info:
            stats_text = (
                f"📈 <b>Resource Allotment:</b>\n"
                f"• CPU Load: <code>{info['cpu_percent']:.1f}%</code>\n"
                f"• Memory RSS: <code>{info['memory_mb']:.1f} MB</code>\n"
                f"• Target PID: <code>{info['pid']}</code>\n"
            )
                         
    # Render API routing parameters if port configured
    api_endpoint_text = ""
    if proj['port']:
        api_endpoint_text = f"🌐 <b>API Route:</b> <code>http://{VPS_PUBLIC_IP}:{proj['port']}</code>\n"
    else:
        api_endpoint_text = f"🌐 <b>API Route:</b> <code>Inactive/No Port Bound</code>\n"
        
    console_view = (
        f"📦 <b>CLOUD WORKSPACE CONSOLE</b>\n"
        f"─────────────────────────────\n"
        f"• Service: <b>{proj['project_name']}</b>\n"
        f"• Status: <b>{status_label}</b>\n"
        f"• Architecture: <code>{proj['framework']}</code>\n"
        f"{api_endpoint_text}"
        f"• Last Booted: <code>{proj['last_started'] or 'Never'}</code>\n\n"
        f"{stats_text}"
        f"─────────────────────────────\n"
        f"👉 <b>Choose Console Operation:</b>"
    )
    
    # Restructured clean layout optimized for mobile screens (maximum 2 buttons per row)
    buttons = [
        [
            InlineKeyboardButton("⏹️ STOP PROCESS" if running else "▶️ BOOT WORKER", callback_data=f"pstate_{project_id}"),
            InlineKeyboardButton("🔐 ENV VARS", callback_data=f"p_env_{project_id}")
        ],
        [
            InlineKeyboardButton("💻 WORKSPACE CLI", callback_data=f"p_cli_{project_id}"),
            InlineKeyboardButton("📋 RUNNER LOGS", callback_data=f"p_logs_{project_id}")
        ],
        [
            InlineKeyboardButton("📦 PKG MANAGER", callback_data=f"p_pkg_{project_id}"),
            InlineKeyboardButton("🌐 PORT / API BIND", callback_data=f"p_api_bind_{project_id}")
        ],
        [
            InlineKeyboardButton("🧹 DEPS REBUILD", callback_data=f"p_build_{project_id}"),
            InlineKeyboardButton("🗑️ PURGE WORKSPACE", callback_data=f"p_purge_{project_id}")
        ],
        [InlineKeyboardButton("🔙 RETURN TO PORTFOLIO", callback_data="refresh_projects")]
    ]
    
    await send_response(update, console_view, reply_markup=InlineKeyboardMarkup(buttons))

async def run_internal_api_ping(port):
    """Diagnose HTTP endpoint bind internally using python standard libraries"""
    start_time = time.time()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
        conn.request("GET", "/")
        resp = conn.getresponse()
        latency = (time.time() - start_time) * 1000
        status = resp.status
        headers = dict(resp.getheaders())
        server_engine = headers.get("Server", headers.get("server", "Python/Node Web Application"))
        conn.close()
        
        return (
            f"✅ <b>API ENDPOINT TEST SUCCESSFUL!</b>\n"
            f"─────────────────────────────\n"
            f"• <b>Status Code:</b> <code>{status}</code>\n"
            f"• <b>Round-Trip Latency:</b> <code>{latency:.1f} ms</code>\n"
            f"• <b>Reported Server Engine:</b> <code>{server_engine}</code>\n\n"
            f"🚀 <i>Your API is successfully running and binded to all local interfaces!</i>"
        )
    except Exception as e:
        return (
            f"⚠️ <b>API PORT DIAGNOSTIC FAILURE</b>\n"
            f"─────────────────────────────\n"
            f"• <b>Error:</b> <code>{html.escape(str(e))}</code>\n\n"
            f"💡 <i>Check if your code listens on <b>0.0.0.0</b>, uses the dynamic environment variable <b>PORT</b>, or is experiencing runtime crashes. Check live logs for debugging.</i>"
        )

async def render_api_bind_panel(update: Update, context: ContextTypes.DEFAULT_TYPE, project_id: int):
    """Dedicated management panel for API endpoints, ports, and internal routing configs"""
    user_id = update.effective_user.id if update.effective_user else update.callback_query.from_user.id
    
    with get_db_connection() as conn:
        proj_row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        
    if not proj_row:
        await send_response(update, "❌ Project details unavailable.")
        return
        
    proj = dict(proj_row)
    port_text = f"<code>{proj['port']}</code>" if proj['port'] else "<i>None Bound (Local CLI only)</i>"
    url_text = f"<code>http://{VPS_PUBLIC_IP}:{proj['port']}</code>" if proj['port'] else "<i>Inactive</i>"
    
    panel_view = (
        f"🌐 <b>WEB API SERVICE & PORT BINDING</b>\n"
        f"─────────────────────────────\n"
        f"• Project Name: <b>{proj['project_name']}</b>\n"
        f"• Running Port: {port_text}\n"
        f"• API Live URL: {url_text}\n\n"
        f"💡 <i>Web service frameworks must run server connections utilizing the dynamic PORT env variable.</i>\n\n"
        f"👉 <b>Choose API Endpoint Action:</b>"
    )
    
    buttons = []
    if proj['port']:
        buttons.append([InlineKeyboardButton("⚡ TEST ACTIVE ENDPOINT", callback_data=f"api_test_{project_id}")])
        
    buttons.append([
        InlineKeyboardButton("✏️ DEFINE PORT", callback_data=f"api_setport_{project_id}"),
        InlineKeyboardButton("🔄 AUTO-ASSIGN", callback_data=f"api_autoport_{project_id}")
    ])
    
    if proj['port']:
        buttons.append([InlineKeyboardButton("❌ DISABLE PORT BINDING", callback_data=f"api_disable_{project_id}")])
        
    buttons.append([InlineKeyboardButton("🔙 BACK TO CONSOLE", callback_data=f"viewproj_{project_id}")])
    
    await send_response(update, panel_view, reply_markup=InlineKeyboardMarkup(buttons))

# ===== WEB PANEL COMMANDS =====
async def web_dashboard_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generate secure login token and return the VPS Admin Dashboard URL"""
    user_id = update.effective_user.id
    if not has_access(user_id):
        await update.message.reply_text("❌ Whitelisting required to view system status.")
        return
        
    username = update.effective_user.username or update.effective_user.first_name
    token = generate_dashboard_token(user_id, username)
    
    # Generate direct direct routing URL linking securely using token auth parameters
    dashboard_url = f"http://{VPS_PUBLIC_IP}:{WEB_DASHBOARD_PORT}/?token={token}"
    
    view_text = (
        f"🖥️ <b>VPS WEB PANEL PORTAL</b>\n"
        f"─────────────────────────────\n"
        f"To access your high-performance Web Control Dashboard, tap the secure direct portal link below.\n\n"
        f"🔑 <b>Security Token Session:</b>\n"
        f"• Access Duration: <code>30 Minutes</code>\n"
        f"• Authorization Level: <code>{'Admin' if is_admin(user_id) else 'Client'}</code>\n\n"
        f"💡 <i>You can fully host, deploy, edit packages, execute CLI terminals, and inspect resource logs directly inside your web browser.</i>"
    )
    
    buttons = [
        [InlineKeyboardButton("🔗 OPEN WEB DASHBOARD", url=dashboard_url)],
        [InlineKeyboardButton("🔄 GENERATE NEW SESSION", callback_data="web_dash_regen")]
    ]
    await update.message.reply_text(view_text, reply_markup=InlineKeyboardMarkup(buttons), parse_mode=ParseMode.HTML)

# ===== EXECUTOR LAUNCH PIPELINE WITH MULTI-LANGUAGE DEPS =====
def start_project_worker(project_id, chat_id, status_msg_id, loop, bot):
    """Robust dynamic worker loader launching environments and installing missing modules with in-place edits"""
    with get_db_connection() as conn:
        fresh = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not fresh: return
    
    project = dict(fresh)
    p_name = project['project_name']
    p_dir = project_folder(project['user_id'], p_name)
    log_file = os.path.join(LOG_DIR, f"project_{project_id}.txt")
    framework = project['framework']
    main_file = project['main_file']
    
    current_status = [
        f"✅ <b>WORKSPACE CONFIGURED!</b>\n",
        f"• Name: <code>{p_name}</code>",
        f"• Framework: <code>{framework}</code>",
        f"• Entrypoint: <code>{main_file}</code>",
        f"─────────────────────────────",
        f"⏳ <b>Deployment Status:</b>"
    ]
    
    def update_status(new_line):
        if not bot or not loop or not chat_id or not status_msg_id: return
        current_status.append(f"  → {new_line}")
        full_text = "\n".join(current_status)
        if len(full_text) > 4000:
            full_text = "..." + full_text[-3800:]
        try:
            asyncio.run_coroutine_threadsafe(
                bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=status_msg_id,
                    text=full_text,
                    parse_mode=ParseMode.HTML
                ), loop
            ).result(timeout=10)
        except Exception as e:
            logger.error(f"Status update failed: {e}")

    try:
        env = os.environ.copy()
        env['BOT_HOSTING_PLATFORM'] = 'True'
        if 'BOT_TOKEN' in env: env.pop('BOT_TOKEN')
        if project['port']: 
            env['PORT'] = str(project['port'])
            env['HOST'] = '0.0.0.0'
        
        try:
            user_env_data = json.loads(project.get('env_vars', '{}'))
            for k, v in user_env_data.items():
                env[str(k)] = str(v)
        except Exception as e:
            logger.warning(f"Failed loading env variables for {p_name}: {e}")
        
        if not project['deps_installed']:
            update_status("Running security dependency scan...")
            auto_packages_to_install = []
            if project['framework'] == "Python":
                auto_packages_to_install = parse_python_imports(p_dir)
            elif project['framework'] == "Node.js":
                auto_packages_to_install = parse_nodejs_imports(p_dir)
                
            if project['framework'] == "Node.js":
                p_json_path = os.path.join(p_dir, 'package.json')
                p_json_packages = set()
                if not os.path.exists(p_json_path):
                    p_json_content = {
                        "name": p_name.lower(),
                        "version": "1.0.0",
                        "main": project['main_file'],
                        "dependencies": {}
                    }
                    try:
                        with open(p_json_path, 'w') as f:
                            json.dump(p_json_content, f, indent=2)
                    except Exception as e:
                        logger.error(f"Failed to generate package.json scaffold: {e}")
                else:
                    p_json_packages = parse_package_json_packages(p_json_path)

                update_status("Executing production npm installs...")
                try:
                    res = subprocess.run(["npm", "install", "--no-audit", "--no-fund"], cwd=p_dir, capture_output=True, text=True, timeout=300)
                except Exception as e:
                    update_status(f"⚠️ Installation alert: {e}")
                
                filtered_auto = [pkg for pkg in auto_packages_to_install if pkg.lower() not in p_json_packages]
                if filtered_auto:
                    update_status(f"Resolving {len(filtered_auto)} system modules...")
                    try:
                        npm_args = ["npm", "install", "--no-audit", "--no-fund", "--save"] + filtered_auto
                        subprocess.run(npm_args, cwd=p_dir, capture_output=True, text=True, timeout=300)
                    except Exception as e:
                        logger.error(f"Dynamic Node dependency installation failed: {e}")
                    
            elif project['framework'] == "PHP" and os.path.exists(os.path.join(p_dir, 'composer.json')):
                update_status("Initializing Composer runtimes...")
                try:
                    subprocess.run(["composer", "install", "--no-interaction", "--ignore-platform-reqs"], cwd=p_dir, capture_output=True, text=True, timeout=300)
                except Exception as e:
                    update_status(f"⚠️ Composer warning: {e}")
                    
            elif project['framework'] == "Python":
                req_file = find_requirements_txt(p_dir)
                req_packages = set()
                if req_file:
                    req_packages = parse_requirements_txt_packages(req_file)
                    update_status("Resolving requirements.txt...")
                    try:
                        res = subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file], capture_output=True, text=True, timeout=300)
                        if res.returncode != 0:
                            subprocess.run(["pip3", "install", "-r", req_file], timeout=300)
                    except Exception as e:
                        update_status(f"⚠️ pip installation warning: {e}")
                
                filtered_auto = []
                for pkg in auto_packages_to_install:
                    normalized_pkg = pkg.lower().replace('_', '-')
                    if normalized_pkg not in req_packages:
                        filtered_auto.append(pkg)
                
                if filtered_auto:
                    update_status(f"Installing missing requirements...")
                    try:
                        pip_args = [sys.executable, "-m", "pip", "install"] + filtered_auto
                        subprocess.run(pip_args, capture_output=True, text=True, timeout=300)
                    except Exception as e:
                        try:
                            pip3_args = ["pip3", "install"] + filtered_auto
                            subprocess.run(pip3_args, capture_output=True, text=True, timeout=300)
                        except Exception as ex:
                            logger.error(f"Dynamic Python dependencies warning: {ex}")
                        
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET deps_installed = 1 WHERE id = ?", (project_id,))
                conn.commit()

        cmd_args = None
        if project['framework'] == "Python":
            cmd_args = [sys.executable, "-u", main_file]
        elif project['framework'] == "Node.js":
            p_json_path = os.path.join(p_dir, "package.json")
            has_start = False
            if os.path.exists(p_json_path):
                try:
                    with open(p_json_path, 'r') as f:
                        p_data = json.load(f)
                        if "scripts" in p_data and "start" in p_data["scripts"]:
                            has_start = True
                except:
                    pass
            if has_start:
                cmd_args = ["npm", "start"]
            else:
                cmd_args = ["node", main_file]
        elif project['framework'] == "PHP":
            if project['port']:
                cmd_args = ["php", "-S", f"0.0.0.0:{project['port']}", "-t", "."]
            else:
                cmd_args = ["php", main_file]
        elif project['framework'] == "Static HTML":
            cmd_args = ["python3", "-m", "http.server", str(project['port'])]

        if not cmd_args:
            update_status("❌ Launcher command configurations missing.")
            return
            
        update_status("Spawning operational thread...")
        with open(log_file, 'a') as lf:
            lf.write(f"\n=== WORKSPACE INITIALIZED AT {datetime.now()} ===\n")
            lf.write(f"Launch command: {' '.join(cmd_args)}\n")
            proc = subprocess.Popen(
                cmd_args, cwd=p_dir, stdout=lf, stderr=lf, env=env
            )
            
        running_processes[project_id] = proc.pid
        with get_db_connection() as conn:
            conn.execute("UPDATE projects SET status = 'running', last_started = CURRENT_TIMESTAMP WHERE id = ?", (project_id,))
            conn.execute("INSERT OR REPLACE INTO process_monitoring (project_id, pid, start_time) VALUES (?, ?, CURRENT_TIMESTAMP)", (project_id, proc.pid))
            conn.commit()
            
        update_status(f"🟢 <b>Process operational</b> (PID: {proc.pid})")
    except Exception as e:
        logger.error(f"Sandbox runner spawning crashed: {e}", exc_info=True)
        update_status(f"❌ Initialization breakdown: {e}")

# ===== DEPLOYMENT HANDLERS WITH ALL-LANGUAGE & SINGLE FILE SUPPORT =====
async def file_upload_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if user_id in user_states and user_states[user_id].get("awaiting_self_update_zip"):
        if not is_admin(user_id): return
        doc = update.message.document
        if not doc or not doc.file_name.endswith('.zip'):
            await update.message.reply_text("❌ Please provide a valid update .zip archive.")
            return
            
        p_msg = await update.message.reply_text("📥 Downloading bot orchestrator codebase updates...")
        try:
            tg_file = await context.bot.get_file(doc.file_id)
            archive_path = os.path.join(TEMP_DIR, "bot_self_update.zip")
            await tg_file.download_to_drive(archive_path)
            
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(BASE_DIR)
                
            os.remove(archive_path)
            await p_msg.edit_text("⚙️ Upgraded workspace contents. Re-executing subshell binary...")
            user_states.pop(user_id, None)
            hot_reboot_bot()
        except Exception as e:
            await p_msg.edit_text(f"❌ Host self-upgrade crashed: {e}")
        return

    if user_id not in user_states or not user_states[user_id].get("awaiting_zip"):
        await update.message.reply_text("❌ Action invalid. Trigger the 'HOST BOT' menu first.")
        return
        
    if not has_access(user_id):
        await update.message.reply_text("❌ Access Denied. Whitelisting required.")
        return
        
    doc = update.message.document
    if not doc:
        await update.message.reply_text("❌ File upload invalid. Please upload a valid code package.")
        return
        
    if doc.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(f"❌ Package limits overflow. Limit: {MAX_FILE_SIZE_MB}MB")
        return
        
    p_msg = await update.message.reply_text("📥 Extracting incoming file structures...")
    
    try:
        tg_file = await context.bot.get_file(doc.file_id)
        
        filename_lower = doc.file_name.lower()
        is_zip = filename_lower.endswith('.zip')
        is_single = filename_lower.endswith(('.py', '.js', '.ts', '.php', '.html', '.htm'))
        
        if not (is_zip or is_single):
            await p_msg.edit_text("❌ Format rejected. Please upload a `.zip` archive or a single code file (<code>.py</code>, <code>.js</code>, <code>.php</code>, <code>.html</code>).", parse_mode=ParseMode.HTML)
            return

        base_name, ext = os.path.splitext(doc.file_name)
        p_name = re.sub(r'[^a-zA-Z0-9_-]', '', base_name)
        extract_dir = os.path.join(TEMP_DIR, f"ext_{user_id}_{p_name}")
        
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
        os.makedirs(extract_dir, exist_ok=True)
        
        main_file = None
        deps_installed_default = 0
        
        if is_zip:
            archive_path = os.path.join(TEMP_DIR, f"{user_id}_{doc.file_name}")
            await tg_file.download_to_drive(archive_path)
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(extract_dir)
            os.remove(archive_path)
            
            main_file = find_main_file(extract_dir)
            if not main_file:
                shutil.rmtree(extract_dir, ignore_errors=True)
                await p_msg.edit_text("❌ Entry point launcher missing in root directories.")
                return
        else:
            file_dest_path = os.path.join(extract_dir, doc.file_name)
            await tg_file.download_to_drive(file_dest_path)
            main_file = doc.file_name
            
            if ext.lower() == '.py':
                with open(os.path.join(extract_dir, "requirements.txt"), "w") as f:
                    f.write("# Generated requirements file\n")
            elif ext.lower() in ('.js', '.ts'):
                p_json_content = {
                    "name": p_name.lower(),
                    "version": "1.0.0",
                    "main": doc.file_name,
                    "dependencies": {}
                }
                with open(os.path.join(extract_dir, "package.json"), "w") as f:
                    json.dump(p_json_content, f, indent=2)
            
        types = detect_project_type(extract_dir, main_file)
        dest_dir = project_folder(user_id, p_name)
        if os.path.exists(dest_dir): 
            shutil.rmtree(dest_dir, ignore_errors=True)
            
        shutil.move(extract_dir, dest_dir)
        create_sandbox_environment(dest_dir)
        
        framework = "Unknown"
        port = None
        
        if main_file.endswith('.py'):
            framework = "Python"
            if any(x in types for x in ["flask", "fastapi", "django"]):
                port = find_available_port()
        elif main_file.endswith(('.js', '.ts')):
            framework = "Node.js"
            if any(x in types for x in ["express", "nodejs"]):
                port = find_available_port()
        elif main_file.endswith('.php'):
            framework = "PHP"
            port = find_available_port()
        elif main_file.endswith(('.html', '.htm')):
            framework = "Static HTML"
            port = find_available_port()
            
        with get_db_connection() as conn:
            existing_project = conn.execute(
                "SELECT id, user_id FROM projects WHERE project_name = ?", (p_name,)
            ).fetchone()
            
            if existing_project:
                if existing_project['user_id'] != user_id:
                    await p_msg.edit_text("❌ <b>Deployment Error:</b> This project name is already reserved by another user.")
                    return
                
                project_id = existing_project['id']
                logger.info(f"Overwriting existing project '{p_name}' (ID: {project_id}). Stopping active instance...")
                stop_process(project_id)
                
                conn.execute("""
                    UPDATE projects 
                    SET main_file = ?, framework = ?, project_type = ?, port = ?, deps_installed = ?
                    WHERE id = ?
                """, (main_file, framework, ','.join(types), port, deps_installed_default, project_id))
            else:
                cursor = conn.execute("""
                    INSERT INTO projects (user_id, project_name, main_file, framework, project_type, port, deps_installed)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (user_id, p_name, main_file, framework, ','.join(types), port, deps_installed_default))
                project_id = cursor.lastrowid
            
            conn.commit()
            
        await p_msg.edit_text(
            f"✅ <b>WORKSPACE INITIALIZED SUCCESSFULLY!</b>\n\n"
            f"• Name: <code>{p_name}</code>\n"
            f"• Framework: <code>{framework}</code>\n"
            f"• Launchpoint: <code>{main_file}</code>\n\n"
            f"⚙️ Resolving environment setups & dependencies..."
        )
        
        loop = asyncio.get_running_loop()
        threading.Thread(
            target=start_project_worker,
            args=(project_id, p_msg.chat.id, p_msg.message_id, loop, context.bot),
            daemon=True
        ).start()
    except Exception as e:
        logger.error(f"Platform code initialization failure: {e}", exc_info=True)
        await p_msg.edit_text(f"❌ Verification framework crash: {e}")
    finally:
        user_states.pop(user_id, None)

# ===== CONSOLE INTERACTION ACTIONS CALLBACKS =====
async def button_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data
    
    if not has_access(user_id):
        await query.edit_message_text("❌ System access expired or deactivated.")
        return
        
    if data.startswith("portfolio_page_"):
        await list_bots_command(update, context, int(data.split("_")[2]))
        return
    elif data == "refresh_projects":
        await list_bots_command(update, context)
        return
    elif data.startswith("viewproj_"):
        p_id = int(data.split("_")[1])
        await show_project_console(update, context, p_id)
        return
    elif data == "web_dash_regen":
        await web_dashboard_command(update, context)
        return
        
    # PROCESS SECURITY ACTION CALLBACKS
    if data == "sys_scan_proc":
        if not is_admin(user_id): return
        p_msg = await context.bot.send_message(query.message.chat.id, "🔍 <i>Scanning RAM spaces for active processes and listening ports...</i>", parse_mode=ParseMode.HTML)
        discovered = scan_vps_for_foreign_services()
        
        if not discovered:
            await p_msg.edit_text("✅ <b>No foreign APIs or active services detected.</b>")
            return
            
        report = f"🔍 <b>VPS FOREIGN APIS REPORT ({len(discovered)})</b>\n\n"
        buttons = []
        
        for d in discovered:
            report += (
                f"⚙️ <b>PID:</b> <code>{d['real_pid']}</code>\n"
                f"• Class: <code>{d['project_type']}</code>\n"
                f"• Target command: <code>{html.escape(d['cmdline'][:60])}...</code>\n"
                f"• Bound Port: <code>{d['port'] or 'N/A'}</code>\n\n"
            )
            buttons.append([
                InlineKeyboardButton(f"🚨 KILL PID {d['real_pid']}", callback_data=f"killproc_{d['real_pid']}"),
                InlineKeyboardButton(f"📥 ADOPT", callback_data=f"regproc_{d['real_pid']}")
            ])
            
        buttons.append([InlineKeyboardButton("🔙 RETURN TO SERVICES", callback_data="refresh_projects")])
        await p_msg.delete()
        await context.bot.send_message(query.message.chat.id, report, reply_markup=InlineKeyboardMarkup(buttons), parse_mode=ParseMode.HTML)
        return

    if data.startswith("killproc_"):
        if not is_admin(user_id): return
        target_pid = int(data.split("_")[1])
        try:
            parent = psutil.Process(target_pid)
            parent.kill()
            await context.bot.send_message(query.message.chat.id, f"✅ <b>Process {target_pid} terminated.</b>", parse_mode=ParseMode.HTML)
        except Exception as e:
            await context.bot.send_message(query.message.chat.id, f"❌ Failed to close process {target_pid}: {e}", parse_mode=ParseMode.HTML)
        return

    if data.startswith("regproc_"):
        if not is_admin(user_id): return
        target_pid = int(data.split("_")[1])
        try:
            proc = psutil.Process(target_pid)
            cmdline = proc.cmdline()
            cmd_str = " ".join(cmdline)
            
            p_name = f"IMPORTED_{target_pid}"
            main_file = cmdline[-1] if len(cmdline) > 0 else "main.py"
            framework = "External (Node.js)" if "node" in cmd_str else "External (PHP)" if "php" in cmd_str else "External (Python)"
            
            with get_db_connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO projects (user_id, project_name, main_file, framework, project_type, status, deps_installed)
                    VALUES (?, ?, ?, ?, ?, 'running', 1)
                """, (OWNER_ID, p_name, main_file, framework, "Imported Daemon"))
                project_id = cursor.lastrowid
                conn.commit()
                
            running_processes[project_id] = target_pid
            await context.bot.send_message(query.message.chat.id, f"✅ Registered under <code>{p_name}</code>.", parse_mode=ParseMode.HTML)
        except Exception as e:
            await context.bot.send_message(query.message.chat.id, f"❌ Failed to import process space: {e}", parse_mode=ParseMode.HTML)
        return

    # PACKAGE MANAGER CALLBACK IMPLEMENTATIONS
    if data.startswith("p_pkg_"):
        p_id = int(data.split("_")[2])
        await render_package_manager(update, context, p_id)
        return
    elif data.startswith("pkg_add_"):
        p_id = int(data.split("_")[2])
        user_states[user_id] = {"awaiting_pkg_install": True, "project_id": p_id}
        await context.bot.send_message(
            query.message.chat.id,
            f"📥 <b>INSTALL OR SPECIFY VERSION</b>\n"
            f"─────────────────────────────\n"
            f"Send the package name and target version lock to install or update.\n\n"
            f"• Python Format: <code>package_name==version</code>\n"
            f"• Node.js Format: <code>package_name@version</code>\n\n"
            f"👉 <i>Example:</i> <code>pyrogram==2.0.106</code> or <code>express@4.19.2</code>",
            parse_mode=ParseMode.HTML
        )
        return
    elif data.startswith("pkg_del_"):
        p_id = int(data.split("_")[2])
        user_states[user_id] = {"awaiting_pkg_uninstall": True, "project_id": p_id}
        await context.bot.send_message(
            query.message.chat.id,
            f"➖ <b>UNINSTALL PACKAGE</b>\n"
            f"─────────────────────────────\n"
            f"Send the exact name of the package you wish to uninstall.",
            parse_mode=ParseMode.HTML
        )
        return

    # API BINDING SUITE ACTIONS
    if data.startswith("p_api_bind_"):
        p_id = int(data.split("_")[3])
        await render_api_bind_panel(update, context, p_id)
        return
    elif data.startswith("api_test_"):
        p_id = int(data.split("_")[2])
        with get_db_connection() as conn:
            proj = conn.execute("SELECT port FROM projects WHERE id = ?", (p_id,)).fetchone()
        if proj and proj['port']:
            diagnostic_msg = await run_internal_api_ping(proj['port'])
            await context.bot.send_message(query.message.chat.id, diagnostic_msg, parse_mode=ParseMode.HTML)
        else:
            await query.answer("❌ No active port allocated to project.", show_alert=True)
        return
    elif data.startswith("api_setport_"):
        p_id = int(data.split("_")[2])
        user_states[user_id] = {"awaiting_custom_port": True, "project_id": p_id}
        await context.bot.send_message(
            query.message.chat.id,
            "✏️ <b>SPECIFY CUSTOM BINDING PORT</b>\n"
            "─────────────────────────────\n"
            "Send an unused port number (between 1024 and 65535) to bind to this service workspace.",
            parse_mode=ParseMode.HTML
        )
        return
    elif data.startswith("api_autoport_"):
        p_id = int(data.split("_")[2])
        free_port = find_available_port()
        if free_port:
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET port = ? WHERE id = ?", (free_port, p_id))
                conn.commit()
            await query.answer(f"🔄 Auto-allocated Port: {free_port}", show_alert=True)
            await render_api_bind_panel(update, context, p_id)
        else:
            await query.answer("❌ No free network ports available on VPS host.", show_alert=True)
        return
    elif data.startswith("api_disable_"):
        p_id = int(data.split("_")[2])
        with get_db_connection() as conn:
            conn.execute("UPDATE projects SET port = NULL WHERE id = ?", (p_id,))
            conn.commit()
        await query.answer("❌ Port binding disabled successfully.")
        await render_api_bind_panel(update, context, p_id)
        return

    # MAIN WORKSPACE CALLBACK HANDLERS
    if data.startswith(("pstate_", "p_env_", "p_cli_", "p_logs_", "p_build_", "p_purge_")):
        action, p_id_str = data.rsplit("_", 1)
        p_id = int(p_id_str)
        
        with get_db_connection() as conn:
            proj = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
        if not proj: return
        
        if not is_admin(user_id) and proj['user_id'] != user_id:
            await query.edit_message_text("❌ Authorization signature invalid.")
            return
            
        if action == "pstate":
            running = is_running(p_id)
            if running:
                stop_process(p_id)
                await query.answer(f"⏹️ Service {proj['project_name']} stopped.")
            else:
                status_msg = await context.bot.send_message(
                    query.message.chat.id, 
                    f"⏳ Launching project <code>{proj['project_name']}</code>...", 
                    parse_mode=ParseMode.HTML
                )
                loop = asyncio.get_running_loop()
                threading.Thread(
                    target=start_project_worker,
                    args=(p_id, query.message.chat.id, status_msg.message_id, loop, context.bot),
                    daemon=True
                ).start()
                return
                
        elif action == "p_env":
            user_states[user_id] = {"awaiting_env_vars": True, "project_id": p_id}
            await context.bot.send_message(
                query.message.chat.id,
                f"⚙️ <b>CONFIGURING ENV FOR: {proj['project_name']}</b>\n"
                f"─────────────────────────────\n"
                f"Please send the environment variables in a valid JSON scheme layout.\n\n"
                f"👉 <code>{{\"BOT_TOKEN\": \"xyz\", \"PORT\": \"8080\"}}</code>",
                parse_mode=ParseMode.HTML
            )
            return
            
        elif action == "p_cli":
            user_states[user_id] = {"awaiting_project_cli": True, "project_id": p_id}
            p_dir = project_folder(proj['user_id'], proj['project_name'])
            await context.bot.send_message(
                query.message.chat.id,
                f"🖥️ <b>VIRTUAL WORKSPACE CLI TERMINAL ACTIVE</b>\n"
                f"─────────────────────────────\n"
                f"📂 Folder Path: <code>{p_dir}</code>\n\n"
                f"Execute commands inside this workspace context. Send <code>exit</code> to terminate the shell.",
                parse_mode=ParseMode.HTML
            )
            return
            
        elif action == "p_logs":
            log_file = os.path.join(LOG_DIR, f"project_{p_id}.txt")
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    logs_data = f.read()[-3000:]
                await query.message.reply_text(
                    f"📋 <b>Runner Logs for {proj['project_name']}:</b>\n"
                    f"─────────────────────────────\n"
                    f"<pre>{html.escape(logs_data)}</pre>", 
                    parse_mode=ParseMode.HTML
                )
            else:
                await query.message.reply_text("📋 Logs database empty for this workspace.")
                
        elif action == "p_build":
            status_msg = await context.bot.send_message(
                query.message.chat.id, 
                f"🧹 Rebuilding workspace dependencies for <code>{proj['project_name']}</code>...", 
                parse_mode=ParseMode.HTML
            )
            stop_process(p_id)
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET deps_installed = 0 WHERE id = ?", (p_id,))
                conn.commit()
            loop = asyncio.get_running_loop()
            threading.Thread(
                target=start_project_worker,
                args=(p_id, query.message.chat.id, status_msg.message_id, loop, context.bot),
                daemon=True
            ).start()
            return
            
        elif action == "p_purge":
            stop_process(p_id)
            p_path = project_folder(proj['user_id'], proj['project_name'])
            shutil.rmtree(p_path, ignore_errors=True)
            
            log_file = os.path.join(LOG_DIR, f"project_{p_id}.txt")
            if os.path.exists(log_file): os.remove(log_file)
            
            with get_db_connection() as conn:
                conn.execute("DELETE FROM projects WHERE id = ?", (p_id,))
                conn.execute("DELETE FROM process_monitoring WHERE project_id = ?", (p_id,))
                conn.commit()
                
            await query.answer("🗑️ Project workspace purged fully!")
            await list_bots_command(update, context)
            return

        await asyncio.sleep(1.2)
        try:
            await show_project_console(update, context, p_id)
        except Exception:
            pass

# ===== DYNAMIC REQUIREMENTS & VERSION MANAGER PANEL =====
async def render_package_manager(update: Update, context: ContextTypes.DEFAULT_TYPE, project_id: int):
    """Dynamic package list view and modification panel"""
    user_id = update.effective_user.id if update.effective_user else update.callback_query.from_user.id
    
    with get_db_connection() as conn:
        proj_row = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if not proj_row: return
    
    proj = dict(proj_row)
    p_dir = project_folder(proj['user_id'], proj['project_name'])
    framework = proj['framework']
    
    pkg_list = ""
    if framework == "Python":
        req_file = find_requirements_txt(p_dir)
        if req_file and os.path.exists(req_file):
            try:
                with open(req_file, "r") as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                pkg_list = "\n".join([f"• <code>{html.escape(l)}</code>" for l in lines]) if lines else "<i>(None listed)</i>"
            except Exception as e:
                pkg_list = f"<i>Error reading packages: {e}</i>"
        else:
            pkg_list = "<i>No requirements.txt found</i>"
            
    elif framework == "Node.js":
        p_json_path = os.path.join(p_dir, 'package.json')
        if os.path.exists(p_json_path):
            try:
                with open(p_json_path, "r") as f:
                    data = json.load(f)
                deps = data.get("dependencies", {})
                pkg_list = "\n".join([f"• <code>{html.escape(k)}@{html.escape(str(v))}</code>" for k, v in deps.items()]) if deps else "<i>(None listed)</i>"
            except Exception as e:
                pkg_list = f"<i>Error reading package.json: {e}</i>"
        else:
            pkg_list = "<i>No package.json found</i>"
    else:
        pkg_list = "<i>Package management only supported for Python/Node.js</i>"

    manager_text = (
        f"📦 <b>WORKSPACE PACKAGE MANAGER</b>\n"
        f"─────────────────────────────\n"
        f"🛠️ Service: <b>{proj['project_name']}</b>\n"
        f"📚 Framework Class: <code>{framework}</code>\n\n"
        f"📋 <b>Identified Dependencies:</b>\n"
        f"{pkg_list}\n\n"
        f"👉 <b>Choose Package Operation:</b>"
    )
    
    buttons = [
        [
            InlineKeyboardButton("➕ ADD / LOCK VERSION", callback_data=f"pkg_add_{project_id}"),
            InlineKeyboardButton("➖ REMOVE PACKAGE", callback_data=f"pkg_del_{project_id}")
        ],
        [InlineKeyboardButton("🔙 BACK TO CONSOLE", callback_data=f"viewproj_{project_id}")]
    ]
    await send_response(update, manager_text, reply_markup=InlineKeyboardMarkup(buttons))

# ===== VPS CONTROLS & DAEMON INTERFACES =====
async def systemd_action_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    if len(context.args) < 2:
        await update.message.reply_text("❌ Usage: <code>/systemd [action] [service_name]</code>", parse_mode=ParseMode.HTML)
        return
    
    action, service = context.args[0], context.args[1]
    ok, response = manage_systemd_unit(service, action)
    output = (
        f"🗳️ <b>SYSTEMD OPERATION OUTPUT:</b>\n"
        f"─────────────────────────────\n"
        f"<pre>{html.escape(response or '')}</pre>"
    )
    await update.message.reply_text(output, parse_mode=ParseMode.HTML)

async def exec_shell_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    user_states[user_id] = {"awaiting_shell_cmd": True}
    await update.message.reply_text(
        "💻 <b>VPS DIRECT BASH SHELL TERMINAL ACTIVE</b>\n"
        "─────────────────────────────\n"
        "Send any bash command to execute it directly on the host VPS system root workspace.\n"
        "👉 Send <code>exit</code> to terminate shell terminal.",
        parse_mode=ParseMode.HTML
    )

async def self_management_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    
    buttons = [
        [InlineKeyboardButton("🔄 Git Pull Core Engine", callback_data="self_git_pull")],
        [InlineKeyboardButton("📤 Upload Bot ZIP Update", callback_data="self_zip_update")],
        [InlineKeyboardButton("🔌 System-wide Hot Reboot", callback_data="self_hot_reboot")]
    ]
    await update.message.reply_text(
        "⚙️ <b>BOT SELF-MANAGEMENT CONTROL PANEL</b>\n"
        "─────────────────────────────\n"
        "Deploy, upgrade, and rebuild the orchestrator engine directly:",
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode=ParseMode.HTML
    )

async def self_cb_management(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data
    
    if not is_admin(user_id): return
    
    if data == "self_git_pull":
        await query.message.reply_text("🔄 Initiating Git Upstream Pull Operations...")
        res = execute_vps_shell("git pull", timeout=15)
        if res["code"] == 0:
            await query.message.reply_text(f"✅ Git Pull Complete:\n<pre>{html.escape(res['stdout'])}</pre>\nTriggering system-wide reboot...", parse_mode=ParseMode.HTML)
            hot_reboot_bot()
        else:
            await query.message.reply_text(f"❌ Pull Operation Failure:\n<pre>{html.escape(res['stderr'])}</pre>", parse_mode=ParseMode.HTML)
            
    elif data == "self_zip_update":
        user_states[user_id] = {"awaiting_self_update_zip": True}
        await query.message.reply_text("📤 Please upload the updated code repository packaged as a <code>.zip</code> file.", parse_mode=ParseMode.HTML)
        
    elif data == "self_hot_reboot":
        await query.message.reply_text("🔌 Executing safe hot-restart of VPS orchestrator process space...")
        hot_reboot_bot()

# ===== CORE PLATFORM DIAGNOSTICS COMMANDS =====
async def bot_logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    
    log_path = os.path.join(LOG_DIR, "hosting_bot.log")
    if not os.path.exists(log_path):
        await update.message.reply_text("📋 Logs are currently empty.")
        return
        
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            log_data = f.read()[-3000:]
        await update.message.reply_text(
            f"📋 <b>Bot Core Host Logs:</b>\n"
            f"─────────────────────────────\n"
            f"<pre>{html.escape(log_data)}</pre>",
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error reading bot logs: {e}")

async def system_status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    
    cpu_percent = psutil.cpu_percent(interval=0.5)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    with get_db_connection() as conn:
        total_users = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
        total_projects = conn.execute("SELECT COUNT(*) as count FROM projects").fetchone()['count']
        running_projects = conn.execute("SELECT COUNT(*) as count FROM projects WHERE status = 'running'").fetchone()['count']
        
    py_versions = "".join([f"• {k}: {v}\n" for k, v in PYTHON_VERSIONS.items()])
    node_status = "✅ Active" if NODEJS_AVAILABLE else "❌ Missing dependency"
    
    status_text = (
        f"🖥️ <b>VPS CORE SYSTEM STATUS</b>\n"
        f"─────────────────────────────\n"
        f"📈 <b>Hardware Allocation:</b>\n"
        f"• {get_performance_color(cpu_percent)} CPU Usage: <code>{cpu_percent}%</code>\n"
        f"• {get_performance_color(memory.percent)} Memory Usage: <code>{memory.percent}%</code> (Free: {memory.available // (1024*1024)}MB)\n"
        f"• {get_performance_color(disk.percent)} Storage Usage: <code>{disk.percent}%</code> (Free: {disk.free // (1024*1024*1024)}GB)\n\n"
        f"📊 <b>Platform Databases:</b>\n"
        f"• Registered Users: <code>{total_users}</code>\n"
        f"• Deployed Services: <code>{total_projects}</code>\n"
        f"• Online Workers: <code>{running_projects}</code>\n\n"
        f"⚙️ <b>Server Environments:</b>\n"
        f"{py_versions}"
        f"• Node.js Engine: {node_status}"
    )
    await update.message.reply_text(status_text, parse_mode=ParseMode.HTML)

async def user_management_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    
    with get_db_connection() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY last_active DESC LIMIT 30").fetchall()
        
    text = (
        f"👥 <b>PLATFORM CLIENT MANAGEMENT</b>\n"
        f"─────────────────────────────\n"
    )
    for u in users:
        limit_lbl = "🔧 Admin" if u['file_limit'] == -1 else str(u['file_limit'])
        text += f"• <code>{u['user_id']}</code> | @{u['username'] or 'Unknown'} | Access: <b>{limit_lbl}</b>\n"
        
    text += f"\n👉 Admin Utility commands:\n" \
            f"• Whitelist: <code>/limit [USERID] [LIMIT]</code>\n" \
            f"• Promote Admin (Owner Only): <code>/addadmin [USERID]</code>"
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)

async def clear_logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    
    try:
        cleared_files = 0
        for filename in os.listdir(LOG_DIR):
            file_path = os.path.join(LOG_DIR, filename)
            if os.path.isfile(file_path):
                with open(file_path, 'w') as f:
                    f.write(f"=== Log Session Cleared at {datetime.now()} ===\n")
                cleared_files += 1
        
        await update.message.reply_text(f"🧹 <b>Logs Cleared successfully!</b>\nCleaned {cleared_files} records securely.")
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to truncate log directory: {e}")

# ===== ADMIN EXCLUSIVE SYSTEM ROUTINES =====
async def promo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    if len(context.args) < 2: return
    target_id = int(context.args[0])
    msg = " ".join(context.args[1:])
    try:
        await context.bot.send_message(target_id, f"📢 <b>ADMIN BULLETIN:</b>\n\n{msg}", parse_mode=ParseMode.HTML)
        await update.message.reply_text("✅ Message routed successfully.")
    except Exception as e:
        await update.message.reply_text(f"❌ Transport system failure: {e}")

async def limit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Configure client resource limits. Only the supreme Owner can make admins."""
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    if len(context.args) != 2: return
    target_id = int(context.args[0])
    limit = int(context.args[1])
    
    if limit == -1 and user_id != OWNER_ID:
        await update.message.reply_text("❌ <b>Access Denied</b>\nOnly the supreme Platform Owner @EliteHM can promote users to administrators.", parse_mode=ParseMode.HTML)
        return
    
    with get_db_connection() as conn:
        conn.execute("INSERT INTO users (user_id, username, file_limit) VALUES (?, 'Unknown', ?) ON CONFLICT(user_id) DO UPDATE SET file_limit = ?", (target_id, limit, limit))
        conn.commit()
    await update.message.reply_text(f"✅ User ID <code>{target_id}</code> limit updated to: {limit}", parse_mode=ParseMode.HTML)

    try:
        if limit > 0:
            notify_msg = (
                f"🎉 <b>PLATFORM ACCESS GRANTED!</b>\n\n"
                f"Your hosting platform account has been successfully authorized by the administrator.\n"
                f"📦 <b>Your Deployment Limit:</b> {limit} bot(s)\n\n"
                f"👉 Send /start to initialize your hosting dashboard controls!"
            )
        elif limit == -1:
            notify_msg = (
                f"👑 <b>ADMIN STATUS GRANTED!</b>\n\n"
                f"Your account has been promoted to a Platform Administrator.\n\n"
                f"👉 Send /start to load your administrative control panel dashboard!"
            )
        else:
            notify_msg = (
                f"⚠️ <b>ACCESS SUSPENDED!</b>\n\n"
                f"Your hosting platform clearance has been revoked by the administrator."
            )
            
        await context.bot.send_message(chat_id=target_id, text=notify_msg, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.warning(f"Could not send clearance notification to target user {target_id}: {e}")

async def add_admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Add a new administrator. Strictly restricted to Platform Owner (HmGamer) only."""
    user_id = update.effective_user.id
    if user_id != OWNER_ID:
        await update.message.reply_text("❌ <b>Unauthorized Action</b>\nOnly the supreme Platform Owner @EliteHM can add new administrators.", parse_mode=ParseMode.HTML)
        return
        
    if not context.args:
        await update.message.reply_text("❌ <b>Usage:</b> <code>/addadmin [USER_ID]</code>", parse_mode=ParseMode.HTML)
        return
        
    try:
        target_id = int(context.args[0])
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO users (user_id, username, file_limit) 
                VALUES (?, 'Unknown', -1) 
                ON CONFLICT(user_id) DO UPDATE SET file_limit = -1
            """, (target_id,))
            conn.commit()
            
        await update.message.reply_text(f"👑 <b>New Admin Appointed</b>\nUser ID <code>{target_id}</code> is now configured as a platform administrator.", parse_mode=ParseMode.HTML)
        
        try:
            notify_msg = (
                f"👑 <b>ADMIN STATUS GRANTED!</b>\n\n"
                f"You have been officially promoted to a Platform Administrator by the Owner <b>HmGamer</b>.\n\n"
                f"👉 Send /start to initialize your systemd commands and dashboard workspace controllers!"
            )
            await context.bot.send_message(chat_id=target_id, text=notify_msg, parse_mode=ParseMode.HTML)
        except Exception as e:
            logger.warning(f"Could not send administrator notification to target ID {target_id}: {e}")
            
    except ValueError:
        await update.message.reply_text("❌ Please specify a valid numeric User ID.", parse_mode=ParseMode.HTML)

async def refresh_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    running_processes.clear()
    threading.Thread(target=auto_start_all_projects, daemon=True).start()
    await update.message.reply_text("🔄 Virtualization stack re-initialized successfully.")

async def install_deps_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not context.args: return
    pkg = " ".join(context.args)
    p_msg = await update.message.reply_text(f"📦 Shell installing system module: <code>{pkg}</code>...")
    try:
        res = subprocess.run(f"sudo apt-get install -y {pkg}", shell=True, capture_output=True, text=True, timeout=300)
        await p_msg.edit_text(f"✅ System installation sequence terminated with return code {res.returncode}.\n\nOutput log preview:\n<pre>{html.escape(res.stdout[-1500:])}</pre>", parse_mode=ParseMode.HTML)
    except Exception as e:
        await p_msg.edit_text(f"❌ Package pipeline exception crash: {e}")

# ===== BROADCAST & TEXT INPUT ROUTINES =====
async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    broadcast_states[user_id] = {"awaiting_broadcast": True}
    await update.message.reply_text("📢 <b>Enter broadcast package layout contents:</b>", parse_mode=ParseMode.HTML)

async def text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text
    
    menu_buttons = [
        "🚀 HOST BOT", "📊 MY PROJECTS", "🖥️ VPS CONTROLS", 
        "⚙️ SELF-MGMT", "📢 BROADCAST", "📋 BOT LOGS", 
        "🖥️ SYSTEM STATUS", "👥 USER MANAGEMENT", "🧹 CLEAR LOGS",
        "🖥️ WEB DASHBOARD"
    ]
    
    if text in menu_buttons:
        user_states.pop(user_id, None)
        broadcast_states.pop(user_id, None)
        
        if text == "🚀 HOST BOT": await bot_host_command(update, context)
        elif text == "📊 MY PROJECTS": await list_bots_command(update, context)
        elif text == "🖥️ VPS CONTROLS": await exec_shell_panel(update, context)
        elif text == "⚙️ SELF-MGMT": await self_management_panel(update, context)
        elif text == "📢 BROADCAST": await broadcast_command(update, context)
        elif text == "📋 BOT LOGS": await bot_logs_command(update, context)
        elif text == "🖥️ SYSTEM STATUS": await system_status_command(update, context)
        elif text == "👥 USER MANAGEMENT": await user_management_command(update, context)
        elif text == "🧹 CLEAR LOGS": await clear_logs_command(update, context)
        elif text == "🖥️ WEB DASHBOARD": await web_dashboard_command(update, context)
        return
    
    # INTERACTIVE REQUIREMENT & VERSION INSTALLATION STATE PROCESSORS
    if user_id in user_states and user_states[user_id].get("awaiting_pkg_install"):
        p_id = user_states[user_id]["project_id"]
        user_states.pop(user_id, None)
        
        p_msg = await update.message.reply_text("⏳ <i>Running environment package installer sequence...</i>", parse_mode=ParseMode.HTML)
        
        with get_db_connection() as conn:
            proj = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
        if not proj:
            await p_msg.edit_text("❌ Project directory not found.")
            return
            
        proj = dict(proj)
        p_dir = project_folder(proj['user_id'], proj['project_name'])
        framework = proj['framework']
        
        install_target = text.strip()
        
        try:
            if framework == "Python":
                cmd = [sys.executable, "-m", "pip", "install", install_target]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if res.returncode == 0:
                    req_file = os.path.join(p_dir, "requirements.txt")
                    base_pkg = re.split(r'==|>=|<=|~=|<|>', install_target)[0].strip()
                    lines = []
                    if os.path.exists(req_file):
                        with open(req_file, "r") as r:
                            lines = r.readlines()
                    
                    new_lines = []
                    for line in lines:
                        clean_l = line.strip()
                        if clean_l and not clean_l.startswith('#'):
                            line_pkg = re.split(r'==|>=|<=|~=|<|>', clean_l)[0].strip()
                            if line_pkg.lower() == base_pkg.lower():
                                continue
                        new_lines.append(line)
                    
                    new_lines.append(f"{install_target}\n")
                    with open(req_file, "w") as w:
                        w.writelines(new_lines)
                        
                    await p_msg.edit_text(f"✅ <b>Package Installed/Updated</b>\n<code>{install_target}</code> was loaded and locked into requirements.txt.")
                else:
                    await p_msg.edit_text(f"❌ <b>Installation Failed:</b>\n<pre>{html.escape(res.stderr or res.stdout)}</pre>", parse_mode=ParseMode.HTML)
                    
            elif framework == "Node.js":
                cmd = ["npm", "install", install_target, "--save"]
                res = subprocess.run(cmd, cwd=p_dir, capture_output=True, text=True, timeout=120)
                if res.returncode == 0:
                    await p_msg.edit_text(f"✅ <b>Package Installed/Updated</b>\n<code>{install_target}</code> successfully installed and listed in package.json.")
                else:
                    await p_msg.edit_text(f"❌ <b>npm Installation Failed:</b>\n<pre>{html.escape(res.stderr or res.stdout)}</pre>", parse_mode=ParseMode.HTML)
            else:
                await p_msg.edit_text("❌ Action only supported for Python or NodeJS frameworks.")
                
        except Exception as e:
            await p_msg.edit_text(f"❌ Execution crash: {e}")
            
        await asyncio.sleep(1.5)
        await render_package_manager(update, context, p_id)
        return

    # UNINSTALL PACKAGE ACTION
    if user_id in user_states and user_states[user_id].get("awaiting_pkg_uninstall"):
        p_id = user_states[user_id]["project_id"]
        user_states.pop(user_id, None)
        
        p_msg = await update.message.reply_text("⏳ <i>Running package uninstallation routine...</i>", parse_mode=ParseMode.HTML)
        
        with get_db_connection() as conn:
            proj = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
        if not proj:
            await p_msg.edit_text("❌ Project not found.")
            return
            
        proj = dict(proj)
        p_dir = project_folder(proj['user_id'], proj['project_name'])
        framework = proj['framework']
        target_pkg = text.strip()
        
        try:
            if framework == "Python":
                cmd = [sys.executable, "-m", "pip", "uninstall", "-y", target_pkg]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                req_file = os.path.join(p_dir, "requirements.txt")
                if os.path.exists(req_file):
                    with open(req_file, "r") as r:
                        lines = r.readlines()
                    new_lines = []
                    for line in lines:
                        clean_l = line.strip()
                        if clean_l and not clean_l.startswith('#'):
                            line_pkg = re.split(r'==|>=|<=|~=|<|>', clean_l)[0].strip()
                            if line_pkg.lower() == target_pkg.lower():
                                continue
                        new_lines.append(line)
                    with open(req_file, "w") as w:
                        w.writelines(new_lines)
                        
                await p_msg.edit_text(f"✅ <b>Package Uninstalled</b>\n<code>{target_pkg}</code> removed and expunged from requirements.txt.")
                
            elif framework == "Node.js":
                cmd = ["npm", "uninstall", target_pkg, "--save"]
                res = subprocess.run(cmd, cwd=p_dir, capture_output=True, text=True, timeout=120)
                if res.returncode == 0:
                    await p_msg.edit_text(f"✅ <b>Package Uninstalled</b>\n<code>{target_pkg}</code> removed from node_modules and package.json.")
                else:
                    await p_msg.edit_text(f"❌ <b>npm Uninstall Failed:</b>\n<pre>{html.escape(res.stderr or res.stdout)}</pre>", parse_mode=ParseMode.HTML)
            else:
                await p_msg.edit_text("❌ Action only supported for Python or NodeJS frameworks.")
                
        except Exception as e:
            await p_msg.edit_text(f"❌ Execution crash: {e}")
            
        await asyncio.sleep(1.5)
        await render_package_manager(update, context, p_id)
        return

    # PORT CUSTOM CONFIGURATION INPUT
    if user_id in user_states and user_states[user_id].get("awaiting_custom_port"):
        p_id = user_states[user_id]["project_id"]
        user_states.pop(user_id, None)
        
        try:
            custom_port = int(text.strip())
            if not (1024 <= custom_port <= 65535):
                raise ValueError()
                
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET port = ? WHERE id = ?", (custom_port, p_id))
                conn.commit()
            await update.message.reply_text(f"✅ Port allocation set manually to: <code>{custom_port}</code>. Restart workspace to deploy.", parse_mode=ParseMode.HTML)
        except ValueError:
            await update.message.reply_text("❌ Invalid input. Port must be a numeric value between 1024 and 65535.")
            
        await asyncio.sleep(1.2)
        await render_api_bind_panel(update, context, p_id)
        return

    # SCOPED CONSOLE/CLI TERMINAL
    if user_id in user_states and user_states[user_id].get("awaiting_project_cli"):
        p_id = user_states[user_id]["project_id"]
        if text.lower() == "exit":
            user_states.pop(user_id, None)
            await update.message.reply_text("🔌 Scoped container subshell closed.")
            await show_project_console(update, context, p_id)
            return
            
        p_msg = await update.message.reply_text("⏳ Shell executing command in sandboxed scope...")
        
        with get_db_connection() as conn:
            proj = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
        if not proj:
            user_states.pop(user_id, None)
            await p_msg.edit_text("❌ Project directory not found.")
            return
            
        p_dir = project_folder(proj['user_id'], proj['project_name'])
        
        env = os.environ.copy()
        try:
            user_env = json.loads(proj.get('env_vars', '{}'))
            for k, v in user_env.items():
                env[str(k)] = str(v)
        except:
            pass
            
        try:
            res = subprocess.run(
                text,
                shell=True,
                cwd=p_dir,
                capture_output=True,
                text=True,
                timeout=25,
                env=env
            )
            output_txt = f"⚙️ <b>CONTAINER CLI EXECUTION COMPLETE (Code: {res.returncode})</b>\n\n"
            if res.stdout:
                output_txt += f"<b>Stdout:</b>\n<pre>{html.escape(res.stdout[-3000:])}</pre>"
            if res.stderr:
                output_txt += f"\n<b>Stderr:</b>\n<pre>{html.escape(res.stderr[-1000:])}</pre>"
            if not res.stdout and not res.stderr:
                output_txt += "<i>(No outputs returned)</i>"
                
            await p_msg.edit_text(output_txt, parse_mode=ParseMode.HTML)
        except subprocess.TimeoutExpired:
            await p_msg.edit_text("❌ Subshell execution timed out (25s limit reached).")
        except Exception as e:
            await p_msg.edit_text(f"❌ Subshell execution error: {e}")
        return

    if user_id in user_states and user_states[user_id].get("awaiting_shell_cmd"):
        if not is_admin(user_id): return
        if text.lower() == "exit":
            user_states.pop(user_id, None)
            await update.message.reply_text("🔌 Closed active subshell session.")
            return
            
        p_msg = await update.message.reply_text("⏳ Processing Shell command...")
        res = execute_vps_shell(text, timeout=20)
        
        output_txt = f"⚙️ <b>SHELL EXECUTION COMPLETE (Code: {res['code']})</b>\n\n"
        if res["stdout"]:
            output_txt += f"<b>Stdout:</b>\n<pre>{html.escape(res['stdout'][-3500:])}</pre>"
        if res["stderr"]:
            output_txt += f"\n<b>Stderr:</b>\n<pre>{html.escape(res['stderr'][-1000:])}</pre>"
            
        await p_msg.edit_text(output_txt, parse_mode=ParseMode.HTML)
        return
        
    if user_id in user_states and user_states[user_id].get("awaiting_env_vars"):
        proj_id = user_states[user_id]["project_id"]
        try:
            parsed_data = json.loads(text)
            serialized = json.dumps(parsed_data)
            
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET env_vars = ? WHERE id = ?", (serialized, proj_id))
                conn.commit()
                
            await update.message.reply_text("✅ Project environment configuration saved. Restart the project workspace to apply.")
            await show_project_console(update, context, proj_id)
        except json.JSONDecodeError:
            await update.message.reply_text("❌ Invalid JSON schema format. Configuration operation aborted.")
        finally:
            user_states.pop(user_id, None)
        return

    if user_id in broadcast_states and broadcast_states[user_id].get("awaiting_broadcast"):
        broadcast_states.pop(user_id)
        with get_db_connection() as conn:
            users = conn.execute("SELECT user_id FROM users").fetchall()
        for u in users:
            try:
                await context.bot.send_message(u['user_id'], text)
                await asyncio.sleep(0.05)
            except Exception:
                pass
        await update.message.reply_text("✅ Core broadcast package fully pushed.")
        return
        
    await update.message.reply_text("🤖 Use platform menu or /start for assistance.", parse_mode=ParseMode.HTML)

# ===== STATE RESILIENCY AUTO-START LOOPS =====
def auto_start_all_projects():
    """Resume active workspaces and startup daemons when bot restarts"""
    try:
        with get_db_connection() as conn:
            projs = conn.execute("SELECT * FROM projects WHERE status = 'running' OR (auto_restart = 1 AND status != 'stopped')").fetchall()
        
        logger.info(f"🔄 State Resiliency Engine: Found {len(projs)} active workspaces to restore...")
        
        for p in projs:
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET status = 'stopped' WHERE id = ?", (p['id'],))
                conn.commit()
            
            threading.Thread(
                target=start_project_worker, 
                args=(p['id'], None, None, None, None), 
                daemon=True
            ).start()
            time.sleep(2.5)  # Safe spacing interval to prevent VPS CPU spikes during boot
            
    except Exception as e:
        logger.error(f"State recovery manager encountered an issue: {e}")

# ===== GLOBAL ERROR EXCEPTION DISPATCHER =====
async def global_exception_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Filters, suppresses, and logs temporary HTTPX read drops and socket timeouts gracefully"""
    error = context.error
    if isinstance(error, NetworkError) or "httpx.ReadError" in str(error) or "ReadTimeout" in str(error) or "Event loop is closed" in str(error):
        logger.warning(f"⚠️ VPS Network Link Fluctuation (Telegram gateway dropped request - HTTPX will auto-retry): {error}")
        return
    logger.error("Exception while handling update cycle:", exc_info=error)

# ===== WEB PORTAL CONTROLLER PAGE SERVING (ZERO DEPENDENCY PURE HTML WEB HOST) =====
class DashboardHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Dynamic, secure high-fidelity web gateway panel serving process utilities directly from RAM"""
    
    # Silence default requests output in standard console stdout
    def log_message(self, format, *args):
        pass

    def check_auth(self):
        """Extract and validate secure cookie sessions or secure query token authentications"""
        # 1. Inspect secure token query parameters first
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        token = params.get('token', [None])[0]
        
        if token and token in dashboard_tokens:
            session_data = dashboard_tokens[token]
            if session_data["expires"] > datetime.now():
                return session_data
                
        # 2. Inspect session cookies fallback
        cookies_header = self.headers.get('Cookie', '')
        cookies = {}
        for c in cookies_header.split(';'):
            if '=' in c:
                k, v = c.strip().split('=', 1)
                cookies[k] = v
                
        session_token = cookies.get('session_token')
        if session_token and session_token in dashboard_tokens:
            session_data = dashboard_tokens[session_token]
            if session_data["expires"] > datetime.now():
                return session_data
        return None

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Cookie")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Cookie")
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # Session authentication interceptor
        session = self.check_auth()
        
        # Token Login Gateway redirection pattern
        params = urllib.parse.parse_qs(parsed_url.query)
        url_token = params.get('token', [None])[0]
        if url_token and url_token in dashboard_tokens:
            self.send_response(302)
            # Bind session cookie securely
            self.send_header("Set-Cookie", f"session_token={url_token}; Path=/; HttpOnly; Max-Age=1800; SameSite=Lax")
            self.send_header("Location", "/")
            self.end_headers()
            return

        if not session:
            # Server clean professional Unauthorized Login screen
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            unauthorized_html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Access Denied - VPS Orchestrator</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
                <style>body { font-family: 'Inter', sans-serif; }</style>
            </head>
            <body class="bg-[#0b0f19] text-[#f3f4f6] flex items-center justify-center min-h-screen">
                <div class="max-w-md w-full mx-4 p-8 bg-[#161c2a] rounded-2xl border border-red-500/20 text-center shadow-2xl shadow-red-500/5">
                    <div class="text-6xl mb-4">🔒</div>
                    <h1 class="text-2xl font-bold text-red-500 mb-2">Unauthorized Session</h1>
                    <p class="text-[#9ca3af] mb-6">Web Dashboard access is strictly protected. Please request a secure authentication link using the Telegram bot.</p>
                    <div class="bg-[#1f293d] p-4 rounded-xl text-left border border-[#2d3748]">
                        <p class="text-xs text-[#38bdf8] font-bold mb-1">STEPS TO ACCESS:</p>
                        <ol class="list-decimal list-inside text-xs text-[#9ca3af] space-y-1">
                            <li>Open your Telegram bot workspace</li>
                            <li>Send or tap command <code class="text-yellow-400 bg-black/30 px-1 py-0.5 rounded">/dashboard</code></li>
                            <li>Click the secure <b>Open Dashboard</b> dynamic token portal</li>
                        </ol>
                    </div>
                </div>
            </body>
            </html>
            """
            self.wfile.write(unauthorized_html.encode('utf-8'))
            return

        # Serve Dashboard Single-Page Application (SPA) Client
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(self.get_spa_html(session).encode('utf-8'))
            return

        # Fetch system hardware metrics in-RAM
        if path == "/api/stats":
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            with get_db_connection() as conn:
                total_projects = conn.execute("SELECT COUNT(*) as count FROM projects").fetchone()['count']
                running_projects = conn.execute("SELECT COUNT(*) as count FROM projects WHERE status = 'running'").fetchone()['count']
                
            stats = {
                "cpu": cpu,
                "memory": mem.percent,
                "memory_mb_used": (mem.total - mem.available) // (1024*1024),
                "memory_mb_total": mem.total // (1024*1024),
                "disk": disk.percent,
                "disk_gb_free": disk.free // (1024*1024*1024),
                "total_projects": total_projects,
                "running_projects": running_projects,
                "uptime_hours": int(time.time() - psutil.boot_time()) // 3600,
                "vps_ip": VPS_PUBLIC_IP
            }
            self.send_json(stats)
            return

        # Retrieve managed code workspaces list
        if path == "/api/projects":
            with get_db_connection() as conn:
                rows = conn.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
            projects_list = []
            for r in rows:
                p_dict = dict(r)
                p_dict["running"] = is_running(p_dict["id"])
                
                # Fetch runtime logs if process is operational
                p_dict["ram_usage"] = 0
                p_dict["cpu_usage"] = 0
                if p_dict["running"]:
                    info = get_process_info(p_dict["id"])
                    if info:
                        p_dict["ram_usage"] = round(info["memory_mb"], 1)
                        p_dict["cpu_usage"] = round(info["cpu_percent"], 1)
                projects_list.append(p_dict)
            self.send_json(projects_list)
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        session = self.check_auth()
        if not session:
            self.send_json({"error": "Unauthorized session"}, 401)
            return
            
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else "{}"
        
        try:
            payload = json.loads(body) if body else {}
        except Exception:
            payload = {}

        # 🚀 API BIND: NEW DRAG & DROP / WEB PORTAL CODE DEPLOYER
        if path == "/api/project/deploy":
            proj_name = payload.get("project_name")
            filename = payload.get("filename")
            base64_data = payload.get("file_data") # Base64 payload prevents tricky browser multipart boundaries crashes
            
            if not proj_name or not filename or not base64_data:
                self.send_json({"error": "Missing parameters"}, 400)
                return
                
            clean_proj_name = re.sub(r'[^a-zA-Z0-9_-]', '', proj_name)
            try:
                # Resolve package data write files safely
                file_bytes = base64.b64decode(base64_data)
                extract_dir = os.path.join(TEMP_DIR, f"web_{session['user_id']}_{clean_proj_name}")
                if os.path.exists(extract_dir):
                    shutil.rmtree(extract_dir, ignore_errors=True)
                os.makedirs(extract_dir, exist_ok=True)
                
                is_zip = filename.lower().endswith('.zip')
                main_file = None
                
                if is_zip:
                    zip_path = os.path.join(TEMP_DIR, f"web_{clean_proj_name}.zip")
                    with open(zip_path, "wb") as f:
                        f.write(file_bytes)
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        zf.extractall(extract_dir)
                    os.remove(zip_path)
                    
                    main_file = find_main_file(extract_dir)
                    if not main_file:
                        shutil.rmtree(extract_dir, ignore_errors=True)
                        self.send_json({"error": "Launcher entrypoint file not detected"}, 400)
                        return
                else:
                    file_path = os.path.join(extract_dir, filename)
                    with open(file_path, "wb") as f:
                        f.write(file_bytes)
                    main_file = filename
                    
                    # Scaffolding configuration setups
                    _, ext = os.path.splitext(filename)
                    if ext.lower() == '.py':
                        with open(os.path.join(extract_dir, "requirements.txt"), "w") as f:
                            f.write("# Auto-generated\n")
                    elif ext.lower() in ('.js', '.ts'):
                        p_json_content = {
                            "name": clean_proj_name.lower(),
                            "version": "1.0.0",
                            "main": filename,
                            "dependencies": {}
                        }
                        with open(os.path.join(extract_dir, "package.json"), "w") as f:
                            json.dump(p_json_content, f, indent=2)
                            
                types = detect_project_type(extract_dir, main_file)
                dest_dir = project_folder(session["user_id"], clean_proj_name)
                
                if os.path.exists(dest_dir):
                    shutil.rmtree(dest_dir, ignore_errors=True)
                    
                shutil.move(extract_dir, dest_dir)
                create_sandbox_environment(dest_dir)
                
                framework = "Unknown"
                port = None
                
                if main_file.endswith('.py'):
                    framework = "Python"
                    if any(x in types for x in ["flask", "fastapi", "django"]):
                        port = find_available_port()
                elif main_file.endswith(('.js', '.ts')):
                    framework = "Node.js"
                    if any(x in types for x in ["express", "nodejs"]):
                        port = find_available_port()
                elif main_file.endswith('.php'):
                    framework = "PHP"
                    port = find_available_port()
                elif main_file.endswith(('.html', '.htm')):
                    framework = "Static HTML"
                    port = find_available_port()

                with get_db_connection() as conn:
                    existing = conn.execute("SELECT id FROM projects WHERE project_name = ?", (clean_proj_name,)).fetchone()
                    if existing:
                        project_id = existing['id']
                        stop_process(project_id)
                        conn.execute("""
                            UPDATE projects 
                            SET main_file = ?, framework = ?, project_type = ?, port = ?, deps_installed = 0
                            WHERE id = ?
                        """, (main_file, framework, ','.join(types), port, project_id))
                    else:
                        cursor = conn.execute("""
                            INSERT INTO projects (user_id, project_name, main_file, framework, project_type, port, deps_installed)
                            VALUES (?, ?, ?, ?, ?, ?, 0)
                        """, (session["user_id"], clean_proj_name, main_file, framework, ','.join(types), port))
                        project_id = cursor.lastrowid
                    conn.commit()
                    
                # Safe operational spawn worker running in standard executor logs
                threading.Thread(
                    target=start_project_worker,
                    args=(project_id, None, None, None, None),
                    daemon=True
                ).start()
                
                self.send_json({"success": True, "message": f"Successfully hosted workspace '{clean_proj_name}'!"})
                return
            except Exception as e:
                self.send_json({"error": f"Build crash: {e}"}, 500)
                return

        # Project running configurations controls (START/STOP/REBUILD/PURGE)
        if path == "/api/project/control":
            p_id = payload.get("project_id")
            action = payload.get("action")
            
            with get_db_connection() as conn:
                p_row = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
            if not p_row:
                self.send_json({"error": "Project not found"}, 404)
                return
                
            p_dict = dict(p_row)
            if not is_admin(session["user_id"]) and p_dict["user_id"] != session["user_id"]:
                self.send_json({"error": "Unauthorized process clearance"}, 403)
                return
                
            if action == "start":
                if is_running(p_id):
                    self.send_json({"success": True, "message": "Service is already running."})
                    return
                threading.Thread(
                    target=start_project_worker,
                    args=(p_id, None, None, None, None),
                    daemon=True
                ).start()
                self.send_json({"success": True, "message": "Service startup signal dispatched."})
                return
                
            elif action == "stop":
                stop_process(p_id)
                self.send_json({"success": True, "message": "Service stopped successfully."})
                return
                
            elif action == "build":
                stop_process(p_id)
                with get_db_connection() as conn:
                    conn.execute("UPDATE projects SET deps_installed = 0 WHERE id = ?", (p_id,))
                    conn.commit()
                threading.Thread(
                    target=start_project_worker,
                    args=(p_id, None, None, None, None),
                    daemon=True
                ).start()
                self.send_json({"success": True, "message": "Workspace cleanup and rebuild triggered."})
                return
                
            elif action == "purge":
                stop_process(p_id)
                p_path = project_folder(p_dict['user_id'], p_dict['project_name'])
                shutil.rmtree(p_path, ignore_errors=True)
                log_file = os.path.join(LOG_DIR, f"project_{p_id}.txt")
                if os.path.exists(log_file): os.remove(log_file)
                
                with get_db_connection() as conn:
                    conn.execute("DELETE FROM projects WHERE id = ?", (p_id,))
                    conn.execute("DELETE FROM process_monitoring WHERE project_id = ?", (p_id,))
                    conn.commit()
                self.send_json({"success": True, "message": "Workspace purged fully."})
                return

        # Read specific project logs
        if path == "/api/project/logs":
            p_id = payload.get("project_id")
            log_file = os.path.join(LOG_DIR, f"project_{p_id}.txt")
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    logs_data = f.read()[-6000:]
                self.send_json({"logs": logs_data})
            else:
                self.send_json({"logs": "Log manifest is empty. Start your service to load output streams."})
            return

        # Save environmental configuration variables
        if path == "/api/project/env":
            p_id = payload.get("project_id")
            env_data = payload.get("env_vars")
            
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET env_vars = ? WHERE id = ?", (json.dumps(env_data), p_id))
                conn.commit()
            self.send_json({"success": True, "message": "Environment settings mapped. Restart service to apply."})
            return

        # Install Package inside project container context
        if path == "/api/project/pkg/install":
            p_id = payload.get("project_id")
            target_pkg = payload.get("package")
            
            with get_db_connection() as conn:
                p_row = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
            if not p_row:
                self.send_json({"error": "Project details lost"}, 404)
                return
                
            proj = dict(p_row)
            p_dir = project_folder(proj['user_id'], proj['project_name'])
            framework = proj['framework']
            
            try:
                if framework == "Python":
                    cmd = [sys.executable, "-m", "pip", "install", target_pkg]
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if res.returncode == 0:
                        req_file = os.path.join(p_dir, "requirements.txt")
                        base_pkg = re.split(r'==|>=|<=|~=|<|>', target_pkg)[0].strip()
                        lines = []
                        if os.path.exists(req_file):
                            with open(req_file, "r") as r: lines = r.readlines()
                        new_lines = [l for l in lines if not l.strip() or l.strip().startswith('#') or re.split(r'==|>=|<=|~=|<|>', l.strip())[0].strip().lower() != base_pkg.lower()]
                        new_lines.append(f"{target_pkg}\n")
                        with open(req_file, "w") as w: w.writelines(new_lines)
                        self.send_json({"success": True, "message": f"Successfully installed and locked {target_pkg}."})
                    else:
                        self.send_json({"error": res.stderr or res.stdout}, 400)
                elif framework == "Node.js":
                    cmd = ["npm", "install", target_pkg, "--save"]
                    res = subprocess.run(cmd, cwd=p_dir, capture_output=True, text=True, timeout=120)
                    if res.returncode == 0:
                        self.send_json({"success": True, "message": f"Successfully installed npm package {target_pkg}."})
                    else:
                        self.send_json({"error": res.stderr or res.stdout}, 400)
                else:
                    self.send_json({"error": "Package locks only available for Python/Node.js"}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        # Uninstall Package inside project container context
        if path == "/api/project/pkg/uninstall":
            p_id = payload.get("project_id")
            target_pkg = payload.get("package")
            
            with get_db_connection() as conn:
                p_row = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
            if not p_row:
                self.send_json({"error": "Project not found"}, 404)
                return
                
            proj = dict(p_row)
            p_dir = project_folder(proj['user_id'], proj['project_name'])
            framework = proj['framework']
            
            try:
                if framework == "Python":
                    cmd = [sys.executable, "-m", "pip", "uninstall", "-y", target_pkg]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    req_file = os.path.join(p_dir, "requirements.txt")
                    if os.path.exists(req_file):
                        with open(req_file, "r") as r: lines = r.readlines()
                        new_lines = [l for l in lines if not l.strip() or l.strip().startswith('#') or re.split(r'==|>=|<=|~=|<|>', l.strip())[0].strip().lower() != target_pkg.lower()]
                        with open(req_file, "w") as w: w.writelines(new_lines)
                    self.send_json({"success": True, "message": f"Successfully removed {target_pkg}."})
                elif framework == "Node.js":
                    cmd = ["npm", "uninstall", target_pkg, "--save"]
                    res = subprocess.run(cmd, cwd=p_dir, capture_output=True, text=True, timeout=120)
                    if res.returncode == 0:
                        self.send_json({"success": True, "message": f"Removed npm package {target_pkg}."})
                    else:
                        self.send_json({"error": res.stderr or res.stdout}, 400)
                else:
                    self.send_json({"error": "Package controllers unavailable on static frameworks"}, 400)
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        # CLI terminal executing scoped workspace commands
        if path == "/api/project/cli":
            p_id = payload.get("project_id")
            command = payload.get("command")
            
            with get_db_connection() as conn:
                proj = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
            if not proj:
                self.send_json({"error": "Project details unavailable"}, 404)
                return
                
            proj = dict(proj)
            if not is_admin(session["user_id"]) and proj["user_id"] != session["user_id"]:
                self.send_json({"error": "Admin access constraints active"}, 403)
                return
                
            p_dir = project_folder(proj['user_id'], proj['project_name'])
            
            env = os.environ.copy()
            try:
                user_env = json.loads(proj.get('env_vars', '{}'))
                for k, v in user_env.items(): env[str(k)] = str(v)
            except: pass
            
            try:
                res = subprocess.run(
                    command,
                    shell=True,
                    cwd=p_dir,
                    capture_output=True,
                    text=True,
                    timeout=25,
                    env=env
                )
                self.send_json({
                    "code": res.returncode,
                    "stdout": res.stdout,
                    "stderr": res.stderr
                })
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        # Interactive Global VPS security command executor (MAIN VPS BASH SHELL)
        if path == "/api/system/cmd":
            if not is_admin(session["user_id"]):
                self.send_json({"error": "Admin permission required"}, 403)
                return
            command = payload.get("command")
            res = execute_vps_shell(command, timeout=20)
            self.send_json(res)
            return

        # Active host process scanning tree lists
        if path == "/api/system/processes":
            if not is_admin(session["user_id"]):
                self.send_json({"error": "Admin permission required"}, 403)
                return
            discovered = scan_vps_for_foreign_services()
            self.send_json(discovered)
            return

        # Terminate hostile process PID
        if path == "/api/system/process/kill":
            if not is_admin(session["user_id"]):
                self.send_json({"error": "Admin permission required"}, 403)
                return
            target_pid = int(payload.get("pid", 0))
            try:
                parent = psutil.Process(target_pid)
                parent.kill()
                self.send_json({"success": True, "message": f"Successfully killed PID {target_pid}."})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        # Manage external systemd unit state
        if path == "/api/system/systemd":
            if not is_admin(session["user_id"]):
                self.send_json({"error": "Admin permission required"}, 403)
                return
            service = payload.get("service")
            action = payload.get("action")
            ok, response = manage_systemd_unit(service, action)
            self.send_json({"success": ok, "output": response})
            return

        self.send_response(404)
        self.end_headers()

    def get_spa_html(self, session):
        """Construct stunning dark-themed high-fidelity HTML controller panel served from RAM"""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPS Cloud Orchestrator Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: 'Inter', sans-serif;
            background-color: #0b0f19;
            color: #f3f4f6;
            overflow-x: hidden;
        }}
        .monospace {{
            font-family: 'Fira Code', monospace;
        }}
        ::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}
        ::-webkit-scrollbar-track {{
            background: #0f172a;
        }}
        ::-webkit-scrollbar-thumb {{
            background: #1e293b;
            border-radius: 4px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: #334155;
        }}
    </style>
</head>
<body class="flex flex-col min-h-screen">
    <!-- Main Top Navigation Panel Header -->
    <header class="bg-[#111827] border-b border-[#1f2937] px-6 py-4 flex flex-col sm:flex-row justify-between items-center gap-4">
        <div class="flex items-center gap-3">
            <span class="text-3xl">😈</span>
            <div>
                <h1 class="text-xl font-bold tracking-tight bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">VPS Orchestrator Console</h1>
                <p class="text-xs text-[#9ca3af]">Enterprise Virtualization Service Controller</p>
            </div>
        </div>
        <div class="flex items-center gap-4 flex-wrap justify-center">
            <span class="text-xs px-3 py-1 bg-green-500/10 text-green-400 border border-green-500/20 rounded-full font-medium">🌍 VPS IP: {VPS_PUBLIC_IP}</span>
            <span class="text-xs px-3 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded-full font-medium">👤 User: @{session["username"]}</span>
            <button onclick="logoutSession()" class="text-xs px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 transition rounded-full border border-red-500/30">🚪 Logout</button>
        </div>
    </header>

    <div class="flex-1 flex flex-col md:flex-row">
        <!-- Responsive Left Sidebar Navigation Links Dock -->
        <aside class="w-full md:w-64 bg-[#111827] border-r border-[#1f2937] p-4 space-y-2 flex-shrink-0">
            <button onclick="switchTab('dashboard')" id="btn-tab-dashboard" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-semibold rounded-xl bg-[#1f293d] text-white transition">
                📊 Infrastructure Status
            </button>
            <button onclick="switchTab('workspaces')" id="btn-tab-workspaces" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-semibold rounded-xl hover:bg-[#1f293d]/50 text-[#9ca3af] hover:text-white transition">
                📦 Code Workspaces
            </button>
            <button onclick="switchTab('vps-controls')" id="btn-tab-vps-controls" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-semibold rounded-xl hover:bg-[#1f293d]/50 text-[#9ca3af] hover:text-white transition">
                🖥️ System Daemon CLI
            </button>
            <button onclick="switchTab('deploy')" id="btn-tab-deploy" class="w-full flex items-center gap-3 px-4 py-3 text-sm font-semibold rounded-xl hover:bg-[#1f293d]/50 text-[#9ca3af] hover:text-white transition">
                🚀 Deploy Workspace
            </button>
        </aside>

        <!-- Dynamic Content Viewing Container Viewports -->
        <main class="flex-1 p-6 space-y-6 overflow-y-auto">
            
            <!-- VIEWPORT 1: INFRASTRUCTURE STATUS -->
            <section id="viewport-dashboard" class="space-y-6">
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                    <div class="bg-[#111827] border border-[#1f2937] p-5 rounded-2xl flex items-center justify-between">
                        <div>
                            <p class="text-xs text-[#9ca3af] uppercase tracking-wider">CPU Core Allocation</p>
                            <h3 class="text-2xl font-bold monospace mt-1" id="val-cpu">0.0%</h3>
                        </div>
                        <div class="text-3xl">🖥️</div>
                    </div>
                    <div class="bg-[#111827] border border-[#1f2937] p-5 rounded-2xl flex items-center justify-between">
                        <div>
                            <p class="text-xs text-[#9ca3af] uppercase tracking-wider">RAM Allocation RSS</p>
                            <h3 class="text-2xl font-bold monospace mt-1" id="val-ram">0%</h3>
                            <p class="text-[10px] text-[#9ca3af]" id="val-ram-mb">0 / 0 MB</p>
                        </div>
                        <div class="text-3xl">💾</div>
                    </div>
                    <div class="bg-[#111827] border border-[#1f2937] p-5 rounded-2xl flex items-center justify-between">
                        <div>
                            <p class="text-xs text-[#9ca3af] uppercase tracking-wider">Storage Usage</p>
                            <h3 class="text-2xl font-bold monospace mt-1" id="val-disk">0%</h3>
                            <p class="text-[10px] text-[#9ca3af]" id="val-disk-free">0 GB Free</p>
                        </div>
                        <div class="text-3xl">🗄️</div>
                    </div>
                    <div class="bg-[#111827] border border-[#1f2937] p-5 rounded-2xl flex items-center justify-between">
                        <div>
                            <p class="text-xs text-[#9ca3af] uppercase tracking-wider">Active Daemons</p>
                            <h3 class="text-2xl font-bold monospace mt-1"><span id="val-active-projs">0</span>/<span id="val-total-projs">0</span></h3>
                            <p class="text-[10px] text-[#9ca3af]">Uptime: <span id="val-uptime">0</span> Hours</p>
                        </div>
                        <div class="text-3xl">⚡</div>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div class="bg-[#111827] border border-[#1f2937] p-5 rounded-2xl space-y-4">
                        <h2 class="text-lg font-bold">🎯 Global Live Monitoring</h2>
                        <div class="h-64 relative">
                            <canvas id="loadChart"></canvas>
                        </div>
                    </div>
                    <div class="bg-[#111827] border border-[#1f2937] p-5 rounded-2xl space-y-4">
                        <div class="flex justify-between items-center">
                            <h2 class="text-lg font-bold">🛠️ active services overview</h2>
                            <button onclick="fetchProjects()" class="text-xs px-3 py-1.5 bg-[#1f293d] hover:bg-[#2d3748] rounded-xl font-semibold transition">🔄 reload list</button>
                        </div>
                        <div class="overflow-y-auto max-h-[16rem] space-y-3" id="dash-project-summaries">
                            <!-- Injected inside loading logic handlers -->
                        </div>
                    </div>
                </div>
            </section>

            <!-- VIEWPORT 2: WORKSPACE PORTFOLIO MANAGER -->
            <section id="viewport-workspaces" class="space-y-6 hidden">
                <div class="flex justify-between items-center flex-wrap gap-4">
                    <div>
                        <h2 class="text-2xl font-bold text-white">📦 Code Workspaces</h2>
                        <p class="text-xs text-[#9ca3af]">Manage your running bots, APIs, sandboxes, and ports</p>
                    </div>
                    <button onclick="switchTab('deploy')" class="px-4 py-2 bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 rounded-xl font-bold text-sm shadow-lg shadow-blue-500/15 transition">🚀 Deploy Workspace</button>
                </div>

                <div class="grid grid-cols-1 xl:grid-cols-2 gap-6" id="workspaces-cards-container">
                    <!-- Dynamic project cards go here -->
                </div>
            </section>

            <!-- VIEWPORT 3: VPS CONTROLS & BASH SUB-SHELLS -->
            <section id="viewport-vps-controls" class="space-y-6 hidden">
                <div>
                    <h2 class="text-2xl font-bold text-white">🖥️ System Daemon CLI</h2>
                    <p class="text-xs text-[#9ca3af]">Direct bash controls, systemd units, and memory process management</p>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Left: Monospace Terminal Shell -->
                    <div class="bg-[#111827] border border-[#1f2937] rounded-2xl p-5 flex flex-col h-[32rem]">
                        <h3 class="text-sm font-bold text-[#38bdf8] uppercase tracking-wider mb-3">💻 Host VPS Terminal (Bash Shell)</h3>
                        <div id="vps-cli-output" class="flex-1 bg-[#05070c] rounded-xl p-4 overflow-y-auto monospace text-xs text-[#10b981] space-y-2 mb-3">
                            <p class="text-[#9ca3af]"># Safe VPS Orchestrator Terminal Loaded.</p>
                        </div>
                        <div class="flex gap-2">
                            <input type="text" id="vps-cli-input" placeholder="Type bash command (e.g. df -h, free -m) and hit enter..." class="flex-1 bg-[#1f293d] border border-[#2d3748] rounded-xl px-4 py-2 text-xs monospace text-white focus:outline-none focus:border-[#38bdf8]" onkeydown="handleVpsCommand(event)">
                            <button onclick="sendVpsCommand()" class="px-4 py-2 bg-[#38bdf8] hover:bg-[#0ea5e9] text-black font-bold text-xs rounded-xl transition">Run</button>
                        </div>
                    </div>

                    <!-- Right: Foreign system processes scanner & Systemd units -->
                    <div class="bg-[#111827] border border-[#1f2937] rounded-2xl p-5 flex flex-col h-[32rem]">
                        <div class="flex justify-between items-center mb-3">
                            <h3 class="text-sm font-bold text-yellow-400 uppercase tracking-wider">🔍 Alien Process supervisor</h3>
                            <button onclick="scanVPSProcesses()" class="text-xs px-2.5 py-1 bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20 rounded-lg transition border border-yellow-500/20">🔄 Scan RAM</button>
                        </div>
                        <div id="vps-processes-list" class="flex-1 bg-[#161c2a] rounded-xl p-4 overflow-y-auto space-y-3">
                            <p class="text-xs text-[#9ca3af] text-center py-8">Execute scanner to locate active external processes or foreign web servers on VPS.</p>
                        </div>
                    </div>
                </div>
            </section>

            <!-- VIEWPORT 4: DEPLOY HUB -->
            <section id="viewport-deploy" class="space-y-6 hidden">
                <div class="max-w-xl mx-auto bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-5">
                    <div class="text-center">
                        <span class="text-5xl">🚀</span>
                        <h2 class="text-xl font-bold mt-2">Deploy New Workspace</h2>
                        <p class="text-xs text-[#9ca3af] mt-1">Deploy Python, Node.js, PHP CLI tasks or static HTML websites instantly</p>
                    </div>

                    <div class="space-y-4">
                        <div>
                            <label class="block text-xs text-[#9ca3af] uppercase tracking-wider font-semibold mb-1">Project Identifier Name</label>
                            <input type="text" id="dep-name" placeholder="e.g. MyAwesomeAPI" class="w-full bg-[#1f293d] border border-[#2d3748] rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500 text-white">
                        </div>

                        <div>
                            <label class="block text-xs text-[#9ca3af] uppercase tracking-wider font-semibold mb-1">Target ZIP Archive or Code script</label>
                            <div class="border-2 border-dashed border-[#2d3748] hover:border-blue-500 transition rounded-xl p-6 text-center cursor-pointer relative" id="drop-zone">
                                <input type="file" id="dep-file" class="absolute inset-0 opacity-0 cursor-pointer" onchange="handleFileSelect(event)">
                                <span class="text-3xl">📤</span>
                                <p class="text-xs text-[#9ca3af] mt-1" id="file-label-text">Drag & drop your code .zip or script file (.py, .js, .php, .html) here, or click to browse</p>
                            </div>
                        </div>

                        <button onclick="deployProject()" class="w-full py-3 bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 rounded-xl text-white font-bold text-sm tracking-wide shadow-lg shadow-blue-500/15 transition">DEPLOY TO HOST SANDBOX</button>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <!-- MODAL 1: ENVIRONMENT VARIABLES CONFIGURATOR -->
    <div id="modal-env" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 hidden">
        <div class="max-w-md w-full bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-4 shadow-2xl">
            <div class="flex justify-between items-center">
                <h3 class="text-md font-bold text-white">⚙️ Environment Variables Configurator</h3>
                <button onclick="closeModal('env')" class="text-[#9ca3af] hover:text-white text-lg">✕</button>
            </div>
            <p class="text-xs text-[#9ca3af]">Define credentials, secrets, or API configurations in valid JSON format:</p>
            <textarea id="modal-env-json" rows="8" class="w-full bg-[#161c2a] border border-[#1f2937] rounded-xl p-3 text-xs monospace focus:outline-none focus:border-[#38bdf8] text-[#10b981]" placeholder='{{"BOT_TOKEN": "123456:AABB...", "PORT": "8080"}}'></textarea>
            <div class="flex justify-end gap-3 text-xs">
                <button onclick="closeModal('env')" class="px-4 py-2 bg-[#1f293d] hover:bg-[#2d3748] rounded-xl font-bold transition">Cancel</button>
                <button onclick="saveProjectEnv()" class="px-4 py-2 bg-[#38bdf8] hover:bg-[#0ea5e9] text-black font-bold rounded-xl transition">Save Variables</button>
            </div>
        </div>
    </div>

    <!-- MODAL 2: PACKAGE MANAGER OVERLAY -->
    <div id="modal-pkg" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 hidden">
        <div class="max-w-md w-full bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-4 shadow-2xl">
            <div class="flex justify-between items-center">
                <h3 class="text-md font-bold text-white">📦 Package Manifest Manager</h3>
                <button onclick="closeModal('pkg')" class="text-[#9ca3af] hover:text-white text-lg">✕</button>
            </div>
            <div class="space-y-3">
                <div class="flex gap-2">
                    <input type="text" id="modal-pkg-name" placeholder="package_name==version (Python) or package@version (Node.js)" class="flex-1 bg-[#1f293d] border border-[#2d3748] rounded-xl px-4 py-2 text-xs focus:outline-none focus:border-[#38bdf8] text-white">
                    <button onclick="installPackage()" class="px-4 py-2 bg-[#38bdf8] hover:bg-[#0ea5e9] text-black font-bold text-xs rounded-xl transition">Install</button>
                </div>
                <div class="flex gap-2">
                    <input type="text" id="modal-pkg-del-name" placeholder="Package name to uninstall" class="flex-1 bg-[#1f293d] border border-[#2d3748] rounded-xl px-4 py-2 text-xs focus:outline-none focus:border-red-500 text-white">
                    <button onclick="uninstallPackage()" class="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 font-bold text-xs rounded-xl transition">Uninstall</button>
                </div>
            </div>
        </div>
    </div>

    <!-- MODAL 3: WORKSPACE CLI CONSOLE TERMINAL -->
    <div id="modal-cli" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 hidden">
        <div class="max-w-2xl w-full bg-[#111827] border border-[#1f2937] rounded-2xl p-5 flex flex-col h-[30rem] shadow-2xl">
            <div class="flex justify-between items-center mb-3">
                <h3 class="text-md font-bold text-white flex items-center gap-2">💻 Workspace Container CLI</h3>
                <button onclick="closeModal('cli')" class="text-[#9ca3af] hover:text-white text-lg">✕</button>
            </div>
            <div id="modal-cli-output" class="flex-1 bg-[#05070c] rounded-xl p-4 overflow-y-auto monospace text-xs text-[#10b981] space-y-2 mb-3">
                <p class="text-[#9ca3af] monospace">// CLI subshell established inside project target folder</p>
            </div>
            <div class="flex gap-2">
                <input type="text" id="modal-cli-input" placeholder="Type workspace command (e.g. ls -la, npm run build) and hit enter..." class="flex-1 bg-[#1f293d] border border-[#2d3748] rounded-xl px-4 py-2 text-xs monospace text-white focus:outline-none focus:border-[#38bdf8]" onkeydown="handleModalCliCommand(event)">
                <button onclick="sendModalCliCommand()" class="px-4 py-2 bg-[#38bdf8] hover:bg-[#0ea5e9] text-black font-bold text-xs rounded-xl transition">Run</button>
            </div>
        </div>
    </div>

    <!-- MODAL 4: RUNNER LIVE LOGS STREAMS -->
    <div id="modal-logs" class="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50 hidden">
        <div class="max-w-3xl w-full bg-[#111827] border border-[#1f2937] rounded-2xl p-5 flex flex-col h-[32rem] shadow-2xl">
            <div class="flex justify-between items-center mb-3">
                <h3 class="text-md font-bold text-white flex items-center gap-2">📋 Sandbox Active Runner Logs</h3>
                <div class="flex gap-2">
                    <button onclick="fetchActiveLogs()" class="text-xs px-2.5 py-1 bg-[#1f293d] hover:bg-[#2d3748] rounded-lg transition text-[#9ca3af]">🔄 Refresh</button>
                    <button onclick="closeModal('logs')" class="text-[#9ca3af] hover:text-white text-lg">✕</button>
                </div>
            </div>
            <pre id="modal-logs-output" class="flex-1 bg-[#05070c] rounded-xl p-4 overflow-y-auto monospace text-xs text-[#9ca3af] whitespace-pre-wrap mb-2 border border-[#1f2937]">Loading stdout streams...</pre>
        </div>
    </div>

    <!-- JAVASCRIPT LOGIC CONTROLLERS FOR DATA BINDINGS -->
    <script>
        let currentTab = 'dashboard';
        let projects = [];
        let systemStats = {{}};
        let activeModalProjectId = null;
        let selectedFileBase64 = null;
        let selectedFileName = null;
        let loadChartInstance = null;
        let cpuHistory = Array(20).fill(0);
        let memHistory = Array(20).fill(0);
        let chartLabels = Array(20).fill('');

        // Periodic diagnostic monitoring loops
        window.onload = function() {{
            initializeChart();
            fetchStats();
            fetchProjects();
            setInterval(fetchStats, 3000);
            setInterval(fetchProjects, 4000);
        }};

        function switchTab(tabId) {{
            document.querySelectorAll('main > section').forEach(el => el.classList.add('hidden'));
            document.getElementById(`viewport-${{tabId}}`).classList.remove('hidden');
            
            // Toggle sidebar button styles
            document.querySelectorAll('aside > button').forEach(el => {{
                el.classList.remove('bg-[#1f293d]', 'text-white');
                el.classList.add('hover:bg-[#1f293d]/50', 'text-[#9ca3af]');
            }});
            const activeBtn = document.getElementById(`btn-tab-${{tabId}}`);
            if (activeBtn) {{
                activeBtn.classList.add('bg-[#1f293d]', 'text-white');
                activeBtn.classList.remove('hover:bg-[#1f293d]/50', 'text-[#9ca3af]');
            }}
            currentTab = tabId;
        }}

        function fetchStats() {{
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {{
                    systemStats = data;
                    document.getElementById('val-cpu').innerText = `${{data.cpu}}%`;
                    document.getElementById('val-ram').innerText = `${{data.memory}}%`;
                    document.getElementById('val-ram-mb').innerText = `${{data.memory_mb_used}} / ${{data.memory_mb_total}} MB`;
                    document.getElementById('val-disk').innerText = `${{data.disk}}%`;
                    document.getElementById('val-disk-free').innerText = `${{data.disk_gb_free}} GB Free`;
                    document.getElementById('val-total-projs').innerText = data.total_projects;
                    document.getElementById('val-active-projs').innerText = data.running_projects;
                    document.getElementById('val-uptime').innerText = data.uptime_hours;

                    // Update live monitoring chart records
                    updateChart(data.cpu, data.memory);
                }});
        }}

        function initializeChart() {{
            const ctx = document.getElementById('loadChart').getContext('2d');
            loadChartInstance = new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: chartLabels,
                    datasets: [
                        {{
                            label: 'CPU Load %',
                            data: cpuHistory,
                            borderColor: '#38bdf8',
                            backgroundColor: 'rgba(56, 189, 248, 0.05)',
                            tension: 0.3,
                            borderWidth: 2,
                            fill: true
                        }},
                        {{
                            label: 'RAM Allocation %',
                            data: memHistory,
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.05)',
                            tension: 0.3,
                            borderWidth: 2,
                            fill: true
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{ legend: {{ labels: {{ color: '#9ca3af', font: {{ family: 'Inter' }} }} }} }},
                    scales: {{
                        y: {{ min: 0, max: 100, grid: {{ color: '#1f2937' }}, ticks: {{ color: '#9ca3af' }} }},
                        x: {{ grid: {{ display: false }}, ticks: {{ display: false }} }}
                    }}
                }}
            }});
        }}

        function updateChart(cpu, mem) {{
            if (!loadChartInstance) return;
            cpuHistory.shift();
            cpuHistory.push(cpu);
            memHistory.shift();
            memHistory.push(mem);
            loadChartInstance.update();
        }}

        function fetchProjects() {{
            fetch('/api/projects')
                .then(r => r.json())
                .then(data => {{
                    projects = data;
                    renderProjectSummaries();
                    if (currentTab === 'workspaces') {{
                        renderWorkspaces();
                    }}
                }});
        }}

        function renderProjectSummaries() {{
            const container = document.getElementById('dash-project-summaries');
            container.innerHTML = '';
            if (projects.length === 0) {{
                container.innerHTML = '<p class="text-xs text-[#9ca3af] text-center py-6">No deployed workspaces currently available.</p>';
                return;
            }}
            projects.forEach(p => {{
                const statusBadge = p.running 
                    ? '<span class="text-[10px] px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 border border-green-500/20">Active</span>'
                    : '<span class="text-[10px] px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 border border-red-500/20">Offline</span>';
                
                const portText = p.port ? `<span class="text-xs text-[#38bdf8] monospace">:${{p.port}}</span>` : '';

                const el = document.createElement('div');
                el.className = "flex justify-between items-center p-3 bg-[#161c2a] rounded-xl border border-[#1f2937]";
                el.innerHTML = `
                    <div>
                        <h4 class="text-sm font-semibold text-white flex items-center gap-1.5">${{p.project_name}} ${{portText}}</h4>
                        <p class="text-[10px] text-[#9ca3af]">${{p.framework}} • entry: ${{p.main_file}}</p>
                    </div>
                    <div>${{statusBadge}}</div>
                `;
                container.appendChild(el);
            }});
        }}

        function renderWorkspaces() {{
            const container = document.getElementById('workspaces-cards-container');
            container.innerHTML = '';
            projects.forEach(p => {{
                const statusClass = p.running ? 'bg-green-500/10 border-green-500/20 text-green-400' : 'bg-red-500/10 border-red-500/20 text-red-400';
                const statusLabel = p.running ? 'Active (Running)' : 'Offline (Stopped)';
                const btnStateLabel = p.running ? '⏹️ STOP WORKER' : '▶️ BOOT WORKER';
                
                const apiLink = p.port 
                    ? `<div class="bg-[#161c2a] border border-[#1f2937] p-3 rounded-xl flex items-center justify-between text-xs mt-3">
                         <span class="text-[#9ca3af]">🌐 Live Endpoint:</span>
                         <a href="http://${{systemStats.vps_ip || 'localhost'}}:${{p.port}}" target="_blank" class="text-cyan-400 hover:underline monospace font-medium">http://${{systemStats.vps_ip || 'localhost'}}:${{p.port}}</a>
                       </div>`
                    : '';

                const resourceUsage = p.running
                    ? `<div class="grid grid-cols-2 gap-3 text-xs border-t border-[#1f2937]/50 pt-3 mt-3">
                         <div>
                            <span class="text-[#9ca3af]">CPU Allocation:</span>
                            <span class="text-white monospace ml-1 font-bold">${{p.cpu_usage || 0}}%</span>
                         </div>
                         <div>
                            <span class="text-[#9ca3af]">Memory RSS:</span>
                            <span class="text-white monospace ml-1 font-bold">${{p.ram_usage || 0}} MB</span>
                         </div>
                       </div>`
                    : '';

                const el = document.createElement('div');
                el.className = "bg-[#111827] border border-[#1f2937] rounded-2xl p-5 space-y-4 shadow-xl";
                el.innerHTML = `
                    <div class="flex justify-between items-start flex-wrap gap-2">
                        <div>
                            <h3 class="text-lg font-bold text-white flex items-center gap-2">${{p.project_name}} <span class="text-[10px] uppercase font-semibold text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">${{p.framework}}</span></h3>
                            <p class="text-xs text-[#9ca3af]">Sandbox ID: <code>${{p.id}}</code> | Main Executable: <code>${{p.main_file}}</code></p>
                        </div>
                        <span class="text-xs px-3 py-1.5 rounded-full border ${{statusClass}} font-semibold">${{statusLabel}}</span>
                    </div>

                    ${{apiLink}}
                    ${{resourceUsage}}

                    <div class="border-t border-[#1f2937]/50 pt-4 flex flex-wrap gap-2 text-xs font-semibold">
                        <button onclick="triggerControl(${{p.id}}, '${{p.running ? 'stop' : 'start'}}')" class="px-3.5 py-2 bg-[#1f293d] hover:bg-[#2d3748] rounded-xl transition flex-1 text-center min-w-[7rem]">${{btnStateLabel}}</button>
                        <button onclick="openModal('env', ${{p.id}})" class="px-3.5 py-2 bg-[#1f293d] hover:bg-[#2d3748] rounded-xl transition">⚙️ Config Env</button>
                        <button onclick="openModal('pkg', ${{p.id}})" class="px-3.5 py-2 bg-[#1f293d] hover:bg-[#2d3748] rounded-xl transition">📦 Packages</button>
                        <button onclick="openModal('cli', ${{p.id}})" class="px-3.5 py-2 bg-[#1f293d] hover:bg-[#2d3748] rounded-xl transition">💻 CLI Shell</button>
                        <button onclick="openModal('logs', ${{p.id}})" class="px-3.5 py-2 bg-[#1f293d] hover:bg-[#2d3748
