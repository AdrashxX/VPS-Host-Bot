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
import http.client
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
        ["🧹 CLEAR LOGS"]
    ] if is_admin(user_id) else [
        ["🚀 HOST BOT", "📊 MY PROJECTS"]
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
        f"• Automated cluster state recovery\n\n"
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
        f"• Authorization Level: <code>{'👑 Owner' if user_id == OWNER_ID else '🔧 Admin' if is_admin(user_id) else '✅ Premium Client'}</code>"
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
        # Resolve request pathways natively using python's built-in http.client 
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
        proj_row = conn.execute("SELECT * VALUES FROM projects WHERE id = ?", (project_id,)).fetchone()
        
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
    # If a port is bound, provide direct connection test options
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
        # Map port binding to system-level port variables
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
        
        # Determine frameworks and auto-allocate API ports if web scripts detected
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
        "🖥️ SYSTEM STATUS", "👥 USER MANAGEMENT", "🧹 CLEAR LOGS"
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

# ===== SYSTEM APPLICATION INCEPTION =====
def main():
    check_single_instance()
    apply_schema_migrations()
    init_advanced_database()
    
    # Resolve and cache VPS Public IP for accurate API endpoints
    resolve_vps_public_ip()
    
    # Run state recovery sequence inside background threads
    threading.Thread(target=auto_start_all_projects, daemon=True).start()
    
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .connection_pool_size(12)
        .connect_timeout(35.0)
        .read_timeout(35.0)
        .write_timeout(35.0)
        .pool_timeout(35.0)
        .build()
    )
    
    async def post_init_setup(application: Application) -> None:
        asyncio.create_task(run_auto_provisioner_async(application.bot))
        
    app.post_init = post_init_setup
    app.add_error_handler(global_exception_handler)
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("promo", promo_command))
    app.add_handler(CommandHandler("limit", limit_command))
    app.add_handler(CommandHandler("addadmin", add_admin_command))
    app.add_handler(CommandHandler("refresh", refresh_command))
    app.add_handler(CommandHandler("install_deps", install_deps_command))
    app.add_handler(CommandHandler("systemd", systemd_action_handler))
    
    app.add_handler(MessageHandler(filters.Document.ALL, file_upload_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    
    app.add_handler(CallbackQueryHandler(self_cb_management, pattern="^self_"))
    app.add_handler(CallbackQueryHandler(button_callback_handler))
    
    logger.info("⚡ System Operational core up and serving updates...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
