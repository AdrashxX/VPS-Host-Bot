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
from datetime import datetime, timedelta
import psutil
import subprocess

# Safe dynamic guard checking and installing of core library dependencies
try:
    from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
    from telegram.constants import ParseMode
    from telegram.error import BadRequest, Conflict, InvalidToken, NetworkError
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "python-telegram-bot==20.7"], check=True)
    from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
    from telegram.constants import ParseMode
    from telegram.error import BadRequest, Conflict, InvalidToken, NetworkError

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
                pid = p_id = pinfo = pinfo_cmd = None
                
                # Retrieve process metadata
                pid = u_pid = p_id = p_id_val = p_info_val = pinfo = u_pid = u_p_id = u_p = p = p_pid_val = p_id_val = None
                pid = u_pid = p_id = p_id_str = p_val = p_row = p_row_obj = p_row_data = p_row_val = p_row_val_str = p_row_val_data = None
                
                pid = p_id = proc.pid
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
                    reason = "Foreign Telegram/Discord Bot"
                    framework = "Node.js" if "node" in cmd_str else "Python"
                elif any(x in cmd_str for x in ["uvicorn", "gunicorn", "flask", "fastapi", "django", "express", "nodemon", "pm2", "php -s"]):
                    is_foreign = True
                    reason = "Running Web API Server"
                    framework = "PHP" if "php" in cmd_str else "Node.js" if "node" in cmd_str else "Python"
                elif ("python" in cmd_str or "node" in cmd_str or "php" in cmd_str) and any(x in cmd_str for x in ["api", "server", "app", "main"]):
                    is_foreign = True
                    reason = "Generic Script (App/API Execution)"
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
                alert = f"🚨 <b>UNAUTHORIZED REGISTRATION ALERT</b>\n\n👤 User: {username_display}\n🆔 ID: <code>{user_id}</code>\n\nWhitelist using command: <code>/limit {user_id} [limit]</code>"
                await context.bot.send_message(OWNER_ID, alert, parse_mode=ParseMode.HTML)
            except Exception as e:
                logger.error(f"Owner notification failure: {e}")

    # Build Admin navigation with shortened SELF-MGMT title
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
    promo = f"😈 <b>VPS ORCHESTRATOR & SERVICE MASTER</b>\n\n" \
            f"⚡ **Enterprise Grade Capabilities Enabled:**\n" \
            f"• Isolated sandboxed runtime execution environments\n" \
            f"• Systemd daemon units supervisor integration\n" \
            f"• Advanced Shell command processor interface\n" \
            f"• Supports: Python (.py), Node.js (.js), PHP (.php), HTML (.html)\n" \
            f"• Secure live Git updating and Hot-Reboots\n\n" \
            f"🔒 <b>Whitelisted Admins & Approved Clients Only</b>\n" \
            f"👤 <b>Developed by:</b> HmGamer (@EliteHM)"
            
    await update.message.reply_text(promo, parse_mode=ParseMode.HTML)
    
    if not has_access(user_id):
        await update.message.reply_text(
            f"❌ <b>Access Denied</b>\n\nYour account must be manually whitelisted by HmGamer.\nYour ID: <code>{user_id}</code>",
            reply_markup=kb, parse_mode=ParseMode.HTML
        )
        return

    welcome = f"📊 <b>VPS HOSTING DASHBOARD ACTIVE</b>\n\n" \
              f"Welcome back <b>{username_display}</b>!\n\n" \
              f"📈 <b>Statistics:</b>\n" \
              f"• Account Limit: {get_user_limit(user_id)}\n" \
              f"• Account Class: {'👑 Owner' if user_id == OWNER_ID else '🔧 Admin' if is_admin(user_id) else '✅ Approved Premium Client'}"
              
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
        f"🚀 <b>VPS ENVIRONMENT DEPLOYMENT MANAGER</b>\n\n"
        f"Please upload your configuration code as a <code>.zip</code> archive package.\n\n"
        f"📋 <b>Requirements by File Type:</b>\n"
        f"• <b>Python (.py)</b>: Entrypoint script (main.py/bot.py) + <code>requirements.txt</code>\n"
        f"• <b>Node.js (.js)</b>: Entrypoint (main.js/index.js) + <code>package.json</code>\n"
        f"• <b>PHP (.php)</b>: Runs as web-daemon or CLI worker. Composer supported.\n"
        f"• <b>Static HTML (.html)</b>: Fast static asset server deployed automatically.\n\n"
        f"⚙️ Supported Runtimes:\n"
        f"{py_versions}"
        f"• Node.js: {nodejs_info}\n\n"
        f"📤 <b>Send the ZIP file now:</b>",
        parse_mode=ParseMode.HTML
    )

# ===== CONSOLE-DRIVEN MY PROJECTS UI =====
async def list_bots_command(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 1):
    user_id = update.effective_user.id
    if not has_access(user_id):
        await send_response(update, "❌ Access Denied")
        return
        
    is_admin_flag = is_admin(user_id)
    PER_PAGE = 10
    
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
        await send_response(update, f"📁 <b>BOT PORTFOLIO MANAGER</b>\n\nAccount limit: {get_user_limit(user_id)}\nDeployments: 0\n\n🚀 Hit 'HOST BOT' to load code packages.")
        return

    header = f"👑 <b>ADMIN SYSTEM CONSOLE BOARD</b>" if is_admin_flag else f"📁 <b>YOUR DEPLOYED SERVICES</b>"
    text = f"{header}\n\nSelect a project workspace from the list below to access its console, edit environments, or execute terminal commands:\n\n"
    
    buttons = []
    # Render projects as clean, selectable console blocks
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
    
    # 👑 Main Admin Exclusive VPS Active Service Integration Interface
    if is_admin_flag:
        buttons.append([InlineKeyboardButton("🔍 SCAN FOR OTHER ACTIVE BOTS / APIs", callback_data="sys_scan_proc")])
        
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
    status_label = "🟢 ACTIVE (Running)" if running else "🔴 OFFLINE (Stopped)"
    
    # Detailed runtime metadata
    stats_text = ""
    if running:
        info = get_process_info(project_id)
        if info:
            stats_text = f"💻 <b>CPU Usage:</b> {info['cpu_percent']:.1f}%\n" \
                         f"💾 <b>RAM usage:</b> {info['memory_mb']:.1f} MB\n" \
                         f"🔢 <b>Process PID:</b> <code>{info['pid']}</code>\n"
                         
    port_text = f"<code>{proj['port']}</code>" if proj['port'] else "N/A"
    
    console_view = (
        f"📦 <b>CLOUD WORKSPACE CONSOLE</b>\n"
        f"---------------------------------------\n"
        f"🛠️ <b>Service:</b> <code>{proj['project_name']}</code>\n"
        f"🆔 <b>Workspace ID:</b> <code>{proj['id']}</code>\n"
        f"⚡ <b>Status:</b> {status_label}\n"
        f"📋 <b>Engine Type:</b> {proj['framework']}\n"
        f"🌐 <b>Port Binding:</b> {port_text}\n"
        f"🕒 <b>Last Launched:</b> {proj['last_started'] or 'Never'}\n\n"
        f"{stats_text}"
        f"---------------------------------------\n"
        f"👉 <b>Choose Console Operation:</b>"
    )
    
    buttons = [
        [
            InlineKeyboardButton("⏹️ STOP WORKER" if running else "▶️ START WORKER", callback_data=f"pstate_{project_id}"),
            InlineKeyboardButton("⚙️ ENV VARS", callback_data=f"p_env_{project_id}")
        ],
        [
            InlineKeyboardButton("💻 CONTAINER CLI", callback_data=f"p_cli_{project_id}"),
            InlineKeyboardButton("📋 LIVE LOGS", callback_data=f"p_logs_{project_id}")
        ],
        [
            InlineKeyboardButton("🧹 AUTO BUILD", callback_data=f"p_build_{project_id}"),
            InlineKeyboardButton("🗑️ PURGE WORKSPACE", callback_data=f"p_purge_{project_id}")
        ],
        [InlineKeyboardButton("🔙 BACK TO PORTFOLIO", callback_data="refresh_projects")]
    ]
    
    await send_response(update, console_view, reply_markup=InlineKeyboardMarkup(buttons))

# ===== EXECUTOR LAUNCH PIPELINE WITH MULTI-LANGUAGE DEPS =====
def start_project_worker(project_id, chat_id, loop, bot):
    """Robust dynamic worker loader launching environments and installing missing modules"""
    def push_msg(msg):
        if not bot or not loop or not chat_id: return
        try:
            asyncio.run_coroutine_threadsafe(
                bot.send_message(chat_id, msg, parse_mode=ParseMode.HTML), loop
            ).result(timeout=10)
        except Exception as e:
            logger.error(f"Worker communication failure: {e}")

    try:
        with get_db_connection() as conn:
            fresh = conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not fresh: return
        
        project = dict(fresh)
        p_name = project['project_name']
        p_dir = project_folder(project['user_id'], p_name)
        log_file = os.path.join(LOG_DIR, f"project_{project_id}.txt")
        
        # Configure env variables safely
        env = os.environ.copy()
        env['BOT_HOSTING_PLATFORM'] = 'True'
        if 'BOT_TOKEN' in env: env.pop('BOT_TOKEN')
        if project['port']: env['PORT'] = str(project['port'])
        
        try:
            user_env_data = json.loads(project.get('env_vars', '{}'))
            for k, v in user_env_data.items():
                env[str(k)] = str(v)
        except Exception as e:
            logger.warning(f"Failed loading env variables for {p_name}: {e}")
        
        # Multi-Language Automated Dependency Builder
        if not project['deps_installed']:
            push_msg(f"🛠️ [{p_name}] System analyzing packages & triggering automated dependency builder...")
            
            # 1. Node.js Runtimes
            if project['framework'] == "Node.js" and os.path.exists(os.path.join(p_dir, 'package.json')):
                push_msg(f"⚡ Running npm installation sequences for <code>{p_name}</code>...")
                try:
                    res = subprocess.run(["npm", "install", "--no-audit", "--no-fund"], cwd=p_dir, capture_output=True, text=True, timeout=300)
                    if res.returncode == 0:
                        push_msg("✅ npm installation sequence completed.")
                    else:
                        logger.warning(f"npm install alert: {res.stderr}")
                except Exception as e:
                    push_msg(f"⚠️ npm installation warning: {e}")
                    
            # 2. PHP Composer Support
            elif project['framework'] == "PHP" and os.path.exists(os.path.join(p_dir, 'composer.json')):
                push_msg(f"⚡ Running Composer workspace installation patterns for <code>{p_name}</code>...")
                try:
                    res = subprocess.run(["composer", "install", "--no-interaction", "--ignore-platform-reqs"], cwd=p_dir, capture_output=True, text=True, timeout=300)
                    if res.returncode == 0:
                        push_msg("✅ Composer resolved dependencies successfully.")
                except Exception as e:
                    push_msg(f"⚠️ Composer launcher omitted: {e}")
                    
            # 3. Python Virtualenv installs
            elif project['framework'] == "Python":
                req_file = find_requirements_txt(p_dir)
                if req_file:
                    push_msg(f"⚡ Building PyPI dependencies from requirements.txt...")
                    try:
                        res = subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file], capture_output=True, text=True, timeout=300)
                        if res.returncode != 0:
                            # Fallback
                            subprocess.run(["pip3", "install", "-r", req_file], timeout=300)
                        push_msg("✅ Python package configurations established.")
                    except Exception as e:
                        push_msg(f"⚠️ pip installation wrapper warning: {e}")
                        
            # Set deployment dependencies as loaded
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET deps_installed = 1 WHERE id = ?", (project_id,))
                conn.commit()

        # Generate Launcher Commands based on engine architectures
        main_file = project['main_file']
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
            push_msg(f"❌ [{p_name}] Launch command configuration could not be generated.")
            return
            
        with open(log_file, 'a') as lf:
            lf.write(f"\n=== LAUNCH WORKER ACTIVE AT {datetime.now()} ===\n")
            lf.write(f"Launch command: {' '.join(cmd_args)}\n")
            proc = subprocess.Popen(
                cmd_args, cwd=p_dir, stdout=lf, stderr=lf, env=env
            )
            
        running_processes[project_id] = proc.pid
        with get_db_connection() as conn:
            conn.execute("UPDATE projects SET status = 'running', last_started = CURRENT_TIMESTAMP WHERE id = ?", (project_id,))
            conn.execute("INSERT OR REPLACE INTO process_monitoring (project_id, pid, start_time) VALUES (?, ?, CURRENT_TIMESTAMP)", (project_id, proc.pid))
            conn.commit()
            
        push_msg(f"🟢 [{p_name}] Workspace runner successfully spawned (PID: {proc.pid})")
    except Exception as e:
        logger.error(f"Sandbox runner spawning crashed: {e}", exc_info=True)
        push_msg(f"❌ Launcher engine breakdown: {e}")

# ===== DEPLOYMENT HANDLERS WITH ALL-LANGUAGE SUPPORT =====
async def file_upload_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    # Handle direct codebase upgrades of the host orchestrator itself via ZIP upload
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
        await update.message.reply_text("❌ Action invalid. Trigger 'HOST BOT' menu first.")
        return
        
    if not has_access(user_id):
        await update.message.reply_text("❌ Access Denied. Whitelisting required.")
        return
        
    doc = update.message.document
    if not doc or not doc.file_name.endswith('.zip'):
        await update.message.reply_text("❌ Package format rejected. Please send `.zip` package format.")
        return
        
    if doc.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(f"❌ Package limits overflow. Limit: {MAX_FILE_SIZE_MB}MB")
        return
        
    p_msg = await update.message.reply_text("📥 Extracting incoming file structures...")
    
    try:
        tg_file = await context.bot.get_file(doc.file_id)
        archive_path = os.path.join(TEMP_DIR, f"{user_id}_{doc.file_name}")
        await tg_file.download_to_drive(archive_path)
        
        p_name = re.sub(r'[^a-zA-Z0-9_-]', '', doc.file_name.replace('.zip', ''))
        extract_dir = os.path.join(TEMP_DIR, f"ext_{user_id}_{p_name}")
        
        with zipfile.ZipFile(archive_path, 'r') as zf:
            zf.extractall(extract_dir)
            
        main_file = find_main_file(extract_dir)
        if not main_file:
            shutil.rmtree(extract_dir, ignore_errors=True)
            os.remove(archive_path)
            await p_msg.edit_text("❌ Launch configuration main entrypoint file absent. Please verify script entrypoint files exist.")
            return
            
        types = detect_project_type(extract_dir, main_file)
        dest_dir = project_folder(user_id, p_name)
        if os.path.exists(dest_dir): shutil.rmtree(dest_dir)
        shutil.move(extract_dir, dest_dir)
        create_sandbox_environment(dest_dir)
        
        # Engine Classification Resolving
        framework = "Unknown"
        port = None
        
        if main_file.endswith('.py'):
            framework = "Python"
        elif main_file.endswith(('.js', '.ts')):
            framework = "Node.js"
        elif main_file.endswith('.php'):
            framework = "PHP"
            if os.path.exists(os.path.join(dest_dir, "index.php")) or "index" in main_file:
                port = find_available_port()
        elif main_file.endswith(('.html', '.htm')):
            framework = "Static HTML"
            port = find_available_port()
            
        with get_db_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO projects (user_id, project_name, main_file, framework, project_type, port, deps_installed)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (user_id, p_name, main_file, framework, ','.join(types), port))
            project_id = cursor.lastrowid
            conn.commit()
            
        os.remove(archive_path)
        
        await p_msg.edit_text(
            f"✅ <b>WORKSPACE INITIALIZED SUCCESSFULLY!</b>\n\n"
            f"• <b>Project Name:</b> <code>{p_name}</code>\n"
            f"• <b>Engine Class:</b> {framework}\n"
            f"• <b>Entry Launch File:</b> <code>{main_file}</code>\n\n"
            f"⚙️ Running dependencies manager & launching worker process safely..."
        )
        
        loop = asyncio.get_running_loop()
        threading.Thread(
            target=start_project_worker,
            args=(project_id, p_msg.chat.id, loop, context.bot),
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
        
    # Process scan triggers for other host-level bots and active APIs
    if data == "sys_scan_proc":
        if not is_admin(user_id): return
        p_msg = await context.bot.send_message(query.message.chat.id, "🔍 <i>Deep-scanning host memory spaces for foreign services and listening APIs...</i>", parse_mode=ParseMode.HTML)
        discovered = scan_vps_for_foreign_services()
        
        if not discovered:
            await p_msg.edit_text("✅ <b>Scan Complete:</b> No external bots or active APIs detected.")
            return
            
        report = f"🔍 <b>VPS ALIEN SERVICE REPORT ({len(discovered)} Found)</b>\n\n"
        buttons = []
        
        for d in discovered:
            report += f"⚙️ <b>PID:</b> <code>{d['real_pid']}</code>\n" \
                      f"• <b>Class:</b> {d['project_type']}\n" \
                      f"• <b>Command:</b> <code>{html.escape(d['cmdline'][:100])}</code>\n" \
                      f"• <b>Active Port:</b> <code>{d['port'] or 'N/A'}</code>\n\n"
                      
            buttons.append([
                InlineKeyboardButton(f"🚨 KILL PID {d['real_pid']}", callback_data=f"killproc_{d['real_pid']}"),
                InlineKeyboardButton(f"📥 REGISTER", callback_data=f"regproc_{d['real_pid']}")
            ])
            
        buttons.append([InlineKeyboardButton("🔙 BACK TO PORTFOLIO", callback_data="refresh_projects")])
        await p_msg.delete()
        await context.bot.send_message(query.message.chat.id, report, reply_markup=InlineKeyboardMarkup(buttons), parse_mode=ParseMode.HTML)
        return

    # Process direct manual termination of external discovered PIDs
    if data.startswith("killproc_"):
        if not is_admin(user_id): return
        target_pid = int(data.split("_")[1])
        try:
            parent = psutil.Process(target_pid)
            parent.kill()
            await context.bot.send_message(query.message.chat.id, f"✅ <b>Process {target_pid} terminated successfully.</b>", parse_mode=ParseMode.HTML)
        except Exception as e:
            await context.bot.send_message(query.message.chat.id, f"❌ Failed to kill process {target_pid}: {e}", parse_mode=ParseMode.HTML)
        return

    # Process dynamic registration of discovered external systems
    if data.startswith("regproc_"):
        if not is_admin(user_id): return
        target_pid = int(data.split("_")[1])
        try:
            proc = psutil.Process(target_pid)
            cmdline = proc.cmdline()
            cmd_str = " ".join(cmdline)
            cwd = proc.cwd()
            
            p_name = f"IMPORTED_{target_pid}"
            main_file = cmdline[-1] if len(cmdline) > 0 else "main.py"
            framework = "External (Node.js)" if "node" in cmd_str else "External (PHP)" if "php" in cmd_str else "External (Python)"
            
            with get_db_connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO projects (user_id, project_name, main_file, framework, project_type, status, deps_installed)
                    VALUES (?, ?, ?, ?, ?, 'running', 1)
                """, (OWNER_ID, p_name, main_file, framework, "Imported Service"))
                project_id = cursor.lastrowid
                conn.commit()
                
            # Bind running state mapping locally
            running_processes[project_id] = target_pid
            
            await context.bot.send_message(query.message.chat.id, f"✅ <b>Imported successfully!</b> Project registered under name <code>{p_name}</code>.", parse_mode=ParseMode.HTML)
        except Exception as e:
            await context.bot.send_message(query.message.chat.id, f"❌ Failed to import process: {e}", parse_mode=ParseMode.HTML)
        return

    # Project Dashboard Console Callback Actions
    if data.startswith(("pstate_", "p_env_", "p_cli_", "p_logs_", "p_build_", "p_purge_")):
        action, p_id_str = data.split("_", 1)
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
                await query.message.reply_text(f"⏹️ Project {proj['project_name']} stopped.")
            else:
                loop = asyncio.get_running_loop()
                threading.Thread(
                    target=start_project_worker,
                    args=(p_id, query.message.chat.id, loop, context.bot),
                    daemon=True
                ).start()
                await query.message.reply_text(f"▶️ Starting project {proj['project_name']} worker process...")
                
        elif action == "p_env":
            user_states[user_id] = {"awaiting_env_vars": True, "project_id": p_id}
            await context.bot.send_message(
                query.message.chat.id,
                f"⚙️ <b>CONFIGURING ENV FOR: {proj['project_name']}</b>\n\n"
                f"Please send the environment variables in valid JSON format. Example:\n"
                f"<code>{{\"DATABASE_URL\": \"sqlite://...\", \"PORT\": \"8080\"}}</code>",
                parse_mode=ParseMode.HTML
            )
            return
            
        elif action == "p_cli":
            user_states[user_id] = {"awaiting_project_cli": True, "project_id": p_id}
            p_dir = project_folder(proj['user_id'], proj['project_name'])
            await context.bot.send_message(
                query.message.chat.id,
                f"💻 <b>PROJECT CONTAINER TERMINAL ACTIVE</b>\n\n"
                f"📂 <b>Workspace Directory:</b>\n<code>{p_dir}</code>\n\n"
                f"You can now execute terminal commands (e.g. <code>ls -la</code>, <code>npm run build</code>, <code>composer update</code>) directly inside this folder context.\n"
                f"👉 Send <code>exit</code> to stop.",
                parse_mode=ParseMode.HTML
            )
            return
            
        elif action == "p_logs":
            log_file = os.path.join(LOG_DIR, f"project_{p_id}.txt")
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    logs_data = f.read()[-3000:]
                await query.message.reply_text(f"📋 <b>Runner Logs for {proj['project_name']}:</b>\n\n<pre>{html.escape(logs_data)}</pre>", parse_mode=ParseMode.HTML)
            else:
                await query.message.reply_text("📋 Logs database empty for this workspace.")
                
        elif action == "p_build":
            stop_process(p_id)
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET deps_installed = 0 WHERE id = ?", (p_id,))
                conn.commit()
            loop = asyncio.get_running_loop()
            threading.Thread(
                target=start_project_worker,
                args=(p_id, query.message.chat.id, loop, context.bot),
                daemon=True
            ).start()
            await query.message.reply_text(f"🧹 Workspace dependencies build queued for <code>{proj['project_name']}</code>.", parse_mode=ParseMode.HTML)
            
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
                
            await query.message.reply_text(f"🗑️ Purged project <code>{proj['project_name']}</code> workspace fully.", parse_mode=ParseMode.HTML)
            await list_bots_command(update, context)
            return

        # Return back into project console automatically
        await asyncio.sleep(1.2)
        try:
            await show_project_console(update, context, p_id)
        except Exception:
            pass

# ===== VPS CONTROLS & DAE MON INTERFACES =====
async def systemd_action_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    if len(context.args) < 2:
        await update.message.reply_text("❌ Usage: <code>/systemd [action] [service_name]</code>", parse_mode=ParseMode.HTML)
        return
    
    action, service = context.args[0], context.args[1]
    ok, response = manage_systemd_unit(service, action)
    output = f"🗳️ <b>SYSTEMD OPERATION OUTPUT:</b>\n\n<pre>{html.escape(response or '')}</pre>"
    await update.message.reply_text(output, parse_mode=ParseMode.HTML)

async def exec_shell_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    user_states[user_id] = {"awaiting_shell_cmd": True}
    await update.message.reply_text(
        "💻 <b>VPS DIRECT BASH SHELL TERMINAL ACTIVE</b>\n\n"
        "Send any bash command to execute it directly on the server. Send <code>exit</code> to stop.",
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
        "⚙️ <b>BOT SELF-MANAGEMENT CONTROL PANEL</b>\n\n"
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
            f"📋 <b>Bot Core Host Logs:</b>\n\n<pre>{html.escape(log_data)}</pre>",
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
        f"🖥️ <b>VPS CORE SYSTEM STATUS</b>\n\n"
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
        
    text = "👥 <b>PLATFORM CLIENT MANAGEMENT</b>\n\n"
    for u in users:
        limit_lbl = "🔧 Admin" if u['file_limit'] == -1 else str(u['file_limit'])
        text += f"• <code>{u['user_id']}</code> | @{u['username'] or 'Unknown'} | Access: {limit_lbl}\n"
        
    text += f"\n👉 Admin Commands:\n" \
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
    
    # Block non-owners from promoting admins via /limit
    if limit == -1 and user_id != OWNER_ID:
        await update.message.reply_text("❌ <b>Access Denied</b>\nOnly the supreme Platform Owner HmGamer can promote users to administrators.", parse_mode=ParseMode.HTML)
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
        await update.message.reply_text("❌ <b>Unauthorized Action</b>\nOnly the supreme Platform Owner HmGamer can add new administrators.", parse_mode=ParseMode.HTML)
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
    
    # 🌟 KEYBOARD MENU INTERCEPTOR: Safe drop of subshell/env states on button clicks
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
    
    # 💻 INTERACTIVE SCOPED CONTAINER CLI TERMINAL
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
            import subprocess
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
            await p_msg.edit_text("❌ Subshell execution timed out (25s ceiling limit reached).")
        except Exception as e:
            await p_msg.edit_text(f"❌ Subshell execution error: {e}")
        return

    # Process secure standard terminal inputs
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
        
    # Process environmental dynamic updates JSON formats
    if user_id in user_states and user_states[user_id].get("awaiting_env_vars"):
        proj_id = user_states[user_id]["project_id"]
        try:
            parsed_data = json.loads(text)
            serialized = json.dumps(parsed_data)
            
            with get_db_connection() as conn:
                conn.execute("UPDATE projects SET env_vars = ? WHERE id = ?", (serialized, proj_id))
                conn.commit()
                
            await update.message.reply_text("✅ Project environment configuration saved. Choose 'AUTO BUILD' or restart the project to load variables.")
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
        
    # Default fallback
    await update.message.reply_text("🤖 Use platform menu or /start for assistance.", parse_mode=ParseMode.HTML)

# ===== BACKGROUND SERVICE LOOPS =====
def auto_start_all_projects():
    try:
        with get_db_connection() as conn:
            projs = conn.execute("SELECT * FROM projects WHERE auto_restart = 1 AND status = 'stopped'").fetchall()
        for p in projs:
            threading.Thread(target=start_project_worker, args=(p['id'], None, None, None), daemon=True).start()
            time.sleep(2)
    except Exception as e:
        logger.error(f"Auto-restart routine issue: {e}")

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
    
    # Run auto start sequence in thread
    threading.Thread(target=auto_start_all_projects, daemon=True).start()
    
    # Set up the base application with the custom HTTPX connection configurations
    # We construct them via the builder directly so they lazy-initialize within the proper event loop.
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .connection_pool_size(10)
        .connect_timeout(30.0)
        .read_timeout(30.0)
        .write_timeout(30.0)
        .pool_timeout(30.0)
        .build()
    )
    
    # 🌟 NATIVE POST_INIT HOOK REGISTRATION
    # We register the async auto provisioner task as a post-init task. This executes it natively
    # inside the main thread's asyncio event loop, safely sharing PTB's event loop structure.
    async def post_init_setup(application: Application) -> None:
        asyncio.create_task(run_auto_provisioner_async(application.bot))
        
    app.post_init = post_init_setup
    
    # Bind custom resiliency error callback to silence HTTPX ReadError drops
    app.add_error_handler(global_exception_handler)
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("promo", promo_command))
    app.add_handler(CommandHandler("limit", limit_command))
    app.add_handler(CommandHandler("addadmin", add_admin_command))
    app.add_handler(CommandHandler("refresh", refresh_command))
    app.add_handler(CommandHandler("install_deps", install_deps_command))
    app.add_handler(CommandHandler("systemd", systemd_action_handler))
    
    app.add_handler(MessageHandler(filters.Document.ZIP, file_upload_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_handler))
    
    app.add_handler(CallbackQueryHandler(self_cb_management, pattern="^self_"))
    app.add_handler(CallbackQueryHandler(button_callback_handler))
    
    logger.info("⚡ System Operational core up and serving updates...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
