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
from datetime import datetime
import psutil

# Safe dynamic guard checking and installing of core library dependency
try:
    from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
    from telegram.constants import ParseMode
    from telegram.error import BadRequest, Conflict, InvalidToken
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "python-telegram-bot==20.7"], check=True)
    from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup, InlineKeyboardButton, Bot
    from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
    from telegram.constants import ParseMode
    from telegram.error import BadRequest, Conflict, InvalidToken

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
    install_dependencies, execute_vps_shell, hot_reboot_bot, manage_systemd_unit
)

logger = setup_advanced_logging()

# User navigation tracking states
user_states = {}
broadcast_states = {}

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

    # Build Admin navigation including Host Controls and Core VPS managers
    buttons = [
        ["🚀 HOST BOT", "📊 MY PROJECTS"],
        ["🖥️ VPS CONTROLS", "⚙️ BOT SELF-MANAGEMENT"],
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
        f"📋 <b>Requirements:</b>\n"
        f"• Must hold a clear launch entrypoint (e.g. main.py, bot.py, app.js)\n"
        f"• Maximum archive limit: {MAX_FILE_SIZE_MB}MB\n"
        f"• <code>requirements.txt</code> (Python) or <code>package.json</code> (Node.js) must be populated\n\n"
        f"⚙️ Supported Engines:\n"
        f"{py_versions}"
        f"• Node.js: {nodejs_info}\n\n"
        f"📤 <b>Send the ZIP file now:</b>",
        parse_mode=ParseMode.HTML
    )

async def list_bots_command(update: Update, context: ContextTypes.DEFAULT_TYPE, page: int = 1):
    user_id = update.effective_user.id
    if not has_access(user_id):
        await send_response(update, "❌ Access Denied")
        return
        
    is_admin_flag = is_admin(user_id)
    PER_PAGE = 15
    
    with get_db_connection() as conn:
        if is_admin_flag:
            total_count = conn.execute("SELECT COUNT(*) as count FROM projects").fetchone()['count']
            projects = conn.execute("""
                SELECT p.*, u.username, pm.pid, pm.cpu_usage, pm.memory_usage 
                FROM projects p 
                LEFT JOIN users u ON p.user_id = u.user_id
                LEFT JOIN process_monitoring pm ON p.id = pm.project_id
                ORDER BY p.created_at DESC LIMIT ? OFFSET ?
            """, (PER_PAGE, (page-1)*PER_PAGE)).fetchall()
        else:
            total_count = conn.execute("SELECT COUNT(*) as count FROM projects WHERE user_id = ?", (user_id,)).fetchone()['count']
            projects = conn.execute("""
                SELECT p.*, pm.pid, pm.cpu_usage, pm.memory_usage 
                FROM projects p 
                LEFT JOIN process_monitoring pm ON p.id = pm.project_id
                WHERE p.user_id = ? 
                ORDER BY p.created_at DESC LIMIT ? OFFSET ?
            """, (user_id, PER_PAGE, (page-1)*PER_PAGE)).fetchall()

    total_pages = max(1, (total_count + PER_PAGE - 1) // PER_PAGE)
    if not projects and page == 1:
        await send_response(update, f"📁 <b>BOT PORTFOLIO MANAGER</b>\n\nAccount limit: {get_user_limit(user_id)}\nDeployments: 0\n\n🚀 Hit 'HOST BOT' to load code packages.")
        return

    header = f"👑 <b>ADMIN PORTFOLIO CONTROL BOARD</b>" if is_admin_flag else f"📁 <b>USER PROJECTS COMPILATION</b>"
    text = f"{header}\n\nPage {page}/{total_pages} (Total: {total_count})\n\n"
    
    buttons = []
    for p in projects:
        running = is_running(p['id'])
        status_lbl = "🟢 RUNNING" if running else "🔴 OFFLINE"
        owner_info = f" (by {get_display_username(p)})" if is_admin_flag else ""
        text += f"<b>• {p['project_name']}</b>{owner_info}\n" \
                f"  Engine: {p['framework']} | Status: {status_lbl}\n"
                
        if running:
            info = get_process_info(p['id'])
            if info:
                cpu_col = get_performance_color(info['cpu_percent'])
                text += f"  Stats: {cpu_col} CPU: {info['cpu_percent']:.1f}% | 💾 RAM: {info['memory_mb']:.1f}MB\n"
        text += "\n"
        
        row = [
            InlineKeyboardButton("⏹️ STOP" if running else "▶️ START", callback_data=f"{'stop' if running else 'start'}_{p['id']}"),
            InlineKeyboardButton("⚙️ ENV", callback_data=f"manageenv_{p['id']}"),
            InlineKeyboardButton("🗑️ PURGE", callback_data=f"delete_{p['id']}")
        ]
        buttons.append(row)
        
    nav = []
    if page > 1:
        nav.append(InlineKeyboardButton("⬅️ Prev", callback_data=f"projects_page_{page-1}"))
    nav.append(InlineKeyboardButton(f"📄 {page}/{total_pages}", callback_data="current"))
    if page < total_pages:
        nav.append(InlineKeyboardButton("Next ➡️", callback_data=f"projects_page_{page+1}"))
    buttons.append(nav)
    buttons.append([InlineKeyboardButton("🔄 FORWARD REFRESH", callback_data="refresh_projects")])
    
    await send_response(update, text, reply_markup=InlineKeyboardMarkup(buttons))

# ===== EXECUTOR LAUNCH PIPELINE =====
def start_project_worker(project_id, project, chat_id, loop, bot):
    """Execution pipeline handling builds and launching sandboxed process workers"""
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
        
        # Parse environmental parameters safely
        env = os.environ.copy()
        env['BOT_HOSTING_PLATFORM'] = 'True'
        if 'BOT_TOKEN' in env: env.pop('BOT_TOKEN')
        if project['port']: env['PORT'] = str(project['port'])
        
        # Load user configurations
        try:
            user_env_data = json.loads(project.get('env_vars', '{}'))
            for k, v in user_env_data.items():
                env[str(k)] = str(v)
        except Exception as e:
            logger.warning(f"Failed loading env variables for {p_name}: {e}")
        
        if not project['deps_installed']:
            push_msg(f"🛠️ [{p_name}] Running dynamic dependencies build pipeline...")
            ok, output = install_dependencies(p_dir, project['framework'])
            if ok:
                with get_db_connection() as conn:
                    conn.execute("UPDATE projects SET deps_installed = 1 WHERE id = ?", (project_id,))
                    conn.commit()
                push_msg(f"✅ [{p_name}] Dynamic dependencies compiled successfully.")
            else:
                push_msg(f"❌ [{p_name}] Dependencies build system failure:\n<code>{html.escape(output)}</code>")
                return
                
        # Generate Executable Args
        main_file = project['main_file']
        cmd_args = None
        if main_file.endswith('.py'):
            cmd_args = [sys.executable, "-u", main_file]
        elif main_file.endswith(('.js', '.ts')):
            cmd_args = ["node", main_file]
            
        if not cmd_args:
            push_msg(f"❌ [{p_name}] Unsupported executor wrapper runtime.")
            return
            
        with open(log_file, 'a') as lf:
            lf.write(f"\n=== LAUNCH SESSION RUNNING {datetime.now()} ===\n")
            proc = subprocess.Popen(
                cmd_args, cwd=p_dir, stdout=lf, stderr=lf, env=env
            )
            
        running_processes[project_id] = proc.pid
        with get_db_connection() as conn:
            conn.execute("UPDATE projects SET status = 'running', last_started = CURRENT_TIMESTAMP WHERE id = ?", (project_id,))
            conn.execute("INSERT OR REPLACE INTO process_monitoring (project_id, pid, start_time) VALUES (?, ?, CURRENT_TIMESTAMP)", (project_id, proc.pid))
            conn.commit()
            
        push_msg(f"🟢 [{p_name}] Sandboxed runner fully active under local PID {proc.pid}")
    except Exception as e:
        logger.error(f"Thread deployment execution breakdown: {e}")
        push_msg(f"❌ Process launch breakdown for project ID {project_id}: {e}")

# ===== DYNAMIC DEPLOYMENT HANDLER =====
async def file_upload_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    # Check if we are self-updating the bot script itself via ZIP
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
            
            # Extract directly over current deployment workspace directory
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
        
    p_msg = await update.message.reply_text("📥 Downloading repository content...")
    
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
            await p_msg.edit_text("❌ Launch configuration main entrypoint file absent.")
            return
            
        if main_file.endswith('.py') and not find_requirements_txt(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
            os.remove(archive_path)
            await p_msg.edit_text("❌ Missing python `requirements.txt` file.")
            return
            
        types = detect_project_type(extract_dir, main_file)
        dest_dir = project_folder(user_id, p_name)
        if os.path.exists(dest_dir): shutil.rmtree(dest_dir)
        shutil.move(extract_dir, dest_dir)
        create_sandbox_environment(dest_dir)
        
        framework = "Python" if main_file.endswith('.py') else "Node.js"
        port = find_available_port() if framework == "Node.js" else None
        
        with get_db_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO projects (user_id, project_name, main_file, framework, project_type, port)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, p_name, main_file, framework, ','.join(types), port))
            project_id = cursor.lastrowid
            conn.commit()
            
        os.remove(archive_path)
        
        await p_msg.edit_text(
            f"✅ <b>PACKAGE INITIALIZATION SUCCESSFUL!</b>\n\n"
            f"• Project Name: {p_name}\n"
            f"• Engine Type: {framework}\n"
            f"• Target Entry: {main_file}\n\n"
            f"⚡ Launching worker process safely..."
        )
        
        loop = asyncio.get_running_loop()
        threading.Thread(
            target=start_project_worker,
            args=(project_id, {}, p_msg.chat.id, loop, context.bot),
            daemon=True
        ).start()
    except Exception as e:
        logger.error(f"Platform code initialization failure: {e}", exc_info=True)
        await p_msg.edit_text(f"❌ Verification framework crash: {e}")
    finally:
        user_states.pop(user_id, None)

# ===== BUTTON ACTIONS CALLBACKS =====
async def button_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data
    
    if not has_access(user_id):
        await query.edit_message_text("❌ System access expired or deactivated.")
        return
        
    if data.startswith("projects_page_"):
        await list_bots_command(update, context, int(data.split("_")[2]))
        return
    elif data == "refresh_projects":
        await list_bots_command(update, context)
        return
        
    # Split actions mapping [action, id]
    parts = data.split('_', 1)
    if len(parts) < 2: return
    action, p_id = parts[0], int(parts[1])
    
    with get_db_connection() as conn:
        proj = conn.execute("SELECT * FROM projects WHERE id = ?", (p_id,)).fetchone()
    if not proj: return
    
    if not is_admin(user_id) and proj['user_id'] != user_id:
        await query.edit_message_text("❌ Authorization signature invalid.")
        return
        
    if action == "start":
        if is_running(p_id): return
        loop = asyncio.get_running_loop()
        threading.Thread(
            target=start_project_worker,
            args=(p_id, dict(proj), query.message.chat.id, loop, context.bot),
            daemon=True
        ).start()
    elif action == "stop":
        stop_process(p_id)
    elif action == "delete":
        stop_process(p_id)
        p_path = project_folder(proj['user_id'], proj['project_name'])
        shutil.rmtree(p_path, ignore_errors=True)
        
        with get_db_connection() as conn:
            conn.execute("DELETE FROM projects WHERE id = ?", (p_id,))
            conn.execute("DELETE FROM process_monitoring WHERE project_id = ?", (p_id,))
            conn.commit()
    elif action == "manageenv":
        # Interactive configuration variable settings
        user_states[user_id] = {"awaiting_env_vars": True, "project_id": p_id}
        await context.bot.send_message(
            query.message.chat.id,
            f"⚙️ <b>CONFIGURING ENVIRONMENT FOR: {proj['project_name']}</b>\n\n"
            f"Please send the environment variables in valid JSON format. Example:\n"
            f"<code>{{\"API_KEY\": \"abc\", \"PORT\": \"80\"}}</code>",
            parse_mode=ParseMode.HTML
        )
        return

    class FakeUpdate:
        def __init__(self, query):
            self.callback_query = query
            self.effective_user = query.from_user
            
    await asyncio.sleep(1.5)
    try:
        await list_bots_command(FakeUpdate(query), context)
    except Exception:
        pass

# ===== VPS CONTROLS & MANAGEMENT INTERFACES =====
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
    
    # Render inline keyboard for hot pulling repository upgrades
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

# ===== CORE PLATFORM COMMAND IMPLEMENTATIONS =====
async def bot_logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Core function returning rolling platform engine logs"""
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    
    log_path = os.path.join(LOG_DIR, "hosting_bot.log")
    if not os.path.exists(log_path):
        await update.message.reply_text("📋 Logs are currently empty.")
        return
        
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            log_data = f.read()[-3000:]
        await update.message.reply_text(
            f"📋 <b>Bot Core Host Logs:</b>\n\n<pre>{html.escape(log_data)}</pre>",
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error reading bot logs: {e}")

async def system_status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Retrieves VPS system metric performance diagnostics"""
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
    """Renders user metrics and quick whitelisting settings"""
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    
    with get_db_connection() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY last_active DESC LIMIT 30").fetchall()
        
    text = "👥 <b>PLATFORM CLIENT MANAGEMENT</b>\n\n"
    for u in users:
        limit_lbl = "Unlimited" if u['file_limit'] == -1 else str(u['file_limit'])
        text += f"• <code>{u['user_id']}</code> | @{u['username'] or 'Unknown'} | Limit: {limit_lbl}\n"
        
    text += f"\n👉 Admin Command: <code>/limit [USERID] [LIMIT]</code>"
    await update.message.reply_text(text, parse_mode=ParseMode.HTML)

async def clear_logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Truncates VPS logs cleanly"""
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
    user_id = update.effective_user.id
    if not is_admin(user_id): return
    if len(context.args) != 2: return
    target_id = int(context.args[0])
    limit = int(context.args[1])
    
    with get_db_connection() as conn:
        conn.execute("INSERT INTO users (user_id, username, file_limit) VALUES (?, 'Unknown', ?) ON CONFLICT(user_id) DO UPDATE SET file_limit = ?", (target_id, limit, limit))
        conn.commit()
    await update.message.reply_text(f"✅ User ID <code>{target_id}</code> limit updated to: {limit}", parse_mode=ParseMode.HTML)

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
    
    # 🌟 CRITICAL FIX: Intercept keyboard menu inputs first, popping awaiting_shell_cmd state.
    menu_buttons = [
        "🚀 HOST BOT", "📊 MY PROJECTS", "🖥️ VPS CONTROLS", 
        "⚙️ BOT SELF-MANAGEMENT", "📢 BROADCAST", "📋 BOT LOGS", 
        "🖥️ SYSTEM STATUS", "👥 USER MANAGEMENT", "🧹 CLEAR LOGS"
    ]
    
    if text in menu_buttons:
        # Instantly close any awaiting shell, update, or broadcast states
        user_states.pop(user_id, None)
        broadcast_states.pop(user_id, None)
        
        if text == "🚀 HOST BOT": await bot_host_command(update, context)
        elif text == "📊 MY PROJECTS": await list_bots_command(update, context)
        elif text == "🖥️ VPS CONTROLS": await exec_shell_panel(update, context)
        elif text == "⚙️ BOT SELF-MANAGEMENT": await self_management_panel(update, context)
        elif text == "📢 BROADCAST": await broadcast_command(update, context)
        elif text == "📋 BOT LOGS": await bot_logs_command(update, context)
        elif text == "🖥️ SYSTEM STATUS": await system_status_command(update, context)
        elif text == "👥 USER MANAGEMENT": await user_management_command(update, context)
        elif text == "🧹 CLEAR LOGS": await clear_logs_command(update, context)
        return
    
    # Process secure terminal input
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
                
            await update.message.reply_text("✅ Project environment updated successfully. Restart the project to apply variables.")
        except json.JSONDecodeError:
            await update.message.reply_text("❌ Invalid JSON schema format. Operation aborted.")
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
            threading.Thread(target=start_project_worker, args=(p['id'], dict(p), None, None, None), daemon=True).start()
            time.sleep(2)
    except Exception as e:
        logger.error(f"Auto-restart routine issue: {e}")

# ===== SYSTEM APPLICATION INCEPTION =====
def main():
    check_single_instance()
    init_advanced_database()
    
    # Run auto start sequence in thread
    threading.Thread(target=auto_start_all_projects, daemon=True).start()
    
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("promo", promo_command))
    app.add_handler(CommandHandler("limit", limit_command))
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
