import os
import sys
import re
import logging
import psutil
import atexit
import subprocess

# ===== TOKEN VALIDATION =====
def validate_bot_token(token):
    """Validate Telegram bot token format"""
    if not token:
        return False, "Token is empty"
    
    token_pattern = r'^\d{9,10}:[a-zA-Z0-9_-]{35}$'
    if not re.match(token_pattern, token):
        return False, "Invalid token format"
    
    return True, "Token format is valid"

# ===== ENVIRONMENT DETECTION =====
def check_nodejs_installation():
    """Check if Node.js and npm are installed on the host VPS"""
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True, timeout=10)
        npm_result = subprocess.run(['npm', '--version'], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and npm_result.returncode == 0:
            return True
        return False
    except Exception:
        return False

def check_python_versions():
    """Check available Python CLI commands and return versions"""
    python_versions = {}
    
    # Check Python 3
    try:
        result = subprocess.run(['python3', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            python_versions['python3'] = result.stdout.strip()
    except Exception:
        pass
    
    # Check Python
    try:
        result = subprocess.run(['python', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            python_versions['python'] = result.stdout.strip()
    except Exception:
        pass
    
    return python_versions

# ===== CORE PARAMETERS =====
RAW_BOT_TOKEN = os.environ.get("BOT_TOKEN", "8816601154:AAHFNSbAGxzYxOnAJNK3EOV-L415Q_E2_Qc")
875
is_valid, validation_msg = validate_bot_token(RAW_BOT_TOKEN)
if not is_valid:
    print(f"❌ Token Validation Failed: {validation_msg}")
    print(f"❌ Provided Token: {RAW_BOT_TOKEN}")
    sys.exit(1)

BOT_TOKEN = RAW_BOT_TOKEN
OWNER_ID = int(os.environ.get("OWNER_ID", "8587570983"))
OWNER_USERNAME = os.environ.get("OWNER_USERNAME", "@EliteHM")
DEVELOPER_NAME = "HmGamer"

# ===== PATH DIRECTORIES =====
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
PID_FILE = os.path.join(BASE_DIR, "advanced_hosting_bot.pid")
DB_PATH = os.path.join(BASE_DIR, "advanced_hosting.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "hosted_projects")
LOG_DIR = os.path.join(BASE_DIR, "bot_logs")
TEMP_DIR = os.path.join(BASE_DIR, "temp_uploads")

# ===== DEPLOYMENT SETTINGS =====
MAX_FILE_SIZE_MB = 100
MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024
INSTALL_TIMEOUT_SECONDS = 1800
AUTO_RESTART_ENABLED = True
MONITORING_INTERVAL = 30

# Create operational directories if missing
for directory in [UPLOAD_DIR, LOG_DIR, TEMP_DIR]:
    os.makedirs(directory, exist_ok=True)

# Run environment checking flags
NODEJS_AVAILABLE = check_nodejs_installation()
PYTHON_VERSIONS = check_python_versions()

# ===== LOGGING SYSTEM =====
def setup_advanced_logging():
    """Setup comprehensive logging system logging to both stdout and a rolling file log"""
    main_logger = logging.getLogger("AdvancedHostingBot")
    main_logger.setLevel(logging.INFO)
    
    if main_logger.handlers:
        main_logger.handlers.clear()
        
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    main_logger.addHandler(console_handler)
    
    file_handler = logging.FileHandler(os.path.join(LOG_DIR, "hosting_bot.log"))
    file_formatter = logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    main_logger.addHandler(file_handler)
    
    return main_logger

logger = setup_advanced_logging()

# ===== SINGLE INSTANCE PROTECTION =====
def cleanup_pid_file():
    """Advanced cleanup of process files on safe termination"""
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            logger.info("🔐 PID file cleaned up successfully")
    except Exception as e:
        logger.error(f"❌ Error cleaning PID file: {e}")

def check_single_instance():
    """Ensure only a single instance of the script runs on the host VPS system"""
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, 'r') as f:
                old_pid = int(f.read().strip())
            
            if psutil.pid_exists(old_pid):
                logger.error(f"❌ Another instance running (PID: {old_pid}). Terminating.")
                sys.exit(1)
            else:
                logger.warning("⚠️ Found stale PID file. Previous process crashed or terminated forcefully.")
        except (ValueError, FileNotFoundError):
            logger.warning("⚠️ Invalid/unreadable PID file found. Overwriting.")
    
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        atexit.register(cleanup_pid_file)
        logger.info(f"🔐 Single instance protection activated (PID: {os.getpid()})")
    except Exception as e:
        logger.error(f"❌ Could not create PID file: {e}")
        sys.exit(1)
