import sqlite3
import logging
from config import DB_PATH, OWNER_ID, OWNER_USERNAME

logger = logging.getLogger("AdvancedHostingBot")

def get_db_connection():
    """Get database connection with configuration Row factory"""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# ===== STREAMING_CHUNK: Generating dynamic system table schemas... =====
def init_advanced_database():
    """Initialize SQLite DB schemas and synchronize structural parameters"""
    with get_db_connection() as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Modified users table to reflect strict whitelisting access control
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                file_limit INTEGER DEFAULT 0,
                total_projects INTEGER DEFAULT 0,
                max_concurrent INTEGER DEFAULT 3,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Expanded projects configuration table for advanced VPS environment parameters
        conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                project_name TEXT UNIQUE,
                main_file TEXT,
                framework TEXT,
                project_type TEXT,
                port INTEGER,
                auto_restart BOOLEAN DEFAULT 1,
                deps_installed BOOLEAN DEFAULT 0,
                hosting_type TEXT DEFAULT 'zip',
                git_url TEXT,
                env_vars TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_started TIMESTAMP,
                webhook_url TEXT,
                status TEXT DEFAULT 'stopped',
                resource_usage TEXT DEFAULT '{}',
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS process_monitoring (
                project_id INTEGER PRIMARY KEY,
                pid INTEGER,
                start_time TIMESTAMP,
                cpu_usage REAL DEFAULT 0,
                memory_usage REAL DEFAULT 0,
                restart_count INTEGER DEFAULT 0,
                last_restart TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id)
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS system_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER,
                log_level TEXT,
                message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects (id)
            )
        """)
        
        # Default entry for Owner with infinite configuration space
        conn.execute("""
            INSERT OR REPLACE INTO users (user_id, username, file_limit, max_concurrent) 
            VALUES (?, ?, -1, -1)
        """, (OWNER_ID, OWNER_USERNAME))
        
        conn.commit()
        logger.info("🗄️ Core schemas synchronized successfully (Strict Whitelist Admin Rules Active)")

# ===== STREAMING_CHUNK: Designing modular access verification layers... =====
# ===== DB QUERY HELPERS =====
def has_access(user_id):
    """Check if the user is authorized manually by an admin to use hosting resources"""
    if user_id == OWNER_ID:
        return True
    
    with get_db_connection() as conn:
        user = conn.execute("SELECT file_limit FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if not user:
            return False
        
        return user['file_limit'] == -1 or user['file_limit'] > 0

def is_admin(user_id):
    """Determine if a user has platform administrator authorization"""
    if user_id == OWNER_ID:
        return True
    
    with get_db_connection() as conn:
        user = conn.execute("SELECT file_limit FROM users WHERE user_id = ?", (user_id,)).fetchone()
        return user is not None and user['file_limit'] == -1

def get_user_limit(user_id):
    """Return friendly representation of assigned user project limits"""
    if user_id == OWNER_ID:
        return "Unlimited"
    
    with get_db_connection() as conn:
        user = conn.execute("SELECT file_limit FROM users WHERE user_id = ?", (user_id,)).fetchone()
        if user:
            return "Unlimited" if user['file_limit'] == -1 else str(user['file_limit'])
        return "0"

def get_regular_project_count(user_id):
    """Get active standard projects deployed by the user"""
    with get_db_connection() as conn:
        count = conn.execute("""
            SELECT COUNT(*) as count FROM projects 
            WHERE user_id = ?
        """, (user_id,)).fetchone()['count']
    return count
