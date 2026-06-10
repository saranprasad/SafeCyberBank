import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta

# Fallback pattern: Use sqlite3 dynamically if mysql-connector-python is not installed
# to ensure the developer's app launches out-of-the-box in local environments too.
try:
    import mysql.connector
    from mysql.connector import pooling
    HAS_MYSQL = True
except ImportError:
    import sqlite3
    HAS_MYSQL = False

class SafeCyberMySQLDatabase:
    def __init__(self):
        self.mysql_config = {
            "host": os.getenv("MYSQL_HOST", "localhost"),
            "user": os.getenv("MYSQL_USER", "root"),
            "password": os.getenv("MYSQL_PASSWORD", ""),
            "database": os.getenv("MYSQL_DB", "safe_cyber_bank"),
            "port": int(os.getenv("MYSQL_PORT", 3306))
        }
        self.audit_secret = secrets.token_hex(32)
        self.db_type = "MySQL" if HAS_MYSQL else "SQLite Fallback"
        
        self.init_database()
        self.seed_users()

    def get_connection(self):
        if HAS_MYSQL:
            try:
                # Try connecting with standard pool or direct connection
                return mysql.connector.connect(**self.mysql_config)
            except Exception as e:
                print(f"[Database Error] Could not connect to MySQL server. Ensure MySQL is running. Error: {e}")
                raise e
        else:
            # Local SQLite connection
            conn = sqlite3.connect("safe_cyber_sqlite_db.db")
            conn.row_factory = sqlite3.Row
            return conn

    def init_database(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if not HAS_MYSQL:
            # SQLite Table Schemes matching MySQL schemas exactly
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 1000.00,
                failed_login_count INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login_at TEXT
            )""")
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                label TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )""")
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                username TEXT NOT NULL,
                ip TEXT NOT NULL,
                details TEXT NOT NULL,
                severity TEXT NOT NULL,
                signature TEXT NOT NULL
            )""")
        else:
            # Tables creation in MySQL
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(50) PRIMARY KEY,
                password_hash VARCHAR(130) NOT NULL,
                salt VARCHAR(32) NOT NULL,
                balance DECIMAL(15, 2) NOT NULL DEFAULT 1000.00,
                failed_login_count INT NOT NULL DEFAULT 0,
                locked_until DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login_at DATETIME NULL
            )""")
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id VARCHAR(50) PRIMARY KEY,
                sender VARCHAR(50) NOT NULL,
                recipient VARCHAR(50) NOT NULL,
                amount DECIMAL(15, 2) NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                label VARCHAR(255) NOT NULL,
                previous_hash VARCHAR(64) NOT NULL,
                hash VARCHAR(64) NOT NULL
            )""")
            
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id VARCHAR(50) PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_type VARCHAR(100) NOT NULL,
                username VARCHAR(50) NOT NULL,
                ip VARCHAR(45) NOT NULL,
                details TEXT NOT NULL,
                severity VARCHAR(20) NOT NULL,
                signature VARCHAR(64) NOT NULL
            )""")
            
        conn.commit()
        cursor.close()
        conn.close()

    def hash_password(self, password, salt=None):
        if salt is None:
            salt = secrets.token_hex(16)
        
        # PBKDF2 standard conforming hashing
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha512',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            10000
        ).hex()
        return pwd_hash, salt

    def verify_password(self, password, hashed_pwd, salt):
        check_hash, _ = self.hash_password(password, salt)
        return hmac.compare_digest(hashed_pwd, check_hash)

    def calculate_transaction_hash(self, tx_id, sender, recipient, amount, timestamp, label, previous_hash):
        content = f"{tx_id}|{sender}|{recipient}|{amount}|{timestamp}|{label}|{previous_hash}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def sign_audit_log(self, log_id, timestamp, event_type, username, ip, details, severity):
        content = f"{log_id}|{timestamp}|{event_type}|{username}|{ip}|{details}|{severity}"
        return hmac.new(
            self.audit_secret.encode('utf-8'),
            content.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    def seed_users(self):
        # Checks if we have preseeded. If database has users already, do not re-seed.
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        
        if count == 0:
            print(f"[{self.db_type}] Pre-seeding required bank entities...")
            # 15 users required mapping
            seed_data = [
                ("administrator", "admin2026", 10000.00),
                ("saran", "saran2026", 5000.00),
                ("naveen", "naveen2026", 5000.00),
                ("richa", "richa2026", 5000.00),
                ("fahim", "fahim2026", 5000.00),
                ("hamza", "hamza2026", 5000.00),
                ("basim", "basim2026", 5000.00),
                ("elanie", "elanie2026", 5000.00),
                ("valentin", "valentin2026", 5000.00),
                ("ken", "ken2026", 5000.00),
                ("poly", "poly2026", 5000.00),
                ("usha", "usha2026", 5000.00),
                ("chintan", "chintan2026", 5000.00),
                ("mahsa", "mahsa2026", 5000.00),
                ("prasanna", "prasanna2026", 5000.00),
                ("security_auditor", "AuditPass2026#", 10000.00)
            ]
            
            for username, password, initial_balance in seed_data:
                pwd_hash, salt = self.hash_password(password)
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt, balance, failed_login_count, locked_until, created_at, last_login_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" if HAS_MYSQL else
                    "INSERT INTO users (username, password_hash, salt, balance, failed_login_count, locked_until, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (username, pwd_hash, salt, initial_balance, 0, None, datetime.utcnow().isoformat(), None)
                )
            
            # Seed starting transactions in ledger chain
            prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            seed_tx_records = [
                ("tx_seed_1", "SYS_MINT", "saran", 5000.00, "Initial Security Bank Deposit"),
                ("tx_seed_2", "SYS_MINT", "naveen", 5000.00, "Pre-Approved Vault Provision"),
                ("tx_seed_3", "SYS_MINT", "security_auditor", 10000.00, "Audit Ledger Seed Funds"),
                ("tx_seed_4", "saran", "naveen", 200.00, "Safe Tunnel Integration Transfer")
            ]
            
            for tx_id, sender, recipient, amount, label in seed_tx_records:
                ts = datetime.utcnow().isoformat()
                tx_hash = self.calculate_transaction_hash(tx_id, sender, recipient, amount, ts, label, prev_hash)
                
                # Debit and Credit
                if sender != "SYS_MINT":
                    cursor.execute("UPDATE users SET balance = balance - %s WHERE username = %s" if HAS_MYSQL else "UPDATE users SET balance = balance - ? WHERE username = ?", (amount, sender))
                cursor.execute("UPDATE users SET balance = balance + %s WHERE username = %s" if HAS_MYSQL else "UPDATE users SET balance = balance + ? WHERE username = ?", (amount, recipient))
                
                cursor.execute(
                    "INSERT INTO transactions (id, sender, recipient, amount, timestamp, label, previous_hash, hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" if HAS_MYSQL else
                    "INSERT INTO transactions (id, sender, recipient, amount, timestamp, label, previous_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (tx_id, sender, recipient, amount, ts, label, prev_hash, tx_hash)
                )
                prev_hash = tx_hash
                
            # Log initial startup audit
            log_id = "log_sys_init"
            log_ts = datetime.utcnow().isoformat()
            log_type = "SYS_STARTUP"
            log_det = "Safe Cyber Bank active. Flask / MySQL persistence layer booted."
            log_sev = "INFO"
            log_sig = self.sign_audit_log(log_id, log_ts, log_type, "SYSTEM", "127.0.0.1", log_det, log_sev)
            cursor.execute(
                "INSERT INTO audit_logs (id, timestamp, event_type, username, ip, details, severity, signature) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" if HAS_MYSQL else
                "INSERT INTO audit_logs (id, timestamp, event_type, username, ip, details, severity, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (log_id, log_ts, log_type, "SYSTEM", "127.0.0.1", log_det, log_sev, log_sig)
            )
            
            conn.commit()
            print("[Database init] Completed setup success.")
            
        cursor.close()
        conn.close()

    def create_audit_log(self, cursor, username, event_type, details, severity, ip):
        log_id = f"log_{secrets.token_hex(12)}"
        ts = datetime.utcnow().isoformat()
        sig = self.sign_audit_log(log_id, ts, event_type, username, ip, details, severity)
        cursor.execute(
            "INSERT INTO audit_logs (id, timestamp, event_type, username, ip, details, severity, signature) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" if HAS_MYSQL else
            "INSERT INTO audit_logs (id, timestamp, event_type, username, ip, details, severity, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (log_id, ts, event_type, username, ip, details, severity, sig)
        )
