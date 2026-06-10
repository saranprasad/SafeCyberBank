import os
import uuid
import math
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, make_response, send_from_directory
from flask_cors import CORS
from database.mysql_db import SafeCyberMySQLDatabase

app = Flask(__name__, static_folder="static", static_url_path="")
# Enable CORS for cross-origin local testing
CORS(app, resources={r"/api/*": {"origins": "*"}})

db_layer = SafeCyberMySQLDatabase()

# In-memory session store mapped to user session info
SESSIONS = {}

def create_session(username):
    token = uuid.uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=15)
    SESSIONS[token] = {
        "username": username,
        "expires_at": expires_at
    }
    return token, expires_at

def get_session_user(token):
    if not token:
        return None
    session = SESSIONS.get(token)
    if not session:
        return None
    
    # Check expiration (sliding window)
    if datetime.utcnow() > session["expires_at"]:
        SESSIONS.pop(token, None)
        return None
        
    # Sliding window shift (refresh session expiration on request)
    session["expires_at"] = datetime.utcnow() + timedelta(minutes=15)
    return session["username"]

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")

# --- FLASK REST API ROUTING ---

@app.route("/api/health", methods=["GET"])
def health():
    # Verify cryptographic sequence link integrity in MySQL/SQLite
    conn = db_layer.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, sender, recipient, amount, timestamp, label, previous_hash, hash FROM transactions ORDER BY timestamp ASC")
    txs = cursor.fetchall()
    
    prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    is_valid = True
    checked_count = 0
    
    for tx in txs:
        tx_id, sender, recipient, amount, ts, label, p_hash, hsh = tx[0], tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], tx[7]
        if p_hash != prev_hash:
            is_valid = False
            break
        
        computed = db_layer.calculate_transaction_hash(tx_id, sender, recipient, amount, ts, label, p_hash)
        if hsh != computed:
            is_valid = False
            break
        
        prev_hash = hsh
        checked_count += 1
        
    cursor.close()
    conn.close()
    
    return jsonify({
        "status": "ACTIVE",
        "version": "1.0.0-Python-Flask",
        "compliance": "ISO-27001:2022 Verified",
        "timestamp": datetime.utcnow().isoformat(),
        "ledger": {
            "healthy": is_valid,
            "block_count": checked_count,
            "integrity_flag": "SECURE" if is_valid else "UNEXPECTED_ALTERATION"
        }
    })

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    ip = get_client_ip()
    
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
        
    if len(username) < 3 or len(username) > 20:
        return jsonify({"error": "Username must be between 3 and 20 characters."}), 400
        
    conn = db_layer.get_connection()
    cursor = conn.cursor()
    
    # Check if exists
    cursor.execute("SELECT username FROM users WHERE username = %s" if db_layer.db_type == "MySQL" else "SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        db_layer.create_audit_log(cursor, "SYSTEM", "AUTH_REGISTER_FAIL", f"Enrollment fail: {username} already exists.", "WARN", ip)
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"error": "Username is already taken."}), 400
        
    pwd_hash, salt = db_layer.hash_password(password)
    
    cursor.execute(
        "INSERT INTO users (username, password_hash, salt, balance, failed_login_count, locked_until, created_at, last_login_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" if db_layer.db_type == "MySQL" else
        "INSERT INTO users (username, password_hash, salt, balance, failed_login_count, locked_until, created_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (username, pwd_hash, salt, 1000.00, 0, None, datetime.utcnow().isoformat(), None)
    )
    
    db_layer.create_audit_log(cursor, username, "USER_REGISTER", "Account successfully provisioned with custom Flask keys.", "INFO", ip)
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({"success": True, "message": "Account created successfully!"})

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    ip = get_client_ip()
    
    if not username or not password:
        return jsonify({"error": "Credentials must not be empty"}), 400
        
    conn = db_layer.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, password_hash, salt, balance, failed_login_count, locked_until FROM users WHERE username = %s" if db_layer.db_type == "MySQL" else "SELECT username, password_hash, salt, balance, failed_login_count, locked_until FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        db_layer.create_audit_log(cursor, username, "AUTH_LOGIN_FAILED", "Username not recognized. Harvest control triggered.", "WARN", ip)
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401
        
    u_name, u_hash, u_salt, u_bal, u_fld, u_lck = user[0], user[1], user[2], user[3], user[4], user[5]
    
    # Check locks
    if u_lck:
        unlocked = False
        try:
            # Parse database lock timestamp
            if isinstance(u_lck, str):
                lock_time = datetime.fromisoformat(u_lck)
            else:
                lock_time = u_lck
                
            if datetime.utcnow() < lock_time:
                rem = math.ceil((lock_time - datetime.utcnow()).total_seconds())
                cursor.close()
                conn.close()
                return jsonify({"error": f"Account suspended. Try again in {rem}s."}), 403
            else:
                unlocked = True
        except:
            unlocked = True
            
        if unlocked:
            cursor.execute("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = %s" if db_layer.db_type == "MySQL" else "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = ?", (username,))

    matched = db_layer.verify_password(password, u_hash, u_salt)
    if not matched:
        new_count = u_fld + 1
        if new_count >= 5:
            lock_until = (datetime.utcnow() + timedelta(minutes=1)).isoformat()
            cursor.execute("UPDATE users SET failed_login_count = %s, locked_until = %s WHERE username = %s" if db_layer.db_type == "MySQL" else "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE username = ?", (new_count, lock_until, username))
            db_layer.create_audit_log(cursor, username, "USER_LOCKOUT", f"Lockout active due to multiple attempts. Release at {lock_until}", "CRITICAL", ip)
        else:
            cursor.execute("UPDATE users SET failed_login_count = %s WHERE username = %s" if db_layer.db_type == "MySQL" else "UPDATE users SET failed_login_count = ? WHERE username = ?", (new_count, username))
            db_layer.create_audit_log(cursor, username, "AUTH_LOGIN_FAILED", f"Password mismatch count: {new_count}", "WARN", ip)
            
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid username or password"}), 401
        
    # Reset failures and create session
    now_str = datetime.utcnow().isoformat()
    cursor.execute("UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = %s WHERE username = %s" if db_layer.db_type == "MySQL" else "UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = ? WHERE username = ?", (now_str, username))
    
    token, expires_at = create_session(username)
    db_layer.create_audit_log(cursor, username, "AUTH_LOGIN_SUCCESS", "Flask Portal Authentication. Session active.", "INFO", ip)
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({
        "success": True,
        "token": token,
        "expiresAt": expires_at.isoformat(),
        "user": {
            "username": username,
            "balance": float(u_bal)
        }
    })

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        SESSIONS.pop(token, None)
    return jsonify({"success": True, "message": "Terminated Python-Flask session successfully."})

@app.route("/api/user/info", methods=["GET"])
def user_info():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Requires active authorization token"}), 401
        
    token = auth_header.replace("Bearer ", "")
    username = get_session_user(token)
    if not username:
        return jsonify({"error": "Session expired or terminated."}), 401
        
    conn = db_layer.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, balance, created_at, last_login_at FROM users WHERE username = %s" if db_layer.db_type == "MySQL" else "SELECT username, balance, created_at, last_login_at FROM users WHERE username = ?", (username,))
    u = cursor.fetchone()
    
    if not u:
        cursor.close()
        conn.close()
        return jsonify({"error": "User record missing"}), 404
        
    u_name, u_bal, u_cre, u_lst = u[0], u[1], u[2], u[3]
    
    # Fetch user transactions
    cursor.execute(
        "SELECT id, sender, recipient, amount, timestamp, label, previous_hash, hash FROM transactions WHERE sender = %s OR recipient = %s ORDER BY timestamp DESC" if db_layer.db_type == "MySQL" else
        "SELECT id, sender, recipient, amount, timestamp, label, previous_hash, hash FROM transactions WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC", 
        (username, username)
    )
    tx_rows = cursor.fetchall()
    txs = []
    for r in tx_rows:
        txs.append({
            "id": r[0], "sender": r[1], "recipient": r[2], "amount": float(r[3]), "timestamp": r[4], "label": r[5], "previousHash": r[6], "hash": r[7]
        })
        
    # Fetch user audit logs
    if username == "security_auditor":
        cursor.execute("SELECT id, timestamp, event_type, username, ip, details, severity, signature FROM audit_logs ORDER BY timestamp DESC")
    else:
        cursor.execute(
            "SELECT id, timestamp, event_type, username, ip, details, severity, signature FROM audit_logs WHERE username = %s ORDER BY timestamp DESC" if db_layer.db_type == "MySQL" else
            "SELECT id, timestamp, event_type, username, ip, details, severity, signature FROM audit_logs WHERE username = ? ORDER BY timestamp DESC",
            (username,)
        )
    log_rows = cursor.fetchall()
    logs = []
    for r in log_rows:
        logs.append({
            "id": r[0], "timestamp": r[1], "eventType": r[2], "username": r[3], "ip": r[4], "details": r[5], "severity": r[6], "signature": r[7]
        })
        
    # Standard ledger quick health status
    cursor.execute("SELECT id, sender, recipient, amount, timestamp, label, previous_hash, hash FROM transactions ORDER BY timestamp ASC")
    all_all = cursor.fetchall()
    p_h = "0000000000000000000000000000000000000000000000000000000000000000"
    is_h = True
    for t in all_all:
        if t[6] != p_h:
            is_h = False
            break
        p_h = t[7]
        
    cursor.close()
    conn.close()
    
    return jsonify({
        "username": u_name,
        "balance": float(u_bal),
        "createdAt": u_cre,
        "lastLoginAt": u_lst,
        "transactions": txs,
        "auditLogs": logs,
        "ledger": {
            "healthy": is_h,
            "tamper_witnessed": "VERIFIED" if is_h else "COMPROMISED"
        }
    })

@app.route("/api/user/transfer", methods=["POST"])
def transfer():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Requires active authorization"}), 401
        
    token = auth_header.replace("Bearer ", "")
    sender = get_session_user(token)
    if not sender:
        return jsonify({"error": "Session expired."}), 401
        
    data = request.get_json() or {}
    recipient = data.get("recipient", "").strip().lower()
    amount_str = data.get("amount", "0")
    label = data.get("label", "").strip()
    ip = get_client_ip()
    
    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({"error": "Amount must be a positive numeric value."}), 400
        
    if not recipient:
        return jsonify({"error": "Recipient username cannot be empty."}), 400
        
    if sender == recipient:
        return jsonify({"error": "You cannot send money to yourself."}), 400
        
    if amount <= 0:
        return jsonify({"error": "Amount must be a positive number."}), 400
        
    if amount > 5000:
        return jsonify({"error": "Single transfer limit is $5000."}), 400
        
    conn = db_layer.get_connection()
    cursor = conn.cursor()
    
    # Select sender balance
    cursor.execute("SELECT balance FROM users WHERE username = %s" if db_layer.db_type == "MySQL" else "SELECT balance FROM users WHERE username = ?", (sender,))
    s_row = cursor.fetchone()
    if not s_row or float(s_row[0]) < amount:
        db_layer.create_audit_log(cursor, sender, "TX_FAIL", f"Transfer of ${amount} failed: insufficient funds.", "WARN", ip)
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"error": "Insufficient funds to execute this transfer"}), 400
        
    # Select recipient
    cursor.execute("SELECT username FROM users WHERE username = %s" if db_layer.db_type == "MySQL" else "SELECT username FROM users WHERE username = ?", (recipient,))
    r_row = cursor.fetchone()
    if not r_row:
        db_layer.create_audit_log(cursor, sender, "TX_FAIL", f"Wire failed: Recipient '{recipient}' not found.", "WARN", ip)
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"error": f"The recipient username '{recipient}' was not found."}), 400
        
    # Execute Debit and Credit
    cursor.execute("UPDATE users SET balance = balance - %s WHERE username = %s" if db_layer.db_type == "MySQL" else "UPDATE users SET balance = balance - ? WHERE username = ?", (amount, sender))
    cursor.execute("UPDATE users SET balance = balance + %s WHERE username = %s" if db_layer.db_type == "MySQL" else "UPDATE users SET balance = balance + ? WHERE username = ?", (amount, recipient))
    
    # Get last transaction details to chain hash properly
    cursor.execute("SELECT hash FROM transactions ORDER BY timestamp DESC LIMIT 1")
    l_tx = cursor.fetchone()
    prev_hash = l_tx[0] if l_tx else "0000000000000000000000000000000000000000000000000000000000000000"
    
    tx_id = f"tx_{uuid.uuid4().hex[:24]}"
    ts = datetime.utcnow().isoformat()
    clean_label = label[:100] if label else "Intra-Bank Trust Wire"
    tx_hash = db_layer.calculate_transaction_hash(tx_id, sender, recipient, amount, ts, clean_label, prev_hash)
    
    cursor.execute(
        "INSERT INTO transactions (id, sender, recipient, amount, timestamp, label, previous_hash, hash) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)" if db_layer.db_type == "MySQL" else
        "INSERT INTO transactions (id, sender, recipient, amount, timestamp, label, previous_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (tx_id, sender, recipient, amount, ts, clean_label, prev_hash, tx_hash)
    )
    
    db_layer.create_audit_log(cursor, sender, "TX_INIT", f"Transferred ${amount:.2f} to {recipient}. Sealed: [{tx_hash[:8]}...]", "INFO", ip)
    db_layer.create_audit_log(cursor, recipient, "TX_RECV", f"Received ${amount:.2f} from {sender}. Sealed: [{tx_hash[:8]}...]", "INFO", "127.0.0.1")
    
    conn.commit()
    
    # Fetch new balance
    cursor.execute("SELECT balance FROM users WHERE username = %s" if db_layer.db_type == "MySQL" else "SELECT balance FROM users WHERE username = ?", (sender,))
    new_bal = cursor.fetchone()[0]
    
    cursor.close()
    conn.close()
    
    return jsonify({
        "success": True,
        "message": f"Successfully transferred ${amount:.2f} to {recipient}",
        "newBalance": float(new_bal)
    })

@app.route("/api/audit/system-logs", methods=["GET"])
def system_logs():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Requires authentication"}), 401
        
    token = auth_header.replace("Bearer ", "")
    username = get_session_user(token)
    if username != "security_auditor":
        return jsonify({"error": "Administrative/Auditor credentials required."}), 403
        
    conn = db_layer.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, timestamp, event_type, username, ip, details, severity, signature FROM audit_logs ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    
    logs = []
    for r in rows:
        logs.append({
            "id": r[0], "timestamp": r[1], "eventType": r[2], "username": r[3], "ip": r[4], "details": r[5], "severity": r[6], "signature": r[7]
        })
        
    cursor.close()
    conn.close()
    
    return jsonify({
        "compliance": "ISO/IEC 27001:2022 standard security logs",
        "systemHealth": "SECURE",
        "logs": logs
    })

# Catch-all route to serve static built files for client-side routing
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    print(f" * Starting Safe Cyber Bank Flask server on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)
