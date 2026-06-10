import fs from "fs";
import path from "path";
import crypto from "crypto";

const STORAGE_DIR = path.join(process.cwd(), "data");
const DB_FILE = path.join(STORAGE_DIR, "bank_secure_db.json");

// Generate secret key for signing audit logs (stored in-memory, rotates each server start)
const AUDIT_SECRET = crypto.randomBytes(32).toString("hex");

// Base seed data for mock banking
const INITIAL_USERS = [
  {
    username: "administrator",
    ...hashPassword("admin2026"),
    balance: 10000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "saran",
    ...hashPassword("saran2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "naveen",
    ...hashPassword("naveen2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "richa",
    ...hashPassword("richa2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "fahim",
    ...hashPassword("fahim2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "hamza",
    ...hashPassword("hamza2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "basim",
    ...hashPassword("basim2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "elanie",
    ...hashPassword("elanie2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "valentin",
    ...hashPassword("valentin2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "ken",
    ...hashPassword("ken2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "poly",
    ...hashPassword("poly2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "usha",
    ...hashPassword("usha2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "chintan",
    ...hashPassword("chintan2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "mahsa",
    ...hashPassword("mahsa2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "prasanna",
    ...hashPassword("prasanna2026"),
    balance: 5000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  },
  {
    username: "security_auditor",
    ...hashPassword("AuditPass2026#"),
    balance: 10000,
    failedLoginCount: 0,
    lockedUntil: null,
    createdAt: new Date().toISOString(),
    lastLoginAt: null,
  }
];

// Helper to hash password with PBKDF2 (FIPS compliance / secure crypto)
export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
  return { passwordHash: hash, salt };
}

export function verifyPassword(password, hash, salt) {
  const checkHash = crypto.pbkdf2Sync(password, salt, 10000, 64, "sha512").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(checkHash, "hex"));
}

// Generate SHA-256 for transactions to ensure Tamper Evidence
function calculateTransactionHash(tx) {
  const content = `${tx.id}|${tx.sender}|${tx.recipient}|${tx.amount}|${tx.timestamp}|${tx.label}|${tx.previousHash}`;
  return crypto.createHash("sha256").update(content).digest("hex");
}

// Sign an audit log using HMAC
function signAuditLog(log) {
  const content = `${log.id}|${log.timestamp}|${log.eventType}|${log.username}|${log.ip}|${log.details}|${log.severity}`;
  return crypto.createHmac("sha256", AUDIT_SECRET).update(content).digest("hex");
}

class SafeCyberDatabase {
  constructor() {
    this.users = new Map();
    this.transactions = [];
    this.auditLogs = [];
    this.sessions = new Map();
    this.ensureInitialized();
  }

  ensureInitialized() {
    if (!fs.existsSync(STORAGE_DIR)) {
      fs.mkdirSync(STORAGE_DIR, { recursive: true });
    }

    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, "utf-8");
        const parsed = JSON.parse(raw);
        
        parsed.users.forEach((u) => this.users.set(u.username, u));
        this.transactions = parsed.transactions;
        this.auditLogs = parsed.auditLogs;
      } catch (err) {
        console.error("Failed to parse database, generating new database state", err);
        this.initializeDefaults();
      }
    } else {
      this.initializeDefaults();
    }
  }

  initializeDefaults() {
    INITIAL_USERS.forEach(u => this.users.set(u.username, u));
    
    // Seed initial ledger transactions
    let prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
    
    const seedTxs = [
      { id: "tx_seed_1", sender: "SYS_MINT", recipient: "saran", amount: 5000, timestamp: new Date(Date.now() - 48 * 3600 * 1000).toISOString(), label: "Initial Security Bank Deposit" },
      { id: "tx_seed_2", sender: "SYS_MINT", recipient: "naveen", amount: 5000, timestamp: new Date(Date.now() - 36 * 3600 * 1000).toISOString(), label: "Pre-Approved Vault Provision" },
      { id: "tx_seed_3", sender: "SYS_MINT", recipient: "security_auditor", amount: 10000, timestamp: new Date(Date.now() - 24 * 3600 * 1000).toISOString(), label: "Audit Ledger Seed Funds" },
      { id: "tx_seed_4", sender: "saran", recipient: "naveen", amount: 200, timestamp: new Date(Date.now() - 12 * 3600 * 1000).toISOString(), label: "Safe Tunnel Integration Transfer" }
    ];

    for (const t of seedTxs) {
      const fullTx = {
        ...t,
        previousHash: prevHash,
        hash: ""
      };
      fullTx.hash = calculateTransactionHash(fullTx);
      this.transactions.push(fullTx);
      prevHash = fullTx.hash;
    }

    // Update balances based on seed transfers (saran transferred 200 to naveen)
    const saranUser = this.users.get("saran");
    const naveenUser = this.users.get("naveen");
    if (saranUser) saranUser.balance = 4800;
    if (naveenUser) naveenUser.balance = 5200;

    this.writeToDisk();
    this.createAuditLog("SYSTEM", "SYS_STARTUP", "Safe Cyber Bank initialized in isolated environment. Secure Ledger running. Key rotated.", "INFO", "127.0.0.1");
  }

  writeToDisk() {
    try {
      const output = {
        users: Array.from(this.users.values()),
        transactions: this.transactions,
        auditLogs: this.auditLogs,
      };
      fs.writeFileSync(DB_FILE, JSON.stringify(output, null, 2), "utf-8");
    } catch (err) {
      console.error("Database writing failure", err);
    }
  }

  // --- Session Management ---
  createSession(username) {
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 mins expiry
    const session = { token, username, expiresAt };
    this.sessions.set(token, session);
    return session;
  }

  getSession(token) {
    const sess = this.sessions.get(token);
    if (!sess) return null;
    
    // Check expiration
    if (new Date(sess.expiresAt).getTime() < Date.now()) {
      this.sessions.delete(token);
      return null;
    }
    
    // Refresh session on activity (sliding window of 15 mins)
    sess.expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    return sess;
  }

  terminateSession(token) {
    this.sessions.delete(token);
  }

  // --- Users Operations ---
  getUser(username) {
    const u = this.users.get(username.toLowerCase());
    return u ? { ...u } : null;
  }

  registerUser(username, pass, ip) {
    const normUser = username.toLowerCase().trim();
    if (this.users.has(normUser)) {
      this.createAuditLog("SYSTEM", "AUTH_REGISTER_FAIL", `Sign up failed: User '${normUser}' already exists.`, "WARN", ip);
      return { success: false, message: "Username is already taken" };
    }

    // Password validation according to ISO 27001 password specifications
    const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passRegex.test(pass) && pass.length < 16) { 
      if (pass.length < 8) {
        return { success: false, message: "Security standard requires at least 8 characters." };
      }
      return { success: false, message: "Password must contain an uppercase letter, lowercase letter, and a number." };
    }

    const { passwordHash, salt } = hashPassword(pass);
    const newUser = {
      username: normUser,
      passwordHash,
      salt,
      balance: 1000,
      failedLoginCount: 0,
      lockedUntil: null,
      createdAt: new Date().toISOString(),
      lastLoginAt: null
    };

    this.users.set(normUser, newUser);
    this.writeToDisk();

    this.createAuditLog(normUser, "USER_REGISTER", "Account successfully provisioned with a secure container. Balance: $1000.00", "INFO", ip);
    return { success: true, message: "Account created successfully" };
  }

  handleFailedLoginAttempt(username, ip) {
    const normUser = username.toLowerCase();
    const user = this.users.get(normUser);
    if (!user) return;

    user.failedLoginCount += 1;
    if (user.failedLoginCount >= 5) {
      const lockedTime = new Date(Date.now() + 60000).toISOString();
      user.lockedUntil = lockedTime;
      this.createAuditLog(normUser, "USER_LOCKOUT", `Account locked due to 5 failed login attempts. Suspended until ${lockedTime}`, "CRITICAL", ip);
    } else {
      this.createAuditLog(normUser, "AUTH_LOGIN_FAILED", `Failed password attempt (${user.failedLoginCount}/5).`, "WARN", ip);
    }
    this.writeToDisk();
  }

  resetFailedLoginAttempts(username) {
    const user = this.users.get(username.toLowerCase());
    if (user) {
      user.failedLoginCount = 0;
      user.lockedUntil = null;
      user.lastLoginAt = new Date().toISOString();
      this.writeToDisk();
    }
  }

  // --- Transactions ---
  getTransactionsForUser(username) {
    const name = username.toLowerCase();
    return this.transactions.filter(t => t.sender === name || t.recipient === name);
  }

  executeTransfer(sender, recipient, amount, label, ip) {
    const senderName = sender.toLowerCase();
    const rcptName = recipient.toLowerCase().trim();

    if (senderName === rcptName) {
      this.createAuditLog(senderName, "TX_FAIL", "Transfer failed: Self-transfer prohibited.", "WARN", ip);
      return { success: false, message: "You cannot send money to yourself." };
    }

    if (isNaN(amount) || amount <= 0) {
      this.createAuditLog(senderName, "TX_FAIL", `Transfer failed: Invalid amount: ${amount}`, "WARN", ip);
      return { success: false, message: "Amount must be a positive number." };
    }

    if (amount > 5000) {
      this.createAuditLog(senderName, "TX_FAIL", `Transfer of $${amount} exceeded transaction limit of $5000.`, "WARN", ip);
      return { success: false, message: "Single transfer limit is $5000 for standard customer protection." };
    }

    const senderUser = this.users.get(senderName);
    const rcptUser = this.users.get(rcptName);

    if (!senderUser) {
      return { success: false, message: "Sender identity integrity error." };
    }

    if (!rcptUser) {
      this.createAuditLog(senderName, "TX_FAIL", `Target user '${recipient}' does not exist.`, "WARN", ip);
      return { success: false, message: `The recipient username "${recipient}" was not found in Safe Cyber Bank records.` };
    }

    if (senderUser.balance < amount) {
      this.createAuditLog(senderName, "TX_FAIL", `Transfer of $${amount} failed due to insufficient funds (Balance: $${senderUser.balance}).`, "WARN", ip);
      return { success: false, message: "Insufficient funds to execute this transfer." };
    }

    senderUser.balance -= amount;
    rcptUser.balance += amount;

    const previousTx = this.transactions[this.transactions.length - 1];
    const prevHash = previousTx ? previousTx.hash : "0000000000000000000000000000000000000000000000000000000000000000";

    const cleanLabel = (label || "").trim().slice(0, 100) || "Intra-Bank Trust Wire";

    const newTx = {
      id: "tx_" + crypto.randomBytes(12).toString("hex"),
      sender: senderName,
      recipient: rcptName,
      amount,
      timestamp: new Date().toISOString(),
      label: cleanLabel,
      previousHash: prevHash,
      hash: ""
    };

    newTx.hash = calculateTransactionHash(newTx);
    this.transactions.push(newTx);

    this.writeToDisk();

    this.createAuditLog(senderName, "TX_INIT", `Transferred $${amount.toFixed(2)} to ${rcptName}. Tx sealed: [${newTx.hash.slice(0, 8)}...]`, "INFO", ip);
    this.createAuditLog(rcptName, "TX_RECV", `Received $${amount.toFixed(2)} from ${senderName}. Tx sealed: [${newTx.hash.slice(0, 8)}...]`, "INFO", "127.0.0.1");

    return { success: true, message: `Successfully transferred $${amount.toFixed(2)} to ${rcptName}` };
  }

  // --- Verification ---
  verifyLedgerIntegrity() {
    let prevHash = "0000000000000000000000000000000000000000000000000000000000000000";
    
    for (let i = 0; i < this.transactions.length; i++) {
      const tx = this.transactions[i];
      if (tx.previousHash !== prevHash) {
        return { isValid: false, checkedCount: i, errorTxIndex: i };
      }
      
      const computed = calculateTransactionHash(tx);
      if (tx.hash !== computed) {
        return { isValid: false, checkedCount: i, errorTxIndex: i };
      }
      
      prevHash = tx.hash;
    }
    
    return { isValid: true, checkedCount: this.transactions.length, errorTxIndex: null };
  }

  // --- Audit Logs ---
  createAuditLog(username, eventType, details, severity, ip) {
    const entry = {
      id: "log_" + crypto.randomBytes(12).toString("hex"),
      timestamp: new Date().toISOString(),
      eventType,
      username,
      ip,
      details,
      severity
    };

    const finishedEntry = {
      ...entry,
      signature: signAuditLog(entry)
    };

    this.auditLogs.unshift(finishedEntry); // newest logs first
    
    if (this.auditLogs.length > 1000) {
      this.auditLogs.pop();
    }
    
    this.writeToDisk();
    return finishedEntry;
  }

  getAuditLogsForUser(username) {
    const name = username.toLowerCase();
    if (name === "security_auditor") {
      return this.auditLogs;
    }
    return this.auditLogs.filter(log => log.username === name);
  }

  getSystemAuditLogs() {
    return this.auditLogs;
  }
}

export const db = new SafeCyberDatabase();
