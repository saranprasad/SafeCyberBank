import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { db, verifyPassword } from "./src/server/db.js";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Log all system web requests for general ISO 27001 network audit (A.12)
  app.use((req, res, next) => {
    // Basic IP resolution
    const clientIp = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "127.0.0.1";
    req.body = req.body || {};
    // Bind IP to requests
    (req as any).ipAddress = clientIp;
    next();
  });

  // --- API ROUTING ENFORMENT ---

  // Health endpoint checks system status and validates the tamper-evident cryptographic chain
  app.get("/api/health", (req, res) => {
    const check = db.verifyLedgerIntegrity();
    res.json({
      status: "ACTIVE",
      version: "1.0.0",
      compliance: "ISO-27001:2022 Verified",
      timestamp: new Date().toISOString(),
      ledger: {
        healthy: check.isValid,
        block_count: check.checkedCount,
        integrity_flag: check.isValid ? "SECURE" : "UNEXPECTED_ALTERATION"
      }
    });
  });

  // User registration
  app.post("/api/auth/register", (req, res) => {
    const { username, password } = req.body;
    const clientIp = (req as any).ipAddress;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required." });
    }

    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({ error: "Username must be between 3 and 20 alphanumeric characters." });
    }

    const result = db.registerUser(username, password, clientIp);
    if (!result.success) {
      return res.status(400).json({ error: result.message });
    }

    res.json({ success: true, message: result.message });
  });

  // User authentication & session injection
  app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body;
    const clientIp = (req as any).ipAddress;

    if (!username || !password) {
      return res.status(400).json({ error: "Credentials must not be empty" });
    }

    const user = db.getUser(username);
    if (!user) {
      // Return a general error message to prevent account harvesting (ISO 27001 Access Control Guidelines)
      db.createAuditLog(username, "AUTH_LOGIN_FAILED", `Username not found or credential mismatch`, "WARN", clientIp);
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Check account lockout status
    if (user.lockedUntil) {
      const lockDate = new Date(user.lockedUntil);
      if (lockDate.getTime() > Date.now()) {
        const secondsRemaining = Math.ceil((lockDate.getTime() - Date.now()) / 1000);
        return res.status(403).json({
          error: `This account is temporarily suspended due to repeated authentication failures. Try again in ${secondsRemaining}s.`
        });
      } else {
        // Unlock time elapsed
        db.resetFailedLoginAttempts(username);
      }
    }

    const matched = verifyPassword(password, user.passwordHash, user.salt);
    if (!matched) {
      db.handleFailedLoginAttempt(username, clientIp);
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Reset failed login count and register login success
    db.resetFailedLoginAttempts(username);
    const session = db.createSession(username);

    db.createAuditLog(username, "AUTH_LOGIN_SUCCESS", `Secure ISO authentication verified. Session generated.`, "INFO", clientIp);

    res.json({
      success: true,
      token: session.token,
      expiresAt: session.expiresAt,
      user: {
        username: user.username,
        balance: user.balance
      }
    });
  });

  // User termination
  app.post("/api/auth/logout", (req, res) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.replace("Bearer ", "");
      db.terminateSession(token);
    }
    res.json({ success: true, message: "Logged out from system sandbox." });
  });

  // Middleware to authenticate session token
  function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Requires active authorization token" });
    }

    const token = authHeader.replace("Bearer ", "");
    const session = db.getSession(token);

    if (!session) {
      return res.status(401).json({ error: "Session expired or terminated due to inactivity" });
    }

    (req as any).username = session.username;
    (req as any).sessionToken = token;
    next();
  }

  // Get current user dashboard state
  app.get("/api/user/info", requireAuth, (req, res) => {
    const username = (req as any).username;
    const user = db.getUser(username);
    if (!user) {
      return res.status(404).json({ error: "User profile missing" });
    }

    const transactions = db.getTransactionsForUser(username);
    const auditLogs = db.getAuditLogsForUser(username);
    const ledgerHealth = db.verifyLedgerIntegrity();

    res.json({
      username: user.username,
      balance: user.balance,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt,
      transactions,
      auditLogs,
      ledger: {
        healthy: ledgerHealth.isValid,
        tamper_witnessed: ledgerHealth.isValid ? "VERIFIED" : "COMPROMISED"
      }
    });
  });

  // Request secure funds transfer inside the intra-bank ecosystem (internal user transfers)
  app.post("/api/user/transfer", requireAuth, (req, res) => {
    const sender = (req as any).username;
    const clientIp = (req as any).ipAddress;
    const { recipient, amount, label } = req.body;

    if (!recipient) {
      return res.status(400).json({ error: "Recipient username cannot be empty." });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: "Amount must be a numeric value greater than zero." });
    }

    const result = db.executeTransfer(sender, recipient, parsedAmount, label, clientIp);
    if (!result.success) {
      return res.status(400).json({ error: result.message });
    }

    res.json({
      success: true,
      message: result.message,
      newBalance: db.getUser(sender)?.balance
    });
  });

  // Run cryptographical security audits for ISO-27001 auditor panel
  app.get("/api/audit/system-logs", requireAuth, (req, res) => {
    const username = (req as any).username;
    if (username !== "security_auditor") {
      db.createAuditLog(username, "SECURITY_BREACH_ATTEMPT", `Unauthorized attempt to fetch master audit registers`, "CRITICAL", (req as any).ipAddress);
      return res.status(403).json({ error: "Administrative/Auditor credentials required to fetch system-wide security ledgers." });
    }

    const allLogs = db.getSystemAuditLogs();
    const ledgerCheck = db.verifyLedgerIntegrity();

    res.json({
      compliance: "ISO/IEC 27001:2022 standard security logs",
      systemHealth: "SECURE",
      ledgerStatus: ledgerCheck.isValid ? "INTECT_SECURE" : "TAMPERED",
      checkedBlocks: ledgerCheck.checkedCount,
      logs: allLogs
    });
  });

  // --- VITE WEB AND COMPILATION HANDLING ---

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Safe Cyber Bank Server] Listening on port ${PORT}`);
  });
}

startServer().catch(err => {
  console.error("Fatal startup crash", err);
});
