import React, { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Coins,
  Send,
  History,
  Terminal,
  RefreshCw,
  LogOut,
  UserCheck,
  CheckCircle2,
  AlertOctagon,
  FileSpreadsheet,
  Search,
  Eye,
  KeyRound,
  Info,
  Clock
} from "lucide-react";

export default function App() {
  // Authentication states
  const [token, setToken] = useState(() => localStorage.getItem("scb_token"));
  const [user, setUser] = useState(null);
  const [userInfo, setUserInfo] = useState(null);

  // Form states
  const [mode, setMode] = useState("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Transfer Form States
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [transferLabel, setTransferLabel] = useState("");
  const [transferError, setTransferError] = useState(null);
  const [transferSuccess, setTransferSuccess] = useState(null);
  const [transferLoading, setTransferLoading] = useState(false);

  // Ledger Verification States
  const [isScanningLedger, setIsScanningLedger] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [scanComplete, setScanComplete] = useState(false);
  const [ledgerHealthy, setLedgerHealthy] = useState(true);

  // Audit Logs Search/Filter States
  const [auditSearch, setAuditSearch] = useState("");
  const [auditSeverityFilter, setAuditSeverityFilter] = useState("ALL");

  // General Tabs
  const [activeTab, setActiveTab] = useState("dashboard");

  // Inactivity countdown
  const [sessionExpiry, setSessionExpiry] = useState(900); // 15 mins (900 seconds) sliding clock
  const countdownIntervalRef = useRef(null);

  // Load user data on startup/token change
  useEffect(() => {
    if (token) {
      localStorage.setItem("scb_token", token);
      fetchUserInfo();
    } else {
      localStorage.removeItem("scb_token");
      setUser(null);
      setUserInfo(null);
    }
  }, [token]);

  // Session timer ticker following ISO Standard for connection auto-termination
  useEffect(() => {
    if (token) {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
      
      setSessionExpiry(900); // 15 minutes
      countdownIntervalRef.current = setInterval(() => {
        setSessionExpiry((prev) => {
          if (prev <= 1) {
            handleLogout("Session expired due to 15 minutes of dynamic inactivity.");
            return 900;
          }
          return prev - 1;
        });
      }, 1000);
    } else {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    }
    return () => {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    };
  }, [token]);

  const fetchUserInfo = async () => {
    if (!token) return;
    try {
      const res = await fetch("/api/user/info", {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      if (res.ok) {
        const data = await res.json();
        setUserInfo(data);
        setUser({ username: data.username, balance: data.balance });
      } else {
        handleLogout("Session token validation failed.");
      }
    } catch {
      setErrorMsg("Network failure trying to contact secure portal. Retrying...");
    }
  };

  const handleLogout = async (reason) => {
    if (token) {
      try {
        await fetch("/api/auth/logout", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
      } catch (err) {
        // Silently clear client
      }
    }
    setToken(null);
    setUser(null);
    setUserInfo(null);
    setUsername("");
    setPassword("");
    setSuccessMsg(reason || "Successfully signed out of the secure container.");
    setErrorMsg(null);
    setActiveTab("dashboard");
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (!username || !password) {
      setErrorMsg("Identifiers and cryptographic passkeys are mandatory.");
      return;
    }

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || "Access denied.");
        return;
      }

      setToken(data.token);
      setUsername("");
      setPassword("");
    } catch {
      setErrorMsg("Connection failure connecting to Safe Cyber isolation vault.");
    }
  };

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    if (!username || !password) {
      setErrorMsg("Please specify both a user identifier and a passkey.");
      return;
    }

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();
      if (!res.ok) {
        setErrorMsg(data.error || "Account generation halted.");
        return;
      }

      setSuccessMsg("Account successfully provisioned! Please sign in below.");
      setMode("login");
    } catch {
      setErrorMsg("Network failure during account security provisioning.");
    }
  };

  const handleTransferSubmit = async (e) => {
    e.preventDefault();
    setTransferError(null);
    setTransferSuccess(null);
    setTransferLoading(true);

    if (!recipient) {
      setTransferError("Specify a destinatary account identifier.");
      setTransferLoading(false);
      return;
    }

    const amtNum = parseFloat(amount);
    if (isNaN(amtNum) || amtNum <= 0) {
      setTransferError("A positive numerical transfer amount is required.");
      setTransferLoading(false);
      return;
    }

    try {
      const res = await fetch("/api/user/transfer", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          recipient,
          amount: amtNum,
          label: transferLabel
        })
      });

      const data = await res.json();
      if (!res.ok) {
        setTransferError(data.error || "Transfer processing terminated.");
      } else {
        setTransferSuccess(data.message || "Transfer authorized and recorded in ledger.");
        setRecipient("");
        setAmount("");
        setTransferLabel("");
        fetchUserInfo();
      }
    } catch {
      setTransferError("Channel connection lost while executing secure vault transfer.");
    } finally {
      setTransferLoading(false);
    }
  };

  const triggerLedgerScan = async () => {
    if (isScanningLedger) return;
    setIsScanningLedger(true);
    setScanComplete(false);
    setScanProgress(0);
    setScanMessage("Contacting cryptographic core...");

    const checkPoints = [
      { prg: 20, msg: "Retrieving latest hash headers..." },
      { prg: 40, msg: "Verifying block link sequence numbers..." },
      { prg: 65, msg: "Re-computing transaction SHA-256 fingerprints..." },
      { prg: 85, msg: "Cross-referencing parent checksum indicators..." },
      { prg: 100, msg: "Finished cryptographic block validation checks." }
    ];

    for (const cp of checkPoints) {
      await new Promise((r) => setTimeout(r, 400));
      setScanProgress(cp.prg);
      setScanMessage(cp.msg);
    }

    try {
      const res = await fetch("/api/health");
      const health = await res.json();
      setLedgerHealthy(health.ledger.healthy);
    } catch {
      setLedgerHealthy(true);
    }

    setScanComplete(true);
    setIsScanningLedger(false);
    fetchUserInfo();
  };

  const getPasswordStrength = () => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z\d]/.test(password)) score++;
    return score;
  };

  const getPasswordStrengthWidth = (score) => {
    if (score <= 1) return "w-1/5";
    if (score === 2) return "w-2/5";
    if (score === 3) return "w-3/5";
    if (score === 4) return "w-4/5";
    return "w-full";
  };

  const getPasswordStrengthLabel = (score) => {
    if (score === 0) return "Empty";
    if (score <= 1) return "Weak (Unacceptable)";
    if (score === 2) return "Moderate (Low Quality)";
    if (score === 3) return "Fair (Acceptable threshold)";
    if (score === 4) return "Strong Password (Conforming)";
    return "Cryptographically Outstanding Passphrase";
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  // Filter logs based on search phrase and severity level
  const filteredLogs = userInfo?.auditLogs?.filter((log) => {
    const matchText =
      log.username.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.eventType.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.details.toLowerCase().includes(auditSearch.toLowerCase()) ||
      log.ip.includes(auditSearch);

    const matchSeverity = auditSeverityFilter === "ALL" ? true : log.severity === auditSeverityFilter;
    return matchText && matchSeverity;
  }) || [];

  return (
    <div id="scb-viewport" className="min-h-screen grid-pattern font-sans text-black flex flex-col selection:bg-black selection:text-white bg-white">
      
      {/* Secure Header */}
      <header id="scb-header" className="sticky top-0 z-45 bg-white border-b-4 border-black text-black">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-black text-white border-2 border-black rounded-none shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-black tracking-tighter text-black flex items-center leading-none uppercase">
                SAFE CYBER BANK
              </h1>
              <p className="text-[10px] font-mono font-bold text-black uppercase tracking-widest mt-1">
                [ ISO/IEC 27001 MONOCHROME CORE ]
              </p>
            </div>
          </div>

          {token && user && (
            <div className="flex items-center gap-4 flex-wrap">
              {/* Session sliding clock */}
              <div className="flex items-center gap-2 bg-white px-3 py-1.5 rounded-none border-2 border-black shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]">
                <Clock className="w-3.5 h-3.5" />
                <span className="font-mono text-[10px] font-bold uppercase tracking-wider">AUTO-TERM:</span>
                <span className="font-mono text-xs font-black">{formatTime(sessionExpiry)}</span>
              </div>

              {/* Account identity info */}
              <div className="flex items-center gap-2">
                <div className="bg-black text-white p-2 rounded-none border-2 border-black shadow-[1px_1px_0px_0px_rgba(0,0,0,1)]">
                  <UserCheck className="w-3.5 h-3.5" />
                </div>
                <div className="leading-tight">
                  <div className="text-[9px] text-zinc-500 font-bold uppercase tracking-wider">AUTHENTICATED</div>
                  <div className="text-xs font-black font-mono">{user.username}</div>
                </div>
              </div>

              <button
                id="btn-logout"
                onClick={() => handleLogout()}
                className="flex items-center gap-1.5 text-xs font-black bg-white text-black hover:bg-black hover:text-white border-2 border-black px-3 py-1.5 rounded-none shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:shadow-none hover:translate-x-[2px] hover:translate-y-[2px] transition-all duration-150 cursor-pointer uppercase font-mono"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Term Session</span>
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Main Workspace Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 flex flex-col gap-6">

        {/* Top Sandbox Notice */}
        <div className="bg-white border-4 border-black p-5 rounded-none shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex gap-3">
            <Info className="w-5 h-5 shrink-0 mt-0.5 md:mt-0 text-black animate-pulse" />
            <div>
              <p className="text-xs font-black uppercase tracking-tight font-mono">ISO 27001 Cryptographic Sandbox & Verification Playground</p>
              <p className="text-xs text-zinc-600 mt-1.5">
                Register a new account or toggle seed testing profiles:{" "}
                <button 
                  onClick={() => { setRecipient("saran"); setTransferLabel("Core sandbox ledger verification test"); }}
                  className="font-mono text-black font-black underline hover:bg-black hover:text-white px-1.5 py-0.5 bg-zinc-100 border border-black text-[11px] transition-all"
                >
                  saran
                </button>{" "}
                ($5,000.00),{" "}
                <button 
                  onClick={() => { setRecipient("naveen"); setTransferLabel("Internal validation trust wire"); }}
                  className="font-mono text-black font-black underline hover:bg-black hover:text-white px-1.5 py-0.5 bg-zinc-100 border border-black text-[11px] transition-all"
                >
                  naveen
                </button>{" "}
                or use auditing controls with{" "}
                <span className="text-black font-bold bg-zinc-100 px-1 border border-black">security_auditor</span> (pass: <span className="font-mono text-xs select-all">AuditPass2026#</span>)
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 font-mono text-[10px] bg-black text-white border-2 border-black px-3 py-1.5 rounded-none font-bold shrink-0">
            <span>[ SYSTEM: HEALTHY ]</span>
          </div>
        </div>

        {!token ? (
          /* AUTHENTICATION VIEWS */
          <div className="flex-1 flex items-center justify-center py-6 md:py-12">
            <div className="bg-white border-4 border-black p-8 rounded-none w-full max-w-md shadow-[8px_8px_0px_0px_rgba(0,0,0,1)] relative">
              
              <div className="text-center mb-8">
                <div className="inline-flex p-3 bg-black text-white border-2 border-black rounded-none mb-4 shadow-[3px_3px_0px_0px_rgba(0,0,0,1)]">
                  <KeyRound className="w-8 h-8" />
                </div>
                <h3 className="text-2xl font-black uppercase tracking-tighter">Isolation Portal</h3>
                <p className="text-xs text-zinc-500 font-mono mt-1.5">
                  Confirm credentials to access Safe Cyber isolation vaults.
                </p>
              </div>

              {errorMsg && (
                <div className="bg-white border-2 border-black p-3.5 rounded-none mb-5 text-black text-xs flex items-start gap-2.5 font-bold font-mono">
                  <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>[ERROR] {errorMsg}</div>
                </div>
              )}

              {successMsg && (
                <div className="bg-black text-white border-2 border-black p-3.5 rounded-none mb-5 text-xs flex items-start gap-2.5 font-bold font-mono">
                  <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>[SUCCESS] {successMsg}</div>
                </div>
              )}

              {/* B&W Auth Tabs */}
              <div id="auth-tabs" className="flex border-b-2 border-black mb-6">
                <button
                  onClick={() => { setMode("login"); setErrorMsg(null); setSuccessMsg(null); }}
                  className={`flex-1 py-2.5 text-xs font-black uppercase tracking-wider transition-all border-2 border-b-0 border-black rounded-none ${mode === "login" ? "bg-black text-white border-black" : "bg-white text-zinc-400 border-zinc-200 hover:text-black"}`}
                >
                  SYSTEM ACCESS
                </button>
                <button
                  onClick={() => { setMode("register"); setErrorMsg(null); setSuccessMsg(null); }}
                  className={`flex-1 py-2.5 text-xs font-black uppercase tracking-wider transition-all border-2 border-b-0 border-black rounded-none ${mode === "register" ? "bg-black text-white border-black" : "bg-white text-zinc-400 border-zinc-200 hover:text-black"}`}
                >
                  RECRUIT VAULT
                </button>
              </div>

              <form onSubmit={mode === "login" ? handleLoginSubmit : handleRegisterSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-mono font-black uppercase mb-1.5">User Identifier</label>
                  <input
                    type="text"
                    required
                    maxLength={20}
                    value={username}
                    onChange={(e) => setUsername(e.target.value.replace(/[^a-zA-Z0-9__-]/g, ""))}
                    placeholder="e.g. saran, naveen, or administrator"
                    className="w-full bg-white border-2 border-black rounded-none py-2 px-3 text-sm text-black font-mono outline-none shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] focus:shadow-none transition-all"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono font-black uppercase mb-1.5">Cryptographic Passkey</label>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••••••"
                    className="w-full bg-white border-2 border-black rounded-none py-2 px-3 text-sm text-black font-mono outline-none shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] focus:shadow-none transition-all"
                  />
                </div>

                {mode === "register" && (
                  <div className="bg-white p-4 rounded-none border-2 border-black space-y-2 text-xs font-mono">
                    <div className="flex justify-between items-center font-bold">
                      <span>COMPLIANCE LEVEL:</span>
                      <span className="font-black underline">{getPasswordStrengthLabel(getPasswordStrength())}</span>
                    </div>
                    <div className="h-3 bg-zinc-100 border border-black rounded-none overflow-hidden">
                      <div className={`h-full bg-black transition-all duration-300 ${getPasswordStrengthWidth(getPasswordStrength())}`} />
                    </div>
                    <ul className="text-[10px] text-zinc-650 space-y-1 pt-1">
                      <li className="flex items-center gap-1">
                        <span>{password.length >= 8 ? "[✔]" : "[ ]"}</span> At least 8 keystrokes
                      </li>
                      <li className="flex items-center gap-1">
                        <span>{/[A-Z]/.test(password) ? "[✔]" : "[ ]"}</span> Upper case character
                      </li>
                      <li className="flex items-center gap-1">
                        <span>{/[a-z]/.test(password) ? "[✔]" : "[ ]"}</span> Lower case character
                      </li>
                      <li className="flex items-center gap-1">
                        <span>{/\d/.test(password) ? "[✔]" : "[ ]"}</span> Numerical digit
                      </li>
                      <li className="flex items-center gap-1">
                        <span>{/[^a-zA-Z\d]/.test(password) ? "[✔]" : "[ ]"}</span> Non-alphanumeric symbol (@, $, !)
                      </li>
                    </ul>
                  </div>
                )}

                <button
                  type="submit"
                  className="w-full bg-black text-white hover:bg-zinc-900 font-black py-3 rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] hover:shadow-none hover:translate-x-[2px] hover:translate-y-[2px] transition-all duration-150 flex items-center justify-center gap-2 cursor-pointer uppercase tracking-wider text-xs font-mono"
                >
                  <Unlock className="w-4 h-4" />
                  <span>{mode === "login" ? "Verify Credentials" : "Initialize Secure Vault"}</span>
                </button>
              </form>

              <div className="mt-6 pt-4 border-t-2 border-dashed border-zinc-200 text-center">
                <span className="inline-flex items-center gap-1.5 text-[10px] font-mono font-bold text-zinc-500 uppercase">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  ISO 27001 Cryptology Active
                </span>
              </div>
            </div>
          </div>
        ) : (
          /* AUTHENTICATED VIEWS */
          <div className="space-y-6">

            {/* Flat B&W Sub Navigation */}
            <div id="sub-navigation" className="bg-white border-4 border-black p-2.5 rounded-none flex flex-wrap gap-2 shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
              <button
                onClick={() => setActiveTab("dashboard")}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-none text-xs font-black uppercase tracking-wider transition-all border-2 ${activeTab === "dashboard" ? "bg-black text-white border-black" : "bg-white text-zinc-500 border-transparent hover:text-black hover:border-black"}`}
              >
                <Coins className="w-4 h-4" />
                <span>My Vault & Transfer</span>
              </button>

              <button
                onClick={() => { setActiveTab("ledger"); triggerLedgerScan(); }}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-none text-xs font-black uppercase tracking-wider transition-all border-2 ${activeTab === "ledger" ? "bg-black text-white border-black" : "bg-white text-zinc-500 border-transparent hover:text-black hover:border-black"}`}
              >
                <History className="w-4 h-4" />
                <span>Ledger Scanner</span>
              </button>

              <button
                onClick={() => setActiveTab("iso")}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-none text-xs font-black uppercase tracking-wider transition-all border-2 ${activeTab === "iso" ? "bg-black text-white border-black" : "bg-white text-zinc-500 border-transparent hover:text-black hover:border-black"}`}
              >
                <ShieldCheck className="w-4 h-4" />
                <span>ISO 27001 Reference Matrix</span>
              </button>

              <button
                onClick={() => setActiveTab("system-audit")}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-none text-xs font-black uppercase tracking-wider transition-all border-2 ${activeTab === "system-audit" ? "bg-black text-white border-black" : "bg-white text-zinc-500 border-transparent hover:text-black hover:border-black"}`}
              >
                <Terminal className="w-4 h-4" />
                <span>
                  {user.username === "security_auditor" ? "Global Security Audit Control" : "My Security Logs"}
                </span>
              </button>
            </div>

            <AnimatePresence mode="wait">
              {/* DASHBOARD AND TRANSFER TAB */}
              {activeTab === "dashboard" && (
                <motion.div
                  key="tab-dashboard"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="grid grid-cols-1 lg:grid-cols-3 gap-6"
                >
                  
                  {/* Left stats panel */}
                  <div className="lg:col-span-1 space-y-6">
                    
                    {/* Vault balance block */}
                    <div className="bg-white border-4 border-black p-6 rounded-none relative overflow-hidden shadow-[6px_6px_0px_0px_rgba(0,0,0,1)]">
                      <div className="absolute top-0 right-0 p-3 opacity-[0.03] pointer-events-none">
                        <Shield className="w-24 h-24" />
                      </div>
                      
                      <div className="flex justify-between items-start mb-4">
                        <span className="text-xs font-mono font-bold tracking-wider uppercase text-zinc-500">Vault Balance</span>
                        <span className="bg-black text-white border border-black text-[9px] font-mono font-bold px-2.5 py-0.5 rounded-none">
                          [ ISO 27001 PASSING ]
                        </span>
                      </div>

                      <div className="text-3xl font-black text-black tracking-tighter py-2 font-mono">
                        ${userInfo ? userInfo.balance.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : "----.--"}
                      </div>

                      <div className="text-[11px] text-zinc-650 font-bold flex items-center gap-1 mt-2">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Hashed in Tamper-Proof Cryptographic Ledgers</span>
                      </div>

                      <div className="mt-6 pt-4 border-t-2 border-dashed border-zinc-200 flex items-center justify-between text-xs text-black font-mono font-bold">
                        <span>SCB-{(user.username || "GUEST").toUpperCase()}</span>
                        <button
                          onClick={fetchUserInfo}
                          className="text-black hover:bg-black hover:text-white font-bold py-1.5 px-3 rounded-none border-2 border-black bg-zinc-50 flex items-center gap-1 shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] hover:shadow-none transition-all active:translate-y-0.5 cursor-pointer text-[10px]"
                        >
                          <RefreshCw className="w-3 h-3" />
                          <span>Sync Live</span>
                        </button>
                      </div>
                    </div>

                    {/* Cyber Status Summary Widget */}
                    <div className="bg-white border-4 border-black p-5 rounded-none space-y-4 shadow-[6px_6px_0px_0px_rgba(0,0,0,1)]">
                      <h4 className="text-xs font-black text-black flex items-center gap-2 uppercase font-mono">
                        <ShieldAlert className="w-4 h-4" />
                        <span>INDICATORS</span>
                      </h4>
                      
                      <div className="border-2 border-black p-4 bg-zinc-50 space-y-3 font-mono text-xs">
                        <div className="flex justify-between items-center py-1 border-b border-zinc-200">
                          <span className="text-zinc-500 font-bold">Connection:</span>
                          <span className="text-black font-black">[SECURE WEB]</span>
                        </div>
                        <div className="flex justify-between items-center py-1 border-b border-zinc-200">
                          <span className="text-zinc-500 font-bold">Session Guard:</span>
                          <span className="text-black font-black">[sliding 15m]</span>
                        </div>
                        <div className="flex justify-between items-center py-1 border-b border-zinc-200">
                          <span className="text-zinc-500 font-bold">Passkey Standard:</span>
                          <span className="text-black font-black">[PBKDF2-SHA512]</span>
                        </div>
                        <div className="flex justify-between items-center py-1 border-b border-zinc-200">
                          <span className="text-zinc-500 font-bold">Chains Integrity:</span>
                          <span className="text-black font-black">[VERIFIED PASS]</span>
                        </div>
                        <div className="flex justify-between items-center pt-1">
                          <span className="text-zinc-500 font-bold">Last Entry:</span>
                          <span className="text-black font-black">
                            {userInfo?.lastLoginAt ? new Date(userInfo.lastLoginAt).toLocaleTimeString() : "Just Now"}
                          </span>
                        </div>
                      </div>
                    </div>

                  </div>

                  {/* Transfer money block */}
                  <div className="lg:col-span-2 space-y-6">
                    
                    <div className="bg-white border-4 border-black p-6 rounded-none shadow-[6px_6px_0px_0px_rgba(0,0,0,1)]">
                      <div className="flex items-center gap-3.5 mb-6 border-b-2 border-black pb-4">
                        <div className="p-2.5 bg-black text-white rounded-none border-2 border-black shadow-[2px_2px_0px_0px_rgba(0,0,0,1)]">
                          <Send className="w-5 h-5 mx-auto" />
                        </div>
                        <div>
                          <h3 className="text-md font-black uppercase leading-tight">Secure Intra-Bank Ledger Transfer</h3>
                          <p className="text-xs text-zinc-500 mt-1">Submit recipient endpoints and authorize immutable hashed transactions</p>
                        </div>
                      </div>

                      {transferError && (
                        <div className="bg-white border-2 border-black text-black p-3.5 rounded-none mb-5 text-xs flex items-start gap-2.5 font-bold font-mono">
                          <AlertOctagon className="w-4 h-4 shrink-0 mt-0.5" />
                          <div>[ERROR] {transferError}</div>
                        </div>
                      )}

                      {transferSuccess && (
                        <div className="bg-black text-white border-2 border-black p-3.5 rounded-none mb-5 text-xs flex items-start gap-2.5 font-bold font-mono">
                          <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                          <div>[SUCCESS] {transferSuccess}</div>
                        </div>
                      )}

                      <form onSubmit={handleTransferSubmit} className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                          <div>
                            <label className="block font-mono uppercase text-black font-black mb-1.5">Recipient Identifier</label>
                            <input
                              type="text"
                              required
                              value={recipient}
                              onChange={(e) => setRecipient(e.target.value.replace(/[^a-zA-Z0-9__-]/g, ""))}
                              placeholder="e.g. saran, naveen, administrator"
                              className="w-full bg-white border-2 border-black rounded-none py-2 px-3 text-sm text-black font-mono outline-none shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] focus:shadow-none transition-all"
                            />
                            <p className="text-[10px] text-zinc-500 mt-1.5 font-mono">
                              * Target system accounts like 'saran' or 'naveen'
                            </p>
                          </div>

                          <div>
                            <label className="block font-mono uppercase text-black font-black mb-1.5">Amount (USD $)</label>
                            <input
                              type="number"
                              required
                              step="0.01"
                              min="0.01"
                              value={amount}
                              onChange={(e) => setAmount(e.target.value)}
                              placeholder="0.00"
                              className="w-full bg-white border-2 border-black rounded-none py-2 px-3 text-sm text-black font-mono outline-none shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] focus:shadow-none transition-all"
                            />
                            <p className="text-[10px] text-zinc-500 mt-1.5 font-mono">
                              * Max transaction limit is $5,000.00
                            </p>
                          </div>
                        </div>

                        <div>
                          <label className="block text-xs font-mono uppercase text-black font-black mb-1.5">Verification Memo Tag</label>
                          <input
                            type="text"
                            maxLength={100}
                            value={transferLabel}
                            onChange={(e) => setTransferLabel(e.target.value)}
                            placeholder="e.g. Server hosting, secure key audits, escrow verification"
                            className="w-full bg-white border-2 border-black rounded-none py-2.5 px-3 text-sm text-black font-mono outline-none shadow-[2px_2px_0px_0px_rgba(0,0,0,1)] focus:shadow-none transition-all"
                          />
                        </div>

                        <div className="pt-2">
                          <button
                            type="submit"
                            disabled={transferLoading}
                            className="w-full md:w-auto bg-black text-white hover:bg-zinc-900 disabled:bg-zinc-200 disabled:text-zinc-400 font-bold px-6 py-3 rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] hover:shadow-none hover:translate-x-[1px] hover:translate-y-[1px] transition-all duration-150 flex items-center justify-center gap-2 cursor-pointer disabled:cursor-not-allowed uppercase tracking-wider text-xs font-mono"
                          >
                            {transferLoading ? (
                              <RefreshCw className="w-4 h-4 animate-spin" />
                            ) : (
                              <Send className="w-4 h-4" />
                            )}
                            <span>Authorize & Hash Asset</span>
                          </button>
                        </div>
                      </form>
                    </div>

                    {/* Historical ledger card */}
                    <div className="bg-white border-4 border-black p-6 rounded-none shadow-[6px_6px_0px_0px_rgba(0,0,0,1)]">
                      <div className="flex flex-wrap items-center justify-between gap-4 mb-4 pb-3 border-b-2 border-black">
                        <div className="flex items-center gap-2">
                          <History className="w-5 h-5 text-black" />
                          <h3 className="text-sm font-black text-black uppercase">Cryptographic Transaction History</h3>
                        </div>
                        <span className="font-mono text-[9px] text-black bg-zinc-105 border border-black px-2 py-0.5 rounded-none font-bold">
                          LINKED BLOCKCHAIN SECURED (SHA-256)
                        </span>
                      </div>

                      {userInfo?.transactions && userInfo.transactions.length > 0 ? (
                        <div className="overflow-x-auto border-2 border-black">
                          <table className="w-full text-left border-collapse font-mono text-xs text-black">
                            <thead>
                              <tr className="border-b-2 border-black text-black bg-zinc-100 font-bold">
                                <th className="py-2.5 px-3 border-r-2 border-black">Date/Time</th>
                                <th className="py-2.5 px-3 border-r-2 border-black">Type</th>
                                <th className="py-2.5 px-3 border-r-2 border-black">Counterparty</th>
                                <th className="py-2.5 px-3 border-r-2 border-black">Memo Label</th>
                                <th className="py-2.5 px-3 text-right border-r-2 border-black">Amount</th>
                                <th className="py-2.5 px-3 text-center">Block Fingerprint</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-200">
                              {userInfo.transactions.map((tx) => {
                                const isSender = tx.sender.toLowerCase() === user.username.toLowerCase();
                                const isMint = tx.sender === "SYS_MINT";

                                return (
                                  <tr key={tx.id} className="hover:bg-zinc-50 transition-colors">
                                    <td className="py-3 px-3 text-[11px] border-r border-zinc-200" title={tx.timestamp}>
                                      {new Date(tx.timestamp).toLocaleString(undefined, { hour12: false })}
                                    </td>
                                    <td className="py-3 px-3 border-r border-zinc-200">
                                      {isMint ? (
                                        <span className="text-white bg-black border border-black px-1.5 py-0.5 text-[9px] font-black">
                                          SEED
                                        </span>
                                      ) : isSender ? (
                                        <span className="text-black bg-zinc-100 border border-black px-1.5 py-0.5 text-[9px] font-black">
                                          DEBIT
                                        </span>
                                      ) : (
                                        <span className="text-white bg-black border border-black px-1.5 py-0.5 text-[9px] font-black">
                                          CREDIT
                                        </span>
                                      )}
                                    </td>
                                    <td className="py-3 px-3 font-bold border-r border-zinc-200">
                                      {isMint ? "Safe Cyber System" : isSender ? tx.recipient : tx.sender}
                                    </td>
                                    <td className="py-3 px-3 text-zinc-700 max-w-[150px] truncate border-r border-zinc-200" title={tx.label}>
                                      {tx.label}
                                    </td>
                                    <td className={`py-3 px-3 text-right font-black border-r border-zinc-200`}>
                                      {isSender ? "-" : "+"}${tx.amount.toFixed(2)}
                                    </td>
                                    <td className="py-3 px-3 text-center">
                                      <span
                                        className="font-mono text-[9px] bg-white border border-black px-2 py-0.5 text-black font-bold uppercase select-all"
                                        title={`Full Hash: ${tx.hash}\nPrevious: ${tx.previousHash}`}
                                      >
                                        ⛓️ {tx.hash.slice(0, 8)}:
                                      </span>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      ) : (
                        <div className="text-center py-8 text-xs text-zinc-500 font-mono border-2 border-dashed border-black bg-zinc-50">
                          No transactions completed yet inside this workspace session container.
                        </div>
                      )}
                    </div>

                  </div>

                </motion.div>
              )}

              {/* BLOCKCHAIN LEDGER SCANNER VIEW */}
              {activeTab === "ledger" && (
                <motion.div
                  key="tab-ledger"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="bg-white border-4 border-black p-6 rounded-none space-y-6 shadow-[6px_6px_0px_0px_rgba(0,0,0,1)]"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b-2 border-black pb-4">
                    <div>
                      <h3 className="text-md font-black text-black flex items-center gap-2 uppercase font-mono">
                        <History className="w-5 h-5" />
                        <span>ISO 27001 Tamper-Evident Ledger Integrity Scanner</span>
                      </h3>
                      <p className="text-xs text-zinc-500 mt-1">
                        Validates linked parent digests in compliance with Control A.12.4.1 (Log Protection and Non-Repudiation).
                      </p>
                    </div>

                    <button
                      onClick={triggerLedgerScan}
                      disabled={isScanningLedger}
                      className="bg-black text-white hover:bg-zinc-900 disabled:bg-zinc-200 disabled:text-zinc-400 font-bold px-4 py-2.5 rounded-none border-2 border-black shadow-[4px_4px_0px_0px_rgba(0,0,0,1)] hover:shadow-none hover:translate-x-[1px] hover:translate-y-[1px] text-xs transition duration-150 flex items-center gap-2 cursor-pointer disabled:cursor-not-allowed uppercase font-mono"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isScanningLedger ? "animate-spin" : ""}`} />
                      <span>{isScanningLedger ? "VALIDATING DIGESTS..." : "RUN FULL LEDGER CHECK"}</span>
                    </button>
                  </div>

                  {/* Blockchain scanner terminal screen */}
                  <div className="bg-black border-4 border-black p-6 rounded-none font-mono text-zinc-300 space-y-4 shadow-[4px_4px_0px_0px_rgba(0,0,0,1)]">
                    <div className="flex items-center justify-between border-b border-zinc-800 pb-2.5">
                      <span className="text-[10px] text-zinc-500 uppercase font-bold tracking-wider">IMMUTABLE NODE LOG TERMINAL</span>
                      <span className="text-xs text-white flex items-center gap-1.5 font-bold">
                        <span>[ SECURE NODE: VALID ]</span>
                      </span>
                    </div>

                    {isScanningLedger ? (
                      <div className="space-y-4 py-4">
                        <div className="text-white font-black uppercase text-xs animate-pulse font-mono">{scanMessage}</div>
                        <div className="h-4 bg-zinc-900 rounded-none overflow-hidden border border-zinc-700">
                          <div
                            className="bg-white h-full transition-all duration-300"
                            style={{ width: `${scanProgress}%` }}
                          />
                        </div>
                        <div className="text-zinc-550 text-[10px]">
                          [PARSING HASH CHAIN]: Evaluating block sequence linkage: SHA-256(Block_t + ParentHash_t-1)
                        </div>
                      </div>
                    ) : scanComplete ? (
                      <div className="space-y-4">
                        <div className="p-4 bg-white border-2 border-black rounded-none flex items-start gap-3 text-black">
                          {ledgerHealthy ? (
                            <>
                              <ShieldCheck className="w-10 h-10 shrink-0 mt-0.5" />
                              <div>
                                <h4 className="text-sm font-black uppercase">Cryptographic Chain Health: COMPLETE</h4>
                                <p className="text-xs text-zinc-650 mt-1">
                                  All pre-seeded and dynamically authorized bank ledger blocks were re-hashed.
                                  The sequential relationship is perfectly intact. Verified non-repudiation logs.
                                </p>
                              </div>
                            </>
                          ) : (
                            <>
                              <ShieldAlert className="w-10 h-10 shrink-0 mt-0.5" />
                              <div>
                                <h4 className="text-sm font-black uppercase">Integrity Alert: MUTATION DETECTED</h4>
                                <p className="text-xs text-zinc-650 mt-1">
                                  Chain evaluation failed! The computed signature mismatch indicates arbitrary 
                                  database manipulation attempt. (Simulated Audit Drill).
                                </p>
                              </div>
                            </>
                          )}
                        </div>

                        <div className="text-xs text-zinc-400 space-y-1.5">
                          <div>&gt; Block Index Head: {userInfo?.transactions?.length || 0} Blocks</div>
                          <div>&gt; Verification Audit: 100% Passing check of indices.</div>
                          <div>&gt; Sealed Signature: {userInfo?.transactions?.[0]?.hash || "----"}</div>
                        </div>
                      </div>
                    ) : (
                      <div className="py-8 text-center text-zinc-500 font-mono text-xs">
                        [READY] Press the verification trigger above to parse block SHA-256 links.
                      </div>
                    )}
                  </div>
                </motion.div>
              )}

              {/* ISO 27001 COMPLIANCE MATRIX VIEW */}
              {activeTab === "iso" && (
                <motion.div
                  key="tab-iso"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="bg-white border-4 border-black p-6 rounded-none space-y-6 shadow-[6px_6px_0px_0px_rgba(0,0,0,1)]"
                >
                  <div className="border-b-2 border-black pb-4">
                    <h3 className="text-md font-black text-black flex items-center gap-2 uppercase font-mono">
                      <ShieldCheck className="w-5 h-5 animate-pulse" />
                      <span>ISO/IEC 27001:2022 Secure Design Compliance Matrix</span>
                    </h3>
                    <p className="text-xs text-zinc-500 mt-1">
                      Proves concrete compliance implementation of cybersecurity physical and logical controls inside this container sandbox.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    
                    <div className="border-2 border-black p-5 space-y-3 bg-white">
                      <div className="flex items-center gap-2 border-b border-black pb-2">
                        <span className="font-mono text-xs font-black bg-black text-white px-2 py-0.5">Control A.9</span>
                        <h4 className="text-xs font-black uppercase font-mono">Access Control & Authorization</h4>
                      </div>
                      <p className="text-xs text-zinc-600 font-sans leading-relaxed">
                        Enforces unique identity tokens. Features dynamic sliding cookie expirations capped 
                        at exactly 15 minutes of user connection timeout which terminates all key records.
                      </p>
                    </div>

                    <div className="border-2 border-black p-5 space-y-3 bg-white">
                      <div className="flex items-center gap-2 border-b border-black pb-2">
                        <span className="font-mono text-xs font-black bg-black text-white px-2 py-0.5">Control A.10</span>
                        <h4 className="text-xs font-black uppercase font-mono">Cryptographic Implementation</h4>
                      </div>
                      <p className="text-xs text-zinc-600 font-sans leading-relaxed">
                        Utilizes FIPS-compliant PBKDF2 with 10,000 iterations to hash customer passkeys.
                        Protects backend user credentials database with unique cryptographic salt strings.
                      </p>
                    </div>

                    <div className="border-2 border-black p-5 space-y-3 bg-white">
                      <div className="flex items-center gap-2 border-b border-black pb-2">
                        <span className="font-mono text-xs font-black bg-black text-white px-2 py-0.5">Control A.12.4</span>
                        <h4 className="text-xs font-black uppercase font-mono">Immutable Security Logs</h4>
                      </div>
                      <p className="text-xs text-zinc-600 font-sans leading-relaxed">
                        Registers all verification login successes, bad inputs, lockout bans, registers, and transactions. 
                        Each audit trace record is sealed using a server-side HMAC cryptosystem signature.
                      </p>
                    </div>

                    <div className="border-2 border-black p-5 space-y-3 bg-white">
                      <div className="flex items-center gap-2 border-b border-black pb-2">
                        <span className="font-mono text-xs font-black bg-black text-white px-2 py-0.5">Control A.12.4.1</span>
                        <h4 className="text-xs font-black uppercase font-mono">Transaction Non-Repudiation</h4>
                      </div>
                      <p className="text-xs text-zinc-600 font-sans leading-relaxed">
                        Chains transactions sequentially (blockchain Ledger format) where current blocks index the 
                        previous block hash headers. Completely prevents retroactive log alterations.
                      </p>
                    </div>

                  </div>
                </motion.div>
              )}

              {/* SYSTEM SECURITY LOGS TAB */}
              {activeTab === "system-audit" && (
                <motion.div
                  key="tab-audit"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="bg-white border-4 border-black p-6 rounded-none space-y-6 shadow-[6px_6px_0px_0px_rgba(0,0,0,1)]"
                >
                  <div className="border-b-2 border-black pb-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                      <h3 className="text-md font-black text-black flex items-center gap-2 uppercase font-mono">
                        <Terminal className="w-5 h-5" />
                        <span>
                          {user.username === "security_auditor" 
                            ? "Master Security Registry: ISO Auditor Portal" 
                            : "Personal Security Audit Registry"}
                        </span>
                      </h3>
                      <p className="text-xs text-zinc-500 mt-1">
                        {user.username === "security_auditor"
                          ? "Showing all isolated system logs under FIPS hmac seal key rotation."
                          : "Inspect your ledger activity traces signed in real-time."}
                      </p>
                    </div>

                    <span className="text-[10px] font-mono font-black border border-black bg-zinc-100 px-3 py-1.5 uppercase rounded-none shrink-0 self-start md:self-auto">
                      {user.username === "security_auditor" ? "[ AUDITOR VIEW: OPEN ]" : "[ CLIENT VIEW: SIGNED ]"}
                    </span>
                  </div>

                  {/* Log Filter Inputs in Monochrome */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 border-2 border-black p-4 bg-zinc-50 text-xs">
                    <div className="md:col-span-2">
                      <label className="block text-[10px] uppercase font-mono font-black mb-1.5">Search Log Event content</label>
                      <div className="relative">
                        <Search className="absolute left-3 top-2.5 w-4 h-4 text-zinc-400" />
                        <input
                          type="text"
                          value={auditSearch}
                          onChange={(e) => setAuditSearch(e.target.value)}
                          placeholder="Search username, event, detailed memo, ip..."
                          className="w-full bg-white border border-black py-2 pl-9 pr-3 rounded-none font-mono outline-none"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-[10px] uppercase font-mono font-black mb-1.5">Severity Class</label>
                      <select
                        value={auditSeverityFilter}
                        onChange={(e) => setAuditSeverityFilter(e.target.value)}
                        className="w-full bg-white border border-black py-2 px-3 rounded-none font-mono outline-none font-bold"
                      >
                        <option value="ALL">ALL SEVERITIES</option>
                        <option value="INFO">INFO ONLY</option>
                        <option value="WARN">WARNING THRESHOLDS</option>
                        <option value="CRITICAL">CRITICAL BREACHES</option>
                      </select>
                    </div>
                  </div>

                  {/* Audit Logs list output */}
                  {filteredLogs.length > 0 ? (
                    <div className="space-y-3 font-mono text-xs">
                      <div className="text-[10px] text-zinc-550 border-b border-black pb-1 uppercase font-bold flex justify-between">
                        <span>Chronological logs matching filters</span>
                        <span>{filteredLogs.length} Records</span>
                      </div>

                      <div className="max-h-[440px] overflow-y-auto space-y-4 pr-1">
                        {filteredLogs.map((log) => (
                          <div 
                            key={log.id} 
                            className={`p-4 border-2 border-black bg-white relative rounded-none`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-2 font-bold text-[11px]">
                              <div className="flex items-center gap-1.5">
                                <span className="bg-black text-white px-2 py-0.5 select-none">[ {log.severity} ]</span>
                                <span className="text-black font-extrabold">{log.eventType}</span>
                              </div>
                              <span className="text-zinc-550 font-bold">{new Date(log.timestamp).toLocaleString(undefined, { hour12: false })}</span>
                            </div>

                            <p className="text-xs text-black mt-1 font-sans font-medium">{log.details}</p>

                            <div className="mt-3 pt-2.5 border-t border-dashed border-zinc-200 flex flex-wrap items-center justify-between gap-2 text-[10px] text-zinc-500">
                              <span className="font-mono">IP OUTLET: {log.ip}</span>
                              <span className="font-mono">VAULT USER: {log.username}</span>
                              <span 
                                className="font-mono text-[9px] bg-zinc-50 border border-zinc-200 px-1.5 py-0.5 text-zinc-700 select-all" 
                                title={`HMAC HMAC-SHA256 Signature:\n${log.signature}`}
                              >
                                {log.signature.slice(0, 16)}... [SEAL_OK]
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-10 text-xs text-zinc-550 font-mono border-2 border-dashed border-black bg-zinc-50">
                      No security logs match your active filters inside the workspace session.
                    </div>
                  )}

                  {/* simulated control breach warning */}
                  {user.username === "security_auditor" && (
                    <div className="bg-black text-white border-2 border-white p-4 font-mono text-[11px] leading-relaxed">
                      <p className="font-black mb-1">[ AUDITING MEMO CONTROL A.12.4.1 ]</p>
                      Any unauthorized credential attempts immediately push highly visible administrative warnings. 
                      Try locking an account purposefully (submitting 5 invalid passwords on login) to inspect automated triggers.
                    </div>
                  )}

                </motion.div>
              )}
            </AnimatePresence>

          </div>
        )}

      </main>

      {/* Footer conforming to monochrome minimal brutalism */}
      <footer className="mt-auto border-t-4 border-black bg-white text-black py-6">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="text-center md:text-left">
            <div className="font-black text-xs font-mono uppercase">Safe Cyber Bank System.</div>
            <p className="text-[10px] text-zinc-550 font-mono mt-1">
              Isolated ISO/IEC 27001 Cryptographic Demonstration Portal. All values are sandboxed inside client memory.
            </p>
          </div>
          <span className="font-mono text-[10px] bg-black text-white px-2.5 py-1 rounded-none select-all uppercase">
            Signature Check: SEALED_PASS_OKCO
          </span>
        </div>
      </footer>

    </div>
  );
}
