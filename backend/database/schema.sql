-- SQL Schema for Safe Cyber Bank (MySQL Database)
-- Compliance reference: ISO/IEC 27001 Access Control (A.9) and Log Integrity (A.12)

CREATE DATABASE IF NOT EXISTS safe_cyber_bank;
USE safe_cyber_bank;

-- 1. Users table (ISO 27001 A.9 User Access Management)
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(50) PRIMARY KEY,
    password_hash VARCHAR(130) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    balance DECIMAL(15, 2) NOT NULL DEFAULT 1000.00,
    failed_login_count INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME NULL
);

-- 2. Ledger Transactions table (ISO 27001 A.14.2.1 Secure Development Policy / Non-repudiation)
CREATE TABLE IF NOT EXISTS transactions (
    id VARCHAR(50) PRIMARY KEY,
    sender VARCHAR(50) NOT NULL,
    recipient VARCHAR(50) NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    label VARCHAR(255) NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    hash VARCHAR(64) NOT NULL,
    FOREIGN KEY (sender) REFERENCES users(username) ON DELETE RESTRICT,
    FOREIGN KEY (recipient) REFERENCES users(username) ON DELETE RESTRICT
);

-- 3. Tamper-witnessed Audit Logs (ISO 27001 A.12.4.1 Logging and Monitoring)
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(50) PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100) NOT NULL,
    username VARCHAR(50) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    details TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    signature VARCHAR(64) NOT NULL -- HMAC-SHA256 signature to witness ledger alterations
);
