-- ScamShield AI - MySQL Database Schema
-- Database: scamshield_db
-- Target: MySQL 8.0+

CREATE DATABASE IF NOT EXISTS scamshield_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE scamshield_db;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_email (email),
    INDEX idx_user_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Scans Table
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    scan_type VARCHAR(30) NOT NULL, -- 'message', 'email', 'url', 'image', 'pdf_invoice'
    input_preview TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'completed',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_scans_user_id (user_id),
    INDEX idx_scans_type (scan_type),
    INDEX idx_scans_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Scan Results Table
CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL UNIQUE,
    risk_score INT NOT NULL, -- 0 to 100
    risk_level VARCHAR(30) NOT NULL, -- 'Low Risk', 'Medium Risk', 'High Risk', 'Very High Risk'
    predicted_category VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL DEFAULT 'v1.0.0',
    confidence FLOAT NOT NULL DEFAULT 0.0,
    explanation TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    INDEX idx_scan_risk_score (risk_score),
    INDEX idx_scan_category (predicted_category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Scan Evidence Table
CREATE TABLE IF NOT EXISTS scan_evidence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_result_id INT NOT NULL,
    evidence_type VARCHAR(50) NOT NULL,
    evidence_description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE CASCADE,
    INDEX idx_evidence_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Scan History Table
CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    user_id INT NULL,
    action_taken VARCHAR(100) NOT NULL DEFAULT 'scanned',
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_history_user (user_id),
    INDEX idx_history_time (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_audit_action (action),
    INDEX idx_audit_time (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
