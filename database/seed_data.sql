-- ScamShield AI - Seed Data
-- Provides initial admin, standard user, and sample scan records

USE scamshield_db;

-- 1. Insert Initial Users
-- Passwords:
-- admin: Admin@123
-- user:  User@123
INSERT INTO users (id, username, email, password_hash, role, is_active, created_at)
VALUES
(1, 'admin', 'admin@scamshield.ai', 'scrypt:32768:8:1$mZtmlkNPtvGUKsVG$85be665a9ddce2a1ca30b3eea608d9fca42efb014fab93d301ca5ee17e9d90d32ad17835dad510674c7aa896cc95bd4a9f1fbc7a67f8763fa749e51d59d8b088', 'admin', 1, NOW()),
(2, 'user', 'demo@scamshield.ai', 'scrypt:32768:8:1$sJag6zPTbwJFrzrA$4a9aba64fbe440d6cef15db735aa3706d45f3ea77cb7cea3891de86d042db5ff02bb037aa8be02ae7a267061b95c92d72dbf2d181959b9b8dbfb742d0c2b8d20', 'user', 1, NOW())
ON DUPLICATE KEY UPDATE updated_at = NOW();

-- 2. Insert Sample Scans
INSERT INTO scans (id, user_id, scan_type, input_preview, status, created_at)
VALUES
(1, 2, 'message', 'Dear customer, your SBI account 4819 is blocked due to missing PAN. Click http://sbi-pan-update.in to verify immediately.', 'completed', DATE_SUB(NOW(), INTERVAL 5 DAY)),
(2, 2, 'email', 'Subject: Income Tax Refund Notice 2026 - Action Required within 24 hours to claim Rs 42,850', 'completed', DATE_SUB(NOW(), INTERVAL 4 DAY)),
(3, 2, 'url', 'http://192.168.1.1/paytm-kyc-approval/login.php', 'completed', DATE_SUB(NOW(), INTERVAL 3 DAY)),
(4, 2, 'message', 'Hi Mom, I lost my phone and wallet. Please transfer 15000 urgently to this UPI id: emergency.help@upi', 'completed', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(5, 2, 'pdf_invoice', 'Invoice #INV-2026-098 from Apex Tech Supplies - Bank account updated to ICICI A/C 99882211', 'completed', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(6, 2, 'message', 'Meeting scheduled for tomorrow at 10 AM at the Bangalore main branch. Please bring your laptop.', 'completed', NOW())
ON DUPLICATE KEY UPDATE status = 'completed';

-- 3. Insert Scan Results
INSERT INTO scan_results (id, scan_id, risk_score, risk_level, predicted_category, model_version, confidence, explanation, recommendations, created_at)
VALUES
(1, 1, 94, 'Very High Risk', 'Fake KYC updates', 'v1.0.0', 0.96, 'High probability banking phishing attempt impersonating State Bank of India (SBI) requesting urgent PAN verification via suspicious external domain.', '["Do NOT click the embedded link.", "Block and report this number to 1930 or sbi.co.in.", "Banks never send unverified third-party links for KYC."]', DATE_SUB(NOW(), INTERVAL 5 DAY)),
(2, 2, 88, 'Very High Risk', 'Refund scams', 'v1.0.0', 0.91, 'Impersonates Income Tax Department offering fraudulent tax refund with artificial 24-hour urgency deadline to extract banking credentials.', '["Never share banking credentials for refunds.", "Verify legitimate refunds only on incometax.gov.in.", "Report phishing email to incident@cert-in.org.in."]', DATE_SUB(NOW(), INTERVAL 4 DAY)),
(3, 3, 92, 'Very High Risk', 'Malicious URLs', 'v1.0.0', 0.95, 'Suspicious raw IP address hostname disguised as Paytm KYC portal with suspicious URL path keywords.', '["Do NOT visit or input login credentials.", "Report malicious IP to national cybercrime portal.", "Always access Paytm exclusively via official app or paytm.com."]', DATE_SUB(NOW(), INTERVAL 3 DAY)),
(4, 4, 78, 'High Risk', 'UPI payment fraud', 'v1.0.0', 0.83, 'Impersonation urgency fraud soliciting direct money transfer via UPI under emergency pretexts.', '["Call your relative directly on their known phone number.", "Never send money to unverified UPI IDs.", "Verify caller identity before initiating payments."]', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(5, 5, 82, 'Very High Risk', 'Fake invoice and supplier payment fraud', 'v1.0.0', 0.85, 'Supplier invoice contains unverified bank account change notification, urgency payment cues, and mismatched tax arithmetic.', '["Perform out-of-band phone verification with vendor management.", "Do NOT transfer funds until bank account change is authorized.", "Cross-reference vendor GSTIN on official GST portal."]', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(6, 6, 8, 'Low Risk', 'Legitimate communication', 'v1.0.0', 0.12, 'Normal business communication with no deceptive links, financial solicitations, urgency triggers, or credential harvesting indicators.', '["Standard safe business communication.", "Verify calendar invites as per normal routine."]', NOW())
ON DUPLICATE KEY UPDATE risk_score = VALUES(risk_score);

-- 4. Insert Scan Evidence
INSERT INTO scan_evidence (scan_result_id, evidence_type, evidence_description, severity)
VALUES
(1, 'impersonation', 'Impersonates State Bank of India (SBI)', 'critical'),
(1, 'url', 'Suspicious non-official domain http://sbi-pan-update.in', 'critical'),
(1, 'urgency', 'Urgency trigger: "blocked immediately"', 'high'),
(2, 'impersonation', 'Impersonates Government Tax Authority', 'critical'),
(2, 'urgency', 'Artificial 24-hour deadline trigger', 'high'),
(2, 'financial', 'Lure: Rs 42,850 tax refund', 'high'),
(3, 'url_ip', 'Raw IPv4 address hostname used instead of legitimate domain', 'critical'),
(3, 'keywords', 'Keywords "paytm-kyc-approval" on untrusted host', 'high'),
(4, 'social_engineering', 'Impersonating family member with urgent distress narrative', 'high'),
(4, 'financial', 'Direct unverified UPI address transfer request', 'high'),
(5, 'bank_change', 'Noticeable supplier bank account change detected', 'critical'),
(5, 'arithmetic', 'Mismatched subtotal and tax amounts on invoice lines', 'high');

-- 5. Insert Scan History
INSERT INTO scan_history (scan_id, user_id, action_taken, timestamp)
VALUES
(1, 2, 'scanned', DATE_SUB(NOW(), INTERVAL 5 DAY)),
(2, 2, 'scanned', DATE_SUB(NOW(), INTERVAL 4 DAY)),
(3, 2, 'scanned', DATE_SUB(NOW(), INTERVAL 3 DAY)),
(4, 2, 'scanned', DATE_SUB(NOW(), INTERVAL 2 DAY)),
(5, 2, 'scanned', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(6, 2, 'scanned', NOW());

-- 6. Insert Audit Logs
INSERT INTO audit_logs (user_id, action, details, ip_address, timestamp)
VALUES
(1, 'USER_LOGIN', 'Admin user logged in successfully', '127.0.0.1', DATE_SUB(NOW(), INTERVAL 6 DAY)),
(2, 'USER_REGISTER', 'User demo registered account', '127.0.0.1', DATE_SUB(NOW(), INTERVAL 5 DAY)),
(2, 'SCAN_EXECUTE', 'User scanned SMS message #1', '127.0.0.1', DATE_SUB(NOW(), INTERVAL 5 DAY)),
(2, 'SCAN_EXECUTE', 'User scanned Email #2', '127.0.0.1', DATE_SUB(NOW(), INTERVAL 4 DAY)),
(2, 'SCAN_EXECUTE', 'User scanned URL #3', '127.0.0.1', DATE_SUB(NOW(), INTERVAL 3 DAY));
