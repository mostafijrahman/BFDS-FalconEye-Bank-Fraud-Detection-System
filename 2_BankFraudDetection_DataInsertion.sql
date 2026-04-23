-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Script 2: Sample Data Insertion
-- Version: 2.0  |  Date: April 2026
-- ============================================================

USE bank_fraud_detection_db;
GO

-- ============================================================
-- SECTION 1: INSERT USERS  (6 users: low / medium / high risk)
-- ============================================================
INSERT INTO users
    (first_name, last_name, email, phone, account_status, risk_profile, country_iso_code, registration_ip_address)
VALUES
-- Low-risk users
('John',    'Doe',      'john.doe@email.com',      '3185551001', 'active',    'low',    'US', '192.168.1.10'),
('Sarah',   'Connor',   'sarah.connor@email.com',  '3185551004', 'active',    'low',    'US', '10.0.0.21'),
-- Medium-risk users
('Alice',   'Smith',    'alice.smith@email.com',   '3185551002', 'active',    'medium', 'US', '192.168.1.11'),
('David',   'Nguyen',   'david.nguyen@email.com',  '3185551005', 'suspended', 'medium', 'US', '10.0.0.22'),
-- High-risk users
('Michael', 'Brown',    'michael.brown@email.com', '3185551003', 'active',    'high',   'US', '192.168.1.12'),
('Olga',    'Petrov',   'olga.petrov@email.com',   '3185551006', 'active',    'high',   'RU', '185.220.101.5');
GO

-- ============================================================
-- SECTION 2: INSERT CARDS
-- ============================================================
INSERT INTO cards
    (user_id, card_type, card_number_hash, last_four_digits, expiry_date, card_status, daily_limit, monthly_limit)
VALUES
(1, 'credit',  'HASH_4111111111111111', '1111', '2027-12-31', 'active',  5000.00,  20000.00),
(2, 'debit',   'HASH_4000000000000002', '0002', '2028-06-30', 'active',  3000.00,  12000.00),
(3, 'debit',   'HASH_5500000000000004', '0004', '2026-08-31', 'active',  2000.00,  10000.00),
(4, 'prepaid', 'HASH_6011000000000004', '0003', '2026-03-31', 'blocked', 500.00,    1500.00),
(5, 'credit',  'HASH_340000000000009',  '0009', '2025-05-31', 'active',  8000.00,  30000.00),
(6, 'credit',  'HASH_370000000000002',  '0002', '2025-11-30', 'active',  10000.00, 40000.00);
GO

-- ============================================================
-- SECTION 3: INSERT MERCHANTS
-- ============================================================
INSERT INTO merchants
    (merchant_name, merchant_category_code, mcc_description, country_iso_code, risk_score, is_blacklisted, fraud_report_count)
VALUES
('Amazon',           '5942', 'Book Stores',        'US', 0.20, 0,  2),
('Walmart',          '5411', 'Grocery Stores',     'US', 0.10, 0,  1),
('CryptoExchangeX',  '6051', 'Digital Currency',   'US', 0.85, 0, 15),
('DarkWebShop',      '5999', 'Misc Retail',        'RU', 0.95, 1, 50),
('BetOnline Casino', '7995', 'Online Gambling',    'US', 0.90, 0, 30),
('WireTransferHub',  '4829', 'Wire Transfer',      'US', 0.75, 0, 10),
('Target',           '5311', 'Department Stores',  'US', 0.15, 0,  0),
('StarbucksCoffee',  '5812', 'Restaurants/Dining', 'US', 0.05, 0,  0);
GO

-- ============================================================
-- SECTION 4: INSERT USER DEVICES
-- ============================================================
INSERT INTO user_devices
    (device_id, user_id, device_type, device_name, os_type, last_seen, is_trusted)
VALUES
('DEV-IPHONE-001',  1, 'mobile',  'iPhone 15',       'iOS',     GETUTCDATE(), 1),
('DEV-IPAD-002',    2, 'tablet',  'iPad Pro',         'iOS',     GETUTCDATE(), 1),
('DEV-LAPTOP-003',  3, 'laptop',  'Dell XPS',         'Windows', GETUTCDATE(), 1),
('DEV-PHONE-004',   4, 'mobile',  'Samsung Galaxy',   'Android', GETUTCDATE(), 0),
('DEV-TABLET-005',  5, 'tablet',  'Samsung Tab',      'Android', GETUTCDATE(), 0),
('DEV-LAPTOP-006',  6, 'laptop',  'Lenovo ThinkPad',  'Linux',   GETUTCDATE(), 0);
GO

-- ============================================================
-- SECTION 5: INSERT USER KNOWN LOCATIONS
-- ============================================================
INSERT INTO user_known_locations
    (user_id, city, country_iso_code, latitude, longitude, last_transaction_at, frequency_count)
VALUES
(1, 'Shreveport', 'US',  32.52520000,  -93.75020000, GETUTCDATE(), 15),
(2, 'New York',   'US',  40.71280000,  -74.00600000, GETUTCDATE(), 20),
(3, 'Dallas',     'US',  32.77670000,  -96.79700000, GETUTCDATE(), 10),
(4, 'Chicago',    'US',  41.85030000,  -87.65010000, GETUTCDATE(),  5),
(5, 'Houston',    'US',  29.76040000,  -95.36980000, GETUTCDATE(),  8),
(6, 'Moscow',     'RU',  55.75580000,   37.61730000, GETUTCDATE(),  3);
GO

-- ============================================================
-- SECTION 6: INSERT AUTHENTICATION (Bank Employees)
-- ============================================================
-- NOTE: Passwords are bcrypt/SHA-256 hashes — NEVER store plain text
INSERT INTO authentication
    (employee_id, username, password_hash, role, is_active)
VALUES
('EMP-SA-001', 'admin.superuser',    'HASH_bcrypt_SuperAdmin@2026!',       'super_admin',        1),
('EMP-CO-001', 'officer.compliance', 'HASH_bcrypt_Compliance@2026!',       'compliance_officer', 1),
('EMP-BE-001', 'emp.johndoe',        'HASH_bcrypt_BankEmp001@2026!',       'bank_employee',      1),
('EMP-BE-002', 'emp.alicesmith',     'HASH_bcrypt_BankEmp002@2026!',       'bank_employee',      1),
('EMP-BE-003', 'emp.michaelbrown',   'HASH_bcrypt_BankEmp003@2026!',       'bank_employee',      0);
GO

-- ============================================================
-- SECTION 7: INSERT TRANSACTIONS
--   Normal, medium-risk, and fraud-triggering records
--   (Covers all 3 detection rules + velocity breach)
-- ============================================================

-- ---- Normal Transactions ----
INSERT INTO transactions
    (card_id, merchant_id, user_id, transaction_amount, currency_code,
     merchant_country, customer_country, merchant_mcc,
     transaction_status, is_online, device_id, ip_address, latitude, longitude)
VALUES
-- Normal: John buys from Amazon in his home city
(1, 1, 1, 120.50, 'USD', 'US', 'US', '5942',
 'completed', 1, 'DEV-IPHONE-001', '192.168.1.10',
 32.52520000, -93.75020000),

-- Normal: Sarah shops at Target in New York
(2, 7, 2, 75.00, 'USD', 'US', 'US', '5311',
 'completed', 0, 'DEV-IPAD-002', '10.0.0.21',
 40.71280000, -74.00600000),

-- Normal: Alice buys coffee at Starbucks in Dallas
(3, 8, 3, 15.00, 'USD', 'US', 'US', '5812',
 'completed', 0, 'DEV-LAPTOP-003', '192.168.1.11',
 32.77670000, -96.79700000),

-- Normal: Alice buys groceries at Walmart in Dallas
(3, 2, 3, 210.00, 'USD', 'US', 'US', '5411',
 'completed', 0, 'DEV-LAPTOP-003', '192.168.1.11',
 32.77670000, -96.79700000);
GO

-- ---- Rule 1: Impossible Travel ----
-- Michael transacts in Houston, then 2 minutes later appears in Moscow
INSERT INTO transactions
    (card_id, merchant_id, user_id, transaction_amount, currency_code,
     merchant_country, customer_country, merchant_mcc,
     transaction_status, is_online, device_id, ip_address, latitude, longitude, transaction_timestamp)
VALUES
(5, 2, 5, 350.00, 'USD', 'US', 'US', '5411',
 'completed', 0, 'DEV-TABLET-005', '192.168.1.20',
 29.76040000, -95.36980000,
 DATEADD(MINUTE, -5, GETUTCDATE())),       -- Houston  5 min ago

(5, 4, 5, 4800.00, 'USD', 'RU', 'RU', '5999',
 'completed', 1, 'UNKNOWN-DEVICE', '185.220.101.1',
 55.75580000, 37.61730000,
 DATEADD(MINUTE, -3, GETUTCDATE()));       -- Moscow   3 min ago (IMPOSSIBLE)
GO

-- ---- Rule 2: Structured Transactions / AML (Smurfing) ----
-- Olga makes 5 small transactions just below a $3,000 reporting threshold
INSERT INTO transactions
    (card_id, merchant_id, user_id, transaction_amount, currency_code,
     merchant_country, customer_country, merchant_mcc,
     transaction_status, is_online, device_id, ip_address, latitude, longitude, transaction_timestamp)
VALUES
(6, 6, 6, 2950.00, 'USD', 'US', 'US', '4829',
 'completed', 1, 'DEV-LAPTOP-006', '185.220.101.5',
 55.75580000, 37.61730000, DATEADD(MINUTE, -50, GETUTCDATE())),

(6, 6, 6, 2980.00, 'USD', 'US', 'US', '4829',
 'completed', 1, 'DEV-LAPTOP-006', '185.220.101.5',
 55.75580000, 37.61730000, DATEADD(MINUTE, -40, GETUTCDATE())),

(6, 6, 6, 2940.00, 'USD', 'US', 'US', '4829',
 'completed', 1, 'DEV-LAPTOP-006', '185.220.101.5',
 55.75580000, 37.61730000, DATEADD(MINUTE, -30, GETUTCDATE())),

(6, 6, 6, 2970.00, 'USD', 'US', 'US', '4829',
 'completed', 1, 'DEV-LAPTOP-006', '185.220.101.5',
 55.75580000, 37.61730000, DATEADD(MINUTE, -20, GETUTCDATE())),

(6, 6, 6, 2960.00, 'USD', 'US', 'US', '4829',
 'completed', 1, 'DEV-LAPTOP-006', '185.220.101.5',
 55.75580000, 37.61730000, DATEADD(MINUTE, -10, GETUTCDATE()));
GO

-- ---- Rule 3: Blacklisted Merchant / High-Risk Category ----
-- John transacts at the blacklisted DarkWebShop from an unknown device
INSERT INTO transactions
    (card_id, merchant_id, user_id, transaction_amount, currency_code,
     merchant_country, customer_country, merchant_mcc,
     transaction_status, is_online, device_id, ip_address, latitude, longitude)
VALUES
(1, 4, 1, 15000.00, 'USD', 'RU', 'US', '5999',
 'completed', 1, 'UNKNOWN-DEVICE', '185.220.101.1',
 55.75580000, 37.61730000),

-- Michael gambles at high-risk Casino merchant
(5, 5, 5, 9500.00, 'USD', 'US', 'US', '7995',
 'completed', 1, 'DEV-TABLET-005', '10.0.0.5',
 40.71280000, -74.00600000);
GO

-- ============================================================
-- SECTION 8: INSERT ALERTS (generated from above transactions)
-- ============================================================
INSERT INTO alerts
    (transaction_id, card_id, user_id, alert_type, risk_score, alert_message, alert_status)
VALUES
-- Rule 1: Impossible Travel alert for Michael
(5, 5, 5, 'impossible_travel', 9.80,
 'User 5 (Michael Brown) transacted in Houston (US) and Moscow (RU) within 2 minutes — physically impossible.',
 'open'),

-- Rule 2: AML Structuring alert for Olga
(NULL, 6, 6, 'structuring_aml', 9.50,
 'User 6 (Olga Petrov) made 5 wire-transfer transactions between $2,940–$2,980 within 50 minutes — possible smurfing.',
 'open'),

-- Rule 3a: Blacklisted merchant alert for John
(8, 1, 1, 'blacklisted_merchant', 9.95,
 'User 1 (John Doe) transacted $15,000 at blacklisted merchant DarkWebShop from UNKNOWN-DEVICE at IP 185.220.101.1.',
 'open'),

-- Rule 3b: High-risk MCC alert for Michael (Casino)
(9, 5, 5, 'high_risk_mcc', 8.50,
 'User 5 (Michael Brown) transacted $9,500 at BetOnline Casino (MCC 7995 — Online Gambling).',
 'acknowledged');
GO

-- ============================================================
-- SECTION 9: INSERT AUDIT LOG
-- ============================================================
INSERT INTO transaction_audit_log
    (transaction_id, previous_status, new_status, changed_by, change_reason)
VALUES
(5, 'completed', 'reversed', 'system.fraud_engine',
 'Reversed due to impossible travel alert — Rule 1 triggered.'),
(8, 'completed', 'reversed', 'emp.johndoe',
 'Manually reversed — blacklisted merchant DarkWebShop transaction confirmed fraud.');
GO

-- ============================================================
-- END OF SCRIPT 2: DATA INSERTION
-- ============================================================
