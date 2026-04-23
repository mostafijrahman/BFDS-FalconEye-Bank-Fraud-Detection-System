-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Script 3: Viewing Queries & Rule-Based Detection Tests
-- Version: 2.0  |  Date: April 2026
-- ============================================================

USE bank_fraud_detection_db;
GO

-- ============================================================
-- SECTION A: BASIC TABLE VIEWS
-- ============================================================

-- A1. All Users with Risk Profile
SELECT user_id, first_name, last_name, email, account_status, risk_profile, country_iso_code
FROM   users
ORDER  BY risk_profile DESC, user_id;
GO

-- A2. All Cards with Owner Name
SELECT c.card_id, u.first_name + ' ' + u.last_name AS card_holder,
       c.card_type, c.last_four_digits, c.card_status,
       c.daily_limit, c.monthly_limit, c.expiry_date
FROM   cards c
JOIN   users u ON u.user_id = c.user_id
ORDER  BY c.card_id;
GO

-- A3. All Merchants (Highlight Blacklisted)
SELECT merchant_id, merchant_name, merchant_category_code, mcc_description,
       country_iso_code, risk_score, is_blacklisted, fraud_report_count
FROM   merchants
ORDER  BY is_blacklisted DESC, risk_score DESC;
GO

-- A4. All Transactions with User + Merchant Info
SELECT t.transaction_id,
       u.first_name + ' ' + u.last_name  AS user_name,
       m.merchant_name,
       t.transaction_amount, t.currency_code,
       t.transaction_timestamp,
       t.ip_address,
       t.latitude, t.longitude,
       t.transaction_status,
       t.device_id
FROM   transactions t
JOIN   users     u ON u.user_id     = t.user_id
JOIN   merchants m ON m.merchant_id = t.merchant_id
ORDER  BY t.transaction_timestamp DESC;
GO

-- A5. All Open Alerts
SELECT a.alert_id,
       u.first_name + ' ' + u.last_name AS user_name,
       a.alert_type, a.risk_score, a.alert_status,
       a.alert_message, a.created_at
FROM   alerts a
JOIN   users u ON u.user_id = a.user_id
WHERE  a.alert_status = 'open'
ORDER  BY a.risk_score DESC;
GO

-- A6. Authentication / Bank Employee Roles
SELECT auth_id, employee_id, username, role, is_active, last_login_at, failed_attempts
FROM   authentication
ORDER  BY role, auth_id;
GO

-- A7. User Known Locations
SELECT ukl.location_id, u.first_name + ' ' + u.last_name AS user_name,
       ukl.city, ukl.country_iso_code, ukl.latitude, ukl.longitude,
       ukl.frequency_count, ukl.last_transaction_at
FROM   user_known_locations ukl
JOIN   users u ON u.user_id = ukl.user_id
ORDER  BY ukl.user_id;
GO

-- A8. User Devices
SELECT ud.device_id, u.first_name + ' ' + u.last_name AS user_name,
       ud.device_type, ud.device_name, ud.os_type, ud.is_trusted, ud.last_seen
FROM   user_devices ud
JOIN   users u ON u.user_id = ud.user_id
ORDER  BY ud.user_id;
GO

-- ============================================================
-- SECTION B: RULE 1 — GEOGRAPHIC IMPOSSIBILITY (Impossible Travel)
-- Detects two transactions from the same card in different
-- countries within a time window too short for physical travel.
-- Threshold: 500 km apart in less than 60 minutes
-- ============================================================

WITH ranked_txns AS (
    SELECT
        t.transaction_id,
        t.user_id,
        t.card_id,
        t.transaction_timestamp,
        t.latitude,
        t.longitude,
        t.merchant_country,
        t.ip_address,
        LAG(t.transaction_timestamp) OVER (PARTITION BY t.card_id ORDER BY t.transaction_timestamp) AS prev_timestamp,
        LAG(t.latitude)              OVER (PARTITION BY t.card_id ORDER BY t.transaction_timestamp) AS prev_lat,
        LAG(t.longitude)             OVER (PARTITION BY t.card_id ORDER BY t.transaction_timestamp) AS prev_lon,
        LAG(t.merchant_country)      OVER (PARTITION BY t.card_id ORDER BY t.transaction_timestamp) AS prev_country
    FROM transactions t
),
distance_calc AS (
    SELECT *,
        -- Haversine approximation (degrees to km): 1 degree ≈ 111 km
        SQRT(
            POWER((latitude  - prev_lat)  * 111.0, 2) +
            POWER((longitude - prev_lon)  * 111.0 * COS(RADIANS((latitude + prev_lat) / 2)), 2)
        ) AS distance_km,
        DATEDIFF(MINUTE, prev_timestamp, transaction_timestamp) AS minutes_apart
    FROM ranked_txns
    WHERE prev_timestamp IS NOT NULL
)
SELECT
    rt.transaction_id,
    u.first_name + ' ' + u.last_name  AS user_name,
    rt.card_id,
    rt.prev_country                   AS location_before,
    rt.merchant_country               AS location_after,
    ROUND(rt.distance_km, 2)          AS distance_km,
    rt.minutes_apart,
    rt.ip_address,
    '⚠ IMPOSSIBLE TRAVEL DETECTED'   AS flag
FROM   distance_calc rt
JOIN   users u ON u.user_id = rt.user_id
WHERE  rt.distance_km   > 500      -- more than 500 km apart
  AND  rt.minutes_apart < 60       -- within 60 minutes
ORDER  BY rt.distance_km DESC;
GO

-- ============================================================
-- SECTION C: RULE 2 — STRUCTURED TRANSACTIONS / AML (Smurfing)
-- Detects 3+ transactions by same user within 60 minutes,
-- each between $2,000 and $3,000 (just below reporting threshold)
-- ============================================================

WITH structured AS (
    SELECT
        t.user_id,
        t.card_id,
        t.transaction_id,
        t.transaction_amount,
        t.transaction_timestamp,
        t.merchant_mcc,
        COUNT(*) OVER (
            PARTITION BY t.user_id
            ORDER BY t.transaction_timestamp
            RANGE BETWEEN INTERVAL '60' MINUTE PRECEDING AND CURRENT ROW
        ) AS txn_count_in_window
    FROM transactions t
    WHERE t.transaction_amount BETWEEN 2000 AND 3000
      AND t.transaction_status = 'completed'
)
SELECT
    s.user_id,
    u.first_name + ' ' + u.last_name  AS user_name,
    s.card_id,
    s.transaction_id,
    s.transaction_amount,
    s.transaction_timestamp,
    s.txn_count_in_window,
    '⚠ STRUCTURING / AML PATTERN'    AS flag
FROM   structured s
JOIN   users u ON u.user_id = s.user_id
WHERE  s.txn_count_in_window >= 3
ORDER  BY s.user_id, s.transaction_timestamp;
GO

-- Simplified fallback (T-SQL compatible — no INTERVAL in RANGE):
-- Count transactions per user in past 60 minutes in $2K-$3K band
SELECT
    t.user_id,
    u.first_name + ' ' + u.last_name  AS user_name,
    COUNT(*)                           AS txn_count,
    SUM(t.transaction_amount)          AS total_amount,
    MIN(t.transaction_amount)          AS min_amount,
    MAX(t.transaction_amount)          AS max_amount,
    MIN(t.transaction_timestamp)       AS window_start,
    MAX(t.transaction_timestamp)       AS window_end,
    '⚠ STRUCTURING / AML PATTERN'     AS flag
FROM   transactions t
JOIN   users u ON u.user_id = t.user_id
WHERE  t.transaction_amount  BETWEEN 2000 AND 3000
  AND  t.transaction_status  = 'completed'
  AND  t.transaction_timestamp >= DATEADD(HOUR, -1, GETUTCDATE())
GROUP  BY t.user_id, u.first_name, u.last_name
HAVING COUNT(*) >= 3
ORDER  BY txn_count DESC;
GO

-- ============================================================
-- SECTION D: RULE 3 — BLACKLISTED MERCHANT / HIGH-RISK MCC
-- Flags any transaction at a blacklisted merchant OR
-- at a high-risk merchant category code
-- ============================================================

SELECT
    t.transaction_id,
    u.first_name + ' ' + u.last_name  AS user_name,
    m.merchant_name,
    m.merchant_category_code,
    m.mcc_description,
    t.transaction_amount,
    t.transaction_timestamp,
    t.ip_address,
    t.device_id,
    m.risk_score,
    m.fraud_report_count,
    CASE
        WHEN m.is_blacklisted = 1           THEN '🚫 BLACKLISTED MERCHANT'
        WHEN m.merchant_category_code IN (
             '6051',  -- Digital Currency / Crypto
             '7995',  -- Online Gambling
             '4829',  -- Wire Transfer
             '6010',  -- Manual Cash Disbursement
             '6011'   -- ATM
        )                                   THEN '⚠ HIGH-RISK MCC CATEGORY'
        ELSE 'MONITOR'
    END AS risk_flag
FROM   transactions t
JOIN   users     u ON u.user_id     = t.user_id
JOIN   merchants m ON m.merchant_id = t.merchant_id
WHERE  m.is_blacklisted = 1
   OR  m.merchant_category_code IN ('6051', '7995', '4829', '6010', '6011')
ORDER  BY m.is_blacklisted DESC, t.transaction_amount DESC;
GO

-- ============================================================
-- SECTION E: ROLE-BASED ACCESS VIEWS
-- Simulates what each role can see (manual enforcement)
-- ============================================================

-- E1. SUPER ADMIN — Full Transaction Dashboard
SELECT t.transaction_id, u.first_name + ' ' + u.last_name AS user_name,
       m.merchant_name, t.transaction_amount, t.transaction_status,
       t.ip_address, t.latitude, t.longitude,
       a.alert_type, a.risk_score, a.alert_status
FROM   transactions t
JOIN   users     u ON u.user_id     = t.user_id
JOIN   merchants m ON m.merchant_id = t.merchant_id
LEFT   JOIN alerts a ON a.transaction_id = t.transaction_id
ORDER  BY t.transaction_timestamp DESC;
GO

-- E2. COMPLIANCE OFFICER — Alert & Audit Log Summary
SELECT a.alert_id, a.alert_type, a.risk_score,
       a.alert_status, a.alert_message,
       a.created_at, a.resolved_at,
       tal.previous_status, tal.new_status, tal.changed_by, tal.change_reason
FROM   alerts a
LEFT   JOIN transaction_audit_log tal ON tal.transaction_id = a.transaction_id
ORDER  BY a.risk_score DESC;
GO

-- E3. BANK EMPLOYEE — User + Card + Active Alerts
SELECT u.user_id, u.first_name + ' ' + u.last_name AS user_name,
       u.email, u.phone, u.account_status, u.risk_profile,
       c.card_id, c.card_type, c.last_four_digits, c.card_status,
       a.alert_type, a.alert_status, a.risk_score
FROM   users u
JOIN   cards  c ON c.user_id  = u.user_id
LEFT   JOIN alerts a ON a.user_id = u.user_id AND a.alert_status = 'open'
ORDER  BY u.risk_profile DESC, u.user_id;
GO

-- ============================================================
-- SECTION F: SUMMARY DASHBOARD
-- ============================================================

-- F1. Fraud Alert Summary by Type
SELECT alert_type,
       COUNT(*)                         AS total_alerts,
       SUM(CASE WHEN alert_status = 'confirmed_fraud' THEN 1 ELSE 0 END) AS confirmed,
       SUM(CASE WHEN alert_status = 'open'            THEN 1 ELSE 0 END) AS open_count,
       ROUND(AVG(risk_score), 2)        AS avg_risk_score
FROM   alerts
GROUP  BY alert_type
ORDER  BY avg_risk_score DESC;
GO

-- F2. High-Risk Users with Alert Count
SELECT u.user_id,
       u.first_name + ' ' + u.last_name AS user_name,
       u.risk_profile,
       COUNT(a.alert_id)                 AS total_alerts,
       MAX(a.risk_score)                 AS max_risk_score
FROM   users  u
LEFT   JOIN alerts a ON a.user_id = u.user_id
GROUP  BY u.user_id, u.first_name, u.last_name, u.risk_profile
HAVING COUNT(a.alert_id) > 0
ORDER  BY max_risk_score DESC;
GO

-- F3. Transaction Volume by Merchant (Last 7 Days)
SELECT m.merchant_name,
       m.merchant_category_code,
       COUNT(t.transaction_id)           AS total_transactions,
       SUM(t.transaction_amount)         AS total_volume,
       m.is_blacklisted
FROM   transactions t
JOIN   merchants m ON m.merchant_id = t.merchant_id
WHERE  t.transaction_timestamp >= DATEADD(DAY, -7, GETUTCDATE())
GROUP  BY m.merchant_name, m.merchant_category_code, m.is_blacklisted
ORDER  BY total_volume DESC;
GO

-- ============================================================
-- SECTION G: SUMMARY DASHBOARD
-- ============================================================

-- G1. transactions
SELECT * FROM transactions;

SELECT * FROM  authentication;

SELECT * FROM  alerts;


-- ============================================================
-- END OF SCRIPT 3: VIEWING & TEST QUERIES
-- ============================================================
