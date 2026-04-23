-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Rule 3: Blacklisted Merchant / High-Risk Category
-- Database : bank_fraud_detection_db
-- Version  : 3.0  |  Date: April 2026
-- ============================================================
-- ARCHITECTURE:
--   fn_GetMerchantRiskFlag     — Scalar function: risk label
--   fn_IsHighRiskMCC           — Scalar function: BIT flag
--   usp_CheckMerchantRisk      — SP: merchant risk evaluation
--   trg_BlockRestrictedMerchant — INSTEAD OF INSERT/UPDATE:
--                                   1. Blocks blacklisted merchant txns
--                                   2. Raises BLACKLISTED_MERCHANT alert
--                                   3. Writes transaction_audit_log
--   trg_FlagHighRiskMCC        — AFTER INSERT trigger:
--                                   1. Flags high-risk MCC txns
--                                   2. Raises HIGH_RISK_MCC alert
--                                   3. Writes transaction_audit_log
--
-- RULE DEFINITIONS:
--   BLOCK : merchant is_blacklisted = 1  → transaction REJECTED entirely
--   FLAG  : merchant MCC in high-risk list → transaction ALLOWED but flagged
-- ============================================================

USE bank_fraud_detection_db;
GO

-- ============================================================
-- PART 1A: SCALAR FUNCTION — fn_IsHighRiskMCC
-- ============================================================
-- Returns 1 if the MCC code falls in a high-risk category,
-- 0 otherwise. Single place to maintain the MCC list.
-- ============================================================

CREATE OR ALTER FUNCTION dbo.fn_IsHighRiskMCC
(
    @MCC NVARCHAR(10)
)
RETURNS BIT
WITH SCHEMABINDING
AS
BEGIN
    RETURN
        CASE
            WHEN @MCC IN (
                '6051',  -- Non-Financial Institutions / Digital Currency / Crypto
                '7995',  -- Gambling Transactions
                '4829',  -- Wire Transfer / Money Orders
                '6010',  -- Manual Cash Disbursements
                '6011',  -- Automated Cash Disbursements (ATM)
                '5912',  -- Drug Stores / Pharmacies (high misuse)
                '7273',  -- Dating / Escort Services
                '5999'   -- Miscellaneous & Specialty Retail (catch-all risk)
            ) THEN CAST(1 AS BIT)
            ELSE         CAST(0 AS BIT)
        END;
END;
GO

PRINT 'fn_IsHighRiskMCC created successfully.';
GO

-- ============================================================
-- PART 1B: SCALAR FUNCTION — fn_GetMerchantRiskFlag
-- ============================================================
-- Returns a human-readable risk flag label for reporting.
-- ============================================================

CREATE OR ALTER FUNCTION dbo.fn_GetMerchantRiskFlag
(
    @IsBlacklisted  BIT,
    @MCC            NVARCHAR(10),
    @RiskScore      DECIMAL(3,2)
)
RETURNS NVARCHAR(50)
WITH SCHEMABINDING
AS
BEGIN
    RETURN
        CASE
            WHEN @IsBlacklisted = 1                          THEN N'BLOCKED: BLACKLISTED MERCHANT'
            WHEN dbo.fn_IsHighRiskMCC(@MCC) = 1             THEN N'FLAGGED: HIGH-RISK MCC'
            WHEN @RiskScore >= 0.75                          THEN N'WATCH: HIGH RISK SCORE'
            WHEN @RiskScore >= 0.50                          THEN N'MONITOR: MEDIUM RISK SCORE'
            ELSE                                                  N'CLEAR'
        END;
END;
GO

PRINT 'fn_GetMerchantRiskFlag created successfully.';
GO

-- ============================================================
-- PART 2: STORED PROCEDURE — usp_CheckMerchantRisk
-- ============================================================
-- Evaluates a merchant by ID and returns its full risk profile.
-- Can be called standalone by compliance officers to review
-- any merchant in the system.
-- ============================================================

CREATE OR ALTER PROCEDURE dbo.usp_CheckMerchantRisk
    @MerchantID INT = NULL          -- NULL = evaluate ALL merchants
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        m.merchant_id,
        m.merchant_name,
        m.merchant_category_code                AS mcc,
        m.mcc_description,
        m.country_iso_code,
        m.risk_score,
        m.is_blacklisted,
        m.fraud_report_count,
        dbo.fn_IsHighRiskMCC(m.merchant_category_code)  AS is_high_risk_mcc,
        dbo.fn_GetMerchantRiskFlag(
            m.is_blacklisted,
            m.merchant_category_code,
            m.risk_score
        )                                                AS risk_flag,

        -- Transaction summary
        COUNT(t.transaction_id)                 AS total_transactions,
        ISNULL(SUM(t.transaction_amount), 0)    AS total_volume,
        ISNULL(MAX(t.transaction_amount), 0)    AS largest_transaction,
        ISNULL(AVG(t.transaction_amount), 0)    AS avg_transaction,

        -- Alert summary
        COUNT(DISTINCT a.alert_id)              AS alerts_raised
    FROM   merchants m
    LEFT   JOIN transactions t ON t.merchant_id = m.merchant_id
    LEFT   JOIN alerts       a ON a.transaction_id = t.transaction_id
    WHERE  (@MerchantID IS NULL OR m.merchant_id = @MerchantID)
    GROUP  BY
        m.merchant_id, m.merchant_name, m.merchant_category_code,
        m.mcc_description, m.country_iso_code, m.risk_score,
        m.is_blacklisted, m.fraud_report_count
    ORDER  BY m.is_blacklisted DESC, m.risk_score DESC;

END;
GO

PRINT 'usp_CheckMerchantRisk created successfully.';
GO

-- ============================================================
-- PART 3: INSTEAD OF TRIGGER — trg_BlockRestrictedMerchant
-- ============================================================
-- Fires INSTEAD OF INSERT or UPDATE on transactions.
-- If ANY row targets a blacklisted merchant (is_blacklisted = 1):
--   STEP 1 → Block the entire operation — row NEVER written
--   STEP 2 → Raise RAISERROR to notify the application
--   STEP 3 → Insert a BLACKLISTED_MERCHANT alert per offending row
--   STEP 4 → Write a BLOCKED entry into transaction_audit_log
-- If merchant is NOT blacklisted:
--   → Re-execute the original INSERT or UPDATE normally
-- ============================================================

CREATE OR ALTER TRIGGER dbo.trg_BlockRestrictedMerchant
ON transactions
INSTEAD OF INSERT, UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    -- ── STEP 1: Check whether any row targets a blacklisted merchant ──
    IF EXISTS (
        SELECT 1
        FROM   inserted i
        INNER  JOIN merchants m ON m.merchant_id = i.merchant_id
        WHERE  m.is_blacklisted = 1
    )
    BEGIN

        -- ── STEP 2: Raise application-level error ─────────────
        RAISERROR(
            'TRANSACTION BLOCKED: One or more rows target a blacklisted merchant. '
            'This INSERT or UPDATE has been rejected and a BLACKLISTED_MERCHANT '
            'alert has been raised in the alerts table.',
            16, 1
        );

        -- ── STEP 3: Insert one alert per offending row ─────────
        INSERT INTO alerts
        (
            transaction_id, card_id, user_id,
            alert_type, risk_score, alert_message,
            alert_status, investigation_notes, created_at, resolved_at
        )
        SELECT
            NULL,                               -- txn blocked → no id
            i.card_id,
            i.user_id,
            'BLACKLISTED_MERCHANT',
            ISNULL(m.risk_score, 1.00),

            'BLOCKED ATTEMPT: user_id '
                + CAST(i.user_id AS NVARCHAR(20))
                + ' tried to transact with blacklisted merchant_id '
                + CAST(i.merchant_id AS NVARCHAR(20))
                + ' (' + m.merchant_name + ')'
                + ' for $' + CAST(i.transaction_amount AS NVARCHAR(30))
                + ' ' + i.currency_code
                + '. Operation REJECTED by trg_BlockRestrictedMerchant.',

            'open',

            -- Full investigation detail block
            'Trigger    : trg_BlockRestrictedMerchant (INSTEAD OF INSERT/UPDATE)'
            + CHAR(13)+CHAR(10)
            + 'Blocked at : ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 120)
            + CHAR(13)+CHAR(10)
            + '------------------------------------------------------------'
            + CHAR(13)+CHAR(10)
            + 'Attempted Transaction Details'
            + CHAR(13)+CHAR(10)
            + '   user_id           : ' + CAST(i.user_id            AS NVARCHAR(20))
            + CHAR(13)+CHAR(10)
            + '   card_id           : ' + CAST(i.card_id            AS NVARCHAR(20))
            + CHAR(13)+CHAR(10)
            + '   merchant_id       : ' + CAST(i.merchant_id        AS NVARCHAR(20))
            + ' (' + m.merchant_name + ' — BLACKLISTED)'
            + CHAR(13)+CHAR(10)
            + '   amount            : $' + CAST(i.transaction_amount AS NVARCHAR(30))
            + ' ' + i.currency_code
            + CHAR(13)+CHAR(10)
            + '   merchant_country  : ' + ISNULL(i.merchant_country, 'N/A')
            + CHAR(13)+CHAR(10)
            + '   customer_country  : ' + ISNULL(i.customer_country, 'N/A')
            + CHAR(13)+CHAR(10)
            + '   merchant_mcc      : ' + ISNULL(i.merchant_mcc,     'N/A')
            + CHAR(13)+CHAR(10)
            + '   is_online         : ' + CAST(ISNULL(i.is_online, 0) AS NVARCHAR(5))
            + CHAR(13)+CHAR(10)
            + '   device_id         : ' + ISNULL(i.device_id,        'N/A')
            + CHAR(13)+CHAR(10)
            + '   ip_address        : ' + ISNULL(i.ip_address,       'N/A')
            + CHAR(13)+CHAR(10)
            + '   coordinates       : ('
                + ISNULL(CAST(i.latitude  AS NVARCHAR(20)), 'N/A')
                + ', '
                + ISNULL(CAST(i.longitude AS NVARCHAR(20)), 'N/A')
                + ')'
            + CHAR(13)+CHAR(10)
            + '------------------------------------------------------------'
            + CHAR(13)+CHAR(10)
            + 'Merchant Risk Profile'
            + CHAR(13)+CHAR(10)
            + '   merchant_name      : ' + m.merchant_name
            + CHAR(13)+CHAR(10)
            + '   is_blacklisted     : YES'
            + CHAR(13)+CHAR(10)
            + '   fraud_report_count : ' + CAST(m.fraud_report_count AS NVARCHAR(10))
            + CHAR(13)+CHAR(10)
            + '   risk_score         : ' + CAST(m.risk_score AS NVARCHAR(10))
            + CHAR(13)+CHAR(10)
            + '   mcc                : ' + ISNULL(m.merchant_category_code, 'N/A')
            + ' (' + ISNULL(m.mcc_description, 'N/A') + ')',

            GETUTCDATE(), NULL

        FROM inserted i
        INNER JOIN merchants m ON m.merchant_id = i.merchant_id
        WHERE m.is_blacklisted = 1;

        -- ── STEP 4: Write BLOCKED audit log entry ─────────────
        -- card_id is available from inserted; transaction_id is NULL (blocked)
        -- We log using card_id via a temporary anchor approach
        INSERT INTO transaction_audit_log
        (
            transaction_id, previous_status, new_status,
            changed_by, changed_at, change_reason
        )
        SELECT
            NULL,                               -- blocked — no transaction_id exists
            NULL,
            'blocked',
            'SYSTEM: trg_BlockRestrictedMerchant',
            GETUTCDATE(),
            'Rule 3 — BLACKLISTED MERCHANT BLOCKED. '
            + 'user_id: '        + CAST(i.user_id        AS NVARCHAR(20))
            + ' | card_id: '     + CAST(i.card_id        AS NVARCHAR(20))
            + ' | merchant_id: ' + CAST(i.merchant_id    AS NVARCHAR(20))
            + ' (' + m.merchant_name + ')'
            + ' | Amount: $'     + CAST(i.transaction_amount AS NVARCHAR(30))
            + ' | IP: '          + ISNULL(i.ip_address, 'N/A')
            + ' | Risk Score: '  + CAST(m.risk_score AS NVARCHAR(10))
        FROM inserted i
        INNER JOIN merchants m ON m.merchant_id = i.merchant_id
        WHERE m.is_blacklisted = 1;

        -- Block completed — do NOT fall through to the safe path
        RETURN;

    END

    -- ============================================================
    -- SAFE PATH: No blacklisted merchant — allow operation normally
    -- INSTEAD OF triggers must manually re-execute the original DML
    -- ============================================================

    -- ── Handle INSERT ──────────────────────────────────────────
    IF EXISTS (SELECT 1 FROM inserted)
       AND NOT EXISTS (SELECT 1 FROM deleted)
    BEGIN
        INSERT INTO transactions
        (
            card_id, merchant_id, user_id,
            transaction_amount, currency_code, transaction_timestamp,
            merchant_country, customer_country, merchant_mcc,
            transaction_status, is_online, device_id,
            ip_address, latitude, longitude
        )
        SELECT
            card_id, merchant_id, user_id,
            transaction_amount, currency_code, transaction_timestamp,
            merchant_country, customer_country, merchant_mcc,
            transaction_status, is_online, device_id,
            ip_address, latitude, longitude
        FROM inserted;
    END

    -- ── Handle UPDATE ──────────────────────────────────────────
    ELSE IF EXISTS (SELECT 1 FROM inserted) AND EXISTS (SELECT 1 FROM deleted)
    BEGIN
        UPDATE t
        SET
            t.card_id               = i.card_id,
            t.merchant_id           = i.merchant_id,
            t.user_id               = i.user_id,
            t.transaction_amount    = i.transaction_amount,
            t.currency_code         = i.currency_code,
            t.transaction_timestamp = i.transaction_timestamp,
            t.merchant_country      = i.merchant_country,
            t.customer_country      = i.customer_country,
            t.merchant_mcc          = i.merchant_mcc,
            t.transaction_status    = i.transaction_status,
            t.is_online             = i.is_online,
            t.device_id             = i.device_id,
            t.ip_address            = i.ip_address,
            t.latitude              = i.latitude,
            t.longitude             = i.longitude
        FROM transactions t
        INNER JOIN inserted i ON t.transaction_id = i.transaction_id;
    END

END;
GO

PRINT 'trg_BlockRestrictedMerchant (INSTEAD OF INSERT/UPDATE) created successfully.';
GO

-- ============================================================
-- PART 4: AFTER INSERT TRIGGER — trg_FlagHighRiskMCC
-- ============================================================
-- Fires AFTER INSERT on transactions (blacklisted already blocked
-- by the INSTEAD OF trigger above, so this only sees safe rows).
-- For every newly inserted row:
--   If merchant MCC is in the high-risk list:
--     A) Insert or Update HIGH_RISK_MCC alert
--     B) Write FLAGGED audit log entry
--   Else:
--     B) Write clean audit log entry
-- ============================================================

CREATE OR ALTER TRIGGER dbo.trg_FlagHighRiskMCC
ON transactions
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    -- ── Per-row working variables ────────────────────────────
    DECLARE @TxnID          BIGINT;
    DECLARE @UserID         INT;
    DECLARE @CardID         INT;
    DECLARE @MerchantID     INT;
    DECLARE @Amount         DECIMAL(15,2);
    DECLARE @MCC            NVARCHAR(10);
    DECLARE @IPAddress      NVARCHAR(45);
    DECLARE @DeviceID       NVARCHAR(255);
    DECLARE @TxnStatus      NVARCHAR(20);

    -- ── Merchant lookup variables ───────────────────────────
    DECLARE @MerchantName   NVARCHAR(255);
    DECLARE @RiskScore      DECIMAL(3,2);
    DECLARE @MCCDesc        NVARCHAR(255);
    DECLARE @FraudCount     INT;
    DECLARE @IsHighRisk     BIT;
    DECLARE @RiskFlag       NVARCHAR(50);
    DECLARE @AlertMessage   NVARCHAR(MAX);
    DECLARE @InvNotes       NVARCHAR(MAX);

    -- ── Cursor: every newly inserted row ────────────────────
    DECLARE mcc_cursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT
            i.transaction_id, i.user_id, i.card_id, i.merchant_id,
            i.transaction_amount, i.merchant_mcc,
            i.ip_address, i.device_id, i.transaction_status
        FROM inserted i
        WHERE i.transaction_status <> 'reversed';   -- skip reversed evidence rows

    OPEN mcc_cursor;
    FETCH NEXT FROM mcc_cursor INTO
        @TxnID, @UserID, @CardID, @MerchantID,
        @Amount, @MCC, @IPAddress, @DeviceID, @TxnStatus;

    WHILE @@FETCH_STATUS = 0
    BEGIN

        -- ── Lookup merchant risk profile ─────────────────────
        SELECT
            @MerchantName   = merchant_name,
            @RiskScore      = risk_score,
            @MCCDesc        = mcc_description,
            @FraudCount     = fraud_report_count
        FROM merchants
        WHERE merchant_id = @MerchantID;

        SET @IsHighRisk = dbo.fn_IsHighRiskMCC(@MCC);
        SET @RiskFlag   = dbo.fn_GetMerchantRiskFlag(0, @MCC, @RiskScore);

        IF @IsHighRisk = 1
        BEGIN
            -- ── Build alert messages ─────────────────────────
            SET @AlertMessage =
                'HIGH-RISK MCC ALERT | user_id: '   + CAST(@UserID AS NVARCHAR(20))
                + ' | txn_id: '                     + CAST(@TxnID AS NVARCHAR(20))
                + ' | Merchant: '                   + ISNULL(@MerchantName, 'N/A')
                + ' | MCC: '                        + ISNULL(@MCC, 'N/A')
                + ' (' + ISNULL(@MCCDesc, 'N/A') + ')'
                + ' | Amount: $'                    + CAST(@Amount AS NVARCHAR(30))
                + ' | Risk Score: '                 + CAST(@RiskScore AS NVARCHAR(10))
                + ' | Fraud Reports: '              + CAST(@FraudCount AS NVARCHAR(10));

            SET @InvNotes =
                'Auto-raised by trg_FlagHighRiskMCC.'
                + CHAR(13)+CHAR(10)
                + 'Transaction Details:'
                + CHAR(13)+CHAR(10)
                + '   txn_id        : ' + CAST(@TxnID AS NVARCHAR(20))
                + CHAR(13)+CHAR(10)
                + '   user_id       : ' + CAST(@UserID AS NVARCHAR(20))
                + CHAR(13)+CHAR(10)
                + '   card_id       : ' + CAST(@CardID AS NVARCHAR(20))
                + CHAR(13)+CHAR(10)
                + '   merchant_id   : ' + CAST(@MerchantID AS NVARCHAR(20))
                + ' (' + ISNULL(@MerchantName, 'N/A') + ')'
                + CHAR(13)+CHAR(10)
                + '   mcc           : ' + ISNULL(@MCC, 'N/A')
                + ' (' + ISNULL(@MCCDesc, 'N/A') + ')'
                + CHAR(13)+CHAR(10)
                + '   amount        : $' + CAST(@Amount AS NVARCHAR(30))
                + CHAR(13)+CHAR(10)
                + '   ip_address    : ' + ISNULL(@IPAddress, 'N/A')
                + CHAR(13)+CHAR(10)
                + '   device_id     : ' + ISNULL(@DeviceID, 'N/A')
                + CHAR(13)+CHAR(10)
                + 'Merchant Risk Profile:'
                + CHAR(13)+CHAR(10)
                + '   risk_score         : ' + CAST(@RiskScore AS NVARCHAR(10))
                + CHAR(13)+CHAR(10)
                + '   fraud_report_count : ' + CAST(@FraudCount AS NVARCHAR(10))
                + CHAR(13)+CHAR(10)
                + '   risk_flag          : ' + @RiskFlag;

            -- ── Insert or Update HIGH_RISK_MCC alert ─────────
            IF EXISTS (
                SELECT 1 FROM alerts
                WHERE  user_id      = @UserID
                  AND  alert_type   = 'HIGH_RISK_MCC'
                  AND  alert_status = 'open'
            )
            BEGIN
                UPDATE alerts
                SET
                    risk_score          = @RiskScore,
                    investigation_notes =
                        investigation_notes
                        + CHAR(13)+CHAR(10)
                        + '--- UPDATED by trigger at '
                        + CONVERT(NVARCHAR(30), GETUTCDATE(), 120) + ' ---'
                        + CHAR(13)+CHAR(10)
                        + 'New txn_id: '  + CAST(@TxnID AS NVARCHAR(20))
                        + ' | MCC: '      + ISNULL(@MCC, 'N/A')
                        + ' | Amount: $'  + CAST(@Amount AS NVARCHAR(30))
                WHERE  user_id      = @UserID
                  AND  alert_type   = 'HIGH_RISK_MCC'
                  AND  alert_status = 'open';
            END
            ELSE
            BEGIN
                INSERT INTO alerts
                (
                    transaction_id, card_id, user_id,
                    alert_type, risk_score, alert_message,
                    alert_status, investigation_notes, created_at, resolved_at
                )
                VALUES
                (
                    @TxnID, @CardID, @UserID,
                    'HIGH_RISK_MCC', @RiskScore, @AlertMessage,
                    'open', @InvNotes, GETUTCDATE(), NULL
                );
            END

            -- ── Write FLAGGED audit entry ────────────────────
            INSERT INTO transaction_audit_log
            (
                transaction_id, previous_status, new_status,
                changed_by, changed_at, change_reason
            )
            VALUES
            (
                @TxnID,
                'completed',
                'completed',                    -- status unchanged; flagged, not blocked
                'SYSTEM: trg_FlagHighRiskMCC',
                GETUTCDATE(),
                'Rule 3 — HIGH-RISK MCC FLAGGED. '
                + 'Merchant: '  + ISNULL(@MerchantName, 'N/A')
                + ' | MCC: '    + ISNULL(@MCC, 'N/A')
                + ' (' + ISNULL(@MCCDesc, 'N/A') + ')'
                + ' | Amount: $' + CAST(@Amount AS NVARCHAR(30))
                + ' | Risk Score: ' + CAST(@RiskScore AS NVARCHAR(10))
                + ' | Fraud Reports: ' + CAST(@FraudCount AS NVARCHAR(10))
            );

        END
        ELSE
        BEGIN
            -- ── CLEAN PATH: Write no-risk audit entry ─────────
            INSERT INTO transaction_audit_log
            (
                transaction_id, previous_status, new_status,
                changed_by, changed_at, change_reason
            )
            VALUES
            (
                @TxnID,
                NULL,
                'completed',
                'SYSTEM: trg_FlagHighRiskMCC',
                GETUTCDATE(),
                'Rule 3 — Merchant MCC Check: CLEAR. '
                + 'Merchant: '    + ISNULL(@MerchantName, 'N/A')
                + ' | MCC: '     + ISNULL(@MCC, 'N/A')
                + ' | Risk Flag: ' + @RiskFlag
            );
        END

        FETCH NEXT FROM mcc_cursor INTO
            @TxnID, @UserID, @CardID, @MerchantID,
            @Amount, @MCC, @IPAddress, @DeviceID, @TxnStatus;
    END

    CLOSE     mcc_cursor;
    DEALLOCATE mcc_cursor;

END;
GO

PRINT 'trg_FlagHighRiskMCC (AFTER INSERT) created successfully.';
GO

-- ============================================================
-- VERIFICATION TESTS
-- ============================================================

-- ✅ TEST 1: Allowed merchant INSERT — Amazon (merchant_id = 1, MCC 5942)
--    Expected: 1 row in transactions | 0 alerts | audit: CLEAR
-- ------------------------------------------------------------
PRINT '==== TEST 1: Normal transaction — Amazon ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(1, 1, 1, 120.50, 'USD', 'US', 'US', '5942', 'completed',
 1, 'DEV-IPHONE-001', '192.168.1.10', 32.52520000, -93.75020000);

PRINT 'TEST 1 DONE — Expected: row inserted | 0 alerts | audit: CLEAR.';
GO

-- ❌ TEST 2: Blacklisted merchant INSERT — DarkWebShop (is_blacklisted = 1)
--    Expected: 0 rows in transactions | BLACKLISTED_MERCHANT alert | audit: blocked
-- ------------------------------------------------------------
PRINT '==== TEST 2: Blacklisted INSERT — DarkWebShop ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(1, 4, 1, 15000.00, 'USD', 'RU', 'US', '5999', 'completed',
 1, 'UNKNOWN-DEVICE', '185.220.101.1', 55.75580000, 37.61730000);

PRINT 'TEST 2: SHOULD NOT REACH HERE — trigger blocks and returns.';
GO

-- ❌ TEST 3: Blacklisted merchant UPDATE
--    Expected: transaction NOT updated | BLACKLISTED_MERCHANT alert | audit: blocked
-- ------------------------------------------------------------
PRINT '==== TEST 3: Blacklisted UPDATE — reassign existing txn to DarkWebShop ====';

UPDATE transactions
SET    merchant_id = 4
WHERE  transaction_id = 1;

PRINT 'TEST 3: SHOULD NOT REACH HERE — trigger blocks the UPDATE.';
GO

-- ❌ TEST 4: High-risk MCC INSERT — CryptoExchangeX (MCC 6051)
--    Expected: row inserted (not blocked) | HIGH_RISK_MCC alert | audit: FLAGGED
-- ------------------------------------------------------------
PRINT '==== TEST 4: High-Risk MCC — CryptoExchangeX ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(5, 3, 5, 9500.00, 'USD', 'US', 'US', '6051', 'completed',
 1, 'DEV-TABLET-005', '10.0.0.5', 40.71280000, -74.00600000);

PRINT 'TEST 4 DONE — Expected: row inserted | HIGH_RISK_MCC alert | audit: FLAGGED.';
GO

-- ❌ TEST 5: High-risk MCC INSERT — Online Gambling (MCC 7995)
--    Expected: row inserted | HIGH_RISK_MCC alert (or update if open) | audit: FLAGGED
-- ------------------------------------------------------------
PRINT '==== TEST 5: High-Risk MCC — Online Gambling Casino ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(5, 5, 5, 4500.00, 'USD', 'US', 'US', '7995', 'completed',
 1, 'DEV-TABLET-005', '10.0.0.5', 40.71280000, -74.00600000);

PRINT 'TEST 5 DONE — Expected: row inserted | existing HIGH_RISK_MCC alert UPDATED | audit: FLAGGED.';
GO

-- ✅ TEST 6: Multi-row INSERT — one clean, one blacklisted → ENTIRE batch blocked
--    Expected: 0 rows in transactions | 1 alert | audit: blocked
-- ------------------------------------------------------------
PRINT '==== TEST 6: Multi-row INSERT — 1 clean + 1 blacklisted ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(1, 1, 1, 80.00, 'USD', 'US', 'US', '5942', 'completed',
 1, 'DEV-IPHONE-001', '192.168.1.10', 32.52520000, -93.75020000),

(3, 4, 3, 9999.00, 'USD', 'RU', 'US', '5999', 'completed',
 1, 'UNKNOWN-DEVICE', '185.220.101.1', 55.75580000, 37.61730000);

PRINT 'TEST 6: SHOULD NOT REACH HERE — entire batch blocked by blacklisted row.';
GO

-- ============================================================
-- VIEW RESULTS
-- ============================================================

-- All transactions — confirm no blacklisted merchant rows
SELECT
    t.transaction_id,
    u.first_name + ' ' + u.last_name AS user_name,
    m.merchant_name,
    m.is_blacklisted,
    dbo.fn_GetMerchantRiskFlag(m.is_blacklisted, t.merchant_mcc, m.risk_score) AS risk_flag,
    t.transaction_amount,
    t.transaction_status,
    t.transaction_timestamp
FROM   transactions t
JOIN   users     u ON u.user_id     = t.user_id
JOIN   merchants m ON m.merchant_id = t.merchant_id
ORDER  BY t.transaction_timestamp DESC;
GO

-- Blacklisted merchant alerts
SELECT
    alert_id, card_id, user_id,
    alert_type, risk_score, alert_status,
    alert_message, investigation_notes, created_at
FROM   alerts
WHERE  alert_type = 'BLACKLISTED_MERCHANT'
ORDER  BY created_at DESC;
GO

-- High-risk MCC alerts
SELECT
    alert_id, transaction_id, card_id, user_id,
    alert_type, risk_score, alert_status,
    alert_message, investigation_notes, created_at
FROM   alerts
WHERE  alert_type = 'HIGH_RISK_MCC'
ORDER  BY created_at DESC;
GO

-- Audit log entries from Rule 3 triggers
SELECT
    audit_id, transaction_id,
    previous_status, new_status,
    changed_by, changed_at, change_reason
FROM   transaction_audit_log
WHERE  changed_by IN (
    'SYSTEM: trg_BlockRestrictedMerchant',
    'SYSTEM: trg_FlagHighRiskMCC'
)
ORDER  BY changed_at DESC;
GO

-- Merchant risk report (all merchants)
EXEC dbo.usp_CheckMerchantRisk;
GO

-- ============================================================
-- END OF RULE 3: Blacklisted Merchant / High-Risk Category
-- ============================================================
