-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Rule 2: Structured Transaction Patterns (AML / Smurfing)
-- Database : bank_fraud_detection_db
-- Version  : 3.0  |  Date: April 2026
-- ============================================================
-- ARCHITECTURE:
--   fn_GetStructuringSeverity — Scalar function: severity label
--   fn_GetStructuringRiskScore — Scalar function: risk score 0–1
--   usp_DetectStructuring      — SP: full AML analysis, result set
--                                + optional alert auto-raise
--   trg_AMLStructuringAlert    — AFTER INSERT trigger:
--                                  1. Inline structuring detection
--                                  2. Raises AML_STRUCTURING alert
--                                  3. Writes transaction_audit_log
--
-- DETECTION PARAMETERS:
--   Threshold : $10,000  (BSA / CTR regulatory reporting limit)
--   Window    : 48 hours (rolling)
--   Min Count : 2 transactions
-- ============================================================

USE bank_fraud_detection_db;
GO

-- ============================================================
-- PART 1A: SCALAR FUNCTION — fn_GetStructuringRiskScore
-- ============================================================
-- Returns risk score 0.00 – 1.00 based on aggregate-to-threshold
-- ratio and transaction count. Consistent across SP and trigger.
-- ============================================================

CREATE OR ALTER FUNCTION dbo.fn_GetStructuringRiskScore
(
    @AggregateTotal     DECIMAL(15,2),
    @ThresholdAmount    DECIMAL(15,2),
    @TxnCount           INT
)
RETURNS DECIMAL(4,2)
WITH SCHEMABINDING
AS
BEGIN
    RETURN
        CASE
            WHEN (@AggregateTotal / @ThresholdAmount) >= 2.0
                THEN 1.00
            ELSE
                CAST(
                    ROUND(
                        0.70
                        + (CAST(@TxnCount AS DECIMAL(5,2)) / 100.0)
                        + ((@AggregateTotal - @ThresholdAmount)
                           / (@ThresholdAmount * 10.0))
                    , 2)
                AS DECIMAL(4,2))
        END;
END;
GO

PRINT 'fn_GetStructuringRiskScore created successfully.';
GO

-- ============================================================
-- PART 1B: SCALAR FUNCTION — fn_GetStructuringSeverity
-- ============================================================

CREATE OR ALTER FUNCTION dbo.fn_GetStructuringSeverity
(
    @AggregateTotal     DECIMAL(15,2),
    @ThresholdAmount    DECIMAL(15,2)
)
RETURNS NVARCHAR(20)
WITH SCHEMABINDING
AS
BEGIN
    RETURN
        CASE
            WHEN @AggregateTotal >= (@ThresholdAmount * 2.0) THEN N'CRITICAL'
            WHEN @AggregateTotal >= (@ThresholdAmount * 1.5) THEN N'HIGH'
            WHEN @AggregateTotal >= (@ThresholdAmount * 1.1) THEN N'MEDIUM'
            ELSE                                                   N'LOW'
        END;
END;
GO

PRINT 'fn_GetStructuringSeverity created successfully.';
GO

-- ============================================================
-- PART 2: STORED PROCEDURE — usp_DetectStructuring
-- ============================================================
-- PURPOSE:
--   Detects Structuring (Smurfing) — multiple transactions
--   individually below the $10,000 CTR threshold whose
--   rolling aggregate breaches it within a time window.
--
-- PARAMETERS:
--   @ThresholdAmount     - regulatory limit  (default $10,000)
--   @MinTransactionCount - minimum txn count (default 2)
--   @WindowHours         - rolling window hrs (default 48)
--   @UserID              - specific user or NULL = all users
--   @RaiseAlert          - 1 = auto-insert into alerts table
-- ============================================================

CREATE OR ALTER PROCEDURE dbo.usp_DetectStructuring
    @ThresholdAmount        DECIMAL(15,2)   = 10000.00,
    @MinTransactionCount    INT             = 2,
    @WindowHours            INT             = 48,
    @UserID                 INT             = NULL,
    @RaiseAlert             BIT             = 1
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @WindowStart    DATETIME2 = DATEADD(HOUR, -@WindowHours, GETUTCDATE());
    DECLARE @WindowEnd      DATETIME2 = GETUTCDATE();
    DECLARE @AlertsRaised   INT       = 0;

    -- ── STEP 1: Identify suspects ─────────────────────────────
    ;WITH SuspectTransactions AS
    (
        SELECT
            t.user_id,
            t.transaction_id,
            t.card_id,
            t.transaction_amount,
            t.transaction_timestamp,
            t.merchant_id,
            t.ip_address,
            t.device_id
        FROM transactions t
        WHERE
            t.transaction_timestamp BETWEEN @WindowStart AND @WindowEnd
            AND t.transaction_status = 'completed'
            AND t.transaction_amount < @ThresholdAmount
            AND (@UserID IS NULL OR t.user_id = @UserID)
    ),
    AggregatedByUser AS
    (
        SELECT
            st.user_id,
            COUNT(st.transaction_id)        AS transaction_count,
            SUM(st.transaction_amount)      AS total_amount,
            MIN(st.transaction_amount)      AS min_single_txn,
            MAX(st.transaction_amount)      AS max_single_txn,
            AVG(st.transaction_amount)      AS avg_single_txn,
            MIN(st.transaction_timestamp)   AS window_start_txn,
            MAX(st.transaction_timestamp)   AS window_end_txn,
            MAX(st.card_id)                 AS latest_card_id
        FROM SuspectTransactions st
        GROUP BY st.user_id
        HAVING
            COUNT(st.transaction_id)     >= @MinTransactionCount
            AND SUM(st.transaction_amount) >= @ThresholdAmount
    )

    -- ── STEP 2: Result set with full user context ─────────────
    SELECT
        a.user_id,
        u.first_name + ' ' + u.last_name           AS full_name,
        u.email,
        u.risk_profile                              AS current_risk_profile,
        u.country_iso_code,

        -- Pattern summary
        a.transaction_count                         AS txn_count_in_window,
        a.total_amount                              AS aggregate_total,
        @ThresholdAmount                            AS reporting_threshold,
        a.total_amount - @ThresholdAmount           AS amount_over_threshold,
        a.min_single_txn,
        a.max_single_txn,
        a.avg_single_txn,

        -- Window details
        @WindowHours                                AS window_hours,
        a.window_start_txn                          AS first_txn_in_window,
        a.window_end_txn                            AS last_txn_in_window,
        DATEDIFF(MINUTE, a.window_start_txn,
                         a.window_end_txn)          AS span_minutes,

        -- Risk score and severity via shared functions
        dbo.fn_GetStructuringRiskScore(
            a.total_amount, @ThresholdAmount, a.transaction_count
        )                                           AS calculated_risk_score,

        dbo.fn_GetStructuringSeverity(
            a.total_amount, @ThresholdAmount
        )                                           AS severity_level,

        'AML Structuring / Smurfing Detected'       AS alert_type,
        'Multiple transactions below $'
            + CAST(CAST(@ThresholdAmount AS INT) AS NVARCHAR)
            + ' threshold totaling $'
            + CAST(CAST(a.total_amount AS INT) AS NVARCHAR)
            + ' across '
            + CAST(a.transaction_count AS NVARCHAR)
            + ' transactions in '
            + CAST(@WindowHours AS NVARCHAR)
            + ' hours.'                             AS alert_message,

        a.latest_card_id
    INTO #StructuringSuspects
    FROM AggregatedByUser a
    INNER JOIN users u ON a.user_id = u.user_id;

    -- Show results
    SELECT * FROM #StructuringSuspects
    ORDER BY aggregate_total DESC;

    -- ── STEP 3: Optionally raise alerts ───────────────────────
    IF @RaiseAlert = 1 AND EXISTS (SELECT 1 FROM #StructuringSuspects)
    BEGIN
        INSERT INTO alerts
        (
            transaction_id, card_id, user_id,
            alert_type, risk_score, alert_message,
            alert_status, investigation_notes
        )
        SELECT
            NULL,
            s.latest_card_id,
            s.user_id,
            'AML_STRUCTURING',
            s.calculated_risk_score,
            s.alert_message,
            'open',
            'Auto-generated by usp_DetectStructuring. '
            + 'Severity: '      + s.severity_level
            + ' | Window: Last ' + CAST(@WindowHours AS NVARCHAR) + ' hours'
            + ' | Txn Count: '   + CAST(s.txn_count_in_window AS NVARCHAR)
            + ' | Aggregate: $'  + CAST(CAST(s.aggregate_total AS INT) AS NVARCHAR)
        FROM #StructuringSuspects s
        WHERE NOT EXISTS (
            SELECT 1 FROM alerts al
            WHERE  al.user_id     = s.user_id
              AND  al.alert_type  = 'AML_STRUCTURING'
              AND  al.alert_status = 'open'
        );

        SET @AlertsRaised = @@ROWCOUNT;
    END

    -- ── STEP 4: Summary output ────────────────────────────────
    SELECT
        COUNT(*)         AS total_suspects_detected,
        @AlertsRaised    AS new_alerts_raised,
        @WindowStart     AS analysis_window_start,
        @WindowEnd       AS analysis_window_end,
        @ThresholdAmount AS threshold_used,
        @WindowHours     AS window_hours_used
    FROM #StructuringSuspects;

    DROP TABLE IF EXISTS #StructuringSuspects;

END;
GO

PRINT 'usp_DetectStructuring created successfully.';
GO

-- ============================================================
-- PART 3: AFTER INSERT TRIGGER — trg_AMLStructuringAlert
-- ============================================================
-- Fires on every INSERT into transactions.
-- Consolidates the logic of both the old trg_AutoDetectStructuring
-- and trg_InsertStructuringAlert into a single unified trigger.
--
-- For each inserted row:
--   1. Aggregates the user's rolling 48-hr window of sub-threshold txns
--   2. Checks the 3-rule AML structuring test
--   3. On violation: INSERT or UPDATE AML_STRUCTURING alert
--   4. Writes one entry to transaction_audit_log (violation or clean)
-- ============================================================

CREATE OR ALTER TRIGGER dbo.trg_AMLStructuringAlert
ON transactions
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    -- ── Fixed AML parameters ─────────────────────────────────
    DECLARE @ThresholdAmount        DECIMAL(15,2)   = 10000.00;
    DECLARE @WindowHours            INT             = 48;
    DECLARE @MinTransactionCount    INT             = 2;

    -- ── Per-row working variables ────────────────────────────
    DECLARE @InsertedUserID         INT;
    DECLARE @InsertedTransactionID  BIGINT;
    DECLARE @InsertedAmount         DECIMAL(15,2);
    DECLARE @LatestCardID           INT;

    -- ── Aggregated detection variables ───────────────────────
    DECLARE @TxnCount               INT;
    DECLARE @AggregateTotal         DECIMAL(15,2);
    DECLARE @RiskScore              DECIMAL(4,2);
    DECLARE @SeverityLevel          NVARCHAR(20);
    DECLARE @AlertMessage           NVARCHAR(MAX);
    DECLARE @InvestigationNotes     NVARCHAR(MAX);
    DECLARE @ViolationDetected      BIT;
    DECLARE @AlertAlreadyOpen       BIT;

    DECLARE @WindowStart            DATETIME2 = DATEADD(HOUR, -@WindowHours, GETUTCDATE());

    -- ── Cursor: one pass per inserted row ────────────────────
    DECLARE inserted_cursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT user_id, transaction_id, transaction_amount
        FROM   inserted;

    OPEN inserted_cursor;
    FETCH NEXT FROM inserted_cursor
    INTO @InsertedUserID, @InsertedTransactionID, @InsertedAmount;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- Reset per-row flags
        SET @ViolationDetected  = 0;
        SET @AlertAlreadyOpen   = 0;
        SET @TxnCount           = 0;
        SET @AggregateTotal     = 0;

        -- ── STEP 1: Aggregate rolling window for this user ───
        SELECT
            @TxnCount       = COUNT(transaction_id),
            @AggregateTotal = ISNULL(SUM(transaction_amount), 0),
            @LatestCardID   = MAX(card_id)
        FROM transactions
        WHERE
            user_id               = @InsertedUserID
            AND transaction_status = 'completed'
            AND transaction_amount < @ThresholdAmount
            AND transaction_timestamp BETWEEN @WindowStart AND GETUTCDATE();

        -- ── STEP 2: Apply 3-rule AML check ──────────────────
        --   Rule 1: each txn < threshold   (WHERE clause above)
        --   Rule 2: count >= minimum
        --   Rule 3: sum   >= threshold
        IF  @TxnCount       >= @MinTransactionCount
        AND @AggregateTotal >= @ThresholdAmount
        BEGIN
            SET @ViolationDetected = 1;

            -- ── STEP 3: Risk score and severity via functions ─
            SET @RiskScore     = dbo.fn_GetStructuringRiskScore(
                                     @AggregateTotal, @ThresholdAmount, @TxnCount);
            SET @SeverityLevel = dbo.fn_GetStructuringSeverity(
                                     @AggregateTotal, @ThresholdAmount);

            -- ── STEP 4: Build messages ────────────────────────
            SET @AlertMessage =
                'AML STRUCTURING ALERT | user_id: '     + CAST(@InsertedUserID AS NVARCHAR(20))
                + ' | Transactions: '                   + CAST(@TxnCount AS NVARCHAR(10))
                + ' | Aggregate Total: $'               + CAST(CAST(@AggregateTotal AS DECIMAL(15,2)) AS NVARCHAR(30))
                + ' | Threshold: $'                     + CAST(CAST(@ThresholdAmount AS INT) AS NVARCHAR(10))
                + ' | Window: '                         + CAST(@WindowHours AS NVARCHAR(5)) + ' hrs'
                + ' | Severity: '                       + @SeverityLevel;

            SET @InvestigationNotes =
                'Auto-raised by trg_AMLStructuringAlert. '
                + 'Threshold=$'             + CAST(CAST(@ThresholdAmount AS INT) AS NVARCHAR(10))
                + ' | WindowHours='         + CAST(@WindowHours AS NVARCHAR(5))
                + ' | MinTxnCount='         + CAST(@MinTransactionCount AS NVARCHAR(5))
                + ' | Triggering txn_id: '  + CAST(@InsertedTransactionID AS NVARCHAR(20))
                + ' ($'                     + CAST(@InsertedAmount AS NVARCHAR(20)) + ')'
                + ' | Risk Score: '         + CAST(@RiskScore AS NVARCHAR(10))
                + ' | Severity: '           + @SeverityLevel
                + ' | Total txns: '         + CAST(@TxnCount AS NVARCHAR(10))
                + ' | Aggregate: $'         + CAST(CAST(@AggregateTotal AS DECIMAL(15,2)) AS NVARCHAR(30));

            -- ── STEP 5: Insert or Update alert ───────────────
            IF EXISTS (
                SELECT 1 FROM alerts
                WHERE  user_id     = @InsertedUserID
                  AND  alert_type  = 'AML_STRUCTURING'
                  AND  alert_status = 'open'
            )
            BEGIN
                SET @AlertAlreadyOpen = 1;
                -- UPDATE: append to existing open alert
                UPDATE alerts
                SET
                    risk_score          = @RiskScore,
                    investigation_notes =
                        investigation_notes
                        + CHAR(13)+CHAR(10)
                        + '--- UPDATED by trigger at '
                        + CONVERT(NVARCHAR(30), GETUTCDATE(), 120)
                        + ' ---'
                        + CHAR(13)+CHAR(10)
                        + 'New triggering txn_id: '    + CAST(@InsertedTransactionID AS NVARCHAR(20))
                        + ' | Amount: $'               + CAST(@InsertedAmount AS NVARCHAR(20))
                        + ' | New Aggregate: $'        + CAST(CAST(@AggregateTotal AS DECIMAL(15,2)) AS NVARCHAR(30))
                        + ' | Txn Count: '             + CAST(@TxnCount AS NVARCHAR(10))
                        + ' | Updated Risk Score: '    + CAST(@RiskScore AS NVARCHAR(10))
                        + ' | Severity: '              + @SeverityLevel
                WHERE  user_id     = @InsertedUserID
                  AND  alert_type  = 'AML_STRUCTURING'
                  AND  alert_status = 'open';
            END
            ELSE
            BEGIN
                -- INSERT: new alert row
                INSERT INTO alerts
                (
                    transaction_id, card_id, user_id,
                    alert_type, risk_score, alert_message,
                    alert_status, investigation_notes, created_at, resolved_at
                )
                VALUES
                (
                    @InsertedTransactionID, @LatestCardID, @InsertedUserID,
                    'AML_STRUCTURING', @RiskScore, @AlertMessage,
                    'open', @InvestigationNotes, GETUTCDATE(), NULL
                );
            END

            -- ── STEP 6: Write VIOLATION audit log ─────────────
            INSERT INTO transaction_audit_log
            (
                transaction_id, previous_status, new_status,
                changed_by, changed_at, change_reason
            )
            VALUES
            (
                @InsertedTransactionID,
                'completed',
                'completed',                        -- txn status unchanged; flagged, not reversed
                'SYSTEM: trg_AMLStructuringAlert',
                GETUTCDATE(),
                'Rule 2 — AML Structuring '
                + CASE WHEN @AlertAlreadyOpen = 1 THEN '(EXISTING ALERT UPDATED). ' ELSE '(NEW ALERT RAISED). ' END
                + 'Txn Count: '     + CAST(@TxnCount AS NVARCHAR(10))
                + ' | Aggregate: $' + CAST(CAST(@AggregateTotal AS DECIMAL(15,2)) AS NVARCHAR(30))
                + ' | Risk Score: ' + CAST(@RiskScore AS NVARCHAR(10))
                + ' | Severity: '   + @SeverityLevel
            );

        END
        ELSE
        BEGIN
            -- ── CLEAN PATH: Write no-violation audit entry ────
            INSERT INTO transaction_audit_log
            (
                transaction_id, previous_status, new_status,
                changed_by, changed_at, change_reason
            )
            VALUES
            (
                @InsertedTransactionID,
                NULL,
                'completed',
                'SYSTEM: trg_AMLStructuringAlert',
                GETUTCDATE(),
                'Rule 2 — AML Structuring: No violation detected. '
                + 'Aggregate so far: $' + CAST(ISNULL(@AggregateTotal, 0) AS NVARCHAR(30))
                + ' across '            + CAST(ISNULL(@TxnCount, 0) AS NVARCHAR(10)) + ' txn(s) in window.'
            );
        END

        FETCH NEXT FROM inserted_cursor
        INTO @InsertedUserID, @InsertedTransactionID, @InsertedAmount;
    END

    CLOSE     inserted_cursor;
    DEALLOCATE inserted_cursor;

END;
GO

PRINT 'trg_AMLStructuringAlert (AFTER INSERT) created successfully.';
GO

-- ============================================================
-- VERIFICATION TESTS
-- ============================================================

-- ✅ TEST 1: Safe — single small transaction (no pattern yet)
--    Expected: 0 AML alerts | audit log: no violation
-- ------------------------------------------------------------
PRINT '==== TEST 1: Single safe transaction — no pattern ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(3, 2, 3, 800.00, 'USD', 'US', 'US', '5411', 'completed',
 0, 'DEV-TABLET-005', '192.168.1.20', 32.77670000, -96.79700000);

PRINT 'TEST 1 DONE — Expected: 0 alerts | audit: no violation.';
GO

-- ❌ TEST 2: Smurfing — 4 transactions just below $10,000 for user 6
--    Total ≈ $37,000 — Expected: NEW AML_STRUCTURING alert
-- ------------------------------------------------------------
PRINT '==== TEST 2: 4-txn smurfing pattern — user 6 ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(6, 6, 6, 9800.00, 'USD', 'US', 'US', '4829', 'completed',
 1, 'DEV-LAPTOP-006', '185.220.101.5', 55.75580000, 37.61730000),

(6, 6, 6, 9500.00, 'USD', 'US', 'US', '4829', 'completed',
 1, 'DEV-LAPTOP-006', '185.220.101.5', 55.75580000, 37.61730000),

(6, 6, 6, 9100.00, 'USD', 'US', 'US', '4829', 'completed',
 1, 'DEV-LAPTOP-006', '185.220.101.5', 55.75580000, 37.61730000),

(6, 6, 6, 8700.00, 'USD', 'US', 'US', '4829', 'completed',
 1, 'DEV-LAPTOP-006', '185.220.101.5', 55.75580000, 37.61730000);

PRINT 'TEST 2 DONE — Expected: NEW AML_STRUCTURING alert for user 6.';
GO

-- ❌ TEST 3: Follow-up txn for user 6 (alert already open)
--    Expected: EXISTING alert UPDATED — no duplicate
-- ------------------------------------------------------------
PRINT '==== TEST 3: Follow-up txn for user 6 — update existing alert ====';

INSERT INTO transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(6, 6, 6, 7500.00, 'USD', 'US', 'US', '4829', 'completed',
 1, 'DEV-LAPTOP-006', '185.220.101.5', 55.75580000, 37.61730000);

PRINT 'TEST 3 DONE — Expected: existing alert UPDATED, no duplicate.';
GO

-- ============================================================
-- VIEW RESULTS
-- ============================================================

-- All AML structuring alerts
SELECT
    alert_id, transaction_id, card_id, user_id,
    alert_type, risk_score, alert_status,
    alert_message, investigation_notes, created_at
FROM   alerts
WHERE  alert_type = 'AML_STRUCTURING'
ORDER  BY created_at DESC;
GO

-- Audit log entries from Rule 2
SELECT
    audit_id, transaction_id,
    previous_status, new_status,
    changed_by, changed_at, change_reason
FROM   transaction_audit_log
WHERE  changed_by = 'SYSTEM: trg_AMLStructuringAlert'
ORDER  BY changed_at DESC;
GO

-- Manual SP execution to cross-verify
EXEC dbo.usp_DetectStructuring
    @ThresholdAmount     = 10000.00,
    @WindowHours         = 48,
    @MinTransactionCount = 2,
    @RaiseAlert          = 1;
GO

-- ============================================================
-- END OF RULE 2: Structured Transaction Patterns
-- ============================================================
