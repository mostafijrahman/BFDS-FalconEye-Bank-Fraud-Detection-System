-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Rule 1: Geographic Impossibility (Impossible Travel)
-- Database : bank_fraud_detection_db
-- Version  : 4.0  |  Date: April 2026
-- ============================================================
-- KEY CHANGES FROM v3.0:
--   ✅ On violation, the ORIGINAL transaction's status is set
--      to 'declined' directly (no duplicate evidence row).
--   ✅ Alert is written to the alerts table using alert_type
--      = 'impossible_travel' to match the CHK_alerts_type
--      constraint on the alerts table.
--   ✅ transaction_audit_log records the before/after status
--      change (completed → declined) on the original txn.
--   ✅ alert_status defaults to 'open' for all new violations.
--   ✅ Repeat violations UPDATE the existing open alert
--      (risk_score, message, notes) instead of duplicating.
--
-- ARCHITECTURE:
--   fn_HaversineDistance        — Scalar UDF: great-circle km
--   usp_DetectGeoImpossibility  — SP: physics analysis, OUTPUT
--   trg_GeoImpossibilityAlert   — AFTER INSERT trigger:
--       1. Calls SP to evaluate new transaction
--       2. On VIOLATION:
--            A. UPDATE original transaction → 'declined'
--            B. INSERT / UPDATE alert (impossible_travel)
--            C. INSERT audit log (completed → declined)
--       3. On CLEAN PASS:
--            C. INSERT audit log (no_violation)
--
-- DETECTION THRESHOLD: 900 km/h (commercial airline ceiling)
-- ============================================================

USE bank_fraud_detection_db;
GO

-- ============================================================
-- PART 1: SCALAR FUNCTION — fn_HaversineDistance
-- ============================================================
-- Returns the great-circle distance in km between two
-- lat/lon coordinate pairs using the Haversine formula.
--
--   a = sin²(Δφ/2) + cos(φ1)·cos(φ2)·sin²(Δλ/2)
--   c = 2 · atan2(√a, √(1−a))
--   d = R · c       (R = 6,371 km Earth mean radius)
-- ============================================================

CREATE OR ALTER FUNCTION dbo.fn_HaversineDistance
(
    @Lat1  DECIMAL(10,8),
    @Lon1  DECIMAL(11,8),
    @Lat2  DECIMAL(10,8),
    @Lon2  DECIMAL(11,8)
)
RETURNS DECIMAL(12,4)
WITH SCHEMABINDING
AS
BEGIN
    DECLARE @Lat1Rad  FLOAT = CAST(@Lat1 AS FLOAT) * PI() / 180.0;
    DECLARE @Lat2Rad  FLOAT = CAST(@Lat2 AS FLOAT) * PI() / 180.0;
    DECLARE @DeltaLat FLOAT = (CAST(@Lat2 AS FLOAT) - CAST(@Lat1 AS FLOAT)) * PI() / 180.0;
    DECLARE @DeltaLon FLOAT = (CAST(@Lon2 AS FLOAT) - CAST(@Lon1 AS FLOAT)) * PI() / 180.0;

    DECLARE @HavA FLOAT =
          SIN(@DeltaLat / 2.0) * SIN(@DeltaLat / 2.0)
        + COS(@Lat1Rad) * COS(@Lat2Rad)
        * SIN(@DeltaLon / 2.0) * SIN(@DeltaLon / 2.0);

    DECLARE @HavC FLOAT =
        2.0 * ATN2(SQRT(@HavA), SQRT(1.0 - @HavA));

    RETURN CAST(6371.0 * @HavC AS DECIMAL(12,4));
END;
GO

PRINT 'fn_HaversineDistance created successfully.';
GO

-- ============================================================
-- PART 2: STORED PROCEDURE — usp_DetectGeoImpossibility
-- ============================================================
-- Receives the newly inserted transaction details as INPUT
-- parameters. Locates the user's most recent prior transaction
-- with coordinates, calculates distance via fn_HaversineDistance,
-- computes required travel speed, and determines violation.
--
-- All results are returned through OUTPUT parameters so the
-- trigger can call this cleanly without result-set conflicts.
-- ============================================================

CREATE OR ALTER PROCEDURE dbo.usp_DetectGeoImpossibility
    -- ── INPUTS ──────────────────────────────────────────────
    @NewTransactionID   BIGINT,
    @NewUserID          INT,
    @NewCardID          INT,
    @NewLat             DECIMAL(10,8),
    @NewLon             DECIMAL(11,8),
    @NewTimestamp       DATETIME2,
    @NewIPAddress       NVARCHAR(45),
    @MaxSpeedKmh        DECIMAL(10,2)   = 900.00,

    -- ── OUTPUTS ─────────────────────────────────────────────
    @ViolationFound     BIT             OUTPUT,
    @DistanceKm         DECIMAL(12,4)   OUTPUT,
    @RequiredSpeedKmh   DECIMAL(12,4)   OUTPUT,
    @TimeDiffMinutes    DECIMAL(10,2)   OUTPUT,
    @SpeedRatio         DECIMAL(10,2)   OUTPUT,
    @RiskScore          DECIMAL(4,2)    OUTPUT,
    @SeverityLevel      NVARCHAR(20)    OUTPUT,
    @AlertMessage       NVARCHAR(MAX)   OUTPUT,
    @InvestigationNotes NVARCHAR(MAX)   OUTPUT,
    @PrevTransactionID  BIGINT          OUTPUT,
    @PrevLat            DECIMAL(10,8)   OUTPUT,
    @PrevLon            DECIMAL(11,8)   OUTPUT,
    @PrevTimestamp      DATETIME2       OUTPUT,
    @PrevIPAddress      NVARCHAR(45)    OUTPUT
AS
BEGIN
    SET NOCOUNT ON;

    -- ── Initialise all OUTPUTs to safe defaults ──────────────
    SET @ViolationFound     = 0;
    SET @DistanceKm         = 0.00;
    SET @RequiredSpeedKmh   = 0.00;
    SET @TimeDiffMinutes    = 0.00;
    SET @SpeedRatio         = 0.00;
    SET @RiskScore          = 0.00;
    SET @SeverityLevel      = 'NONE';
    SET @AlertMessage       = NULL;
    SET @InvestigationNotes = NULL;
    SET @PrevTransactionID  = NULL;
    SET @PrevLat            = NULL;
    SET @PrevLon            = NULL;
    SET @PrevTimestamp      = NULL;
    SET @PrevIPAddress      = NULL;

    -- ── GUARD 1: Coordinates required ───────────────────────
    IF @NewLat IS NULL OR @NewLon IS NULL
    BEGIN
        PRINT 'usp_DetectGeoImpossibility: Skipped — new transaction has no coordinates.';
        RETURN;
    END

    -- ── STEP 1: Find most recent prior transaction with coordinates ──
    -- Excludes already-declined transactions to avoid chaining.
    SELECT TOP 1
        @PrevTransactionID = transaction_id,
        @PrevLat           = latitude,
        @PrevLon           = longitude,
        @PrevTimestamp     = transaction_timestamp,
        @PrevIPAddress     = ip_address
    FROM   dbo.transactions
    WHERE  user_id               =  @NewUserID
      AND  transaction_id        <> @NewTransactionID
      AND  latitude              IS NOT NULL
      AND  longitude             IS NOT NULL
      AND  transaction_status    NOT IN ('declined', 'reversed')
      AND  transaction_timestamp <  @NewTimestamp
    ORDER  BY transaction_timestamp DESC;

    -- ── GUARD 2: Must have a prior point to compare ──────────
    IF @PrevTransactionID IS NULL
    BEGIN
        PRINT 'usp_DetectGeoImpossibility: Skipped — no prior transaction with coordinates.';
        RETURN;
    END

    -- ── STEP 2: Time difference ──────────────────────────────
    DECLARE @TimeDiffSeconds DECIMAL(18,6);
    DECLARE @TimeDiffHours   DECIMAL(18,6);

    SET @TimeDiffSeconds = CAST(
        DATEDIFF(SECOND, @PrevTimestamp, @NewTimestamp)
    AS DECIMAL(18,6));

    IF @TimeDiffSeconds <= 0
        SET @TimeDiffSeconds = 1.0;          -- prevent division by zero

    SET @TimeDiffHours   = @TimeDiffSeconds / 3600.0;
    SET @TimeDiffMinutes = CAST(@TimeDiffSeconds / 60.0 AS DECIMAL(10,2));

    -- ── STEP 3: Haversine distance ───────────────────────────
    SET @DistanceKm = dbo.fn_HaversineDistance(
        @PrevLat, @PrevLon, @NewLat, @NewLon
    );

    -- ── STEP 4: Required travel speed ────────────────────────
    SET @RequiredSpeedKmh = CAST(
        @DistanceKm / CAST(@TimeDiffHours AS DECIMAL(18,6))
    AS DECIMAL(12,4));

    -- ── STEP 5: Compare against threshold ────────────────────
    IF @RequiredSpeedKmh <= @MaxSpeedKmh
        RETURN;                              -- clean — no violation

    -- ── STEP 6: VIOLATION CONFIRMED — compute risk metrics ───
    SET @ViolationFound = 1;
    SET @SpeedRatio     = CAST(@RequiredSpeedKmh / @MaxSpeedKmh AS DECIMAL(10,2));

    SET @RiskScore =
        CASE
            WHEN @SpeedRatio >= 5.0 THEN 1.00
            WHEN @SpeedRatio >= 3.0 THEN 0.97
            WHEN @SpeedRatio >= 2.0 THEN 0.93
            WHEN @SpeedRatio >= 1.5 THEN 0.87
            ELSE CAST(ROUND(0.70 + ((@SpeedRatio - 1.0) * 0.20), 2) AS DECIMAL(4,2))
        END;

    SET @SeverityLevel =
        CASE
            WHEN @SpeedRatio >= 5.0 THEN 'CRITICAL'
            WHEN @SpeedRatio >= 2.0 THEN 'HIGH'
            WHEN @SpeedRatio >= 1.5 THEN 'MEDIUM'
            ELSE                         'LOW'
        END;

    -- ── STEP 7: Build alert message & investigation notes ────
    SET @AlertMessage =
        'IMPOSSIBLE TRAVEL | user_id: '      + CAST(@NewUserID AS NVARCHAR(20))
        + ' | txn_id: '                      + CAST(@NewTransactionID AS NVARCHAR(20))
        + ' | Distance: '                    + CAST(@DistanceKm AS NVARCHAR(20))             + ' km'
        + ' | Time Gap: '                    + CAST(@TimeDiffMinutes AS NVARCHAR(20))         + ' mins'
        + ' | Req. Speed: '                  + CAST(CAST(@RequiredSpeedKmh AS INT) AS NVARCHAR(20)) + ' km/h'
        + ' | Threshold: '                   + CAST(CAST(@MaxSpeedKmh AS INT)   AS NVARCHAR(20)) + ' km/h'
        + ' | Speed Ratio: '                 + CAST(@SpeedRatio AS NVARCHAR(20))              + 'x'
        + ' | Risk Score: '                  + CAST(@RiskScore AS NVARCHAR(10))
        + ' | Severity: '                    + @SeverityLevel
        + ' | Transaction status set to: DECLINED';

    SET @InvestigationNotes =
        'Raised by usp_DetectGeoImpossibility via trg_GeoImpossibilityAlert.'
        + CHAR(13)+CHAR(10)
        + '============================================================'
        + CHAR(13)+CHAR(10)
        + 'LOCATION A — Previous Transaction (reference point)'
        + CHAR(13)+CHAR(10)
        + '   txn_id    : ' + CAST(@PrevTransactionID AS NVARCHAR(20))
        + CHAR(13)+CHAR(10)
        + '   Coords    : (' + CAST(@PrevLat AS NVARCHAR(20)) + ', ' + CAST(@PrevLon AS NVARCHAR(20)) + ')'
        + CHAR(13)+CHAR(10)
        + '   Timestamp : ' + CONVERT(NVARCHAR(30), @PrevTimestamp, 120)
        + CHAR(13)+CHAR(10)
        + '   IP Address: ' + ISNULL(@PrevIPAddress, 'N/A')
        + CHAR(13)+CHAR(10)
        + '------------------------------------------------------------'
        + CHAR(13)+CHAR(10)
        + 'LOCATION B — Suspicious Transaction (status = DECLINED)'
        + CHAR(13)+CHAR(10)
        + '   txn_id    : ' + CAST(@NewTransactionID AS NVARCHAR(20))
        + CHAR(13)+CHAR(10)
        + '   Coords    : (' + CAST(@NewLat AS NVARCHAR(20)) + ', ' + CAST(@NewLon AS NVARCHAR(20)) + ')'
        + CHAR(13)+CHAR(10)
        + '   Timestamp : ' + CONVERT(NVARCHAR(30), @NewTimestamp, 120)
        + CHAR(13)+CHAR(10)
        + '   IP Address: ' + ISNULL(@NewIPAddress, 'N/A')
        + CHAR(13)+CHAR(10)
        + '============================================================'
        + CHAR(13)+CHAR(10)
        + 'PHYSICS ANALYSIS'
        + CHAR(13)+CHAR(10)
        + '   Distance       : ' + CAST(@DistanceKm AS NVARCHAR(20))                          + ' km'
        + CHAR(13)+CHAR(10)
        + '   Time Gap       : ' + CAST(@TimeDiffMinutes AS NVARCHAR(20))                     + ' minutes'
        + CHAR(13)+CHAR(10)
        + '   Required Speed : ' + CAST(CAST(@RequiredSpeedKmh AS INT) AS NVARCHAR(20))       + ' km/h'
        + CHAR(13)+CHAR(10)
        + '   Airline Limit  : ' + CAST(CAST(@MaxSpeedKmh AS INT) AS NVARCHAR(20))            + ' km/h'
        + CHAR(13)+CHAR(10)
        + '   Speed Ratio    : ' + CAST(@SpeedRatio AS NVARCHAR(20))                          + 'x airline speed'
        + CHAR(13)+CHAR(10)
        + '   Risk Score     : ' + CAST(@RiskScore AS NVARCHAR(10))
        + CHAR(13)+CHAR(10)
        + '   Severity       : ' + @SeverityLevel
        + CHAR(13)+CHAR(10)
        + '   Action Taken   : Original transaction set to DECLINED.';

END;
GO

PRINT 'usp_DetectGeoImpossibility created successfully.';
GO

-- ============================================================
-- PART 3: AFTER INSERT TRIGGER — trg_GeoImpossibilityAlert
-- ============================================================
-- For every INSERT on dbo.transactions:
--   1. Calls usp_DetectGeoImpossibility via OUTPUT params.
--   2. On VIOLATION:
--        A. UPDATE the original transaction → 'declined'
--           (no duplicate evidence row — status change in place)
--        B. INSERT a new 'impossible_travel' alert into alerts,
--           OR UPDATE an existing open alert for this user.
--        C. INSERT one audit log row per violation
--           (previous_status = 'completed', new_status = 'declined')
--   3. On CLEAN PASS:
--        C. INSERT audit log row (no violation detected)
-- ============================================================

CREATE OR ALTER TRIGGER dbo.trg_GeoImpossibilityAlert
ON dbo.transactions
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    -- ── Row-level working variables ──────────────────────────
    DECLARE @TxnID              BIGINT;
    DECLARE @UserID             INT;
    DECLARE @CardID             INT;
    DECLARE @MerchantID         INT;
    DECLARE @Amount             DECIMAL(15,2);
    DECLARE @Currency           NVARCHAR(3);
    DECLARE @TxnTimestamp       DATETIME2;
    DECLARE @MerchantCountry    NVARCHAR(2);
    DECLARE @CustomerCountry    NVARCHAR(2);
    DECLARE @MerchantMCC        NVARCHAR(10);
    DECLARE @IsOnline           BIT;
    DECLARE @DeviceID           NVARCHAR(255);
    DECLARE @IPAddress          NVARCHAR(45);
    DECLARE @Lat                DECIMAL(10,8);
    DECLARE @Lon                DECIMAL(11,8);

    -- ── SP OUTPUT variables ──────────────────────────────────
    DECLARE @ViolationFound     BIT;
    DECLARE @DistanceKm         DECIMAL(12,4);
    DECLARE @RequiredSpeedKmh   DECIMAL(12,4);
    DECLARE @TimeDiffMinutes    DECIMAL(10,2);
    DECLARE @SpeedRatio         DECIMAL(10,2);
    DECLARE @RiskScore          DECIMAL(4,2);
    DECLARE @SeverityLevel      NVARCHAR(20);
    DECLARE @AlertMessage       NVARCHAR(MAX);
    DECLARE @InvestigationNotes NVARCHAR(MAX);
    DECLARE @PrevTransactionID  BIGINT;
    DECLARE @PrevLat            DECIMAL(10,8);
    DECLARE @PrevLon            DECIMAL(11,8);
    DECLARE @PrevTimestamp      DATETIME2;
    DECLARE @PrevIPAddress      NVARCHAR(45);

    -- ── Cursor: process each inserted row with coordinates ───
    DECLARE geo_cursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT
            transaction_id, user_id, card_id, merchant_id,
            transaction_amount, currency_code, transaction_timestamp,
            merchant_country, customer_country, merchant_mcc,
            is_online, device_id, ip_address, latitude, longitude
        FROM inserted
        WHERE latitude  IS NOT NULL
          AND longitude IS NOT NULL;

    OPEN geo_cursor;
    FETCH NEXT FROM geo_cursor INTO
        @TxnID, @UserID, @CardID, @MerchantID,
        @Amount, @Currency, @TxnTimestamp,
        @MerchantCountry, @CustomerCountry, @MerchantMCC,
        @IsOnline, @DeviceID, @IPAddress, @Lat, @Lon;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- Reset per-row
        SET @ViolationFound     = 0;
        SET @DistanceKm         = 0;
        SET @RequiredSpeedKmh   = 0;
        SET @TimeDiffMinutes    = 0;
        SET @SpeedRatio         = 0;
        SET @RiskScore          = 0;
        SET @SeverityLevel      = 'NONE';
        SET @AlertMessage       = NULL;
        SET @InvestigationNotes = NULL;
        SET @PrevTransactionID  = NULL;
        SET @PrevLat            = NULL;
        SET @PrevLon            = NULL;
        SET @PrevTimestamp      = NULL;
        SET @PrevIPAddress      = NULL;

        -- ── CALL SP ─────────────────────────────────────────
        EXEC dbo.usp_DetectGeoImpossibility
            @NewTransactionID   = @TxnID,
            @NewUserID          = @UserID,
            @NewCardID          = @CardID,
            @NewLat             = @Lat,
            @NewLon             = @Lon,
            @NewTimestamp       = @TxnTimestamp,
            @NewIPAddress       = @IPAddress,
            @MaxSpeedKmh        = 900.00,
            @ViolationFound     = @ViolationFound     OUTPUT,
            @DistanceKm         = @DistanceKm         OUTPUT,
            @RequiredSpeedKmh   = @RequiredSpeedKmh   OUTPUT,
            @TimeDiffMinutes    = @TimeDiffMinutes    OUTPUT,
            @SpeedRatio         = @SpeedRatio         OUTPUT,
            @RiskScore          = @RiskScore          OUTPUT,
            @SeverityLevel      = @SeverityLevel      OUTPUT,
            @AlertMessage       = @AlertMessage       OUTPUT,
            @InvestigationNotes = @InvestigationNotes OUTPUT,
            @PrevTransactionID  = @PrevTransactionID  OUTPUT,
            @PrevLat            = @PrevLat            OUTPUT,
            @PrevLon            = @PrevLon            OUTPUT,
            @PrevTimestamp      = @PrevTimestamp      OUTPUT,
            @PrevIPAddress      = @PrevIPAddress      OUTPUT;

        -- ── VIOLATION PATH ───────────────────────────────────
        IF @ViolationFound = 1
        BEGIN

            -- ─────────────────────────────────────────────────
            -- ACTION A: UPDATE the original transaction status
            --   Set transaction_status = 'declined' directly
            --   on the row that just triggered the insert.
            --   No duplicate / evidence row is inserted.
            -- ─────────────────────────────────────────────────
            UPDATE dbo.transactions
            SET    transaction_status = 'declined'
            WHERE  transaction_id     = @TxnID;

            -- ─────────────────────────────────────────────────
            -- ACTION B: Write alert to alerts table
            --   alert_type = 'impossible_travel' matches
            --   CHK_alerts_type constraint on alerts table.
            --   If an open alert already exists for this user,
            --   UPDATE it (escalate risk_score + append notes).
            --   Otherwise INSERT a fresh alert.
            -- ─────────────────────────────────────────────────
            IF EXISTS (
                SELECT 1
                FROM   dbo.alerts
                WHERE  user_id      = @UserID
                  AND  alert_type   = 'impossible_travel'
                  AND  alert_status = 'open'
            )
            BEGIN
                -- Update existing open alert (re-trigger / escalate)
                UPDATE dbo.alerts
                SET
                    transaction_id      = @TxnID,
                    risk_score          = @RiskScore,
                    alert_message       = @AlertMessage,
                    investigation_notes =
                        investigation_notes
                        + CHAR(13)+CHAR(10)
                        + '============================================================'
                        + CHAR(13)+CHAR(10)
                        + 'RE-TRIGGERED at ' + CONVERT(NVARCHAR(30), GETUTCDATE(), 120)
                        + CHAR(13)+CHAR(10)
                        + 'Declined txn_id : ' + CAST(@TxnID AS NVARCHAR(20))
                        + CHAR(13)+CHAR(10)
                        + @InvestigationNotes
                WHERE  user_id      = @UserID
                  AND  alert_type   = 'impossible_travel'
                  AND  alert_status = 'open';
            END
            ELSE
            BEGIN
                -- Insert new impossible_travel alert
                INSERT INTO dbo.alerts
                (
                    transaction_id,
                    card_id,
                    user_id,
                    alert_type,
                    risk_score,
                    alert_message,
                    alert_status,
                    investigation_notes,
                    created_at,
                    resolved_at
                )
                VALUES
                (
                    @TxnID,
                    @CardID,
                    @UserID,
                    'impossible_travel',         -- matches CHK_alerts_type
                    @RiskScore,
                    @AlertMessage,
                    'open',
                    @InvestigationNotes,
                    GETUTCDATE(),
                    NULL
                );
            END

            -- ─────────────────────────────────────────────────
            -- ACTION C: Audit log — completed → declined
            -- ─────────────────────────────────────────────────
            INSERT INTO dbo.transaction_audit_log
            (
                transaction_id,
                previous_status,
                new_status,
                changed_by,
                changed_at,
                change_reason
            )
            VALUES
            (
                @TxnID,
                'completed',
                'declined',
                'SYSTEM: trg_GeoImpossibilityAlert',
                GETUTCDATE(),
                'Rule 1 — Geographic Impossibility triggered. '
                + 'txn_id: '         + CAST(@TxnID AS NVARCHAR(20))
                + ' | prev_txn_id: ' + CAST(@PrevTransactionID AS NVARCHAR(20))
                + ' | Distance: '    + CAST(@DistanceKm AS NVARCHAR(20))                     + ' km'
                + ' | Time Gap: '    + CAST(@TimeDiffMinutes AS NVARCHAR(20))                 + ' mins'
                + ' | Req. Speed: '  + CAST(CAST(@RequiredSpeedKmh AS INT) AS NVARCHAR(20))  + ' km/h'
                + ' | Speed Ratio: ' + CAST(@SpeedRatio AS NVARCHAR(20))                     + 'x'
                + ' | Risk Score: '  + CAST(@RiskScore AS NVARCHAR(10))
                + ' | Severity: '    + @SeverityLevel
                + ' | Action: transaction_status set to DECLINED.'
            );

        END
        ELSE
        BEGIN
            -- ── CLEAN PATH: no violation — audit log only ────
            INSERT INTO dbo.transaction_audit_log
            (
                transaction_id,
                previous_status,
                new_status,
                changed_by,
                changed_at,
                change_reason
            )
            VALUES
            (
                @TxnID,
                NULL,
                'completed',
                'SYSTEM: trg_GeoImpossibilityAlert',
                GETUTCDATE(),
                'Rule 1 — Geographic Impossibility: No violation detected. '
                + CASE
                    WHEN @PrevTransactionID IS NULL
                        THEN 'No prior coordinate point available for comparison.'
                    ELSE
                        'Distance: '    + CAST(@DistanceKm AS NVARCHAR(20))   + ' km'
                        + ' | Speed: ' + CAST(CAST(@RequiredSpeedKmh AS INT) AS NVARCHAR(20))
                        + ' km/h — within 900 km/h threshold. Transaction remains completed.'
                  END
            );
        END

        FETCH NEXT FROM geo_cursor INTO
            @TxnID, @UserID, @CardID, @MerchantID,
            @Amount, @Currency, @TxnTimestamp,
            @MerchantCountry, @CustomerCountry, @MerchantMCC,
            @IsOnline, @DeviceID, @IPAddress, @Lat, @Lon;
    END

    CLOSE     geo_cursor;
    DEALLOCATE geo_cursor;

END;
GO

PRINT 'trg_GeoImpossibilityAlert (AFTER INSERT) created successfully.';
GO

-- ============================================================
-- VERIFICATION TESTS
-- ============================================================
-- Each test inserts a transaction with transaction_status =
-- 'completed'. The trigger fires AFTER INSERT and:
--   - On violation: flips the status to 'declined',
--     writes an alert, writes an audit log row.
--   - On clean pass: writes an audit log row only.
-- ============================================================

-- ✅ TEST 1: Normal — User 1 transacts in Shreveport (anchor point)
--    Expected: status = completed | 0 alerts | audit: no violation
-- ------------------------------------------------------------
PRINT '==== TEST 1: Normal baseline — Shreveport ====';

INSERT INTO dbo.transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(1, 1, 1, 85.00, 'USD', 'US', 'US', '5942', 'completed',
 1, 'DEV-IPHONE-001', '192.168.1.10',
 32.52520000, -93.75020000);

PRINT 'TEST 1 DONE — Expected: status = completed | 0 alerts | audit: no violation.';
GO

-- ❌ TEST 2: IMPOSSIBLE — User 1: Shreveport → Moscow (seconds later)
--    Distance ≈ 9,800 km | CRITICAL speed ratio
--    Expected: status flipped to DECLINED | impossible_travel alert (open) | audit log
-- ------------------------------------------------------------
PRINT '==== TEST 2: Impossible Travel — Shreveport → Moscow ====';

INSERT INTO dbo.transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(1, 3, 1, 4200.00, 'USD', 'RU', 'US', '6051', 'completed',
 1, 'UNKNOWN-DEVICE', '185.220.101.1',
 55.75580000, 37.61730000);

PRINT 'TEST 2 DONE — Expected: status = declined | 1 new impossible_travel alert | audit log entry.';
GO

-- ❌ TEST 3: IMPOSSIBLE — User 3: Dallas → Tokyo (seconds later)
--    Distance ≈ 11,350 km | CRITICAL
--    Expected: status flipped to DECLINED | new alert for user 3 | audit log
-- ------------------------------------------------------------
PRINT '==== TEST 3: Impossible Travel — Dallas → Tokyo ====';

INSERT INTO dbo.transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(3, 2, 3, 1800.00, 'USD', 'JP', 'US', '5411', 'completed',
 1, 'DEV-TABLET-005', '203.104.209.104',
 35.68950000, 139.69171000);

PRINT 'TEST 3 DONE — Expected: status = declined | new impossible_travel alert for user 3 | audit log.';
GO

-- ❌ TEST 4: REPEAT VIOLATION — User 1: Moscow → Sydney (seconds later)
--    Distance ≈ 14,500 km | Existing open alert must UPDATE, not duplicate
-- ------------------------------------------------------------
PRINT '==== TEST 4: Repeat Violation — User 1 (existing open alert) ====';

INSERT INTO dbo.transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(1, 2, 1, 3300.00, 'USD', 'AU', 'US', '5411', 'completed',
 1, 'UNKNOWN-DEVICE-2', '203.2.218.1',
 -33.86850000, 151.20930000);

PRINT 'TEST 4 DONE — Expected: status = declined | EXISTING alert UPDATED for user 1 | audit log.';
GO

-- ✅ TEST 5: SAFE — User 5 first transaction in Houston (no prior geo point)
--    Expected: status = completed | 0 alerts | audit: no prior coordinates
-- ------------------------------------------------------------
PRINT '==== TEST 5: Safe — User 5 first transaction, Houston ====';

INSERT INTO dbo.transactions
(card_id, merchant_id, user_id, transaction_amount, currency_code,
 merchant_country, customer_country, merchant_mcc, transaction_status,
 is_online, device_id, ip_address, latitude, longitude)
VALUES
(5, 2, 5, 250.00, 'USD', 'US', 'US', '5411', 'completed',
 0, 'DEV-TABLET-005', '192.168.1.20',
 29.76040000, -95.36980000);

PRINT 'TEST 5 DONE — Expected: status = completed | 0 alerts | audit: no prior coords.';
GO

-- ============================================================
-- VIEW RESULTS
-- ============================================================

-- R1. All transactions — verify declined rows are the correct originals
SELECT
    transaction_id,
    user_id,
    card_id,
    merchant_id,
    transaction_amount,
    merchant_country,
    ip_address,
    CAST(latitude  AS NVARCHAR(15)) + ', '
        + CAST(longitude AS NVARCHAR(15)) AS coordinates,
    transaction_status,
    transaction_timestamp
FROM   dbo.transactions
ORDER  BY user_id ASC, transaction_timestamp ASC, transaction_id ASC;
GO

-- R2. All impossible_travel alerts (written by this rule)
SELECT
    alert_id,
    transaction_id,
    card_id,
    user_id,
    alert_type,
    risk_score,
    alert_status,
    alert_message,
    investigation_notes,
    created_at
FROM   dbo.alerts
WHERE  alert_type = 'impossible_travel'
ORDER  BY created_at DESC;
GO

-- R3. Audit log entries written by Rule 1 trigger
SELECT
    audit_id,
    transaction_id,
    previous_status,
    new_status,
    changed_by,
    changed_at,
    change_reason
FROM   dbo.transaction_audit_log
WHERE  changed_by = 'SYSTEM: trg_GeoImpossibilityAlert'
ORDER  BY changed_at DESC;
GO

-- R4. Summary: declined transactions with their open alerts side-by-side
SELECT
    t.transaction_id,
    t.user_id,
    t.transaction_amount,
    t.merchant_country,
    t.ip_address,
    t.transaction_status,
    t.transaction_timestamp,
    a.alert_id,
    a.alert_type,
    a.risk_score,
    a.alert_status
FROM   dbo.transactions t
LEFT   JOIN dbo.alerts a
    ON  a.transaction_id = t.transaction_id
   AND  a.alert_type     = 'impossible_travel'
WHERE  t.transaction_status = 'declined'
ORDER  BY t.transaction_timestamp DESC;
GO

-- ============================================================
-- END OF RULE 1: Geographic Impossibility — v4.0
-- ============================================================
