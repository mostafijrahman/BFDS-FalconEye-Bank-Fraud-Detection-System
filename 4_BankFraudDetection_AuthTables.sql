-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Script: Authentication & Authentication Audit Log Tables
-- Version: 2.0  |  Date: April 2026
-- ============================================================

USE bank_fraud_detection_db;
GO

-- ============================================================
-- DROP IF EXISTS (for re-run safety)
-- ============================================================
IF OBJECT_ID('dbo.authentication_audit_log', 'U') IS NOT NULL
    DROP TABLE dbo.authentication_audit_log;
GO
IF OBJECT_ID('dbo.authentication', 'U') IS NOT NULL
    DROP TABLE dbo.authentication;
GO

-- ============================================================
-- TABLE 1: authentication
-- Stores bank employee login credentials and role assignments
-- ============================================================
CREATE TABLE authentication (
    auth_id             INT             NOT NULL IDENTITY(1,1),
    employee_id         NVARCHAR(50)    NOT NULL,           -- e.g. EMP-SA-001
    username            NVARCHAR(100)   NOT NULL,           -- login username
    password_hash       NVARCHAR(256)   NOT NULL,           -- bcrypt / SHA-256 hash ONLY
    salt                NVARCHAR(64)    NOT NULL,           -- unique per-user salt
    role                NVARCHAR(50)    NOT NULL DEFAULT 'bank_employee',
    is_active           BIT             NOT NULL DEFAULT 1,
    email               NVARCHAR(150)   NULL,               -- for password reset notifications
    phone               NVARCHAR(20)    NULL,               -- for MFA (future)
    mfa_enabled         BIT             NOT NULL DEFAULT 0,
    mfa_secret_hash     NVARCHAR(256)   NULL,               -- TOTP secret (hashed)

    -- Login tracking
    last_login_at       DATETIME2       NULL,
    last_login_ip       NVARCHAR(45)    NULL,
    failed_attempts     INT             NOT NULL DEFAULT 0,
    locked_until        DATETIME2       NULL,               -- NULL = not locked
    password_changed_at DATETIME2       NULL,               -- track password expiry
    must_change_password BIT            NOT NULL DEFAULT 0,  -- force reset on first login

    -- Timestamps
    created_at          DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    updated_at          DATETIME2       NULL,
    deactivated_at      DATETIME2       NULL,

    -- ── Constraints ──────────────────────────────────────────
    CONSTRAINT PK_authentication        PRIMARY KEY (auth_id),
    CONSTRAINT UK_auth_employee_id      UNIQUE (employee_id),
    CONSTRAINT UK_auth_username         UNIQUE (username),
    CONSTRAINT UK_auth_email            UNIQUE (email),
    CONSTRAINT CHK_auth_role            CHECK  (role IN (
                                            'super_admin',
                                            'compliance_officer',
                                            'bank_employee'
                                        )),
    CONSTRAINT CHK_auth_failed_attempts CHECK  (failed_attempts >= 0),
    CONSTRAINT CHK_auth_active_deact    CHECK  (
                                            is_active = 1 OR deactivated_at IS NOT NULL
                                        )
);
GO

-- Indexes
CREATE INDEX idx_auth_username    ON authentication (username);
CREATE INDEX idx_auth_employee_id ON authentication (employee_id);
CREATE INDEX idx_auth_role        ON authentication (role);
CREATE INDEX idx_auth_is_active   ON authentication (is_active);
CREATE INDEX idx_auth_locked      ON authentication (locked_until)
    WHERE locked_until IS NOT NULL;
GO

-- ============================================================
-- TABLE 2: authentication_audit_log
-- Records EVERY login attempt — successful or failed —
-- with full context for forensic and compliance review
-- ============================================================
CREATE TABLE authentication_audit_log (
    log_id              BIGINT          NOT NULL IDENTITY(1,1),

    -- Who attempted
    auth_id             INT             NULL,               -- NULL if username not found
    employee_id         NVARCHAR(50)    NULL,               -- denormalized for fast querying
    username_attempted  NVARCHAR(100)   NOT NULL,           -- exact input used at login

    -- Outcome
    event_type          NVARCHAR(50)    NOT NULL,           -- see CHECK below
    login_status        NVARCHAR(20)    NOT NULL,           -- 'success' | 'failure'
    failure_reason      NVARCHAR(100)   NULL,               -- populated on failure only

    -- Session info
    session_token_hash  NVARCHAR(256)   NULL,               -- hashed session/JWT token on success
    session_expires_at  DATETIME2       NULL,

    -- Network / Device context
    ip_address          NVARCHAR(45)    NULL,
    user_agent          NVARCHAR(500)   NULL,               -- browser / client identifier
    device_fingerprint  NVARCHAR(256)   NULL,               -- optional device hash
    geo_country         NVARCHAR(2)     NULL,               -- derived from IP (optional)
    geo_city            NVARCHAR(100)   NULL,

    -- MFA
    mfa_used            BIT             NOT NULL DEFAULT 0,
    mfa_outcome         NVARCHAR(20)    NULL,               -- 'passed' | 'failed' | 'skipped'

    -- Metadata
    event_timestamp     DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    notes               NVARCHAR(MAX)   NULL,               -- e.g. "Account locked after this attempt"

    -- ── Constraints ──────────────────────────────────────────
    CONSTRAINT PK_auth_audit_log        PRIMARY KEY (log_id),
    CONSTRAINT FK_audit_log_auth        FOREIGN KEY (auth_id)
                                            REFERENCES authentication(auth_id)
                                            ON DELETE SET NULL,  -- keep log even if employee removed
    CONSTRAINT CHK_audit_event_type     CHECK (event_type IN (
                                            'login_success',        -- correct credentials
                                            'login_failure',        -- wrong password
                                            'account_locked',       -- threshold breached
                                            'account_unlocked',     -- admin unlocked
                                            'logout',               -- explicit logout
                                            'session_expired',      -- token/session timeout
                                            'password_changed',     -- password reset/change
                                            'mfa_success',          -- MFA passed
                                            'mfa_failure',          -- MFA failed
                                            'username_not_found',   -- no matching user
                                            'inactive_account',     -- login on disabled account
                                            'forced_logout'         -- admin-forced session kill
                                        )),
    CONSTRAINT CHK_audit_login_status   CHECK (login_status IN ('success', 'failure')),
    CONSTRAINT CHK_audit_mfa_outcome    CHECK (mfa_outcome  IN ('passed', 'failed', 'skipped') OR mfa_outcome IS NULL)
);
GO

-- Indexes — optimized for security queries and compliance reports
CREATE INDEX idx_aal_auth_id        ON authentication_audit_log (auth_id);
CREATE INDEX idx_aal_employee_id    ON authentication_audit_log (employee_id);
CREATE INDEX idx_aal_event_ts       ON authentication_audit_log (event_timestamp DESC);
CREATE INDEX idx_aal_login_status   ON authentication_audit_log (login_status);
CREATE INDEX idx_aal_event_type     ON authentication_audit_log (event_type);
CREATE INDEX idx_aal_ip_address     ON authentication_audit_log (ip_address);

-- Composite: most common security query pattern
CREATE INDEX idx_aal_user_ts        ON authentication_audit_log (auth_id, event_timestamp DESC);
CREATE INDEX idx_aal_status_ts      ON authentication_audit_log (login_status, event_timestamp DESC);
GO

-- ============================================================
-- TRIGGER: auto-update authentication.updated_at on any change
-- ============================================================
CREATE OR ALTER TRIGGER trg_auth_updated_at
ON authentication
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE authentication
    SET    updated_at = GETUTCDATE()
    FROM   authentication a
    INNER JOIN inserted i ON a.auth_id = i.auth_id;
END;
GO

-- ============================================================
-- TRIGGER: auto-lock account after 5 consecutive failures
-- Reads latest failure count from authentication_audit_log
-- and sets locked_until = 30 minutes from now
-- ============================================================
CREATE OR ALTER TRIGGER trg_auto_lock_on_failures
ON authentication_audit_log
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    -- For each newly inserted failure row, check consecutive failures
    UPDATE a
    SET
        a.failed_attempts = a.failed_attempts + 1,
        a.locked_until    = CASE
                                WHEN (a.failed_attempts + 1) >= 5
                                THEN DATEADD(MINUTE, 30, GETUTCDATE())
                                ELSE a.locked_until
                            END,
        a.updated_at      = GETUTCDATE()
    FROM authentication a
    INNER JOIN inserted i ON a.auth_id = i.auth_id
    WHERE i.login_status  = 'failure'
      AND i.event_type    = 'login_failure';

    -- Reset failed_attempts counter on successful login
    UPDATE a
    SET
        a.failed_attempts  = 0,
        a.locked_until     = NULL,
        a.last_login_at    = GETUTCDATE(),
        a.last_login_ip    = i.ip_address,
        a.updated_at       = GETUTCDATE()
    FROM authentication a
    INNER JOIN inserted i ON a.auth_id = i.auth_id
    WHERE i.login_status = 'success'
      AND i.event_type   = 'login_success';
END;
GO

-- ============================================================
-- SAMPLE DATA: authentication (5 bank employees)
-- ============================================================
INSERT INTO authentication
    (employee_id, username, password_hash, salt, role,
     is_active, email, mfa_enabled, must_change_password)
VALUES
-- Super Admin
('EMP-SA-001', 'admin.superuser',
 'HASH_bcrypt_$2b$12$SuperAdmin2026!xKpQ',
 'SALT_SA001_xKpQrandom',
 'super_admin', 1, 'superadmin@bfds.bank', 1, 0),

-- Compliance Officers
('EMP-CO-001', 'officer.compliance',
 'HASH_bcrypt_$2b$12$Compliance2026!yLmN',
 'SALT_CO001_yLmNrandom',
 'compliance_officer', 1, 'compliance1@bfds.bank', 1, 0),

-- Bank Employees
('EMP-BE-001', 'emp.johndoe',
 'HASH_bcrypt_$2b$12$BankEmp001_2026!zPqR',
 'SALT_BE001_zPqRrandom',
 'bank_employee', 1, 'j.doe@bfds.bank', 0, 0),

('EMP-BE-002', 'emp.alicesmith',
 'HASH_bcrypt_$2b$12$BankEmp002_2026!aWsX',
 'SALT_BE002_aWsXrandom',
 'bank_employee', 1, 'a.smith@bfds.bank', 0, 1),   -- must change password

('EMP-BE-003', 'emp.michaelbrown',
 'HASH_bcrypt_$2b$12$BankEmp003_2026!bEtY',
 'SALT_BE003_bEtYrandom',
 'bank_employee', 0, 'm.brown@bfds.bank', 0, 0);   -- deactivated
GO

-- ============================================================
-- SAMPLE DATA: authentication_audit_log
-- Mix of successes, failures, lockout, MFA events
-- ============================================================
INSERT INTO authentication_audit_log
    (auth_id, employee_id, username_attempted,
     event_type, login_status, failure_reason,
     session_token_hash, session_expires_at,
     ip_address, user_agent, geo_country, geo_city,
     mfa_used, mfa_outcome, notes)
VALUES

-- ✅ Successful login — Super Admin
(1, 'EMP-SA-001', 'admin.superuser',
 'login_success', 'success', NULL,
 'HASH_JWT_SA001_session_abc123', DATEADD(HOUR, 8, GETUTCDATE()),
 '10.0.0.1', 'Mozilla/5.0 (Windows NT 10.0) Chrome/124',
 'US', 'New York', 1, 'passed',
 'MFA via TOTP passed. Session established.'),

-- ✅ Successful login — Compliance Officer
(2, 'EMP-CO-001', 'officer.compliance',
 'login_success', 'success', NULL,
 'HASH_JWT_CO001_session_def456', DATEADD(HOUR, 8, GETUTCDATE()),
 '10.0.0.2', 'Mozilla/5.0 (Macintosh) Safari/17',
 'US', 'Dallas', 1, 'passed',
 'Standard login. MFA passed.'),

-- ✅ Successful login — Bank Employee
(3, 'EMP-BE-001', 'emp.johndoe',
 'login_success', 'success', NULL,
 'HASH_JWT_BE001_session_ghi789', DATEADD(HOUR, 8, GETUTCDATE()),
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'MFA not enabled. Login from trusted internal IP.'),

-- ❌ Failed login — Wrong password (attempt 1)
(3, 'EMP-BE-001', 'emp.johndoe',
 'login_failure', 'failure', 'invalid_password',
 NULL, NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'Failed attempt 1 of 5.'),

-- ❌ Failed login — Wrong password (attempt 2)
(3, 'EMP-BE-001', 'emp.johndoe',
 'login_failure', 'failure', 'invalid_password',
 NULL, NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'Failed attempt 2 of 5.'),

-- ❌ Failed login — Username does not exist
(NULL, NULL, 'hacker.unknown',
 'username_not_found', 'failure', 'username_not_found',
 NULL, NULL,
 '185.220.101.99', 'python-requests/2.31.0',
 'RU', 'Moscow', 0, NULL,
 'Suspicious: unknown username from foreign IP.'),

-- ❌ Failed login — Inactive account
(5, 'EMP-BE-003', 'emp.michaelbrown',
 'inactive_account', 'failure', 'account_deactivated',
 NULL, NULL,
 '10.0.0.99', 'Mozilla/5.0 (X11; Linux) Firefox/124',
 'US', 'Houston', 0, NULL,
 'Account is deactivated. Login rejected.'),

-- 🔒 Account locked after repeated failures
(4, 'EMP-BE-002', 'emp.alicesmith',
 'account_locked', 'failure', 'max_failed_attempts_reached',
 NULL, NULL,
 '203.0.113.55', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17)',
 'US', 'Chicago', 0, 'skipped',
 'Account locked for 30 minutes after 5 consecutive failures.'),

-- ❌ MFA failure after correct password
(1, 'EMP-SA-001', 'admin.superuser',
 'mfa_failure', 'failure', 'invalid_mfa_code',
 NULL, NULL,
 '10.0.0.1', 'Mozilla/5.0 (Windows NT 10.0) Chrome/124',
 'US', 'New York', 1, 'failed',
 'Correct password. TOTP code expired or incorrect.'),

-- 🔓 Account unlocked by admin
(4, 'EMP-BE-002', 'emp.alicesmith',
 'account_unlocked', 'success', NULL,
 NULL, NULL,
 '10.0.0.1', 'AdminConsole/BFDS-v2.0',
 'US', 'New York', 0, 'skipped',
 'Account manually unlocked by EMP-SA-001.'),

-- 🔑 Password changed
(3, 'EMP-BE-001', 'emp.johndoe',
 'password_changed', 'success', NULL,
 NULL, NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'User initiated password change from profile settings.'),

-- 🚪 Explicit logout
(2, 'EMP-CO-001', 'officer.compliance',
 'logout', 'success', NULL,
 'HASH_JWT_CO001_session_def456', NULL,
 '10.0.0.2', 'Mozilla/5.0 (Macintosh) Safari/17',
 'US', 'Dallas', 0, 'skipped',
 'User logged out. Session token invalidated.'),

-- ⏱ Session expired
(3, 'EMP-BE-001', 'emp.johndoe',
 'session_expired', 'failure', 'session_timeout',
 'HASH_JWT_BE001_session_ghi789', NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'Session token expired after 8-hour TTL. User must re-authenticate.'),

-- 🚫 Forced logout by admin
(5, 'EMP-BE-003', 'emp.michaelbrown',
 'forced_logout', 'success', NULL,
 NULL, NULL,
 '10.0.0.1', 'AdminConsole/BFDS-v2.0',
 'US', 'New York', 0, 'skipped',
 'Admin forced session termination for EMP-BE-003.');
GO

-- ============================================================
-- VIEWING QUERIES
-- ============================================================

-- V1. Full authentication_audit_log with employee name
SELECT
    aal.log_id,
    aal.employee_id,
    aal.username_attempted,
    aal.event_type,
    aal.login_status,
    aal.failure_reason,
    aal.ip_address,
    aal.geo_country,
    aal.geo_city,
    aal.mfa_used,
    aal.mfa_outcome,
    aal.event_timestamp,
    aal.notes
FROM   authentication_audit_log aal
ORDER  BY aal.event_timestamp DESC;
GO

-- V2. All failed login attempts (security monitoring)
SELECT
    aal.log_id,
    aal.employee_id,
    aal.username_attempted,
    aal.event_type,
    aal.failure_reason,
    aal.ip_address,
    aal.geo_country,
    aal.geo_city,
    aal.user_agent,
    aal.event_timestamp
FROM   authentication_audit_log aal
WHERE  aal.login_status = 'failure'
ORDER  BY aal.event_timestamp DESC;
GO

-- V3. Suspicious activity — foreign IPs or unknown usernames
SELECT
    aal.log_id,
    aal.username_attempted,
    aal.event_type,
    aal.failure_reason,
    aal.ip_address,
    aal.geo_country,
    aal.user_agent,
    aal.event_timestamp,
    '⚠ SUSPICIOUS' AS flag
FROM   authentication_audit_log aal
WHERE  aal.geo_country NOT IN ('US')
   OR  aal.event_type   = 'username_not_found'
   OR  aal.event_type   = 'account_locked'
ORDER  BY aal.event_timestamp DESC;
GO

-- V4. Login history for a specific employee (replace @emp)
DECLARE @emp NVARCHAR(50) = 'EMP-BE-001';
SELECT
    aal.log_id,
    aal.event_type,
    aal.login_status,
    aal.failure_reason,
    aal.ip_address,
    aal.geo_country,
    aal.mfa_used,
    aal.mfa_outcome,
    aal.event_timestamp
FROM   authentication_audit_log aal
WHERE  aal.employee_id = @emp
ORDER  BY aal.event_timestamp DESC;
GO

-- V5. Account lockout events summary
SELECT
    aal.employee_id,
    COUNT(*)                     AS lockout_events,
    MAX(aal.event_timestamp)     AS last_lockout,
    STRING_AGG(aal.ip_address, ', ') AS ips_involved
FROM   authentication_audit_log aal
WHERE  aal.event_type = 'account_locked'
GROUP  BY aal.employee_id
ORDER  BY lockout_events DESC;
GO

-- V6. Current authentication status of all employees
SELECT
    a.auth_id,
    a.employee_id,
    a.username,
    a.role,
    a.is_active,
    a.failed_attempts,
    a.locked_until,
    a.last_login_at,
    a.last_login_ip,
    a.mfa_enabled,
    a.must_change_password,
    CASE
        WHEN a.is_active    = 0                  THEN '🔴 Deactivated'
        WHEN a.locked_until > GETUTCDATE()       THEN '🔒 Locked'
        WHEN a.failed_attempts BETWEEN 3 AND 4   THEN '⚠ At Risk'
        ELSE                                          '✅ Active'
    END AS account_health
FROM  authentication a
ORDER BY a.role, a.auth_id;
GO

-- ============================================================
-- END OF SCRIPT: Authentication & Audit Log
-- ============================================================
