-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Script: Authentication — Database Roles + Full Setup
-- Database : bank_fraud_detection_db
-- Version  : 3.0  |  Date: April 2026
-- ============================================================
-- WHAT THIS SCRIPT DOES (run top-to-bottom once):
--   STEP 1  — Switch to bank_fraud_detection_db
--   STEP 2  — Drop & recreate authentication + audit log tables
--   STEP 3  — CREATE DATABASE ROLES (visible under Security → Roles)
--   STEP 4  — GRANT permissions per role
--   STEP 5  — Create helper trigger
--   STEP 6  — Insert sample users (all 3 roles, 10 employees)
--   STEP 7  — Map SQL logins → database roles
--   STEP 8  — Post-insert state updates
--   STEP 9  — Insert sample audit log events
--   STEP 10 — Verification SELECT queries
-- ============================================================

USE bank_fraud_detection_db;
GO

-- ============================================================
-- STEP 1 — SAFE DROP (re-run friendly)
-- ============================================================
IF OBJECT_ID('dbo.authentication_audit_log', 'U') IS NOT NULL
    DROP TABLE dbo.authentication_audit_log;
GO
IF OBJECT_ID('dbo.authentication', 'U') IS NOT NULL
    DROP TABLE dbo.authentication;
GO

-- Drop roles if they already exist (clean re-run)
IF DATABASE_PRINCIPAL_ID('super_admin')        IS NOT NULL DROP ROLE super_admin;
IF DATABASE_PRINCIPAL_ID('compliance_officer') IS NOT NULL DROP ROLE compliance_officer;
IF DATABASE_PRINCIPAL_ID('bank_employee')      IS NOT NULL DROP ROLE bank_employee;
GO

-- ============================================================
-- STEP 2 — TABLE: authentication
-- ============================================================
CREATE TABLE dbo.authentication (
    auth_id              INT             NOT NULL IDENTITY(1,1),
    employee_id          NVARCHAR(50)    NOT NULL,           -- e.g. EMP-SA-001
    username             NVARCHAR(100)   NOT NULL,           -- login username
    password_hash        NVARCHAR(256)   NOT NULL,           -- bcrypt hash ONLY
    salt                 NVARCHAR(64)    NOT NULL,           -- unique per-user salt
    role                 NVARCHAR(50)    NOT NULL DEFAULT 'bank_employee',
    is_active            BIT             NOT NULL DEFAULT 1,
    email                NVARCHAR(150)   NULL,
    phone                NVARCHAR(20)    NULL,
    mfa_enabled          BIT             NOT NULL DEFAULT 0,
    mfa_secret_hash      NVARCHAR(256)   NULL,               -- TOTP secret (hashed)

    -- Login tracking
    last_login_at        DATETIME2       NULL,
    last_login_ip        NVARCHAR(45)    NULL,
    failed_attempts      INT             NOT NULL DEFAULT 0,
    locked_until         DATETIME2       NULL,
    password_changed_at  DATETIME2       NULL,
    must_change_password BIT             NOT NULL DEFAULT 0,

    -- Timestamps
    created_at           DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    updated_at           DATETIME2       NULL,
    deactivated_at       DATETIME2       NULL,

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

CREATE INDEX idx_auth_username    ON dbo.authentication (username);
CREATE INDEX idx_auth_employee_id ON dbo.authentication (employee_id);
CREATE INDEX idx_auth_role        ON dbo.authentication (role);
CREATE INDEX idx_auth_is_active   ON dbo.authentication (is_active);
CREATE INDEX idx_auth_locked      ON dbo.authentication (locked_until)
    WHERE locked_until IS NOT NULL;
GO

-- ============================================================
-- STEP 2b — TABLE: authentication_audit_log
-- ============================================================
CREATE TABLE dbo.authentication_audit_log (
    log_id              BIGINT          NOT NULL IDENTITY(1,1),
    auth_id             INT             NULL,
    employee_id         NVARCHAR(50)    NULL,
    username_attempted  NVARCHAR(100)   NOT NULL,
    event_type          NVARCHAR(50)    NOT NULL,
    login_status        NVARCHAR(20)    NOT NULL,
    failure_reason      NVARCHAR(100)   NULL,
    session_token_hash  NVARCHAR(256)   NULL,
    session_expires_at  DATETIME2       NULL,
    ip_address          NVARCHAR(45)    NULL,
    user_agent          NVARCHAR(500)   NULL,
    device_fingerprint  NVARCHAR(256)   NULL,
    geo_country         NVARCHAR(2)     NULL,
    geo_city            NVARCHAR(100)   NULL,
    mfa_used            BIT             NOT NULL DEFAULT 0,
    mfa_outcome         NVARCHAR(20)    NULL,
    event_timestamp     DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    notes               NVARCHAR(MAX)   NULL,

    CONSTRAINT PK_auth_audit_log     PRIMARY KEY (log_id),
    CONSTRAINT FK_audit_log_auth     FOREIGN KEY (auth_id)
                                         REFERENCES dbo.authentication(auth_id)
                                         ON DELETE SET NULL,
    CONSTRAINT CHK_audit_event_type  CHECK (event_type IN (
                                         'login_success',
                                         'login_failure',
                                         'account_locked',
                                         'account_unlocked',
                                         'logout',
                                         'session_expired',
                                         'password_changed',
                                         'mfa_success',
                                         'mfa_failure',
                                         'username_not_found',
                                         'inactive_account',
                                         'forced_logout'
                                     )),
    CONSTRAINT CHK_audit_login_status CHECK (login_status IN ('success', 'failure')),
    CONSTRAINT CHK_audit_mfa_outcome  CHECK (mfa_outcome  IN ('passed', 'failed', 'skipped') OR mfa_outcome IS NULL)
);
GO

CREATE INDEX idx_aal_auth_id      ON dbo.authentication_audit_log (auth_id);
CREATE INDEX idx_aal_employee_id  ON dbo.authentication_audit_log (employee_id);
CREATE INDEX idx_aal_event_ts     ON dbo.authentication_audit_log (event_timestamp DESC);
CREATE INDEX idx_aal_login_status ON dbo.authentication_audit_log (login_status);
CREATE INDEX idx_aal_event_type   ON dbo.authentication_audit_log (event_type);
CREATE INDEX idx_aal_ip_address   ON dbo.authentication_audit_log (ip_address);
CREATE INDEX idx_aal_user_ts      ON dbo.authentication_audit_log (auth_id, event_timestamp DESC);
CREATE INDEX idx_aal_status_ts    ON dbo.authentication_audit_log (login_status, event_timestamp DESC);
GO

-- ============================================================
-- STEP 3 — CREATE DATABASE ROLES
-- After running, these appear in SSMS under:
--   bank_fraud_detection_db → Security → Roles → Database Roles
-- ============================================================

-- ── Role 1: super_admin ──────────────────────────────────────
-- Full system access: read + write + manage all objects
CREATE ROLE super_admin;
GO

-- ── Role 2: compliance_officer ───────────────────────────────
-- Read-only access to reports, alerts, audit data, transactions
CREATE ROLE compliance_officer;
GO

-- ── Role 3: bank_employee ────────────────────────────────────
-- Operational access: view user profiles, cards, transactions
CREATE ROLE bank_employee;
GO

-- ============================================================
-- STEP 4 — GRANT PERMISSIONS PER ROLE
-- ============================================================

-- ── super_admin: full control over all tables ────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.users                    TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.cards                    TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.merchants                TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.transactions             TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.alerts                   TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.transaction_audit_log    TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.user_known_locations     TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.user_devices             TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.authentication           TO super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.authentication_audit_log TO super_admin;
GO

-- ── compliance_officer: read-only on audit / report tables ───
GRANT SELECT ON dbo.users                    TO compliance_officer;
GRANT SELECT ON dbo.cards                    TO compliance_officer;
GRANT SELECT ON dbo.merchants                TO compliance_officer;
GRANT SELECT ON dbo.transactions             TO compliance_officer;
GRANT SELECT ON dbo.alerts                   TO compliance_officer;
GRANT SELECT ON dbo.transaction_audit_log    TO compliance_officer;
GRANT SELECT ON dbo.user_known_locations     TO compliance_officer;
GRANT SELECT ON dbo.user_devices             TO compliance_officer;
GRANT SELECT ON dbo.authentication_audit_log TO compliance_officer;
-- compliance_officer cannot read authentication (password hashes / salts)
DENY  SELECT ON dbo.authentication           TO compliance_officer;
GO

-- ── bank_employee: operational read + limited write ──────────
GRANT SELECT ON dbo.users                    TO bank_employee;
GRANT SELECT ON dbo.cards                    TO bank_employee;
GRANT SELECT ON dbo.merchants                TO bank_employee;
GRANT SELECT ON dbo.transactions             TO bank_employee;
GRANT SELECT ON dbo.alerts                   TO bank_employee;
GRANT SELECT ON dbo.user_known_locations     TO bank_employee;
GRANT SELECT ON dbo.user_devices             TO bank_employee;
-- Employees can INSERT and UPDATE alerts (investigation workflow)
GRANT INSERT, UPDATE ON dbo.alerts           TO bank_employee;
-- Employees can INSERT into audit log (for their actions)
GRANT INSERT ON dbo.transaction_audit_log    TO bank_employee;
-- Employees cannot read other employees' auth data
DENY  SELECT ON dbo.authentication           TO bank_employee;
DENY  SELECT ON dbo.authentication_audit_log TO bank_employee;
GO

-- ============================================================
-- STEP 5 — TRIGGERS
-- ============================================================

-- Trigger: auto-update authentication.updated_at
CREATE OR ALTER TRIGGER dbo.trg_auth_updated_at
ON dbo.authentication
AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    UPDATE dbo.authentication
    SET    updated_at = GETUTCDATE()
    FROM   dbo.authentication a
    INNER JOIN inserted i ON a.auth_id = i.auth_id;
END;
GO

-- Trigger: auto-lock after 5 consecutive failures; reset on success
CREATE OR ALTER TRIGGER dbo.trg_auto_lock_on_failures
ON dbo.authentication_audit_log
AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;

    -- Increment failure counter; lock after 5 failures
    UPDATE a
    SET
        a.failed_attempts = a.failed_attempts + 1,
        a.locked_until    = CASE
                                WHEN (a.failed_attempts + 1) >= 5
                                THEN DATEADD(MINUTE, 30, GETUTCDATE())
                                ELSE a.locked_until
                            END,
        a.updated_at      = GETUTCDATE()
    FROM dbo.authentication a
    INNER JOIN inserted i ON a.auth_id = i.auth_id
    WHERE i.login_status = 'failure'
      AND i.event_type   = 'login_failure';

    -- Reset counter and unlock on successful login
    UPDATE a
    SET
        a.failed_attempts = 0,
        a.locked_until    = NULL,
        a.last_login_at   = GETUTCDATE(),
        a.last_login_ip   = i.ip_address,
        a.updated_at      = GETUTCDATE()
    FROM dbo.authentication a
    INNER JOIN inserted i ON a.auth_id = i.auth_id
    WHERE i.login_status = 'success'
      AND i.event_type   = 'login_success';
END;
GO

-- ============================================================
-- STEP 6 — SAMPLE USER INSERT (10 employees, all 3 roles)
-- ⚠ password_hash values are PLACEHOLDERS — replace with
--   real bcrypt hashes from your backend before production.
-- ============================================================

-- Clean slate for re-run
DELETE FROM dbo.authentication
WHERE employee_id IN (
    'EMP-SA-001', 'EMP-SA-002',
    'EMP-CO-001', 'EMP-CO-002',
    'EMP-BE-001', 'EMP-BE-002', 'EMP-BE-003',
    'EMP-BE-004', 'EMP-BE-005', 'EMP-BE-006'
);
GO

-- ── SUPER ADMIN (2 users) ─────────────────────────────────────
INSERT INTO dbo.authentication
(employee_id, username, password_hash, salt, role, is_active,
 email, phone, mfa_enabled, mfa_secret_hash, must_change_password, password_changed_at)
VALUES
(
    'EMP-SA-001', 'admin.primary',
    -- DEV password: Admin@BFDS2026!
    '$2b$12$KIX8.pWqLm3nRvTzYoUeAOeM5HvJ2WqXpLm3nRvTzYoUeAOeM5H',
    'SALT$KIX8pWqLm3nRvTz',
    'super_admin', 1,
    'admin.primary@bfds.bank', '3185550001',
    1, 'TOTP$SECRET$SA001$BASE32HASH',
    0, DATEADD(DAY, -30, GETUTCDATE())
),
(
    'EMP-SA-002', 'admin.secondary',
    -- DEV password: Admin2@BFDS2026!
    '$2b$12$PQR9.xWqLm4nSvUzZpVfBPfN6IwK3XrYqMn4oSwUaZpVfBPfN6I',
    'SALT$PQR9xWqLm4nSvUz',
    'super_admin', 1,
    'admin.secondary@bfds.bank', '3185550002',
    1, 'TOTP$SECRET$SA002$BASE32HASH',
    0, DATEADD(DAY, -15, GETUTCDATE())
);
GO

-- ── COMPLIANCE OFFICER (2 users) ─────────────────────────────
INSERT INTO dbo.authentication
(employee_id, username, password_hash, salt, role, is_active,
 email, phone, mfa_enabled, mfa_secret_hash, must_change_password, password_changed_at)
VALUES
(
    'EMP-CO-001', 'compliance.officer1',
    -- DEV password: Comply@BFDS2026!
    '$2b$12$ABC1.mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh',
    'SALT$ABC1mNpQrStUvWx',
    'compliance_officer', 1,
    'compliance.officer1@bfds.bank', '3185550003',
    1, 'TOTP$SECRET$CO001$BASE32HASH',
    0, DATEADD(DAY, -45, GETUTCDATE())
),
(
    'EMP-CO-002', 'compliance.officer2',
    -- DEV password: Comply2@BFDS2026!
    '$2b$12$DEF2.nOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfG',
    'SALT$DEF2nOpQrStUvWx',
    'compliance_officer', 1,
    'compliance.officer2@bfds.bank', '3185550004',
    0, NULL,
    1, NULL   -- must_change_password on first login
);
GO

-- ── BANK EMPLOYEE (6 users) ───────────────────────────────────
INSERT INTO dbo.authentication
(employee_id, username, password_hash, salt, role, is_active,
 email, phone, mfa_enabled, mfa_secret_hash, must_change_password, password_changed_at)
VALUES
(
    'EMP-BE-001', 'emp.john.doe',
    -- DEV password: Emp001@BFDS2026!
    '$2b$12$GHI3.oRsUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjK',
    'SALT$GHI3oRsUvWxYzAb',
    'bank_employee', 1,
    'john.doe@bfds.bank', '3185550005',
    0, NULL,
    0, DATEADD(DAY, -60, GETUTCDATE())
),
(
    'EMP-BE-002', 'emp.alice.smith',
    -- DEV password: Emp002@BFDS2026!
    '$2b$12$JKL4.pStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKl',
    'SALT$JKL4pStUvWxYzAb',
    'bank_employee', 1,
    'alice.smith@bfds.bank', '3185550006',
    0, NULL,
    0, DATEADD(DAY, -20, GETUTCDATE())
),
(
    'EMP-BE-003', 'emp.david.nguyen',
    -- DEV password: TempPass@2026!
    '$2b$12$MNO5.qTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLm',
    'SALT$MNO5qTuVwXyZaBc',
    'bank_employee', 1,
    'david.nguyen@bfds.bank', '3185550007',
    0, NULL,
    1, NULL    -- must_change_password: YES (new hire)
),
(
    'EMP-BE-004', 'emp.sarah.connor',
    -- DEV password: Emp004@BFDS2026!
    '$2b$12$PQR6.rUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn',
    'SALT$PQR6rUvWxYzAbCd',
    'bank_employee', 1,
    'sarah.connor@bfds.bank', '3185550008',
    1, 'TOTP$SECRET$BE004$BASE32HASH',
    0, DATEADD(DAY, -10, GETUTCDATE())
),
(
    'EMP-BE-005', 'emp.michael.brown',
    -- DEV password: Emp005@BFDS2026!
    '$2b$12$STU7.sVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo',
    'SALT$STU7sVwXyZaBcDe',
    'bank_employee', 1,
    'michael.brown@bfds.bank', '3185550009',
    0, NULL,
    0, DATEADD(DAY, -90, GETUTCDATE())
),
(
    'EMP-BE-006', 'emp.olga.petrov',
    -- DEV password: Emp006@BFDS2026!
    '$2b$12$VWX8.tWxYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp',
    'SALT$VWX8tWxYzAbCdEf',
    'bank_employee', 1,   -- deactivated
    'olga.petrov@bfds.bank', '3185550010',
    0, NULL,
    0, DATEADD(DAY, -180, GETUTCDATE())
);
GO

-- ============================================================
-- STEP 7 — MAP SQL LOGINS → DATABASE ROLES
-- ─────────────────────────────────────────────────────────────
-- INSTRUCTIONS:
--   Replace each 'YourDomain\LoginName' or 'SqlLoginName' with
--   the actual SQL Server login that matches this employee.
--
--   Option A — Windows Authentication:
--       CREATE LOGIN [DOMAIN\john.doe] FROM WINDOWS;
--       USE bank_fraud_detection_db;
--       CREATE USER [DOMAIN\john.doe] FOR LOGIN [DOMAIN\john.doe];
--       ALTER ROLE bank_employee ADD MEMBER [DOMAIN\john.doe];
--
--   Option B — SQL Authentication:
--       CREATE LOGIN emp_john_doe WITH PASSWORD = 'StrongP@ss!';
--       USE bank_fraud_detection_db;
--       CREATE USER emp_john_doe FOR LOGIN emp_john_doe;
--       ALTER ROLE bank_employee ADD MEMBER emp_john_doe;
--
-- The block below creates SQL logins + users automatically.
-- Adjust login names / passwords before running in production.
-- ============================================================

-- ── super_admin logins ───────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_admin_primary')
    CREATE LOGIN bfds_admin_primary   WITH PASSWORD = 'Admin@BFDS2026!',
                                           CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_admin_secondary')
    CREATE LOGIN bfds_admin_secondary WITH PASSWORD = 'Admin2@BFDS2026!',
                                           CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
GO

-- ── compliance_officer logins ────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_compliance1')
    CREATE LOGIN bfds_compliance1 WITH PASSWORD = 'Comply@BFDS2026!',
                                       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_compliance2')
    CREATE LOGIN bfds_compliance2 WITH PASSWORD = 'Comply2@BFDS2026!',
                                       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
GO

-- ── bank_employee logins ─────────────────────────────────────
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_emp_john')
    CREATE LOGIN bfds_emp_john    WITH PASSWORD = 'Emp001@BFDS2026!',
                                       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_emp_alice')
    CREATE LOGIN bfds_emp_alice   WITH PASSWORD = 'Emp002@BFDS2026!',
                                       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_emp_david')
    CREATE LOGIN bfds_emp_david   WITH PASSWORD = 'TempPass@2026!',
                                       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_emp_sarah')
    CREATE LOGIN bfds_emp_sarah   WITH PASSWORD = 'Emp004@BFDS2026!',
                                       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'bfds_emp_michael')
    CREATE LOGIN bfds_emp_michael WITH PASSWORD = 'Emp005@BFDS2026!',
                                       CHECK_POLICY = ON, CHECK_EXPIRATION = ON;
-- NOTE: Olga Petrov is deactivated — no login created intentionally
GO

USE bank_fraud_detection_db;
GO

-- Create database users for each login
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_admin_primary')
    CREATE USER bfds_admin_primary   FOR LOGIN bfds_admin_primary;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_admin_secondary')
    CREATE USER bfds_admin_secondary FOR LOGIN bfds_admin_secondary;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_compliance1')
    CREATE USER bfds_compliance1     FOR LOGIN bfds_compliance1;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_compliance2')
    CREATE USER bfds_compliance2     FOR LOGIN bfds_compliance2;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_emp_john')
    CREATE USER bfds_emp_john        FOR LOGIN bfds_emp_john;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_emp_alice')
    CREATE USER bfds_emp_alice       FOR LOGIN bfds_emp_alice;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_emp_david')
    CREATE USER bfds_emp_david       FOR LOGIN bfds_emp_david;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_emp_sarah')
    CREATE USER bfds_emp_sarah       FOR LOGIN bfds_emp_sarah;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'bfds_emp_michael')
    CREATE USER bfds_emp_michael     FOR LOGIN bfds_emp_michael;
GO

-- Assign users to database roles
ALTER ROLE super_admin        ADD MEMBER bfds_admin_primary;
ALTER ROLE super_admin        ADD MEMBER bfds_admin_secondary;
ALTER ROLE compliance_officer ADD MEMBER bfds_compliance1;
ALTER ROLE compliance_officer ADD MEMBER bfds_compliance2;
ALTER ROLE bank_employee      ADD MEMBER bfds_emp_john;
ALTER ROLE bank_employee      ADD MEMBER bfds_emp_alice;
ALTER ROLE bank_employee      ADD MEMBER bfds_emp_david;
ALTER ROLE bank_employee      ADD MEMBER bfds_emp_sarah;
ALTER ROLE bank_employee      ADD MEMBER bfds_emp_michael;
GO

-- ============================================================
-- STEP 8 — POST-INSERT STATE UPDATES
-- ============================================================

-- EMP-BE-005 (Michael Brown): simulate locked account
UPDATE dbo.authentication
SET
    failed_attempts = 5,
    locked_until    = DATEADD(MINUTE, 30, GETUTCDATE()),
    updated_at      = GETUTCDATE()
WHERE employee_id = 'EMP-BE-005';

-- EMP-BE-006 (Olga Petrov): set deactivated_at for offboarded employee
UPDATE dbo.authentication
SET
    deactivated_at = DATEADD(DAY, -30, GETUTCDATE()),
    updated_at     = GETUTCDATE()
WHERE employee_id = 'EMP-BE-006';

-- All active users: set a realistic last_login_at and last_login_ip
UPDATE dbo.authentication
SET
    last_login_at = DATEADD(HOUR, -ABS(CHECKSUM(NEWID())) % 72, GETUTCDATE()),
    last_login_ip = CASE role
                        WHEN 'super_admin'        THEN '10.0.0.1'
                        WHEN 'compliance_officer' THEN '10.0.0.2'
                        ELSE '192.168.1.' + CAST(ABS(CHECKSUM(NEWID())) % 50 + 10 AS NVARCHAR(5))
                    END,
    updated_at    = GETUTCDATE()
-- Exclude: new hire (no login yet) and deactivated employee
WHERE employee_id NOT IN ('EMP-BE-003', 'EMP-BE-006');
GO

-- ============================================================
-- STEP 9 — SAMPLE AUDIT LOG EVENTS
-- ============================================================
INSERT INTO dbo.authentication_audit_log
(auth_id, employee_id, username_attempted,
 event_type, login_status, failure_reason,
 session_token_hash, session_expires_at,
 ip_address, user_agent,
 geo_country, geo_city, mfa_used, mfa_outcome, notes)
VALUES
-- ✅ Successful login — super_admin
(1, 'EMP-SA-001', 'admin.primary',
 'login_success', 'success', NULL,
 'HASH_JWT_SA001_session_abc123', DATEADD(HOUR, 8, GETUTCDATE()),
 '10.0.0.1', 'Mozilla/5.0 (Windows NT 10.0) Chrome/124',
 'US', 'New York', 1, 'passed',
 'Admin logged in. MFA passed.'),

-- ✅ Successful login — compliance_officer
(3, 'EMP-CO-001', 'compliance.officer1',
 'login_success', 'success', NULL,
 'HASH_JWT_CO001_session_def456', DATEADD(HOUR, 8, GETUTCDATE()),
 '10.0.0.2', 'Mozilla/5.0 (Macintosh) Safari/17',
 'US', 'Dallas', 1, 'passed',
 'Compliance officer logged in. MFA passed.'),

-- ✅ Successful login — bank_employee
(4, 'EMP-BE-001', 'emp.john.doe',
 'login_success', 'success', NULL,
 'HASH_JWT_BE001_session_ghi789', DATEADD(HOUR, 8, GETUTCDATE()),
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'MFA not enabled. Login from trusted internal IP.'),

-- ❌ Failed login — wrong password (attempt 1)
(4, 'EMP-BE-001', 'emp.john.doe',
 'login_failure', 'failure', 'invalid_password',
 NULL, NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'Failed attempt 1 of 5.'),

-- ❌ Failed login — wrong password (attempt 2)
(4, 'EMP-BE-001', 'emp.john.doe',
 'login_failure', 'failure', 'invalid_password',
 NULL, NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'Failed attempt 2 of 5.'),

-- ❌ Failed login — unknown username (possible brute-force)
(NULL, NULL, 'hacker.unknown',
 'username_not_found', 'failure', 'username_not_found',
 NULL, NULL,
 '185.220.101.99', 'python-requests/2.31.0',
 'RU', 'Moscow', 0, NULL,
 'Suspicious: unknown username from foreign IP.'),

-- ❌ Failed login — deactivated account
(4, 'EMP-BE-005', 'emp.michael.brown',
 'inactive_account', 'failure', 'account_deactivated',
 NULL, NULL,
 '10.0.0.99', 'Mozilla/5.0 (X11; Linux) Firefox/124',
 'US', 'Houston', 0, NULL,
 'Account is deactivated. Login rejected.'),

-- 🔒 Account locked after max failures
(4, 'EMP-BE-002', 'emp.alice.smith',
 'account_locked', 'failure', 'max_failed_attempts_reached',
 NULL, NULL,
 '203.0.113.55', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17)',
 'US', 'Chicago', 0, 'skipped',
 'Account locked for 30 minutes after 5 consecutive failures.'),

-- ❌ MFA failure after correct password
(1, 'EMP-SA-001', 'admin.primary',
 'mfa_failure', 'failure', 'invalid_mfa_code',
 NULL, NULL,
 '10.0.0.1', 'Mozilla/5.0 (Windows NT 10.0) Chrome/124',
 'US', 'New York', 1, 'failed',
 'Correct password. TOTP code expired or incorrect.'),

-- 🔓 Account manually unlocked by admin
(2, 'EMP-BE-002', 'emp.alice.smith',
 'account_unlocked', 'success', NULL,
 NULL, NULL,
 '10.0.0.1', 'AdminConsole/BFDS-v2.0',
 'US', 'New York', 0, 'skipped',
 'Account manually unlocked by EMP-SA-001.'),

-- 🔑 Password changed
(11, 'EMP-BE-001', 'emp.john.doe',
 'password_changed', 'success', NULL,
 NULL, NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'User initiated password change from profile settings.'),

-- 🚪 Explicit logout
(3, 'EMP-CO-001', 'compliance.officer1',
 'logout', 'success', NULL,
 'HASH_JWT_CO001_session_def456', NULL,
 '10.0.0.2', 'Mozilla/5.0 (Macintosh) Safari/17',
 'US', 'Dallas', 0, 'skipped',
 'User logged out. Session token invalidated.'),

-- ⏱ Session expired
(12, 'EMP-BE-001', 'emp.john.doe',
 'session_expired', 'failure', 'session_timeout',
 'HASH_JWT_BE001_session_ghi789', NULL,
 '192.168.1.10', 'Mozilla/5.0 (Windows NT 10.0) Edge/124',
 'US', 'Shreveport', 0, 'skipped',
 'Session token expired after 8-hour TTL. User must re-authenticate.'),

-- 🚫 Forced logout by admin
(13, 'EMP-BE-005', 'emp.michael.brown',
 'forced_logout', 'success', NULL,
 NULL, NULL,
 '10.0.0.1', 'AdminConsole/BFDS-v2.0',
 'US', 'New York', 0, 'skipped',
 'Admin forced session termination for EMP-BE-005.');
GO

-- ============================================================
-- STEP 10 — VERIFICATION QUERIES
-- ============================================================

-- V1. Confirm database roles exist
-- (Should show super_admin, compliance_officer, bank_employee)
SELECT
    dp.principal_id,
    dp.name          AS role_name,
    dp.type_desc     AS principal_type,
    dp.create_date,
    dp.modify_date
FROM   sys.database_principals dp
WHERE  dp.type = 'R'
  AND  dp.name IN ('super_admin', 'compliance_officer', 'bank_employee')
ORDER  BY dp.name;
GO

-- V2. Show role members (who belongs to each role)
SELECT
    r.name  AS role_name,
    m.name  AS member_login
FROM   sys.database_role_members rm
JOIN   sys.database_principals   r ON rm.role_principal_id   = r.principal_id
JOIN   sys.database_principals   m ON rm.member_principal_id = m.principal_id
WHERE  r.name IN ('super_admin', 'compliance_officer', 'bank_employee')
ORDER  BY r.name, m.name;
GO

-- V3. All authentication records with account health
SELECT
    auth_id,
    employee_id,
    username,
    role,
    email,
    phone,
    is_active,
    mfa_enabled,
    must_change_password,
    failed_attempts,
    locked_until,
    last_login_at,
    last_login_ip,
    password_changed_at,
    deactivated_at,
    created_at,
    CASE
        WHEN is_active    = 0                THEN '🔴 Deactivated'
        WHEN locked_until > GETUTCDATE()     THEN '🔒 Locked'
        WHEN must_change_password = 1        THEN '🔑 Must Change Password'
        WHEN failed_attempts BETWEEN 3 AND 4 THEN '⚠ At Risk'
        ELSE                                      '✅ Active'
    END AS account_health
FROM   dbo.authentication
ORDER  BY
    CASE role
        WHEN 'super_admin'        THEN 1
        WHEN 'compliance_officer' THEN 2
        WHEN 'bank_employee'      THEN 3
    END,
    auth_id;
GO

-- V4. Full audit log
SELECT
    log_id, employee_id, username_attempted,
    event_type, login_status, failure_reason,
    ip_address, geo_country, geo_city,
    mfa_used, mfa_outcome, event_timestamp, notes
FROM   dbo.authentication_audit_log
ORDER  BY event_timestamp DESC;
GO

-- V5. Failed login summary by employee
SELECT
    employee_id,
    COUNT(*)                 AS total_failures,
    MAX(event_timestamp)     AS last_failure,
    STRING_AGG(ip_address, ', ') AS ips_used
FROM   dbo.authentication_audit_log
WHERE  login_status = 'failure'
GROUP  BY employee_id
ORDER  BY total_failures DESC;
GO

-- ============================================================
-- QUICK REFERENCE — Dev Login Credentials
-- ⚠ Remove / replace password_hash before production!
-- ============================================================
/*
╔══════════════════╦══════════════════════╦════════════════════════╦════════════════════════╗
║ Role             ║ Username             ║ Password (DEV ONLY)    ║ Account State          ║
╠══════════════════╬══════════════════════╬════════════════════════╬════════════════════════╣
║ super_admin      ║ admin.primary        ║ Admin@BFDS2026!        ║ ✅ Active + MFA        ║
║ super_admin      ║ admin.secondary      ║ Admin2@BFDS2026!       ║ ✅ Active + MFA        ║
╠══════════════════╬══════════════════════╬════════════════════════╬════════════════════════╣
║ compliance_ofcr  ║ compliance.officer1  ║ Comply@BFDS2026!       ║ ✅ Active + MFA        ║
║ compliance_ofcr  ║ compliance.officer2  ║ Comply2@BFDS2026!      ║ 🔑 Must Change Pass    ║
╠══════════════════╬══════════════════════╬════════════════════════╬════════════════════════╣
║ bank_employee    ║ emp.john.doe         ║ Emp001@BFDS2026!       ║ ✅ Active              ║
║ bank_employee    ║ emp.alice.smith      ║ Emp002@BFDS2026!       ║ ✅ Active              ║
║ bank_employee    ║ emp.david.nguyen     ║ TempPass@2026!         ║ 🔑 Must Change Pass    ║
║ bank_employee    ║ emp.sarah.connor     ║ Emp004@BFDS2026!       ║ ✅ Active + MFA        ║
║ bank_employee    ║ emp.michael.brown    ║ Emp005@BFDS2026!       ║ 🔒 Locked (5 fails)    ║
║ bank_employee    ║ emp.olga.petrov      ║ Emp006@BFDS2026!       ║ 🔴 Deactivated (no DB login) ║
╚══════════════════╩══════════════════════╩════════════════════════╩════════════════════════╝

BACKEND INTEGRATION NOTES:
  1. Hash passwords with bcrypt (cost factor 12+) before storing.
  2. Generate a cryptographically random salt per user (16+ bytes).
  3. For MFA users, generate a real TOTP secret (Base32, 20 bytes).
  4. Login endpoint must:
       a. SELECT by username
       b. Verify bcrypt(input, stored_hash)
       c. Check is_active = 1
       d. Check locked_until IS NULL OR locked_until < GETUTCDATE()
       e. Check must_change_password — redirect to reset if 1
       f. If mfa_enabled = 1 — prompt TOTP before granting session
       g. On success — INSERT login_success into authentication_audit_log
       h. On failure — INSERT login_failure + increment failed_attempts
                       + lock account if failed_attempts >= 5

WHERE TO SEE ROLES IN SSMS:
  Object Explorer → bank_fraud_detection_db
    → Security
      → Roles
        → Database Roles
          → super_admin
          → compliance_officer
          → bank_employee
*/

-- ============================================================
-- END OF SCRIPT: Authentication Roles + Full Setup v3.0
-- ============================================================
