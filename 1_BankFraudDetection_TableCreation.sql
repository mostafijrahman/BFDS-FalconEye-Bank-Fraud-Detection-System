-- ============================================================
-- BANK FRAUD DETECTION SYSTEM (BFDS) - FalconEye
-- Script 1: Database & Table Creation
-- Version: 2.0  |  Date: April 2026
-- ============================================================

CREATE DATABASE bank_fraud_detection_db;
GO

USE bank_fraud_detection_db;
GO

-- ============================================================
-- TABLE 1: users
-- ============================================================
CREATE TABLE users (
    user_id                 INT             NOT NULL IDENTITY(1,1),
    first_name              NVARCHAR(100)   NULL,
    last_name               NVARCHAR(100)   NULL,
    email                   NVARCHAR(150)   NOT NULL,
    phone                   NVARCHAR(20)    NULL,
    account_created_at      DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    account_status          NVARCHAR(20)    NOT NULL DEFAULT 'active',
    risk_profile            NVARCHAR(20)    NOT NULL DEFAULT 'low',
    country_iso_code        NVARCHAR(2)     NULL,
    registration_ip_address NVARCHAR(45)    NULL,

    CONSTRAINT PK_users             PRIMARY KEY (user_id),
    CONSTRAINT UK_users_email       UNIQUE (email),
    CONSTRAINT CHK_users_status     CHECK (account_status IN ('active', 'suspended', 'closed')),
    CONSTRAINT CHK_users_risk       CHECK (risk_profile   IN ('low', 'medium', 'high'))
);
GO
CREATE INDEX idx_users_email          ON users (email);
CREATE INDEX idx_users_account_status ON users (account_status);
GO

-- ============================================================
-- TABLE 2: cards
-- ============================================================
CREATE TABLE cards (
    card_id            INT             NOT NULL IDENTITY(1,1),
    user_id            INT             NOT NULL,
    card_type          NVARCHAR(20)    NOT NULL,
    card_number_hash   NVARCHAR(256)   NOT NULL,
    last_four_digits   NVARCHAR(4)     NULL,
    expiry_date        DATE            NULL,
    card_status        NVARCHAR(20)    NOT NULL DEFAULT 'active',
    issued_date        DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    reported_lost_at   DATETIME2       NULL,
    daily_limit        DECIMAL(10,2)   NULL,
    monthly_limit      DECIMAL(10,2)   NULL,

    CONSTRAINT PK_cards                  PRIMARY KEY (card_id),
    CONSTRAINT UK_cards_hash             UNIQUE (card_number_hash),
    CONSTRAINT FK_cards_users            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT CHK_cards_type            CHECK (card_type   IN ('debit', 'credit', 'prepaid')),
    CONSTRAINT CHK_cards_status          CHECK (card_status IN ('active', 'blocked', 'expired'))
);
GO
CREATE INDEX idx_cards_user_id     ON cards (user_id);
CREATE INDEX idx_cards_card_status ON cards (card_status);
GO

-- ============================================================
-- TABLE 3: merchants
-- ============================================================
CREATE TABLE merchants (
    merchant_id            INT             NOT NULL IDENTITY(1,1),
    merchant_name          NVARCHAR(255)   NOT NULL,
    merchant_category_code NVARCHAR(10)    NULL,
    mcc_description        NVARCHAR(255)   NULL,
    country_iso_code       NVARCHAR(2)     NULL,
    risk_score             DECIMAL(3,2)    NOT NULL DEFAULT 0.00,
    is_blacklisted         BIT             NOT NULL DEFAULT 0,
    fraud_report_count     INT             NOT NULL DEFAULT 0,
    created_at             DATETIME2       NOT NULL DEFAULT GETUTCDATE(),

    CONSTRAINT PK_merchants PRIMARY KEY (merchant_id),
    CONSTRAINT CHK_merchants_risk CHECK (risk_score BETWEEN 0.00 AND 1.00)
);
GO
CREATE INDEX idx_merchants_mcc         ON merchants (merchant_category_code);
CREATE INDEX idx_merchants_blacklisted ON merchants (is_blacklisted);
GO

-- ============================================================
-- TABLE 4: transactions
-- ============================================================
CREATE TABLE transactions (
    transaction_id        BIGINT          NOT NULL IDENTITY(1,1),
    card_id               INT             NOT NULL,
    merchant_id           INT             NOT NULL,
    user_id               INT             NOT NULL,
    transaction_amount    DECIMAL(15,2)   NOT NULL,
    currency_code         NVARCHAR(3)     NOT NULL DEFAULT 'USD',
    transaction_timestamp DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    merchant_country      NVARCHAR(2)     NULL,
    customer_country      NVARCHAR(2)     NULL,
    merchant_mcc          NVARCHAR(10)    NULL,
    transaction_status    NVARCHAR(20)    NOT NULL DEFAULT 'completed',
    is_online             BIT             NULL,
    device_id             NVARCHAR(255)   NULL,
    ip_address            NVARCHAR(45)    NULL,
    latitude              DECIMAL(10,8)   NULL,
    longitude             DECIMAL(11,8)   NULL,

    CONSTRAINT PK_transactions            PRIMARY KEY (transaction_id),
    CONSTRAINT FK_transactions_cards      FOREIGN KEY (card_id)     REFERENCES cards(card_id),
    CONSTRAINT FK_transactions_merchants  FOREIGN KEY (merchant_id) REFERENCES merchants(merchant_id),
    CONSTRAINT FK_transactions_users      FOREIGN KEY (user_id)     REFERENCES users(user_id),
    CONSTRAINT CHK_transactions_status    CHECK (transaction_status IN ('completed', 'pending', 'declined', 'reversed')),
    CONSTRAINT CHK_transactions_amount    CHECK (transaction_amount > 0)
);
GO
CREATE INDEX idx_txn_user_timestamp ON transactions (user_id, transaction_timestamp);
CREATE INDEX idx_txn_card_timestamp ON transactions (card_id, transaction_timestamp);
CREATE INDEX idx_txn_merchant       ON transactions (merchant_id);
CREATE INDEX idx_txn_timestamp      ON transactions (transaction_timestamp);
CREATE INDEX idx_txn_ip             ON transactions (ip_address);
GO

-- ============================================================
-- TABLE 5: alerts
-- ============================================================
CREATE TABLE alerts (
    alert_id             BIGINT          NOT NULL IDENTITY(1,1),
    transaction_id       BIGINT          NULL,
    card_id              INT             NOT NULL,
    user_id              INT             NOT NULL,
    alert_type           NVARCHAR(100)   NOT NULL,
    risk_score           DECIMAL(4,2)    NULL,
    alert_message        NVARCHAR(MAX)   NULL,
    alert_status         NVARCHAR(30)    NOT NULL DEFAULT 'open',
    investigation_notes  NVARCHAR(MAX)   NULL,
    created_at           DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    resolved_at          DATETIME2       NULL,

    CONSTRAINT PK_alerts               PRIMARY KEY (alert_id),
    CONSTRAINT FK_alerts_transactions  FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id),
    CONSTRAINT FK_alerts_cards         FOREIGN KEY (card_id)        REFERENCES cards(card_id),
    CONSTRAINT FK_alerts_users         FOREIGN KEY (user_id)        REFERENCES users(user_id),
    CONSTRAINT CHK_alerts_status       CHECK (alert_status IN ('open', 'acknowledged', 'false_positive', 'confirmed_fraud')),
    CONSTRAINT CHK_alerts_type         CHECK (alert_type   IN ('impossible_travel', 'structuring_aml', 'blacklisted_merchant',
                                                                'high_risk_mcc', 'velocity_breach', 'unknown_device', 'other'))
);
GO
CREATE INDEX idx_alerts_user_created ON alerts (user_id, created_at);
CREATE INDEX idx_alerts_status       ON alerts (alert_status);
CREATE INDEX idx_alerts_type         ON alerts (alert_type);
CREATE INDEX idx_alerts_created_at   ON alerts (created_at);
GO

-- ============================================================
-- TABLE 6: transaction_audit_log
-- ============================================================
CREATE TABLE transaction_audit_log (
    audit_id         BIGINT          NOT NULL IDENTITY(1,1),
    transaction_id   BIGINT          NOT NULL,
    previous_status  NVARCHAR(50)    NULL,
    new_status       NVARCHAR(50)    NULL,
    changed_by       NVARCHAR(255)   NULL,
    changed_at       DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    change_reason    NVARCHAR(MAX)   NULL,

    CONSTRAINT PK_transaction_audit_log    PRIMARY KEY (audit_id),
    CONSTRAINT FK_audit_log_transactions   FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
);
GO
CREATE INDEX idx_audit_txn_id    ON transaction_audit_log (transaction_id);
CREATE INDEX idx_audit_changed   ON transaction_audit_log (changed_at);
GO

-- ============================================================
-- TABLE 7: user_known_locations
-- ============================================================
CREATE TABLE user_known_locations (
    location_id          INT             NOT NULL IDENTITY(1,1),
    user_id              INT             NOT NULL,
    city                 NVARCHAR(100)   NULL,
    country_iso_code     NVARCHAR(2)     NULL,
    latitude             DECIMAL(10,8)   NULL,
    longitude            DECIMAL(11,8)   NULL,
    last_transaction_at  DATETIME2       NULL,
    frequency_count      INT             NOT NULL DEFAULT 1,

    CONSTRAINT PK_user_known_locations         PRIMARY KEY (location_id),
    CONSTRAINT UK_user_known_locations_loc     UNIQUE (user_id, city, country_iso_code),
    CONSTRAINT FK_known_locations_users        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
GO
CREATE INDEX idx_known_locations_user ON user_known_locations (user_id);
GO

-- ============================================================
-- TABLE 8: user_devices
-- ============================================================
CREATE TABLE user_devices (
    device_id    NVARCHAR(255)   NOT NULL,
    user_id      INT             NOT NULL,
    device_type  NVARCHAR(50)    NULL,
    device_name  NVARCHAR(255)   NULL,
    os_type      NVARCHAR(50)    NULL,
    first_seen   DATETIME2       NOT NULL DEFAULT GETUTCDATE(),
    last_seen    DATETIME2       NULL,
    is_trusted   BIT             NOT NULL DEFAULT 0,

    CONSTRAINT PK_user_devices       PRIMARY KEY (device_id),
    CONSTRAINT FK_user_devices_users FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT CHK_device_type       CHECK (device_type IN ('mobile', 'laptop', 'tablet', 'desktop', 'unknown'))
);
GO
CREATE INDEX idx_user_devices_user_id ON user_devices (user_id);
GO

-- ============================================================
-- TABLE 9: authentication  (NEW - Bank Employee Login)
-- ============================================================
CREATE TABLE authentication (
    auth_id          INT             NOT NULL IDENTITY(1,1),
    employee_id      NVARCHAR(50)    NOT NULL,
    username         NVARCHAR(100)   NOT NULL,
    password_hash    NVARCHAR(256)   NOT NULL,   -- Store bcrypt/SHA-256 hash only
    role             NVARCHAR(50)    NOT NULL DEFAULT 'bank_employee',
    is_active        BIT             NOT NULL DEFAULT 1,
    last_login_at    DATETIME2       NULL,
    failed_attempts  INT             NOT NULL DEFAULT 0,
    locked_until     DATETIME2       NULL,
    created_at       DATETIME2       NOT NULL DEFAULT GETUTCDATE(),

    CONSTRAINT PK_authentication       PRIMARY KEY (auth_id),
    CONSTRAINT UK_auth_username        UNIQUE (username),
    CONSTRAINT UK_auth_employee_id     UNIQUE (employee_id),
    CONSTRAINT CHK_auth_role           CHECK (role IN ('super_admin', 'compliance_officer', 'bank_employee'))
);
GO
CREATE INDEX idx_auth_username    ON authentication (username);
CREATE INDEX idx_auth_role        ON authentication (role);
CREATE INDEX idx_auth_is_active   ON authentication (is_active);
GO

-- ============================================================
-- ROW-LEVEL SECURITY (RLS) SETUP
-- ============================================================

-- Security predicate function
CREATE FUNCTION dbo.fn_rls_security_predicate
    (@role NVARCHAR(50))
RETURNS TABLE
WITH SCHEMABINDING
AS
    RETURN SELECT 1 AS fn_result
    WHERE
        -- Super Admin sees everything
        @role = 'super_admin'
        OR
        -- Compliance Officer sees reports / audit data
        @role = 'compliance_officer'
        OR
        -- Bank Employee sees operational data
        @role = 'bank_employee';
GO

-- Security policy on alerts (Compliance Officer + above)
CREATE SECURITY POLICY AlertsAccessPolicy
ADD FILTER PREDICATE dbo.fn_rls_security_predicate(SYSTEM_USER) ON dbo.alerts
WITH (STATE = OFF);   -- Set to ON after role mapping is configured
GO

-- ============================================================
-- END OF SCRIPT 1: TABLE CREATION
-- ============================================================
