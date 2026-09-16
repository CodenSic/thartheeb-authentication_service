CREATE TABLE user_accounts (
    id UUID PRIMARY KEY,
    identifier_normalized VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(24) NOT NULL,
    mfa_required BOOLEAN NOT NULL,
    mfa_secret_encrypted VARCHAR(512) NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    security_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    row_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE tenant_memberships (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE REFERENCES user_accounts(id),
    vendor_id UUID,
    role VARCHAR(64) NOT NULL,
    status VARCHAR(24) NOT NULL
);

CREATE INDEX idx_memberships_vendor ON tenant_memberships(vendor_id, status);

CREATE TABLE mfa_challenges (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(id),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    consumed_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(id),
    vendor_id UUID,
    mfa_level INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_auth_sessions_user_active ON auth_sessions(user_id, revoked_at);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    session_id UUID NOT NULL REFERENCES auth_sessions(id),
    family_id UUID NOT NULL,
    rotation_sequence BIGINT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    row_version BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_session ON refresh_tokens(session_id);

CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(id),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    row_version BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE password_history (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_accounts(id),
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_password_history_user ON password_history(user_id, created_at);

CREATE TABLE revoked_access_tokens (
    jti VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY,
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    published_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_auth_outbox_unpublished ON outbox_events(published_at, occurred_at);
