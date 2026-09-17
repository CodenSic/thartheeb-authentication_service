ALTER TABLE user_accounts ALTER COLUMN mfa_secret_encrypted DROP NOT NULL;

UPDATE user_accounts
SET mfa_required = FALSE,
    mfa_secret_encrypted = NULL
WHERE id IN (
    SELECT user_id FROM tenant_memberships
    WHERE role IN ('VENDOR_ONBOARDING_ADMIN', 'VENDOR_ADMIN')
);

CREATE TABLE vendor_activation_tokens (
    id UUID PRIMARY KEY,
    token_id VARCHAR(64) NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES user_accounts(id),
    vendor_id UUID NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    row_version BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX idx_vendor_activation_user
    ON vendor_activation_tokens(user_id, consumed_at, expires_at);
