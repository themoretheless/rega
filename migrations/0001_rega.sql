-- Schema used by rega::PgAccountStore. Safe to run repeatedly.
CREATE TABLE IF NOT EXISTS rega_users (
    id             BIGSERIAL PRIMARY KEY,
    email          TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    name           TEXT,
    avatar_url     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lookup for auto-linking by verified email (not unique: LinkPolicy::Never
-- may create several users with the same address).
CREATE INDEX IF NOT EXISTS rega_users_verified_email
    ON rega_users (lower(email)) WHERE email_verified;

CREATE TABLE IF NOT EXISTS rega_logins (
    provider   TEXT   NOT NULL,
    subject    TEXT   NOT NULL,
    user_id    BIGINT NOT NULL REFERENCES rega_users (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS rega_logins_user ON rega_logins (user_id);
