-- TLS certificates (M13). Keys, the ACME account key and DNS credentials are
-- encrypted with the Core's secret key (ADR-0019, ADR-0026).

CREATE TABLE tls_settings (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    email            TEXT    NOT NULL DEFAULT '',
    ca               TEXT    NOT NULL DEFAULT 'production' CHECK (ca IN ('production', 'staging')),
    agreed_ms        INTEGER NOT NULL DEFAULT 0,           -- Let's Encrypt subscriber agreement accepted
    agreed_by        TEXT    NOT NULL DEFAULT '',
    dns_provider     TEXT    NOT NULL DEFAULT '' CHECK (dns_provider IN ('', 'cloudflare')),
    dns_credentials  BLOB,                                 -- encrypted
    account_key      BLOB,                                 -- encrypted PKCS#8 (ECDSA P-256)
    account_url      TEXT    NOT NULL DEFAULT '',
    account_dir      TEXT    NOT NULL DEFAULT ''           -- directory the account belongs to
) STRICT;
INSERT INTO tls_settings (id) VALUES (1);

CREATE TABLE tls_certificates (
    id            INTEGER PRIMARY KEY,
    source        TEXT    NOT NULL CHECK (source IN ('upload', 'dns')),
    names         TEXT    NOT NULL,                        -- JSON array
    issuer        TEXT    NOT NULL,
    not_before_ms INTEGER NOT NULL,
    not_after_ms  INTEGER NOT NULL,
    sha256        TEXT    NOT NULL,
    chain_pem     TEXT    NOT NULL,
    key           BLOB    NOT NULL,                        -- encrypted PEM
    created_by    TEXT    NOT NULL,
    created_ms    INTEGER NOT NULL
) STRICT;

-- Hosts without a row use the internal CA.
CREATE TABLE tls_hosts (
    host           TEXT    PRIMARY KEY,
    mode           TEXT    NOT NULL CHECK (mode IN ('internal', 'acme', 'dns', 'custom')),
    certificate_id INTEGER REFERENCES tls_certificates (id),
    error          TEXT    NOT NULL DEFAULT '',            -- last DNS-01 failure
    error_ms       INTEGER NOT NULL DEFAULT 0,
    updated_ms     INTEGER NOT NULL
) STRICT;
