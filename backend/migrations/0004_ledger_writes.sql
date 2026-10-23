-- 0004_ledger_writes
-- Journal of ledger submissions (services/anchoring.py). A record whose anchor came back
-- PENDING/FAILED (ledger outage, open circuit breaker) keeps the exact contract call here, so
-- scripts/scheduled_tasks.py and POST /api/v1/blockchain/anchors/retry can replay it in order.
-- The fabric_* columns persist each anchored write's Hyperledger Fabric mirror status, which
-- previously lived only in a 25-entry in-memory list.
--
-- Forward-only (ADR-014). Records anchored before this migration have no journal row: their
-- original arguments were never stored, so they cannot be replayed automatically.

CREATE TABLE IF NOT EXISTS ledger_writes (
    id VARCHAR(36) PRIMARY KEY,
    contract VARCHAR(40) NOT NULL,
    function VARCHAR(60) NOT NULL,
    args JSON NOT NULL,
    submitter_msp VARCHAR(40) NOT NULL,
    chain_key VARCHAR(200) NOT NULL,
    requires JSON,
    entity_type VARCHAR(40),
    entity_id VARCHAR(36),
    anchor_status VARCHAR(16) NOT NULL,
    tx_id VARCHAR(64),
    block_number INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    anchored_at TIMESTAMP WITH TIME ZONE,
    fabric_key VARCHAR(160),
    fabric_status VARCHAR(16),
    fabric_tx_id VARCHAR(128),
    fabric_error TEXT,
    fabric_attempts INTEGER NOT NULL DEFAULT 0,
    mirrored_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_ledger_writes_status_created ON ledger_writes (anchor_status, created_at);

CREATE INDEX IF NOT EXISTS ix_ledger_writes_chain_key ON ledger_writes (chain_key);

CREATE INDEX IF NOT EXISTS ix_ledger_writes_entity_id ON ledger_writes (entity_id);

CREATE INDEX IF NOT EXISTS ix_ledger_writes_fabric_status ON ledger_writes (fabric_status);

CREATE INDEX IF NOT EXISTS ix_ledger_writes_created_at ON ledger_writes (created_at);
