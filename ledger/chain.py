"""The ledger: transaction lifecycle, ordering, blocks, world state, verification.

Lifecycle: propose -> simulate -> endorse (policy) -> sign -> order -> block -> commit.
DEMO/SIMULATION: single-node ordering. Everything cryptographic is real.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .block import Block, Transaction, GENESIS_PREV_HASH, canonical, merkle_proof, now_iso, sha256_hex
from .contracts import ContractError, ENDORSEMENT_POLICIES, SUBMIT_RIGHTS, resolve
from .identity import MSPRegistry, OrgIdentity


class LedgerError(Exception):
    """Ledger-level failure (ordering, persistence, unknown identity)."""


class EndorsementError(LedgerError):
    """The endorsement policy for the function was not satisfied."""


DEFAULT_ORGS = {
    "BiotechMSP": "Seed and Biotechnology Company",
    "FarmMSP": "Farm Cooperative",
    "SupplyMSP": "Processor and Distributor",
    "RegulatorMSP": "Regulator and Certification Body",
}


class Ledger:
    def __init__(self, data_dir: str | Path = "./ledger_data", channel: str = "agri-channel") -> None:
        self.dir = Path(data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.blocks_path = self.dir / "blocks.jsonl"
        self.channel = channel
        self.msp = MSPRegistry(self.dir)
        self._lock = threading.RLock()
        self.blocks: list[Block] = []
        self.state: dict[str, Any] = {}
        self._tx_index: dict[str, tuple[int, int]] = {}     # tx_id -> (block number, position)
        for msp_id, name in DEFAULT_ORGS.items():
            self.msp.ensure(msp_id, name)
        self._load()

    # -- persistence -----------------------------------------------------
    def _load(self) -> None:
        if not self.blocks_path.is_file():
            self._create_genesis()
            return
        for line in self.blocks_path.read_text().splitlines():
            if line.strip():
                self.blocks.append(Block.from_dict(json.loads(line)))
        self._rebuild_state()
        if not self.blocks:
            self._create_genesis()

    def _append_block_file(self, block: Block) -> None:
        with self.blocks_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(block.to_dict()) + "\n")

    def _create_genesis(self) -> None:
        tx = Transaction(
            contract="system", function="Genesis",
            args={"channel": self.channel,
                  "members": {m: self.msp.public_key(m) for m in DEFAULT_ORGS}},
            submitter_msp="RegulatorMSP", channel=self.channel, timestamp=now_iso(),
        )
        tx.tx_id = tx.compute_tx_id()
        identity = self.msp.get("RegulatorMSP")
        if identity:
            tx.signature = identity.sign(tx.payload_for_signing())
            tx.endorsements = [{"msp_id": "RegulatorMSP", "signature": tx.signature}]
        block = Block(number=0, previous_hash=GENESIS_PREV_HASH, timestamp=now_iso(),
                      transactions=[tx]).seal()
        self.blocks.append(block)
        self._tx_index[tx.tx_id] = (0, 0)
        self._append_block_file(block)

    def _rebuild_state(self) -> None:
        self.state = {}
        self._tx_index = {}
        for block in self.blocks:
            for position, tx in enumerate(block.transactions):
                self._tx_index[tx.tx_id] = (block.number, position)
                self.state.update(tx.write_set)

    # -- properties ------------------------------------------------------
    @property
    def height(self) -> int:
        return len(self.blocks)

    @property
    def head(self) -> Block:
        return self.blocks[-1]

    # -- submission ------------------------------------------------------
    def submit(self, contract: str, function: str, args: dict[str, Any],
               submitter_msp: str) -> dict[str, Any]:
        """Full transaction lifecycle. Raises ContractError / EndorsementError / LedgerError."""
        with self._lock:
            key = f"{contract}.{function}"
            identity = self.msp.get(submitter_msp)
            if identity is None:
                raise LedgerError(f"Unknown submitting organisation {submitter_msp}")
            allowed = SUBMIT_RIGHTS.get(key)
            if allowed is not None and submitter_msp not in allowed:
                raise ContractError(
                    f"{submitter_msp} is not authorised to submit {key}; allowed: {sorted(allowed)}")

            # 1. simulate against the current world state
            handler = resolve(contract, function)
            read_set, write_set = handler(self.state, args, submitter_msp)

            tx = Transaction(contract=contract, function=function, args=args,
                             submitter_msp=submitter_msp, channel=self.channel,
                             timestamp=now_iso(), read_set=list(read_set), write_set=write_set)
            tx.tx_id = tx.compute_tx_id()
            if tx.tx_id in self._tx_index:
                raise ContractError("Duplicate transaction (identical content already committed)")

            payload = tx.payload_for_signing()

            # 2. endorse per policy
            tx.endorsements = self._collect_endorsements(key, payload, submitter_msp)

            # 3. submitter signature
            tx.signature = identity.sign(payload)

            # 4. order and cut a block (single-node ordering — DEMO)
            block = Block(number=self.height, previous_hash=self.head.block_hash,
                          timestamp=now_iso(), transactions=[tx]).seal()

            # 5. commit
            self.blocks.append(block)
            self._tx_index[tx.tx_id] = (block.number, 0)
            self.state.update(write_set)
            self._append_block_file(block)

            return {"tx_id": tx.tx_id, "block_number": block.number,
                    "block_hash": block.block_hash, "timestamp": tx.timestamp,
                    "endorsers": [e["msp_id"] for e in tx.endorsements],
                    "network": "single-node-demo"}

    def _collect_endorsements(self, key: str, payload: str, submitter: str) -> list[dict[str, str]]:
        policy = ENDORSEMENT_POLICIES.get(key, {"rule": "OR", "orgs": [submitter]})
        required = policy["orgs"]
        endorsements: list[dict[str, str]] = []
        if policy["rule"] == "AND":
            for msp_id in required:
                identity = self.msp.get(msp_id)
                if identity is None:
                    raise EndorsementError(f"Endorsing organisation {msp_id} is unavailable")
                endorsements.append({"msp_id": msp_id, "signature": identity.sign(payload)})
        else:
            candidates = [submitter] + [o for o in required if o != submitter]
            for msp_id in candidates:
                if msp_id in required:
                    identity = self.msp.get(msp_id)
                    if identity is not None:
                        endorsements.append({"msp_id": msp_id, "signature": identity.sign(payload)})
                        break
            if not endorsements:
                raise EndorsementError(
                    f"No endorsing organisation available for {key}; policy requires one of {required}")
        return endorsements

    # -- queries ---------------------------------------------------------
    def query(self, state_key: str) -> Any:
        return self.state.get(state_key)

    def query_prefix(self, prefix: str) -> dict[str, Any]:
        return {k: v for k, v in self.state.items() if k.startswith(prefix)}

    def get_transaction(self, tx_id: str) -> dict[str, Any] | None:
        location = self._tx_index.get(tx_id)
        if location is None:
            return None
        block_number, position = location
        block = self.blocks[block_number]
        return {"transaction": block.transactions[position].to_dict(),
                "block_number": block_number, "block_hash": block.block_hash}

    def get_block(self, number: int) -> dict[str, Any] | None:
        if 0 <= number < len(self.blocks):
            return self.blocks[number].to_dict()
        return None

    def recent_blocks(self, limit: int = 20) -> list[dict[str, Any]]:
        return [b.to_dict() for b in self.blocks[-limit:][::-1]]

    def proof(self, tx_id: str) -> dict[str, Any] | None:
        location = self._tx_index.get(tx_id)
        if location is None:
            return None
        block_number, position = location
        block = self.blocks[block_number]
        leaves = [t.tx_id for t in block.transactions]
        return {"tx_id": tx_id, "block_number": block_number,
                "merkle_root": block.merkle_root, "proof": merkle_proof(leaves, position)}

    # -- verification ----------------------------------------------------
    def verify_chain(self) -> dict[str, Any]:
        """Replay every block: parent hash, Merkle root, block hash, every signature."""
        problems: list[dict[str, Any]] = []
        previous = GENESIS_PREV_HASH
        checked_signatures = 0
        for block in self.blocks:
            if block.previous_hash != previous:
                problems.append({"block": block.number, "issue": "previous_hash_mismatch"})
            if block.compute_merkle_root() != block.merkle_root:
                problems.append({"block": block.number, "issue": "merkle_root_mismatch"})
            if block.compute_hash() != block.block_hash:
                problems.append({"block": block.number, "issue": "block_hash_mismatch"})
            for tx in block.transactions:
                if tx.compute_tx_id() != tx.tx_id:
                    problems.append({"block": block.number, "tx": tx.tx_id, "issue": "tx_id_mismatch"})
                payload = tx.payload_for_signing()
                for endorsement in tx.endorsements:
                    public_pem = self.msp.public_key(endorsement["msp_id"])
                    checked_signatures += 1
                    if not public_pem or not OrgIdentity.verify(public_pem, payload,
                                                                endorsement["signature"]):
                        problems.append({"block": block.number, "tx": tx.tx_id,
                                         "issue": f"invalid_endorsement:{endorsement['msp_id']}"})
                if tx.signature:
                    public_pem = self.msp.public_key(tx.submitter_msp)
                    checked_signatures += 1
                    if not public_pem or not OrgIdentity.verify(public_pem, payload, tx.signature):
                        problems.append({"block": block.number, "tx": tx.tx_id,
                                         "issue": "invalid_submitter_signature"})
            previous = block.block_hash
        return {
            "valid": not problems,
            "height": self.height,
            "transactions": len(self._tx_index),
            "signatures_verified": checked_signatures,
            "first_divergence": problems[0] if problems else None,
            "problems": problems[:20],
            "network": "single-node-demo",
        }

    def verify_content_hash(self, entity_hash: str, tx_id: str | None = None) -> dict[str, Any]:
        """Compare a recomputed off-chain content hash against its on-chain anchor (ADR-011)."""
        if tx_id:
            record = self.get_transaction(tx_id)
            if record is None:
                return {"result": "NOT_ANCHORED", "detail": "Transaction not found on the ledger"}
            anchored = str(record["transaction"]["args"].get("content_hash", ""))
            if not anchored:
                for value in record["transaction"]["write_set"].values():
                    if isinstance(value, dict) and value.get("content_hash"):
                        anchored = value["content_hash"]
                        break
            if anchored == entity_hash:
                return {"result": "MATCH", "tx_id": tx_id, "block_number": record["block_number"]}
            return {"result": "MISMATCH", "tx_id": tx_id, "anchored_hash": anchored,
                    "computed_hash": entity_hash, "block_number": record["block_number"]}
        for key, value in self.state.items():
            if isinstance(value, dict) and value.get("content_hash") == entity_hash:
                return {"result": "MATCH", "state_key": key}
        return {"result": "NOT_ANCHORED"}

    def stats(self) -> dict[str, Any]:
        contracts: dict[str, int] = {}
        for block in self.blocks:
            for tx in block.transactions:
                name = f"{tx.contract}.{tx.function}"
                contracts[name] = contracts.get(name, 0) + 1
        return {"height": self.height, "transactions": len(self._tx_index),
                "state_keys": len(self.state), "organizations": sorted(self.msp.all()),
                "by_function": contracts, "channel": self.channel, "network": "single-node-demo"}
