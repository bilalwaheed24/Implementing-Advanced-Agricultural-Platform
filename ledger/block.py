"""Transaction, Merkle tree and Block structures (REAL cryptography)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

GENESIS_PREV_HASH = "0" * 64


def canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """SHA-256 Merkle root; the last leaf is duplicated for odd counts."""
    if not leaves:
        return sha256_hex("")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], index: int) -> list[dict[str, str]]:
    """Inclusion proof: ordered sibling hashes from leaf to root."""
    if not leaves or index < 0 or index >= len(leaves):
        return []
    proof: list[dict[str, str]] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = idx + 1 if idx % 2 == 0 else idx - 1
        proof.append({"position": "right" if idx % 2 == 0 else "left", "hash": level[sibling]})
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return proof


def verify_merkle_proof(leaf: str, proof: list[dict[str, str]], root: str) -> bool:
    current = leaf
    for step in proof:
        current = (sha256_hex(current + step["hash"]) if step["position"] == "right"
                   else sha256_hex(step["hash"] + current))
    return current == root


@dataclass
class Transaction:
    contract: str
    function: str
    args: dict[str, Any]
    submitter_msp: str
    channel: str
    timestamp: str
    read_set: list[str] = field(default_factory=list)
    write_set: dict[str, Any] = field(default_factory=dict)
    endorsements: list[dict[str, str]] = field(default_factory=list)
    signature: str = ""
    tx_id: str = ""

    def payload_for_signing(self) -> str:
        """Everything that is signed: excludes signatures themselves."""
        return canonical({
            "contract": self.contract,
            "function": self.function,
            "args": self.args,
            "submitter_msp": self.submitter_msp,
            "channel": self.channel,
            "timestamp": self.timestamp,
            "read_set": sorted(self.read_set),
            "write_set": self.write_set,
        })

    def compute_tx_id(self) -> str:
        return sha256_hex(self.payload_for_signing())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Transaction":
        return cls(**data)


@dataclass
class Block:
    number: int
    previous_hash: str
    timestamp: str
    transactions: list[Transaction]
    merkle_root: str = ""
    block_hash: str = ""

    def compute_merkle_root(self) -> str:
        return merkle_root([t.tx_id for t in self.transactions])

    def compute_hash(self) -> str:
        return sha256_hex(canonical({
            "number": self.number,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
        }))

    def seal(self) -> "Block":
        self.merkle_root = self.compute_merkle_root()
        self.block_hash = self.compute_hash()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "block_hash": self.block_hash,
            "transactions": [t.to_dict() for t in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Block":
        block = cls(
            number=data["number"],
            previous_hash=data["previous_hash"],
            timestamp=data["timestamp"],
            transactions=[Transaction.from_dict(t) for t in data["transactions"]],
            merkle_root=data.get("merkle_root", ""),
            block_hash=data.get("block_hash", ""),
        )
        return block


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
