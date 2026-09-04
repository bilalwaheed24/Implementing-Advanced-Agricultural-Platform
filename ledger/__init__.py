"""Permissioned ledger implementing the Hyperledger Fabric transaction model.

REAL:  ECDSA P-256 signing/verification, SHA-256 hash-linked blocks, Merkle roots
       and inclusion proofs, MSP identity registry, endorsement policy evaluation,
       world state, chaincode-style contracts, tamper detection.
DEMO:  single-node ordering (no Raft cluster, no multi-peer gossip).
See docs/Blockchain-integration.md and ADR-003.
"""
from .identity import MSPRegistry, OrgIdentity          # noqa: F401
from .block import Block, Transaction, merkle_root, merkle_proof, verify_merkle_proof  # noqa: F401
from .chain import Ledger, LedgerError, EndorsementError, ContractError  # noqa: F401
