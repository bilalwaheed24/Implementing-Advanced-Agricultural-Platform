"""MSP identities: one ECDSA P-256 key pair per organisation (REAL cryptography)."""
from __future__ import annotations

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256R1()


class OrgIdentity:
    """An organisation's signing identity within an MSP."""

    def __init__(self, msp_id: str, name: str, private_key: ec.EllipticCurvePrivateKey | None,
                 public_pem: str) -> None:
        self.msp_id = msp_id
        self.name = name
        self._private_key = private_key
        self.public_pem = public_pem

    # -- construction ----------------------------------------------------
    @classmethod
    def generate(cls, msp_id: str, name: str) -> "OrgIdentity":
        key = ec.generate_private_key(CURVE)
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return cls(msp_id, name, key, public_pem)

    @classmethod
    def from_files(cls, msp_id: str, name: str, private_pem: str, public_pem: str) -> "OrgIdentity":
        key = serialization.load_pem_private_key(private_pem.encode(), password=None)
        return cls(msp_id, name, key, public_pem)   # type: ignore[arg-type]

    # -- operations ------------------------------------------------------
    def sign(self, message: str) -> str:
        if self._private_key is None:
            raise RuntimeError(f"No private key held for {self.msp_id}")
        return self._private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256())).hex()

    def private_pem(self) -> str:
        if self._private_key is None:
            raise RuntimeError("No private key held")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    @staticmethod
    def verify(public_pem: str, message: str, signature_hex: str) -> bool:
        try:
            public_key = serialization.load_pem_public_key(public_pem.encode())
            public_key.verify(bytes.fromhex(signature_hex), message.encode(),
                              ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


class MSPRegistry:
    """Registry of organisation identities. Persists to LEDGER_DATA_DIR/msp (git-ignored)."""

    def __init__(self, data_dir: str | Path) -> None:
        self.dir = Path(data_dir) / "msp"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._identities: dict[str, OrgIdentity] = {}
        self._load()

    def _load(self) -> None:
        index = self.dir / "index.json"
        if not index.is_file():
            return
        for msp_id, meta in json.loads(index.read_text()).items():
            priv = self.dir / f"{msp_id}.key.pem"
            pub = self.dir / f"{msp_id}.pub.pem"
            if pub.is_file():
                if priv.is_file():
                    self._identities[msp_id] = OrgIdentity.from_files(
                        msp_id, meta["name"], priv.read_text(), pub.read_text())
                else:
                    self._identities[msp_id] = OrgIdentity(msp_id, meta["name"], None, pub.read_text())

    def _save_index(self) -> None:
        index = {m: {"name": i.name} for m, i in self._identities.items()}
        (self.dir / "index.json").write_text(json.dumps(index, indent=2))

    def ensure(self, msp_id: str, name: str) -> OrgIdentity:
        if msp_id in self._identities:
            return self._identities[msp_id]
        identity = OrgIdentity.generate(msp_id, name)
        key_path = self.dir / f"{msp_id}.key.pem"
        key_path.write_text(identity.private_pem())
        key_path.chmod(0o600)                      # private key: owner-read only
        (self.dir / f"{msp_id}.pub.pem").write_text(identity.public_pem)
        self._identities[msp_id] = identity
        self._save_index()
        return identity

    def get(self, msp_id: str) -> OrgIdentity | None:
        return self._identities.get(msp_id)

    def public_key(self, msp_id: str) -> str | None:
        identity = self._identities.get(msp_id)
        return identity.public_pem if identity else None

    def all(self) -> dict[str, OrgIdentity]:
        return dict(self._identities)
