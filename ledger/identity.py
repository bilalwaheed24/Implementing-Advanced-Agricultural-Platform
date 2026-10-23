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
                 public_pem: str, org_type: str | None = None) -> None:
        self.msp_id = msp_id
        self.name = name
        # The organisation's type (BIOTECH | FARM | SUPPLY | REGULATOR). Submit rights are
        # granted per type (contracts.SUBMIT_RIGHTS), so an organisation created at run time
        # with its own MSP identifier has the same rights as the seeded one of its type.
        self.org_type = org_type
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
                    identity = OrgIdentity.from_files(
                        msp_id, meta["name"], priv.read_text(), pub.read_text())
                else:
                    identity = OrgIdentity(msp_id, meta["name"], None, pub.read_text())
                identity.org_type = meta.get("org_type")
                self._identities[msp_id] = identity

    def _save_index(self) -> None:
        index = {m: {"name": i.name, "org_type": i.org_type} for m, i in self._identities.items()}
        (self.dir / "index.json").write_text(json.dumps(index, indent=2))

    def ensure(self, msp_id: str, name: str, org_type: str | None = None) -> OrgIdentity:
        """Create the identity if missing. A type is recorded the first time one is given
        (an identity registered before types existed gets its type on the next ensure) and
        is never changed afterwards, so re-registering cannot widen an organisation's rights."""
        org_type = org_type.upper() if org_type else None
        if msp_id in self._identities:
            identity = self._identities[msp_id]
            if org_type and identity.org_type is None:
                identity.org_type = org_type
                self._save_index()
            return identity
        identity = OrgIdentity.generate(msp_id, name)
        identity.org_type = org_type
        key_path = self.dir / f"{msp_id}.key.pem"
        key_path.write_text(identity.private_pem())
        key_path.chmod(0o600)                      # private key: owner-read only
        (self.dir / f"{msp_id}.pub.pem").write_text(identity.public_pem)
        self._identities[msp_id] = identity
        self._save_index()
        return identity

    def get(self, msp_id: str) -> OrgIdentity | None:
        return self._identities.get(msp_id)

    def org_type(self, msp_id: str) -> str | None:
        identity = self._identities.get(msp_id)
        return identity.org_type if identity else None

    def public_key(self, msp_id: str) -> str | None:
        identity = self._identities.get(msp_id)
        return identity.public_pem if identity else None

    def all(self) -> dict[str, OrgIdentity]:
        return dict(self._identities)
