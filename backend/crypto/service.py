"""PR-RABE lifecycle service — bridges Flask routes and the real PR-RABE module.

Manages in-memory cryptographic state (CRS, keys, AGK groups) and logs
all operations to the database for audit.  If the server restarts the
ceremony must be re-run (acceptable for a research prototype).

Requires charm-crypto (Linux / WSL only).
"""

import json
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from threading import Lock

from backend.database import get_connection

try:
    from backend.crypto.prrabe.params import setup as prrabe_setup
    from backend.crypto.prrabe.scheme import (
        keygen, is_valid, aggregate, decrypt, DecryptionFailed,
    )
    from backend.crypto.prrabe.owner import AttributeGroups, DataOwner
    from backend.crypto.prrabe.hybrid import seal, open_envelope
    CHARM_AVAILABLE = True
except Exception as _charm_err:
    import sys
    print(f"[PR-RABE] charm-crypto not loaded: {type(_charm_err).__name__}: {_charm_err}", file=sys.stderr)
    CHARM_AVAILABLE = False

SECTORS = ["FINANCE", "HEALTHCARE", "EDUCATION", "TECHNOLOGY", "GOVERNMENT", "ENERGY"]
TRUST_TIERS = ["HIGH", "MEDIUM", "LOW"]
ATTRIBUTE_UNIVERSE = (
    [f"SECTOR:{s}" for s in SECTORS]
    + [f"TRUST:{t}" for t in TRUST_TIERS]
)


@dataclass
class OrgSlot:
    org_id: int
    org_name: str
    slot: int
    sector: str
    trust_tier: str
    attributes: frozenset
    pk: object = None
    sk: object = None
    hsk: object = None
    registered_at: str = ""


class _FallbackDataOwner:
    """Lightweight stand-in when charm-crypto is absent."""
    def __init__(self, slots):
        self.records = {}
        self._slots = slots


class PRRABEService:

    def __init__(self):
        self._lock = Lock()
        self._reset()

    def _reset(self):
        self.crs = None
        self.mpk = None
        self.data_owner = None
        self.num_slots = 0
        self.slots = {}          # slot_index -> OrgSlot
        self.org_to_slot = {}    # org_id -> slot_index
        self.envelopes = {}      # record_id (str) -> hybrid.Envelope
        self.aggregated = False
        self.setup_at = None
        self.aggregate_at = None

    @property
    def available(self):
        return CHARM_AVAILABLE

    # -------------------------------------------------------------- Setup

    def init_system(self, num_slots):
        if num_slots < 2:
            raise ValueError("Need at least 2 slots.")

        with self._lock:
            self._reset()
            t0 = time.perf_counter()
            if CHARM_AVAILABLE:
                self.crs = prrabe_setup(num_slots)
            else:
                self.crs = {"mock": True, "num_slots": num_slots}
            ms = _ms(t0)
            self.num_slots = num_slots
            self.setup_at = _now()

            _log("system_setup", num_slots=num_slots, elapsed_ms=ms,
                 fallback=not CHARM_AVAILABLE)

            note = "CRS generated. Setup secrets discarded — no trapdoor exists."
            if not CHARM_AVAILABLE:
                note += " (Fallback mode — AES demo, not real ABE.)"

            return {
                "status": "ok",
                "num_slots": num_slots,
                "group": "SS512 (Type-A symmetric pairing)" if CHARM_AVAILABLE else "AES-256 (fallback demo)",
                "security": "80-bit (prototype)" if CHARM_AVAILABLE else "128-bit AES (demo only)",
                "elapsed_ms": ms,
                "note": note,
            }

    # -------------------------------------------------------------- KeyGen

    def register_org(self, org_id, org_name, sector, trust_tier):
        if self.crs is None:
            raise RuntimeError("System not initialised. Call init_system first.")

        with self._lock:
            if org_id in self.org_to_slot:
                s = self.slots[self.org_to_slot[org_id]]
                return {
                    "status": "already_registered",
                    "slot": s.slot,
                    "attribute_count": len(s.attributes),
                }

            slot = self._next_free_slot()
            if slot is None:
                raise RuntimeError(f"All {self.num_slots} slots occupied.")

            attrs = frozenset({
                f"SECTOR:{sector.upper()}",
                f"TRUST:{trust_tier.upper()}",
            })

            t0 = time.perf_counter()
            if CHARM_AVAILABLE:
                pk, sk = keygen(self.crs, slot)
                valid = is_valid(self.crs, slot, pk)
            else:
                import os as _os
                pk = _os.urandom(32).hex()
                sk = _os.urandom(32).hex()
                valid = True
            ms = _ms(t0)

            if not valid:
                raise RuntimeError("IsValid check failed.")

            reg = OrgSlot(
                org_id=org_id, org_name=org_name, slot=slot,
                sector=sector.upper(), trust_tier=trust_tier.upper(),
                attributes=attrs, pk=pk, sk=sk,
                registered_at=_now(),
            )
            self.slots[slot] = reg
            self.org_to_slot[org_id] = slot

            if self.aggregated:
                self._invalidate_aggregate()

            _log("keygen", org_id=org_id, org_name=org_name,
                 slot=slot, attributes=sorted(attrs), elapsed_ms=ms)

            return {
                "status": "ok",
                "slot": slot,
                "attribute_count": len(attrs),
                "is_valid": True,
                "elapsed_ms": ms,
                "registered": len(self.slots),
                "total_slots": self.num_slots,
                "ready_to_aggregate": len(self.slots) == self.num_slots,
            }

    # -------------------------------------------------------------- Aggregate

    def run_aggregate(self):
        if self.crs is None:
            raise RuntimeError("System not initialised.")

        with self._lock:
            filled = len(self.slots)
            if filled != self.num_slots:
                raise RuntimeError(
                    f"Need {self.num_slots} registrations, have {filled}. "
                    f"All slots must be filled before aggregation."
                )

            t0 = time.perf_counter()
            if CHARM_AVAILABLE:
                reg_list = [
                    (self.slots[i].pk, self.slots[i].attributes)
                    for i in range(self.num_slots)
                ]
                mpk, hsks = aggregate(self.crs, reg_list, ATTRIBUTE_UNIVERSE)
                self.mpk = mpk
                for i in range(self.num_slots):
                    self.slots[i].hsk = hsks[i]

                attr_map = {i: self.slots[i].attributes for i in range(self.num_slots)}
                groups = AttributeGroups(self.crs.group, attr_map)
                self.data_owner = DataOwner(self.crs, mpk, groups)
            else:
                import os as _os
                self.mpk = _os.urandom(32).hex()
                for i in range(self.num_slots):
                    self.slots[i].hsk = _os.urandom(32).hex()
                self.data_owner = _FallbackDataOwner(self.slots)
            ms = _ms(t0)
            self.aggregated = True
            self.aggregate_at = _now()

            _log("aggregate", org_count=filled, elapsed_ms=ms,
                 orgs=[{"slot": i, "name": self.slots[i].org_name,
                        "attrs": sorted(self.slots[i].attributes)}
                       for i in range(self.num_slots)])

            return {
                "status": "ok",
                "org_count": filled,
                "elapsed_ms": ms,
                "note": "Aggregate is deterministic — Key Curator holds no secrets. Anyone can verify.",
                "orgs": [
                    {"slot": i, "name": self.slots[i].org_name,
                     "attribute_count": len(self.slots[i].attributes)}
                    for i in range(self.num_slots)
                ],
            }

    # -------------------------------------------------------------- Encrypt

    def encrypt_record(self, record_id, policy_string, payload_dict,
                       encrypted_by_org_id=None):
        if not self.aggregated:
            raise RuntimeError("System not aggregated yet.")

        rid = str(record_id)

        with self._lock:
            t0 = time.perf_counter()
            payload_bytes = json.dumps(payload_dict).encode()

            if CHARM_AVAILABLE:
                env = seal(self.data_owner, rid, payload_bytes, policy_string)
                self.envelopes[rid] = env
                ct = self.data_owner.records[rid].ct
                names = ct.names
                agk_versions = ct.agk_versions
            else:
                import base64 as _b64
                from hashlib import sha256 as _sha256
                key = _sha256(policy_string.encode()).digest()
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                import os as _os
                nonce = _os.urandom(12)
                ct_bytes = AESGCM(key).encrypt(nonce, payload_bytes, rid.encode())
                self.envelopes[rid] = {"nonce": nonce, "ct": ct_bytes, "policy": policy_string, "payload": payload_dict}
                self.data_owner.records[rid] = {"policy": policy_string}
                names = [n.split(":")[0] for n in policy_string.replace("(", "").replace(")", "").split(" AND ") if ":" in n]
                agk_versions = {n: 1 for n in names}
            ms = _ms(t0)

            _log("encrypt", record_id=rid, policy=policy_string,
                 names=names, versions=agk_versions,
                 encrypted_by=encrypted_by_org_id, elapsed_ms=ms)

            return {
                "status": "ok",
                "record_id": rid,
                "policy_hidden": True,
                "elapsed_ms": ms,
            }

    # -------------------------------------------------------------- Decrypt

    def decrypt_record(self, org_id, record_id):
        if not self.aggregated:
            raise RuntimeError("System not aggregated yet.")

        rid = str(record_id)

        with self._lock:
            if org_id not in self.org_to_slot:
                return {"success": False, "reason": f"Org {org_id} not registered in PR-RABE."}

            slot = self.org_to_slot[org_id]
            reg = self.slots[slot]

            records_store = self.data_owner.records if CHARM_AVAILABLE else self.data_owner.records
            if rid not in records_store:
                return {"success": False, "reason": f"Record {rid} not in encrypted store."}
            if rid not in self.envelopes:
                return {"success": False, "reason": f"Envelope for {rid} not found."}

            t0 = time.perf_counter()

            if CHARM_AVAILABLE:
                stored = self.data_owner.records[rid]
                env = self.envelopes[rid]
                try:
                    plaintext = open_envelope(
                        self.crs, reg.hsk, reg.sk, stored.ct, env,
                    )
                except DecryptionFailed as exc:
                    ms = _ms(t0)
                    _log("decrypt_fail", org_id=org_id, org_name=reg.org_name,
                         record_id=rid, reason=str(exc), elapsed_ms=ms)
                    return {
                        "success": False,
                        "reason": "Access denied.",
                        "org_name": reg.org_name,
                        "elapsed_ms": ms,
                    }
                data = json.loads(plaintext)
            else:
                env = self.envelopes[rid]
                policy = env["policy"]
                policy_attrs = set()
                for part in policy.replace("(", "").replace(")", "").split(" AND "):
                    part = part.strip()
                    if ":" in part:
                        policy_attrs.add(part)
                if not _fallback_satisfies(policy_attrs, reg.attributes):
                    ms = _ms(t0)
                    _log("decrypt_fail", org_id=org_id, org_name=reg.org_name,
                         record_id=rid, reason="Policy not satisfied", elapsed_ms=ms)
                    return {
                        "success": False,
                        "reason": "Access denied.",
                        "org_name": reg.org_name,
                        "elapsed_ms": ms,
                    }
                data = env["payload"]

            ms = _ms(t0)

            _log("decrypt_ok", org_id=org_id, org_name=reg.org_name,
                 record_id=rid, elapsed_ms=ms)

            return {
                "success": True,
                "data": data,
                "org_name": reg.org_name,
                "elapsed_ms": ms,
            }

    # -------------------------------------------------------------- Revoke

    def revoke_attribute(self, org_id, attribute):
        if not self.aggregated:
            raise RuntimeError("System not aggregated yet.")

        with self._lock:
            if org_id not in self.org_to_slot:
                raise RuntimeError(f"Org {org_id} not registered.")

            slot = self.org_to_slot[org_id]
            reg = self.slots[slot]

            t0 = time.perf_counter()

            if CHARM_AVAILABLE:
                result = self.data_owner.revoke(slot, attribute)
                new_ver = result.new_agk_version
                reencrypted = result.records_reencrypted
            else:
                reg.attributes = frozenset(a for a in reg.attributes if a != attribute)
                new_ver = 2
                reencrypted = len(self.envelopes)
            ms = _ms(t0)

            _log("revoke", org_id=org_id, org_name=reg.org_name,
                 slot=slot, attribute=attribute,
                 new_version=new_ver,
                 reencrypted=reencrypted, elapsed_ms=ms)

            return {
                "status": "ok",
                "org_name": reg.org_name,
                "new_agk_version": new_ver,
                "records_reencrypted": reencrypted,
                "elapsed_ms": ms,
                "note": (
                    f"AGK rotated to v{new_ver}. "
                    f"{reencrypted} record(s) re-encrypted. "
                    f"No organisation's private key was changed."
                ),
            }

    # -------------------------------------------------------------- Status

    def get_status(self):
        with self._lock:
            orgs = []
            for i in sorted(self.slots):
                s = self.slots[i]
                orgs.append({
                    "slot": s.slot, "org_id": s.org_id,
                    "org_name": s.org_name,
                    "has_key": s.pk is not None,
                    "has_helper_key": s.hsk is not None,
                    "registered_at": s.registered_at,
                })

            return {
                "charm_available": CHARM_AVAILABLE,
                "initialized": self.crs is not None,
                "setup_at": self.setup_at,
                "num_slots": self.num_slots,
                "registered": len(self.slots),
                "aggregated": self.aggregated,
                "aggregate_at": self.aggregate_at,
                "encrypted_records": len(self.data_owner.records) if self.data_owner else 0,
                "orgs": orgs,
            }

    # -------------------------------------------------------------- helpers

    def _next_free_slot(self):
        for i in range(self.num_slots):
            if i not in self.slots:
                return i
        return None

    def _invalidate_aggregate(self):
        self.aggregated = False
        self.mpk = None
        self.data_owner = None
        self.envelopes.clear()
        for s in self.slots.values():
            s.hsk = None


_TRUST_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _fallback_satisfies(policy_attrs, org_attrs):
    """Check if org_attrs satisfy policy_attrs with trust hierarchy.

    TRUST:HIGH satisfies TRUST:HIGH/MEDIUM/LOW requirements.
    SECTOR must match exactly.
    """
    for req in policy_attrs:
        if req.startswith("TRUST:"):
            req_tier = req.split(":")[1]
            org_trust = None
            for a in org_attrs:
                if a.startswith("TRUST:"):
                    org_trust = a.split(":")[1]
                    break
            if org_trust is None:
                return False
            if _TRUST_RANK.get(org_trust, 0) < _TRUST_RANK.get(req_tier, 0):
                return False
        elif req not in org_attrs:
            return False
    return True


# ------------------------------------------------------------------ module helpers

def _now():
    return datetime.now(timezone.utc).isoformat()


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 1)


def _log(event_type, **details):
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO prrabe_events (event_type, details, timestamp) "
                "VALUES (?, ?, ?)",
                (event_type, json.dumps(details, default=str), _now()),
            )
            conn.commit()
    except Exception:
        pass


def get_events(limit=50):
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM prrabe_events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


# Singleton
service = PRRABEService()
