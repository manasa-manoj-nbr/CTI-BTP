"""Flask Blueprint for PR-RABE cryptographic operations.

Exposes REST endpoints for the crypto module (Member 3):
  - System setup and key generation
  - Organisation registration and aggregation
  - Encrypt CTI records under attribute-based policies
  - Decrypt CTI records
  - Revoke an organisation's attribute
  - Status / health check

The crypto module requires Charm-Crypto (Linux/WSL2 only).
On Windows, a graceful fallback returns 503 if the library is missing.
"""

import json
import traceback

from flask import Blueprint, request, jsonify, g

from backend.authentication import require_auth

crypto_bp = Blueprint("crypto", __name__, url_prefix="/api/crypto")

try:
    from backend.crypto.prrabe.params import setup, CRS
    from backend.crypto.prrabe.scheme import (
        keygen, is_valid, aggregate, encrypt, decrypt,
        DecryptionFailed,
    )
    from backend.crypto.prrabe.owner import AttributeGroups, DataOwner
    from backend.crypto.prrabe.hybrid import seal, open_envelope, Envelope
    CRYPTO_AVAILABLE = True
    CRYPTO_ERROR = None
except ImportError as e:
    CRYPTO_AVAILABLE = False
    CRYPTO_ERROR = str(e)


_state = {
    "crs": None,
    "mpk": None,
    "hsks": [],
    "sks": [],
    "groups": None,
    "owner": None,
    "registrations_raw": {},
    "L": 0,
}


def _require_crypto(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not CRYPTO_AVAILABLE:
            return jsonify({
                "error": "Crypto module not available",
                "detail": CRYPTO_ERROR,
                "hint": "Charm-Crypto requires Linux/WSL2. See backend/crypto/README.md",
            }), 503
        return f(*args, **kwargs)
    return wrapper


# --------------------------------------------------
# Health / status
# --------------------------------------------------

@crypto_bp.route("/status", methods=["GET"])
def crypto_status():
    return jsonify({
        "crypto_available": CRYPTO_AVAILABLE,
        "crypto_error": CRYPTO_ERROR,
        "system_initialized": _state["crs"] is not None,
        "num_slots": _state["L"],
        "organizations_registered": len(_state["registrations_raw"]),
        "records_encrypted": len(_state["owner"].records) if _state["owner"] else 0,
    }), 200


# --------------------------------------------------
# 1. Setup — initialise the CRS
# --------------------------------------------------

@crypto_bp.route("/setup", methods=["POST"])
@require_auth
@_require_crypto
def crypto_setup():
    data = request.get_json(silent=True) or {}
    L = data.get("num_slots", 4)
    if not isinstance(L, int) or L < 2 or L > 20:
        return jsonify({"error": "num_slots must be an integer between 2 and 20"}), 400

    crs = setup(L)
    _state["crs"] = crs
    _state["L"] = L
    _state["mpk"] = None
    _state["hsks"] = []
    _state["sks"] = []
    _state["groups"] = None
    _state["owner"] = None
    _state["registrations_raw"] = {}

    return jsonify({
        "message": "CRS generated successfully",
        "num_slots": L,
        "index_set": crs.D,
        "group": "SS512 (PBC Type-A symmetric, ~80-bit security)",
    }), 201


# --------------------------------------------------
# 2. KeyGen — generate keys for an organisation slot
# --------------------------------------------------

@crypto_bp.route("/keygen", methods=["POST"])
@require_auth
@_require_crypto
def crypto_keygen():
    if _state["crs"] is None:
        return jsonify({"error": "Run /api/crypto/setup first"}), 400

    data = request.get_json(silent=True) or {}
    slot = data.get("slot")
    attributes = data.get("attributes", [])

    if not isinstance(slot, int) or slot < 0 or slot >= _state["L"]:
        return jsonify({
            "error": f"slot must be an integer from 0 to {_state['L'] - 1}"
        }), 400
    if not isinstance(attributes, list) or not attributes:
        return jsonify({
            "error": "attributes must be a non-empty list like ['SECTOR:FINANCE', 'TRUST:HIGH']"
        }), 400
    for a in attributes:
        if not isinstance(a, str) or ":" not in a:
            return jsonify({
                "error": f"Each attribute must be NAME:VALUE format, got '{a}'"
            }), 400
    if slot in _state["registrations_raw"]:
        return jsonify({"error": f"Slot {slot} already registered"}), 409

    pk, sk = keygen(_state["crs"], slot)
    valid = is_valid(_state["crs"], slot, pk)

    _state["registrations_raw"][slot] = {
        "pk": pk, "sk": sk, "attributes": set(attributes),
    }

    return jsonify({
        "message": f"Keys generated for slot {slot}",
        "slot": slot,
        "attributes": sorted(attributes),
        "key_valid": valid,
        "slots_registered": len(_state["registrations_raw"]),
        "slots_remaining": _state["L"] - len(_state["registrations_raw"]),
    }), 201


# --------------------------------------------------
# 3. Aggregate — combine all keys into MPK + helper keys
# --------------------------------------------------

@crypto_bp.route("/aggregate", methods=["POST"])
@require_auth
@_require_crypto
def crypto_aggregate():
    if _state["crs"] is None:
        return jsonify({"error": "Run /api/crypto/setup first"}), 400
    if len(_state["registrations_raw"]) != _state["L"]:
        return jsonify({
            "error": f"Need {_state['L']} registrations, have {len(_state['registrations_raw'])}"
        }), 400

    crs = _state["crs"]
    regs = []
    sks = []
    all_attrs = set()
    slot_attrs = {}
    for i in range(_state["L"]):
        entry = _state["registrations_raw"][i]
        regs.append((entry["pk"], entry["attributes"]))
        sks.append(entry["sk"])
        all_attrs.update(entry["attributes"])
        slot_attrs[i] = entry["attributes"]

    mpk, hsks = aggregate(crs, regs, all_attrs)
    groups = AttributeGroups(crs.group, slot_attrs)
    owner = DataOwner(crs, mpk, groups)

    _state["mpk"] = mpk
    _state["hsks"] = hsks
    _state["sks"] = sks
    _state["groups"] = groups
    _state["owner"] = owner

    return jsonify({
        "message": "Aggregation complete — system is ready for encryption",
        "universe": sorted(all_attrs),
        "num_helper_keys": len(hsks),
    }), 200


# --------------------------------------------------
# 4. Encrypt — encrypt a CTI record under an access policy
# --------------------------------------------------

@crypto_bp.route("/encrypt", methods=["POST"])
@require_auth
@_require_crypto
def crypto_encrypt():
    if _state["owner"] is None:
        return jsonify({"error": "Run /api/crypto/aggregate first"}), 400

    data = request.get_json(silent=True) or {}
    record_id = data.get("record_id")
    policy = data.get("policy")
    payload = data.get("payload")

    if not record_id or not isinstance(record_id, str):
        return jsonify({"error": "record_id (string) is required"}), 400
    if not policy or not isinstance(policy, str):
        return jsonify({"error": "policy (string) is required, e.g. '(SECTOR:FINANCE and TRUST:HIGH)'"}), 400
    if not payload:
        return jsonify({"error": "payload is required (JSON object or string)"}), 400

    if isinstance(payload, dict):
        payload_bytes = json.dumps(payload).encode()
    else:
        payload_bytes = str(payload).encode()

    try:
        envelope = seal(_state["owner"], record_id, payload_bytes, policy)
        ct = _state["owner"].records[record_id].ct
        return jsonify({
            "message": "Record encrypted successfully",
            "record_id": record_id,
            "policy": policy,
            "policy_rows": ct.names,
            "agk_versions": {str(k): v for k, v in ct.agk_versions.items()},
            "authorized_slots": {str(k): sorted(ct.hdr[k].keys()) for k in ct.hdr},
            "payload_size_bytes": len(payload_bytes),
            "ciphertext_stored": True,
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {e}"}), 500


# --------------------------------------------------
# 5. Decrypt — decrypt a CTI record for a specific slot
# --------------------------------------------------

@crypto_bp.route("/decrypt", methods=["POST"])
@require_auth
@_require_crypto
def crypto_decrypt():
    if _state["owner"] is None:
        return jsonify({"error": "System not initialized"}), 400

    data = request.get_json(silent=True) or {}
    record_id = data.get("record_id")
    slot = data.get("slot")

    if not record_id or not isinstance(record_id, str):
        return jsonify({"error": "record_id (string) is required"}), 400
    if not isinstance(slot, int) or slot < 0 or slot >= _state["L"]:
        return jsonify({"error": f"slot must be 0..{_state['L'] - 1}"}), 400

    if record_id not in _state["owner"].records:
        return jsonify({"error": f"Record '{record_id}' not found"}), 404

    stored = _state["owner"].records[record_id]
    try:
        m = decrypt(_state["crs"], _state["hsks"][slot], _state["sks"][slot], stored.ct)
        return jsonify({
            "message": "Decryption successful",
            "record_id": record_id,
            "slot": slot,
            "access": "GRANTED",
        }), 200
    except DecryptionFailed as e:
        return jsonify({
            "record_id": record_id,
            "slot": slot,
            "access": "DENIED",
            "reason": str(e),
        }), 403


# --------------------------------------------------
# 6. Revoke — revoke a slot's attribute and re-encrypt
# --------------------------------------------------

@crypto_bp.route("/revoke", methods=["POST"])
@require_auth
@_require_crypto
def crypto_revoke():
    if _state["owner"] is None:
        return jsonify({"error": "System not initialized"}), 400

    data = request.get_json(silent=True) or {}
    slot = data.get("slot")
    attribute = data.get("attribute")

    if not isinstance(slot, int) or slot < 0 or slot >= _state["L"]:
        return jsonify({"error": f"slot must be 0..{_state['L'] - 1}"}), 400
    if not attribute or not isinstance(attribute, str) or ":" not in attribute:
        return jsonify({"error": "attribute must be NAME:VALUE format"}), 400

    try:
        result = _state["owner"].revoke(slot, attribute)
        return jsonify({
            "message": f"Slot {slot} revoked from attribute '{attribute}'",
            "slot": result.slot,
            "attribute": result.attribute,
            "new_agk_version": result.new_agk_version,
            "records_reencrypted": result.records_reencrypted,
            "elapsed_ms": round(result.elapsed_ms, 2),
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# --------------------------------------------------
# 7. Demo — run the full 4-org scenario from demo_slide19
# --------------------------------------------------

@crypto_bp.route("/demo", methods=["POST"])
@require_auth
@_require_crypto
def crypto_demo():
    """Run a complete PR-RABE demo: setup, keygen, aggregate, encrypt, decrypt, revoke."""
    crs = setup(4)

    orgs = [
        {"name": "Alpha Bank",      "slot": 0, "attrs": {"SECTOR:FINANCE", "TRUST:HIGH"}},
        {"name": "Beta FinTech",    "slot": 1, "attrs": {"SECTOR:FINANCE", "TRUST:HIGH"}},
        {"name": "City Hospital",   "slot": 2, "attrs": {"SECTOR:HEALTH", "TRUST:MEDIUM"}},
        {"name": "Delta Insurance",  "slot": 3, "attrs": {"SECTOR:FINANCE", "TRUST:MEDIUM"}},
    ]

    regs, sks_demo = [], []
    slot_attrs = {}
    all_attrs = set()
    for org in orgs:
        pk, sk = keygen(crs, org["slot"])
        regs.append((pk, org["attrs"]))
        sks_demo.append(sk)
        slot_attrs[org["slot"]] = org["attrs"]
        all_attrs.update(org["attrs"])

    mpk, hsks = aggregate(crs, regs, all_attrs)
    groups = AttributeGroups(crs.group, slot_attrs)
    owner = DataOwner(crs, mpk, groups)

    policy = "(SECTOR:FINANCE and TRUST:HIGH)"
    m = crs.group.random(crs.group.GT)
    owner.encrypt("campaign-X", policy, m)

    results = []
    for org in orgs:
        i = org["slot"]
        try:
            decrypt(crs, hsks[i], sks_demo[i], owner.records["campaign-X"].ct)
            results.append({"org": org["name"], "slot": i, "access": "GRANTED"})
        except DecryptionFailed as e:
            results.append({"org": org["name"], "slot": i, "access": "DENIED", "reason": str(e)})

    revoke_result = owner.revoke(1, "TRUST:HIGH")

    post_revoke = []
    for org in orgs:
        i = org["slot"]
        try:
            decrypt(crs, hsks[i], sks_demo[i], owner.records["campaign-X"].ct)
            post_revoke.append({"org": org["name"], "slot": i, "access": "GRANTED"})
        except DecryptionFailed as e:
            post_revoke.append({"org": org["name"], "slot": i, "access": "DENIED", "reason": str(e)})

    return jsonify({
        "message": "PR-RABE demo completed",
        "scenario": {
            "organizations": [
                {"name": o["name"], "slot": o["slot"], "attributes": sorted(o["attrs"])}
                for o in orgs
            ],
            "policy": policy,
        },
        "pre_revocation": results,
        "revocation": {
            "action": "Revoked Beta FinTech (slot 1) from TRUST:HIGH",
            "new_agk_version": revoke_result.new_agk_version,
            "records_reencrypted": revoke_result.records_reencrypted,
            "elapsed_ms": round(revoke_result.elapsed_ms, 2),
        },
        "post_revocation": post_revoke,
    }), 200
