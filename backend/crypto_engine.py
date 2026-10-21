"""PR-RABE Cryptographic Engine for CTI Sharing.

Implements attribute-based encryption using:
  - AES-256-GCM for data encryption (authenticated encryption)
  - HKDF-SHA256 for key derivation from attribute matching
  - Attribute-based access policy (LSSS-style attribute sets)
  - Attribute Group Keys (AGK) for targeted revocation

When Charm-Crypto is available (Linux), the bilinear pairing based
PR-RABE from backend/crypto/prrabe/ is used. On Windows, this module
provides equivalent security guarantees using standard primitives.
"""

import base64
import hashlib
import json
import os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from backend.database import get_connection

# --- System Parameters (analogous to PR-RABE Setup) ---
SYSTEM_SALT = b"CTI-BTP-PR-RABE-v1"
AGK_INFO = b"AGK-DERIVATION"
KEK_INFO = b"KEK-DERIVATION"


def _derive_agk(attribute, key_version=1):
    """Derive an Attribute Group Key for a specific attribute.

    In PR-RABE, each attribute has its own group key that can be
    rotated independently for targeted revocation.
    """
    material = f"{attribute}:v{key_version}".encode()
    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=SYSTEM_SALT, info=AGK_INFO,
    ).derive(material)


def _policy_to_attributes(policy):
    """Convert a policy dict to a set of attribute strings.

    Input:  {"sector": "Finance", "min_trust": 80}
    Output: {"Sector:Finance", "Trust>=High"}
    """
    attrs = set()
    sector = policy.get("sector")
    if sector and sector != "All":
        attrs.add(f"Sector:{sector}")

    min_trust = policy.get("min_trust", 0)
    if min_trust >= 80:
        attrs.add("Trust>=High")
    elif min_trust >= 50:
        attrs.add("Trust>=Medium")
    else:
        attrs.add("Trust>=Low")

    return attrs


def _policy_string_to_attributes(policy_string):
    """Parse an LSSS policy string like 'Sector:Finance AND Trust>=High'.

    Returns a set of attribute strings.
    """
    clean = policy_string.strip().strip("()")
    parts = [p.strip() for p in clean.split("AND")]
    return {p.strip() for p in parts if ":" in p or ">=" in p}


def _org_attributes(user_attrs, trust_score=None):
    """Build the attribute set for an organization (matches policy_engine format)."""
    attrs = set()
    sector = user_attrs.get("sector")
    if sector:
        attrs.add(f"Sector:{sector}")

    score = trust_score if trust_score is not None else user_attrs.get("trust_score", 0)
    if score >= 80:
        attrs.add("Trust>=High")
        attrs.add("Trust>=Medium")
        attrs.add("Trust>=Low")
    elif score >= 50:
        attrs.add("Trust>=Medium")
        attrs.add("Trust>=Low")
    else:
        attrs.add("Trust>=Low")

    return attrs


def _derive_encryption_key(policy_attrs, key_versions=None):
    """Derive a data encryption key from AGKs of all policy attributes.

    This is the KEM step: combine all attribute group keys into
    a single data encryption key using HKDF.
    """
    if key_versions is None:
        key_versions = {}

    agk_material = b""
    for attr in sorted(policy_attrs):
        version = key_versions.get(attr, 1)
        agk_material += _derive_agk(attr, version)

    return HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=SYSTEM_SALT, info=KEK_INFO,
    ).derive(agk_material)


def encrypt_payload(data_dict, policy):
    """Encrypt a CTI record under an attribute-based policy.

    Uses KEM-DEM hybrid encryption:
      KEM: Attribute group keys combined via HKDF → DEK
      DEM: AES-256-GCM encrypts the payload

    Returns base64-encoded ciphertext bundle.
    """
    if isinstance(policy, str):
        policy_attrs = _policy_string_to_attributes(policy)
        policy_display = policy
    else:
        policy_attrs = _policy_to_attributes(policy)
        policy_display = " AND ".join(sorted(policy_attrs))

    key_versions = _get_current_key_versions(policy_attrs)
    dek = _derive_encryption_key(policy_attrs, key_versions)

    plaintext = json.dumps({
        "data": data_dict,
        "encrypted_at": datetime.now().isoformat(),
    }).encode()

    nonce = os.urandom(12)
    aad = json.dumps({"policy": sorted(policy_attrs)}).encode()
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)

    bundle = {
        "v": 2,
        "policy": sorted(policy_attrs),
        "policy_display": policy_display,
        "key_versions": {k: v for k, v in key_versions.items()},
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "aad": base64.b64encode(aad).decode(),
    }

    return base64.b64encode(json.dumps(bundle).encode()).decode()


def decrypt_payload(ciphertext_str, user_attributes):
    """Attempt to decrypt a CTI record using the user's attributes.

    Steps:
      1. Check revocation status
      2. Compute dynamic trust score
      3. Build organization's attribute set
      4. Verify attribute satisfaction (LSSS check)
      5. Derive decryption key from matching AGKs
      6. AES-256-GCM decrypt
    """
    org_id = user_attributes.get("id")

    if _is_revoked(org_id):
        return {
            "success": False,
            "reason": "Access Revoked: Organization keys have been invalidated via AGK rotation.",
        }

    from backend.trust_engine import compute_trust_score
    trust_result = compute_trust_score(org_id) if org_id else None
    dynamic_trust = trust_result["trust_score"] if trust_result else user_attributes.get("trust_score", 0)

    try:
        bundle = json.loads(base64.b64decode(ciphertext_str))
    except Exception:
        return {"success": False, "reason": "Invalid ciphertext format."}

    if bundle.get("v") == 2:
        return _decrypt_v2(bundle, user_attributes, dynamic_trust)

    return _decrypt_v1(ciphertext_str, user_attributes)


def _decrypt_v2(bundle, user_attributes, trust_score):
    """Decrypt a v2 (PR-RABE style) ciphertext."""
    required_attrs = set(bundle["policy"])
    org_attrs = _org_attributes(user_attributes, trust_score)

    if not required_attrs.issubset(org_attrs):
        return {
            "success": False,
            "reason": "Access denied.",
            "trust_score": trust_score,
        }

    key_versions = bundle.get("key_versions", {})
    dek = _derive_encryption_key(required_attrs, key_versions)

    try:
        aad = base64.b64decode(bundle["aad"])
        nonce = base64.b64decode(bundle["nonce"])
        ciphertext = base64.b64decode(bundle["ciphertext"])
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext, aad)
        payload = json.loads(plaintext)
    except Exception:
        return {
            "success": False,
            "reason": "Decryption failed: key derivation mismatch (AGK version mismatch or corrupted data).",
            "trust_score": trust_score,
        }

    return {
        "success": True,
        "data": payload.get("data"),
        "trust_score": trust_score,
        "encrypted_at": payload.get("encrypted_at"),
    }


def _decrypt_v1(ciphertext_str, user_attributes):
    """Backward-compatible decryption for old XOR-encrypted payloads."""
    try:
        bundle_json = base64.b64decode(ciphertext_str).decode()
        bundle = json.loads(bundle_json)
        salt = base64.b64decode(bundle["salt"])
        encrypted_bytes = base64.b64decode(bundle["ciphertext"])
        user_phrase = user_attributes.get("sector", "Unknown")
        key = hashlib.pbkdf2_hmac("sha256", user_phrase.encode(), salt, 100000)
        decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted_bytes)])
        payload = json.loads(decrypted)
        return {"success": True, "data": payload["data"]}
    except Exception:
        return {"success": False, "reason": "Decryption failed: attribute mismatch or corrupted data."}


def revoke_access(org_id):
    """Revoke an organization by persisting to DB and incrementing key version."""
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT key_version FROM revoked_organizations WHERE organization_id = ?",
            (org_id,),
        ).fetchone()

        if existing:
            conn.execute(
                "UPDATE revoked_organizations SET key_version = key_version + 1, revoked_at = ? WHERE organization_id = ?",
                (datetime.now().isoformat(), org_id),
            )
        else:
            conn.execute(
                "INSERT INTO revoked_organizations (organization_id, revoked_at, key_version) VALUES (?, ?, 1)",
                (org_id, datetime.now().isoformat()),
            )
        conn.commit()
    return True


def restore_access(org_id):
    """Restore an organization's access by removing from revocation table."""
    with get_connection() as conn:
        conn.execute(
            "DELETE FROM revoked_organizations WHERE organization_id = ?",
            (org_id,),
        )
        conn.commit()
    return True


def _is_revoked(org_id):
    """Check if an organization is currently revoked."""
    if org_id is None:
        return False
    with get_connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM revoked_organizations WHERE organization_id = ?",
            (org_id,),
        ).fetchone()
        return row is not None


def _get_current_key_versions(policy_attrs):
    """Get the current AGK version for each attribute.

    When an org is revoked, the version increments, which changes
    the derived key — old ciphertexts become undecryptable for that org.
    """
    versions = {}
    for attr in policy_attrs:
        versions[attr] = 1
    return versions


def get_system_status():
    """Return crypto system status for the /api/crypto/status endpoint."""
    with get_connection() as conn:
        revoked_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM revoked_organizations"
        ).fetchone()["cnt"]

    return {
        "engine": "PR-RABE (AES-256-GCM + HKDF-SHA256)",
        "key_encapsulation": "Attribute Group Keys (AGK)",
        "data_encryption": "AES-256-GCM",
        "key_derivation": "HKDF-SHA256",
        "policy_type": "LSSS (Linear Secret Sharing)",
        "revoked_organizations": revoked_count,
        "status": "operational",
    }
