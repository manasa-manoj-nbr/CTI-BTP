"""
Risk-adaptive policy engine.

Turns CTI sensitivity and organization trust into PR-RABE attribute
policies, and turns changes in either into GRANT/REVOKE/re-wrap events.

Design (each rule comes from a published model, not a guess):

1. Classification - a record's sensitivity is the HIGHEST level any
   factor assigns (FIPS 199 / NIST SP 800-60 high-water mark). Factors:
   FIRST TLP 2.0 marking, stored risk level, verification status.
2. Clearance - an organization may read a level only if its trust level
   dominates it (Bell-LaPadula "no read-up").
3. Conflicts - hard rules first, deny-overrides, default deny
   (OASIS XACML 3.0 combining algorithms).
4. Enforceability - every policy is a monotone AND-of-ORs over
   attributes, which an LSSS (and therefore PR-RABE) can express.

Trust attributes are cumulative (an org at High holds Trust>=Low,
Trust>=Medium and Trust>=High), so a drop from High to Medium revokes
exactly one attribute group and leaves every other member untouched.
Records never need re-encrypting when an organization's trust changes:
their policies name attributes, not organizations. A record is only
re-wrapped when its OWN sensitivity changes.

Boundaries with the rest of the project:

- Trust is an INPUT. The trust engine pushes levels with update_trust();
  until it does, the level comes from the existing organizations
  trust_score via organizations.get_trust_level(). This module never
  computes trust.
- Other modules' tables are only read. Everything the engine stores
  (multi-sector membership, TLP labels, attribute state, policies,
  events) lives in its own tables, created on first use.
- Changes are picked up two ways: other modules (or the demo) call the
  on_* / update_* functions, and every access check reconciles the
  org and record it touches, so changes made elsewhere still produce
  GRANT/REVOKE/REWRAP events.
"""

import json
import time
from datetime import datetime, timezone

from backend import database
from backend.database import get_connection
from backend.organizations import get_trust_level as score_to_level
from backend.prrabe_interface import get_backend


# --------------------------------------------------
# CONFIGURATION - the decision tables
# --------------------------------------------------

SENSITIVITY_LEVELS = ["Public", "Internal", "Confidential", "Restricted"]
TRUST_LEVELS = ["Low", "Medium", "High"]

# FIRST TLP 2.0 marking -> sensitivity.
TLP_SENSITIVITY = {
    "CLEAR": "Public",
    "GREEN": "Internal",
    "AMBER": "Confidential",
    "AMBER+STRICT": "Restricted",
    "RED": "Restricted",
}
DEFAULT_TLP = "GREEN"

# Stored risk level -> sensitivity.
RISK_SENSITIVITY = {
    "Low": "Public",
    "Medium": "Internal",
    "High": "Confidential",
    "Critical": "Restricted",
}

# Verification status. Every new record starts "Under Review", so the
# floor is Internal rather than Confidential: medium-trust partners still
# get early warning, but unverified intel never reaches low-trust orgs.
STATUS_FLOOR = {
    "Under Review": "Internal",
    "Disputed": "Confidential",
}
NOT_SHARED_STATUSES = {"Rejected"}
# Independent reports from this many organizations count as verification.
CORROBORATION_THRESHOLD = 2

# Trust level required for each sensitivity level (no read-up).
REQUIRED_TRUST = {
    "Public": "Low",
    "Internal": "Medium",
    "Confidential": "High",
    "Restricted": "High",
}
# Levels that also require a matching sector attribute.
SECTOR_BOUND_LEVELS = {"Confidential", "Restricted"}

ALL_SECTORS = "All"
VALID_SECTORS = {
    "Finance",
    "Healthcare",
    "Education",
    "Technology",
    "Government",
    "Energy",
}

LEGACY_SEVERITY_RISK = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}


# --------------------------------------------------
# PURE FUNCTIONS (no database access)
# --------------------------------------------------

def trust_attribute(level):
    return f"Trust>={level}"


def sector_attribute(sector):
    return f"Sector:{sector}"


def normalize_trust_level(level):
    lookup = {value.lower(): value for value in TRUST_LEVELS}
    if not isinstance(level, str) or level.strip().lower() not in lookup:
        raise ValueError(f"Unsupported trust level: {level!r}")
    return lookup[level.strip().lower()]


def normalize_sectors(sectors):
    """Validate and canonicalize a sector list. "All" stands alone."""
    if isinstance(sectors, str):
        sectors = [sectors]
    if not isinstance(sectors, (list, tuple, set)) or not sectors:
        raise ValueError("At least one sector is required.")

    lookup = {s.lower(): s for s in VALID_SECTORS | {ALL_SECTORS}}
    clean = set()
    for sector in sectors:
        if not isinstance(sector, str) or sector.strip().lower() not in lookup:
            raise ValueError(f"Unsupported sector: {sector!r}")
        clean.add(lookup[sector.strip().lower()])

    if ALL_SECTORS in clean:
        return [ALL_SECTORS]
    return sorted(clean)


def normalize_tlp(tlp):
    if tlp is None:
        return DEFAULT_TLP
    value = str(tlp).strip().upper().replace("TLP:", "")
    if value not in TLP_SENSITIVITY:
        raise ValueError(f"Unsupported TLP marking: {tlp!r}")
    return value


def classify(risk_level, tlp=None, status="Verified", corroborating_orgs=1):
    """
    Return (sensitivity, reasons) using the high-water mark.

    Every factor proposes a level; the record takes the highest.
    Unknown risk levels fail closed to Restricted.
    """
    tlp = normalize_tlp(tlp)
    factors = [
        (TLP_SENSITIVITY[tlp], f"TLP:{tlp}"),
        (RISK_SENSITIVITY.get(risk_level, "Restricted"),
         f"risk level {risk_level}"),
    ]

    corroborated = corroborating_orgs >= CORROBORATION_THRESHOLD
    if status in STATUS_FLOOR and not (status == "Under Review" and corroborated):
        factors.append((STATUS_FLOOR[status], f"status {status}"))

    sensitivity = max(
        (level for level, _ in factors),
        key=SENSITIVITY_LEVELS.index,
    )
    reasons = [f"{reason} -> {level}" for level, reason in factors]
    return sensitivity, reasons


def build_policy(sensitivity, record_sectors, owner_sectors=()):
    """
    Build a monotone policy as a list of OR-clauses that are ANDed.

    [["Sector:Finance", "Sector:Healthcare"], ["Trust>=High"]]
    == (Sector:Finance OR Sector:Healthcare) AND Trust>=High

    Returns None when nobody but the owner may read the record.
    """
    clauses = []
    sectors = normalize_sectors(record_sectors)

    if sensitivity in SECTOR_BOUND_LEVELS:
        if sectors == [ALL_SECTORS] and sensitivity == "Restricted":
            # Restricted intel is never broadcast; fall back to the
            # submitting organization's own sectors.
            sectors = sorted(set(owner_sectors) - {ALL_SECTORS})
            if not sectors:
                return None
        if sectors != [ALL_SECTORS]:
            clauses.append([sector_attribute(s) for s in sectors])

    clauses.append([trust_attribute(REQUIRED_TRUST[sensitivity])])
    return clauses


def policy_to_string(policy):
    if policy is None:
        return "NONE"

    parts = []
    for clause in policy:
        text = " OR ".join(clause)
        parts.append(f"({text})" if len(clause) > 1 else text)
    return " AND ".join(parts)


def _hide_policy_values(policy):
    """Show attribute names but hide values — preserves PR-RABE policy hiding."""
    if policy is None:
        return "NONE"
    import re
    parts = []
    for clause in policy:
        hidden = [re.sub(r":.*", ":***", attr) for attr in clause]
        text = " OR ".join(hidden)
        parts.append(f"({text})" if len(clause) > 1 else text)
    return " AND ".join(parts)


def satisfies(attributes, policy):
    """True iff the attribute set satisfies every clause of the policy."""
    if policy is None:
        return False
    attributes = set(attributes)
    return all(attributes.intersection(clause) for clause in policy)


def missing_clauses(attributes, policy):
    if policy is None:
        return ["NONE"]
    attributes = set(attributes)
    return [
        policy_to_string([clause])
        for clause in policy
        if not attributes.intersection(clause)
    ]


def compute_attributes(sectors, trust_level, is_active=True):
    """
    Return (attribute_set, hard_rule_or_None).

    trust_level is used as given. Hard rules (deny-overrides) strip
    every attribute.
    """
    if not is_active:
        return set(), "Organization is inactive"

    attributes = {sector_attribute(s) for s in sectors if s != ALL_SECTORS}
    for level in TRUST_LEVELS[: TRUST_LEVELS.index(trust_level) + 1]:
        attributes.add(trust_attribute(level))
    return attributes, None


# --------------------------------------------------
# OWN TABLES (created on first use, per database file)
# --------------------------------------------------

_initialized_paths = set()


def _connect():
    connection = get_connection()
    if database.DB_PATH not in _initialized_paths:
        _create_tables(connection)
        connection.commit()
        _initialized_paths.add(database.DB_PATH)
    return connection


def _create_tables(connection):
    # Organizations can belong to several sectors.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS policy_org_sectors (
            organization_id INTEGER NOT NULL,
            sector TEXT NOT NULL,
            PRIMARY KEY (organization_id, sector)
        )
    """)

    # TLP marking and sharing sectors per CTI record.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS policy_record_labels (
            record_id INTEGER PRIMARY KEY,
            tlp TEXT NOT NULL,
            sectors TEXT NOT NULL
        )
    """)

    # reported_trust_level is what the trust engine last sent;
    # trust_level and attributes are what enforcement currently reflects.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS policy_org_state (
            organization_id INTEGER PRIMARY KEY,
            trust_level TEXT,
            reported_trust_level TEXT,
            trust_source TEXT NOT NULL DEFAULT 'trust_score',
            attributes TEXT NOT NULL DEFAULT '[]',
            hard_rule TEXT,
            updated_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS policy_record_state (
            record_id INTEGER PRIMARY KEY,
            sensitivity TEXT NOT NULL,
            policy TEXT,
            policy_text TEXT NOT NULL,
            reasons TEXT NOT NULL,
            key_version INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL
        )
    """)

    # Audit trail: enforcement changes and access decisions.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS policy_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            organization_id INTEGER,
            record_id INTEGER,
            attribute TEXT,
            old_value TEXT,
            new_value TEXT,
            trigger TEXT NOT NULL,
            detail TEXT,
            latency_ms REAL,
            created_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE INDEX IF NOT EXISTS idx_policy_events_org
        ON policy_events(organization_id)
    """)


# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------

def _now():
    return datetime.now(timezone.utc).isoformat()


def _load_org(connection, organization_id):
    row = connection.execute(
        """
        SELECT id, name, sector, trust_score, is_active
        FROM organizations WHERE id = ?
        """,
        (organization_id,),
    ).fetchone()
    return dict(row) if row else None


def _org_sectors(connection, organization):
    rows = connection.execute(
        "SELECT sector FROM policy_org_sectors WHERE organization_id = ?",
        (organization["id"],),
    ).fetchall()
    if rows:
        return sorted(row["sector"] for row in rows)
    # Not yet given several sectors: use the organization's own sector.
    return [organization["sector"]] if organization["sector"] in VALID_SECTORS else []


def _record_labels(connection, record):
    row = connection.execute(
        "SELECT tlp, sectors FROM policy_record_labels WHERE record_id = ?",
        (record["id"],),
    ).fetchone()
    if row:
        return row["tlp"], json.loads(row["sectors"])
    try:
        sectors = normalize_sectors(record["sharing_sector"] or ALL_SECTORS)
    except ValueError:
        sectors = [ALL_SECTORS]
    return DEFAULT_TLP, sectors


def _record_owners(connection, record_id):
    rows = connection.execute(
        """
        SELECT organization_id FROM cti_submissions
        WHERE cti_record_id = ?
        ORDER BY created_at, id
        """,
        (record_id,),
    ).fetchall()
    return list(dict.fromkeys(row["organization_id"] for row in rows))


def _log_event(connection, event_type, trigger, organization_id=None,
               record_id=None, attribute=None, old_value=None,
               new_value=None, detail=None, latency_ms=None):
    connection.execute(
        """
        INSERT INTO policy_events (
            event_type, organization_id, record_id, attribute,
            old_value, new_value, trigger, detail, latency_ms, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_type, organization_id, record_id, attribute,
            old_value, new_value, trigger,
            json.dumps(detail) if detail is not None else None,
            latency_ms, _now(),
        ),
    )


def _load_org_state(connection, organization_id):
    row = connection.execute(
        "SELECT * FROM policy_org_state WHERE organization_id = ?",
        (organization_id,),
    ).fetchone()
    if row is None:
        return None
    state = dict(row)
    state["attributes"] = set(json.loads(state["attributes"]))
    return state


def _load_record_state(connection, record_id):
    row = connection.execute(
        "SELECT * FROM policy_record_state WHERE record_id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        return None
    entry = dict(row)
    entry["policy"] = json.loads(entry["policy"]) if entry["policy"] else None
    entry["reasons"] = json.loads(entry["reasons"])
    return entry


# --------------------------------------------------
# INPUTS FROM OTHER PARTS OF THE PROJECT
# --------------------------------------------------

def update_trust(organization_id, trust_level, trigger="trust_changed"):
    """
    Called by the trust engine whenever it re-evaluates an organization
    (for example after every CTI submission). Returns GRANT/REVOKE events;
    an unchanged level produces none.
    """
    trust_level = normalize_trust_level(trust_level)
    with _connect() as connection:
        if _load_org(connection, organization_id) is None:
            raise ValueError("Organization not found")
        connection.execute(
            """
            INSERT INTO policy_org_state (
                organization_id, reported_trust_level, trust_source,
                updated_at
            )
            VALUES (?, ?, 'trust_engine', ?)
            ON CONFLICT(organization_id) DO UPDATE SET
                reported_trust_level = excluded.reported_trust_level,
                trust_source = excluded.trust_source,
                updated_at = excluded.updated_at
            """,
            (organization_id, trust_level, _now()),
        )
    return on_org_change(organization_id, trigger)


def set_org_sectors(organization_id, sectors, trigger="sectors_changed"):
    """Set every sector an organization belongs to (from onboarding)."""
    sectors = normalize_sectors(sectors)
    if sectors == [ALL_SECTORS]:
        raise ValueError("An organization must belong to specific sectors.")

    with _connect() as connection:
        if _load_org(connection, organization_id) is None:
            raise ValueError("Organization not found")
        connection.execute(
            "DELETE FROM policy_org_sectors WHERE organization_id = ?",
            (organization_id,),
        )
        connection.executemany(
            "INSERT INTO policy_org_sectors (organization_id, sector) VALUES (?, ?)",
            [(organization_id, s) for s in sectors],
        )
    return on_org_change(organization_id, trigger)


def set_record_labels(record_id, tlp=None, sectors=None, trigger="relabelled"):
    """Set a record's TLP marking and/or sharing sectors."""
    with _connect() as connection:
        record = connection.execute(
            "SELECT id, sharing_sector FROM cti_records WHERE id = ?",
            (record_id,),
        ).fetchone()
        if record is None:
            raise ValueError("CTI record not found")

        current_tlp, current_sectors = _record_labels(connection, record)
        connection.execute(
            """
            INSERT INTO policy_record_labels (record_id, tlp, sectors)
            VALUES (?, ?, ?)
            ON CONFLICT(record_id) DO UPDATE SET
                tlp = excluded.tlp, sectors = excluded.sectors
            """,
            (
                record_id,
                normalize_tlp(tlp) if tlp is not None else current_tlp,
                json.dumps(
                    normalize_sectors(sectors)
                    if sectors is not None else current_sectors
                ),
            ),
        )
    return on_record_change(record_id, trigger)


# --------------------------------------------------
# EVENT HANDLERS
# --------------------------------------------------

def _current_trust_level(organization, state):
    if state and state["trust_source"] == "trust_engine":
        return state["reported_trust_level"]
    return normalize_trust_level(score_to_level(organization["trust_score"]))


def on_org_change(organization_id, trigger):
    """
    Recompute an organization's attributes and enforce the difference.

    Emits one REVOKE per attribute lost and one GRANT per attribute
    gained, and calls PR-RABE for each. Never re-encrypts records.
    Returns the list of events.
    """
    started = time.perf_counter()
    backend = get_backend()

    with _connect() as connection:
        organization = _load_org(connection, organization_id)
        if organization is None:
            raise ValueError("Organization not found")

        state = _load_org_state(connection, organization_id)
        old_attributes = state["attributes"] if state else set()
        old_level = state["trust_level"] if state else None

        trust_level = _current_trust_level(organization, state)
        attributes, hard_rule = compute_attributes(
            _org_sectors(connection, organization),
            trust_level,
            bool(organization["is_active"]),
        )

        events = []
        for event_type, changed in (
            ("REVOKE", sorted(old_attributes - attributes)),
            ("GRANT", sorted(attributes - old_attributes)),
        ):
            for attribute in changed:
                if event_type == "REVOKE":
                    result = backend.revoke(organization_id, attribute)
                else:
                    result = backend.grant(organization_id, attribute)
                events.append({
                    "event_type": event_type,
                    "organization_id": organization_id,
                    "attribute": attribute,
                    "group_version": result.get("group_version"),
                    "members_rekeyed": result.get("members_rekeyed", 0),
                })

        latency_ms = round((time.perf_counter() - started) * 1000, 3)
        for event in events:
            _log_event(
                connection, event["event_type"], trigger,
                organization_id=organization_id,
                attribute=event["attribute"],
                old_value=old_level, new_value=trust_level,
                detail={
                    "group_version": event["group_version"],
                    "members_rekeyed": event["members_rekeyed"],
                    "hard_rule": hard_rule,
                },
                latency_ms=latency_ms,
            )

        connection.execute(
            """
            INSERT INTO policy_org_state (
                organization_id, trust_level, trust_source, attributes,
                hard_rule, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(organization_id) DO UPDATE SET
                trust_level = excluded.trust_level,
                attributes = excluded.attributes,
                hard_rule = excluded.hard_rule,
                updated_at = excluded.updated_at
            """,
            (
                organization_id, trust_level,
                state["trust_source"] if state else "trust_score",
                json.dumps(sorted(attributes)), hard_rule, _now(),
            ),
        )

    return events


def on_record_change(record_id, trigger):
    """
    Reclassify a record and re-wrap its key only if its policy changed.

    Returns the event dict, or None when nothing changed.
    """
    started = time.perf_counter()
    backend = get_backend()

    with _connect() as connection:
        record = connection.execute(
            """
            SELECT id, risk_level, status, sharing_sector
            FROM cti_records WHERE id = ?
            """,
            (record_id,),
        ).fetchone()
        if record is None:
            raise ValueError("CTI record not found")

        tlp, sectors = _record_labels(connection, record)
        owners = _record_owners(connection, record_id)

        if record["status"] in NOT_SHARED_STATUSES:
            sensitivity = "Restricted"
            reasons = [f"status {record['status']} -> not shared"]
            policy = None
        else:
            sensitivity, reasons = classify(
                record["risk_level"], tlp, record["status"], len(owners)
            )
            owner = _load_org(connection, owners[0]) if owners else None
            policy = build_policy(
                sensitivity, sectors,
                _org_sectors(connection, owner) if owner else [],
            )
        policy_text = policy_to_string(policy)

        previous = _load_record_state(connection, record_id)
        if previous and previous["policy_text"] == policy_text:
            if previous["reasons"] != reasons:
                connection.execute(
                    "UPDATE policy_record_state SET reasons = ? WHERE record_id = ?",
                    (json.dumps(reasons), record_id),
                )
            return None

        key_version = backend.protect_record(record_id, policy)["key_version"]
        event_type = "REWRAP" if previous else "POLICY_SET"

        connection.execute(
            """
            INSERT INTO policy_record_state (
                record_id, sensitivity, policy, policy_text, reasons,
                key_version, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(record_id) DO UPDATE SET
                sensitivity = excluded.sensitivity,
                policy = excluded.policy,
                policy_text = excluded.policy_text,
                reasons = excluded.reasons,
                key_version = excluded.key_version,
                updated_at = excluded.updated_at
            """,
            (
                record_id, sensitivity,
                json.dumps(policy) if policy is not None else None,
                policy_text, json.dumps(reasons), key_version, _now(),
            ),
        )

        _log_event(
            connection, event_type, trigger, record_id=record_id,
            old_value=previous["policy_text"] if previous else None,
            new_value=policy_text,
            detail={"sensitivity": sensitivity, "key_version": key_version},
            latency_ms=round((time.perf_counter() - started) * 1000, 3),
        )

    return {
        "event_type": event_type,
        "record_id": record_id,
        "sensitivity": sensitivity,
        "policy": policy_text,
        "key_version": key_version,
    }


def sync_all(trigger="sync"):
    """Bring every organization and record up to date."""
    with _connect() as connection:
        org_ids = [r["id"] for r in connection.execute(
            "SELECT id FROM organizations ORDER BY id"
        )]
        record_ids = [r["id"] for r in connection.execute(
            "SELECT id FROM cti_records ORDER BY id"
        )]

    org_events = []
    for organization_id in org_ids:
        org_events.extend(on_org_change(organization_id, trigger))
    record_events = [
        event for event in (
            on_record_change(record_id, trigger) for record_id in record_ids
        )
        if event
    ]
    return {"org_events": org_events, "record_events": record_events}


# --------------------------------------------------
# QUERIES
# --------------------------------------------------

def get_org_policy_state(organization_id):
    """Current trust level, sectors and attributes for an organization."""
    on_org_change(organization_id, "reconcile")
    with _connect() as connection:
        state = _load_org_state(connection, organization_id)
        state["sectors"] = _org_sectors(
            connection, _load_org(connection, organization_id)
        )
    state["attributes"] = sorted(state["attributes"])
    return state


def get_record_policy(record_id):
    """Current sensitivity, policy and labels for a record."""
    on_record_change(record_id, "reconcile")
    with _connect() as connection:
        entry = _load_record_state(connection, record_id)
        record = connection.execute(
            "SELECT id, sharing_sector FROM cti_records WHERE id = ?",
            (record_id,),
        ).fetchone()
        entry["tlp"], entry["sectors"] = _record_labels(connection, record)
        entry["owners"] = _record_owners(connection, record_id)
    return entry


def list_policy_events(organization_id=None, record_id=None,
                       event_type=None, limit=100):
    query = "SELECT * FROM policy_events"
    conditions, values = [], []
    for column, value in (
        ("organization_id", organization_id),
        ("record_id", record_id),
        ("event_type", event_type),
    ):
        if value is not None:
            conditions.append(f"{column} = ?")
            values.append(value)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"
    values.append(limit)

    with _connect() as connection:
        rows = connection.execute(query, values).fetchall()

    events = []
    for row in rows:
        event = dict(row)
        event["detail"] = json.loads(event["detail"]) if event["detail"] else None
        events.append(event)
    return events


# --------------------------------------------------
# ACCESS DECISION (called by the existing API routes)
# --------------------------------------------------

def _decide(organization_id, org_state, policy, sensitivity, owners):
    """Deny-overrides, default deny. Returns (decision, reason, missing)."""
    if organization_id in owners:
        return "ALLOW", "Organization submitted this CTI (data owner)", []
    if org_state["hard_rule"]:
        return "DENY", org_state["hard_rule"], []
    if policy is None:
        return "DENY", "Record is not shared (rejected or no eligible sector)", []

    missing = missing_clauses(org_state["attributes"], policy)
    if missing:
        return "DENY", (
            f"{sensitivity} CTI requires attributes your organization does not satisfy"
        ), missing
    return "ALLOW", f"Organization attributes satisfy the required policy", []


def _log_access(organization_id, record_id, record_type, decision, reason):
    with _connect() as connection:
        _log_event(
            connection, "ACCESS", record_type,
            organization_id=organization_id, record_id=record_id,
            new_value=decision, detail={"reason": reason},
        )


def _response(organization, org_state, record_id, record_type, sharing,
              risk_score, risk_level, sensitivity, policy, reasons,
              decision, reason, missing):
    return {
        "decision": decision,
        "reason": (
            "Access granted."
            if decision == "ALLOW"
            else "Organization does not satisfy the access requirements."
        ),
        "organization_id": organization["id"],
        "indicator_id": record_id,
        "record_type": record_type,
    }


def generate_advanced_access_policy(organization_id, record_id):
    """Evaluate access to an advanced CTI record."""
    with _connect() as connection:
        organization = _load_org(connection, organization_id)
        if organization is None:
            return {"decision": "DENY", "reason": "Organization not found"}
        record = connection.execute(
            """
            SELECT id, title, category, risk_score, risk_level, status
            FROM cti_records WHERE id = ?
            """,
            (record_id,),
        ).fetchone()
        if record is None:
            return {"decision": "DENY", "reason": "Advanced CTI record not found"}
        record = dict(record)

    org_state = get_org_policy_state(organization_id)
    entry = get_record_policy(record_id)
    decision, reason, missing = _decide(
        organization_id, org_state, entry["policy"], entry["sensitivity"],
        entry["owners"],
    )
    _log_access(organization_id, record_id, "advanced_cti", decision, reason)

    result = _response(
        organization, org_state, record_id, "advanced_cti",
        ", ".join(entry["sectors"]), record["risk_score"],
        record["risk_level"], entry["sensitivity"], entry["policy"],
        entry["reasons"], decision, reason, missing,
    )
    result["record_id"] = record_id
    result["title"] = record["title"]
    result["category"] = record["category"]
    result["status"] = record["status"]
    return result


def generate_access_policy(organization_id, indicator_id):
    """Evaluate access to a legacy indicator (classified on the fly)."""
    with _connect() as connection:
        organization = _load_org(connection, organization_id)
        if organization is None:
            return {"decision": "DENY", "reason": "Organization not found"}
        indicator = connection.execute(
            "SELECT id, severity, sharing_sector FROM indicators WHERE id = ?",
            (indicator_id,),
        ).fetchone()
        if indicator is None:
            return {"decision": "DENY", "reason": "CTI indicator not found"}

    risk_level = LEGACY_SEVERITY_RISK.get(
        str(indicator["severity"]).lower(), "Critical"
    )
    try:
        sharing = normalize_sectors(indicator["sharing_sector"] or ALL_SECTORS)
    except ValueError:
        sharing = [ALL_SECTORS]
    sensitivity, reasons = classify(risk_level, DEFAULT_TLP, "Verified")
    policy = build_policy(sensitivity, sharing)

    org_state = get_org_policy_state(organization_id)
    decision, reason, missing = _decide(
        organization_id, org_state, policy, sensitivity, []
    )
    _log_access(organization_id, indicator_id, "legacy_indicator", decision, reason)
    return _response(
        organization, org_state, indicator_id, "legacy_indicator",
        ", ".join(sharing), None, risk_level, sensitivity, policy, reasons,
        decision, reason, missing,
    )
