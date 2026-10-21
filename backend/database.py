import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "cti.db"


def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    with get_connection() as connection:

        # 1. Create the legacy indicators table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                stix_data TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Safely migrate the indicators table.
        indicator_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(indicators)"
            ).fetchall()
        }

        if "sharing_sector" not in indicator_columns:
            connection.execute("""
                ALTER TABLE indicators
                ADD COLUMN sharing_sector TEXT NOT NULL DEFAULT 'All'
            """)

        # 2. Create the organizations table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                sector TEXT NOT NULL,
                trust_score INTEGER NOT NULL DEFAULT 50
                    CHECK (trust_score BETWEEN 0 AND 100),
                policy_violations INTEGER NOT NULL DEFAULT 0
                    CHECK (policy_violations >= 0),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Safely migrate existing organizations.
        organization_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(organizations)"
            ).fetchall()
        }

        if "is_active" not in organization_columns:
            connection.execute("""
                ALTER TABLE organizations
                ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1
                CHECK (is_active IN (0, 1))
            """)

        # 3. Create the advanced CTI records table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS cti_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                sharing_sector TEXT NOT NULL DEFAULT 'All',
                stix_data TEXT NOT NULL,
                risk_score INTEGER NOT NULL DEFAULT 0,
                risk_level TEXT NOT NULL DEFAULT 'Low',
                status TEXT NOT NULL DEFAULT 'Under Review',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 4. Create the CTI submission history table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS cti_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cti_record_id INTEGER NOT NULL,
                organization_id INTEGER NOT NULL,
                source_type TEXT NOT NULL,
                source_reliability TEXT NOT NULL,
                observed_at TEXT,
                submitted_severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                evidence TEXT DEFAULT '',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (cti_record_id)
                    REFERENCES cti_records(id),

                FOREIGN KEY (organization_id)
                    REFERENCES organizations(id)
            )
        """)

        # 5. Create the users table for authentication.
        # Passwords must be stored as secure hashes, never plaintext.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                organization_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst'
                    CHECK (role IN ('admin', 'analyst')),
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1)),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (organization_id)
                    REFERENCES organizations(id)
            )
        """)

        # 6. Create indexes for faster queries.
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_cti_category
            ON cti_records(category)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_cti_value
            ON cti_records(indicator_type, indicator_value)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_cti_submissions_record
            ON cti_submissions(cti_record_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_cti_submissions_org
            ON cti_submissions(organization_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_organization
            ON users(organization_id)
        """)

        # 7. Create the audit_logs table for security audit trail.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER,
                organization_name TEXT NOT NULL,
                record_value TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 8. Create revoked_organizations table for persistent revocation.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS revoked_organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL UNIQUE,
                revoked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                key_version INTEGER NOT NULL DEFAULT 1
            )
        """)

        audit_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(audit_logs)"
            ).fetchall()
        }
        if "organization_id" not in audit_columns:
            connection.execute("""
                ALTER TABLE audit_logs
                ADD COLUMN organization_id INTEGER
            """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp
            ON audit_logs(timestamp)
        """)

        # 9. Create the encrypted_records table for stored ciphertexts.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS encrypted_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cti_record_id INTEGER NOT NULL,
                ciphertext TEXT NOT NULL,
                policy_display TEXT NOT NULL,
                sensitivity TEXT,
                classification TEXT,
                encrypted_by_user_id INTEGER NOT NULL,
                encrypted_by_org_id INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cti_record_id) REFERENCES cti_records(id),
                FOREIGN KEY (encrypted_by_user_id) REFERENCES users(id),
                FOREIGN KEY (encrypted_by_org_id) REFERENCES organizations(id)
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_encrypted_records_cti
            ON encrypted_records(cti_record_id)
        """)

        # 10. PR-RABE ceremony event log.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS prrabe_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_prrabe_events_type
            ON prrabe_events(event_type)
        """)

        # 11. Incentive wallet — one row per organisation.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incentive_wallet (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL UNIQUE,
                balance REAL NOT NULL DEFAULT 0,
                lifetime_earned REAL NOT NULL DEFAULT 0,
                lifetime_spent REAL NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations(id)
            )
        """)

        # 12. Incentive transaction ledger.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incentive_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                reason TEXT NOT NULL,
                reference_id TEXT,
                balance_after REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations(id)
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_incentive_tx_org
            ON incentive_transactions(organization_id)
        """)


# --------------------------------------------------
# LEGACY CTI INDICATORS
# --------------------------------------------------

def save_indicator(
    ip_address,
    description,
    severity,
    stix_data,
    sharing_sector="All",
):
    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO indicators (
                ip_address,
                description,
                severity,
                stix_data,
                sharing_sector
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            ip_address,
            description,
            severity,
            stix_data,
            sharing_sector,
        ))

        return cursor.lastrowid


def get_all_indicators():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT id, ip_address, description, severity,
                   stix_data, sharing_sector, created_at
            FROM indicators
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in rows]


# --------------------------------------------------
# ORGANIZATION MANAGEMENT
# --------------------------------------------------

def register_organization(name, sector, trust_score=50):
    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO organizations (
                name,
                sector,
                trust_score
            )
            VALUES (?, ?, ?)
        """, (
            name,
            sector,
            trust_score,
        ))

        return cursor.lastrowid


def get_all_organizations():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT
                id,
                name,
                sector,
                trust_score,
                policy_violations,
                is_active,
                created_at
            FROM organizations
            ORDER BY id
        """).fetchall()

        return [dict(row) for row in rows]


def get_organization_by_id(organization_id):
    with get_connection() as connection:
        row = connection.execute("""
            SELECT
                id,
                name,
                sector,
                trust_score,
                policy_violations,
                is_active,
                created_at
            FROM organizations
            WHERE id = ?
        """, (organization_id,)).fetchone()

        return dict(row) if row else None


def update_organization(
    organization_id,
    name=None,
    sector=None,
):
    updates = []
    values = []

    if name is not None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Organization name cannot be empty")

        updates.append("name = ?")
        values.append(name.strip())

    if sector is not None:
        if not isinstance(sector, str) or not sector.strip():
            raise ValueError("Organization sector cannot be empty")

        updates.append("sector = ?")
        values.append(sector.strip())

    if not updates:
        raise ValueError("Provide a name or sector to update")

    values.append(organization_id)

    with get_connection() as connection:
        cursor = connection.execute(
            f"""
            UPDATE organizations
            SET {", ".join(updates)}
            WHERE id = ?
            """,
            values,
        )

        return cursor.rowcount > 0


def update_organization_trust_score(
    organization_id,
    trust_score,
):
    if type(trust_score) is not int or not 0 <= trust_score <= 100:
        raise ValueError("Trust score must be an integer from 0 to 100")

    with get_connection() as connection:
        cursor = connection.execute("""
            UPDATE organizations
            SET trust_score = ?
            WHERE id = ?
        """, (
            trust_score,
            organization_id,
        ))

        return cursor.rowcount > 0


def update_policy_violations(
    organization_id,
    policy_violations,
):
    if (
        type(policy_violations) is not int
        or policy_violations < 0
    ):
        raise ValueError(
            "Policy violations must be a non-negative integer"
        )

    with get_connection() as connection:
        cursor = connection.execute("""
            UPDATE organizations
            SET policy_violations = ?
            WHERE id = ?
        """, (
            policy_violations,
            organization_id,
        ))

        return cursor.rowcount > 0


def set_organization_status(organization_id, is_active):
    if type(is_active) is not bool:
        raise ValueError("is_active must be true or false")

    with get_connection() as connection:
        cursor = connection.execute("""
            UPDATE organizations
            SET is_active = ?
            WHERE id = ?
        """, (
            int(is_active),
            organization_id,
        ))

        return cursor.rowcount > 0


def get_trust_level(score):
    if score >= 80:
        return "high"
    elif score >= 50:
        return "medium"

    return "low"