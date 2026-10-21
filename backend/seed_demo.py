"""Seed the database with demo organizations, users, and sample CTI records.

Run from the project root:
    python -m backend.seed_demo
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import (
    get_connection,
    initialize_database,
    register_organization,
    get_all_organizations,
    update_organization_trust_score,
)
from backend.authentication import register_user

DEMO_ORGS = [
    {"name": "Alpha Bank",       "sector": "Finance",    "trust": 85},
    {"name": "City Hospital",    "sector": "Healthcare", "trust": 55},
    {"name": "Delta Insurance",  "sector": "Finance",    "trust": 45},
]

DEMO_USERS = [
    {"name": "Alice Martin",  "email": "alice@alphabank.com",       "password": "Demo1234!", "org": "Alpha Bank"},
    {"name": "Bob Chen",      "email": "bob@cityhospital.com",      "password": "Demo1234!", "org": "City Hospital"},
    {"name": "Carol Davis",   "email": "carol@deltainsurance.com",  "password": "Demo1234!", "org": "Delta Insurance"},
]


def seed():
    initialize_database()

    existing_orgs = {o["name"] for o in get_all_organizations()}
    org_map = {}

    for org in DEMO_ORGS:
        if org["name"] in existing_orgs:
            print(f"  [skip] Org '{org['name']}' already exists")
            for o in get_all_organizations():
                if o["name"] == org["name"]:
                    org_map[org["name"]] = o["id"]
                    break
        else:
            oid = register_organization(org["name"], org["sector"], org["trust"])
            update_organization_trust_score(oid, org["trust"])
            org_map[org["name"]] = oid
            print(f"  [created] Org '{org['name']}' (id={oid}, trust={org['trust']})")

    conn = get_connection()
    existing_emails = {
        row["email"]
        for row in conn.execute("SELECT email FROM users").fetchall()
    }
    conn.close()

    for u in DEMO_USERS:
        if u["email"] in existing_emails:
            print(f"  [skip] User '{u['email']}' already exists")
            continue
        oid = org_map.get(u["org"])
        if not oid:
            print(f"  [error] Org '{u['org']}' not found for user '{u['email']}'")
            continue
        try:
            register_user(u["name"], u["email"], u["password"], oid)
            print(f"  [created] User '{u['email']}' -> {u['org']}")
        except Exception as e:
            print(f"  [error] User '{u['email']}': {e}")

    print("\nDemo accounts ready:")
    print("  alice@alphabank.com      / Demo1234!  (Alpha Bank, Finance, High trust)")
    print("  bob@cityhospital.com     / Demo1234!  (City Hospital, Healthcare, Medium trust)")
    print("  carol@deltainsurance.com / Demo1234!  (Delta Insurance, Finance, Low trust)")


if __name__ == "__main__":
    seed()
