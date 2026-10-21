"""Incentive wallet for CTI sharing rewards.

Organisations earn tokens for sharing quality CTI and lose tokens for
violations or revocations.  The wallet balance is cosmetic — it does
not gate decryption (that is the trust score's job) — but it makes
the incentive loop visible and gamified.

Token schedule:
    +10  shared a CTI record
    +5   high-confidence submission bonus
    +3   cross-sector sharing bonus
    -20  policy violation
    -50  access revocation
"""

from backend.database import get_connection

REWARD_SHARE = 10.0
REWARD_HIGH_CONFIDENCE = 5.0
REWARD_CROSS_SECTOR = 3.0
PENALTY_VIOLATION = -20.0
PENALTY_REVOCATION = -50.0


def _ensure_wallet(conn, org_id):
    row = conn.execute(
        "SELECT id FROM incentive_wallet WHERE organization_id = ?",
        (org_id,),
    ).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO incentive_wallet (organization_id, balance) VALUES (?, 0)",
            (org_id,),
        )
        conn.commit()


def _transact(org_id, amount, reason, reference_id=None):
    with get_connection() as conn:
        _ensure_wallet(conn, org_id)

        wallet = conn.execute(
            "SELECT balance FROM incentive_wallet WHERE organization_id = ?",
            (org_id,),
        ).fetchone()
        new_balance = max(0, round(wallet["balance"] + amount, 2))

        if amount > 0:
            conn.execute(
                "UPDATE incentive_wallet SET balance = ?, lifetime_earned = lifetime_earned + ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE organization_id = ?",
                (new_balance, amount, org_id),
            )
        else:
            conn.execute(
                "UPDATE incentive_wallet SET balance = ?, lifetime_spent = lifetime_spent + ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE organization_id = ?",
                (new_balance, abs(amount), org_id),
            )

        conn.execute(
            "INSERT INTO incentive_transactions "
            "(organization_id, amount, reason, reference_id, balance_after) "
            "VALUES (?, ?, ?, ?, ?)",
            (org_id, amount, reason, reference_id, new_balance),
        )
        conn.commit()

    return {"org_id": org_id, "amount": amount, "reason": reason,
            "balance": new_balance}


def reward_share(org_id, record_id=None):
    if record_id is not None:
        with get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM incentive_transactions WHERE organization_id = ? AND reason = ? AND reference_id = ?",
                (org_id, "shared_cti", str(record_id)),
            ).fetchone()
            if existing:
                return {"org_id": org_id, "amount": 0, "reason": "already_rewarded", "balance": None}
    return _transact(org_id, REWARD_SHARE, "shared_cti", str(record_id))


def reward_high_confidence(org_id, record_id=None):
    if record_id is not None:
        with get_connection() as conn:
            existing = conn.execute(
                "SELECT id FROM incentive_transactions WHERE organization_id = ? AND reason = ? AND reference_id = ?",
                (org_id, "high_confidence_bonus", str(record_id)),
            ).fetchone()
            if existing:
                return {"org_id": org_id, "amount": 0, "reason": "already_rewarded", "balance": None}
    return _transact(org_id, REWARD_HIGH_CONFIDENCE, "high_confidence_bonus",
                     str(record_id))


def reward_cross_sector(org_id, record_id=None):
    return _transact(org_id, REWARD_CROSS_SECTOR, "cross_sector_bonus",
                     str(record_id))


def penalize_violation(org_id):
    return _transact(org_id, PENALTY_VIOLATION, "policy_violation")


def penalize_revocation(org_id):
    return _transact(org_id, PENALTY_REVOCATION, "access_revocation")


def get_wallet(org_id):
    with get_connection() as conn:
        _ensure_wallet(conn, org_id)
        row = conn.execute(
            "SELECT * FROM incentive_wallet WHERE organization_id = ?",
            (org_id,),
        ).fetchone()
        return dict(row) if row else None


def get_transactions(org_id, limit=30):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM incentive_transactions WHERE organization_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (org_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_leaderboard():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT w.organization_id, o.name, o.sector, o.trust_score,
                   w.balance, w.lifetime_earned, w.lifetime_spent, w.updated_at
            FROM incentive_wallet w
            JOIN organizations o ON w.organization_id = o.id
            ORDER BY w.balance DESC
        """).fetchall()
        ranked = []
        for i, r in enumerate(rows, 1):
            d = dict(r)
            d["rank"] = i
            if d["balance"] >= 100:
                d["tier"] = "Premium"
            elif d["balance"] >= 50:
                d["tier"] = "Standard"
            else:
                d["tier"] = "Basic"
            ranked.append(d)
        return ranked
