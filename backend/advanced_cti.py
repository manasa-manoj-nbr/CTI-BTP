from contextlib import closing
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request, g
import os
import tempfile

from werkzeug.exceptions import RequestEntityTooLarge

from backend.authentication import require_auth
from backend.pdf_cti_extractor import extract_cti_from_pdf
from backend.advanced_cti_processor import (
    CATEGORIES,
    CONFIDENCES,
    INDICATOR_TYPES,
    RELIABILITIES,
    SECTORS,
    SEVERITIES,
    SOURCE_TYPES,
    normalize_cti,
    validate_indicator,
)
from backend.cti_knowledge_graph import build_knowledge_graph
from backend.database import get_connection
from backend.temporal_intelligence import analyze_temporal_intelligence

advanced_cti_bp = Blueprint("advanced_cti", __name__)

# --------------------------------------------------
# CONSTANTS
# --------------------------------------------------

SEVERITY_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
RELIABILITY_ORDER = {"unverified": 0, "partial": 1, "verified": 2}

SEVERITY_SCORES = {"low": 20, "medium": 40, "high": 70, "critical": 90, "unknown": 20}
CONFIDENCE_SCORES = {"low": 40, "medium": 65, "high": 90, "unknown": 40}
RELIABILITY_SCORES = {"unverified": 30, "partial": 60, "verified": 90}

MAX_TITLE = 200
MAX_TEXT = 10000

REQUIRED_FIELDS = [
    "organization_id",
    "category",
    "indicator_type",
    "title",
    "description",
    "severity",
    "confidence",
    "sharing_sector",
    "source_type",
    "source_reliability",
]


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def error(message, status=400, **extra):
    return jsonify({"error": message, **extra}), status


def calculate_risk(severity, confidence, reliability, corroborating_orgs):
    """Prototype risk score (0-100). Not a statistical measure."""
    base = (
        SEVERITY_SCORES.get(severity, 20) * 0.50
        + CONFIDENCE_SCORES.get(confidence, 40) * 0.30
        + RELIABILITY_SCORES.get(reliability, 30) * 0.20
    )

    # +5 per additional independent organization, capped at +15.
    bonus = min(max(corroborating_orgs - 1, 0) * 5, 15)
    score = min(round(base + bonus), 100)

    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    return score, level


def parse_timestamp(value):
    """Return a timezone-aware datetime or raise ValueError."""
    if not isinstance(value, str) or len(value) > 50:
        raise ValueError("observed_at must be an ISO timestamp string.")
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def match_sector(value):
    lookup = {sector.lower(): sector for sector in SECTORS}
    return lookup.get(value.strip().lower())


def parse_submission(data):
    """Validate a payload. Returns (clean_dict, None) or (None, message)."""
    if not isinstance(data, dict):
        return None, "Send the submission as a JSON object."

    missing = [
        field for field in REQUIRED_FIELDS
        if data.get(field) is None
        or (isinstance(data[field], str) and not data[field].strip())
    ]
    if missing:
        return None, ("Missing required fields: " + ", ".join(missing))

    raw_org = data["organization_id"]
    if isinstance(raw_org, bool):
        return None, "organization_id must be an integer."
    try:
        organization_id = int(raw_org)
    except (TypeError, ValueError):
        return None, "organization_id must be an integer."
    if organization_id < 1:
        return None, "Invalid organization_id."

    clean = {"organization_id": organization_id}

    choices = [
        ("category", CATEGORIES, "Unsupported CTI category."),
        ("indicator_type", INDICATOR_TYPES, "Unsupported indicator type."),
        ("severity", SEVERITIES, "Unsupported severity."),
        ("confidence", CONFIDENCES, "Unsupported confidence."),
        ("source_type", SOURCE_TYPES, "Unsupported source type."),
        ("source_reliability", RELIABILITIES, "Unsupported source reliability."),
    ]
    for field, allowed, message in choices:
        value = str(data[field]).strip().lower()
        if value not in allowed:
            return None, message
        clean[field] = value

    sector = match_sector(str(data["sharing_sector"]))
    if sector is None:
        return None, "Unsupported sharing sector."
    clean["sharing_sector"] = sector

    title = str(data["title"]).strip()
    description = str(data["description"]).strip()
    if not title or not description:
        return None, "Title and description cannot be empty."
    if len(title) > MAX_TITLE or len(description) > MAX_TEXT:
        return None, (
            f"Title must be at most {MAX_TITLE} characters and "
            f"description at most {MAX_TEXT}."
        )
    clean["title"] = title
    clean["description"] = description

    try:
        clean["indicator_value"] = validate_indicator(
            clean["indicator_type"], data.get("indicator_value", "")
        )
    except ValueError as exc:
        return None, str(exc)

    observed_at = data.get("observed_at")
    if observed_at is not None:
        try:
            parsed = parse_timestamp(observed_at)
        except ValueError as exc:
            message = str(exc)
            if "ISO timestamp string" not in message:
                message = "Invalid observed_at timestamp."
            return None, message
        if parsed > datetime.now(timezone.utc):
            return None, "observed_at cannot be in the future."
    clean["observed_at"] = observed_at

    evidence = data.get("evidence")
    if evidence is None:
        evidence = ""
    if not isinstance(evidence, str) or len(evidence) > MAX_TEXT:
        return None, f"Evidence must be text of at most {MAX_TEXT} characters."
    clean["evidence"] = evidence

    return clean, None


def insert_submission(connection, record_id, c):
    connection.execute(
        """
        INSERT INTO cti_submissions (
            cti_record_id, organization_id, source_type,
            source_reliability, observed_at, submitted_severity,
            confidence, evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record_id,
            c["organization_id"],
            c["source_type"],
            c["source_reliability"],
            c.get("observed_at"),
            c["severity"],
            c["confidence"],
            c["evidence"],
        ),
    )


def submission_stats(connection, record_id):
    """Return (total submissions, distinct orgs, best reliability)."""
    total, orgs = connection.execute(
        """
        SELECT COUNT(*), COUNT(DISTINCT organization_id)
        FROM cti_submissions
        WHERE cti_record_id = ?
        """,
        (record_id,),
    ).fetchone()

    rows = connection.execute(
        "SELECT source_reliability FROM cti_submissions WHERE cti_record_id = ?",
        (record_id,),
    ).fetchall()
    best = max(
        (row["source_reliability"] for row in rows),
        key=lambda v: RELIABILITY_ORDER.get(v, 0),
        default="unverified",
    )
    return total, orgs, best


# --------------------------------------------------
# SUBMIT CTI
# --------------------------------------------------

@advanced_cti_bp.route("/api/cti/submit", methods=["POST"])
@require_auth
def submit_cti():
    c, problem = parse_submission(request.get_json(silent=True))
    if problem:
        return error(problem)

    if c["organization_id"] != g.current_user["organization_id"]:
        return error("You can only submit CTI for your own organization", 403)

    with closing(get_connection()) as connection:
        try:
            # Take the write lock up front so duplicate detection and the
            # insert are atomic across concurrent requests.
            connection.execute("BEGIN IMMEDIATE")

            organization = connection.execute(
                "SELECT id, name FROM organizations WHERE id = ?",
                (c["organization_id"],),
            ).fetchone()
            if organization is None:
                connection.rollback()
                return error("Organization not found. Register it first.", 404)

            existing = None
            if c["indicator_type"] != "none":
                existing = connection.execute(
                    """
                    SELECT id, severity, confidence
                    FROM cti_records
                    WHERE indicator_type = ?
                      AND indicator_value = ?
                      AND sharing_sector = ?
                    ORDER BY id
                    LIMIT 1
                    """,
                    (
                        c["indicator_type"],
                        c["indicator_value"],
                        c["sharing_sector"],
                    ),
                ).fetchone()

            # ---------- duplicate: merge into existing record ----------
            if existing:
                record_id = existing["id"]
                insert_submission(connection, record_id, c)

                final_severity = max(
                    [existing["severity"], c["severity"]],
                    key=lambda v: SEVERITY_ORDER.get(v, 0),
                )
                final_confidence = max(
                    [existing["confidence"], c["confidence"]],
                    key=lambda v: CONFIDENCE_ORDER.get(v, 0),
                )
                total, orgs, final_reliability = submission_stats(
                    connection, record_id
                )
                risk_score, risk_level = calculate_risk(
                    final_severity, final_confidence, final_reliability, orgs
                )

                connection.execute(
                    """
                    UPDATE cti_records
                    SET severity = ?, confidence = ?,
                        risk_score = ?, risk_level = ?,
                        status = 'Under Review'
                    WHERE id = ?
                    """,
                    (
                        final_severity,
                        final_confidence,
                        risk_score,
                        risk_level,
                        record_id,
                    ),
                )
                connection.commit()

                return jsonify({
                    "message": "Duplicate indicator detected; submission recorded.",
                    "duplicate": True,
                    "record_id": record_id,
                    "submission_count": total,
                    "corroborating_organizations": orgs,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                }), 200

            # ---------- new record ----------
            stix_data = normalize_cti(
                c["category"],
                c["indicator_type"],
                c["indicator_value"],
                c["title"],
                c["description"],
                c["severity"],
            )
            risk_score, risk_level = calculate_risk(
                c["severity"], c["confidence"], c["source_reliability"], 1
            )

            cursor = connection.execute(
                """
                INSERT INTO cti_records (
                    category, indicator_type, indicator_value, title,
                    description, severity, confidence, sharing_sector,
                    stix_data, risk_score, risk_level, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    c["category"],
                    c["indicator_type"],
                    c["indicator_value"],
                    c["title"],
                    c["description"],
                    c["severity"],
                    c["confidence"],
                    c["sharing_sector"],
                    stix_data,
                    risk_score,
                    risk_level,
                    "Under Review",
                ),
            )
            record_id = cursor.lastrowid
            insert_submission(connection, record_id, c)
            connection.commit()

            return jsonify({
                "message": "CTI submitted and normalized successfully.",
                "duplicate": False,
                "record_id": record_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "stix": stix_data,
            }), 201

        except Exception:
            connection.rollback()
            current_app.logger.exception("CTI submission failed.")
            return error("The CTI submission could not be processed.", 500)


# --------------------------------------------------
# LIST ADVANCED CTI RECORDS
# --------------------------------------------------

@advanced_cti_bp.route("/api/cti/advanced", methods=["GET"])
def list_advanced_cti():
    limit = min(max(request.args.get("limit", default=100, type=int), 1), 500)
    offset = max(request.args.get("offset", default=0, type=int), 0)
    org_id = request.args.get("organization_id", default=None, type=int)

    with closing(get_connection()) as connection:
        if org_id:
            rows = connection.execute(
                """
                SELECT DISTINCT r.id, r.category, r.indicator_type, r.indicator_value, r.title,
                       r.description, r.severity, r.confidence, r.sharing_sector,
                       r.stix_data, r.risk_score, r.risk_level, r.status, r.created_at
                FROM cti_records r
                JOIN cti_submissions s ON s.cti_record_id = r.id
                WHERE s.organization_id = ?
                ORDER BY r.id DESC
                LIMIT ? OFFSET ?
                """,
                (org_id, limit, offset),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT id, category, indicator_type, indicator_value, title,
                       description, severity, confidence, sharing_sector,
                       stix_data, risk_score, risk_level, status, created_at
                FROM cti_records
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

    return jsonify({
        "records": [dict(row) for row in rows],
        "limit": limit,
        "offset": offset,
    }), 200


# --------------------------------------------------
# LIST SUBMISSIONS FOR ONE CTI RECORD
# --------------------------------------------------

@advanced_cti_bp.route(
    "/api/cti/advanced/<int:record_id>/submissions", methods=["GET"]
)
def list_cti_submissions(record_id):
    with closing(get_connection()) as connection:
        record = connection.execute(
            "SELECT id FROM cti_records WHERE id = ?", (record_id,)
        ).fetchone()
        if record is None:
            return error("CTI record not found.", 404)

        rows = connection.execute(
            """
            SELECT id, cti_record_id, organization_id, source_type,
                   source_reliability, observed_at, submitted_severity,
                   confidence, evidence, created_at
            FROM cti_submissions
            WHERE cti_record_id = ?
            ORDER BY created_at, id
            """,
            (record_id,),
        ).fetchall()

    return jsonify({"submissions": [dict(row) for row in rows]}), 200


# --------------------------------------------------
# TEMPORAL EVIDENCE TIMELINE
# --------------------------------------------------

@advanced_cti_bp.route(
    "/api/cti/advanced/<int:record_id>/evidence-timeline", methods=["GET"]
)
def get_cti_evidence_timeline(record_id):
    """
    Source submission history for one CTI record.

    Observation time and submission time stay distinct, and severity
    disagreements are reported rather than hidden.
    """
    with closing(get_connection()) as connection:
        record_row = connection.execute(
            """
            SELECT id, title, category, indicator_type, indicator_value,
                   severity, confidence, risk_score, risk_level, created_at
            FROM cti_records
            WHERE id = ?
            """,
            (record_id,),
        ).fetchone()
        if record_row is None:
            return error("CTI record not found.", 404)

        rows = connection.execute(
            """
            SELECT
                s.id AS submission_id,
                s.cti_record_id,
                s.organization_id,
                o.name AS organization_name,
                o.sector AS organization_sector,
                s.source_type,
                s.source_reliability,
                s.observed_at,
                s.submitted_severity,
                s.confidence,
                s.evidence,
                s.created_at AS submitted_at
            FROM cti_submissions AS s
            LEFT JOIN organizations AS o ON o.id = s.organization_id
            WHERE s.cti_record_id = ?
            ORDER BY s.created_at, s.id
            """,
            (record_id,),
        ).fetchall()

    submissions = [dict(row) for row in rows]

    def distinct_values(key):
        return sorted({
            str(item[key]).strip().lower()
            for item in submissions
            if item[key] is not None and str(item[key]).strip()
        })

    severity_values = distinct_values("submitted_severity")
    reliability_values = distinct_values("source_reliability")

    total = len(submissions)
    with_time = sum(
        1 for item in submissions
        if isinstance(item["observed_at"], str) and item["observed_at"].strip()
    )

    if with_time == 0:
        observation_time_status = "missing"
    elif with_time < total:
        observation_time_status = "partial"
    else:
        observation_time_status = "complete"

    return jsonify({
        "record": dict(record_row),
        "submission_count": total,
        "severity_conflict": len(severity_values) > 1,
        "reported_severities": severity_values,
        "reliability_levels": reliability_values,
        "observation_time_status": observation_time_status,
        "timeline": submissions,
    }), 200


# --------------------------------------------------
# CTI KNOWLEDGE GRAPH API
# --------------------------------------------------

@advanced_cti_bp.route("/api/cti/knowledge-graph", methods=["GET"])
def get_knowledge_graph():
    """Read-only view of the CTI knowledge graph."""
    try:
        return jsonify(build_knowledge_graph()), 200
    except Exception:
        current_app.logger.exception("Failed to build CTI knowledge graph")
        return error("Unable to build the CTI knowledge graph", 500)

# --------------------------------------------------
# TEMPORAL INTELLIGENCE API
# --------------------------------------------------

@advanced_cti_bp.route("/api/cti/temporal-intelligence", methods=["GET"])
def get_temporal_intelligence():
    """Return read-only temporal CTI evidence analysis."""
    try:
        report = analyze_temporal_intelligence()
        return jsonify(report), 200
    except Exception:
        current_app.logger.exception("Temporal intelligence analysis failed")
        return error("Temporal intelligence analysis failed.", 500)


# --------------------------------------------------
# PDF-TO-CTI EXTRACTION API
# --------------------------------------------------

MAX_UPLOAD_BYTES = 15 * 1024 * 1024


@advanced_cti_bp.route("/api/cti/extract-pdf", methods=["POST"])
@require_auth
def extract_cti_pdf():
    """Extract candidate CTI findings from an authenticated PDF upload.

    This endpoint does not write extracted findings to the database.
    """
    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        return error("Please upload a PDF using the 'file' field.", 400)

    if not uploaded_file.filename.lower().endswith(".pdf"):
        return error("Only PDF files are supported.", 400)

    temporary_path = None

    try:
        # Store the upload in a temporary file, not in the project directory.
        with tempfile.NamedTemporaryFile(
            prefix="cti_upload_",
            suffix=".pdf",
            delete=False,
        ) as temporary_file:
            temporary_path = temporary_file.name
            total_bytes = 0

            while True:
                chunk = uploaded_file.stream.read(64 * 1024)

                if not chunk:
                    break

                total_bytes += len(chunk)

                if total_bytes > MAX_UPLOAD_BYTES:
                    return error("PDF exceeds the 15 MB upload limit.", 413)

                temporary_file.write(chunk)

        # Basic file signature check; the extractor also validates the PDF.
        with open(temporary_path, "rb") as pdf_file:
            if not pdf_file.read(5).startswith(b"%PDF-"):
                return error("The uploaded file is not a valid PDF file.", 400)

        result = extract_cti_from_pdf(temporary_path)

        return jsonify({
            "message": "PDF extraction completed. Review findings before use.",
            "organization_id": g.current_user["organization_id"],
            "filename": os.path.basename(uploaded_file.filename),
            "extraction": result,
            "saved_to_database": False,
        }), 200

    except ValueError as exc:
        return error(str(exc), 400)

    except Exception:
        current_app.logger.exception("PDF-to-CTI extraction failed")
        return error("Unable to process the uploaded PDF.", 500)

    finally:
        if temporary_path and os.path.exists(temporary_path):
            try:
                os.remove(temporary_path)
            except OSError:
                current_app.logger.warning(
                    "Could not remove temporary PDF file."
                )
