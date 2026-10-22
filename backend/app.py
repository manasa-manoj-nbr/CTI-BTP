from backend.graph_analytics import analyze_graph_centrality
from backend.ai_predictor import predict_threat_severity
from backend.temporal_engine import calculate_decayed_risk
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.crypto_engine import encrypt_payload, decrypt_payload, revoke_access, restore_access, get_system_status
from backend.trust_engine import compute_trust_score, get_trust_tier, generate_policy_string
from backend.policy_engine import classify, build_policy, policy_to_string
from backend.crypto.service import service as prrabe_service, get_events as get_prrabe_events
from backend import incentive_engine
import ipaddress
import json
import re
import sqlite3
import threading
import time
from datetime import datetime

from flask import Flask, g, jsonify, request
from flask_cors import CORS

from backend.advanced_cti import advanced_cti_bp
from backend.authentication import (
    authenticate_user, create_access_token, register_user, require_auth, verify_access_token,
)
from backend.correlation import correlate_indicators
from backend.cti_processor import process_cti
from backend.database import (
    get_all_indicators, initialize_database, save_indicator, get_connection,
)
from backend.organizations import (
    get_all_organizations, get_organization, register_organization,
    set_organization_status, update_organization, update_policy_violations, update_trust_score,
)
from backend.policy_engine import (
    generate_access_policy, generate_advanced_access_policy,
)
from backend.risk_analysis import calculate_risk
from backend.knowledge_graph import build_temporal_graph, detect_contradictions


import re as _re

def _hide_stored_policy(policy_str):
    """Replace attribute values with *** in stored policy strings to preserve policy hiding."""
    if not policy_str:
        return policy_str
    return _re.sub(r'(?<=:)[A-Za-z0-9_]+', '***', policy_str)


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------
MAX_REQUEST_BYTES = 16 * 1024 * 1024
LEGACY_SECTORS = ["Finance", "Healthcare", "Education", "Technology", "Government", "Energy"]
LEGACY_SEVERITIES = ("low", "medium", "high", "critical")
MAX_NAME_LENGTH = 100
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128

LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 5 * 60
REGISTER_MAX_ATTEMPTS = 10
REGISTER_WINDOW_SECONDS = 60 * 60

DEV_ORIGINS = [f"http://{host}:{port}" for host in ("localhost", "127.0.0.1") for port in (5173, 5174, 5175)]
EXTRA_ORIGINS = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": DEV_ORIGINS + EXTRA_ORIGINS,
            "allow_headers": ["Authorization", "Content-Type"],
            "expose_headers": ["Retry-After"],
            "max_age": 600,
        }
    },
)

app.register_blueprint(advanced_cti_bp)
initialize_database()


# --------------------------------------------------
# RATE LIMITING
# --------------------------------------------------
class AttemptLimiter:
    def __init__(self, max_attempts, window_seconds, max_keys=10000):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self.max_keys = max_keys
        self._attempts = {}
        self._lock = threading.Lock()

    def _recent(self, key, now):
        stamps = [stamp for stamp in self._attempts.get(key, []) if now - stamp < self.window]
        if stamps:
            self._attempts[key] = stamps
        else:
            self._attempts.pop(key, None)
        return stamps

    def retry_after(self, key):
        now = time.monotonic()
        with self._lock:
            stamps = self._recent(key, now)
            if len(stamps) < self.max_attempts:
                return 0
            return max(1, int(self.window - (now - stamps[0])) + 1)

    def record(self, key):
        now = time.monotonic()
        with self._lock:
            if len(self._attempts) >= self.max_keys:
                self._attempts.clear()
            self._recent(key, now)
            self._attempts.setdefault(key, []).append(now)

    def clear(self, key):
        with self._lock:
            self._attempts.pop(key, None)

login_limiter = AttemptLimiter(LOGIN_MAX_FAILURES, LOGIN_WINDOW_SECONDS)
register_limiter = AttemptLimiter(REGISTER_MAX_ATTEMPTS, REGISTER_WINDOW_SECONDS)


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def error_response(message, status=400, **extra):
    return jsonify({"error": message, **extra}), status

def too_many_requests(wait_seconds):
    response = jsonify({"error": "Too many attempts.", "retry_after_seconds": wait_seconds})
    response.status_code = 429
    response.headers["Retry-After"] = str(wait_seconds)
    return response

def get_json_object():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None

def valid_positive_id(value):
    return type(value) is int and value > 0

def organization_not_found_response(organization_id):
    return error_response("Organization not found", 404, organization_id=organization_id)

def clean_email(value):
    return value.strip().lower() if isinstance(value, str) else value

def public_user(user):
    return {key: value for key, value in user.items() if "password" not in key.lower()}

def bearer_token():
    parts = request.headers.get("Authorization", "").split()
    return parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else None

def current_user():
    token = bearer_token()
    if not token:
        return None
    try:
        return verify_access_token(token)
    except Exception:
        app.logger.exception("Token verification failed")
        return None

def defang_and_normalize(value):
    if not isinstance(value, str):
        return value
    value = value.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    value = value.replace("hxxp", "http").replace("hxxps", "https")
    value = value.replace("[", "").replace("]", "")
    return value.strip().lower()


# --------------------------------------------------
# GLOBAL HANDLERS
# --------------------------------------------------
@app.after_request
def add_response_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response

@app.errorhandler(404)
def handle_not_found(_error):
    return error_response("Resource not found", 404)

@app.errorhandler(405)
def handle_method_not_allowed(_error):
    return error_response("Method not allowed", 405)

@app.errorhandler(413)
def handle_too_large(_error):
    return error_response(f"The request is too large (limit {MAX_REQUEST_BYTES // (1024*1024)} MiB).", 413)

@app.errorhandler(500)
def handle_server_error(_error):
    return error_response("Internal server error", 500)


# --------------------------------------------------
# ROUTES
# --------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"project": "CTI-BTP", "status": "Backend running"}), 200

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/api/ai/predict", methods=["GET"])
@require_auth
def get_ai_prediction():
    try:
        result = predict_threat_severity()
        return jsonify(result), 200
    except Exception as e:
        return error_response(f"AI prediction failed: {str(e)}", 500)

@app.route("/api/attack/matrix", methods=["GET"])
@require_auth
def get_attack_matrix():
    try:
        with get_connection() as conn:
            conn.row_factory = sqlite3.Row
            orgs = conn.execute("SELECT id, name FROM organizations").fetchall()
            org_list = [dict(o) for o in orgs]

            rows = conn.execute("""
                SELECT org.id as org_id, org.name as org_name, rec.indicator_value as technique
                FROM cti_submissions sub
                JOIN organizations org ON sub.organization_id = org.id
                JOIN cti_records rec ON sub.cti_record_id = rec.id
                WHERE rec.indicator_type = 'attack_technique'
            """).fetchall()

        org_techniques = {}
        for row in rows:
            org_name = row["org_name"]
            tech = row["technique"]
            if org_name not in org_techniques:
                org_techniques[org_name] = set()
            org_techniques[org_name].add(tech)

        global_techs = {}
        for techs in org_techniques.values():
            for t in techs:
                global_techs[t] = global_techs.get(t, 0) + 1

        suggestions = {}
        for target_org, target_techs in org_techniques.items():
            tech_scores = {}
            
            for other_org, other_techs in org_techniques.items():
                if target_org == other_org: continue

                intersection = len(target_techs.intersection(other_techs))
                union = len(target_techs.union(other_techs))
                similarity = intersection / union if union > 0 else 0

                if similarity > 0:
                    unseen_techs = other_techs - target_techs
                    for tech in unseen_techs:
                        global_pop = global_techs.get(tech, 1) / len(org_list)
                        weight = (similarity * 0.7) + (global_pop * 0.3)
                        tech_scores[tech] = tech_scores.get(tech, 0) + weight

            sorted_suggestions = sorted(tech_scores.items(), key=lambda x: x[1], reverse=True)
            suggestions[target_org] = [
                {"tech": tech, "confidence": round(min(score * 100, 99), 1)} 
                for tech, score in sorted_suggestions[:5]
            ]

        return jsonify({
            "organizations": org_list,
            "org_techniques": {k: list(v) for k, v in org_techniques.items()},
            "global_frequency": global_techs,
            "suggestions": suggestions
        }), 200
    except Exception as e:
        app.logger.exception("Failed to build ATT&CK matrix")
        return error_response(f"Failed to build ATT&CK matrix: {str(e)}", 500)

@app.route("/api/graph/temporal", methods=["GET"])
@require_auth
def get_temporal_graph():
    try:
        org_id = request.args.get('org_id', type=int)
        
        if org_id:
            with get_connection() as conn:
                conn.row_factory = sqlite3.Row
                org = conn.execute("SELECT id, name, sector FROM organizations WHERE id = ?", (org_id,)).fetchone()
                if not org:
                    return jsonify({"nodes": [], "links": []}), 200
                
                rows = conn.execute("""
                    SELECT DISTINCT rec.id, rec.indicator_value, rec.indicator_type, rec.category
                    FROM cti_submissions sub
                    JOIN cti_records rec ON sub.cti_record_id = rec.id
                    WHERE sub.organization_id = ?
                """, (org_id,)).fetchall()
            
            nodes = [{"id": f"org_{org['name']}", "label": org["name"], "type": "organization", "sector": org["sector"]}]
            links = []
            for row in rows:
                ioc_id = f"ioc_{row['id']}"
                nodes.append({
                    "id": ioc_id, "label": row["indicator_value"],
                    "type": row["indicator_type"], "category": row["category"]
                })
                links.append({"source": f"org_{org['name']}", "target": ioc_id, "type": "submitted"})
            return jsonify({"nodes": nodes, "links": links}), 200

        return jsonify(build_temporal_graph()), 200
    except Exception as e:
        app.logger.exception("Graph failed")
        return error_response(f"Graph failed: {str(e)}", 500)

@app.route("/api/graph/centrality", methods=["GET"])
@require_auth
def get_graph_centrality():
    try:
        return jsonify(analyze_graph_centrality()), 200
    except Exception as e:
        return error_response(f"Graph analytics failed: {str(e)}", 500)

@app.route("/api/graph/contradictions", methods=["GET"])
@require_auth
def get_contradictions():
    try:
        conflicts = detect_contradictions()
        return jsonify({"count": len(conflicts), "contradictions": conflicts}), 200
    except Exception:
        return error_response("Failed to detect contradictions", 500)

@app.route("/api/intelligence/temporal", methods=["GET"])
@require_auth
def get_temporal_intelligence():
    org_id = request.args.get('org_id', type=int)
    
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        query = """
            SELECT rec.indicator_value, rec.category, sub.observed_at, sub.submitted_severity, 
                   sub.confidence, org.name as org_name, org.sector as org_sector
            FROM cti_submissions sub
            JOIN organizations org ON sub.organization_id = org.id
            JOIN cti_records rec ON sub.cti_record_id = rec.id
        """
        params = []
        if org_id:
            query += " WHERE sub.organization_id = ?"
            params.append(org_id)
        query += " ORDER BY rec.indicator_value, sub.observed_at ASC"
        rows = conn.execute(query, params).fetchall()

    iocs = {}
    for row in rows:
        val = row["indicator_value"]
        if val not in iocs:
            iocs[val] = {"indicator_value": val, "category": row["category"], "timeline": [], "sectors": set(), "risk_score": 0, "risk_explanation": []}
        
        iocs[val]["timeline"].append({
            "date": row["observed_at"], "severity": row["submitted_severity"],
            "org": row["org_name"], "sector": row["org_sector"], "confidence": row["confidence"]
        })
        if row["org_sector"]: iocs[val]["sectors"].add(row["org_sector"])

    for val, data in iocs.items():
        score = 0
        explanations = []
        severity_map = {"low": 10, "medium": 25, "high": 40, "critical": 50}
        latest_severity = data["timeline"][-1]["severity"].lower()
        score += severity_map.get(latest_severity, 10)
        explanations.append(f"Latest severity ({latest_severity}) contributed {score} pts")
        
        vol_score = min(len(data["timeline"]) * 5, 20)
        score += vol_score
        explanations.append(f"{len(data['timeline'])} independent reports contributed {vol_score} pts")
        
        sec_score = min(len(data["sectors"]) * 10, 20)
        score += sec_score
        if sec_score > 0: explanations.append(f"Cross-sector impact contributed {sec_score} pts")
            
        score += 10
        explanations.append("Recent activity contributed 10 pts")
        
        raw_score = min(score, 100)
        data["risk_score"] = calculate_decayed_risk(raw_score, data["timeline"][-1]["date"])
        if data["risk_score"] < raw_score:
            explanations.append(f"⚠ Dynamic decay applied ({raw_score} → {data['risk_score']})")
        data["risk_explanation"] = explanations
        data["sectors"] = list(data["sectors"])

    return jsonify({"intelligence": list(iocs.values())}), 200

@app.route("/api/export/stix", methods=["GET"])
@require_auth
def export_stix_bundle():
    try:
        with get_connection() as conn:
            rows = conn.execute("SELECT stix_data FROM cti_records").fetchall()
        objects = [{"type": "identity", "spec_version": "2.1", "id": "identity--00000000-0000-0000-0000-000000000001", "created": datetime.now().isoformat() + "Z", "name": "CTI-BTP Platform", "identity_class": "system"}]
        for row in rows:
            if row["stix_data"]:
                try:
                    parsed = json.loads(row["stix_data"])
                    objects.extend(parsed.get("objects", []) if parsed.get("type") == "bundle" else [parsed])
                except Exception: pass
        return jsonify({"type": "bundle", "id": "bundle--11111111-1111-1111-1111-111111111111", "objects": objects}), 200
    except Exception as e:
        return error_response(f"STIX export failed: {str(e)}", 500)

@app.route("/api/cti", methods=["POST", "OPTIONS"])
@require_auth
def receive_cti():
    if request.method == "OPTIONS": return jsonify({}), 200
    user = g.current_user
    if not user.get("organization_id"):
        return error_response("You must belong to an organization", 403)
    data = get_json_object()
    if data is None: return error_response("Send a valid JSON object")
    
    raw_ip = data.get("ip_address")
    ip_address = defang_and_normalize(raw_ip)
    try:
        ip_obj = ipaddress.ip_address(ip_address.strip())
        if ip_obj.version != 4: return error_response("Only IPv4 addresses are supported")
    except ValueError: return error_response("Invalid IPv4 address")

    severity = data.get("severity").strip().lower()
    if severity not in LEGACY_SEVERITIES: return error_response("Severity must be low, medium, high, or critical")

    try:
        result = process_cti(ip_address=str(ip_obj), description=data.get("description"), severity=severity)
        record_id = save_indicator(ip_address=str(ip_obj), description=data.get("description"), severity=severity, stix_data=result["stix_data"], sharing_sector=data.get("sharing_sector", "All"))
        return jsonify({"message": "CTI saved", "record_id": record_id}), 201
    except Exception: return error_response("CTI processing failed", 500)

@app.route("/api/correlations", methods=["GET"])
@require_auth
def list_correlations():
    try: return jsonify({"count": len(correlate_indicators()), "correlations": correlate_indicators()}), 200
    except Exception: return error_response("CTI correlation failed", 500)

@app.route("/api/risk", methods=["GET"])
@require_auth
def get_risk_analysis():
    try: return jsonify({"count": len(calculate_risk()), "results": calculate_risk()}), 200
    except Exception: return error_response("Risk analysis failed", 500)

@app.route("/api/organizations", methods=["POST"])
def create_organization():
    try: has_organizations = bool(get_all_organizations())
    except Exception: return error_response("Organization registration failed", 500)
    if has_organizations and current_user() is None: return error_response("Authentication required", 401)
    data = get_json_object()
    if not data or not data.get("name") or not data.get("sector"): return error_response("Name and sector are required")
    try:
        org_id = register_organization(data["name"].strip(), data["sector"].strip(), 50)
        return jsonify({"message": "Organization registered", "organization": get_organization(org_id)}), 201
    except sqlite3.IntegrityError: return error_response("Organization name already exists", 409)
    except Exception: return error_response("Organization registration failed", 500)

@app.route("/api/organizations", methods=["GET"])
@require_auth
def list_organizations():
    try: return jsonify({"count": len(get_all_organizations()), "organizations": get_all_organizations()}), 200
    except Exception: return error_response("Organization retrieval failed", 500)

@app.route("/api/organizations/public", methods=["GET"])
def list_organizations_public():
    """Return org id/name/sector for the registration form (no auth)."""
    try:
        orgs = get_all_organizations()
        public = [{"id": o["id"], "name": o["name"], "sector": o["sector"]} for o in orgs]
        return jsonify({"organizations": public}), 200
    except Exception:
        return error_response("Organization retrieval failed", 500)

@app.route("/api/policies", methods=["GET"])
@require_auth
def list_policies():
    return jsonify({"count": 0, "policies": [], "note": "Evaluated on demand."}), 200

@app.route("/api/policies", methods=["POST", "OPTIONS"])
def evaluate_policy():
    if request.method == "OPTIONS": return jsonify({}), 200
    user = current_user()
    if not user: return error_response("Authentication required", 401)
    data = get_json_object()
    if not data or not valid_positive_id(data.get("organization_id")) or not valid_positive_id(data.get("indicator_id")):
        return error_response("organization_id and indicator_id must be positive integers")
    if int(data["organization_id"]) != user["organization_id"]:
        return error_response("You can only evaluate access for your own organization", 403)
    try:
        result = generate_access_policy(data["organization_id"], data["indicator_id"])
        return jsonify(result), 404 if result.get("reason") in ("Organization not found", "CTI indicator not found", "Risk assessment not available") else 200
    except Exception: return error_response("Access policy evaluation failed", 500)

@app.route("/api/advanced-policies", methods=["POST", "OPTIONS"])
def advanced_access_policy():
    if request.method == "OPTIONS": return jsonify({}), 200
    user = current_user()
    if not user: return error_response("Authentication required", 401)
    data = get_json_object()
    if not data or not valid_positive_id(data.get("organization_id")) or not valid_positive_id(data.get("record_id")):
        return error_response("organization_id and record_id must be positive integers")
    if int(data["organization_id"]) != user["organization_id"]:
        return error_response("You can only evaluate access for your own organization", 403)
    try:
        result = generate_advanced_access_policy(data["organization_id"], data["record_id"])
        try:
            with get_connection() as conn:
                org = conn.execute("SELECT name FROM organizations WHERE id = ?", (data["organization_id"],)).fetchone()
                rec = conn.execute("SELECT indicator_value FROM cti_records WHERE id = ?", (data["record_id"],)).fetchone()
                decision_val = (result.get("decision") or "").upper()
                is_granted = decision_val in ["ALLOW", "GRANTED"] or result.get("allowed") is True
                conn.execute("INSERT INTO audit_logs (organization_id, organization_name, record_value, decision, reason, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                    (data["organization_id"], org["name"] if org else "Unknown", rec["indicator_value"] if rec else "Unknown", "GRANTED" if is_granted else "DENIED", result.get("reason", ""), datetime.now().isoformat()))
                conn.commit()
        except Exception: pass
        return jsonify(result), 404 if result.get("reason") in ("Organization not found", "Advanced CTI record not found") else 200
    except Exception: return error_response("Advanced CTI access policy evaluation failed", 500)

@app.route("/api/audit-logs", methods=["GET"])
@require_auth
def get_audit_logs():
    try:
        user = current_user()
        org_id = user["organization_id"] if user else None
        with get_connection() as conn:
            conn.row_factory = sqlite3.Row
            if org_id:
                rows = conn.execute(
                    "SELECT * FROM audit_logs WHERE organization_id = ? ORDER BY id DESC LIMIT 50",
                    (org_id,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50").fetchall()
            return jsonify([dict(r) for r in rows]), 200
    except Exception as e: return error_response(f"Failed to fetch audit logs: {str(e)}", 500)

@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    data = get_json_object()
    if data is None: return error_response("Send a valid JSON object")
    limiter_key = f"register|{request.remote_addr}"
    if register_limiter.retry_after(limiter_key): return too_many_requests(register_limiter.retry_after(limiter_key))
    register_limiter.record(limiter_key)
    try:
        org_id = data.get("organization_id")
        if not org_id and data.get("new_org_name") and data.get("new_org_sector"):
            org_name = data["new_org_name"].strip()
            org_sector = data["new_org_sector"].strip()
            if len(org_name) < 2:
                return error_response("Organization name must be at least 2 characters.")
            try:
                org_id = register_organization(org_name, org_sector, 50)
            except sqlite3.IntegrityError:
                return error_response("Organization name already exists. Select it from the list instead.", 409)
        if not org_id:
            return error_response("Select an organization or create a new one.")
        user = register_user(name=data.get("name"), email=clean_email(data.get("email")), password=data.get("password"), organization_id=org_id)
        return jsonify({"message": "Registration successful", "user": public_user(user)}), 201
    except ValueError as error: return error_response(str(error), 400)
    except Exception: return error_response("Registration failed", 500)

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = get_json_object()
    if not data or not data.get("email") or not data.get("password"): return error_response("Email and password are required")
    email = clean_email(data.get("email"))
    limiter_key = f"login|{request.remote_addr}|{email}"
    if login_limiter.retry_after(limiter_key): return too_many_requests(login_limiter.retry_after(limiter_key))
    try:
        user = authenticate_user(email, data.get("password"))
        if user is None:
            login_limiter.record(limiter_key)
            return error_response("Invalid credentials", 401)
        login_limiter.clear(limiter_key)
        return jsonify({"message": "Login successful", "access_token": create_access_token(user["id"]), "token_type": "Bearer", "user": public_user(user)}), 200
    except Exception: return error_response("Login failed", 500)

@app.route("/api/auth/me", methods=["GET"])
@require_auth
def auth_me():
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    org = None
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT id, name, sector, trust_score FROM organizations WHERE id = ?", (user["organization_id"],)).fetchone()
            if row:
                org = dict(row)
    except Exception:
        pass
    return jsonify({"user": public_user(user), "organization": org}), 200

@app.route("/api/crypto/status", methods=["GET"])
@require_auth
def crypto_status():
    try:
        return jsonify(get_system_status()), 200
    except Exception as e:
        return error_response(f"Crypto status failed: {str(e)}", 500)

@app.route("/api/trust/compute/<int:org_id>", methods=["GET"])
@require_auth
def get_dynamic_trust(org_id):
    result = compute_trust_score(org_id)
    if result is None:
        return error_response("Organization not found", 404)
    return jsonify(result), 200

@app.route("/api/trust/compute-all", methods=["GET"])
@require_auth
def compute_all_trust():
    try:
        orgs = get_all_organizations()
        results = []
        for org in orgs:
            t = compute_trust_score(org["id"])
            if t:
                results.append(t)
        return jsonify({"count": len(results), "trust_scores": results}), 200
    except Exception as e:
        return error_response(f"Trust computation failed: {str(e)}", 500)

@app.route("/api/crypto/encrypt", methods=["POST", "OPTIONS"])
def crypto_encrypt():
    if request.method == "OPTIONS": return jsonify({}), 200
    user = current_user()
    if not user: return error_response("Authentication required", 401)
    data = get_json_object()
    if not data:
        return error_response("Send a valid JSON object")

    record = data.get("record", {})
    policy = data.get("policy", {})

    if data.get("auto_policy"):
        severity = record.get("severity", "low")
        sector = policy.get("sector", "All")
        risk_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
        risk_level = risk_map.get(severity.lower(), "Low")
        sensitivity, reasons = classify(risk_level)
        struct_policy = build_policy(sensitivity, [sector] if sector != "All" else ["All"])
        policy_string = policy_to_string(struct_policy)
    else:
        policy_string = None
        sensitivity = None
        reasons = None

    ciphertext = encrypt_payload(record, policy_string if policy_string else policy)

    cti_record_id = record.get("id")
    if cti_record_id:
        try:
            with get_connection() as conn:
                conn.execute("""
                    INSERT INTO encrypted_records
                        (cti_record_id, ciphertext, policy_display, sensitivity, classification,
                         encrypted_by_user_id, encrypted_by_org_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    cti_record_id, ciphertext,
                    "Hidden (PR-RABE policy hiding)",
                    sensitivity,
                    None,
                    user["id"], user["organization_id"],
                ))
        except Exception:
            pass

    result = {"ciphertext": ciphertext, "policy_hidden": True}
    if policy_string:
        result["sensitivity"] = sensitivity
    return jsonify(result), 200

@app.route("/api/crypto/encrypted", methods=["GET"])
@require_auth
def list_encrypted_records():
    try:
        user = current_user()
        user_org_id = user["organization_id"] if user else None
        with get_connection() as conn:
            rows = conn.execute("""
                SELECT er.id, er.cti_record_id, er.policy_display, er.sensitivity,
                       er.classification, er.created_at, er.encrypted_by_org_id,
                       cr.title, cr.severity, cr.category, cr.sharing_sector,
                       o.name AS encrypted_by_org
                FROM encrypted_records er
                JOIN cti_records cr ON er.cti_record_id = cr.id
                JOIN organizations o ON er.encrypted_by_org_id = o.id
                ORDER BY er.created_at DESC
            """).fetchall()
        records = []
        for r in rows:
            d = dict(r)
            d["policy_display"] = "Hidden (PR-RABE policy hiding)"
            d.pop("encrypted_by_org_id", None)
            records.append(d)
        return jsonify({"records": records}), 200
    except Exception as e:
        return error_response(f"Failed to list encrypted records: {str(e)}", 500)

@app.route("/api/crypto/decrypt", methods=["POST", "OPTIONS"])
def crypto_decrypt():
    if request.method == "OPTIONS": return jsonify({}), 200
    user = current_user()
    if not user: return error_response("Authentication required", 401)

    data = get_json_object()

    ciphertext = data.get("ciphertext")
    encrypted_record_id = data.get("encrypted_record_id")

    if encrypted_record_id and not ciphertext:
        try:
            with get_connection() as conn:
                row = conn.execute(
                    "SELECT ciphertext FROM encrypted_records WHERE id = ?",
                    (encrypted_record_id,),
                ).fetchone()
            if not row:
                return error_response("Encrypted record not found", 404)
            ciphertext = row["ciphertext"]
        except Exception as e:
            return error_response(f"Failed to fetch encrypted record: {str(e)}", 500)

    if not ciphertext:
        return error_response("No ciphertext provided", 400)

    org_id = user["organization_id"]
    with get_connection() as conn:
        org_row = conn.execute(
            "SELECT id, name, sector, trust_score FROM organizations WHERE id = ?",
            (org_id,),
        ).fetchone()
    if not org_row:
        return error_response("Organization not found", 404)

    server_attributes = {"id": org_row["id"], "sector": org_row["sector"], "trust_score": org_row["trust_score"]}
    result = decrypt_payload(ciphertext, server_attributes)
    return jsonify(result), 200 if result["success"] else 403

@app.route("/api/crypto/revoke", methods=["POST", "OPTIONS"])
@require_auth
def crypto_revoke():
    if request.method == "OPTIONS": return jsonify({}), 200
    data = get_json_object()
    org_id = data.get("organization_id")
    policy_events = []
    if data.get("action") == "restore":
        restore_access(org_id)
        action = "restore"
        try:
            from backend.policy_engine import update_trust
            trust = compute_trust_score(org_id)
            level = "High" if trust and trust["trust_score"] >= 80 else "Medium" if trust and trust["trust_score"] >= 50 else "Low"
            policy_events = update_trust(org_id, level, trigger="access_restored")
        except Exception:
            pass
    else:
        revoke_access(org_id)
        action = "revoke"
        try:
            from backend.policy_engine import update_trust
            policy_events = update_trust(org_id, "Low", trigger="access_revoked")
        except Exception:
            pass
    return jsonify({"message": "Action successful", "action": action, "policy_events": len(policy_events)}), 200

# --------------------------------------------------
# PR-RABE CEREMONY ROUTES
# --------------------------------------------------

@app.route("/api/prrabe/status", methods=["GET"])
@require_auth
def prrabe_status():
    return jsonify(prrabe_service.get_status()), 200


@app.route("/api/prrabe/init", methods=["POST"])
@require_auth
def prrabe_init():
    data = get_json_object() or {}
    num_slots = data.get("num_slots")
    if num_slots is None:
        num_slots = len(get_all_organizations())
    if not isinstance(num_slots, int) or num_slots < 2:
        return error_response("num_slots must be an integer >= 2")
    try:
        result = prrabe_service.init_system(num_slots)
        return jsonify(result), 200
    except RuntimeError as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/keygen", methods=["POST"])
@require_auth
def prrabe_keygen():
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    data = get_json_object() or {}
    org_id = data.get("organization_id", user["organization_id"])
    if org_id != user["organization_id"]:
        return error_response("You can only generate keys for your own organization", 403)
    org = get_organization(org_id)
    if not org:
        return error_response("Organization not found", 404)

    trust = compute_trust_score(org_id)
    trust_tier = get_trust_tier(trust["trust_score"]) if trust else "LOW"

    try:
        result = prrabe_service.register_org(
            org_id=org_id,
            org_name=org["name"],
            sector=org["sector"],
            trust_tier=trust_tier,
        )
        return jsonify(result), 200
    except RuntimeError as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/aggregate", methods=["POST"])
@require_auth
def prrabe_aggregate():
    try:
        result = prrabe_service.run_aggregate()
        return jsonify(result), 200
    except RuntimeError as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/complete-ceremony", methods=["POST"])
@require_auth
def prrabe_complete_ceremony():
    """One-click ceremony: init CRS, keygen for all orgs, aggregate."""
    orgs = get_all_organizations()
    if len(orgs) < 2:
        return error_response("Need at least 2 organizations", 400)

    try:
        init_result = prrabe_service.init_system(len(orgs))

        with get_connection() as conn:
            conn.execute("DELETE FROM encrypted_records")
            conn.commit()

        keygen_results = []
        for org in orgs:
            trust = compute_trust_score(org["id"])
            trust_tier = get_trust_tier(trust["trust_score"]) if trust else "LOW"
            kg = prrabe_service.register_org(
                org_id=org["id"],
                org_name=org["name"],
                sector=org["sector"],
                trust_tier=trust_tier,
            )
            keygen_results.append({"org": org["name"], **kg})

        agg_result = prrabe_service.run_aggregate()

        return jsonify({
            "status": "ok",
            "init": init_result,
            "keygen": keygen_results,
            "aggregate": agg_result,
            "note": "Full ceremony completed. System ready for encrypt/decrypt.",
        }), 200
    except RuntimeError as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/encrypt", methods=["POST"])
@require_auth
def prrabe_encrypt():
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    data = get_json_object()
    if not data or not data.get("record_id"):
        return error_response("record_id is required")

    record_id = data["record_id"]
    with get_connection() as conn:
        rec = conn.execute(
            "SELECT * FROM cti_records WHERE id = ?", (record_id,)
        ).fetchone()
    if not rec:
        return error_response("CTI record not found", 404)
    rec = dict(rec)

    with get_connection() as conn:
        owner_sub = conn.execute(
            "SELECT organization_id FROM cti_submissions WHERE cti_record_id = ? ORDER BY id LIMIT 1",
            (record_id,),
        ).fetchone()
    if owner_sub and owner_sub["organization_id"] != user["organization_id"]:
        return error_response("Only the submitting organization can encrypt its own CTI records", 403)

    policy_string = data.get("policy")
    if not policy_string:
        policy_string = generate_policy_string(rec["severity"], rec["sharing_sector"])

    payload = {
        "title": rec["title"],
        "category": rec["category"],
        "indicator_type": rec["indicator_type"],
        "indicator_value": rec["indicator_value"],
        "severity": rec["severity"],
        "confidence": rec["confidence"],
        "description": rec["description"],
        "sharing_sector": rec["sharing_sector"],
        "risk_score": rec["risk_score"],
        "risk_level": rec["risk_level"],
    }

    try:
        result = prrabe_service.encrypt_record(
            record_id=record_id,
            policy_string=policy_string,
            payload_dict=payload,
            encrypted_by_org_id=user["organization_id"],
        )
        try:
            with get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO encrypted_records
                        (cti_record_id, ciphertext, policy_display, sensitivity, classification,
                         encrypted_by_user_id, encrypted_by_org_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    record_id, "prrabe",
                    "Hidden (PR-RABE policy hiding)", None, None,
                    user["id"], user["organization_id"],
                ))
        except Exception:
            pass
        incentive_engine.reward_share(user["organization_id"], record_id)
        if rec["confidence"] in ("high", "confirmed"):
            incentive_engine.reward_high_confidence(user["organization_id"], record_id)
        return jsonify(result), 200
    except (RuntimeError, ValueError) as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/decrypt", methods=["POST"])
@require_auth
def prrabe_decrypt():
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    data = get_json_object()
    if not data or not data.get("record_id"):
        return error_response("record_id is required")

    org_id = user["organization_id"]
    try:
        result = prrabe_service.decrypt_record(org_id, data["record_id"])
        status_code = 200 if result.get("success") else 403
        return jsonify(result), status_code
    except RuntimeError as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/revoke", methods=["POST"])
@require_auth
def prrabe_revoke():
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    data = get_json_object()
    if not data:
        return error_response("Send a valid JSON object")
    org_id = data.get("organization_id", user["organization_id"])
    if org_id != user["organization_id"]:
        return error_response("You can only revoke attributes for your own organization", 403)
    attribute = data.get("attribute")
    if not attribute:
        return error_response("attribute is required (e.g. TRUST:HIGH)")

    try:
        result = prrabe_service.revoke_attribute(
            org_id, attribute,
        )
        incentive_engine.penalize_revocation(org_id)
        return jsonify(result), 200
    except RuntimeError as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/events", methods=["GET"])
@require_auth
def prrabe_events():
    limit = request.args.get("limit", 50, type=int)
    return jsonify({"events": get_prrabe_events(limit)}), 200


@app.route("/api/prrabe/demo-decrypt", methods=["POST"])
@require_auth
def prrabe_demo_decrypt():
    """Demo-only: decrypt a record as a specified org to demonstrate revocation effects."""
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    data = get_json_object()
    if not data or not data.get("record_id") or not data.get("organization_id"):
        return error_response("record_id and organization_id are required")
    org_id = data["organization_id"]
    org = get_organization(org_id)
    if not org:
        return error_response("Organization not found", 404)
    try:
        result = prrabe_service.decrypt_record(org_id, data["record_id"])
        result["demo_org_name"] = org["name"]
        return jsonify(result), 200 if result.get("success") else 403
    except RuntimeError as e:
        return error_response(str(e), 500)


@app.route("/api/prrabe/demo-revoke", methods=["POST"])
@require_auth
def prrabe_demo_revoke():
    """Demo-only: revoke an attribute for any org to demonstrate AGK rotation."""
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    data = get_json_object()
    if not data:
        return error_response("Send a valid JSON object")
    org_id = data.get("organization_id")
    attribute = data.get("attribute")
    if not org_id or not attribute:
        return error_response("organization_id and attribute are required")
    org = get_organization(org_id)
    if not org:
        return error_response("Organization not found", 404)
    try:
        result = prrabe_service.revoke_attribute(org_id, attribute)
        return jsonify(result), 200
    except RuntimeError as e:
        return error_response(str(e), 500)


# --------------------------------------------------
# INCENTIVE ROUTES
# --------------------------------------------------

@app.route("/api/incentive/wallet", methods=["GET"])
@require_auth
def incentive_wallet():
    user = current_user()
    if not user:
        return error_response("Authentication required", 401)
    org_id = user["organization_id"]
    wallet = incentive_engine.get_wallet(org_id)
    transactions = incentive_engine.get_transactions(org_id)
    return jsonify({"wallet": wallet, "transactions": transactions}), 200


@app.route("/api/incentive/leaderboard", methods=["GET"])
@require_auth
def incentive_leaderboard():
    return jsonify({"leaderboard": incentive_engine.get_leaderboard()}), 200


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=os.environ.get("FLASK_DEBUG", "1") == "1")