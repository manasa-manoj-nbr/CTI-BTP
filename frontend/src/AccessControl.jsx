import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, FileCheck2, AlertTriangle } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./AccessControl.css";

export default function AccessControl() {
  const [organizations, setOrganizations] = useState([]);
  const [records, setRecords] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [selectedRecord, setSelectedRecord] = useState("");
  const [userOrg, setUserOrg] = useState(null);
  
  const [evaluating, setEvaluating] = useState(false);
  const [decision, setDecision] = useState(null);
  const [error, setError] = useState("");
  const [auditLog, setAuditLog] = useState([]);

  useEffect(() => {
    async function loadData() {
      try {
        const token = getAccessToken();
        if (!token) {
          setError("You are not logged in.");
          return;
        }
        const headers = { Authorization: `Bearer ${token}` };

        const [orgRes, recRes, logRes, meRes] = await Promise.all([
          fetch(`${API_BASE_URL}/api/organizations`, { headers }),
          fetch(`${API_BASE_URL}/api/cti/advanced`, { headers }),
          fetch(`${API_BASE_URL}/api/audit-logs`, { headers }),
          fetch(`${API_BASE_URL}/api/auth/me`, { headers }),
        ]);

        const orgData = await orgRes.json();
        const recData = await recRes.json();
        const logData = await logRes.json();

        if (meRes.ok) {
          const meData = await meRes.json();
          if (meData.organization) {
            setUserOrg(meData.organization);
            setSelectedOrg(String(meData.organization.id));
          }
        }

        // Parse Organizations
        if (orgData.organizations) {
          setOrganizations(orgData.organizations);
        } else if (Array.isArray(orgData)) {
          setOrganizations(orgData);
        }

        // Parse Records
        if (recData.records) {
          setRecords(recData.records);
        } else if (Array.isArray(recData)) {
          setRecords(recData);
        }

        // Parse Audit Logs
        if (Array.isArray(logData)) {
          setAuditLog(logData);
        }

      } catch (err) {
        console.error("Load error:", err);
        setError(`Failed to load data: ${err.message}`);
      }
    }
    loadData();
  }, []);

  const handleEvaluate = async (e) => {
    e.preventDefault();
    if (!selectedOrg || !selectedRecord) return;

    setEvaluating(true);
    setError("");
    setDecision(null);

    try {
      const token = getAccessToken();
      if (!token) throw new Error("Not authenticated. Please log in again.");

      const orgId = parseInt(selectedOrg, 10);
      const recordId = parseInt(selectedRecord, 10);
      
      const res = await fetch(`${API_BASE_URL}/api/advanced-policies`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          organization_id: orgId,
          record_id: recordId
        })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `Server error (HTTP ${res.status})`);
      }

      const decisionVal = (data.decision || "").toUpperCase();
      const isGranted = decisionVal === "ALLOW" || decisionVal === "GRANTED" || data.allowed === true;

      setDecision({
        granted: isGranted,
        reason: data.reason || (
          isGranted
            ? "Access granted."
            : "Organization does not satisfy the access requirements."
        ),
      });

      const logRes = await fetch(`${API_BASE_URL}/api/audit-logs`, { headers: { Authorization: `Bearer ${token}` } });
      if (logRes.ok) {
        setAuditLog(await logRes.json());
      }

    } catch (err) {
      console.error("Evaluation failed:", err);
      setError(err.message);
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div className="ac-page">
      <div className="ac-header">
        <h2>Privacy-Preserving Access Control</h2>
        <p>Evaluate your organization's access to shared CTI.</p>
      </div>

      <div className="ac-grid">
        <div className="ac-card">
          <div className="ac-panel-heading">
            <FileCheck2 size={20} />
            <h3>Policy Decision Engine</h3>
          </div>

          <form className="ac-form" onSubmit={handleEvaluate}>
            <label>
              Requesting Organization
              <div className="ac-org-display">
                {userOrg ? `${userOrg.name} (${userOrg.sector})` : "Loading..."}
              </div>
            </label>

            <label>
              Requested Threat Record
              <select value={selectedRecord} onChange={e => setSelectedRecord(e.target.value)} required>
                <option value="">Select IOC...</option>
                {records.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.indicator_value} ({r.severity})
                  </option>
                ))}
              </select>
            </label>

            <button type="submit" className="ac-btn" disabled={evaluating || !selectedOrg || !selectedRecord}>
              {evaluating ? "Evaluating Rules..." : "Evaluate Access Request"}
            </button>
          </form>

          {error && <div className="ac-error" style={{ marginTop: '16px', color: '#c73754', fontSize: '13px' }}>{error}</div>}

          {decision && (
            <div className={`ac-decision ${decision.granted ? "granted" : "denied"}`}>
              <div className="ac-decision-header">
                {decision.granted ? <ShieldCheck size={28} /> : <ShieldAlert size={28} />}
                <h3>{decision.granted ? "ACCESS GRANTED" : "ACCESS DENIED"}</h3>
              </div>
              <p className="ac-reason">{decision.reason}</p>

            </div>
          )}
        </div>

        <div className="ac-card">
          <div className="ac-panel-heading">
            <AlertTriangle size={20} />
            <h3>Security Audit Trail</h3>
          </div>
          <p className="ac-sub">Permanent log of authorization decisions stored in the database.</p>

          <div className="ac-audit-list">
            {auditLog.length === 0 ? (
              <div className="ac-empty">No access requests evaluated yet.</div>
            ) : (
              auditLog.map((log, i) => (
                <div key={i} className="ac-audit-item">
                  <div className="ac-audit-time">
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'Unknown time'}
                  </div>
                  <div className="ac-audit-content">
                    <strong>{log.organization_name}</strong> requested <strong>{log.record_value}</strong>
                  </div>
                  <div className={`ac-audit-status ${log.decision.toLowerCase()}`}>
                    {log.decision}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}