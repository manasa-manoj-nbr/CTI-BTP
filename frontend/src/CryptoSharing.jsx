import { useState, useEffect, useCallback } from "react";
import { Lock, Unlock, ShieldOff, ShieldCheck, Key, FileKey, Activity, Shield, Database, Eye, AlertTriangle, CheckCircle } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./CryptoSharing.css";

export default function CryptoSharing() {
  const [userOrg, setUserOrg] = useState(null);
  const [ctiRecords, setCtiRecords] = useState([]);
  const [encryptedRecords, setEncryptedRecords] = useState([]);
  const [selectedRecord, setSelectedRecord] = useState("");
  const [selectedEncrypted, setSelectedEncrypted] = useState("");

  const [decryptedData, setDecryptedData] = useState(null);
  const [decryptMeta, setDecryptMeta] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [encryptMsg, setEncryptMsg] = useState("");

  const [policySector, setPolicySector] = useState("All");
  const [prrabeStatus, setPrrabeStatus] = useState(null);
  const [trustInfo, setTrustInfo] = useState(null);
  const [loading, setLoading] = useState({ encrypt: false, decrypt: false, revoke: false });

  const token = getAccessToken();
  const headers = { Authorization: `Bearer ${token}` };
  const jsonHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  const loadEncryptedRecords = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/crypto/encrypted`, { headers });
      if (res.ok) {
        const data = await res.json();
        setEncryptedRecords(data.records || []);
      }
    } catch { /* ignore */ }
  }, [token]);

  useEffect(() => {
    async function loadData() {
      try {
        const [meRes, statusRes] = await Promise.all([
          fetch(`${API_BASE_URL}/api/auth/me`, { headers }),
          fetch(`${API_BASE_URL}/api/prrabe/status`, { headers }).catch(() => null),
        ]);

        let myOrg = null;
        if (meRes.ok) {
          const meData = await meRes.json();
          myOrg = meData.organization || null;
          setUserOrg(myOrg);
        }

        const ctiUrl = myOrg
          ? `${API_BASE_URL}/api/cti/advanced?organization_id=${myOrg.id}`
          : `${API_BASE_URL}/api/cti/advanced`;
        const ctiRes = await fetch(ctiUrl, { headers });
        if (ctiRes.ok) {
          const ctiData = await ctiRes.json();
          setCtiRecords(ctiData.records || (Array.isArray(ctiData) ? ctiData : []));
        }

        if (statusRes && statusRes.ok) {
          setPrrabeStatus(await statusRes.json());
        }

        await loadEncryptedRecords();
      } catch { /* ignore */ }
    }
    loadData();
  }, []);

  useEffect(() => {
    if (!userOrg) { setTrustInfo(null); return; }
    async function loadTrust() {
      try {
        const res = await fetch(`${API_BASE_URL}/api/trust/compute/${userOrg.id}`, { headers });
        if (res.ok) setTrustInfo(await res.json());
      } catch { /* ignore */ }
    }
    loadTrust();
  }, [userOrg]);

  const ceremonyReady = prrabeStatus?.aggregated === true;
  const selectedCTI = ctiRecords.find(r => r.id === parseInt(selectedRecord));
  const selectedEnc = encryptedRecords.find(r => r.id === parseInt(selectedEncrypted));

  const userOrgRegistered = prrabeStatus?.orgs?.some(o => o.org_id === userOrg?.id);

  const handleEncrypt = async () => {
    if (!selectedCTI || !ceremonyReady) return;
    setLoading(l => ({ ...l, encrypt: true }));
    setEncryptMsg("");

    try {
      const body = { record_id: selectedCTI.id };
      if (policySector !== "All") {
        body.policy = `SECTOR:${policySector.toUpperCase()}`;
      }

      const res = await fetch(`${API_BASE_URL}/api/prrabe/encrypt`, {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify(body),
      });
      const data = await res.json();

      if (res.ok) {
        setEncryptMsg(`Encrypted with PR-RABE. Took ${data.elapsed_ms}ms.`);
        await loadEncryptedRecords();
        const statusRes = await fetch(`${API_BASE_URL}/api/prrabe/status`, { headers });
        if (statusRes.ok) setPrrabeStatus(await statusRes.json());
      } else {
        setEncryptMsg(`Encryption failed: ${data.error || "Unknown error"}`);
      }
    } catch (e) {
      setEncryptMsg(`Encryption failed: ${e.message}`);
    } finally {
      setLoading(l => ({ ...l, encrypt: false }));
    }
  };

  const handleDecrypt = async () => {
    if (!selectedEnc) return;
    setDecryptedData(null);
    setDecryptMeta(null);
    setErrorMsg("");
    setLoading(l => ({ ...l, decrypt: true }));

    try {
      const res = await fetch(`${API_BASE_URL}/api/prrabe/decrypt`, {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ record_id: selectedEnc.cti_record_id }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        setDecryptedData(data.data);
        setDecryptMeta({
          org_name: data.org_name,
          elapsed_ms: data.elapsed_ms,
        });
      } else {
        setErrorMsg(data.reason || data.error || "Organization does not satisfy the access requirements.");
      }
    } catch (e) {
      setErrorMsg(`Decryption failed: ${e.message}`);
    } finally {
      setLoading(l => ({ ...l, decrypt: false }));
    }
  };

  const handleRevoke = async () => {
    if (!userOrg) return;
    setLoading(l => ({ ...l, revoke: true }));

    const trustAttr = trustInfo
      ? `TRUST:${trustInfo.trust_level?.toUpperCase() || "MEDIUM"}`
      : "TRUST:MEDIUM";

    try {
      const res = await fetch(`${API_BASE_URL}/api/prrabe/revoke`, {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({ attribute: trustAttr }),
      });
      const data = await res.json();

      if (res.ok) {
        setErrorMsg("");
        setDecryptedData(null);
        setDecryptMeta(null);
        setEncryptMsg(`Attribute revoked. AGK rotated to v${data.new_agk_version}. ${data.records_reencrypted} record(s) re-encrypted.`);
        const statusRes = await fetch(`${API_BASE_URL}/api/prrabe/status`, { headers });
        if (statusRes.ok) setPrrabeStatus(await statusRes.json());
      } else {
        setErrorMsg(data.error || "Revocation failed");
      }
    } catch (e) {
      setErrorMsg(`Revocation failed: ${e.message}`);
    } finally {
      setLoading(l => ({ ...l, revoke: false }));
    }
  };

  return (
    <div className="crypto-page">
      <div className="crypto-header">
        <h2>Privacy-Preserving CTI Sharing (PR-RABE)</h2>
        <p>Encrypt threat intelligence with real attribute-based encryption using bilinear pairings. Access is granted or denied based on cryptographic policy evaluation — no trusted authority decides.</p>
      </div>

      {prrabeStatus && (
        <div className={`crypto-status-bar ${ceremonyReady ? "" : "crypto-status-warn"}`}>
          <Shield size={16} />
          <span><strong>PR-RABE:</strong> {ceremonyReady ? "Ready" : prrabeStatus.initialized ? "Ceremony incomplete" : "Not initialized"}</span>
          <span><strong>Registered:</strong> {prrabeStatus.registered}/{prrabeStatus.num_slots} orgs</span>
          <span><strong>Encrypted:</strong> {prrabeStatus.encrypted_records} records</span>
          {!ceremonyReady && (
            <span style={{ color: "#f59e0b" }}>
              <AlertTriangle size={14} style={{ verticalAlign: "middle" }} /> Complete the Key Ceremony first
            </span>
          )}
        </div>
      )}

      {userOrg && (
        <div className="crypto-status-bar" style={{ background: "rgba(56, 189, 248, 0.08)", borderColor: "rgba(56, 189, 248, 0.2)" }}>
          <Database size={16} />
          <span><strong>Your Org:</strong> {userOrg.name} ({userOrg.sector})</span>
          <span><strong>Trust:</strong> {userOrg.trust_score}/100</span>
          {userOrgRegistered && <span style={{ color: "#6ee7b7" }}><CheckCircle size={14} /> Keys registered</span>}
        </div>
      )}

      <div className="crypto-grid">
        {/* LEFT: Encryption */}
        <div className="crypto-card">
          <div className="crypto-panel-heading">
            <Lock size={20} />
            <h3>1. Encrypt & Share CTI Record</h3>
          </div>

          <div className="crypto-form">
            <label>
              CTI Record to Encrypt
              <select value={selectedRecord} onChange={e => { setSelectedRecord(e.target.value); setEncryptMsg(""); }}>
                <option value="">Select a threat record...</option>
                {ctiRecords.map(r => (
                  <option key={r.id} value={r.id}>
                    {r.title} ({r.severity}) — {r.sharing_sector}
                  </option>
                ))}
              </select>
            </label>

            {selectedCTI && (
              <div className="record-preview">
                <div className="record-preview-header">
                  <Eye size={14} />
                  <strong>Record Preview</strong>
                </div>
                <div className="record-preview-body">
                  <div><strong>Category:</strong> {selectedCTI.category}</div>
                  <div><strong>Indicator:</strong> <code>{selectedCTI.indicator_value}</code></div>
                  <div><strong>Severity:</strong> <span className={`sev-badge sev-${selectedCTI.severity}`}>{selectedCTI.severity}</span></div>
                  <div><strong>Risk:</strong> {selectedCTI.risk_level} ({selectedCTI.risk_score}/100)</div>
                  <div><strong>Sector:</strong> {selectedCTI.sharing_sector}</div>
                  <div className="record-preview-desc">{selectedCTI.description}</div>
                </div>
              </div>
            )}

            <label>
              Policy — Sector Restriction
              <select value={policySector} onChange={e => setPolicySector(e.target.value)}>
                <option value="All">Auto (based on severity)</option>
                <option value="Finance">SECTOR:FINANCE</option>
                <option value="Healthcare">SECTOR:HEALTHCARE</option>
                <option value="Education">SECTOR:EDUCATION</option>
                <option value="Technology">SECTOR:TECHNOLOGY</option>
                <option value="Government">SECTOR:GOVERNMENT</option>
                <option value="Energy">SECTOR:ENERGY</option>
              </select>
            </label>

            <button
              className="crypto-btn primary"
              onClick={handleEncrypt}
              disabled={!selectedRecord || !ceremonyReady || loading.encrypt}
            >
              <FileKey size={16} /> {loading.encrypt ? "Encrypting..." : "Encrypt with PR-RABE"}
            </button>

            {!ceremonyReady && selectedRecord && (
              <p className="crypto-hint">Complete the Key Ceremony before encrypting.</p>
            )}
          </div>

          {encryptMsg && (
            <div className="policy-box">
              <p><strong>{encryptMsg}</strong></p>
            </div>
          )}
        </div>

        {/* RIGHT: Decryption */}
        <div className="crypto-card">
          <div className="crypto-panel-heading">
            <Unlock size={20} />
            <h3>2. Decrypt Shared Intelligence</h3>
          </div>

          <div className="crypto-form">
            {userOrg ? (
              <div className="org-auto-bound">
                <strong>Decrypting as:</strong> {userOrg.name} ({userOrg.sector})
              </div>
            ) : (
              <div className="org-auto-bound" style={{ color: "#ef4444" }}>
                Loading your organization...
              </div>
            )}

            {trustInfo && (
              <div className="trust-info-box">
                <Activity size={16} />
                <span>
                  <strong>Dynamic Trust:</strong> {trustInfo.trust_score}/100 ({trustInfo.trust_level})
                </span>
                {trustInfo.components?.sharing && (
                  <div className="trust-breakdown">
                    <small>Sharing: {trustInfo.components.sharing.submissions} submissions | Violations: {trustInfo.components.violations.count} | Reliability: {trustInfo.components.reliability.score}%</small>
                  </div>
                )}
              </div>
            )}

            <label>
              Select Encrypted Record
              <select value={selectedEncrypted} onChange={e => { setSelectedEncrypted(e.target.value); setDecryptedData(null); setDecryptMeta(null); setErrorMsg(""); }}>
                <option value="">Choose an encrypted record to decrypt...</option>
                {encryptedRecords.map(r => (
                  <option key={r.id} value={r.id}>
                    {r.title} ({r.severity}) — by {r.encrypted_by_org}
                  </option>
                ))}
              </select>
            </label>

            {selectedEnc && (
              <div className="record-preview" style={{ borderColor: "rgba(139, 92, 246, 0.3)", background: "rgba(139, 92, 246, 0.04)" }}>
                <div className="record-preview-header">
                  <Lock size={14} />
                  <strong>Encrypted Record Details</strong>
                </div>
                <div className="record-preview-body">
                  <div><strong>Title:</strong> {selectedEnc.title}</div>
                  <div><strong>Severity:</strong> <span className={`sev-badge sev-${selectedEnc.severity}`}>{selectedEnc.severity}</span></div>
                  <div><strong>Category:</strong> {selectedEnc.category}</div>
                  <div><strong>Sector:</strong> {selectedEnc.sharing_sector}</div>
                  <div><strong>Encrypted by:</strong> {selectedEnc.encrypted_by_org}</div>
                  <div><strong>At:</strong> {new Date(selectedEnc.created_at).toLocaleString()}</div>
                </div>
              </div>
            )}

            <div className="crypto-actions">
              <button
                className="crypto-btn success"
                onClick={handleDecrypt}
                disabled={!selectedEnc || !userOrg || !ceremonyReady || loading.decrypt}
              >
                <Key size={16} /> {loading.decrypt ? "Decrypting..." : "Attempt Decryption"}
              </button>

              <button
                className="crypto-btn danger"
                onClick={handleRevoke}
                disabled={!userOrg || !ceremonyReady || loading.revoke}
              >
                <ShieldOff size={16} /> {loading.revoke ? "Revoking..." : "Revoke My Keys (AGK Rotation)"}
              </button>
            </div>

            {!ceremonyReady && (
              <p className="crypto-hint">Complete the Key Ceremony before decrypting or revoking.</p>
            )}
          </div>

          {errorMsg && (
            <div className="crypto-error">
              <ShieldOff size={18} /> <strong>Access Denied:</strong> {errorMsg}
            </div>
          )}

          {decryptedData && (
            <div className="crypto-success">
              <div className="success-header">
                <ShieldCheck size={20} /> Access Granted — Decrypted Intelligence
              </div>
              {decryptMeta && (
                <div className="decrypt-meta">
                  <small>
                    Decrypted as: {decryptMeta.org_name} |
                    Time: {decryptMeta.elapsed_ms}ms
                  </small>
                </div>
              )}
              <div className="decrypted-intel">
                {decryptedData.title && <h4 className="intel-title">{decryptedData.title}</h4>}
                <div className="intel-grid">
                  {decryptedData.category && <div className="intel-field"><span className="intel-label">Category</span><span>{decryptedData.category}</span></div>}
                  {decryptedData.indicator_value && <div className="intel-field"><span className="intel-label">Indicator</span><code>{decryptedData.indicator_value}</code></div>}
                  {decryptedData.indicator_type && <div className="intel-field"><span className="intel-label">Type</span><span>{decryptedData.indicator_type}</span></div>}
                  {decryptedData.severity && <div className="intel-field"><span className="intel-label">Severity</span><span className={`sev-badge sev-${decryptedData.severity}`}>{decryptedData.severity}</span></div>}
                  {decryptedData.confidence && <div className="intel-field"><span className="intel-label">Confidence</span><span>{decryptedData.confidence}</span></div>}
                  {decryptedData.risk_level && <div className="intel-field"><span className="intel-label">Risk</span><span>{decryptedData.risk_level} ({decryptedData.risk_score}/100)</span></div>}
                  {decryptedData.sharing_sector && <div className="intel-field"><span className="intel-label">Sector</span><span>{decryptedData.sharing_sector}</span></div>}
                </div>
                {decryptedData.description && (
                  <div className="intel-description">
                    <span className="intel-label">Description</span>
                    <p>{decryptedData.description}</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
