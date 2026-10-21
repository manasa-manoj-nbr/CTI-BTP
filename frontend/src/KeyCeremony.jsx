import { useState, useEffect, useCallback } from "react";
import {
  Key, Shield, Users, CheckCircle2, AlertCircle, Loader2,
  Lock, Zap, RefreshCw, ChevronRight, Server,
} from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./KeyCeremony.css";

const headers = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${getAccessToken()}`,
});

export default function KeyCeremony() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionMsg, setActionMsg] = useState("");
  const [actionErr, setActionErr] = useState("");
  const [orgs, setOrgs] = useState([]);
  const [busy, setBusy] = useState(false);
  const [userOrg, setUserOrg] = useState(null);

  const load = useCallback(async () => {
    try {
      const [statusRes, orgsRes, meRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/prrabe/status`, { headers: headers() }),
        fetch(`${API_BASE_URL}/api/organizations`, { headers: headers() }),
        fetch(`${API_BASE_URL}/api/auth/me`, { headers: headers() }),
      ]);
      if (statusRes.ok) setStatus(await statusRes.json());
      if (orgsRes.ok) {
        const d = await orgsRes.json();
        setOrgs(d.organizations || []);
      }
      if (meRes.ok) {
        const d = await meRes.json();
        setUserOrg(d.organization || null);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const flash = (msg, err) => {
    setActionMsg(err ? "" : msg);
    setActionErr(err ? msg : "");
  };

  const initSystem = async () => {
    setBusy(true);
    flash("");
    const res = await fetch(`${API_BASE_URL}/api/prrabe/init`, {
      method: "POST", headers: headers(),
      body: JSON.stringify({ num_slots: orgs.length || 3 }),
    });
    const d = await res.json();
    res.ok ? flash(`System initialised in ${d.elapsed_ms} ms. ${d.note}`) : flash(d.error || "Init failed", true);
    await load();
    setBusy(false);
  };

  const genKey = async (orgId) => {
    setBusy(true);
    flash("");
    const res = await fetch(`${API_BASE_URL}/api/prrabe/keygen`, {
      method: "POST", headers: headers(),
      body: JSON.stringify({ organization_id: orgId }),
    });
    const d = await res.json();
    if (res.ok) {
      flash(`Slot ${d.slot}: key generated (${d.elapsed_ms} ms). IsValid: ${d.is_valid ? "PASS" : "FAIL"}`);
    } else {
      flash(d.error || "KeyGen failed", true);
    }
    await load();
    setBusy(false);
  };

  const aggregate = async () => {
    setBusy(true);
    flash("");
    const res = await fetch(`${API_BASE_URL}/api/prrabe/aggregate`, {
      method: "POST", headers: headers(),
    });
    const d = await res.json();
    res.ok ? flash(`Aggregate complete in ${d.elapsed_ms} ms. ${d.note}`) : flash(d.error || "Aggregate failed", true);
    await load();
    setBusy(false);
  };

  const completeCeremony = async () => {
    setBusy(true);
    flash("");
    const res = await fetch(`${API_BASE_URL}/api/prrabe/complete-ceremony`, {
      method: "POST", headers: headers(),
    });
    const d = await res.json();
    if (res.ok) {
      flash(`Full ceremony completed! Init + ${d.keygen?.length || 0} orgs keygen + aggregate done.`);
    } else {
      flash(d.error || "Ceremony failed", true);
    }
    await load();
    setBusy(false);
  };

  if (loading) return <div className="kc-loading"><Loader2 className="spin" size={24} /> Loading ceremony status...</div>;

  const initialized = status?.initialized;
  const aggregated = status?.aggregated;
  const registered = status?.registered || 0;
  const total = status?.num_slots || 0;
  const registeredIds = new Set((status?.orgs || []).map(o => o.org_id));

  const phase = !initialized ? 0 : !aggregated && registered < total ? 1 : !aggregated && registered === total ? 2 : 3;

  return (
    <div className="kc-page">
      <div className="kc-header">
        <h2><Key size={22} /> PR-RABE Key Ceremony</h2>
        <p>Each organisation generates its own key pair — no central authority holds secrets. The Key Curator only aggregates public keys (deterministic, verifiable).</p>
      </div>

      {actionMsg && <div className="kc-flash success"><CheckCircle2 size={16} /> {actionMsg}</div>}
      {actionErr && <div className="kc-flash error"><AlertCircle size={16} /> {actionErr}</div>}

      {!status?.charm_available && (
        <div className="kc-flash info">
          <AlertCircle size={16} /> Running in AES-256 fallback mode (charm-crypto not available). Use Linux/WSL for real PR-RABE bilinear pairings.
        </div>
      )}

      {orgs.length >= 2 && (
        <div className="kc-card highlight" style={{ borderLeft: "4px solid var(--kc-primary, #6366f1)" }}>
          <div className="kc-card-head">
            <Zap size={18} />
            <h3>Quick Setup</h3>
          </div>
          <p>{aggregated ? "Re-run the full ceremony (resets all keys and encrypted records)." : `Complete the entire ceremony in one step: initialise CRS, generate keys for all ${orgs.length} organisations, and aggregate.`}</p>
          <button className="kc-btn primary" onClick={completeCeremony} disabled={busy}>
            {busy ? <Loader2 className="spin" size={16} /> : <Zap size={16} />}
            {aggregated ? "Reset & Re-run Ceremony" : "Complete Full Ceremony"}
          </button>
        </div>
      )}

      {/* ── Phase Stepper ── */}
      <div className="kc-stepper">
        {["Setup CRS", "Org KeyGen", "Aggregate", "Ready"].map((label, i) => (
          <div key={label} className={`kc-step ${phase === i ? "active" : phase > i ? "done" : ""}`}>
            <div className="kc-step-num">{phase > i ? <CheckCircle2 size={16} /> : i + 1}</div>
            <span>{label}</span>
            {i < 3 && <ChevronRight size={14} className="kc-step-arrow" />}
          </div>
        ))}
      </div>

      {/* ── Step 1: Setup ── */}
      <div className={`kc-card ${phase === 0 ? "highlight" : ""}`}>
        <div className="kc-card-head">
          <Server size={18} />
          <h3>1. System Setup — Generate Common Reference String</h3>
          {initialized && <span className="kc-badge done">Done</span>}
        </div>
        <p>Creates the CRS (public parameters) using bilinear pairings. Setup secrets are discarded — <strong>no trapdoor exists</strong>.</p>
        {initialized ? (
          <div className="kc-meta">
            <span>Group: SS512 (Type-A pairing)</span>
            <span>Security: 80-bit (prototype)</span>
            <span>Slots: {total}</span>
            <span>Setup: {status.setup_at?.split("T")[0]}</span>
          </div>
        ) : (
          <button className="kc-btn primary" onClick={initSystem} disabled={busy || orgs.length < 2}>
            {busy ? <Loader2 className="spin" size={16} /> : <Zap size={16} />}
            Initialise CRS ({orgs.length} slots)
          </button>
        )}
        {!initialized && orgs.length < 2 && (
          <p className="kc-hint">Need at least 2 organisations. Currently: {orgs.length}.</p>
        )}
      </div>

      {/* ── Step 2: KeyGen ── */}
      <div className={`kc-card ${phase === 1 || phase === 2 ? "highlight" : ""}`}>
        <div className="kc-card-head">
          <Users size={18} />
          <h3>2. Organisation Key Generation</h3>
          {phase >= 2 && <span className="kc-badge done">All keys generated</span>}
        </div>
        <p>Each organisation generates its own (pk, sk) pair. The secret key never leaves the org. IsValid check proves correctness.</p>

        {initialized && (
          <div className="kc-org-grid">
            {orgs.map(org => {
              const regInfo = (status?.orgs || []).find(o => o.org_id === org.id);
              const hasKey = regInfo?.has_key;
              const isMyOrg = userOrg && org.id === userOrg.id;
              return (
                <div key={org.id} className={`kc-org-card ${hasKey ? "keyed" : ""}`}>
                  <div className="kc-org-top">
                    <div className="kc-org-icon">{hasKey ? <CheckCircle2 size={20} /> : <Key size={20} />}</div>
                    <div>
                      <strong>{org.name}{isMyOrg ? " (You)" : ""}</strong>
                      <small>{org.sector} · Trust: {org.trust_score}</small>
                    </div>
                  </div>
                  {hasKey ? (
                    <div className="kc-org-meta">
                      <span>Slot {regInfo.slot}</span>
                      <span>Private attributes registered</span>
                      <span className="kc-badge done">Key ✓</span>
                    </div>
                  ) : isMyOrg ? (
                    <button
                      className="kc-btn secondary"
                      onClick={() => genKey(org.id)}
                      disabled={busy || !initialized}
                    >
                      {busy ? <Loader2 className="spin" size={14} /> : <Key size={14} />}
                      Generate My Key Pair
                    </button>
                  ) : (
                    <div className="kc-org-meta">
                      <span className="kc-badge pending">Awaiting key from {org.name}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {initialized && (
          <div className="kc-progress">
            <div className="kc-progress-bar" style={{ width: `${(registered / total) * 100}%` }} />
            <span>{registered} / {total} organisations registered</span>
          </div>
        )}
      </div>

      {/* ── Step 3: Aggregate ── */}
      <div className={`kc-card ${phase === 2 ? "highlight" : ""}`}>
        <div className="kc-card-head">
          <Shield size={18} />
          <h3>3. Key Curator — Aggregate</h3>
          {aggregated && <span className="kc-badge done">Aggregated</span>}
        </div>
        <p>The Key Curator combines all public keys into a Master Public Key (mpk) and distributes helper keys. This is <strong>deterministic</strong> — the curator holds no secrets. Anyone can verify.</p>

        {!aggregated && phase === 2 && (
          <button className="kc-btn primary" onClick={aggregate} disabled={busy}>
            {busy ? <Loader2 className="spin" size={16} /> : <Lock size={16} />}
            Run Aggregate
          </button>
        )}

        {aggregated && (
          <div className="kc-aggregate-result">
            <div className="kc-meta">
              <span>Aggregated: {status.aggregate_at?.split("T")[0]}</span>
              <span>Orgs: {registered}</span>
              <span>Encrypted records: {status.encrypted_records}</span>
            </div>
            {Object.keys(status.agk_groups || {}).length > 0 && (
              <div className="kc-agk-table">
                <h4>Attribute Group Keys</h4>
                <table>
                  <thead><tr><th>Attribute</th><th>Version</th><th>Members</th></tr></thead>
                  <tbody>
                    {Object.entries(status.agk_groups).map(([attr, info]) => (
                      <tr key={attr}>
                        <td><code>{attr}</code></td>
                        <td>v{info.version}</td>
                        <td>{info.member_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Step 4: Ready ── */}
      {aggregated && (
        <div className="kc-card highlight">
          <div className="kc-card-head">
            <CheckCircle2 size={18} />
            <h3>4. System Ready — PR-RABE Active</h3>
          </div>
          <p>The system is ready to encrypt and decrypt CTI records using real PR-RABE with bilinear pairings. Navigate to <strong>Crypto Sharing</strong> to encrypt records, or <strong>Revocation Demo</strong> to test AGK rotation.</p>
        </div>
      )}

      <button className="kc-btn secondary" onClick={() => { load(); flash(""); }} style={{ marginTop: 16 }}>
        <RefreshCw size={14} /> Refresh Status
      </button>
    </div>
  );
}
