import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, ShieldCheck, LayoutDashboard, Database, Building2, RefreshCw, Search, Wifi,
  AlertTriangle, LockKeyhole, ArrowLeft, LogOut, FileText, Crosshair, Plus, X,
  Key, ShieldOff, Wallet,
} from 'lucide-react'
import { api, API_BASE_URL, getAccessToken } from './api'
import LandingPage from './LandingPage.jsx'
import LoginPage from './LoginPage.jsx'
import KnowledgeGraph from './KnowledgeGraph.jsx'
import TemporalIntelligence from './TemporalIntelligence.jsx'
import PDFIntelligence from './PDFIntelligence.jsx'
import AccessControl from './AccessControl.jsx'
import CryptoSharing from './CryptoSharing.jsx'
import DashboardOverview from './DashboardOverview.jsx'
import ATTACKNavigator from './ATTACKNavigator.jsx'
import KeyCeremony from './KeyCeremony.jsx'
import RevocationDemo from './RevocationDemo.jsx'
import IncentiveWallet from './IncentiveWallet.jsx'
import CTISubmissionForm from './CTISubmissionForm.jsx'
import './App.css'

// GLOBAL navigation (when no org is selected)
const GLOBAL_NAV = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'Submit CTI', icon: Plus },
  { label: 'Organizations', icon: Building2 },
  { label: 'Key Ceremony', icon: Key },
  { label: 'Crypto Sharing', icon: ShieldCheck },
  { label: 'Revocation Demo', icon: ShieldOff },
  { label: 'Wallet', icon: Wallet },
  { label: 'Access Control', icon: LockKeyhole },
]

// ORG-level navigation (when a specific org is selected)
const ORG_NAV = [
  { label: 'PDF Intelligence', icon: FileText },
  { label: 'Knowledge Graph', icon: Activity },
  { label: 'Temporal Intelligence', icon: Activity },
  { label: 'ATT&CK Matrix', icon: Crosshair },
]

// --------------------------------------------------
// RISK HELPERS
// --------------------------------------------------
const RISK_LEVELS = [
  { key: 'critical', label: 'Critical', badge: 'badge-critical', bar: 'risk-critical' },
  { key: 'high', label: 'High', badge: 'badge-high', bar: 'risk-high' },
  { key: 'medium', label: 'Medium', badge: 'badge-medium', bar: 'risk-medium' },
  { key: 'low', label: 'Low', badge: 'badge-low', bar: 'risk-low' },
]
const KNOWN_LEVELS = new Set(RISK_LEVELS.map((level) => level.key))

function getRiskKey(level, score) {
  const value = String(level ?? '').trim().toLowerCase()
  if (KNOWN_LEVELS.has(value)) return value
  if (score === null || score === undefined || score === '') return 'unknown'
  const numeric = Number(score)
  if (!Number.isFinite(numeric)) return 'unknown'
  if (numeric >= 80) return 'critical'
  if (numeric >= 60) return 'high'
  if (numeric >= 35) return 'medium'
  return 'low'
}
function getRiskClass(level, score) {
  const key = getRiskKey(level, score)
  return RISK_LEVELS.find((item) => item.key === key)?.badge ?? 'badge-neutral'
}
function toList(payload, key) {
  if (Array.isArray(payload)) return payload
  return Array.isArray(payload?.[key]) ? payload[key] : []
}

// --------------------------------------------------
// ADD ORGANIZATION MODAL
// --------------------------------------------------
function AddOrganizationModal({ onClose, onSuccess }) {
  const [name, setName] = useState('')
  const [sector, setSector] = useState('Finance')
  const [trust, setTrust] = useState(50)
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setSubmitting(true)
    setError('')
    try {
      const token = getAccessToken()
      const res = await fetch(`${API_BASE_URL}/api/organizations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: name.trim(), sector, trust_score: parseInt(trust) })
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to create organization')
      }
      onSuccess()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '500px', padding: '32px' }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <h2 style={{ margin: 0, color: '#292454' }}>Add Organization</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer' }}><X size={20} /></button>
        </div>
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', color: '#45435f', fontSize: '13px', fontWeight: 600 }}>
            Organization Name
            <input
              type="text" required value={name} onChange={e => setName(e.target.value)}
              placeholder="e.g. Energy Corp"
              style={{ padding: '10px', border: '1px solid #e8e6f1', borderRadius: '8px', fontSize: '14px' }}
            />
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', color: '#45435f', fontSize: '13px', fontWeight: 600 }}>
            Sector
            <select value={sector} onChange={e => setSector(e.target.value)}
              style={{ padding: '10px', border: '1px solid #e8e6f1', borderRadius: '8px', fontSize: '14px' }}>
              <option value="Finance">Finance</option>
              <option value="Healthcare">Healthcare</option>
              <option value="Energy">Energy</option>
              <option value="Government">Government</option>
              <option value="Technology">Technology</option>
              <option value="Education">Education</option>
            </select>
          </label>
          <label style={{ display: 'flex', flexDirection: 'column', gap: '6px', color: '#45435f', fontSize: '13px', fontWeight: 600 }}>
            Trust Score (0-100)
            <input
              type="number" min="0" max="100" value={trust} onChange={e => setTrust(e.target.value)}
              style={{ padding: '10px', border: '1px solid #e8e6f1', borderRadius: '8px', fontSize: '14px' }}
            />
          </label>
          {error && <div style={{ color: '#c73754', fontSize: '13px' }}>{error}</div>}
          <button type="submit" disabled={submitting || !name.trim()}
            style={{ padding: '12px', background: '#7062e8', color: '#fff', border: 'none', borderRadius: '8px', fontWeight: 600, cursor: 'pointer' }}>
            {submitting ? 'Creating...' : 'Create Organization'}
          </button>
        </form>
      </div>
    </div>
  )
}

// --------------------------------------------------
// APP
// --------------------------------------------------
function App() {
  const [showLandingPage, setShowLandingPage] = useState(true)
  const [authenticated, setAuthenticated] = useState(() => api.isAuthenticated())
  const [user, setUser] = useState(null)
  const [sessionNotice, setSessionNotice] = useState('')
  const [activePage, setActivePage] = useState('Overview')
  const [selectedOrg, setSelectedOrg] = useState(null) // {id, name, sector} or null
  const [showAddOrgModal, setShowAddOrgModal] = useState(false)

  const [records, setRecords] = useState([])
  const [organizations, setOrganizations] = useState([])
  const [policies, setPolicies] = useState([])
  const [correlations, setCorrelations] = useState([])
  const [riskResults, setRiskResults] = useState([])

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [warnings, setWarnings] = useState([])
  const [search, setSearch] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)

  const requestId = useRef(0)

  const resetSession = useCallback(() => {
    requestId.current += 1
    setRecords([]); setOrganizations([]); setPolicies([]); setCorrelations([]); setRiskResults([])
    setWarnings([]); setError(''); setSearch(''); setLastUpdated(null); setActivePage('Overview')
    setSelectedOrg(null); setLoading(true); setUser(null); setAuthenticated(false)
  }, [])

  const handleLogout = useCallback(() => { api.logout(); resetSession() }, [resetSession])
  const handleLogin = useCallback((loggedInUser) => {
    setUser(loggedInUser ?? null); setSessionNotice(''); setAuthenticated(true)
  }, [])

  const loadDashboard = useCallback(async ({ showSpinner = true } = {}) => {
    const currentRequest = ++requestId.current
    if (showSpinner) setLoading(true)
    setError('')
    try {
      const [ctiResult, orgResult, policyResult, correlationResult, riskResult] = await Promise.allSettled([
        api.getAdvancedCTI(), api.getOrganizations(), api.getPolicies(), api.getCorrelations(), api.getRisk()
      ])
      if (currentRequest !== requestId.current) return
      if (ctiResult.status !== 'fulfilled') throw ctiResult.reason

      const optional = [['Organizations', orgResult], ['Policies', policyResult], ['Correlations', correlationResult], ['Risk analysis', riskResult]]
      setRecords(toList(ctiResult.value, 'records'))
      setOrganizations(orgResult.status === 'fulfilled' ? toList(orgResult.value, 'organizations') : [])
      setPolicies(policyResult.status === 'fulfilled' ? toList(policyResult.value, 'policies') : [])
      setCorrelations(correlationResult.status === 'fulfilled' ? toList(correlationResult.value, 'correlations') : [])
      setRiskResults(riskResult.status === 'fulfilled' ? toList(riskResult.value, 'results') : [])
      setWarnings(optional.filter(([, result]) => result.status !== 'fulfilled').map(([name]) => name))
      setLastUpdated(new Date())
    } catch (err) {
      if (currentRequest !== requestId.current) return
      setError(err?.message || 'Unable to load dashboard data.')
    } finally {
      if (currentRequest === requestId.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!authenticated) return undefined
    loadDashboard()
    if (!user) {
      const token = getAccessToken()
      if (token) {
        fetch(`${API_BASE_URL}/api/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        })
          .then(r => r.ok ? r.json() : null)
          .then(d => { if (d?.user) setUser(d.user) })
          .catch(() => {})
      }
    }
    return () => { requestId.current += 1 }
  }, [authenticated, loadDashboard])

  useEffect(() => {
    function handleExpired() {
      setSessionNotice('Your session expired. Please sign in again.')
      resetSession()
    }
    window.addEventListener('cti:unauthorized', handleExpired)
    return () => window.removeEventListener('cti:unauthorized', handleExpired)
  }, [resetSession])

  const refresh = () => loadDashboard()

  const filteredRecords = useMemo(() => {
    const query = search.trim().toLowerCase()
    if (!query) return records
    return records.filter((record) =>
      [record.title, record.indicator_value, record.category, record.severity, record.risk_level, record.status, record.sharing_sector]
        .filter(Boolean).some((value) => String(value).toLowerCase().includes(query))
    )
  }, [records, search])

  function handleSelectOrg(org) {
    setSelectedOrg(org)
    setActivePage('PDF Intelligence') // Default to PDF when entering org mode
  }

  function handleExitOrg() {
    setSelectedOrg(null)
    setActivePage('Organizations')
  }

  function handleOrgCreated() {
    setShowAddOrgModal(false)
    refresh()
  }

  // ------------------------------------------------
  // PAGES
  // ------------------------------------------------

  function renderOrganizations() {
    const myOrgId = user?.organization_id
    return (
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="section-heading">Organizations</h2>
            <p className="section-description">View registered organizations and their trust profiles. Click your own organization to open its workspace.</p>
          </div>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              type="button"
              className="button-primary"
              onClick={() => setShowAddOrgModal(true)}
              style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <Plus size={16} /> Add Organization
            </button>
            <button type="button" className="button-secondary" onClick={refresh} disabled={loading}>
              <RefreshCw size={15} /> Refresh
            </button>
          </div>
        </div>

        {organizations.length ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '16px', marginTop: '20px' }}>
            {organizations.map((org, index) => {
              const isMine = myOrgId && org.id === myOrgId
              return (
                <div
                  key={org.id ?? index}
                  onClick={isMine ? () => handleSelectOrg(org) : undefined}
                  style={{
                    padding: '20px', background: '#fff', border: `1px solid ${isMine ? '#c4b5fd' : '#e8e6f1'}`,
                    borderRadius: '12px', cursor: isMine ? 'pointer' : 'default', transition: 'all 0.2s',
                    boxShadow: '0 2px 8px rgba(37, 35, 69, 0.04)',
                    opacity: isMine ? 1 : 0.75,
                  }}
                  onMouseEnter={isMine ? e => { e.currentTarget.style.borderColor = '#7062e8'; e.currentTarget.style.boxShadow = '0 4px 16px rgba(112, 98, 232, 0.15)' } : undefined}
                  onMouseLeave={isMine ? e => { e.currentTarget.style.borderColor = '#c4b5fd'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(37, 35, 69, 0.04)' } : undefined}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
                    <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: isMine ? '#f0edff' : '#f5f5f5', display: 'grid', placeItems: 'center', color: isMine ? '#7062e8' : '#999' }}>
                      <Building2 size={22} />
                    </div>
                    <div>
                      <h3 style={{ margin: 0, color: '#292454', fontSize: '16px' }}>
                        {org.name || 'Unnamed'}
                        {isMine && <span style={{ marginLeft: '8px', fontSize: '11px', color: '#7062e8', fontWeight: 600 }}>(Your Org)</span>}
                      </h3>
                      <span style={{ color: '#77758e', fontSize: '12px' }}>{org.sector || 'Sector N/A'}</span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#45435f', paddingTop: '12px', borderTop: '1px solid #f0eff6' }}>
                    {isMine ? (
                      <>
                        <span>Trust: <strong>{org.trust_score ?? 'N/A'}</strong></span>
                        <span>Violations: <strong>{org.policy_violations ?? 0}</strong></span>
                      </>
                    ) : (
                      <span style={{ color: '#94a3b8', fontStyle: 'italic' }}>Trust profile private</span>
                    )}
                  </div>
                  {isMine ? (
                    <div style={{ marginTop: '12px', textAlign: 'center', color: '#7062e8', fontSize: '12px', fontWeight: 600 }}>
                      Click to open workspace →
                    </div>
                  ) : (
                    <div style={{ marginTop: '12px', textAlign: 'center', color: '#94a3b8', fontSize: '11px', fontStyle: 'italic' }}>
                      External organization
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        ) : (
          <div className="empty-state" style={{ marginTop: '20px' }}>
            No organizations registered yet. Click "Add Organization" to start.
          </div>
        )}
      </section>
    )
  }

  const currentNav = selectedOrg ? ORG_NAV : GLOBAL_NAV

  const pageContent = selectedOrg
    ? {
        'PDF Intelligence': () => <PDFIntelligence key={selectedOrg.id} orgContext={selectedOrg} />,
        'Knowledge Graph': () => <KnowledgeGraph key={selectedOrg.id} orgContext={selectedOrg} />,
        'Temporal Intelligence': () => <TemporalIntelligence key={selectedOrg.id} orgContext={selectedOrg} />,
        'ATT&CK Matrix': () => <ATTACKNavigator key={selectedOrg.id} orgContext={selectedOrg} />,
      }
    : {
        Overview: () => <DashboardOverview records={records} organizations={organizations} />,
        'Submit CTI': () => <CTISubmissionForm />,
        Organizations: renderOrganizations,
        'Key Ceremony': () => <KeyCeremony />,
        'Crypto Sharing': () => <CryptoSharing />,
        'Revocation Demo': () => <RevocationDemo />,
        'Wallet': () => <IncentiveWallet />,
        'Access Control': () => <AccessControl />,
      }

  if (showLandingPage) return <LandingPage onOpenDashboard={() => setShowLandingPage(false)} />
  if (!authenticated) return <LoginPage notice={sessionNotice} onLogin={handleLogin} onBack={() => setShowLandingPage(true)} />

  const connectionState = error ? 'issue' : loading ? 'connecting' : 'connected'
  const connectionLabel = { issue: 'API issue', connecting: 'Connecting...', connected: 'API connected' }[connectionState]
  const renderPage = pageContent[activePage] ?? (selectedOrg ? pageContent['PDF Intelligence'] : pageContent['Overview'])
  const userInitial = (user?.name || user?.email || 'U').trim().charAt(0).toUpperCase()

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><ShieldCheck size={23} /></div>
          <div><h2>CTI-BTP</h2><small>THREAT INTELLIGENCE</small></div>
        </div>

        {selectedOrg && (
          <div style={{ padding: '12px', margin: '8px 12px', background: 'rgba(112, 98, 232, 0.15)', borderRadius: '10px', border: '1px solid rgba(112, 98, 232, 0.3)' }}>
            <div style={{ fontSize: '10px', color: '#a5b4fc', fontWeight: 700, letterSpacing: '0.5px', marginBottom: '4px' }}>VIEWING ORGANIZATION</div>
            <div style={{ color: '#fff', fontWeight: 600, fontSize: '13px' }}>{selectedOrg.name}</div>
            <div style={{ color: '#94a3b8', fontSize: '11px' }}>{selectedOrg.sector}</div>
          </div>
        )}

        <div className="nav-label">{selectedOrg ? 'ORG WORKSPACE' : 'GLOBAL WORKSPACE'}</div>

        <nav className="nav-list" aria-label="Main navigation">
          {currentNav.map(({ label, icon: Icon }) => (
            <button
              type="button"
              key={label}
              className={`nav-item ${activePage === label ? 'active' : ''}`}
              onClick={() => setActivePage(label)}
            >
              <Icon size={18} /><span>{label}</span>
            </button>
          ))}

          {selectedOrg && (
            <button
              type="button"
              className="nav-item"
              onClick={handleExitOrg}
              style={{ marginTop: '12px', color: '#f87171', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '14px' }}
            >
              <ArrowLeft size={18} /><span>Back to Global View</span>
            </button>
          )}
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />
          API connection<br />
          <span style={{ color: connectionState === 'issue' ? '#f87171' : '#34d399' }}>
            {connectionState === 'issue' ? 'Unreachable' : 'Development environment'}
          </span><br />
          Flask · React · SQLite
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <h1>{selectedOrg ? `${selectedOrg.name} — ${activePage}` : activePage}</h1>
            <p>Risk-adaptive cyber threat intelligence sharing</p>
          </div>

          <div className="topbar-right">
            <span className="connection-badge">
              <Wifi size={13} style={{ display: 'inline', marginRight: 5 }} />
              {connectionLabel}
            </span>
            <button type="button" className="button-secondary refresh-button" onClick={refresh} disabled={loading} title="Refresh">
              <RefreshCw size={15} />
            </button>
            <button
              type="button"
              className="button-secondary refresh-button"
              onClick={() => setShowLandingPage(true)}
              title="Back to landing"
            >
              <ArrowLeft size={15} />
            </button>
            <button
              type="button"
              className="button-secondary refresh-button"
              onClick={handleLogout}
              title="Logout"
              style={{ display: 'flex', alignItems: 'center', gap: '6px', paddingLeft: '12px', paddingRight: '14px' }}
            >
              <LogOut size={15} />
              <span style={{ fontSize: '12px', fontWeight: 600 }}>Logout</span>
            </button>
            <div className="avatar" title={user?.name || user?.email || ''}>{userInitial}</div>
            {user && <span style={{ fontSize: '11px', color: '#77758e', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user.name}</span>}
          </div>
        </header>

        <div className="page-content">
          <div className="toolbar dashboard-toolbar">
            <span className="record-count">
              {lastUpdated ? `Last updated ${lastUpdated.toLocaleTimeString()}` : 'Waiting for API data'}
            </span>
          </div>

          {warnings.length > 0 && (
            <div className="notice" role="status">
              <AlertTriangle size={18} />
              <p>Could not load: {warnings.join(', ')}. Showing available data.</p>
            </div>
          )}

          {renderPage()}
        </div>
      </main>

      {showAddOrgModal && (
        <AddOrganizationModal
          onClose={() => setShowAddOrgModal(false)}
          onSuccess={handleOrgCreated}
        />
      )}
    </div>
  )
}

export default App