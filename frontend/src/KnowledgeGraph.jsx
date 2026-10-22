import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import {
  Activity, AlertTriangle, CircleDot, Clock3, Network, RefreshCw, Search, ShieldAlert, Workflow, Crown, Maximize,
} from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./KnowledgeGraph.css";

const NODE_STYLES = {
  organization: { color: "#7062e8", label: "Organization" },
  ip: { color: "#3b82f6", label: "IP Address" },
  domain: { color: "#10b981", label: "Domain" },
  sha256: { color: "#ec4899", label: "File Hash" },
  sha1: { color: "#ec4899", label: "File Hash" },
  md5: { color: "#ec4899", label: "File Hash" },
  cve: { color: "#f59e0b", label: "CVE" },
  other: { color: "#94a3b8", label: "Other" },
};

function getNodeStyle(node) {
  if (node.type === "organization") return NODE_STYLES.organization;
  return NODE_STYLES[node.type] || NODE_STYLES.other;
}

function shortLabel(node) {
  if (node.type === "organization") return node.label || node.name;
  const val = node.label || "";
  if (val.length > 25) return val.substring(0, 22) + "...";
  return val;
}

function NodeDetails({ node }) {
  if (!node) {
    return (
      <div className="kg-empty">
        <CircleDot size={22} />
        <p>Click any node in the graph to inspect its details.</p>
      </div>
    );
  }
  const fields = Object.entries(node).filter(
    ([key, value]) =>
      !["id", "x", "y", "vx", "vy", "index", "normalized_entity", "color", "label"].includes(key) &&
      value !== null && value !== undefined && typeof value !== "object"
  );
  return (
    <div className="kg-details">
      <span className="kg-eyebrow">{getNodeStyle(node).label}</span>
      <h3 style={{ wordBreak: "break-all" }}>{shortLabel(node)}</h3>
      {fields.map(([key, value]) => (
        <div className="kg-detail-row" key={key}>
          <span>{key.replaceAll("_", " ")}</span>
          <strong>{String(value) || "—"}</strong>
        </div>
      ))}
    </div>
  );
}

export default function KnowledgeGraph({ orgContext }) {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [conflicts, setConflicts] = useState([]);
  const [centralityData, setCentralityData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedNode, setSelectedNode] = useState(null);
  const [search, setSearch] = useState("");
  const [nodeFilter, setNodeFilter] = useState("all");
  const [hoverNode, setHoverNode] = useState(null);
  const [canvasSize, setCanvasSize] = useState({ width: 800, height: 600 });

  const fgRef = useRef();
  const roRef = useRef();
  const canvasWrapperRef = useCallback((el) => {
    if (roRef.current) roRef.current.disconnect();
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      if (width > 0 && height > 0) setCanvasSize({ width, height });
    });
    ro.observe(el);
    roRef.current = ro;
  }, []);

  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const token = getAccessToken();
      if (!token) throw new Error("You are not logged in. Please log in again.");
      const headers = { Authorization: `Bearer ${token}` };
      const orgQuery = orgContext ? `?org_id=${orgContext.id}` : '';
      
      const [graphRes, conflictRes, centralityRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/graph/temporal${orgQuery}`, { headers }),
        fetch(`${API_BASE_URL}/api/graph/contradictions`, { headers }),
        fetch(`${API_BASE_URL}/api/graph/centrality`, { headers })
      ]);
      if (!graphRes.ok) throw new Error(`Server error: ${graphRes.status}`);
      const graphJson = await graphRes.json();
      const conflictJson = conflictRes.ok ? await conflictRes.json() : { contradictions: [] };
      const centralityJson = centralityRes.ok ? await centralityRes.json() : null;
      setGraphData({ nodes: graphJson.nodes || [], links: graphJson.links || [] });
      setConflicts(conflictJson.contradictions || []);
      setCentralityData(centralityJson);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [orgContext]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  useEffect(() => {
    if (graphData.nodes.length > 0 && fgRef.current) {
      setTimeout(() => fgRef.current.zoomToFit(400, 100), 1000);
    }
  }, [graphData]);


  const filteredData = useMemo(() => {
    const query = search.trim().toLowerCase();
    const filteredNodes = graphData.nodes.filter((node) => {
      const matchesType = nodeFilter === "all" || node.type === nodeFilter;
      const matchesSearch = !query || Object.values(node).some((val) => 
        String(val).toLowerCase().includes(query)
      );
      return matchesType && matchesSearch;
    });
    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = graphData.links.filter(
      link => nodeIds.has(link.source.id || link.source) && nodeIds.has(link.target.id || link.target)
    );
    return { nodes: filteredNodes, links: filteredLinks };
  }, [graphData, search, nodeFilter]);

  const isNodeDimmed = (node) => {
    if (!hoverNode) return false;
    if (node.id === hoverNode.id) return false;
    const isConnected = graphData.links.some(
      link => (link.source.id === hoverNode.id && link.target.id === node.id) ||
              (link.target.id === hoverNode.id && link.source.id === node.id)
    );
    return !isConnected;
  };

  if (loading && graphData.nodes.length === 0) return <div className="kg-state">Loading CTI knowledge graph…</div>;
  if (error && graphData.nodes.length === 0) {
    return (
      <div className="kg-error">
        <AlertTriangle size={20} />
        <div>
          <strong>Unable to load graph</strong>
          <p>{error}</p>
          <button className="kg-button" onClick={loadGraph}><RefreshCw size={15} /> Retry</button>
        </div>
      </div>
    );
  }

  return (
    <section className="kg-page">
      <div className="kg-header">
        <div>
          <div className="kg-eyebrow"><Network size={15} /> THREAT INTELLIGENCE</div>
          <h2>{orgContext ? `${orgContext.name} — Knowledge Graph` : 'Temporal Knowledge Graph'}</h2>
          <p>Explore connections between organizations and threat actors. Hover to highlight paths.</p>
        </div>
        <div style={{ display: "flex", gap: "12px" }}>
          <button className="kg-button" onClick={() => fgRef.current?.zoomToFit(400, 100)}>
            <Maximize size={15} /> Fit View
          </button>
          <button className="kg-button" onClick={loadGraph} disabled={loading}>
            <RefreshCw size={15} className={loading ? "kg-spin" : ""} />
            {loading ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </div>

      {error && <div className="kg-inline-error">{error}</div>}

      <div className="kg-metrics">
        <Metric icon={<Network size={19} />} label="Graph nodes" value={filteredData.nodes.length} />
        <Metric icon={<Workflow size={19} />} label="Relationships" value={filteredData.links.length} />
        <Metric icon={<ShieldAlert size={19} />} label="Severity conflicts" value={conflicts.length} alert={conflicts.length > 0} />
        <Metric icon={<Clock3 size={19} />} label="Entities" value={graphData.nodes.filter(n => n.type !== 'organization').length} />
      </div>

      <div className="kg-legend">
        {Object.values(NODE_STYLES).filter(s => s.label !== "Other").map((style, idx) => (
          <span key={idx}><i style={{ background: style.color, color: style.color }} />{style.label}</span>
        ))}
        <span><i className="kg-edge-key" /> Relationship</span>
      </div>

      {centralityData && centralityData.most_influential_nodes && (
        <div className="panel no-print" style={{ marginBottom: '24px', marginTop: '16px' }}>
          <div className="panel-heading">
            <div>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Crown size={18} color="#fbbf24" /> Most Influential Nodes (PageRank)
              </h3>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
            {centralityData.most_influential_nodes.map((node, idx) => (
              <div key={idx} className="kpi-card" style={{ borderLeft: '4px solid #fbbf24', padding: '16px' }}>
                <div className="kpi-label" style={{ fontSize: '11px', marginBottom: '4px' }}>Rank #{idx + 1}</div>
                <div style={{ fontWeight: 700, fontSize: '13px', marginBottom: '8px', wordBreak: 'break-all' }}>
                  {node.node.length > 25 ? node.node.substring(0, 25) + '...' : node.node}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>PageRank: <strong>{node.pagerank_score}</strong></div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Connections: {node.connections}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="kg-layout">
        <div className="kg-panel kg-canvas-wrapper" ref={canvasWrapperRef}>
          <ForceGraph2D
            ref={fgRef}
            graphData={filteredData}
            width={canvasSize.width}
            height={canvasSize.height}
            nodeLabel="label"
            d3VelocityDecay={0.15}
            d3AlphaDecay={0.015}
            cooldownTicks={200}
            d3Force={(d3Force) => {
              d3Force('charge').strength(-1200);
              d3Force('link').distance(150);
            }}
            linkCurvature={0.1}
            linkColor={(link) => {
              if (!hoverNode) return "rgba(255, 255, 255, 0.1)";
              const isLinked = link.source.id === hoverNode.id || link.target.id === hoverNode.id;
              return isLinked ? "rgba(255, 255, 255, 0.8)" : "rgba(255, 255, 255, 0.05)";
            }}
            onNodeHover={(node) => setHoverNode(node)}
            onNodeClick={(node) => setSelectedNode(node)}
            nodeCanvasObject={(node, ctx, globalScale) => {
              const style = getNodeStyle(node);
              const dimmed = isNodeDimmed(node);
              const radius = node.type === "organization" ? 10 : 6;
              ctx.globalAlpha = dimmed ? 0.1 : 1.0;
              ctx.beginPath();
              ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
              ctx.fillStyle = style.color;
              ctx.fill();
              if (hoverNode && node.id === hoverNode.id) {
                ctx.lineWidth = 2 / globalScale;
                ctx.strokeStyle = "#ffffff";
                ctx.stroke();
              }
              const showLabel = globalScale > 1.5 || node.type === "organization" || (hoverNode && node.id === hoverNode.id);
              if (showLabel) {
                const label = shortLabel(node);
                const fontSize = 12 / globalScale;
                ctx.font = `600 ${fontSize}px 'Inter', sans-serif`;
                const textWidth = ctx.measureText(label).width;
                ctx.fillStyle = "rgba(15, 23, 42, 0.85)";
                ctx.fillRect(node.x - textWidth / 2 - 4, node.y + radius + 2, textWidth + 8, fontSize + 4);
                ctx.textAlign = "center";
                ctx.textBaseline = "middle";
                ctx.fillStyle = "#ffffff";
                ctx.fillText(label, node.x, node.y + radius + fontSize / 2 + 4);
              }
              ctx.globalAlpha = 1.0;
            }}
          />
        </div>

        <aside className="kg-panel kg-inspector">
          <div className="kg-panel-heading">
            <CircleDot size={18} />
            <h3>Node details</h3>
          </div>
          <div className="kg-toolbar" style={{ padding: '0 0 16px 0', borderBottom: '1px solid #e8e6f1' }}>
            <label className="kg-search" style={{ flex: 1 }}>
              <Search size={16} />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search graph..." />
            </label>
            <select value={nodeFilter} onChange={(e) => setNodeFilter(e.target.value)}>
              <option value="all">All Types</option>
              <option value="organization">Organizations</option>
              <option value="ip">IP Addresses</option>
              <option value="domain">Domains</option>
              <option value="sha256">File Hashes</option>
              <option value="cve">CVEs</option>
            </select>
          </div>
          <NodeDetails node={selectedNode} />
          <div className="kg-conflicts">
            <div className="kg-panel-heading">
              <AlertTriangle size={17} />
              <h3>Severity conflicts</h3>
            </div>
            {conflicts.length === 0 ? (
              <p className="kg-muted">No severity conflicts detected.</p>
            ) : (
              conflicts.map((conflict, idx) => (
                <div className="kg-conflict" key={idx}>
                  <strong>{conflict.indicator_value}</strong>
                  <div className="kg-severity-list"><span>{conflict.reports}</span></div>
                </div>
              ))
            )}
          </div>
        </aside>
      </div>
    </section>
  );
}

function Metric({ icon, label, value, alert = false }) {
  return (
    <div className="kg-metric">
      <span className={`kg-metric-icon ${alert ? "alert" : ""}`}>{icon}</span>
      <span className="kg-metric-label">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}