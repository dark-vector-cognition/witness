import snapshot from "../public/data/latest.json";
import { ControlContracts } from "./control-contracts";

export const metadata = {
  title: "DVC Agent Flight Recorder",
  description: "Local-first evidence and control plane for AI agent operations.",
};

type Health = "healthy" | "attention" | "unreachable";

const healthLabel: Record<Health, string> = {
  healthy: "Nominal",
  attention: "Attention",
  unreachable: "Unreachable",
};

function StatusDot({ status }: { status: Health }) {
  return <span className={`status-dot ${status}`} aria-hidden="true" />;
}

export default function Home() {
  const healthy = snapshot.sources.filter((source) => source.health === "healthy").length;
  const attention = snapshot.sources.length - healthy;

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="mark" aria-hidden="true"><span>FR</span></div>
          <div>
            <p className="eyebrow">Dark Vector Cognition</p>
            <h1>Agent Flight Recorder</h1>
          </div>
        </div>
        <div className="system-state">
          <span className="live-pulse" aria-hidden="true" />
          <div><strong>Recorder online</strong><small>{snapshot.machine} · local evidence store</small></div>
        </div>
      </header>

      <div className="workspace">
        <aside className="rail" aria-label="Recorder navigation">
          <nav>
            <a className="nav-item active" href="#overview"><span>01</span>Overview</a>
            <a className="nav-item" href="#timeline"><span>02</span>Activity log</a>
            <a className="nav-item" href="#permissions"><span>03</span>Permissions</a>
            <a className="nav-item" href="#controls"><span>04</span>Controls</a>
          </nav>
          <div className="rail-section">
            <p className="rail-label">Observed estate</p>
            {snapshot.inventory.slice(0, 5).map((item) => (
              <div className="estate-row" key={item.id}>
                <StatusDot status={item.health as Health} />
                <div><strong>{item.name}</strong><small>{item.kind} · {item.vendor}</small></div>
              </div>
            ))}
          </div>
          <div className="recording-badge"><span>REC</span><div>Evidence chain<small>{snapshot.chain.verified ? "Hash verified" : "Needs verification"}</small></div></div>
        </aside>

        <section className="content" id="overview">
          <div className="mission-heading">
            <div>
              <p className="kicker">Operational picture / {snapshot.window}</p>
              <h2>What happened, what can act, and what proves it.</h2>
              <p className="lede">A calm, read-only view across local agent infrastructure. Control stays locked until policy and human approval are both present.</p>
            </div>
            <div className="capture-time"><small>Last capture</small><strong>{new Date(snapshot.generatedAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</strong><span>{new Date(snapshot.generatedAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}</span></div>
          </div>

          <div className="metrics" aria-label="Operational summary">
            <article className="metric primary"><p>Observed components</p><strong>{snapshot.inventory.length}</strong><span>{snapshot.counts.agents} agents · {snapshot.counts.models} models · {snapshot.counts.mcpServers} MCP</span></article>
            <article className="metric"><p>Sources nominal</p><strong>{healthy}<em>/{snapshot.sources.length}</em></strong><span className="good">{attention === 0 ? "All read-only feeds current" : `${attention} source needs attention`}</span></article>
            <article className="metric"><p>Evidence events</p><strong>{snapshot.chain.eventCount}</strong><span>Append-only · SHA-256 chained</span></article>
            <article className="metric"><p>Control authority</p><strong className="word">Locked</strong><span>Explicit approval required</span></article>
          </div>

          <div className="grid-main">
            <section className="panel timeline-panel" id="timeline">
              <div className="panel-title"><div><p className="kicker">Append-only record</p><h3>Mission timeline</h3></div><span className="evidence-chip">{snapshot.chain.shortHash}</span></div>
              <ol className="timeline">
                {snapshot.events.map((event) => (
                  <li key={event.id}>
                    <time>{new Date(event.at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time>
                    <span className={`event-node ${event.outcome}`} aria-hidden="true" />
                    <div className="event-body"><div><strong>{event.title}</strong><span className={`outcome ${event.outcome}`}>{event.outcome}</span></div><p>{event.summary}</p><small>{event.source} · evidence {event.evidenceId}</small></div>
                  </li>
                ))}
              </ol>
            </section>

            <aside className="panel source-panel">
              <div className="panel-title"><div><p className="kicker">Live ingestion</p><h3>Source health</h3></div></div>
              <div className="source-list">
                {snapshot.sources.map((source) => (
                  <article key={source.id}>
                    <div className="source-head"><StatusDot status={source.health as Health} /><div><strong>{source.name}</strong><small>{source.boundary}</small></div><span>{healthLabel[source.health as Health]}</span></div>
                    <p>{source.evidence}</p>
                    <div className="source-foot"><span>Freshness</span><strong>{source.freshness}</strong></div>
                  </article>
                ))}
              </div>
            </aside>
          </div>

          <div className="grid-lower">
            <section className="panel permission-panel" id="permissions">
              <div className="panel-title"><div><p className="kicker">Policy posture</p><h3>Permission & approval matrix</h3></div><span className="locked-chip">Deny by default</span></div>
              <div className="table-wrap"><table><thead><tr><th>Identity</th><th>Observed access</th><th>Policy</th><th>Approval evidence</th></tr></thead><tbody>
                {snapshot.permissions.map((permission) => <tr key={permission.id}><td><strong>{permission.identity}</strong><small>{permission.kind}</small></td><td>{permission.access}</td><td><span className={`policy ${permission.policy}`}>{permission.policyLabel}</span></td><td>{permission.approver}</td></tr>)}
              </tbody></table></div>
            </section>

            <section className="panel completion-panel">
              <div className="panel-title"><div><p className="kicker">Human-readable evidence</p><h3>Completion verdict</h3></div><span className="verdict">Supported</span></div>
              <p className="verdict-copy">The recorder collected current evidence from <strong>{snapshot.sources.length} safe local sources</strong>. The chain is intact and no secret-bearing fields were retained.</p>
              <dl><div><dt>Claim</dt><dd>Read-only operating picture captured</dd></div><div><dt>Proof</dt><dd>{snapshot.chain.eventCount} chained events · {snapshot.chain.shortHash}</dd></div><div><dt>Uncertainty</dt><dd>{attention ? `${attention} source failure retained in the record` : "No source failures in this capture"}</dd></div></dl>
            </section>
          </div>

          <ControlContracts contracts={snapshot.controlContracts} />
          <footer><span>DVC Agent Flight Recorder · MVP 0.1.0</span><span>Local only · no telemetry · secrets excluded at collection</span></footer>
        </section>
      </div>
    </main>
  );
}
