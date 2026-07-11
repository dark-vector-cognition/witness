"use client";

import { useEffect, useState } from "react";

type Contract = { id: string; label: string; description: string; mode: string; failure: string };
type ServiceStatus = { service: string; operator: string; target: { id: string; kind: string; state: string }; capabilities: string[] };
type Approval = { approvalId: string; nonce: string; action: string; expiresAt: string; targetId: string; operator: string };
type Receipt = { receiptId: string; action: string; outcome: string; beforeState: string; afterState: string; summary: string };

const controlUrl = "/api/control";

export function ControlContracts({ contracts }: { contracts: Contract[] }) {
  const [selected, setSelected] = useState<Contract | null>(null);
  const [status, setStatus] = useState<ServiceStatus | null>(null);
  const [reason, setReason] = useState("");
  const [approval, setApproval] = useState<Approval | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [message, setMessage] = useState("Connecting to the loopback-only control service…");
  const [busy, setBusy] = useState(false);

  async function refreshStatus() {
    try {
      const response = await fetch(`${controlUrl}/status`, { cache: "no-store" });
      if (!response.ok) throw new Error("offline");
      const nextStatus = await response.json() as ServiceStatus;
      setStatus(nextStatus);
      setMessage("Loopback control service online");
    } catch {
      setStatus(null);
      setMessage("Control service offline — observation remains available");
    }
  }

  useEffect(() => {
    let active = true;
    fetch(`${controlUrl}/status`, { cache: "no-store" })
      .then((response) => { if (!response.ok) throw new Error("offline"); return response.json() as Promise<ServiceStatus>; })
      .then((nextStatus) => { if (active) { setStatus(nextStatus); setMessage("Loopback control service online"); } })
      .catch(() => { if (active) { setStatus(null); setMessage("Control service offline — observation remains available"); } });
    return () => { active = false; };
  }, []);

  async function issueApproval() {
    if (!selected || selected.id === "replay" || !status) return;
    setBusy(true);
    setReceipt(null);
    try {
      const response = await fetch(`${controlUrl}/approvals`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: selected.id, targetId: status.target.id, reason }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "approval denied");
      setApproval(body as Approval);
      setMessage(`Single-use approval ${body.approvalId} recorded`);
    } catch (error) {
      setApproval(null);
      setMessage(error instanceof Error ? error.message : "approval failed");
    } finally { setBusy(false); }
  }

  async function executeControl() {
    if (!approval || !selected) return;
    setBusy(true);
    try {
      const response = await fetch(`${controlUrl}/controls`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ approvalId: approval.approvalId, nonce: approval.nonce, action: selected.id, targetId: approval.targetId }) });
      const body = await response.json() as Receipt;
      setReceipt(body);
      setMessage(body.summary || (response.ok ? "Control verified" : "Control denied"));
      setApproval(null);
      await refreshStatus();
    } catch {
      setMessage("Control result unknown — check the evidence ledger");
    } finally { setBusy(false); }
  }

  function select(contract: Contract) {
    setSelected(contract);
    setApproval(null);
    setReceipt(null);
    setReason("");
    if (contract.id === "replay") setMessage("Replay remains evidence-only and does not re-run side effects");
  }

  return (
    <section className="panel controls-panel" id="controls">
      <div className="panel-title"><div><p className="kicker">Bounded control plane</p><h3>Replay, suspend, resume, terminate</h3></div><span className={status ? "verdict" : "locked-chip"}>{status ? "Test adapter online" : "Observation only"}</span></div>
      <div className="control-state"><span className={status ? "status-dot healthy" : "status-dot attention"} /><div><strong>{status ? status.target.kind : "No controllable target"}</strong><small>{status ? `${status.target.state} · ${status.operator}` : message}</small></div>{status && <code>{status.target.id.slice(-12)}</code>}</div>
      <div className="control-grid">
        {contracts.map((contract) => <button key={contract.id} className={selected?.id === contract.id ? "selected" : ""} onClick={() => select(contract)}><span>{contract.label}</span><small>{contract.description}</small><em>{contract.mode}</em></button>)}
      </div>
      {selected && selected.id !== "replay" && <div className="approval-workflow" role="status">
        <div><p className="kicker">Durable single-use approval</p><strong>{selected.label} · {status?.target.state || "offline"}</strong><p>{selected.failure}</p></div>
        <label>Operator reason<input value={reason} maxLength={240} placeholder="Why is this control necessary?" onChange={(event) => setReason(event.target.value)} /></label>
        <div className="approval-actions"><button disabled={!status || reason.trim().length < 8 || busy || Boolean(approval)} onClick={issueApproval}>Issue approval</button><button className="execute" disabled={!approval || busy} onClick={executeControl}>Execute once</button></div>
        {approval && <p className="approval-proof">{approval.approvalId} · expires {new Date(approval.expiresAt).toLocaleTimeString()}</p>}
      </div>}
      <p className="control-message">{message}</p>
      {receipt && <dl className="control-receipt"><div><dt>Receipt</dt><dd>{receipt.receiptId}</dd></div><div><dt>Verdict</dt><dd>{receipt.outcome}</dd></div><div><dt>State proof</dt><dd>{receipt.beforeState} → {receipt.afterState}</dd></div></dl>}
    </section>
  );
}
