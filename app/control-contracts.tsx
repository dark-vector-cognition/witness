"use client";

import { useState } from "react";

type Contract = { id: string; label: string; description: string; mode: string; failure: string };

export function ControlContracts({ contracts }: { contracts: Contract[] }) {
  const [selected, setSelected] = useState<Contract | null>(null);
  const [approved, setApproved] = useState(false);
  const [receipt, setReceipt] = useState("");

  function simulate() {
    if (!selected || !approved) return;
    const id = `SIM-${Date.now().toString(36).toUpperCase()}`;
    setReceipt(`${id} recorded locally. No process was changed.`);
    setApproved(false);
  }

  return (
    <section className="panel controls-panel" id="controls">
      <div className="panel-title"><div><p className="kicker">Control contracts / simulation only</p><h3>Replay, suspend, terminate</h3></div><span className="locked-chip">No live adapter authorized</span></div>
      <div className="control-grid">
        {contracts.map((contract) => <button key={contract.id} className={selected?.id === contract.id ? "selected" : ""} onClick={() => { setSelected(contract); setReceipt(""); }}><span>{contract.label}</span><small>{contract.description}</small><em>{contract.mode}</em></button>)}
      </div>
      {selected && <div className="approval-drawer" role="status"><div><p className="kicker">Safe execution envelope</p><strong>{selected.label} contract</strong><p>{selected.failure}</p></div><label><input type="checkbox" checked={approved} onChange={(event) => setApproved(event.target.checked)} /> I approve a local simulation receipt only</label><button disabled={!approved} onClick={simulate}>Record simulation</button></div>}
      {receipt && <p className="receipt">{receipt}</p>}
    </section>
  );
}
