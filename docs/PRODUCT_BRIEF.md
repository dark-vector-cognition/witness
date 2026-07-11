# Product brief

## Buyer

The economic buyer is the CIO, CISO, or VP of Infrastructure at a 500–10,000 person organization adopting multiple agent platforms. The day-to-day champion is an IT operations, platform engineering, or AI governance director who must answer audit and incident questions without asking every vendor for a different log export.

## Pain

Agent estates are already fragmented across model providers, desktop copilots, MCP servers, SaaS connectors, local runtimes, and one-off automations. Inventory is incomplete, permission approval is separated from actual behavior, and “the agent finished” is usually a narrative rather than an evidence-backed conclusion. Existing observability tools often begin after model invocation; identity-governance products usually stop before agent action.

## Promise

DVC Agent Flight Recorder provides one local-first operational record of what agent infrastructure exists, what it can reach, who approved it, what happened, whether it completed, and which machine evidence supports that verdict. Observation is safe by default. Control is explicit, permissioned, and independently auditable.

## Competitive wedge

The wedge is the evidence chain between inventory, authorization, action, and outcome across vendors. The product is not another prompt trace viewer or decorative AI inventory. It treats local runtimes, MCP tools, connectors, model APIs, agent identities, human approvals, runtime failures, and durable completion evidence as one operating system. It can begin on one machine without a cloud deployment or data-export negotiation.

## Initial pricing hypothesis

- Evaluation: 30-day local pilot, up to 25 observed components, $5,000 fixed fee with guided evidence review.
- Team: $2,000/month per operating environment, up to 100 observed components and five operators.
- Enterprise: starting at $60,000/year for multiple environments, SSO/RBAC, signed policy packs, retention controls, support, and deployment review.

Pricing should be tested against the cost of audit preparation and AI-incident response, not per-token usage. “Observed component” needs customer discovery before it becomes a durable meter.

## Major risks

- A recorder cannot claim completeness until adapters can prove coverage; absence of evidence must never become evidence of absence.
- Cross-vendor control semantics are inconsistent and can create unsafe false confidence.
- Endpoint and connector metadata can itself be sensitive; collection must remain allow-listed and local by default.
- Large platform vendors may bundle partial inventory or tracing features.
- Buyers may want governance outcomes before they have stable agent identity or ownership conventions.

## MVP boundary

The MVP proves read-only local collection, normalized inventory and health, an append-only evidence timeline, explicit approval posture, human-readable completion evidence, and safe simulated control contracts. It does not claim enterprise-wide discovery, tamper-proof remote attestation, or production process control.
