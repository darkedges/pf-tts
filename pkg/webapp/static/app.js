(() => {
  "use strict";

  const state = { csrf: "", records: [], auditVersion: "", selected: "", timer: 0 };
  const byId = (id) => document.getElementById(id);
  const identity = byId("identity");
  const signIn = byId("sign-in");
  const signOut = byId("sign-out");
  const form = byId("interaction-form");
  const welcome = byId("welcome");
  const serviceState = byId("service-state");
  const auditState = byId("audit-state");
  const auditList = byId("audit-list");
  const refreshAudit = byId("refresh-audit");

  const request = async (path, options = {}) => {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options });
    if (!response.ok) throw new Error(String(response.status));
    if (response.status === 204) return null;
    return response.json();
  };

  const badgeClass = (decision) => decision === "allow" ? "allow" : decision === "deny" ? "deny" : "neutral";
  const setBadge = (element, text, kind) => { element.textContent = text; element.className = `state-badge ${kind}`; };

  const signedOut = () => {
    state.csrf = "";
    state.records = [];
    state.auditVersion = "";
    state.selected = "";
    identity.textContent = "Not signed in";
    signIn.hidden = false;
    signOut.hidden = true;
    form.hidden = true;
    welcome.hidden = false;
    refreshAudit.disabled = true;
    setBadge(serviceState, "Signed out", "neutral");
    auditState.textContent = "Sign in to view interactions.";
    auditList.replaceChildren();
    byId("detail-fields").replaceChildren();
    byId("audit-detail").hidden = true;
    setBadge(byId("result-status"), "No invocation", "neutral");
    byId("result-message").textContent = "Run an approved interaction to see its verified transaction identifier.";
    byId("result-transaction").textContent = "";
    byId("result-details").hidden = true;
    if (state.timer) window.clearInterval(state.timer);
  };

  const loadSession = async () => {
    try {
      const session = await request("/api/session");
      state.csrf = session.csrf_token;
      identity.textContent = `Signed in as ${session.subject}`;
      signIn.hidden = true;
      signOut.hidden = false;
      form.hidden = false;
      welcome.hidden = true;
      refreshAudit.disabled = false;
      setBadge(serviceState, "Ready", "allow");
      await loadAudit();
      state.timer = window.setInterval(loadAudit, 3000);
    } catch (_) {
      signedOut();
    }
  };

  const loadAudit = async () => {
    if (!state.csrf) return;
    auditState.textContent = "Loading verified events…";
    try {
      state.records = await request("/api/interactions");
      renderAudit(state.records);
    } catch (_) {
      auditState.textContent = "Audit trail is unavailable. The operation may have failed closed.";
    }
  };

  const renderAudit = (records) => {
    const version = records.map((record) => record.id).join("|");
    if (version === state.auditVersion) {
      auditState.textContent = `${records.length} verified event${records.length === 1 ? "" : "s"}`;
      return;
    }
    state.auditVersion = version;
    auditList.replaceChildren();
    if (!records.length) {
      auditState.textContent = "No verified interactions yet.";
      return;
    }
    auditState.textContent = `${records.length} verified event${records.length === 1 ? "" : "s"}`;
    const groups = new Map();
    records.forEach((record) => {
      if (!groups.has(record.transaction_id)) groups.set(record.transaction_id, []);
      groups.get(record.transaction_id).push(record);
    });
    groups.forEach((events, transaction) => {
      const group = document.createElement("section");
      group.className = "transaction-group";
      group.setAttribute("role", "listitem");
      const label = document.createElement("div");
      label.className = "transaction-label";
      label.textContent = `Transaction ${transaction}`;
      group.append(label);
      events.sort((a, b) => a.sequence - b.sequence).forEach((event, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "audit-event";
        button.setAttribute("aria-label", `${index + 1} ${event.event_type} ${event.target || event.submitting_spiffe_id} ${event.decision || "observed"} transaction ${transaction}`);
        button.addEventListener("click", () => showDetail(event.id));
        const hop = document.createElement("span");
        hop.className = "hop";
        hop.textContent = String(index + 1);
        const copy = document.createElement("span");
        copy.className = "event-copy";
        const name = document.createElement("strong");
        name.textContent = event.event_type;
        const target = document.createElement("span");
        target.textContent = event.target || event.submitting_spiffe_id;
        copy.append(name, target);
        const badge = document.createElement("span");
        badge.className = `state-badge ${badgeClass(event.decision)}`;
        badge.textContent = event.decision || "observed";
        button.append(hop, copy, badge);
        group.append(button);
      });
      auditList.append(group);
    });
  };

  const showDetail = async (id) => {
    try {
      state.selected = id;
      const record = await request(`/api/interactions/${encodeURIComponent(id)}`);
      const fields = byId("detail-fields");
      fields.replaceChildren();
      const safeFields = ["event_type", "transaction_id", "timestamp", "target", "decision", "reason_code", "agent_id", "transaction_workload_id", "immediate_caller_spiffe_id", "submitting_spiffe_id", "protocol_method", "tool", "purpose", "response_status", "result_type", "duration_ms"];
      safeFields.forEach((key) => {
        if (record[key] === undefined || record[key] === "" || record[key] === 0) return;
        const row = document.createElement("div");
        const term = document.createElement("dt");
        const value = document.createElement("dd");
        term.textContent = key.replaceAll("_", " ");
        value.textContent = String(record[key]);
        row.append(term, value);
        fields.append(row);
      });
      const token = record.verified_transaction_token;
      if (token && typeof token === "object") {
        const tokenFields = ["kind", "fingerprint", "issuer", "audience", "scope", "jwt_id", "agent_instance_id", "issued_at", "expires_at"];
        tokenFields.forEach((key) => {
          if (token[key] === undefined || token[key] === "" || (Array.isArray(token[key]) && token[key].length === 0)) return;
          const row = document.createElement("div");
          const term = document.createElement("dt");
          const value = document.createElement("dd");
          term.textContent = `verified token ${key.replaceAll("_", " ")}`;
          value.textContent = Array.isArray(token[key]) ? token[key].join(", ") : String(token[key]);
          row.append(term, value);
          fields.append(row);
        });
        const notice = document.createElement("div");
        const noticeTerm = document.createElement("dt");
        const noticeValue = document.createElement("dd");
        noticeTerm.textContent = "raw token";
        noticeValue.textContent = "Withheld: bearer credentials are never returned to the browser.";
        notice.append(noticeTerm, noticeValue);
        fields.append(notice);
      }
      byId("audit-detail").hidden = false;
      byId("detail-title").focus?.();
    } catch (_) {
      state.selected = "";
      auditState.textContent = "That audit event is unavailable for this session.";
    }
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const invoke = byId("invoke");
    invoke.disabled = true;
    setBadge(byId("result-status"), "Running", "neutral");
    byId("result-message").textContent = "Exchanging verified identities and invoking the approved service…";
    try {
      const result = await request("/api/interactions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": state.csrf },
        body: JSON.stringify({ tool: byId("tool").value, purpose: byId("purpose").value })
      });
      setBadge(byId("result-status"), "Completed", "allow");
      byId("result-message").textContent = "The delegated call completed with a verified transaction context.";
      byId("result-transaction").textContent = result.transaction_id;
      byId("result-details").hidden = false;
      await loadAudit();
    } catch (error) {
      const denied = error.message === "400" || error.message === "401" || error.message === "403";
      setBadge(byId("result-status"), denied ? "Denied" : "Unavailable", "deny");
      byId("result-message").textContent = denied ? "The request was rejected by an identity or policy boundary." : "A required service or audit boundary was unavailable; the operation failed closed.";
    } finally {
      invoke.disabled = false;
    }
  });

  signOut.addEventListener("click", async () => {
    try {
      await request("/logout", { method: "POST", headers: { "X-CSRF-Token": state.csrf } });
    } finally {
      signedOut();
    }
  });
  refreshAudit.addEventListener("click", loadAudit);
  byId("close-detail").addEventListener("click", () => { state.selected = ""; byId("audit-detail").hidden = true; });
  loadSession();
})();
