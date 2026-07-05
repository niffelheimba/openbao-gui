const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const els = {
  badge: document.querySelector("#connection-badge"),
  warning: document.querySelector("#configuration-warning"),
  message: document.querySelector("#message"),
  roots: document.querySelector("#roots"),
  profiles: document.querySelector("#profiles"),
  sessionSummary: document.querySelector("#session-summary"),
  sessionAction: document.querySelector("#session-action"),
  deploymentName: document.querySelector("#deployment-name"),
  refreshRoots: document.querySelector("#refresh-roots"),
  serverForm: document.querySelector("#server-settings"),
  serverAddress: document.querySelector("#server-address"),
  serverNamespace: document.querySelector("#server-namespace"),
  authMount: document.querySelector("#auth-mount"),
  oidcRole: document.querySelector("#oidc-role"),
  serverSource: document.querySelector("#server-source"),
  resetServer: document.querySelector("#reset-server"),
  checkConnection: document.querySelector("#check-connection"),
};

let status;
let loginPending = false;
let certificateStatuses = new Map();
let serverSettingsLoaded = false;

function escapeHtml(value) {
  const node = document.createElement("span");
  node.textContent = String(value ?? "");
  return node.innerHTML;
}

function showMessage(text, kind = "") {
  els.message.textContent = text;
  els.message.className = `notice ${kind}`.trim();
  els.message.hidden = !text;
}

async function refresh() {
  try {
    status = await invoke("get_app_status");
    els.deploymentName.textContent = status.deploymentName;
    els.warning.hidden = status.configured;
    els.warning.textContent = status.configured ? "" : status.configurationMessage;
    els.badge.textContent = status.configured ? "Configured" : "Setup required";
    els.badge.className = `badge ${status.configured ? "good" : "bad"}`;
    if (!serverSettingsLoaded) {
      els.serverAddress.value = status.serverSettings.address;
      els.serverNamespace.value = status.serverSettings.namespace ?? "";
      els.authMount.value = status.serverSettings.authMount;
      els.oidcRole.value = status.serverSettings.oidcRole;
      serverSettingsLoaded = true;
    }
    els.serverSource.textContent = status.serverOverride ? "Using per-user settings" : "Using embedded defaults";
    els.resetServer.disabled = !status.serverOverride || Boolean(status.session) || loginPending;
    els.checkConnection.disabled = !status.configured;
    for (const control of els.serverForm.querySelectorAll("input, button[type=submit]")) {
      control.disabled = Boolean(status.session) || loginPending;
    }
    renderSession();
    await refreshRoots();
    await refreshCertificateStatus();
    renderProfiles();
  } catch (error) {
    showMessage(String(error), "error");
  }
}

async function refreshRoots() {
  try {
    const roots = await invoke("list_embedded_roots");
    els.roots.innerHTML = roots.length ? roots.map(root => `
      <div class="row">
        <div>
          <p><strong>${escapeHtml(root.subject)}</strong></p>
          <p class="meta">SHA-256 ${escapeHtml(root.fingerprint)}</p>
          <p class="muted">Valid ${escapeHtml(root.notBefore)} – ${escapeHtml(root.notAfter)}</p>
        </div>
        <div>
          ${root.installed && root.refreshable ? `<button class="quiet" data-root-refresh="${escapeHtml(root.id)}">Check update</button>` : ""}
          <button class="${root.installed ? "danger" : ""}" data-root="${escapeHtml(root.id)}" data-installed="${root.installed}">
            ${root.installed ? "Remove" : "Trust"}
          </button>
        </div>
      </div>`).join("") : '<p class="muted">No root certificates are embedded.</p>';
    document.querySelectorAll("[data-root]").forEach(button => button.addEventListener("click", async () => {
      const installed = button.dataset.installed === "true";
      if (!installed && !confirm("Trust this root certificate for your Windows account? Verify its fingerprint first.")) return;
      if (installed && !confirm("Remove this root from your Windows account? Applications that rely on it may stop working.")) return;
      button.disabled = true;
      try {
        await invoke(installed ? "remove_root" : "install_root", { rootId: button.dataset.root });
        showMessage(installed ? "Root trust removed." : "Root certificate trusted.");
        await refreshRoots();
      } catch (error) { showMessage(String(error), "error"); button.disabled = false; }
    }));
    document.querySelectorAll("[data-root-refresh]").forEach(button => button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const root = await invoke("check_root_update", { rootId: button.dataset.rootRefresh });
        if (root.installed) {
          showMessage("OpenBao returned the root that is already installed.");
        } else if (confirm(`OpenBao returned a changed root:\n\n${root.subject}\nSHA-256 ${root.fingerprint}\n\nTrust this root for your Windows account?`)) {
          await invoke("approve_root_update", { rootId: root.id, expectedFingerprint: root.fingerprint });
          showMessage("Updated root certificate trusted.");
          await refreshRoots();
        }
      } catch (error) { showMessage(String(error), "error"); }
      finally { button.disabled = false; }
    }));
  } catch (error) { els.roots.innerHTML = `<p class="muted">${escapeHtml(error)}</p>`; }
}

function renderSession() {
  const session = status?.session;
  const expiry = session ? new Date(session.expiresAt * 1000).toLocaleString() : "";
  els.sessionSummary.textContent = loginPending ? "Waiting for browser authentication…" : session ? `Signed in as ${session.identity}. Session expires ${expiry}.` : "Not signed in.";
  els.sessionAction.textContent = loginPending ? "Cancel" : session ? "Sign out" : "Sign in";
  els.sessionAction.disabled = !status?.configured;
}

function renderProfiles() {
  const profiles = status?.profiles ?? [];
  if (!profiles.length) {
    els.profiles.innerHTML = '<p class="muted">No certificate profiles are configured.</p>';
    return;
  }
  els.profiles.innerHTML = profiles.map(profile => {
    const installed = certificateStatuses.get(profile.id) ?? [];
    const latest = [...installed].sort((a, b) => Date.parse(b.notAfter) - Date.parse(a.notAfter))[0];
    const detail = latest
      ? `Installed · expires ${new Date(latest.notAfter).toLocaleString()}${installed.length > 1 ? ` · ${installed.length} matching` : ""}`
      : profile.description;
    return `
    <div class="row">
      <div><p><strong>${escapeHtml(profile.label)}</strong></p><p class="muted">${escapeHtml(detail)}</p></div>
      <button data-profile="${escapeHtml(profile.id)}" data-replace="${installed.length > 0}" ${status.session ? "" : "disabled"}>${installed.length ? "Replace" : "Request"}</button>
    </div>`;
  }).join("");
  document.querySelectorAll("[data-profile]").forEach(button => button.addEventListener("click", async () => {
    const replacing = button.dataset.replace === "true";
    const prompt = replacing
      ? "A matching certificate is already installed. Generate and install a replacement? The old certificate will remain until you verify the new one."
      : "Generate a non-exportable key and request this certificate?";
    if (!confirm(prompt)) return;
    button.disabled = true;
    showMessage("Generating a Windows key and requesting the certificate…");
    try {
      const result = await invoke("issue_certificate", { profileId: button.dataset.profile, replaceExisting: replacing });
      const warning = result.warnings?.length ? ` ${result.warnings.join(" ")}` : "";
      showMessage(`Installed certificate ${result.thumbprint}; expires ${result.notAfter}.${warning}`);
      await refreshCertificateStatus();
      renderProfiles();
    } catch (error) { showMessage(String(error), "error"); }
    finally { button.disabled = false; }
  }));
}

async function refreshCertificateStatus() {
  certificateStatuses = new Map();
  if (!status?.session) return;
  try {
    const results = await invoke("list_certificate_status");
    for (const result of results) certificateStatuses.set(result.profileId, result.certificates);
  } catch (error) {
    showMessage(`Certificate status is unavailable: ${error}`, "error");
  }
}

els.sessionAction.addEventListener("click", async () => {
  if (loginPending) {
    try { await invoke("cancel_login"); }
    catch (error) { showMessage(String(error), "error"); }
    finally { loginPending = false; renderSession(); }
    return;
  }
  if (status.session) {
    try { await invoke("logout"); showMessage("Signed out."); }
    catch (error) { showMessage(`The local session was cleared, but OpenBao revocation failed: ${error}`, "error"); }
    finally { await refresh(); }
    return;
  }
  loginPending = true;
  renderSession();
  showMessage("Complete authentication in your browser.");
  try {
    await invoke("login");
    showMessage("Authentication complete.");
  } catch (error) { showMessage(String(error), "error"); }
  finally { loginPending = false; await refresh(); }
});

els.refreshRoots.addEventListener("click", refreshRoots);
els.checkConnection.addEventListener("click", async () => {
  els.checkConnection.disabled = true;
  showMessage("Checking OpenBao over Windows-trusted HTTPS…");
  try {
    const health = await invoke("check_openbao_connection");
    showMessage(`OpenBao connection trusted. Server version ${health.version}.`);
  } catch (error) {
    showMessage(String(error), "error");
  } finally {
    els.checkConnection.disabled = false;
  }
});
els.serverForm.addEventListener("submit", async event => {
  event.preventDefault();
  try {
    await invoke("save_server_settings", { settings: {
      schemaVersion: 1,
      address: els.serverAddress.value.trim(),
      namespace: els.serverNamespace.value.trim() || null,
      authMount: els.authMount.value.trim(),
      oidcRole: els.oidcRole.value.trim(),
    }});
    showMessage("Server settings saved. Exit from the tray and reopen the application to apply them.");
  } catch (error) { showMessage(String(error), "error"); }
});
els.resetServer.addEventListener("click", async () => {
  if (!confirm("Remove the per-user server override and return to the server embedded by your administrator?")) return;
  try {
    await invoke("reset_server_settings");
    showMessage("Server override removed. Exit from the tray and reopen the application to apply the embedded defaults.");
  } catch (error) { showMessage(String(error), "error"); }
});
listen("session-changed", refresh);
refresh();
