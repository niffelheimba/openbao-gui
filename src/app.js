const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const els = {
  badge: document.querySelector("#connection-badge"),
  warning: document.querySelector("#configuration-warning"),
  message: document.querySelector("#message"),
  roots: document.querySelector("#roots"),
  installedCertificates: document.querySelector("#installed-certificates"),
  yubikeyCertificates: document.querySelector("#yubikey-certificates"),
  profiles: document.querySelector("#profiles"),
  yubikeyProfiles: document.querySelector("#yubikey-profiles"),
  sessionSummary: document.querySelector("#session-summary"),
  sessionAction: document.querySelector("#session-action"),
  deploymentName: document.querySelector("#deployment-name"),
  refreshRoots: document.querySelector("#refresh-roots"),
  refreshCertificates: document.querySelector("#refresh-certificates"),
  refreshYubiKeyCertificates: document.querySelector("#refresh-yubikey-certificates"),
  serverForm: document.querySelector("#server-settings"),
  serverAddress: document.querySelector("#server-address"),
  serverNamespace: document.querySelector("#server-namespace"),
  authMount: document.querySelector("#auth-mount"),
  oidcRole: document.querySelector("#oidc-role"),
  serverSource: document.querySelector("#server-source"),
  resetServer: document.querySelector("#reset-server"),
  checkConnection: document.querySelector("#check-connection"),
  yubikeySlot: document.querySelector("#yubikey-slot"),
  yubikeyAlgorithm: document.querySelector("#yubikey-algorithm"),
  yubikeyPinPolicy: document.querySelector("#yubikey-pin-policy"),
  yubikeyTouchPolicy: document.querySelector("#yubikey-touch-policy"),
  yubikeyPin: document.querySelector("#yubikey-pin"),
  yubikeyManagementKey: document.querySelector("#yubikey-management-key"),
};

let status;
let loginPending = false;
let certificateStatuses = new Map();
let yubiKeySlots = [];
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
    await refreshInstalledCertificates();
    await refreshYubiKeyCertificates();
    renderProfiles();
    renderYubiKeyProfiles();
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
          <p class="muted">Valid ${escapeHtml(root.notBefore)} - ${escapeHtml(root.notAfter)}</p>
          <p class="muted">${root.installed ? "Installed for this Windows user." : root.machineInstalled ? "Trusted machine-wide; this app can only remove per-user trust." : "Not installed for this Windows user."}</p>
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
      } catch (error) {
        showMessage(String(error), "error");
        button.disabled = false;
      }
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
      } catch (error) {
        showMessage(String(error), "error");
      } finally {
        button.disabled = false;
      }
    }));
  } catch (error) {
    els.roots.innerHTML = `<p class="muted">${escapeHtml(error)}</p>`;
  }
}

function renderSession() {
  const session = status?.session;
  const expiry = session ? new Date(session.expiresAt * 1000).toLocaleString() : "";
  els.sessionSummary.textContent = loginPending
    ? "Waiting for browser authentication..."
    : session
      ? `Signed in as ${session.identity}. Session expires ${expiry}.`
      : "Not signed in.";
  els.sessionAction.textContent = loginPending ? "Cancel" : session ? "Sign out" : "Sign in";
  els.sessionAction.disabled = !status?.configured;
}

function certificatePurpose(certificate) {
  const eku = new Set(certificate.ekuOids ?? []);
  const labels = [];
  if (eku.has("1.3.6.1.5.5.7.3.2")) labels.push("mTLS / client authentication");
  if (eku.has("1.3.6.1.5.5.7.3.4")) labels.push("S/MIME email protection");
  if (eku.has("1.3.6.1.4.1.311.10.3.12")) labels.push("Office document signing");
  if (eku.has("1.3.6.1.5.5.7.3.3")) labels.push("code signing");
  if (!labels.length && eku.size) labels.push("Other certificate usage");
  if (!labels.length) labels.push("No enhanced key usage listed");
  return labels.join(" / ");
}

function formatCertificateDate(value) {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? value : new Date(parsed).toLocaleString();
}

function isExpired(certificate) {
  const parsed = Date.parse(certificate.notAfter);
  return !Number.isNaN(parsed) && parsed <= Date.now();
}

function profileExpectedEkus(profile) {
  return profile.expected_eku_oids ?? profile.expectedEkuOids ?? [];
}

function certificateMatchesIdentity(certificate, identity) {
  if (!identity) return true;
  const lowered = identity.toLowerCase();
  return (certificate.simpleName ?? "").toLowerCase() === lowered
    || (certificate.subject ?? "").split(",").some(part => part.trim().toLowerCase() === `cn=${lowered}`)
    || (certificate.dnsNames ?? []).some(value => value.toLowerCase() === lowered)
    || (certificate.emailNames ?? []).some(value => value.toLowerCase() === lowered);
}

function matchingConfiguredProfiles(certificate) {
  const profiles = status?.profiles ?? [];
  const identities = new Map((status?.profileIdentities ?? []).map(item => [item.profileId, item]));
  return profiles.filter(profile => {
    const expected = profileExpectedEkus(profile);
    const identity = identities.get(profile.id);
    const hasIdentityMatch = identity
      ? certificateMatchesIdentity(certificate, identity.identity) || (identity.san && certificateMatchesIdentity(certificate, identity.san))
      : false;
    const hasEkus = expected.length > 0
      ? expected.every(oid => (certificate.ekuOids ?? []).includes(oid))
      : true;
    return hasIdentityMatch || (!status?.session && hasEkus);
  });
}

function configuredPkiMounts() {
  return [...new Set((status?.profiles ?? [])
    .map(profile => profile.pki_mount ?? profile.pkiMount)
    .filter(Boolean))];
}

function pkiMountForCertificate(certificate) {
  const matches = matchingConfiguredProfiles(certificate);
  const profileMount = matches
    .map(profile => profile.pki_mount ?? profile.pkiMount)
    .find(Boolean);
  if (profileMount) return profileMount;

  const mounts = configuredPkiMounts();
  return mounts.length === 1 ? mounts[0] : null;
}

function isKnownOpenBaoIssuer(certificate) {
  const issuer = (certificate.issuer ?? "").toLowerCase();
  return issuer.includes("northlake pki")
    || issuer.includes("northlake identity issuing ca")
    || issuer.includes("openbao");
}

function isAppManageableCertificate(certificate) {
  return matchingConfiguredProfiles(certificate).length > 0 || isKnownOpenBaoIssuer(certificate);
}

function profileEkuWarning(certificate, profile) {
  const expected = profileExpectedEkus(profile);
  if (!expected.length) return "";
  const missing = expected.filter(oid => !(certificate.ekuOids ?? []).includes(oid));
  return missing.length ? ` Missing expected EKU ${missing.join(", ")}.` : "";
}

function latestProfileCertificate(profileId) {
  const certificates = certificateStatuses.get(profileId) ?? [];
  return [...certificates]
    .filter(certificate => !isExpired(certificate))
    .sort((a, b) => Date.parse(b.notAfter) - Date.parse(a.notAfter))[0] ?? null;
}

function certificateLifecycle(certificate) {
  if (isExpired(certificate)) return { label: "Expired", className: "expired" };
  const matches = matchingConfiguredProfiles(certificate);
  if (!matches.length) {
    return isKnownOpenBaoIssuer(certificate)
      ? { label: "OpenBao-issued", className: "warning" }
      : { label: "Not managed by this app", className: "neutral" };
  }
  const isCurrent = matches.some(profile => {
    const latest = latestProfileCertificate(profile.id);
    return latest?.thumbprint?.toLowerCase() === certificate.thumbprint?.toLowerCase();
  });
  if (isCurrent) return { label: "Current", className: "good" };
  return { label: "Replaced / older", className: "warning" };
}

function expiringSoon(certificate, days = 14) {
  const parsed = Date.parse(certificate.notAfter);
  return !Number.isNaN(parsed) && parsed > Date.now() && parsed <= Date.now() + days * 24 * 60 * 60 * 1000;
}

function configuredProfileLabel(certificate) {
  const matches = matchingConfiguredProfiles(certificate);
  if (!matches.length) {
    return isKnownOpenBaoIssuer(certificate)
      ? "Issued by a configured OpenBao issuer, but it does not match the current profile identity/EKU rules."
      : "";
  }
  const labels = matches.map(profile => profile.label).join(", ");
  const warnings = matches.map(profile => profileEkuWarning(certificate, profile)).filter(Boolean).join(" ");
  const server = status?.serverSettings?.address ?? "the configured OpenBao server";
  return status?.session
    ? `Matches configured OpenBao profile${matches.length > 1 ? "s" : ""} on ${server}: ${labels}.${warnings}`
    : `Matches configured OpenBao profile EKU${matches.length > 1 ? "s" : ""} on ${server}: ${labels}. Sign in to verify identity.`;
}

async function refreshInstalledCertificates() {
  try {
    const certificates = await invoke("list_all_personal_certificates");
    const relevant = certificates
      .filter(certificate => certificate.hasPrivateKey || (certificate.ekuOids ?? []).length)
      .sort((a, b) => Date.parse(b.notAfter) - Date.parse(a.notAfter));
    els.installedCertificates.innerHTML = relevant.length ? relevant.map(certificate => {
      const managed = configuredProfileLabel(certificate);
      const expired = isExpired(certificate);
      const lifecycle = certificateLifecycle(certificate);
      const soon = expiringSoon(certificate);
      const appManageable = isAppManageableCertificate(certificate);
      const pkiMount = pkiMountForCertificate(certificate);
      return `
      <div class="row cert-row">
        <div>
          <p><strong>${escapeHtml(certificate.simpleName || certificate.subject)}</strong> <span class="status-pill ${escapeHtml(lifecycle.className)}">${escapeHtml(lifecycle.label)}</span>${soon ? ` <span class="status-pill warning">Expires soon</span>` : ""}</p>
          <p class="muted">${escapeHtml(certificatePurpose(certificate))}${certificate.hasPrivateKey ? " / private key available" : " / no private key"}</p>
          <p class="muted">${expired ? "Expired" : "Expires"} ${escapeHtml(formatCertificateDate(certificate.notAfter))}</p>
          <p class="muted">Issuer ${escapeHtml(certificate.issuer)}</p>
          ${managed ? `<p class="managed-note">${escapeHtml(managed)}</p>` : ""}
          ${certificate.emailNames?.length ? `<p class="muted">Email ${escapeHtml(certificate.emailNames.join(", "))}</p>` : ""}
          ${certificate.dnsNames?.length ? `<p class="muted">DNS ${escapeHtml(certificate.dnsNames.join(", "))}</p>` : ""}
          <p class="meta">Serial ${escapeHtml(certificate.serialNumber)}</p>
          <p class="meta">Thumbprint ${escapeHtml(certificate.thumbprint)}</p>
        </div>
        ${appManageable ? `<button class="danger" data-remove-cert="${escapeHtml(certificate.thumbprint)}" data-remove-cert-serial="${escapeHtml(certificate.serialNumber)}" data-remove-cert-mount="${escapeHtml(pkiMount ?? "")}" ${status?.session && pkiMount ? "" : "disabled"}>${expired ? "Revoke/remove expired" : "Revoke/remove"}</button>` : ""}
      </div>`;
    }).join("") : '<p class="muted">No client/signing/email certificates were found in CurrentUser\\My.</p>';
    document.querySelectorAll("[data-remove-cert]").forEach(button => button.addEventListener("click", async () => {
      if (!status?.session) {
        showMessage("Sign in before removing OpenBao-issued certificates so the app can revoke them first.", "error");
        return;
      }
      if (!button.dataset.removeCertMount) {
        showMessage("The app cannot infer which OpenBao PKI mount issued this certificate.", "error");
        return;
      }
      if (!confirm("Revoke this certificate in OpenBao and remove it from CurrentUser\\My?")) return;
      button.disabled = true;
      try {
        await invoke("remove_personal_certificate", {
          request: {
            thumbprint: button.dataset.removeCert,
            serialNumber: button.dataset.removeCertSerial,
            pkiMount: button.dataset.removeCertMount,
          }
        });
        showMessage("Certificate revoked in OpenBao and removed from Windows.");
        await refreshInstalledCertificates();
        await refreshCertificateStatus();
        renderProfiles();
      } catch (error) {
        showMessage(String(error), "error");
      } finally {
        button.disabled = false;
      }
    }));
  } catch (error) {
    els.installedCertificates.innerHTML = `<p class="muted">${escapeHtml(error)}</p>`;
  }
}

async function refreshYubiKeyCertificates() {
  try {
    yubiKeySlots = await invoke("list_yubikey_certificates");
    els.yubikeyCertificates.innerHTML = yubiKeySlots.length ? yubiKeySlots.map(slot => {
      const certificate = slot.certificate;
      const managed = certificate ? configuredProfileLabel(certificate) : "";
      const expired = certificate ? isExpired(certificate) : false;
      const matches = certificate ? matchingConfiguredProfiles(certificate) : [];
      const appManageable = certificate ? isAppManageableCertificate(certificate) : false;
      const pkiMount = certificate ? pkiMountForCertificate(certificate) : null;
      const lifecycle = certificate
        ? expired ? { label: "Expired", className: "expired" } : { label: matches.length ? "Profile match" : isKnownOpenBaoIssuer(certificate) ? "OpenBao-issued" : "Not managed by this app", className: matches.length ? "good" : isKnownOpenBaoIssuer(certificate) ? "warning" : "neutral" }
        : slot.hasPrivateKey ? { label: "Key only", className: "warning" } : { label: "Empty", className: "neutral" };
      const keyDetails = [
        slot.keyAlgorithm ? `key ${slot.keyAlgorithm}` : slot.hasPrivateKey ? "key present" : "",
        slot.pinPolicy ? `PIN ${slot.pinPolicy}` : "",
        slot.touchPolicy ? `touch ${slot.touchPolicy}` : "",
      ].filter(Boolean).join(" / ");
      const statusText = certificate
        ? `${certificatePurpose(certificate)} / ${slot.hasPrivateKey ? "hardware private key present" : "certificate only"}`
        : slot.hasPrivateKey
          ? "Private key present; no certificate found in this slot."
          : "Empty slot.";
      return `
      <div class="row cert-row">
        <div>
          <p><strong>Slot ${escapeHtml(slot.slot)} - ${escapeHtml(slot.label)}</strong> <span class="status-pill ${escapeHtml(lifecycle.className)}">${escapeHtml(lifecycle.label)}</span></p>
          <p class="muted">${escapeHtml(statusText)}</p>
          ${keyDetails ? `<p class="muted">${escapeHtml(keyDetails)}</p>` : ""}
          ${certificate ? `
            <p class="muted">${escapeHtml(certificate.simpleName || certificate.subject)}</p>
            <p class="muted">${expired ? "Expired" : "Expires"} ${escapeHtml(formatCertificateDate(certificate.notAfter))}</p>
            <p class="muted">Issuer ${escapeHtml(certificate.issuer)}</p>
            ${managed ? `<p class="managed-note">${escapeHtml(managed)}</p>` : ""}
            ${certificate.emailNames?.length ? `<p class="muted">Email ${escapeHtml(certificate.emailNames.join(", "))}</p>` : ""}
            ${certificate.dnsNames?.length ? `<p class="muted">DNS ${escapeHtml(certificate.dnsNames.join(", "))}</p>` : ""}
            <p class="meta">Serial ${escapeHtml(certificate.serialNumber)}</p>
            <p class="meta">Thumbprint ${escapeHtml(certificate.thumbprint)}</p>
          ` : ""}
        </div>
        ${appManageable ? `<div class="button-column">
          ${matches[0] ? `<button data-yubikey-rerequest="${escapeHtml(matches[0].id)}" data-yubikey-slot-renew="${escapeHtml(slot.slot)}" ${status?.session ? "" : "disabled"}>Re-request</button>` : ""}
          <button class="danger" data-remove-yubikey-cert="${escapeHtml(slot.slot)}" data-remove-yubikey-serial="${escapeHtml(certificate.serialNumber)}" data-remove-yubikey-mount="${escapeHtml(pkiMount ?? "")}" ${status?.session && pkiMount ? "" : "disabled"}>${expired ? "Revoke/remove expired" : "Revoke/remove"}</button>
        </div>` : ""}
      </div>`;
    }).join("") : '<p class="muted">No YubiKey PIV slots were reported.</p>';
    document.querySelectorAll("[data-yubikey-rerequest]").forEach(button => button.addEventListener("click", async () => {
      await requestYubiKeyCertificate(button.dataset.yubikeyRerequest, button.dataset.yubikeySlotRenew, true, button);
    }));
    document.querySelectorAll("[data-remove-yubikey-cert]").forEach(button => button.addEventListener("click", async () => {
      if (!els.yubikeyPin.value) {
        showMessage("Enter the YubiKey PIV PIN before removing a YubiKey certificate.", "error");
        els.yubikeyPin.focus();
        return;
      }
      if (!status?.session) {
        showMessage("Sign in before removing OpenBao-issued certificates so the app can revoke them first.", "error");
        return;
      }
      if (!button.dataset.removeYubikeyMount) {
        showMessage("The app cannot infer which OpenBao PKI mount issued this certificate.", "error");
        return;
      }
      if (!confirm(`Revoke this certificate in OpenBao and remove it from YubiKey PIV slot ${button.dataset.removeYubikeyCert}? The private key remains on the YubiKey.`)) return;
      button.disabled = true;
      try {
        await invoke("remove_yubikey_certificate", {
          request: {
            slot: button.dataset.removeYubikeyCert,
            serialNumber: button.dataset.removeYubikeySerial,
            pkiMount: button.dataset.removeYubikeyMount,
            pin: els.yubikeyPin.value,
            managementKey: els.yubikeyManagementKey.value || null,
          }
        });
        showMessage("Certificate revoked in OpenBao and removed from the YubiKey slot. The private key remains in the slot.");
        await refreshYubiKeyCertificates();
      } catch (error) {
        showMessage(String(error), "error");
      } finally {
        button.disabled = false;
      }
    }));
  } catch (error) {
    els.yubikeyCertificates.innerHTML = `<p class="muted">${escapeHtml(error)}</p>`;
  }
}

function renderProfiles() {
  const profiles = status?.profiles ?? [];
  if (!profiles.length) {
    els.profiles.innerHTML = '<p class="muted">No certificate profiles are configured.</p>';
    return;
  }
  els.profiles.innerHTML = profiles.map(profile => {
    const installed = certificateStatuses.get(profile.id) ?? [];
    const expired = installed.filter(isExpired);
    const active = installed.filter(certificate => !isExpired(certificate));
    const latest = [...active].sort((a, b) => Date.parse(b.notAfter) - Date.parse(a.notAfter))[0]
      ?? [...expired].sort((a, b) => Date.parse(b.notAfter) - Date.parse(a.notAfter))[0];
    const latestExpired = latest ? isExpired(latest) : false;
    const olderCount = Math.max(0, active.length - (latest && !latestExpired ? 1 : 0));
    const detail = latest
      ? `${latestExpired ? "Expired" : "Current"} / ${formatCertificateDate(latest.notAfter)}${expired.length ? ` / ${expired.length} expired` : ""}${olderCount ? ` / ${olderCount} older active` : ""}`
      : profile.description;
    return `
    <div class="row request-row">
      <div>
        <p><strong>${escapeHtml(profile.label)}</strong></p>
        <p class="muted">${escapeHtml(detail)}</p>
        <p class="muted">Windows native / key generated in Microsoft Software Key Storage Provider. Remove expired copies from the Installed certificates section.</p>
      </div>
      <button data-profile="${escapeHtml(profile.id)}" data-replace="${installed.length > 0}" ${status.session ? "" : "disabled"}>${latestExpired ? "Re-request expired" : installed.length ? "Replace" : "Request"}</button>
    </div>`;
  }).join("");
  document.querySelectorAll("[data-profile]").forEach(button => button.addEventListener("click", async () => {
    const replacing = button.dataset.replace === "true";
    const prompt = replacing
      ? "A matching certificate is already installed. Generate and install a replacement? The old certificate will remain until you verify the new one."
      : "Generate a non-exportable Windows key and request this certificate?";
    if (!confirm(prompt)) return;
    button.disabled = true;
    showMessage("Generating a Windows key and requesting the certificate...");
    try {
      const result = await invoke("issue_certificate", { profileId: button.dataset.profile, replaceExisting: replacing });
      const warning = result.warnings?.length ? ` ${result.warnings.join(" ")}` : "";
      showMessage(`Installed certificate ${result.thumbprint}; expires ${result.notAfter}.${warning}`);
      await refreshInstalledCertificates();
      await refreshCertificateStatus();
      renderProfiles();
    } catch (error) {
      showMessage(String(error), "error");
    } finally {
      button.disabled = false;
    }
  }));
}

function renderYubiKeyProfiles() {
  const profiles = status?.profiles ?? [];
  if (!profiles.length) {
    els.yubikeyProfiles.innerHTML = '<p class="muted">No certificate profiles are configured.</p>';
    return;
  }
  els.yubikeyProfiles.innerHTML = profiles.map(profile => {
    const defaultSlot = profile.purpose === "mtls" ? "9a" : "9c";
    return `
    <div class="row request-row">
      <div>
        <p><strong>${escapeHtml(profile.label)}</strong></p>
        <p class="muted">YubiKey-backed ${escapeHtml(profile.purpose)} certificate for web or desktop app client authentication.</p>
        <p class="muted">Requires YubiKey Manager CLI (ykman). The private key is generated on the YubiKey PIV slot.</p>
      </div>
      <label class="inline-field">Slot
        <select data-yubikey-slot-for="${escapeHtml(profile.id)}">
          <option value="9a" ${defaultSlot === "9a" ? "selected" : ""}>9a Auth</option>
          <option value="9c" ${defaultSlot === "9c" ? "selected" : ""}>9c Signature</option>
          <option value="9d">9d Key mgmt</option>
          <option value="9e">9e Card auth</option>
        </select>
      </label>
      <button data-yubikey-profile="${escapeHtml(profile.id)}" ${status.session ? "" : "disabled"}>Request on YubiKey</button>
    </div>`;
  }).join("");
  document.querySelectorAll("[data-yubikey-profile]").forEach(button => button.addEventListener("click", async () => {
    const slotSelector = document.querySelector(`[data-yubikey-slot-for="${CSS.escape(button.dataset.yubikeyProfile)}"]`);
    await requestYubiKeyCertificate(button.dataset.yubikeyProfile, slotSelector?.value ?? els.yubikeySlot.value, false, button);
  }));
}

async function requestYubiKeyCertificate(profileId, slot, replaceExisting, button) {
  if (!els.yubikeyPin.value) {
    showMessage("Enter the YubiKey PIV PIN before requesting a YubiKey certificate.", "error");
    els.yubikeyPin.focus();
    return;
  }
  const prompt = replaceExisting
    ? `Re-request this certificate using the existing key on YubiKey PIV slot ${slot}?`
    : `Generate a new key on YubiKey PIV slot ${slot} and request this certificate?\n\nThis build will not overwrite an existing YubiKey key or certificate unless you use Re-request for an expired YubiKey certificate.`;
  const currentSlot = yubiKeySlots.find(item => item.slot === slot);
  if (!replaceExisting && (currentSlot?.hasPrivateKey || currentSlot?.certificate)) {
    showMessage(`YubiKey slot ${slot} is not empty. Choose an empty slot or use Re-request on an expired certificate.`, "error");
    return;
  }
  if (!confirm(prompt)) return;
  button.disabled = true;
  showMessage("YubiKey request running. If the YubiKey starts blinking, touch its metal contact now; there may not be a separate Windows prompt.", "warning");
  try {
    const result = await invoke("issue_yubikey_certificate", {
      request: {
        profileId,
        slot,
        pin: els.yubikeyPin.value,
        managementKey: els.yubikeyManagementKey.value || null,
        algorithm: els.yubikeyAlgorithm.value,
        pinPolicy: els.yubikeyPinPolicy.value,
        touchPolicy: els.yubikeyTouchPolicy.value,
        replaceExisting,
      }
    });
    const warning = result.warnings?.length ? ` ${result.warnings.join(" ")}` : "";
    showMessage(`Imported YubiKey certificate ${result.thumbprint}; expires ${result.notAfter}.${warning}`);
    els.yubikeyPin.value = "";
    els.yubikeyManagementKey.value = "";
    await refreshInstalledCertificates();
    await refreshYubiKeyCertificates();
  } catch (error) {
    showMessage(String(error), "error");
  } finally {
    button.disabled = false;
  }
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
    try {
      await invoke("cancel_login");
    } catch (error) {
      showMessage(String(error), "error");
    } finally {
      loginPending = false;
      renderSession();
    }
    return;
  }
  if (status.session) {
    try {
      await invoke("logout");
      showMessage("Signed out.");
    } catch (error) {
      showMessage(`The local session was cleared, but OpenBao revocation failed: ${error}`, "error");
    } finally {
      await refresh();
    }
    return;
  }
  loginPending = true;
  renderSession();
  showMessage("Complete authentication in your browser.");
  try {
    await invoke("login");
    showMessage("Authentication complete.");
  } catch (error) {
    showMessage(String(error), "error");
  } finally {
    loginPending = false;
    await refresh();
  }
});

els.refreshRoots.addEventListener("click", refreshRoots);
els.refreshCertificates.addEventListener("click", refreshInstalledCertificates);
els.refreshYubiKeyCertificates.addEventListener("click", refreshYubiKeyCertificates);
els.checkConnection.addEventListener("click", async () => {
  els.checkConnection.disabled = true;
  showMessage("Checking OpenBao over Windows-trusted HTTPS...");
  try {
    const health = await invoke("check_openbao_connection");
    showMessage(health.version
      ? `OpenBao connection trusted. Server version ${health.version}.`
      : "OpenBao connection trusted. Server did not report a version.");
  } catch (error) {
    showMessage(String(error), "error");
  } finally {
    els.checkConnection.disabled = false;
  }
});

els.serverForm.addEventListener("submit", async event => {
  event.preventDefault();
  try {
    await invoke("save_server_settings", {
      settings: {
        schemaVersion: 1,
        address: els.serverAddress.value.trim(),
        namespace: els.serverNamespace.value.trim() || null,
        authMount: els.authMount.value.trim(),
        oidcRole: els.oidcRole.value.trim(),
      }
    });
    showMessage("Server settings saved. Exit from the tray and reopen the application to apply them.");
  } catch (error) {
    showMessage(String(error), "error");
  }
});

els.resetServer.addEventListener("click", async () => {
  if (!confirm("Remove the per-user server override and return to the server embedded by your administrator?")) return;
  try {
    await invoke("reset_server_settings");
    showMessage("Server override removed. Exit from the tray and reopen the application to apply the embedded defaults.");
  } catch (error) {
    showMessage(String(error), "error");
  }
});

listen("session-changed", refresh);
refresh();
