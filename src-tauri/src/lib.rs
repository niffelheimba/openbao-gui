mod api;
mod certificates;
mod config;
mod error;
mod redaction;
mod state;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use api::{OidcChallenge, PkiSignRequest, PollResult, ServerHealth};
use certificates::{
    AcceptancePolicy, IssuedCertificate, PendingRequest, ProfileCertificateStatus, RootInfo,
    YubiKeyRequest,
};
use config::{CertificateProfile, DeploymentConfig, ServerSettings};
use error::{AppError, AppResult};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use sha2::Digest;
use state::{AppState, PublicSession};
use tauri::{Emitter, Manager};
use tokio_util::sync::CancellationToken;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppStatus {
    configured: bool,
    configuration_message: String,
    deployment_name: String,
    session: Option<PublicSession>,
    profiles: Vec<CertificateProfile>,
    server_settings: ServerSettings,
    server_override: bool,
}

#[tauri::command]
async fn get_app_status(state: tauri::State<'_, AppState>) -> AppResult<AppStatus> {
    let runtime = state.runtime.lock().await;
    Ok(AppStatus {
        configured: state.config.configured,
        configuration_message: if state.config.configured {
            String::new()
        } else {
            "This build has no embedded trust roots or certificate profiles. Configure deployment.json before distributing it; the server endpoint itself may be changed below.".into()
        },
        deployment_name: state.config.deployment_name.clone(),
        session: runtime.session.as_ref().map(PublicSession::from),
        profiles: state.config.profiles.clone(),
        server_settings: ServerSettings::from(&state.config.openbao),
        server_override: state.server_override,
    })
}

fn ensure_server_settings_editable(runtime: &state::RuntimeState) -> AppResult<()> {
    if runtime.session.is_some() || runtime.login_cancel.is_some() {
        return Err(AppError::Configuration(
            "sign out or cancel authentication before changing server settings".into(),
        ));
    }
    Ok(())
}

#[tauri::command]
async fn save_server_settings(
    settings: ServerSettings,
    state: tauri::State<'_, AppState>,
) -> AppResult<()> {
    let runtime = state.runtime.lock().await;
    ensure_server_settings_editable(&runtime)?;
    drop(runtime);
    state.config.validate_server_settings(&settings)?;
    let parent = state.server_settings_path.parent().ok_or_else(|| {
        AppError::Configuration("server settings path has no parent directory".into())
    })?;
    std::fs::create_dir_all(parent).map_err(|_| {
        AppError::Configuration("server settings directory could not be created".into())
    })?;
    let json = serde_json::to_vec_pretty(&settings)
        .map_err(|_| AppError::Configuration("server settings could not be encoded".into()))?;
    std::fs::write(&state.server_settings_path, json)
        .map_err(|_| AppError::Configuration("server settings could not be saved".into()))
}

#[tauri::command]
async fn reset_server_settings(state: tauri::State<'_, AppState>) -> AppResult<()> {
    let runtime = state.runtime.lock().await;
    ensure_server_settings_editable(&runtime)?;
    drop(runtime);
    match std::fs::remove_file(&state.server_settings_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AppError::Configuration(
            "saved server settings could not be removed".into(),
        )),
    }
}

#[tauri::command]
fn list_embedded_roots(state: tauri::State<'_, AppState>) -> AppResult<Vec<RootInfo>> {
    state
        .config
        .roots
        .iter()
        .map(certificates::inspect_root)
        .collect()
}

#[tauri::command]
fn install_root(root_id: String, state: tauri::State<'_, AppState>) -> AppResult<()> {
    ensure_configured(&state.config)?;
    let root = state
        .config
        .roots
        .iter()
        .find(|root| root.id == root_id)
        .ok_or_else(|| AppError::Certificate("unknown embedded root".into()))?;
    certificates::install_root(root)
}

#[tauri::command]
async fn check_openbao_connection(state: tauri::State<'_, AppState>) -> AppResult<ServerHealth> {
    ensure_configured(&state.config)?;
    ensure_roots_installed(&state.config)?;
    let health = state.api.server_health().await?;
    if let Some(version) = &health.version {
        let actual = semver::Version::parse(version.trim_start_matches('v'))
            .map_err(|_| AppError::Api("OpenBao reported an invalid server version".into()))?;
        let required =
            semver::Version::parse(state.config.openbao.minimum_version.trim_start_matches('v'))
                .map_err(|_| {
                    AppError::Configuration(
                        "minimum_version is not valid semantic versioning".into(),
                    )
                })?;
        if actual < required {
            return Err(AppError::Api(format!(
                "OpenBao {required} or newer is required; server reported {actual}"
            )));
        }
    }
    Ok(health)
}

#[tauri::command]
fn remove_root(root_id: String, state: tauri::State<'_, AppState>) -> AppResult<()> {
    let root = state
        .config
        .roots
        .iter()
        .find(|root| root.id == root_id)
        .ok_or_else(|| AppError::Certificate("unknown embedded root".into()))?;
    certificates::remove_root(root)
}

#[tauri::command]
async fn login(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> AppResult<PublicSession> {
    ensure_configured(&state.config)?;
    ensure_roots_installed(&state.config)?;
    let cancel = CancellationToken::new();
    {
        let mut runtime = state.runtime.lock().await;
        if let Some(session) = &runtime.session {
            return Ok(PublicSession::from(session));
        }
        if runtime.login_cancel.is_some() {
            return Err(AppError::Api(
                "authentication is already in progress".into(),
            ));
        }
        runtime.login_cancel = Some(cancel.clone());
    }

    let result = run_login(&state, &cancel).await;
    let mut runtime = state.runtime.lock().await;
    runtime.login_cancel = None;
    match result {
        Ok(session) => {
            let public = PublicSession::from(&session);
            runtime.session = Some(session);
            drop(runtime);
            let _ = app.emit("session-changed", &public);
            Ok(public)
        }
        Err(error) => Err(error),
    }
}

async fn run_login(state: &AppState, cancel: &CancellationToken) -> AppResult<state::Session> {
    state
        .api
        .require_minimum_version(&state.config.openbao.minimum_version)
        .await?;
    let nonce = SecretString::from(uuid::Uuid::new_v4().simple().to_string());
    let redirect_uri = state.config.oidc_callback_url()?.to_string();
    let challenge = state.api.begin_oidc(&redirect_uri, nonce).await?;
    open::that(&challenge.auth_url)
        .map_err(|_| AppError::Api("the system browser could not be opened".into()))?;
    poll_until_complete(state, cancel, challenge).await
}

#[tauri::command]
async fn check_root_update(
    root_id: String,
    state: tauri::State<'_, AppState>,
) -> AppResult<RootInfo> {
    ensure_configured(&state.config)?;
    let configured_root = state
        .config
        .roots
        .iter()
        .find(|root| root.id == root_id)
        .cloned()
        .ok_or_else(|| AppError::Certificate("unknown embedded root".into()))?;
    let path = configured_root
        .refresh_path
        .clone()
        .ok_or_else(|| AppError::Certificate("this root has no refresh endpoint".into()))?;
    let token = with_active_session(&state, |session| {
        Ok(SecretString::from(session.token.expose_secret().to_owned()))
    })
    .await?;
    let pem = state.api.read_pem(&token, &path).await?;
    let block = pem::parse(&pem)
        .map_err(|_| AppError::Certificate("OpenBao returned invalid root PEM".into()))?;
    let fingerprint = hex::encode(sha2::Sha256::digest(block.contents()));
    let mut refreshed = configured_root;
    refreshed.pem = pem;
    refreshed.sha256 = fingerprint;
    let info = certificates::inspect_root(&refreshed)?;
    state.runtime.lock().await.pending_root = Some(refreshed);
    Ok(info)
}

#[tauri::command]
async fn approve_root_update(
    root_id: String,
    expected_fingerprint: String,
    state: tauri::State<'_, AppState>,
) -> AppResult<()> {
    let root = state
        .runtime
        .lock()
        .await
        .pending_root
        .take()
        .filter(|root| {
            root.id == root_id && root.sha256.eq_ignore_ascii_case(&expected_fingerprint)
        })
        .ok_or_else(|| {
            AppError::Certificate("the pending root update changed; check it again".into())
        })?;
    certificates::install_refreshed_root(&root)
}

async fn poll_until_complete(
    state: &AppState,
    cancel: &CancellationToken,
    challenge: OidcChallenge,
) -> AppResult<state::Session> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut interval = challenge.poll_interval_seconds;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Err(AppError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(AppError::Timeout),
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                match state.api.poll_oidc(&challenge, &state.config.identity.display_claim).await? {
                    PollResult::Pending => {},
                    PollResult::SlowDown => interval = interval.saturating_mul(2),
                    PollResult::Complete(mut session) => {
                        require_mapped_claim(
                            &session,
                            &state.config.identity.display_claim,
                            "display identity",
                        )?;
                        require_mapped_claim(
                            &session,
                            &state.config.identity.subject_claim,
                            "immutable subject",
                        )?;
                        session.identity = session
                            .metadata
                            .get(&state.config.identity.display_claim)
                            .cloned()
                            .ok_or(AppError::Internal)?;
                        return Ok(session);
                    }
                }
            }
        }
    }
}

fn require_mapped_claim(session: &state::Session, claim: &str, purpose: &str) -> AppResult<()> {
    match session
        .metadata
        .get(claim)
        .filter(|value| !value.trim().is_empty())
    {
        Some(_) => Ok(()),
        None => Err(AppError::Configuration(format!(
            "OpenBao OIDC metadata is missing required {purpose} claim '{claim}'"
        ))),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn with_active_session<T>(
    state: &tauri::State<'_, AppState>,
    read: impl FnOnce(&state::Session) -> AppResult<T>,
) -> AppResult<T> {
    let mut runtime = state.runtime.lock().await;
    if runtime
        .session
        .as_ref()
        .is_some_and(|session| session.expires_at <= unix_now())
    {
        runtime.session = None;
        return Err(AppError::NotAuthenticated);
    }
    let session = runtime.session.as_ref().ok_or(AppError::NotAuthenticated)?;
    read(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn session_with_metadata(metadata: HashMap<String, String>) -> state::Session {
        state::Session {
            token: SecretString::from("test-token".to_owned()),
            identity: "display".into(),
            metadata,
            expires_at: 0,
            renewable: false,
        }
    }

    #[test]
    fn mapped_claim_requires_present_non_empty_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("sub".into(), "user-uuid".into());
        let session = session_with_metadata(metadata);
        assert!(require_mapped_claim(&session, "sub", "immutable subject").is_ok());
        assert!(require_mapped_claim(&session, "preferred_username", "display identity").is_err());
    }

    #[test]
    fn mapped_claim_rejects_blank_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("sub".into(), "   ".into());
        let session = session_with_metadata(metadata);
        assert!(require_mapped_claim(&session, "sub", "immutable subject").is_err());
    }

    #[test]
    fn unix_now_is_nonzero() {
        assert!(unix_now() > 0);
    }
}

#[tauri::command]
async fn cancel_login(state: tauri::State<'_, AppState>) -> AppResult<()> {
    if let Some(cancel) = state.runtime.lock().await.login_cancel.take() {
        cancel.cancel();
    }
    Ok(())
}

#[tauri::command]
async fn logout(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> AppResult<()> {
    let session = {
        let mut runtime = state.runtime.lock().await;
        if let Some(cancel) = runtime.login_cancel.take() {
            cancel.cancel();
        }
        runtime.session.take()
    };
    if let Some(session) = session {
        state.api.revoke(&session.token).await?;
    }
    let _ = app.emit("session-changed", ());
    Ok(())
}

#[tauri::command]
async fn issue_certificate(
    profile_id: String,
    replace_existing: bool,
    state: tauri::State<'_, AppState>,
) -> AppResult<IssuedCertificate> {
    ensure_configured(&state.config)?;
    let profile = state
        .config
        .profiles
        .iter()
        .find(|profile| profile.id == profile_id)
        .cloned()
        .ok_or_else(|| AppError::Certificate("unknown certificate profile".into()))?;
    let (token, identity) = with_active_session(&state, |session| {
        let identity = session
            .metadata
            .get(&profile.subject_claim)
            .cloned()
            .ok_or_else(|| {
                AppError::Certificate(format!(
                    "OIDC session is missing required mapped claim {}",
                    profile.subject_claim
                ))
            })?;
        Ok((
            SecretString::from(session.token.expose_secret().to_owned()),
            identity,
        ))
    })
    .await?;
    let profile_for_inventory = profile.clone();
    let identity_for_inventory = identity.clone();
    let existing = tokio::task::spawn_blocking(move || {
        let all = certificates::list_personal_certificates()?;
        Ok::<_, AppError>(certificates::certificates_for_profile(
            &all,
            &profile_for_inventory,
            &identity_for_inventory,
        ))
    })
    .await
    .map_err(|_| AppError::Internal)??;
    if !existing.is_empty() && !replace_existing {
        return Err(AppError::Certificate(
            "a matching certificate is already installed; confirm replacement to continue".into(),
        ));
    }

    let request_profile = profile.clone();
    let request_identity = identity.clone();
    let pending = tokio::task::spawn_blocking(move || {
        PendingRequest::generate(&request_profile, &request_identity)
    })
    .await
    .map_err(|_| AppError::Internal)??;
    // The configured SAN claim must be present and server-side policy must bind it.
    let alt_name = profile.san_claim.as_ref();
    let alt_value = if let Some(claim) = alt_name {
        with_active_session(&state, |session| {
            session.metadata.get(claim).cloned().ok_or_else(|| {
                AppError::Certificate(format!(
                    "OIDC session is missing required mapped claim {claim}"
                ))
            })
        })
        .await?
    } else {
        String::new()
    };
    let sign_request = PkiSignRequest {
        csr: &pending.csr_pem,
        common_name: &identity,
        alt_names: if alt_value.is_empty() {
            None
        } else {
            Some(&alt_value)
        },
        format: "pem",
        exclude_cn_from_sans: alt_value.is_empty(),
    };
    let signed = state
        .api
        .sign_csr(&token, &profile.pki_mount, &profile.pki_role, &sign_request)
        .await?;
    let expected_ekus = profile.expected_eku_oids.clone();
    let expected_purpose = profile.purpose.clone();
    let expected_san = if alt_value.is_empty() {
        None
    } else {
        Some(alt_value.clone())
    };
    let mut chain = signed.ca_chain;
    if !signed.issuing_ca.is_empty() {
        chain.push(signed.issuing_ca);
    }
    chain.extend(state.config.roots.iter().map(|root| root.pem.clone()));
    let trusted_root_fingerprints = state
        .config
        .roots
        .iter()
        .map(|root| root.sha256.clone())
        .collect::<Vec<_>>();
    let mut issued = tokio::task::spawn_blocking(move || {
        pending.accept(
            &signed.certificate,
            &chain,
            AcceptancePolicy {
                trusted_root_fingerprints: &trusted_root_fingerprints,
                expected_identity: &identity,
                expected_san: expected_san.as_deref(),
                expected_purpose: &expected_purpose,
                expected_eku_oids: &expected_ekus,
            },
        )
    })
    .await
    .map_err(|_| AppError::Internal)??;
    if !existing.is_empty() {
        issued.warnings.push(format!(
            "{} previous matching certificate(s) were retained until the new certificate is verified",
            existing.len()
        ));
    }
    Ok(issued)
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct YubiKeyIssueRequest {
    profile_id: String,
    slot: String,
    pin: String,
    management_key: Option<String>,
    algorithm: String,
    pin_policy: String,
    touch_policy: String,
    replace_existing: bool,
}

#[tauri::command]
async fn issue_yubikey_certificate(
    request: YubiKeyIssueRequest,
    state: tauri::State<'_, AppState>,
) -> AppResult<IssuedCertificate> {
    ensure_configured(&state.config)?;
    let profile = state
        .config
        .profiles
        .iter()
        .find(|profile| profile.id == request.profile_id)
        .cloned()
        .ok_or_else(|| AppError::Certificate("unknown certificate profile".into()))?;
    let (token, identity, alt_value) = with_active_session(&state, |session| {
        let identity = session
            .metadata
            .get(&profile.subject_claim)
            .cloned()
            .ok_or_else(|| {
                AppError::Certificate(format!(
                    "OIDC session is missing required mapped claim {}",
                    profile.subject_claim
                ))
            })?;
        let alt_value = profile
            .san_claim
            .as_ref()
            .map(|claim| {
                session.metadata.get(claim).cloned().ok_or_else(|| {
                    AppError::Certificate(format!(
                        "OIDC session is missing required mapped claim {claim}"
                    ))
                })
            })
            .transpose()?
            .unwrap_or_default();
        Ok((
            SecretString::from(session.token.expose_secret().to_owned()),
            identity,
            alt_value,
        ))
    })
    .await?;

    let yubikey_request = YubiKeyRequest {
        slot: request.slot,
        pin: request.pin,
        management_key: request.management_key,
        algorithm: request.algorithm,
        pin_policy: request.pin_policy,
        touch_policy: request.touch_policy,
    };
    let csr_profile = profile.clone();
    let csr_identity = identity.clone();
    let replace_existing = request.replace_existing;
    let (csr_pem, directory, yubikey_request) = tokio::task::spawn_blocking(move || {
        certificates::generate_yubikey_csr(
            &csr_profile,
            &csr_identity,
            &yubikey_request,
            replace_existing,
        )
        .map(|(csr, directory)| (csr, directory, yubikey_request))
    })
    .await
    .map_err(|_| AppError::Internal)??;

    let sign_request = PkiSignRequest {
        csr: &csr_pem,
        common_name: &identity,
        alt_names: if alt_value.is_empty() {
            None
        } else {
            Some(&alt_value)
        },
        format: "pem",
        exclude_cn_from_sans: alt_value.is_empty(),
    };
    let signed = state
        .api
        .sign_csr(&token, &profile.pki_mount, &profile.pki_role, &sign_request)
        .await?;
    let expected_ekus = profile.expected_eku_oids.clone();
    let expected_purpose = profile.purpose.clone();
    let expected_san = if alt_value.is_empty() {
        None
    } else {
        Some(alt_value.clone())
    };
    let mut chain = signed.ca_chain;
    if !signed.issuing_ca.is_empty() {
        chain.push(signed.issuing_ca);
    }
    chain.extend(state.config.roots.iter().map(|root| root.pem.clone()));
    let trusted_root_fingerprints = state
        .config
        .roots
        .iter()
        .map(|root| root.sha256.clone())
        .collect::<Vec<_>>();
    let certificate = signed.certificate;
    tokio::task::spawn_blocking(move || {
        certificates::import_yubikey_certificate(
            &yubikey_request,
            directory,
            &csr_pem,
            &certificate,
            &chain,
            AcceptancePolicy {
                trusted_root_fingerprints: &trusted_root_fingerprints,
                expected_identity: &identity,
                expected_san: expected_san.as_deref(),
                expected_purpose: &expected_purpose,
                expected_eku_oids: &expected_ekus,
            },
        )
    })
    .await
    .map_err(|_| AppError::Internal)?
}

#[tauri::command]
async fn list_certificate_status(
    state: tauri::State<'_, AppState>,
) -> AppResult<Vec<ProfileCertificateStatus>> {
    let identities = with_active_session(&state, |session| {
        state
            .config
            .profiles
            .iter()
            .map(|profile| {
                session
                    .metadata
                    .get(&profile.subject_claim)
                    .cloned()
                    .map(|identity| (profile.clone(), identity))
                    .ok_or_else(|| {
                        AppError::Certificate(format!(
                            "OIDC session is missing required mapped claim {}",
                            profile.subject_claim
                        ))
                    })
            })
            .collect::<AppResult<Vec<_>>>()
    })
    .await?;
    tokio::task::spawn_blocking(move || {
        let all = certificates::list_personal_certificates()?;
        Ok(identities
            .into_iter()
            .map(|(profile, identity)| ProfileCertificateStatus {
                profile_id: profile.id.clone(),
                certificates: certificates::certificates_for_profile(&all, &profile, &identity),
            })
            .collect())
    })
    .await
    .map_err(|_| AppError::Internal)?
}

#[tauri::command]
async fn list_all_personal_certificates() -> AppResult<Vec<certificates::PersonalCertificate>> {
    tokio::task::spawn_blocking(certificates::list_personal_certificates)
        .await
        .map_err(|_| AppError::Internal)?
}

#[tauri::command]
async fn list_yubikey_certificates() -> AppResult<Vec<certificates::YubiKeySlotCertificate>> {
    tokio::task::spawn_blocking(certificates::list_yubikey_certificates)
        .await
        .map_err(|_| AppError::Internal)?
}

fn ensure_configured(config: &DeploymentConfig) -> AppResult<()> {
    if config.configured {
        Ok(())
    } else {
        Err(AppError::Configuration(
            "this build has not been configured for a homelab".into(),
        ))
    }
}

fn ensure_roots_installed(config: &DeploymentConfig) -> AppResult<()> {
    for root in &config.roots {
        if !certificates::inspect_root(root)?.installed {
            return Err(AppError::Certificate(
                "install the embedded root certificate before signing in".into(),
            ));
        }
    }
    Ok(())
}

fn show_main(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

async fn session_renewal_loop(app: tauri::AppHandle) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let state = app.state::<AppState>();
        let candidate = {
            let runtime = state.runtime.lock().await;
            let now = unix_now();
            runtime
                .session
                .as_ref()
                .filter(|session| {
                    session.renewable && session.expires_at <= now.saturating_add(300)
                })
                .map(|session| {
                    (
                        SecretString::from(session.token.expose_secret().to_owned()),
                        session.identity.clone(),
                    )
                })
        };
        let Some((token, identity)) = candidate else {
            continue;
        };
        match state.api.renew(&token).await {
            Ok((lease, renewable)) => {
                let now = unix_now();
                let mut runtime = state.runtime.lock().await;
                if let Some(session) = runtime
                    .session
                    .as_mut()
                    .filter(|session| session.identity == identity)
                {
                    session.expires_at = now.saturating_add(lease);
                    session.renewable = renewable;
                }
                drop(runtime);
                let _ = app.emit("session-changed", ());
            }
            Err(error) => tracing::warn!(error = %error, "session renewal failed"),
        }
    }
}

async fn revoke_before_exit(app: &tauri::AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let session = state.runtime.lock().await.session.take();
    if let Some(session) = session {
        let _ =
            tokio::time::timeout(Duration::from_secs(2), state.api.revoke(&session.token)).await;
    }
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "openbao_certificate_client=info".into()),
        )
        .with_target(false)
        .without_time()
        .init();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_app_status,
            save_server_settings,
            reset_server_settings,
            list_embedded_roots,
            install_root,
            check_openbao_connection,
            remove_root,
            check_root_update,
            approve_root_update,
            login,
            cancel_login,
            logout,
            list_all_personal_certificates,
            list_yubikey_certificates,
            list_certificate_status,
            issue_yubikey_certificate,
            issue_certificate
        ])
        .setup(|app| {
            let settings_path = app
                .path()
                .app_config_dir()
                .map_err(|error| {
                    std::io::Error::other(format!("resolve app config path: {error}"))
                })?
                .join("server.json");
            let (config, server_override) =
                match DeploymentConfig::load_with_server_settings(&settings_path) {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::warn!(
                            error = %crate::redaction::redact(&error.to_string()),
                            path = %settings_path.display(),
                            "saved server settings could not be loaded; falling back to embedded deployment"
                        );
                        (DeploymentConfig::load_embedded()
                            .map_err(|error| std::io::Error::other(error.to_string()))?, false)
                    }
                };
            let state = AppState::new(config, settings_path, server_override)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            app.manage(state);

            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
            let open_item =
                MenuItem::with_id(app, "open", "Open", true, None::<&str>).map_err(|error| {
                    std::io::Error::other(format!("create Open tray item: {error}"))
                })?;
            let session_item =
                MenuItem::with_id(app, "session", "Sign in / out", true, None::<&str>).map_err(
                    |error| std::io::Error::other(format!("create session tray item: {error}")),
                )?;
            let certificates_item = MenuItem::with_id(
                app,
                "certificates",
                "Certificate status",
                true,
                None::<&str>,
            )
            .map_err(|error| {
                std::io::Error::other(format!("create certificate tray item: {error}"))
            })?;
            let exit_item =
                MenuItem::with_id(app, "exit", "Exit", true, None::<&str>).map_err(|error| {
                    std::io::Error::other(format!("create Exit tray item: {error}"))
                })?;
            let menu = Menu::with_items(
                app,
                &[&open_item, &session_item, &certificates_item, &exit_item],
            )
            .map_err(|error| std::io::Error::other(format!("create tray menu: {error}")))?;
            let icon = tauri::image::Image::new_owned([12, 123, 81, 255].repeat(16 * 16), 16, 16);
            TrayIconBuilder::new()
                .icon(icon)
                .tooltip("OpenBao Certificates")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" | "session" | "certificates" => show_main(app),
                    "exit" => {
                        tauri::async_runtime::block_on(revoke_before_exit(app));
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)
                .map_err(|error| std::io::Error::other(format!("create tray icon: {error}")))?;

            if let Some(window) = app.get_webview_window("main") {
                let window_to_hide = window.clone();
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window_to_hide.hide();
                    }
                });
            }
            tauri::async_runtime::spawn(session_renewal_loop(app.handle().clone()));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running OpenBao Certificate Client");
}
