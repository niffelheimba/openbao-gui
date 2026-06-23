mod api;
mod certificates;
mod config;
mod error;
mod redaction;
mod state;

use std::time::Duration;

use api::{OidcChallenge, PkiSignRequest, PollResult};
use certificates::{IssuedCertificate, PendingRequest, ProfileCertificateStatus, RootInfo};
use config::{CertificateProfile, DeploymentConfig};
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
}

#[tauri::command]
async fn get_app_status(state: tauri::State<'_, AppState>) -> AppResult<AppStatus> {
    let runtime = state.runtime.lock().await;
    Ok(AppStatus {
        configured: state.config.configured,
        configuration_message: if state.config.configured {
            String::new()
        } else {
            "Replace src-tauri/resources/deployment.json with your validated homelab configuration before distributing this build.".into()
        },
        deployment_name: state.config.deployment_name.clone(),
        session: runtime.session.as_ref().map(PublicSession::from),
        profiles: state.config.profiles.clone(),
    })
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
    let token = {
        let runtime = state.runtime.lock().await;
        let session = runtime.session.as_ref().ok_or(AppError::NotAuthenticated)?;
        SecretString::from(session.token.expose_secret().to_owned())
    };
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
                    PollResult::SlowDown => interval = interval.saturating_mul(2).min(60),
                    PollResult::Complete(session) => return Ok(session),
                }
            }
        }
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
    let (token, identity) = {
        let runtime = state.runtime.lock().await;
        let session = runtime.session.as_ref().ok_or(AppError::NotAuthenticated)?;
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
        (
            SecretString::from(session.token.expose_secret().to_owned()),
            identity,
        )
    };
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
        let runtime = state.runtime.lock().await;
        runtime
            .session
            .as_ref()
            .and_then(|session| session.metadata.get(claim))
            .cloned()
            .ok_or_else(|| {
                AppError::Certificate(format!(
                    "OIDC session is missing required mapped claim {claim}"
                ))
            })?
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
    };
    let signed = state
        .api
        .sign_csr(&token, &profile.pki_mount, &profile.pki_role, &sign_request)
        .await?;
    let expected_ekus = profile.expected_eku_oids.clone();
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
            &trusted_root_fingerprints,
            &identity,
            &expected_ekus,
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

#[tauri::command]
async fn list_certificate_status(
    state: tauri::State<'_, AppState>,
) -> AppResult<Vec<ProfileCertificateStatus>> {
    let identities = {
        let runtime = state.runtime.lock().await;
        let session = runtime.session.as_ref().ok_or(AppError::NotAuthenticated)?;
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
            .collect::<AppResult<Vec<_>>>()?
    };
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
    use std::time::{SystemTime, UNIX_EPOCH};
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let state = app.state::<AppState>();
        let candidate = {
            let runtime = state.runtime.lock().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
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
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
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

    let config =
        DeploymentConfig::load_embedded().expect("embedded deployment configuration must be valid");
    let state = AppState::new(config).expect("HTTP client must initialize");
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_app_status,
            list_embedded_roots,
            install_root,
            remove_root,
            check_root_update,
            approve_root_update,
            login,
            cancel_login,
            logout,
            list_certificate_status,
            issue_certificate
        ])
        .setup(|app| {
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
