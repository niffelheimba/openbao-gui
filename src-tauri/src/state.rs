use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use secrecy::SecretString;
use serde::Serialize;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::api::OpenBaoClient;
use crate::config::DeploymentConfig;

#[derive(Debug)]
pub struct Session {
    pub token: SecretString,
    pub identity: String,
    pub metadata: HashMap<String, String>,
    pub expires_at: u64,
    pub renewable: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicSession {
    pub identity: String,
    pub expires_at: u64,
    pub renewable: bool,
}

impl From<&Session> for PublicSession {
    fn from(value: &Session) -> Self {
        Self {
            identity: value.identity.clone(),
            expires_at: value.expires_at,
            renewable: value.renewable,
        }
    }
}

pub struct RuntimeState {
    pub session: Option<Session>,
    pub login_cancel: Option<CancellationToken>,
    pub pending_root: Option<crate::config::RootConfig>,
}

pub struct AppState {
    pub config: DeploymentConfig,
    pub api: OpenBaoClient,
    pub server_settings_path: PathBuf,
    pub server_override: bool,
    pub runtime: Arc<Mutex<RuntimeState>>,
}

impl AppState {
    pub fn new(
        config: DeploymentConfig,
        server_settings_path: PathBuf,
        server_override: bool,
    ) -> crate::error::AppResult<Self> {
        let api = OpenBaoClient::new(&config)?;
        Ok(Self {
            config,
            api,
            server_settings_path,
            server_override,
            runtime: Arc::new(Mutex::new(RuntimeState {
                session: None,
                login_cancel: None,
                pending_root: None,
            })),
        })
    }
}
