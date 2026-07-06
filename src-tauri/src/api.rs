use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::{DeploymentConfig, OpenBaoConfig};
use crate::error::{AppError, AppResult};
use crate::state::Session;

#[derive(Clone)]
pub struct OpenBaoClient {
    http: reqwest::Client,
    config: OpenBaoConfig,
}

#[derive(Debug)]
pub struct OidcChallenge {
    pub auth_url: String,
    pub state: String,
    pub client_nonce: SecretString,
    pub poll_interval_seconds: u64,
}

#[derive(Debug)]
pub enum PollResult {
    Pending,
    SlowDown,
    Complete(Session),
}

#[derive(Debug, Deserialize)]
struct AuthUrlData {
    auth_url: String,
    state: String,
    poll_interval: String,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    data: Option<T>,
    auth: Option<AuthData>,
    #[serde(rename = "errors")]
    _errors: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct AuthData {
    client_token: SecretString,
    lease_duration: u64,
    renewable: bool,
    display_name: Option<String>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct HealthData {
    version: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerHealth {
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PkiSignRequest<'a> {
    pub csr: &'a str,
    pub common_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_names: Option<&'a str>,
    pub format: &'static str,
    pub exclude_cn_from_sans: bool,
}

#[derive(Debug, Deserialize)]
pub struct PkiSignData {
    pub certificate: String,
    #[serde(default)]
    pub issuing_ca: String,
    #[serde(default)]
    pub ca_chain: Vec<String>,
}

impl OpenBaoClient {
    pub fn new(config: &DeploymentConfig) -> AppResult<Self> {
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!(
                "openbao-certificate-client/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;
        Ok(Self {
            http,
            config: config.openbao.clone(),
        })
    }

    fn url(&self, relative: &str) -> AppResult<url::Url> {
        let mut base = self.config.address.clone();
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        base.join(&format!("v1/{}", relative.trim_start_matches('/')))
            .map_err(|error| AppError::Configuration(format!("invalid API URL: {error}")))
    }

    fn headers(&self, token: Option<&SecretString>) -> AppResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        if let Some(namespace) = &self.config.namespace {
            headers.insert(
                "X-Vault-Namespace",
                HeaderValue::from_str(namespace).map_err(|_| {
                    AppError::Configuration("namespace is not a valid header value".into())
                })?,
            );
        }
        if let Some(token) = token {
            headers.insert(
                "X-Vault-Token",
                HeaderValue::from_str(token.expose_secret()).map_err(|_| AppError::Internal)?,
            );
        }
        Ok(headers)
    }

    pub async fn begin_oidc(
        &self,
        redirect_uri: &str,
        client_nonce: SecretString,
    ) -> AppResult<OidcChallenge> {
        let endpoint = format!("auth/{}/oidc/auth_url", self.config.auth_mount);
        let url = self.url(&endpoint)?;
        let response = self
            .http
            .post(url)
            .headers(self.headers(None)?)
            .json(&json!({
                "role": self.config.oidc_role,
                "redirect_uri": redirect_uri,
                "client_nonce": client_nonce.expose_secret(),
            }))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::Api(format!(
                "OIDC auth endpoint was not found at /v1/{endpoint}; verify the client's Auth mount setting matches the OpenBao auth method path"
            )));
        }
        let envelope: Envelope<AuthUrlData> = decode(response).await?;
        let data = envelope.data.ok_or_else(|| {
            AppError::Api(
                "authorization URL was not returned; verify the OpenBao OIDC role and redirect URI"
                    .into(),
            )
        })?;
        if data.auth_url.is_empty() || data.state.is_empty() {
            return Err(AppError::Api(
                "OpenBao returned an incomplete OIDC challenge".into(),
            ));
        }
        let auth_url = url::Url::parse(&data.auth_url).map_err(|_| {
            AppError::Api("OpenBao returned an invalid OIDC authorization URL".into())
        })?;
        if auth_url.scheme() != "https"
            || !auth_url.username().is_empty()
            || auth_url.password().is_some()
        {
            return Err(AppError::Api(
                "OpenBao returned an unsafe OIDC authorization URL".into(),
            ));
        }
        let poll_interval_seconds = parse_poll_interval(&data.poll_interval)?;
        Ok(OidcChallenge {
            auth_url: auth_url.to_string(),
            state: data.state,
            client_nonce,
            poll_interval_seconds,
        })
    }

    pub async fn server_health(&self) -> AppResult<ServerHealth> {
        let response = self
            .http
            .get(self.url("sys/health")?)
            .headers(self.headers(None)?)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let health: HealthData = match serde_json::from_str(&body) {
            Ok(health) => health,
            Err(error) => {
                tracing::warn!(
                    %status,
                    error = %crate::redaction::redact(&error.to_string()),
                    "OpenBao health response was not parseable JSON; treating version as unknown"
                );
                HealthData { version: None }
            }
        };
        Ok(ServerHealth {
            version: health.version,
        })
    }

    pub async fn require_minimum_version(&self, minimum: &str) -> AppResult<()> {
        let health = self.server_health().await?;
        let Some(version) = health.version else {
            tracing::warn!(
                "OpenBao health response did not include a version; skipping minimum-version gate"
            );
            return Ok(());
        };
        let actual = semver::Version::parse(version.trim_start_matches('v'))
            .map_err(|_| AppError::Api("OpenBao reported an invalid server version".into()))?;
        let required = semver::Version::parse(minimum.trim_start_matches('v')).map_err(|_| {
            AppError::Configuration("minimum_version is not valid semantic versioning".into())
        })?;
        if actual < required {
            return Err(AppError::Api(format!(
                "OpenBao {required} or newer is required; server reported {actual}"
            )));
        }
        Ok(())
    }

    pub async fn poll_oidc(
        &self,
        challenge: &OidcChallenge,
        identity_claim: &str,
    ) -> AppResult<PollResult> {
        let url = self.url(&format!("auth/{}/oidc/poll", self.config.auth_mount))?;
        let response = self
            .http
            .post(url)
            .headers(self.headers(None)?)
            .json(&json!({
                "state": challenge.state,
                "client_nonce": challenge.client_nonce.expose_secret(),
            }))
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let errors = parse_errors(&body);
            if errors.iter().any(|e| e.ends_with("authorization_pending")) {
                return Ok(PollResult::Pending);
            }
            if errors.iter().any(|e| e.ends_with("slow_down")) {
                return Ok(PollResult::SlowDown);
            }
            tracing::warn!(%status, error = %crate::redaction::redact(&errors.join("; ")), "OIDC poll failed");
            return Err(AppError::Api(user_safe_error(status, &errors)));
        }
        let envelope: Envelope<Value> =
            serde_json::from_str(&response.text().await.unwrap_or_default()).map_err(|_| {
                AppError::Api("OpenBao returned an invalid authentication response".into())
            })?;
        let auth = envelope.auth.ok_or_else(|| {
            AppError::Api("OpenBao did not return an authentication token".into())
        })?;
        let identity = auth
            .metadata
            .get(identity_claim)
            .cloned()
            .or(auth.display_name)
            .unwrap_or_else(|| "OpenBao user".into());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(PollResult::Complete(Session {
            token: auth.client_token,
            identity,
            metadata: auth.metadata,
            expires_at: now.saturating_add(auth.lease_duration),
            renewable: auth.renewable,
        }))
    }

    pub async fn revoke(&self, token: &SecretString) -> AppResult<()> {
        let response = self
            .http
            .post(self.url("auth/token/revoke-self")?)
            .headers(self.headers(Some(token))?)
            .json(&json!({}))
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(AppError::Api("token revocation failed".into()))
        }
    }

    pub async fn renew(&self, token: &SecretString) -> AppResult<(u64, bool)> {
        let response = self
            .http
            .post(self.url("auth/token/renew-self")?)
            .headers(self.headers(Some(token))?)
            .json(&json!({}))
            .send()
            .await?;
        let envelope: Envelope<Value> = decode(response).await?;
        let auth = envelope
            .auth
            .ok_or_else(|| AppError::Api("OpenBao returned no renewed session".into()))?;
        Ok((auth.lease_duration, auth.renewable))
    }

    pub async fn read_pem(&self, token: &SecretString, path: &str) -> AppResult<String> {
        let response = self
            .http
            .get(self.url(path)?)
            .headers(self.headers(Some(token))?)
            .send()
            .await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            let errors = parse_errors(&body);
            return Err(AppError::Api(user_safe_error(status, &errors)));
        }
        if !body.contains("BEGIN CERTIFICATE") || body.len() > 256 * 1024 {
            return Err(AppError::Api(
                "OpenBao returned an invalid CA certificate".into(),
            ));
        }
        Ok(body)
    }

    pub async fn sign_csr(
        &self,
        token: &SecretString,
        mount: &str,
        role: &str,
        request: &PkiSignRequest<'_>,
    ) -> AppResult<PkiSignData> {
        let response = self
            .http
            .post(self.url(&format!("{mount}/sign/{role}"))?)
            .headers(self.headers(Some(token))?)
            .json(request)
            .send()
            .await?;
        let envelope: Envelope<PkiSignData> = decode(response).await?;
        envelope
            .data
            .ok_or_else(|| AppError::Api("OpenBao returned no signed certificate".into()))
    }
}

async fn decode<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> AppResult<Envelope<T>> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let errors = parse_errors(&body);
        tracing::warn!(%status, error = %crate::redaction::redact(&errors.join("; ")), "OpenBao API error");
        return Err(AppError::Api(user_safe_error(status, &errors)));
    }
    serde_json::from_str(&body)
        .map_err(|_| AppError::Api("OpenBao returned an invalid JSON response".into()))
}

fn parse_errors(body: &str) -> Vec<String> {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value.get("errors").and_then(Value::as_array).cloned())
        .map(|items| {
            items
                .into_iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn user_safe_error(status: reqwest::StatusCode, errors: &[String]) -> String {
    if status == reqwest::StatusCode::FORBIDDEN {
        return "access was denied by OpenBao policy".into();
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return "the OpenBao session is no longer valid".into();
    }
    if status.is_server_error() {
        return "OpenBao is temporarily unavailable".into();
    }
    let message = errors
        .first()
        .map(|s| crate::redaction::redact(s))
        .unwrap_or_else(|| format!("HTTP {status}"));
    if message.len() > 240 {
        "OpenBao rejected the request".into()
    } else {
        message
    }
}

fn parse_poll_interval(value: &str) -> AppResult<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|interval| *interval > 0)
        .ok_or_else(|| AppError::Api("OpenBao returned an invalid OIDC poll interval".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openbao_errors() {
        assert_eq!(
            parse_errors(r#"{"errors":["authorization_pending"]}"#),
            vec!["authorization_pending"]
        );
    }

    #[test]
    fn rejects_zero_poll_interval() {
        assert_eq!(parse_poll_interval("60").unwrap(), 60);
        assert!(parse_poll_interval("0").is_err());
        assert!(parse_poll_interval("soon").is_err());
    }

    #[test]
    fn hides_forbidden_details() {
        assert_eq!(
            user_safe_error(
                reqwest::StatusCode::FORBIDDEN,
                &["sensitive policy path".into()]
            ),
            "access was denied by OpenBao policy"
        );
    }

    #[test]
    fn pki_sign_request_can_exclude_human_cn_from_sans() {
        let request = PkiSignRequest {
            csr: "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----",
            common_name: "nicholas",
            alt_names: None,
            format: "pem",
            exclude_cn_from_sans: true,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["exclude_cn_from_sans"], true);
        assert!(json.get("alt_names").is_none());
    }
}
