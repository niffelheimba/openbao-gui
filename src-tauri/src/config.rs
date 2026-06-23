use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::{AppError, AppResult};

pub const EMBEDDED_DEPLOYMENT: &str = include_str!("../resources/deployment.json");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub schema_version: u32,
    pub configured: bool,
    pub deployment_name: String,
    pub openbao: OpenBaoConfig,
    pub identity: IdentityConfig,
    pub roots: Vec<RootConfig>,
    pub profiles: Vec<CertificateProfile>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBaoConfig {
    pub address: Url,
    pub namespace: Option<String>,
    pub auth_mount: String,
    pub oidc_role: String,
    pub minimum_version: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub display_claim: String,
    pub subject_claim: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    pub id: String,
    pub pem: String,
    pub sha256: String,
    pub refresh_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateProfile {
    pub id: String,
    pub label: String,
    pub description: String,
    pub purpose: CertificatePurpose,
    pub pki_mount: String,
    pub pki_role: String,
    pub subject_claim: String,
    pub san_claim: Option<String>,
    pub destination_store: String,
    pub key_algorithm: String,
    pub expected_eku_oids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CertificatePurpose {
    Mtls,
    DocumentSigning,
    CodeSigning,
}

impl DeploymentConfig {
    pub fn load_embedded() -> AppResult<Self> {
        let config: Self = serde_json::from_str(EMBEDDED_DEPLOYMENT).map_err(|error| {
            AppError::Configuration(format!("deployment.json is invalid: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.schema_version != 1 {
            return Err(AppError::Configuration("schema_version must be 1".into()));
        }
        if self.deployment_name.trim().is_empty() {
            return Err(AppError::Configuration(
                "deployment_name is required".into(),
            ));
        }
        if self.openbao.address.scheme() != "https" {
            return Err(AppError::Configuration(
                "OpenBao address must use HTTPS".into(),
            ));
        }
        if !self.openbao.address.username().is_empty() || self.openbao.address.password().is_some()
        {
            return Err(AppError::Configuration(
                "OpenBao address must not contain credentials".into(),
            ));
        }
        validate_segment("auth_mount", &self.openbao.auth_mount)?;
        validate_segment("oidc_role", &self.openbao.oidc_role)?;
        validate_claim("display_claim", &self.identity.display_claim)?;
        validate_claim("subject_claim", &self.identity.subject_claim)?;

        if self.configured && self.roots.is_empty() {
            return Err(AppError::Configuration(
                "a configured deployment must embed at least one root".into(),
            ));
        }

        let mut ids = std::collections::HashSet::new();
        for root in &self.roots {
            if !ids.insert(format!("root:{}", root.id)) {
                return Err(AppError::Configuration(format!(
                    "duplicate root id {}",
                    root.id
                )));
            }
            validate_id("root id", &root.id)?;
            if let Some(path) = &root.refresh_path {
                validate_api_path("root refresh_path", path)?;
            }
            let pem = pem::parse(&root.pem).map_err(|_| {
                AppError::Configuration(format!("root {} is not valid PEM", root.id))
            })?;
            if pem.tag() != "CERTIFICATE" {
                return Err(AppError::Configuration(format!(
                    "root {} must contain a CERTIFICATE PEM block",
                    root.id
                )));
            }
            let actual = hex::encode(Sha256::digest(pem.contents()));
            if !constant_time_text_eq(&actual, &root.sha256.to_ascii_lowercase()) {
                return Err(AppError::Configuration(format!(
                    "root {} fingerprint does not match its DER",
                    root.id
                )));
            }
        }

        for profile in &self.profiles {
            if !ids.insert(format!("profile:{}", profile.id)) {
                return Err(AppError::Configuration(format!(
                    "duplicate profile id {}",
                    profile.id
                )));
            }
            validate_id("profile id", &profile.id)?;
            validate_segment("pki_mount", &profile.pki_mount)?;
            validate_segment("pki_role", &profile.pki_role)?;
            validate_claim("profile subject_claim", &profile.subject_claim)?;
            if let Some(claim) = &profile.san_claim {
                validate_claim("profile san_claim", claim)?;
            }
            if profile.destination_store != "My" || profile.key_algorithm != "rsa-3072" {
                return Err(AppError::Configuration(format!(
                    "profile {} must use My and rsa-3072 in v1",
                    profile.id
                )));
            }
        }
        Ok(())
    }

    pub fn api_url(&self, relative: &str) -> AppResult<Url> {
        let mut base = self.openbao.address.clone();
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        base.join(&format!("v1/{}", relative.trim_start_matches('/')))
            .map_err(|error| AppError::Configuration(format!("invalid API URL: {error}")))
    }

    pub fn oidc_callback_url(&self) -> AppResult<Url> {
        self.api_url(&format!("auth/{}/oidc/callback", self.openbao.auth_mount))
    }
}

fn validate_segment(name: &str, value: &str) -> AppResult<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(AppError::Configuration(format!(
            "{name} must contain only letters, numbers, '-' or '_'"
        )));
    }
    Ok(())
}

fn validate_claim(name: &str, value: &str) -> AppResult<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(AppError::Configuration(format!(
            "{name} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str) -> AppResult<()> {
    validate_segment(name, value)
}

fn validate_api_path(name: &str, value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'/'))
    {
        return Err(AppError::Configuration(format!(
            "{name} is not a safe relative API path"
        )));
    }
    Ok(())
}

fn constant_time_text_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0_u8, |diff, (x, y)| diff | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_development_configuration_is_valid() {
        DeploymentConfig::load_embedded().unwrap();
    }

    #[test]
    fn rejects_http() {
        let mut config = DeploymentConfig::load_embedded().unwrap();
        config.openbao.address = Url::parse("http://bao.example.test").unwrap();
        assert!(config.validate().unwrap_err().to_string().contains("HTTPS"));
    }

    #[test]
    fn builds_direct_callback_url() {
        let config = DeploymentConfig::load_embedded().unwrap();
        assert_eq!(
            config.oidc_callback_url().unwrap().as_str(),
            "https://openbao.example.invalid:8200/v1/auth/oidc/oidc/callback"
        );
    }

    #[test]
    fn constant_time_comparison_checks_length_and_content() {
        assert!(constant_time_text_eq("abc", "abc"));
        assert!(!constant_time_text_eq("abc", "abd"));
        assert!(!constant_time_text_eq("abc", "ab"));
    }
}
