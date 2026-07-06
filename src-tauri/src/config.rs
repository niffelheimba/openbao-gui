use std::path::Path;

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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBaoConfig {
    pub address: Url,
    pub namespace: Option<String>,
    pub auth_mount: String,
    pub oidc_role: String,
    pub minimum_version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerSettings {
    pub schema_version: u32,
    pub address: Url,
    pub namespace: Option<String>,
    pub auth_mount: String,
    pub oidc_role: String,
}

impl From<&OpenBaoConfig> for ServerSettings {
    fn from(value: &OpenBaoConfig) -> Self {
        Self {
            schema_version: 1,
            address: value.address.clone(),
            namespace: value.namespace.clone(),
            auth_mount: value.auth_mount.clone(),
            oidc_role: value.oidc_role.clone(),
        }
    }
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

impl CertificatePurpose {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Mtls => "mTLS",
            Self::DocumentSigning => "document signing",
            Self::CodeSigning => "code signing",
        }
    }

    pub fn required_eku_oid(&self) -> &'static str {
        match self {
            Self::Mtls => "1.3.6.1.5.5.7.3.2",
            Self::DocumentSigning => "1.3.6.1.4.1.311.10.3.12",
            Self::CodeSigning => "1.3.6.1.5.5.7.3.3",
        }
    }
}

impl DeploymentConfig {
    pub fn load_embedded() -> AppResult<Self> {
        let config: Self = serde_json::from_str(EMBEDDED_DEPLOYMENT).map_err(|error| {
            AppError::Configuration(format!("deployment.json is invalid: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_with_server_settings(path: &Path) -> AppResult<(Self, bool)> {
        let mut config = Self::load_embedded()?;
        if !path.exists() {
            return Ok((config, false));
        }
        let text = std::fs::read_to_string(path).map_err(|_| {
            AppError::Configuration("saved OpenBao server settings could not be read".into())
        })?;
        let text = text.trim_start_matches('\u{feff}');
        let settings: ServerSettings = serde_json::from_str(text).map_err(|error| {
            AppError::Configuration(format!(
                "saved OpenBao server settings are invalid: {error}"
            ))
        })?;
        config.apply_server_settings(&settings)?;
        Ok((config, true))
    }

    pub fn apply_server_settings(&mut self, settings: &ServerSettings) -> AppResult<()> {
        if settings.schema_version != 1 {
            return Err(AppError::Configuration(
                "server settings schema_version must be 1".into(),
            ));
        }
        self.openbao.address = settings.address.clone();
        self.openbao.namespace = settings.namespace.clone();
        self.openbao.auth_mount = settings.auth_mount.clone();
        self.openbao.oidc_role = settings.oidc_role.clone();
        self.validate()
    }

    pub fn validate_server_settings(&self, settings: &ServerSettings) -> AppResult<()> {
        let mut candidate = self.clone();
        candidate.apply_server_settings(settings)
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
        if self.openbao.address.host_str().is_none()
            || self.openbao.address.query().is_some()
            || self.openbao.address.fragment().is_some()
            || !matches!(self.openbao.address.path(), "" | "/")
        {
            return Err(AppError::Configuration(
                "OpenBao address must be an HTTPS origin without a path, query, or fragment".into(),
            ));
        }
        if self.openbao.namespace.as_ref().is_some_and(|namespace| {
            namespace.is_empty()
                || namespace.len() > 256
                || namespace.chars().any(|character| character.is_control())
        }) {
            return Err(AppError::Configuration(
                "OpenBao namespace is empty, too long, or contains control characters".into(),
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
            let required_eku = profile.purpose.required_eku_oid();
            if !profile
                .expected_eku_oids
                .iter()
                .any(|oid| oid == required_eku)
            {
                return Err(AppError::Configuration(format!(
                    "profile {} is missing required EKU {}",
                    profile.id, required_eku
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
        let expected = format!(
            "{}v1/auth/{}/oidc/callback",
            config.openbao.address.as_str(),
            config.openbao.auth_mount
        );
        assert_eq!(config.oidc_callback_url().unwrap().as_str(), expected);
    }

    #[test]
    fn constant_time_comparison_checks_length_and_content() {
        assert!(constant_time_text_eq("abc", "abc"));
        assert!(!constant_time_text_eq("abc", "abd"));
        assert!(!constant_time_text_eq("abc", "ab"));
    }

    #[test]
    fn loads_valid_per_user_server_override() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.json");
        std::fs::write(
            &path,
            r#"{"schemaVersion":1,"address":"https://bao.override.test:8200","namespace":"homelab","authMount":"kanidm","oidcRole":"desktop"}"#,
        )
        .unwrap();
        let (config, overridden) = DeploymentConfig::load_with_server_settings(&path).unwrap();
        assert!(overridden);
        assert_eq!(
            config.openbao.address.as_str(),
            "https://bao.override.test:8200/"
        );
        assert_eq!(config.openbao.namespace.as_deref(), Some("homelab"));
        assert_eq!(config.openbao.auth_mount, "kanidm");
    }

    #[test]
    fn loads_bom_prefixed_per_user_server_override() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.json");
        std::fs::write(
            &path,
            "\u{feff}{\"schemaVersion\":1,\"address\":\"https://bao.override.test:8200\",\"namespace\":null,\"authMount\":\"oidc\",\"oidcRole\":\"northlake-users\"}",
        )
        .unwrap();
        let (config, overridden) = DeploymentConfig::load_with_server_settings(&path).unwrap();
        assert!(overridden);
        assert_eq!(
            config.openbao.address.as_str(),
            "https://bao.override.test:8200/"
        );
        assert_eq!(config.openbao.oidc_role, "northlake-users");
    }

    #[test]
    fn rejects_unsafe_per_user_server_override() {
        let config = DeploymentConfig::load_embedded().unwrap();
        let settings = ServerSettings {
            schema_version: 1,
            address: Url::parse("http://bao.override.test").unwrap(),
            namespace: None,
            auth_mount: "oidc".into(),
            oidc_role: "desktop".into(),
        };
        assert!(config.validate_server_settings(&settings).is_err());
    }

    #[test]
    fn certificate_purposes_define_required_ekus() {
        assert_eq!(
            CertificatePurpose::DocumentSigning.required_eku_oid(),
            "1.3.6.1.4.1.311.10.3.12"
        );
        assert_eq!(
            CertificatePurpose::DocumentSigning.label(),
            "document signing"
        );
    }
}
