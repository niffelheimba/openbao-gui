use std::process::Command;

use serde::{Deserialize, Serialize};
use sha1::Digest;
use sha2::Sha256;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::config::{CertificateProfile, CertificatePurpose, RootConfig};
use crate::error::{AppError, AppResult};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootInfo {
    pub id: String,
    pub subject: String,
    pub issuer: String,
    pub fingerprint: String,
    pub not_before: String,
    pub not_after: String,
    pub installed: bool,
    pub machine_installed: bool,
    pub conflicting_subject: bool,
    pub refreshable: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCertificate {
    pub thumbprint: String,
    pub subject: String,
    pub not_after: String,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PersonalCertificate {
    pub thumbprint: String,
    pub serial_number: String,
    pub subject: String,
    pub issuer: String,
    pub simple_name: String,
    #[serde(default)]
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub email_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub has_private_key: bool,
    pub eku_oids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCertificateStatus {
    pub profile_id: String,
    pub certificates: Vec<PersonalCertificate>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YubiKeySlotCertificate {
    pub slot: String,
    pub label: String,
    pub has_private_key: bool,
    pub key_algorithm: Option<String>,
    pub pin_policy: Option<String>,
    pub touch_policy: Option<String>,
    pub certificate: Option<PersonalCertificate>,
}

pub struct YubiKeyRequest {
    pub slot: String,
    pub pin: String,
    pub management_key: Option<String>,
    pub algorithm: String,
    pub pin_policy: String,
    pub touch_policy: String,
}

const DEFAULT_YUBIKEY_MANAGEMENT_KEY: &str = "010203040506070801020304050607080102030405060708";

pub struct PendingRequest {
    pub csr_pem: String,
    pub key_container: String,
    directory: tempfile::TempDir,
    accepted: bool,
}

pub struct AcceptancePolicy<'a> {
    pub trusted_root_fingerprints: &'a [String],
    pub expected_identity: &'a str,
    pub expected_san: Option<&'a str>,
    pub expected_purpose: &'a CertificatePurpose,
    pub expected_eku_oids: &'a [String],
}

impl PendingRequest {
    pub fn generate(profile: &CertificateProfile, common_name: &str) -> AppResult<Self> {
        validate_identity(common_name)?;
        let directory = tempfile::tempdir().map_err(|_| {
            AppError::Certificate("could not create a protected temporary directory".into())
        })?;
        let key_container = format!("OpenBao-{}-{}", profile.id, uuid::Uuid::new_v4());
        let inf_path = directory.path().join("request.inf");
        let csr_path = directory.path().join("request.req");
        let key_usage = match profile.purpose {
            CertificatePurpose::Mtls => "0xa0",
            CertificatePurpose::DocumentSigning => "0xc0",
            CertificatePurpose::CodeSigning => "0x80",
        };
        let escaped_cn = common_name.replace('"', "\"\"");
        let inf = format!(
            r#"[Version]
Signature="$Windows NT$"

[NewRequest]
Subject="CN={escaped_cn}"
Exportable=FALSE
KeyLength=3072
KeyAlgorithm=RSA
HashAlgorithm=sha256
KeySpec=0
ProviderName="Microsoft Software Key Storage Provider"
ProviderType=0
MachineKeySet=FALSE
RequestType=PKCS10
KeyContainer="{key_container}"
KeyUsage={key_usage}
Silent=TRUE
"#
        );
        std::fs::write(&inf_path, inf)
            .map_err(|_| AppError::Certificate("could not write CSR instructions".into()))?;
        let output = run_windows(
            "certreq.exe",
            &[
                "-new",
                "-q",
                "-user",
                path_text(&inf_path)?,
                path_text(&csr_path)?,
            ],
        )?;
        if !output.status.success() {
            let _ = delete_key_container(&key_container);
            return Err(AppError::Certificate(command_error(
                "Windows could not generate the certificate request",
                &output,
            )));
        }
        let csr_pem = std::fs::read_to_string(&csr_path).map_err(|_| {
            AppError::Certificate("Windows did not produce a certificate request".into())
        })?;
        if !csr_pem.contains("BEGIN NEW CERTIFICATE REQUEST")
            && !csr_pem.contains("BEGIN CERTIFICATE REQUEST")
        {
            let _ = delete_key_container(&key_container);
            return Err(AppError::Certificate(
                "Windows produced an unexpected CSR format".into(),
            ));
        }
        Ok(Self {
            csr_pem,
            key_container,
            directory,
            accepted: false,
        })
    }

    pub fn accept(
        mut self,
        certificate_pem: &str,
        chain_pems: &[String],
        policy: AcceptancePolicy<'_>,
    ) -> AppResult<IssuedCertificate> {
        let validation =
            validate_issued_certificate(&self.csr_pem, certificate_pem, chain_pems, &policy);
        let (metadata, intermediates) = match validation {
            Ok(value) => value,
            Err(error) => {
                let _ = delete_key_container(&self.key_container);
                return Err(error);
            }
        };
        for (index, intermediate) in intermediates.iter().enumerate() {
            let path = self
                .directory
                .path()
                .join(format!("intermediate-{index}.cer"));
            std::fs::write(&path, intermediate).map_err(|_| {
                AppError::Certificate("could not stage the issuing certificate chain".into())
            })?;
            let output = run_windows(
                "certutil.exe",
                &["-user", "-addstore", "-f", "CA", path_text(&path)?],
            )?;
            if !output.status.success() {
                return Err(AppError::Certificate(command_error(
                    "Windows rejected an issuing CA certificate",
                    &output,
                )));
            }
        }
        let cert_path = self.directory.path().join("certificate.cer");
        std::fs::write(&cert_path, certificate_pem)
            .map_err(|_| AppError::Certificate("could not stage the signed certificate".into()))?;
        let output = run_windows(
            "certreq.exe",
            &["-accept", "-q", "-user", path_text(&cert_path)?],
        )?;
        if !output.status.success() {
            let _ = delete_key_container(&self.key_container);
            return Err(AppError::Certificate(command_error(
                "Windows rejected the signed certificate",
                &output,
            )));
        }
        self.accepted = true;
        Ok(metadata)
    }
}

pub fn generate_yubikey_csr(
    _profile: &CertificateProfile,
    common_name: &str,
    request: &YubiKeyRequest,
    replace_existing: bool,
) -> AppResult<(String, tempfile::TempDir, bool)> {
    validate_identity(common_name)?;
    validate_yubikey_request(request)?;
    let directory = tempfile::tempdir().map_err(|_| {
        AppError::Certificate("could not create a protected temporary directory".into())
    })?;
    let slot_has_key = yubikey_slot_has_key(&request.slot)?;
    let slot_has_certificate = yubikey_slot_has_certificate(&request.slot, directory.path())?;
    if slot_has_key && !replace_existing {
        return Err(AppError::Certificate(format!(
            "YubiKey PIV slot {} already contains a private key; choose another slot or clear it with YubiKey Manager before requesting a new certificate",
            request.slot
        )));
    }
    if slot_has_certificate && !replace_existing {
        return Err(AppError::Certificate(format!(
            "YubiKey PIV slot {} already contains a certificate; choose another slot or clear it with YubiKey Manager before requesting a new certificate",
            request.slot
        )));
    }
    let public_key_path = directory.path().join("yubikey-public.pem");
    let csr_path = directory.path().join("yubikey-request.pem");
    let subject = format!("CN={}", common_name.replace(',', "\\,").replace('+', "\\+"));

    let generated_new_key = !slot_has_key;
    if slot_has_key {
        let output = run_ykman(&[
            "piv",
            "keys",
            "export",
            "--verify",
            "--pin",
            &request.pin,
            &request.slot,
            path_text(&public_key_path)?,
        ])?;
        if !output.status.success() {
            return Err(AppError::Certificate(command_error(
                "YubiKey Manager could not export the existing PIV public key",
                &output,
            )));
        }
    } else {
        let mut generate_args = vec![
            "piv",
            "keys",
            "generate",
            "--algorithm",
            &request.algorithm,
            "--pin-policy",
            &request.pin_policy,
            "--touch-policy",
            &request.touch_policy,
        ];
        generate_args.push("--management-key");
        generate_args.push(yubikey_management_key(request));
        if !request.pin.is_empty() {
            generate_args.push("--pin");
            generate_args.push(&request.pin);
        }
        generate_args.push(&request.slot);
        generate_args.push(path_text(&public_key_path)?);
        let output = run_ykman(&generate_args)?;
        if !output.status.success() {
            return Err(AppError::Certificate(command_error(
                "YubiKey Manager could not generate a PIV key",
                &output,
            )));
        }
    }

    let output = match run_ykman(&[
        "piv",
        "certificates",
        "request",
        "--pin",
        &request.pin,
        "--subject",
        &subject,
        &request.slot,
        path_text(&public_key_path)?,
        path_text(&csr_path)?,
    ]) {
        Ok(output) => output,
        Err(error) => {
            if generated_new_key {
                let _ = delete_yubikey_key(request);
            }
            return Err(error);
        }
    };
    if !output.status.success() {
        if generated_new_key {
            let _ = delete_yubikey_key(request);
        }
        return Err(AppError::Certificate(command_error(
            "YubiKey Manager could not generate a CSR",
            &output,
        )));
    }
    let csr_pem = std::fs::read_to_string(&csr_path).map_err(|_| {
        if generated_new_key {
            let _ = delete_yubikey_key(request);
        }
        AppError::Certificate("YubiKey Manager did not produce a certificate request".into())
    })?;
    if !csr_pem.contains("BEGIN CERTIFICATE REQUEST") {
        if generated_new_key {
            let _ = delete_yubikey_key(request);
        }
        return Err(AppError::Certificate(
            "YubiKey Manager produced an unexpected CSR format".into(),
        ));
    }
    Ok((csr_pem, directory, generated_new_key))
}

pub fn import_yubikey_certificate(
    request: &YubiKeyRequest,
    directory: tempfile::TempDir,
    csr_pem: &str,
    certificate_pem: &str,
    chain_pems: &[String],
    policy: AcceptancePolicy<'_>,
    delete_key_on_failure: bool,
) -> AppResult<IssuedCertificate> {
    let metadata = validate_issued_certificate(csr_pem, certificate_pem, chain_pems, &policy)
        .map(|(metadata, _)| metadata)
        .inspect_err(|_| {
            if delete_key_on_failure {
                let _ = delete_yubikey_key(request);
            }
        })?;
    let cert_path = directory.path().join("yubikey-certificate.pem");
    std::fs::write(&cert_path, certificate_pem).map_err(|_| {
        if delete_key_on_failure {
            let _ = delete_yubikey_key(request);
        }
        AppError::Certificate("could not stage the signed YubiKey certificate".into())
    })?;
    let mut args = vec![
        "piv",
        "certificates",
        "import",
        "--verify",
        "--pin",
        &request.pin,
    ];
    args.push("--management-key");
    args.push(yubikey_management_key(request));
    args.push(&request.slot);
    args.push(path_text(&cert_path)?);
    let output = run_ykman(&args)?;
    if !output.status.success() {
        if delete_key_on_failure {
            let _ = delete_yubikey_key(request);
        }
        return Err(AppError::Certificate(command_error(
            "YubiKey Manager could not import the signed certificate",
            &output,
        )));
    }
    Ok(metadata)
}

pub fn delete_yubikey_certificate(request: &YubiKeyRequest) -> AppResult<()> {
    validate_yubikey_request(request)?;
    let mut args = vec!["piv", "certificates", "delete", "--pin", &request.pin];
    args.push("--management-key");
    args.push(yubikey_management_key(request));
    args.push(&request.slot);
    let output = run_ykman(&args)?;
    if !output.status.success() {
        return Err(AppError::Certificate(command_error(
            "YubiKey Manager could not remove the certificate",
            &output,
        )));
    }
    Ok(())
}

fn validate_yubikey_request(request: &YubiKeyRequest) -> AppResult<()> {
    const SLOTS: &[&str] = &["9a", "9c", "9d", "9e"];
    const ALGORITHMS: &[&str] = &["rsa2048", "rsa3072", "rsa4096", "eccp256", "eccp384"];
    const PIN_POLICIES: &[&str] = &["default", "never", "once", "always"];
    const TOUCH_POLICIES: &[&str] = &["default", "never", "always", "cached"];
    if !SLOTS.contains(&request.slot.as_str()) {
        return Err(AppError::Certificate(
            "unsupported YubiKey PIV slot; choose 9a, 9c, 9d, or 9e".into(),
        ));
    }
    if !ALGORITHMS.contains(&request.algorithm.as_str()) {
        return Err(AppError::Certificate(
            "unsupported YubiKey key algorithm".into(),
        ));
    }
    if !PIN_POLICIES.contains(&request.pin_policy.as_str()) {
        return Err(AppError::Certificate(
            "unsupported YubiKey PIN policy".into(),
        ));
    }
    if !TOUCH_POLICIES.contains(&request.touch_policy.as_str()) {
        return Err(AppError::Certificate(
            "unsupported YubiKey touch policy".into(),
        ));
    }
    if request.pin.trim().is_empty() {
        return Err(AppError::Certificate(
            "YubiKey PIV PIN is required for this operation".into(),
        ));
    }
    Ok(())
}

fn yubikey_slot_has_certificate(slot: &str, directory: &std::path::Path) -> AppResult<bool> {
    let path = directory.join("existing-yubikey-certificate.pem");
    let output = run_ykman(&["piv", "certificates", "export", slot, path_text(&path)?])?;
    Ok(output.status.success() && path.exists())
}

fn yubikey_slot_has_key(slot: &str) -> AppResult<bool> {
    let output = run_ykman(&["piv", "keys", "info", slot])?;
    Ok(yubikey_key_info_from_output(&output)?.is_some())
}

fn yubikey_key_info_from_output(
    output: &std::process::Output,
) -> AppResult<Option<YubiKeyKeyInfo>> {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        return Ok(Some(parse_yubikey_key_info(&text)));
    }
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("no key")
        || lowered.contains("not found")
        || lowered.contains("object not found")
        || lowered.contains("not present")
        || lowered.contains("empty")
    {
        Ok(None)
    } else {
        Err(AppError::Certificate(command_error(
            "YubiKey Manager could not inspect the PIV slot",
            output,
        )))
    }
}

fn delete_yubikey_key(request: &YubiKeyRequest) -> AppResult<()> {
    let mut args = vec!["piv", "keys", "delete", "--pin", &request.pin];
    args.push("--management-key");
    args.push(yubikey_management_key(request));
    args.push(&request.slot);
    let _ = run_ykman(&args)?;
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct YubiKeyKeyInfo {
    algorithm: Option<String>,
    pin_policy: Option<String>,
    touch_policy: Option<String>,
}

fn parse_yubikey_key_info(text: &str) -> YubiKeyKeyInfo {
    let mut info = YubiKeyKeyInfo::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.as_str() {
            "algorithm" => info.algorithm = Some(value.to_owned()),
            "pin policy" => info.pin_policy = Some(value.to_owned()),
            "touch policy" => info.touch_policy = Some(value.to_owned()),
            _ => {}
        }
    }
    info
}

fn yubikey_management_key(request: &YubiKeyRequest) -> &str {
    request
        .management_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_YUBIKEY_MANAGEMENT_KEY)
}

pub fn list_yubikey_certificates() -> AppResult<Vec<YubiKeySlotCertificate>> {
    const SLOTS: &[(&str, &str)] = &[
        ("9a", "Authentication"),
        ("9c", "Digital signature"),
        ("9d", "Key management"),
        ("9e", "Card authentication"),
    ];
    let directory = tempfile::tempdir().map_err(|_| {
        AppError::Certificate("could not create a protected temporary directory".into())
    })?;
    let mut results = Vec::with_capacity(SLOTS.len());
    for (slot, label) in SLOTS {
        let key_info = yubikey_key_info_from_output(&run_ykman(&["piv", "keys", "info", slot])?)?;
        let has_private_key = key_info.is_some();
        let cert_path = directory.path().join(format!("yubikey-slot-{slot}.pem"));
        let output = run_ykman(&[
            "piv",
            "certificates",
            "export",
            slot,
            path_text(&cert_path)?,
        ])?;
        let certificate = if output.status.success() && cert_path.exists() {
            let pem = std::fs::read_to_string(&cert_path).map_err(|_| {
                AppError::Certificate("YubiKey certificate could not be read".into())
            })?;
            Some(personal_certificate_from_pem(&pem, has_private_key)?)
        } else {
            None
        };
        results.push(YubiKeySlotCertificate {
            slot: (*slot).to_owned(),
            label: (*label).to_owned(),
            has_private_key,
            key_algorithm: key_info.as_ref().and_then(|info| info.algorithm.clone()),
            pin_policy: key_info.as_ref().and_then(|info| info.pin_policy.clone()),
            touch_policy: key_info.and_then(|info| info.touch_policy),
            certificate,
        });
    }
    Ok(results)
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if !self.accepted {
            let _ = delete_key_container(&self.key_container);
        }
    }
}

pub fn inspect_root(root: &RootConfig) -> AppResult<RootInfo> {
    let parsed_pem = ::pem::parse(&root.pem)
        .map_err(|_| AppError::Certificate("embedded root is invalid PEM".into()))?;
    let (_, cert) = X509Certificate::from_der(parsed_pem.contents())
        .map_err(|_| AppError::Certificate("embedded root is invalid X.509".into()))?;
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|ext| ext.value.ca)
        .unwrap_or(false);
    if cert.subject() != cert.issuer() || !is_ca {
        return Err(AppError::Certificate(format!(
            "embedded certificate {} is not a self-signed CA",
            root.id
        )));
    }
    let fingerprint = hex::encode(Sha256::digest(parsed_pem.contents()));
    let thumbprint = hex::encode(sha1::Sha1::digest(parsed_pem.contents())).to_ascii_uppercase();
    let installed = root_is_user_installed(&thumbprint).unwrap_or(false);
    let machine_installed = root_is_machine_installed(&thumbprint).unwrap_or(false);
    let conflicting_subject =
        subject_has_other_certificate(&cert.subject().to_string(), &fingerprint).unwrap_or(false);
    Ok(RootInfo {
        id: root.id.clone(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        fingerprint,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        installed,
        machine_installed,
        conflicting_subject,
        refreshable: root.refresh_path.is_some(),
    })
}

pub fn install_root(root: &RootConfig) -> AppResult<()> {
    install_root_with_policy(root, false)
}

pub fn install_refreshed_root(root: &RootConfig) -> AppResult<()> {
    install_root_with_policy(root, true)
}

fn install_root_with_policy(root: &RootConfig, allow_same_subject: bool) -> AppResult<()> {
    let info = inspect_root(root)?;
    if info.installed {
        return Ok(());
    }
    if info.conflicting_subject && !allow_same_subject {
        return Err(AppError::Certificate("a different root with the same subject is already installed; resolve the conflict manually".into()));
    }
    let directory = tempfile::tempdir().map_err(|_| {
        AppError::Certificate("could not create a protected temporary directory".into())
    })?;
    let path = directory.path().join("root.cer");
    std::fs::write(&path, &root.pem)
        .map_err(|_| AppError::Certificate("could not stage the root certificate".into()))?;
    let output = run_windows(
        "certutil.exe",
        &["-user", "-addstore", "-f", "Root", path_text(&path)?],
    )?;
    if !output.status.success() {
        return Err(AppError::Certificate(command_error(
            "Windows did not install the root certificate",
            &output,
        )));
    }
    if !root_is_user_installed_by_root(root)? {
        return Err(AppError::Certificate(
            "root installation could not be verified".into(),
        ));
    }
    Ok(())
}

pub fn remove_root(root: &RootConfig) -> AppResult<()> {
    let info = inspect_root(root)?;
    if !info.installed {
        return Ok(());
    }
    let output = remove_root_by_sha1(&root_sha1_thumbprint(root)?)?;
    if !output.status.success() || root_is_user_installed_by_root(root)? {
        return Err(AppError::Certificate(command_error(
            "Windows did not remove the root certificate",
            &output,
        )));
    }
    Ok(())
}

fn root_is_user_installed_by_root(root: &RootConfig) -> AppResult<bool> {
    let thumbprint = root_sha1_thumbprint(root)?;
    root_is_user_installed(&thumbprint)
}

fn root_sha1_thumbprint(root: &RootConfig) -> AppResult<String> {
    let parsed_pem = ::pem::parse(&root.pem)
        .map_err(|_| AppError::Certificate("embedded root is invalid PEM".into()))?;
    Ok(hex::encode(sha1::Sha1::digest(parsed_pem.contents())).to_ascii_uppercase())
}

fn root_is_user_installed(thumbprint: &str) -> AppResult<bool> {
    #[cfg(windows)]
    {
        let output = run_windows("certutil.exe", &["-user", "-store", "Root", thumbprint])?;
        Ok(output.status.success())
    }
    #[cfg(not(windows))]
    {
        let _ = thumbprint;
        Err(AppError::Certificate(
            "this operation is only supported on Windows".into(),
        ))
    }
}

fn root_is_machine_installed(thumbprint: &str) -> AppResult<bool> {
    #[cfg(windows)]
    {
        let output = run_windows("certutil.exe", &["-store", "Root", thumbprint])?;
        Ok(output.status.success())
    }
    #[cfg(not(windows))]
    {
        let _ = thumbprint;
        Err(AppError::Certificate(
            "this operation is only supported on Windows".into(),
        ))
    }
}

fn subject_has_other_certificate(subject: &str, fingerprint: &str) -> AppResult<bool> {
    #[cfg(windows)]
    {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(subject.as_bytes());
        let expected = fingerprint.to_ascii_lowercase();
        let script = format!(
            "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')); $f='{expected}'; $sha=[Security.Cryptography.SHA256]::Create(); $conflict=@(Get-ChildItem Cert:\\CurrentUser\\Root | Where-Object {{$_.Subject -eq $s -and (($sha.ComputeHash($_.RawData) | ForEach-Object {{$_.ToString('x2')}}) -join '') -ne $f}}); if($conflict.Count -gt 0){{exit 7}}else{{exit 0}}"
        );
        let output = run_powershell(&script)?;
        Ok(output.status.code() == Some(7))
    }
    #[cfg(not(windows))]
    {
        let _ = (subject, fingerprint);
        Err(AppError::Certificate(
            "this operation is only supported on Windows".into(),
        ))
    }
}

#[cfg(windows)]
fn remove_root_by_sha1(thumbprint: &str) -> AppResult<std::process::Output> {
    run_windows("certutil.exe", &["-user", "-delstore", "Root", thumbprint])
}

#[cfg(windows)]
fn run_powershell(script: &str) -> AppResult<std::process::Output> {
    run_windows(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
    )
}

#[cfg(windows)]
fn run_ykman(args: &[&str]) -> AppResult<std::process::Output> {
    use std::os::windows::process::CommandExt;
    use std::time::{Duration, Instant};
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let executable = find_ykman();
    let ykman_data = tempfile::Builder::new()
        .prefix("openbao-ykman-")
        .tempdir()
        .map_err(|_| {
            AppError::Certificate(
                "could not create a private YubiKey Manager work directory".into(),
            )
        })?;
    let mut child = Command::new(&executable)
        .args(args)
        .env("XDG_DATA_HOME", ykman_data.path())
        .env("XDG_CACHE_HOME", ykman_data.path())
        .stdin(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| {
            AppError::Certificate(
                "YubiKey Manager CLI (ykman) could not be started; install ykman and try again"
                    .into(),
            )
        })?;
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|_| AppError::Certificate("YubiKey Manager failed unexpectedly".into()))?
            .is_some()
        {
            return child.wait_with_output().map_err(|_| {
                AppError::Certificate("YubiKey Manager output could not be read".into())
            });
        }
        if started.elapsed() > Duration::from_secs(45) {
            let _ = child.kill();
            let _ = child.wait();
            let command = redact_ykman_args(args);
            return Err(AppError::Certificate(
                format!("YubiKey Manager timed out while running 'ykman {command}'; if the YubiKey was waiting for touch, PIN, or overwrite confirmation, try again after clearing the target slot or choosing another slot"),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(windows)]
fn redact_ykman_args(args: &[&str]) -> String {
    let mut redacted = Vec::with_capacity(args.len());
    let mut hide_next = false;
    for arg in args {
        if hide_next {
            redacted.push("<redacted>");
            hide_next = false;
            continue;
        }
        redacted.push(*arg);
        if matches!(
            *arg,
            "--pin" | "-P" | "--management-key" | "-m" | "--password" | "-p"
        ) {
            hide_next = true;
        }
    }
    redacted.join(" ")
}

#[cfg(windows)]
fn find_ykman() -> std::path::PathBuf {
    let default = std::path::PathBuf::from("ykman.exe");
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        let candidate = std::path::PathBuf::from(program_files)
            .join("Yubico")
            .join("YubiKey Manager CLI")
            .join("ykman.exe");
        if candidate.exists() {
            return candidate;
        }
    }
    default
}

#[cfg(not(windows))]
fn run_ykman(_args: &[&str]) -> AppResult<std::process::Output> {
    Err(AppError::Certificate(
        "YubiKey issuance is only supported on Windows in this build".into(),
    ))
}

fn delete_key_container(container: &str) -> AppResult<()> {
    let output = run_windows(
        "certutil.exe",
        &[
            "-user",
            "-csp",
            "Microsoft Software Key Storage Provider",
            "-delkey",
            container,
        ],
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::Certificate(
            "could not remove an orphaned key container".into(),
        ))
    }
}

fn validate_issued_certificate(
    csr_pem: &str,
    certificate_pem: &str,
    chain_pems: &[String],
    policy: &AcceptancePolicy<'_>,
) -> AppResult<(IssuedCertificate, Vec<String>)> {
    let csr_der = decode_csr_pem(csr_pem)?;
    let (_, csr) = X509CertificationRequest::from_der(&csr_der)
        .map_err(|_| AppError::Certificate("generated CSR could not be parsed".into()))?;
    let cert_pem = ::pem::parse(certificate_pem)
        .map_err(|_| AppError::Certificate("OpenBao returned an invalid certificate PEM".into()))?;
    let (_, cert) = X509Certificate::from_der(cert_pem.contents()).map_err(|_| {
        AppError::Certificate("OpenBao returned an invalid X.509 certificate".into())
    })?;
    if !cert.validity().is_valid() {
        return Err(AppError::Certificate(
            "OpenBao returned a certificate that is not currently valid".into(),
        ));
    }
    if csr.certification_request_info.subject_pki.raw != cert.public_key().raw {
        return Err(AppError::Certificate(
            "the signed certificate does not match the locally generated key".into(),
        ));
    }
    let intermediates = validate_chain(&cert, chain_pems, policy.trusted_root_fingerprints)?;
    let cn_matches = cert
        .subject()
        .iter_common_name()
        .filter_map(|value| value.as_str().ok())
        .any(|value| value.eq_ignore_ascii_case(policy.expected_identity));
    if !cn_matches {
        return Err(AppError::Certificate(
            "the signed certificate identity does not match the authenticated user".into(),
        ));
    }
    if let Some(expected_san) = policy.expected_san {
        let san_matches =
            cert.extensions()
                .iter()
                .any(|extension| match extension.parsed_extension() {
                    ParsedExtension::SubjectAlternativeName(san) => {
                        san.general_names.iter().any(|name| match name {
                            GeneralName::RFC822Name(value) | GeneralName::DNSName(value) => {
                                value.eq_ignore_ascii_case(expected_san)
                            }
                            _ => false,
                        })
                    }
                    _ => false,
                });
        if !san_matches {
            return Err(AppError::Certificate(
                "the signed certificate SAN does not match the authenticated user".into(),
            ));
        }
    }
    let actual_ekus = certificate_eku_oids(&cert);
    for expected in policy.expected_eku_oids {
        if !actual_ekus.iter().any(|actual| actual == expected) {
            return Err(AppError::Certificate(format!(
                "the signed certificate is missing required EKU {expected}"
            )));
        }
    }
    validate_key_usage_for_purpose(&cert, policy.expected_purpose)?;
    Ok((
        IssuedCertificate {
            thumbprint: hex::encode(sha1::Sha1::digest(cert_pem.contents())),
            subject: cert.subject().to_string(),
            not_after: cert.validity().not_after.to_string(),
            warnings: Vec::new(),
        },
        intermediates,
    ))
}

fn validate_key_usage_for_purpose(
    cert: &X509Certificate<'_>,
    purpose: &CertificatePurpose,
) -> AppResult<()> {
    let usages = cert
        .extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::KeyUsage(usages) => Some(usages),
            _ => None,
        })
        .ok_or_else(|| {
            AppError::Certificate("the signed certificate is missing Key Usage".into())
        })?;
    let valid = match purpose {
        CertificatePurpose::Mtls | CertificatePurpose::CodeSigning => usages.digital_signature(),
        CertificatePurpose::DocumentSigning => {
            usages.digital_signature() && usages.non_repudiation()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(AppError::Certificate(format!(
            "the signed certificate has the wrong Key Usage for {}",
            purpose.label()
        )))
    }
}

pub fn list_personal_certificates() -> AppResult<Vec<PersonalCertificate>> {
    let script = r#"[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $items = @(Get-ChildItem Cert:\CurrentUser\My | ForEach-Object { [pscustomobject]@{ thumbprint=$_.Thumbprint.ToLowerInvariant(); serialNumber=$_.SerialNumber.ToLowerInvariant(); subject=$_.Subject; issuer=$_.Issuer; simpleName=$_.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false); dnsNames=@($_.DnsNameList | ForEach-Object { if ($_.Unicode) { $_.Unicode } }); emailNames=@($_.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::EmailName, $false) | Where-Object { $_ }); notBefore=$_.NotBefore.ToUniversalTime().ToString('o'); notAfter=$_.NotAfter.ToUniversalTime().ToString('o'); hasPrivateKey=$_.HasPrivateKey; ekuOids=@($_.EnhancedKeyUsageList | ForEach-Object { if ($_.ObjectId -and $_.ObjectId.Value) { $_.ObjectId.Value } }) } }); ConvertTo-Json -Compress -Depth 4 -InputObject $items"#;
    let output = run_windows(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
    )?;
    if !output.status.success() {
        return Err(AppError::Certificate(command_error(
            "Windows could not inspect the Personal certificate store",
            &output,
        )));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| {
        AppError::Certificate("Windows returned invalid certificate-store data".into())
    })?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&text).map_err(|_| {
        AppError::Certificate("Windows returned malformed certificate-store data".into())
    })
}

pub fn remove_personal_certificate(thumbprint: &str) -> AppResult<()> {
    if thumbprint.len() != 40 || !thumbprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Certificate(
            "certificate thumbprint is invalid".into(),
        ));
    }
    let normalized = thumbprint.to_ascii_uppercase();
    let output = run_windows("certutil.exe", &["-user", "-delstore", "My", &normalized])?;
    if !output.status.success() {
        return Err(AppError::Certificate(command_error(
            "Windows could not remove the certificate from CurrentUser\\My",
            &output,
        )));
    }
    Ok(())
}

pub fn certificates_for_profile(
    all: &[PersonalCertificate],
    profile: &CertificateProfile,
    identity: &str,
) -> Vec<PersonalCertificate> {
    all.iter()
        .filter(|certificate| {
            if !certificate.has_private_key || !certificate_matches_identity(certificate, identity)
            {
                return false;
            }
            if certificate.eku_oids.is_empty() {
                return true;
            }
            profile
                .expected_eku_oids
                .iter()
                .all(|expected| certificate.eku_oids.iter().any(|actual| actual == expected))
        })
        .cloned()
        .collect()
}

fn certificate_matches_identity(certificate: &PersonalCertificate, identity: &str) -> bool {
    certificate.simple_name.eq_ignore_ascii_case(identity)
        || certificate.subject.split(',').any(|part| {
            part.trim()
                .strip_prefix("CN=")
                .is_some_and(|cn| cn.eq_ignore_ascii_case(identity))
        })
        || certificate
            .dns_names
            .iter()
            .any(|value| value.eq_ignore_ascii_case(identity))
        || certificate
            .email_names
            .iter()
            .any(|value| value.eq_ignore_ascii_case(identity))
}

struct ChainEntry {
    pem: String,
    der: Vec<u8>,
    trusted_root: bool,
}

fn validate_chain(
    leaf: &X509Certificate<'_>,
    chain_pems: &[String],
    trusted_root_fingerprints: &[String],
) -> AppResult<Vec<String>> {
    let entries = chain_pems
        .iter()
        .filter_map(|value| ::pem::parse(value).ok())
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(|block| {
            let fingerprint = hex::encode(Sha256::digest(block.contents()));
            ChainEntry {
                pem: ::pem::encode(&block),
                der: block.contents().to_vec(),
                trusted_root: trusted_root_fingerprints
                    .iter()
                    .any(|trusted| trusted.eq_ignore_ascii_case(&fingerprint)),
            }
        })
        .collect::<Vec<_>>();
    let mut current_der = leaf.as_raw().to_vec();
    let mut intermediates = Vec::new();
    let mut visited = std::collections::HashSet::new();
    for _ in 0..entries.len().saturating_add(1) {
        let (_, current) = X509Certificate::from_der(&current_der)
            .map_err(|_| AppError::Certificate("certificate chain could not be parsed".into()))?;
        let mut parent_match = None;
        for (index, entry) in entries.iter().enumerate() {
            if visited.contains(&index) {
                continue;
            }
            let Ok((_, candidate)) = X509Certificate::from_der(&entry.der) else {
                continue;
            };
            if current.issuer() == candidate.subject()
                && current
                    .verify_signature(Some(candidate.public_key()))
                    .is_ok()
            {
                parent_match = Some((index, candidate.subject() == candidate.issuer()));
                break;
            }
        }
        let Some((index, self_signed)) = parent_match else {
            return Err(AppError::Certificate(
                "the signed certificate does not chain to an embedded root".into(),
            ));
        };
        visited.insert(index);
        if self_signed {
            let (_, root) = X509Certificate::from_der(&entries[index].der).map_err(|_| {
                AppError::Certificate("root certificate could not be parsed".into())
            })?;
            if !entries[index].trusted_root || root.verify_signature(None).is_err() {
                return Err(AppError::Certificate(
                    "the signed certificate chain ends at an untrusted root".into(),
                ));
            }
            return Ok(intermediates);
        }
        intermediates.push(entries[index].pem.clone());
        current_der = entries[index].der.clone();
    }
    Err(AppError::Certificate(
        "the signed certificate chain contains a loop".into(),
    ))
}

fn certificate_eku_oids(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut result = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = extension.parsed_extension() {
            if eku.client_auth {
                result.push("1.3.6.1.5.5.7.3.2".into());
            }
            if eku.code_signing {
                result.push("1.3.6.1.5.5.7.3.3".into());
            }
            if eku.email_protection {
                result.push("1.3.6.1.5.5.7.3.4".into());
            }
            result.extend(eku.other.iter().map(|oid| oid.to_id_string()));
        }
    }
    result
}

fn personal_certificate_from_pem(
    certificate_pem: &str,
    has_private_key: bool,
) -> AppResult<PersonalCertificate> {
    let block = ::pem::parse(certificate_pem)
        .map_err(|_| AppError::Certificate("YubiKey returned an invalid certificate PEM".into()))?;
    let (_, cert) = X509Certificate::from_der(block.contents()).map_err(|_| {
        AppError::Certificate("YubiKey returned an invalid X.509 certificate".into())
    })?;
    let thumbprint = hex::encode(sha1::Sha1::digest(block.contents())).to_ascii_lowercase();
    let simple_name = cert
        .subject()
        .iter_common_name()
        .find_map(|value| value.as_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut dns_names = Vec::new();
    let mut email_names = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(value) => dns_names.push((*value).to_owned()),
                    GeneralName::RFC822Name(value) => email_names.push((*value).to_owned()),
                    _ => {}
                }
            }
        }
    }
    Ok(PersonalCertificate {
        thumbprint,
        serial_number: normalize_certificate_serial(&cert.tbs_certificate.raw_serial_as_string()),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        simple_name,
        dns_names,
        email_names,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        has_private_key,
        eku_oids: certificate_eku_oids(&cert),
    })
}

pub fn normalize_certificate_serial(value: &str) -> String {
    let mut hex = value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase();
    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }
    hex.as_bytes()
        .chunks(2)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .collect::<Vec<_>>()
        .join(":")
}

fn decode_csr_pem(value: &str) -> AppResult<Vec<u8>> {
    // certreq uses "NEW CERTIFICATE REQUEST", which the generic PEM parser accepts.
    ::pem::parse(value)
        .map(|block| block.contents().to_vec())
        .map_err(|_| AppError::Certificate("Windows returned an invalid CSR PEM".into()))
}

fn validate_identity(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 253
        || value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\r' | '\n' | '\0'))
    {
        return Err(AppError::Certificate(
            "the mapped certificate identity is invalid".into(),
        ));
    }
    Ok(())
}

fn path_text(path: &std::path::Path) -> AppResult<&str> {
    path.to_str()
        .ok_or_else(|| AppError::Certificate("temporary path is not valid Unicode".into()))
}

fn command_error(prefix: &str, output: &std::process::Output) -> String {
    let detail = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let safe = crate::redaction::redact(detail.trim());
    if safe.is_empty() {
        prefix.into()
    } else {
        format!("{prefix}: {}", safe.chars().take(240).collect::<String>())
    }
}

#[cfg(windows)]
fn run_windows(program: &str, args: &[&str]) -> AppResult<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let system_root = std::env::var_os("SystemRoot")
        .ok_or_else(|| AppError::Certificate("Windows SystemRoot is unavailable".into()))?;
    let executable = match program.to_ascii_lowercase().as_str() {
        "powershell.exe" => std::path::PathBuf::from(system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        "certreq.exe" | "certutil.exe" => std::path::PathBuf::from(system_root)
            .join("System32")
            .join(program),
        _ => {
            return Err(AppError::Certificate(
                "refusing to start an unapproved Windows component".into(),
            ));
        }
    };
    Command::new(&executable)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|_| {
            AppError::Certificate(format!(
                "required Windows component {program} could not be started"
            ))
        })
}

#[cfg(not(windows))]
fn run_windows(_program: &str, _args: &[&str]) -> AppResult<std::process::Output> {
    Err(AppError::Certificate(
        "this operation is only supported on Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_control_characters_in_identity() {
        assert!(validate_identity("alice@example.test").is_ok());
        assert!(validate_identity("alice\n[Extensions]").is_err());
    }

    #[test]
    fn windows_personal_store_inventory_smoke_test() {
        let certificates = list_personal_certificates().unwrap();
        assert!(certificates.iter().all(|certificate| {
            certificate.thumbprint.len() == 40
                && certificate
                    .thumbprint
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
        }));
    }

    #[test]
    fn profile_inventory_requires_identity_key_and_all_ekus() {
        let profile = CertificateProfile {
            id: "mtls".into(),
            label: "mTLS".into(),
            description: String::new(),
            purpose: CertificatePurpose::Mtls,
            pki_mount: "pki".into(),
            pki_role: "mtls".into(),
            subject_claim: "email".into(),
            san_claim: Some("email".into()),
            destination_store: "My".into(),
            key_algorithm: "rsa-3072".into(),
            expected_eku_oids: vec!["1.3.6.1.5.5.7.3.2".into()],
        };
        let matching = PersonalCertificate {
            thumbprint: "a".repeat(40),
            serial_number: "01".into(),
            subject: "CN=alice@example.test".into(),
            issuer: "CN=test issuer".into(),
            simple_name: "alice@example.test".into(),
            dns_names: Vec::new(),
            email_names: vec!["alice@example.test".into()],
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after: "2027-01-01T00:00:00Z".into(),
            has_private_key: true,
            eku_oids: vec!["1.3.6.1.5.5.7.3.2".into()],
        };
        let mut wrong_identity = matching.clone();
        wrong_identity.subject = "CN=bob@example.test".into();
        wrong_identity.simple_name = "bob@example.test".into();
        wrong_identity.email_names = vec!["bob@example.test".into()];
        let mut no_key = matching.clone();
        no_key.has_private_key = false;
        assert_eq!(
            certificates_for_profile(
                &[matching, wrong_identity, no_key],
                &profile,
                "alice@example.test"
            )
            .len(),
            1
        );
    }

    #[test]
    fn certificate_identity_can_match_cn_dns_or_email() {
        let mut certificate = PersonalCertificate {
            thumbprint: "a".repeat(40),
            serial_number: "01".into(),
            subject: "CN=alice".into(),
            issuer: "CN=test issuer".into(),
            simple_name: String::new(),
            dns_names: Vec::new(),
            email_names: Vec::new(),
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after: "2027-01-01T00:00:00Z".into(),
            has_private_key: true,
            eku_oids: Vec::new(),
        };
        assert!(certificate_matches_identity(&certificate, "alice"));
        certificate.subject = "CN=other".into();
        certificate.dns_names = vec!["alice".into()];
        assert!(certificate_matches_identity(&certificate, "alice"));
        certificate.dns_names.clear();
        certificate.email_names = vec!["alice@example.test".into()];
        assert!(certificate_matches_identity(
            &certificate,
            "alice@example.test"
        ));
        assert!(!certificate_matches_identity(
            &certificate,
            "bob@example.test"
        ));
    }

    #[test]
    #[ignore = "mutates and then removes a Current User CNG key container"]
    fn windows_cng_request_smoke_test() {
        let profile = CertificateProfile {
            id: "smoke".into(),
            label: "Smoke".into(),
            description: String::new(),
            purpose: CertificatePurpose::Mtls,
            pki_mount: "pki".into(),
            pki_role: "test".into(),
            subject_claim: "email".into(),
            san_claim: Some("email".into()),
            destination_store: "My".into(),
            key_algorithm: "rsa-3072".into(),
            expected_eku_oids: vec!["1.3.6.1.5.5.7.3.2".into()],
        };
        let request = PendingRequest::generate(&profile, "smoke@example.test").unwrap();
        assert!(request.csr_pem.contains("CERTIFICATE REQUEST"));
        drop(request);
    }
}
