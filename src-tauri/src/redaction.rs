const SECRET_KEYS: &[&str] = &[
    "token",
    "client_token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_nonce",
    "state",
    "code",
    "csr",
    "pin",
    "management_key",
    "private_key",
];

pub fn redact(input: &str) -> String {
    let mut output = input.to_owned();
    for key in SECRET_KEYS {
        for separator in ["=", "\":\"", "\": \""] {
            let marker = format!("{key}{separator}");
            let mut search_from = 0;
            while let Some(relative) = output[search_from..].to_ascii_lowercase().find(&marker) {
                let start = search_from + relative + marker.len();
                let end = output[start..]
                    .find(|c: char| c == '&' || c == ',' || c == '"' || c.is_whitespace())
                    .map(|offset| start + offset)
                    .unwrap_or(output.len());
                output.replace_range(start..end, "[REDACTED]");
                search_from = start + "[REDACTED]".len();
            }
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_query_and_json_secrets() {
        let value = redact(
            "token=abc123&x=1 client_token\":\"secret\", private_key=hidden csr=request pin=123456",
        );
        assert!(!value.contains("abc123"));
        assert!(!value.contains("secret"));
        assert!(!value.contains("hidden"));
        assert!(!value.contains("request"));
        assert!(!value.contains("123456"));
    }
}
