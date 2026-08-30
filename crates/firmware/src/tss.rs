use std::io::Cursor;

use plist::{Dictionary, Value};
use reqwest::Url;
use thiserror::Error;
use tracing::{debug, info};

const DEFAULT_TSS_ENDPOINT: &str = "https://gs.apple.com/TSS/controller?action=2";
const TSS_VERSION: &str = "libauthinstall-1033.0.2";

#[derive(Clone, Debug)]
pub struct TssRequest {
    dictionary: Dictionary,
}

impl TssRequest {
    pub fn new() -> Self {
        let mut dictionary = Dictionary::new();
        dictionary.insert("@HostPlatformInfo".into(), "mac".into());
        dictionary.insert("@VersionInfo".into(), TSS_VERSION.into());
        dictionary.insert(
            "@UUID".into(),
            uuid::Uuid::new_v4().to_string().to_uppercase().into(),
        );
        Self { dictionary }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        self.dictionary.insert(key.into(), value.into());
    }

    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }
}

impl Default for TssRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct TssResponse {
    dictionary: Dictionary,
}

impl TssResponse {
    pub fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    pub fn into_dictionary(self) -> Dictionary {
        self.dictionary
    }
}

#[derive(Clone, Debug)]
pub struct TssClient {
    endpoint: Url,
    client: reqwest::Client,
}

impl TssClient {
    pub fn new() -> Self {
        Self {
            endpoint: Url::parse(DEFAULT_TSS_ENDPOINT).expect("default TSS endpoint must be valid"),
            client: reqwest::Client::new(),
        }
    }

    pub fn with_endpoint(endpoint: Url) -> Self {
        Self {
            endpoint,
            client: reqwest::Client::new(),
        }
    }

    pub async fn send(&self, request: &TssRequest) -> Result<TssResponse, TssError> {
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, request.dictionary())?;
        debug!(
            keys = request.dictionary().len(),
            "sending redacted TSS request"
        );
        let response = self
            .client
            .post(self.endpoint.clone())
            .header("Cache-Control", "no-cache")
            .header("Content-Type", "text/xml; charset=utf-8")
            .header("User-Agent", "InetURL/1.0")
            .body(body)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let response = parse_response(&response)?;
        info!(
            keys = response.dictionary.len(),
            "received successful TSS response"
        );
        Ok(response)
    }
}

impl Default for TssClient {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_response(response: &str) -> Result<TssResponse, TssError> {
    let response = response.trim();
    if !response.starts_with("STATUS=0&MESSAGE=SUCCESS") {
        let message = response
            .split('&')
            .find_map(|value| value.strip_prefix("MESSAGE="))
            .unwrap_or("unknown TSS error");
        return Err(TssError::Rejected(message.to_owned()));
    }
    let payload = response
        .split_once("REQUEST_STRING=")
        .map(|(_, payload)| payload)
        .ok_or(TssError::MissingPayload)?;
    let value = Value::from_reader(Cursor::new(payload.as_bytes()))?;
    let dictionary = value
        .into_dictionary()
        .ok_or(TssError::PayloadNotDictionary)?;
    Ok(TssResponse { dictionary })
}

#[derive(Debug, Error)]
pub enum TssError {
    #[error("TSS HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("TSS plist failed: {0}")]
    Plist(#[from] plist::Error),
    #[error("TSS rejected the request: {0}")]
    Rejected(String),
    #[error("TSS response did not include REQUEST_STRING")]
    MissingPayload,
    #[error("TSS payload is not a dictionary")]
    PayloadNotDictionary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_success_response() {
        let response = concat!(
            "STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=",
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<plist version="1.0"><dict><key>ApImg4Ticket</key><data>AQID</data></dict></plist>"#
        );

        let response = parse_response(response).unwrap();
        assert!(response.dictionary().contains_key("ApImg4Ticket"));
    }

    #[test]
    fn preserves_rejection_message() {
        let error = parse_response("STATUS=94&MESSAGE=This device isn't eligible").unwrap_err();
        assert!(
            matches!(error, TssError::Rejected(message) if message == "This device isn't eligible")
        );
    }
}
