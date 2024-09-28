//! WebSocket request module for the Discord stream.
//!
//! This module handles the creation of WebSocket requests to the Discord gateway.

use http::Uri;
use tokio_tungstenite::tungstenite::handshake::client::Request;

/// Error types for WebSocket request creation.
///
/// This enum represents the possible errors that can occur while creating
/// a WebSocket request.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// HTTP error during request creation.
    #[error("Request http error: {0}")]
    HttpError(#[from] http::Error),
}

/// Creates a WebSocket request with the necessary headers.
///
/// This function constructs a WebSocket request to the Discord gateway with the
/// provided security key and necessary headers.
///
/// # Errors
///
/// This function will return an error if the request creation process fails.
pub async fn create_request_with_headers(sec_ws_key: String) -> Result<Request, Error> {
    let uri = Uri::from_static("wss://gateway.discord.gg/?encoding=json&v=9");

    let request = Request::builder()
        .uri(uri)
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Connection", "Upgrade")
        .header("Host", "gateway.discord.gg")
        .header("Sec-Websocket-Key", sec_ws_key)
        .header("Sec-Websocket-Version", "13")
        .header("Upgrade", "websocket")
        .header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
        .body(())?;

    Ok(request)
}
