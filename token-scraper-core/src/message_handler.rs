//! Handles incoming messages from the Discord event stream.

use std::{path::Path, str::FromStr};

use solana_sdk::pubkey::Pubkey;
use twilight_model::gateway::payload::incoming::MessageCreate;

use crate::{
    photon_util::{self, is_photon_link},
    settings::DiscordFilter,
    util::{self, *},
};

/// Errors that can occur when handling a message.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to extract token.
    #[error("Failed to extract token: {0}")]
    ExtractToken(#[from] ExtractTokenError),

    /// Failed to send sniper request.
    #[error("Failed to send sniper request: {0}")]
    FailedToSendSniperRequest(#[from] reqwest::Error),

    /// Detected token file error.
    #[error("Detected token file error: {0}")]
    DetectedTokensFile(#[from] std::io::Error),

    /// Market cap error.
    #[error("Market cap error: {0}")]
    MarketCap(#[from] MarketCapError),
}

/// Handles an incoming Discord message.
///
/// This function processes the message to detect tokens and sends a request to the specified endpoint if a token is found.
///
/// # Arguments
///
/// * `message` - A reference to the `MessageCreate` object.
/// * `detected_tokens_file_path` - A reference to the path of the file where detected tokens are stored.
/// * `discord_filters` - A slice of `DiscordFilter` objects to be checked against.
/// * `rpc_url` - The RPC URL for Solana.
///
/// # Errors
///
/// Returns an `Error` if any step in the process fails.
pub async fn handle_message(
    message: &MessageCreate,
    detected_tokens_file_path: &Path,
    discord_filters: &[DiscordFilter],
    rpc_url: &str,
) -> Result<(), Error> {
    if message.guild_id.is_none() {
        return Ok(());
    }

    let filter = match filter_message(message, discord_filters) {
        Some(f) => f,
        None => return Ok(()),
    };

    let token = match process_message_for_token(message, rpc_url).await? {
        Some(t) => t,
        None => return Ok(()),
    };

    if let Some(max_market_cap) = filter.market_cap {
        let market_cap = get_market_cap(&token.to_string()).await?;
        if market_cap > max_market_cap {
            return Ok(());
        }
    }

    tracing::info!("Found {} for filter: {}", token.to_string(), filter.name);

    if is_token_already_detected(&token.to_string(), detected_tokens_file_path).await? {
        tracing::info!("Token already detected, skipping");
        return Ok(());
    }

    println!(
        "Token {} detected for filter: {}",
        console::style(token.to_string()).green(),
        console::style(filter.name.clone()).yellow()
    );

    send_token_request(&token.to_string(), &filter.token_endpoint_url).await?;
    add_token_to_file(&token.to_string(), detected_tokens_file_path).await?;
    tracing::info!("Successfully sent token to endpoint: {}", token.to_string());

    Ok(())
}

/// Filters a message based on the provided Discord filters.
///
/// This function iterates through the provided `discord_filters` and checks if the message matches any of the filters.
/// If a match is found, the corresponding `DiscordFilter` is returned.
///
/// # Arguments
///
/// * `message` - A reference to the `MessageCreate` object.
/// * `discord_filters` - A slice of `DiscordFilter` objects to be checked against.
///
/// # Returns
///
/// * `Some(DiscordFilter)` if a matching filter is found, otherwise `None`.
fn filter_message(
    message: &MessageCreate,
    discord_filters: &[DiscordFilter],
) -> Option<DiscordFilter> {
    for filter in discord_filters {
        match (filter.channel_id, filter.user_id) {
            (Some(channel_id), Some(user_id)) => {
                if message.channel_id.get() == channel_id && message.author.id.get() == user_id {
                    return Some(filter.clone());
                }
            }
            (Some(channel_id), None) => {
                if message.channel_id.get() == channel_id {
                    return Some(filter.clone());
                }
            }
            (None, Some(user_id)) => {
                if message.author.id.get() == user_id {
                    return Some(filter.clone());
                }
            }
            _ => {
                return Some(filter.clone());
            }
        }
    }
    None
}

/// Processes a message to extract a token.
///
/// This function attempts to extract a token from the message content or the descriptions of the message embeds.
///
/// # Arguments
///
/// * `message` - A reference to the `MessageCreate` object.
///
/// # Errors
///
/// Returns an `ExtractTokenError` if the token extraction fails.
async fn process_message_for_token(
    message: &MessageCreate,
    rpc_url: &str,
) -> Result<Option<Pubkey>, ExtractTokenError> {
    tracing::debug!("Processing message: {:?}", message);

    // Attempt to extract a token from the message content
    if let Some(token) = extract_token(&message.content, rpc_url).await? {
        return Ok(Some(token));
    }

    // Attempt to extract a token from the descriptions of the message embeds
    for embed in &message.embeds {
        if let Some(description) = &embed.description {
            if let Some(token) = extract_token(description, rpc_url).await? {
                return Ok(Some(token));
            }
        }
    }

    Ok(None)
}

/// Errors that can occur when extracting a token.
///
/// This enum represents the possible errors that can occur during the token extraction process.
#[derive(Debug, thiserror::Error)]
pub enum ExtractTokenError {
    /// Error from the `extract_token_from_pumpfun_link` function.
    #[error("Failed to extract token from pumpfun link: {0}")]
    ExtractTokenFromPumpFunLink(#[from] super::util::ExtractTokenFromPumpFunLinkError),

    /// Error from the `photon_util::fetch_token` function.
    #[error("Failed to fetch token from photon link: {0}")]
    PhotonFetchToken(#[from] super::photon_util::FetchTokenError),
}

/// Extracts a token from the given content.
///
/// This function checks each word in the content to see if it is a valid token address,
/// a Pump.fun link, or a Photon link, and extracts the token if found.
///
/// # Arguments
///
/// * `content` - A string slice that holds the content to be checked.
///
/// # Errors
///
/// Returns an `ExtractTokenError` if the token extraction fails.
async fn extract_token(content: &str, rpc_url: &str) -> Result<Option<Pubkey>, ExtractTokenError> {
    for word in content.split_whitespace() {
        if is_valid_token_address(word) {
            return Ok(Some(Pubkey::from_str(word).unwrap()));
        }
        if is_pumpfun_link(word) {
            return Ok(Some(extract_token_from_pumpfun_link(word)?));
        }
        if is_photon_link(word) {
            return Ok(Some(photon_util::fetch_token(word, rpc_url).await?));
        }
    }

    Ok(None)
}

/// Errors that can occur when getting the market cap.
#[derive(Debug, thiserror::Error)]
pub enum MarketCapError {
    /// Error from the `util::get_token_price_jup` function.
    #[error("Failed to get token price from Jupiter API: {0}")]
    GetTokenPriceJup(#[from] util::JupPriceApiError),
}

/// Fetches the market cap of a token.
///
/// This function calculates the market cap of a token by fetching its price from the Jupiter API
/// and multiplying it by the supply of pumpfun tokens.
///
/// # Arguments
///
/// * `token` - A string slice that holds the token symbol.
///
/// # Errors
///
/// Returns a `MarketCapError` if the request to fetch the token price fails.
async fn get_market_cap(token: &str) -> Result<u128, MarketCapError> {
    /// The supply of pumpfun tokens.
    const PUMPFUN_TOKEN_SUPPLY: u128 = 1_000_000_000;

    let price = util::get_token_price_jup(token, "USDC").await?;
    let market_cap = (price * PUMPFUN_TOKEN_SUPPLY as f64) as u128;
    Ok(market_cap)
}
