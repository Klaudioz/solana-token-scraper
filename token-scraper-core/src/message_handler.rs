//! Handles incoming messages from the Discord event stream.

use std::{path::Path, str::FromStr};

use regex::Regex;
use solana_sdk::pubkey::Pubkey;
use twilight_model::gateway::payload::incoming::MessageCreate;

use crate::{
    photon_util::{self, is_photon_link},
    settings::DiscordFilter,
    util::*,
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

    if let Some(market_cap_filter) = filter.market_cap {
        if let Some(market_cap) = extract_market_cap(&message.content) {
            if market_cap > market_cap_filter {
                return Ok(());
            }
        } else {
            return Ok(());
        }
    }

    let token = match process_message_for_token(message, rpc_url).await? {
        Some(t) => t,
        None => return Ok(()),
    };

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

/// Extracts the market cap from the given content.
///
/// This function uses a regular expression to find the market cap value in the content.
/// The market cap is expected to be in the format `FDV: $<value><suffix>`, where `<suffix>` can be `K` for thousands or `M` for millions.
///
/// # Arguments
///
/// * `content` - A string slice that holds the content to be checked.
///
/// # Errors
///
/// Returns `None` if the market cap cannot be extracted.
fn extract_market_cap(content: &str) -> Option<u128> {
    let re = Regex::new(r"FDV:\s*`?\$?([\d\.]+[KM]?)`?").unwrap();
    let caps = re.captures(content);
    if let Some(caps) = caps {
        let value = &caps[1];
        let fdv: u128 = if let Some(value) = value.strip_suffix('K') {
            (value.parse::<f64>().unwrap() * 1_000.0) as u128
        } else if let Some(value) = value.strip_suffix('M') {
            (value.parse::<f64>().unwrap() * 1_000_000.0) as u128
        } else {
            value.parse::<u128>().unwrap()
        };
        return Some(fdv);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_market_cap() {
        let content = r#"<:sol:941653282420576296> Solana @ Raydium 🔥 `#1`
        💰 USD: `$0.0001796`
        💎 FDV: `$179.6K`
        💦 Liq: `$45.8K` 🐡`[x7.8]`
        📊 Vol: `$2M` 🕰️ Age: `55m`
        ⛰️ ATH: `$670.5K` `[21m ago]`
        🚀 1H: `204%` ⋅ `$2.1M` 🅑 `5.5K` 🅢 `4.6K`
        👥 TH: [11.3](https://solscan.io/account/EhSDbRzZLXhNRTrtfsYDAoYXfRP6k6MCTP53t6tsEJ7P)⋅[2.5](https://solscan.io/account/Dind5A7BakWdjD8XygQAyAjLWn76zk7rnds9M9PafqoA)⋅[2.5](https://solscan.io/account/6iAmTtqBYqy6trQsxirYakZDSRnySHfPNEyPLnaqg7Um)⋅[2.2](https://solscan.io/account/EgLQCxBUwZrEa3b9vamZ21att941nYixMVk5REise1op)⋅[2.1](https://solscan.io/account/3np7y4rbmgykpCSu3sG4291fm1CHptb6YAX2PY6aZxqS) `[30%]`
        🖨️ Mint: ✅ ⋅ LP: 🔥
        🧰 More: [ch](https://t.me/RickBurpBot/dsapp?startapp=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump_solana) ⋅ [bm](https://t.me/RickBurpBot/bmapp?startapp=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump_solana_def)

        A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump
        [MAE](https://t.me/MaestroSniperBot?start=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump-rickburpbot)⋅[BAN](https://t.me/BananaGunSolana_bot?start=snp_rickburpbot_A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[BNK](https://t.me/mcqueen_bonkbot?start=ref_rickbot_ca_A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[SHU](https://t.me/ShurikenTradeBot?start=qt-RickSanchez-A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[PEP](https://t.me/pepeboost_sol_bot?start=ref_0xRick_ca_A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[DEX](https://dexscreener.com/solana/2jtegzvtn39pokjyftlyct2rzy9msureowajqfap43np)⋅[BRD](https://birdeye.so/token/A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump?chain=solana)
        [TRO](https://t.me/paris_trojanbot?start=d-RickBot-A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[STB](https://t.me/SolTradingBot?start=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump-yqC7cGy1T)⋅[PHO](https://photon-sol.tinyastro.io/en/r/@RickBurpBot/2jTeGZvtN39pokJyFTLyct2rzY9MSUReowAJQfap43NP)⋅[**BLX**](https://bullx.io/terminal?chainId=1399811149&address=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump&r=M7B0AY33YBS)⋅[EXP](https://solscan.io/account/A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[RUG](https://rugcheck.xyz/tokens/A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[TW](https://twitter.com/search?q=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)
        🔥 **BETA:** Try the web checker: **.web**"#;

        assert_eq!(extract_market_cap(content), Some(179600));

        let content2 = r#"💎 FDV: `15.1K`
        💦 Liq: `$45.8K` 🐡`[x7.8]`
        📊 Vol: `$2M` 🕰️ Age: `55m`
        ⛰️ ATH: `$670.5K` `[21m ago]`
        🚀 1H: `204%` ⋅ `$2.1M` 🅑 `5.5K` 🅢 `4.6K`
        👥 TH: [11.3](https://solscan.io/account/EhSDbRzZLXhNRTrtfsYDAoYXfRP6k6MCTP53t6tsEJ7P)⋅[2.5](https://solscan.io/account/Dind5A7BakWdjD8XygQAyAjLWn76zk7rnds9M9PafqoA)⋅[2.5](https://solscan.io/account/6iAmTtqBYqy6trQsxirYakZDSRnySHfPNEyPLnaqg7Um)⋅[2.2](https://solscan.io/account/EgLQCxBUwZrEa3b9vamZ21att941nYixMVk5REise1op)⋅[2.1](https://solscan.io/account/3np7y4rbmgykpCSu3sG4291fm1CHptb6YAX2PY6aZxqS) `[30%]`
        🖨️ Mint: ✅ ⋅ LP: 🔥
        🧰 More: [ch](https://t.me/RickBurpBot/dsapp?startapp=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump_solana) ⋅ [bm](https://t.me/RickBurpBot/bmapp?startapp=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump_solana_def)

        A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump
        [MAE](https://t.me/MaestroSniperBot?start=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump-rickburpbot)⋅[BAN](https://t.me/BananaGunSolana_bot?start=snp_rickburpbot_A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[BNK](https://t.me/mcqueen_bonkbot?start=ref_rickbot_ca_A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[SHU](https://t.me/ShurikenTradeBot?start=qt-RickSanchez-A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[PEP](https://t.me/pepeboost_sol_bot?start=ref_0xRick_ca_A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[DEX](https://dexscreener.com/solana/2jtegzvtn39pokjyftlyct2rzy9msureowajqfap43np)⋅[BRD](https://birdeye.so/token/A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump?chain=solana)
        [TRO](https://t.me/paris_trojanbot?start=d-RickBot-A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[STB](https://t.me/SolTradingBot?start=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump-yqC7cGy1T)⋅[PHO](https://photon-sol.tinyastro.io/en/r/@RickBurpBot/2jTeGZvtN39pokJyFTLyct2rzY9MSUReowAJQfap43NP)⋅[**BLX**](https://bullx.io/terminal?chainId=1399811149&address=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump&r=M7B0AY33YBS)⋅[EXP](https://solscan.io/account/A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[RUG](https://rugcheck.xyz/tokens/A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)⋅[TW](https://twitter.com/search?q=A1WpmBTaVFbsKSm4Ab2oqaj6D6uAKmA7vSgpiQD6pump)
        🔥 **BETA:** Try the web checker: **.web**"#;

        assert_eq!(extract_market_cap(content2), Some(15100));
    }
}
