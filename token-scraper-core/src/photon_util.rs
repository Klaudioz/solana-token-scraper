//! Utility functions for handling Photon links.

use std::{str::FromStr, time::Duration};

use regex::Regex;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};

/// Wrapped SOL token.
const WRAPPED_SOL: &str = "So11111111111111111111111111111111111111112";
/// USDC token.
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Errors that can occur when fetching a token.
#[derive(Debug, thiserror::Error)]
pub enum FetchTokenError {
    /// Failed to extract the LP account from the link.
    #[error("Failed to extract LP account from link")]
    ExtractLp(#[from] ExtractLpError),

    /// Failed to get the LP account.
    #[error("Failed to get LP account: {0}")]
    GetAccount(#[from] solana_client::client_error::ClientError),

    /// Failed to deserialize AmmInfo.
    #[error("Failed to deserialize AmmInfo")]
    DeserializeAmmInfo(#[from] std::boxed::Box<bincode::ErrorKind>),

    /// Invalid quote token in the LP account.
    #[error("Invalid quote token in LP account: {0}")]
    InvalidQuoteToken(Pubkey),

    /// Unhandled owner for the LP account.
    #[error("Unhandled owner for LP account: {0}")]
    UnhandledOwner(Pubkey),
}

/// Fetches a token from a given link.
///
/// This function extracts the LP account from the provided link, fetches the account data from the Solana blockchain,
/// and returns the token `Pubkey` if it is not a wrapped SOL or USDC token.
///
/// # Arguments
///
/// * `link` - A string slice that holds the link to be checked.
///
/// # Errors
///
/// Returns a `FetchTokenError` if there is an error extracting the LP account, fetching the account data,
/// deserializing the AmmInfo, or if the LP account contains an invalid quote token or has an unhandled owner.
pub async fn fetch_token(link: &str, rpc_url: &str) -> Result<Pubkey, FetchTokenError> {
    let lp = extract_lp(link)?;
    let rpc_client = RpcClient::new_with_timeout_and_commitment(
        rpc_url.to_string(),
        Duration::from_secs(10),
        CommitmentConfig::confirmed(),
    );

    let account = rpc_client.get_account(&lp).await?;

    if account.owner == raydium_amm_interface::ID {
        let amm_info: raydium_amm_interface::AmmInfo = bincode::deserialize(&account.data)?;
        let tokens = [amm_info.coin_mint, amm_info.pc_mint];
        for &token in &tokens {
            if token.to_string() != WRAPPED_SOL && token.to_string() != USDC {
                return Ok(token);
            }
        }
        Err(FetchTokenError::InvalidQuoteToken(lp))
    } else {
        Err(FetchTokenError::UnhandledOwner(lp))
    }
}

/// Checks if the provided link is a Photon link.
///
/// # Arguments
///
/// * `link` - A string slice that holds the link to be checked.
///
/// # Returns
///
/// * `true` if the link starts with "https://photon-sol.tinyastro.io/en/lp/", otherwise `false`.
pub fn is_photon_link(link: &str) -> bool {
    link.contains("https://photon-sol.tinyastro.io/en/lp/")
}

/// Errors that can occur when extracting the LP account from a link.
#[derive(Debug, thiserror::Error)]
pub enum ExtractLpError {
    /// No LP account found in the provided link.
    #[error("No LP found in link: {0}")]
    InvalidLink(String),

    /// Failed to parse the LP account to a Pubkey.
    #[error("Failed to parse LP to Pubkey")]
    ParseLp(#[from] solana_sdk::pubkey::ParsePubkeyError),
}

/// Extracts the LP account from a given URL.
///
/// # Arguments
///
/// * `url` - A string slice that holds the URL to be checked.
///
/// # Returns
///
/// * `Result<Pubkey, ExtractLpError>` containing the LP account if found, otherwise an error.
fn extract_lp(url: &str) -> Result<Pubkey, ExtractLpError> {
    let re = Regex::new(r"/lp/([a-zA-Z0-9]+)").unwrap();
    let lp = re
        .captures(url)
        .and_then(|caps| caps.get(1))
        .ok_or(ExtractLpError::InvalidLink(url.to_string()))?;
    Ok(Pubkey::from_str(lp.as_str())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the `fetch_token` function.
    #[tokio::test]
    async fn test_fetch_token() {
        let rpc_url = "https://api.mainnet-beta.solana.com";
        // Fetch the token using the provided URL.
        let token = fetch_token(
            "https://photon-sol.tinyastro.io/en/lp/Ea2Kyy7JrB3B7HPrWxS7N67HMUnuiFQiLAoQ5L5eswoh?handle=4378214ef5e1b0ab98c",
            rpc_url,
        ).await.unwrap();

        // Assert that the fetched token matches the expected value.
        assert!(token.to_string() == "Dv4FD3WksCDjF8W5r2wU5onnPQzRgpb2hJ3gpQx4pump");
    }

    /// Tests the `is_photon_link` function.
    #[test]
    fn test_is_photon_link() {
        assert!(is_photon_link(
            "\"https://photon-sol.tinyastro.io/en/lp/Ea2Kyy7JrB3B7HPrWxS7N67HMUnuiFQiLAoQ5L5eswoh?handle=4378214ef5e1b0ab98c"
        ));
        assert!(is_photon_link(
            "https://photon-sol.tinyastro.io/en/lp/GZqCkvYTrfNUiPuKs5sWYPuFb2FHqHCJazPkGYWunTng?handle=4378214ef5e1b0ab98c"
        ));
        assert!(!is_photon_link("https://photon-sol.FHqHCJazPkGYWunTng"));
    }

    /// Tests the `extract_lp` function.
    #[test]
    fn test_extract_lp() {
        assert_eq!(
            extract_lp(
                "\"https://photon-sol.tinyastro.io/en/lp/Ea2Kyy7JrB3B7HPrWxS7N67HMUnuiFQiLAoQ5L5eswoh?handle=4378214ef5e1b0ab98c"
            ).unwrap().to_string(),
            "Ea2Kyy7JrB3B7HPrWxS7N67HMUnuiFQiLAoQ5L5eswoh".to_string()
        );
        assert_eq!(
            extract_lp(
                "https://photon-sol.tinyastro.io/en/lp/GZqCkvYTrfNUiPuKs5sWYPuFb2FHqHCJazPkGYWunTng"
            ).unwrap().to_string(),
            "GZqCkvYTrfNUiPuKs5sWYPuFb2FHqHCJazPkGYWunTng".to_string()
        );
    }
}
