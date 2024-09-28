//! Utility functions for the solana-token-scraper program.

use std::{str::FromStr, sync::Arc};

use diesel::prelude::*;
use regex::Regex;
use solana_sdk::pubkey::Pubkey;
use tokio::sync::Mutex;

/// Checks if the provided token address is valid.
///
/// # Arguments
///
/// * `token_address` - A string slice that holds the token address.
///
/// # Errors
///
/// This function does not return errors.
pub fn is_valid_token_address(token_address: &str) -> bool {
    let address = Pubkey::try_from(token_address);
    address.is_ok()
}

/// Sends a sniper request to the specified URL.
///
/// This function sends a GET request to the given URL with the token as a query parameter.
///
/// # Arguments
///
/// * `token` - A string slice that holds the token.
/// * `url` - The base URL to send the request to.
///
/// # Errors
///
/// Returns a `reqwest::Error` if the request fails.
pub async fn send_token_request(token: &str, url: &str) -> Result<(), reqwest::Error> {
    let url = format!("{url}?token={token}");
    reqwest::get(url).await?;
    Ok(())
}

/// Checks if the token is already detected in the database.
///
/// # Arguments
///
/// * `token_address` - A string slice that holds the token address.
/// * `database_connection` - An `Arc` containing the `Mutex` of the database connection.
///
/// # Errors
///
/// Returns a `diesel::result::Error` if the database query fails.
pub async fn is_token_already_detected(
    token_address: &str,
    database_connection: Arc<Mutex<diesel::SqliteConnection>>,
) -> Result<bool, diesel::result::Error> {
    use crate::database::schema::tokens;

    let mut conn = database_connection.lock().await;
    let exists = diesel::select(diesel::dsl::exists(
        tokens::table.filter(tokens::token_address.eq(token_address)),
    ))
    .get_result::<bool>(&mut *conn)?;

    Ok(exists)
}

/// Adds a token to the database.
///
/// # Arguments
///
/// * `token_address` - A string slice that holds the token address.
/// * `database_connection` - An `Arc` containing the `Mutex` of the database connection.
///
/// # Errors
///
/// Returns a `diesel::result::Error` if the database insertion fails.
pub async fn add_token_to_db(
    token_address: &str,
    database_connection: Arc<Mutex<diesel::SqliteConnection>>,
) -> Result<(), diesel::result::Error> {
    use crate::database::schema::tokens;

    let mut conn = database_connection.lock().await;
    diesel::insert_into(tokens::table)
        .values(tokens::token_address.eq(token_address))
        .execute(&mut *conn)?;

    Ok(())
}

/// Checks if the provided link is a Pump.fun link.
///
/// # Arguments
///
/// * `link` - A string slice that holds the link to be checked.
///
/// # Returns
///
/// * `true` if the link contains "https://pump.fun/", otherwise `false`.
pub fn is_pumpfun_link(link: &str) -> bool {
    link.contains("https://pump.fun/")
}

/// Errors that can occur when extracting a token from a Pump.fun link.
#[derive(Debug, thiserror::Error)]
pub enum ExtractTokenFromPumpFunLinkError {
    /// The provided link is invalid.
    #[error("Invalid link")]
    InvalidLink(String),

    /// Failed to parse the token to a Pubkey.
    #[error("Failed to parse token to Pubkey")]
    ParseToken(#[from] solana_sdk::pubkey::ParsePubkeyError),
}

/// Extracts the token from a given Pump.fun link.
///
/// # Arguments
///
/// * `link` - A string slice that holds the Pump.fun link.
///
/// # Returns
///
/// * `Result<Pubkey, ExtractTokenErrorFromPumpFunLink>` containing the token if found, otherwise an error.
pub fn extract_token_from_pumpfun_link(
    link: &str,
) -> Result<Pubkey, ExtractTokenFromPumpFunLinkError> {
    let re = Regex::new(r#"https://pump\.fun/([A-Za-z0-9]+)"#).unwrap();
    let token = re.captures(link).and_then(|caps| caps.get(1)).ok_or(
        ExtractTokenFromPumpFunLinkError::InvalidLink(link.to_string()),
    )?;

    Ok(Pubkey::from_str(token.as_str())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests the `is_pumpfun_link` function.
    #[test]
    fn test_is_pumpfun_link() {
        // Test with a valid Pump.fun link
        assert!(is_pumpfun_link(
            "https://pump.fun/5eMZuRe5JfEz7hdv3ZorNsmcMs4qEGiGH1esFJsJFHka"
        ));
        // Test with a valid Pump.fun link enclosed in quotes
        assert!(is_pumpfun_link(
            "\"https://pump.fun/5eMZuRe5JfEz7hdv3ZorNsmcMs4qEGiGH1esFJsJFHka\""
        ));
        // Test with an invalid Pump.fun link
        assert!(!is_pumpfun_link("pumpfun"));
    }

    /// Tests the `extract_token_from_pumpfun_link` function.
    #[test]
    fn test_extract_token_from_pumpfun_link() {
        // Test with a valid Pump.fun link
        assert_eq!(
            extract_token_from_pumpfun_link(
                "https://pump.fun/5eMZuRe5JfEz7hdv3ZorNsmcMs4qEGiGH1esFJsJFHka"
            )
            .unwrap(),
            Pubkey::from_str("5eMZuRe5JfEz7hdv3ZorNsmcMs4qEGiGH1esFJsJFHka").unwrap()
        );
        // Test with a valid Pump.fun link enclosed in quotes
        assert_eq!(
            extract_token_from_pumpfun_link(
                "\"https://pump.fun/5eMZuRe5JfEz7hdv3ZorNsmcMs4qEGiGH1esFJsJFHka\""
            )
            .unwrap(),
            Pubkey::from_str("5eMZuRe5JfEz7hdv3ZorNsmcMs4qEGiGH1esFJsJFHka").unwrap()
        );
    }
}
