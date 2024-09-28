//! Settings module for the token-scraper application.
//!
//! This module handles loading and managing the configuration settings for the application.
//! It provides a `Settings` struct that holds the configuration values and a method to load these values from a JSON file.

use std::path::Path;

use config::{Config, ConfigError, File, FileFormat};
use serde::Deserialize;
use thiserror::Error;

/// Path to the settings file.
pub const SETTINGS_FILE_PATH: &str = "settings.json";

/// Error types for settings module.
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Deserialization error.
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),
}

/// Settings for the token-scraper application.
///
/// This struct holds the configuration settings for the application.
#[derive(Debug, Deserialize)]
pub struct Settings {
    /// Discord settings.
    pub discord: DiscordSettings,
    /// Solana settings.
    pub solana: SolanaSettings,
}

/// Discord settings for the token-scraper application.
#[derive(Debug, Deserialize)]
pub struct DiscordSettings {
    /// Token for the Discord user.
    pub user_token: String,
    /// Secret WebSocket key.
    pub sec_ws_key: String,
}

/// Solana settings for the token-scraper application.
#[derive(Debug, Deserialize)]
pub struct SolanaSettings {
    /// RPC URL for the Solana network.
    pub rpc_url: String,
}

impl Settings {
    /// Creates a new instance of `Settings` by loading the configuration from `settings.json`.
    ///
    /// This function reads the `settings.json` file, parses it, and deserializes it into a `Settings` struct.
    ///
    /// # Errors
    ///
    /// This function will return an error if the configuration file cannot be read or if the deserialization fails.
    pub fn new() -> Result<Self, Error> {
        let config = Config::builder()
            .add_source(File::new(SETTINGS_FILE_PATH, FileFormat::Json))
            .build()?;

        let settings = config.try_deserialize()?;
        Ok(settings)
    }
}

/// Discord filter for the token-scraper application.
#[derive(Debug, Deserialize, Clone)]
pub struct DiscordFilter {
    /// Name of the filter.
    #[serde(rename = "NAME")]
    pub name: String,
    /// Channel ID to filter.
    #[serde(rename = "CHANNEL_ID")]
    pub channel_id: Option<u64>,
    /// User ID to filter.
    #[serde(rename = "USER_ID")]
    pub user_id: Option<u64>,
    /// Token endpoint URL to filter.
    #[serde(rename = "TOKEN_ENDPOINT_URL")]
    pub token_endpoint_url: String,
}

#[derive(Error, Debug)]
pub enum DiscordFiltersError {
    /// File error.
    #[error("File error: {0}")]
    File(#[from] std::io::Error),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    Deserialize(#[from] csv::Error),
}

/// Reads Discord filters from a CSV file.
///
/// This function opens the specified CSV file, reads its contents, and deserializes each record into a `DiscordFilter` struct.
///
/// # Arguments
///
/// * `file_path` - A `&Path` that holds the path to the CSV file.
///
/// # Errors
///
/// This function will return an error if the file cannot be opened or if deserialization fails.
pub fn read_discord_filters_from_csv(
    file_path: &Path,
) -> Result<Vec<DiscordFilter>, DiscordFiltersError> {
    let mut filters = Vec::new();
    let file = std::fs::File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    let mut rdr = csv::Reader::from_reader(reader);

    for result in rdr.deserialize() {
        let record: DiscordFilter = result?;
        filters.push(record);
    }

    Ok(filters)
}
