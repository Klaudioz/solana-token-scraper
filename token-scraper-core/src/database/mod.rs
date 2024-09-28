//! Database module for the token-scraper application.
//!
//! This module handles the database connection and migrations for the application.
//! It provides functions to establish a connection to the database and run migrations.

use diesel::prelude::*;
use thiserror::Error;

pub mod models;
pub mod schema;

/// Error types for the database module.
#[derive(Debug, Error)]
pub enum Error {
    /// Connection error.
    #[error(transparent)]
    Connection(#[from] ConnectionError),

    /// Migration error.
    #[error("Failed to run database migrations: {0}")]
    DieselMigration(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Establishes a connection to the SQLite database and runs pending migrations.
///
/// This function connects to the SQLite database specified by the `database_url`
/// and applies any pending migrations.
///
/// # Errors
///
/// This function will return an error if the connection to the database fails
/// or if running the migrations fails.
pub async fn establish_database_connection(database_url: &str) -> Result<SqliteConnection, Error> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    /// Define the migrations to be applied
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

    let mut db_connection = SqliteConnection::establish(database_url)?;
    db_connection.run_pending_migrations(MIGRATIONS)?;

    Ok(db_connection)
}
