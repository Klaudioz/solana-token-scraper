//! Database models for the token-scraper application.

use super::schema::*;
use diesel::prelude::*;

/// Represents a token in the database.
///
/// This struct maps to the `tokens` table in the SQLite database.
#[derive(Queryable, Selectable, Identifiable, Debug, PartialEq)]
#[diesel(table_name = tokens)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Token {
    /// The unique identifier for the token.
    pub id: i32,
    /// The address of the token.
    pub token_address: String,
}
