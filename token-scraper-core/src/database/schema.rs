//! Database schema for the token-scraper program.

// @generated automatically by Diesel CLI.

diesel::table! {
    tokens (id) {
        id -> Integer,
        token_address -> Text,
    }
}
