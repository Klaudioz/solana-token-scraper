//! Macros for the token-scraper-core crate.

/// Creates and configures a new spinner with a custom message.
///
/// This macro initializes a new spinner using the `indicatif` crate, sets its style,
/// enables a steady tick, and assigns a custom message to it.
///
/// # Arguments
///
/// * `$msg` - The message to display with the spinner.
#[macro_export]
macro_rules! get_spinner {
    ($msg:expr) => {{
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(ProgressStyle::with_template("{msg} {spinner:.green}").unwrap());
        spinner.enable_steady_tick(Duration::from_millis(120));
        spinner.set_message($msg);
        spinner
    }};
}
