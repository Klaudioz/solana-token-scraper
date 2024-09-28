# Solana Token Scraper

[![CI](https://github.com/thelezend/solana-token-scraper/actions/workflows/ci.yml/badge.svg)](https://github.com/thelezend/solana-token-scraper/actions/workflows/ci.yml)

## Introduction

A minimal CLI application designed to detect and scrape Solana token information from social media channels, particularly useful for tracking free and premium alpha group calls.

### Supported platforms

- [x] Discord
- [ ] Telegram

## Working and Usage

The program connects to the Discord gateway using your token and monitors messages mentioning valid Solana token addresses.

- You can use `discord_filters.csv` to customize it and filter scans to specific channels and user messages.
- This is not a sniping/trading bot but is designed to work alongside automation/sniping bots like [Peppermints](https://www.tensor.trade/trade/peppermints) or your custom programs with similar functionality.
- Once a token is detected, it will send a GET request to the URL specified in the `TOKEN_ENDPOINT_URL` field.
- The detected token addresses are saved in a local text file to avoid duplicate purchases.
- Logs are saved in `logs` directory if you want a record of detected tokens.

> **IMPORTANT: Using user accounts for automation is against Discord's TOS, so use them at your own risk, preferably with accounts you can afford to lose.**

## Installation

You can directly download the pre-built binary executable for your OS and architecture from the [releases](https://github.com/thelezend/solana-token-scraper/releases) page. If you prefer to verify the code, build it yourself, or need to use it on an OS without a binary release, you can easily build it from source. Plenty of Rust-related resources are available online to guide you through the process.

## Configuration

### Settings

Need to have a `settings.json` file in the working directory with the following:

```json
{
    "discord": {
        "user_token": "YOUR_DISCORD_USER_TOKEN",
        "sec_ws_key": "YOUR_DISCORD_SECRET_WS_KEY"
    },
    "solana": {
        "rpc_url": "YOUR_RPC_URL" // Only used for getting tokens from links. Won't be used to send transactions.
    }
}
```

- Read how to get a Discord user account token [here](https://gist.github.com/MarvNC/e601f3603df22f36ebd3102c501116c6).
- You can similarly obtain the `Sec-Websocket-Key` from the headers of the WebSocket request to the Discord gateway.

### Filters

Need to have a `discord_filters.csv` file in the working directory with the following:

```csv
NAME,CHANNEL_ID,USER_ID,TOKEN_ENDPOINT_URL
test,12314,123234,http://localhost:9001/solana
pow-calls,132414,51451345,http://localhost:9005/solana
```

- `CHANNEL_ID` is the ID of the channel you want to monitor.
- `USER_ID` is the ID of the user you want to monitor.
- `TOKEN_ENDPOINT_URL` is the URL to which a GET request will be made, with the token address as a parameter.

## Support and Contact

Feel free to customize and integrate the code as you like. If this has been helpful or profitable, and you’re feeling generous enough to pay for my gym subscription 😅, you can send Solana or any other token to my Solana wallet: `lezend.sol`

If you’d like me to build any app or tool, feel free to reach out to me on Discord.

## Code contributions

Your contributions are welcome! I would love to make this tool better or add new features. Please ensure your code follows the existing style and includes documentation and tests for any new functionality.

For major changes, please open an issue first to discuss what you would like to change or feel free reach out to me on my socials, preferably Discord.

## License

This project is licensed under the MIT OR Apache-2.0 license.
