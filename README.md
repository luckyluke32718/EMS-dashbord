# ReadyResponse

## Run locally

Use Node.js 18 or newer. Create the separate owner credentials file, then start the app:

```text
npm run setup-owner
npm start
```

Open `http://127.0.0.1:3000`. New users can register at `/register`, sign in at `/login`, and complete their saved report at `/report`. The separate owner sign-in and dashboard are at `/owner`.

The owner setup command prompts for an email and password, then saves the email and a salted password hash in `data/owner.json`. The readable password is never written to that file. Keep the data directory private and out of source control.

The owner credentials file can contain multiple owner accounts in its `owners` array. Owners can sign in with an email or username in `/owner`.

## Discord reports

Copy `.env.example` to `.env` and configure:

```text
DISCORD_BOT_TOKEN=your-discord-bot-token
DISCORD_ACCEPTED_CHANNEL_ID=accepted-report-channel-id
```

The bot needs permission to view the channel and send messages. Saving a patient report sends it directly to the configured channel. Keep `.env` private and never share the bot token.

## Local data and security

User account records, successful login timestamps, and EMS reports are saved in `data/store.json`. User and owner passwords are stored as salted scrypt hashes, never as plain text. The data directory is excluded from Git. The owner dashboard can add people, review reports, disable or re-enable accounts, and delete an account and its report.

By default the server listens only on `127.0.0.1`. This local prototype is not a substitute for a production security or privacy review. Do not expose it to the public internet or use it for real medical data without HTTPS, backups, access policies, and an appropriate privacy/security review.
