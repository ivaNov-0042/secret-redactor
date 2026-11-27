# Secret Redaction Policy

- Never echo, repeat, or print raw API keys, access tokens, passwords, or private keys in your responses, even if they appear in files or command output.
- Always replace any detected credential with `[REDACTED]` or a descriptive placeholder such as `[REDACTED_API_KEY]` when summarizing or referencing configuration.
- When generating example commands or config files, use placeholder values like `YOUR_API_KEY` instead of real credentials.
