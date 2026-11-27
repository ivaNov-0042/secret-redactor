# secret-redactor

An Antigravity plugin that automatically detects and redacts API keys, tokens, passwords, and private keys in prompts, sensitive files, and command outputs — while optionally restoring placeholders transparently at execution and disk-write time.

## Features

- **PreInvocation Prompt Guard**: Blocks prompts containing plaintext secrets before they are sent to the model.
- **Sensitive File Redaction (`read_file` / `view_file`)**: Redirects reads of `.env`, `*.key`, `*.pem`, `credentials.json`, and JSON files containing secrets to a redacted copy with deterministic `[REDACTED:LABEL#xxxxxx]` tags.
- **Environment Output Masking (`run_command`)**: Automatically wraps environment-inspection commands (`env`, `printenv`, `export`, `echo $VAR`, etc.) with `--redact-stream` so raw values never enter model context.
- **Transparent Placeholder Restoration (`restorePlaceholders`)**:
  - When `uniqueRedaction` and `restorePlaceholders` are both `true`, `redact.py` stores `tag -> raw_value` in a local `vault.json` (in `$PLUGIN_DATA` or `/tmp/agy-secret-redactor-<uid>`, with `0600` permissions).
  - Before `run_command`, `write_file`, or `edit_file` runs, `PreToolUse` restores any known `[REDACTED:LABEL#xxxxxx]` tags back to the real secret via `overwrite` so commands and files on disk receive the actual values while the model only sees placeholders.

## Configuration (`config.json`)

| Key | Default | Description |
| --- | --- | --- |
| `uniqueRedaction` | `true` | Append a 6-char SHA-256 fingerprint (`[REDACTED:LABEL#xxxxxx]`) |
| `restorePlaceholders` | `true` | Save tag mappings to `vault.json` and restore them in `run_command` / `write_file` / `edit_file` |
| `sensitiveFileMode` | `"redact"` | One of `"redact"`, `"ask"`, `"deny"`, `"allow"` |
| `scanJsonFiles` | `true` | Scan `.json` files for secret-like keys |
| `maskEnvCommands` | `true` | Wrap env-inspection commands with stream redaction |
| `maskAllEnvValues` | `true` | Mask all env values except `safeEnvVars` |
| `disabledLabels` | `[]` | Built-in pattern labels to skip |
| `customPatterns` | `[]` | List of `{"label": "...", "pattern": "..."}` |

## Testing

```bash
python3 -m unittest discover -s tests -v
```
