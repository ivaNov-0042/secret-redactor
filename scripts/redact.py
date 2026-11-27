#!/usr/bin/env python3
"""Antigravity secret-redactor hook script and stream redactor.

Handles:
- PreInvocation: Blocks prompts containing plaintext secrets before they reach the model.
- PreToolUse:
  - run_command: Redacts matched secrets in CommandLine via `overwrite`, and wraps
    environment-inspection commands so their stdout values are masked with unique tags.
  - read_file / view_file: Handles sensitive files according to `sensitiveFileMode`
    in config.json ("redact" | "ask" | "deny" | "allow").
- --redact-stream / --redact-all-lines: CLI stream mode used to mask env output.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
from typing import Callable

SCRIPT_PATH = os.path.abspath(__file__)
PLUGIN_DIR = os.path.dirname(os.path.dirname(SCRIPT_PATH))

DEFAULT_CONFIG = {
    "uniqueRedaction": True,
    "restorePlaceholders": True,
    "sensitiveFileMode": "redact",
    "scanJsonFiles": True,
    "disabledLabels": [],
    "customPatterns": [],
    "maskEnvCommands": True,
    "maskAllEnvValues": True,
    "safeEnvVars": [],
    "sensitiveFiles": [
        ".env",
        ".env.*",
        "*.env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "credentials.json",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
    ],
    "safeEnvSuffixes": [".example", ".sample", ".template", ".dist"],
}


TAG_BLOCK_RE = re.compile(r"(\[REDACTED:[A-Z0-9_]+#[0-9a-f]{6}\])((?:\r?\n\[REDACTED\])*)")


def get_data_dir() -> str:
    """Return the plugin's private data directory with 0700 permissions."""
    base_dir = os.environ.get("PLUGIN_DATA") or os.path.join(
        tempfile.gettempdir(), f"agy-secret-redactor-{os.getuid()}"
    )
    os.makedirs(base_dir, mode=0o700, exist_ok=True)
    return base_dir


def get_vault_path() -> str:
    """Return the path to the local tag->secret vault file."""
    return os.path.join(get_data_dir(), "vault.json")


def load_vault() -> dict[str, str]:
    """Load the tag->secret mapping from vault.json."""
    path = get_vault_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_vault_entries(entries: dict[str, str]) -> None:
    """Merge new tag->secret mappings into vault.json atomically with 0600 permissions."""
    if not entries:
        return
    vault = load_vault()
    changed = False
    for k, v in entries.items():
        if vault.get(k) != v:
            vault[k] = v
            changed = True
    if not changed:
        return

    vault_path = get_vault_path()
    data_dir = os.path.dirname(vault_path)
    fd, tmp_path = tempfile.mkstemp(prefix=".vault-", suffix=".tmp", dir=data_dir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(vault, f, ensure_ascii=False)
        os.replace(tmp_path, vault_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def restore_placeholders(text: str, vault: dict[str, str]) -> tuple[str, int]:
    """Restore [REDACTED:LABEL#xxxxxx] placeholders in text using vault.

    Returns (restored_text, restored_count).
    """
    if not text or not vault or "[REDACTED:" not in text:
        return text, 0

    count = 0

    def _replace(m: re.Match[str]) -> str:
        nonlocal count
        tag = m.group(1)
        cont = m.group(2)
        if tag not in vault:
            return m.group(0)
        raw = vault[tag]
        count += 1
        if not cont:
            return raw
        raw_line_count = len(raw.splitlines())
        if raw_line_count <= 1:
            return raw + cont
        cont_tokens = re.findall(r"\r?\n\[REDACTED\]", cont)
        consumed = min(len(cont_tokens), raw_line_count - 1)
        return raw + "".join(cont_tokens[consumed:])

    return TAG_BLOCK_RE.sub(_replace, text), count


def make_tag(
    label: str,
    raw_value: str,
    unique: bool,
    vault_updates: dict[str, str] | None = None,
) -> str:
    """Build a redaction tag, optionally with a deterministic 6-char SHA-256 fingerprint."""
    if not unique or not raw_value:
        return f"[REDACTED:{label}]"
    fp = hashlib.sha256(raw_value.encode("utf-8", errors="replace")).hexdigest()[:6]
    tag = f"[REDACTED:{label}#{fp}]"
    if vault_updates is not None:
        vault_updates[tag] = raw_value
    return tag


def _redact_multiline_block(
    m: re.Match[str],
    label: str,
    unique: bool,
    vault_updates: dict[str, str] | None = None,
) -> str:
    """Replace a multi-line secret while preserving line count."""
    raw = m.group(0)
    tag = make_tag(label, raw, unique, vault_updates=vault_updates)
    lines = raw.splitlines()
    if len(lines) <= 1:
        return tag
    return "\n".join([tag] + ["[REDACTED]" for _ in range(len(lines) - 1)])


SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Callable[[re.Match[str], bool, dict[str, str] | None], str]]] = [
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        lambda m, u, vu: _redact_multiline_block(m, "PRIVATE_KEY", u, vu),
    ),
    (
        "PUTTY_PRIVATE_KEY",
        re.compile(r"PuTTY-User-Key-File-\d+:[\s\S]*?Private-MAC:\s*[0-9a-fA-F]+"),
        lambda m, u, vu: _redact_multiline_block(m, "PRIVATE_KEY", u, vu),
    ),
    (
        "API_KEY",
        re.compile(r"\bsk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{20,}\b"),
        lambda m, u, vu: make_tag("API_KEY", m.group(0), u, vu),
    ),
    (
        "GITHUB_TOKEN",
        re.compile(
            r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b"
        ),
        lambda m, u, vu: make_tag("GITHUB_TOKEN", m.group(0), u, vu),
    ),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        lambda m, u, vu: make_tag("GOOGLE_API_KEY", m.group(0), u, vu),
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        lambda m, u, vu: make_tag("AWS_ACCESS_KEY", m.group(0), u, vu),
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        lambda m, u, vu: make_tag("SLACK_TOKEN", m.group(0), u, vu),
    ),
    (
        "STRIPE_KEY",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b"),
        lambda m, u, vu: make_tag("STRIPE_KEY", m.group(0), u, vu),
    ),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        lambda m, u, vu: make_tag("JWT", m.group(0), u, vu),
    ),
    (
        "DB_URI_PASSWORD",
        re.compile(
            r"(?i)\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/\"']+:)(?!\[REDACTED:)([^\s@\"']+)@"
        ),
        lambda m, u, vu: f"{m.group(1)}{make_tag('DB_PASS', m.group(2), u, vu)}@",
    ),
    (
        "AUTH_TOKEN",
        re.compile(r"(?i)\b((?:Bearer|Basic)\s+)(?!\[REDACTED:)([A-Za-z0-9._~+/-]{16,}=*)"),
        lambda m, u, vu: f"{m.group(1)}{make_tag('AUTH_TOKEN', m.group(2), u, vu)}",
    ),
    (
        "CN_ID_CARD",
        re.compile(
            r"(?<![0-9A-Za-z])[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx](?![0-9A-Za-z])"
        ),
        lambda m, u, vu: make_tag("CN_ID_CARD", m.group(0), u, vu),
    ),
    (
        "BASE64_DATA",
        re.compile(
            r"(?i)(base64[,:]\s*)(?!\[REDACTED:)([A-Za-z0-9+/]{24,}={0,2})"
        ),
        lambda m, u, vu: f"{m.group(1)}{make_tag('BASE64', m.group(2), u, vu)}",
    ),
    (
        "BASE64_STRING",
        re.compile(
            r"(?<![A-Za-z0-9+/=_-])(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])(?=[A-Za-z0-9+/]*[0-9])(?:[A-Za-z0-9+/]{22,}={1,2}|[A-Za-z0-9/]*\+[A-Za-z0-9+/]{16,}={0,2}|(?:[A-Za-z0-9+/]{4}){8,})(?![A-Za-z0-9+/=_-])"
        ),
        lambda m, u, vu: make_tag("BASE64", m.group(0), u, vu),
    ),
    (
        "SECRET",
        re.compile(
            r"(?i)(\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)\s*[:=]\s*[\"']?)(?!\[REDACTED:)([^\s\"']{12,})([\"']?)"
        ),
        lambda m, u, vu: f"{m.group(1)}{make_tag('SECRET', m.group(2), u, vu)}{m.group(3)}",
    ),
]

# Sensitive variable assignment in .env / config files
SENSITIVE_ENV_ASSIGN_RE = re.compile(
    r"(?im)^(\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASS|PASSWORD|PWD|AUTH|CREDENTIAL|PRIVATE)[A-Z0-9_]*\s*=\s*[\"']?)(?!\[REDACTED:)([^\s\"'#]+)([\"']?)"
)

# Sensitive key-value pairs in JSON files (e.g., "apiKey": "...", "client_secret": "...")
JSON_SECRET_VALUE_RE = re.compile(
    r'(?i)("(?:[A-Za-z0-9_]*(?:key|secret|token|password|passwd|pwd|credential|private_?key))"\s*:\s*")((?!\[REDACTED:)[^"\n]{4,})(")'
)

# General KEY=VALUE line (used when masking env command output)
GENERAL_ENV_LINE_RE = re.compile(
    r"^(?P<prefix>\s*(?:export\s+|declare\s+-x\s+)?)(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<val>.*)$"
)


def load_config() -> dict:
    """Load config from PLUGIN_DIR/config.json and PLUGIN_DATA/config.json, with env override."""
    cfg = dict(DEFAULT_CONFIG)
    candidates = [os.path.join(PLUGIN_DIR, "config.json")]
    plugin_data = os.environ.get("PLUGIN_DATA")
    if plugin_data:
        candidates.append(os.path.join(plugin_data, "config.json"))

    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    cfg.update(loaded)
            except (OSError, json.JSONDecodeError):
                pass

    env_mode = os.environ.get("SECRET_REDACTOR_SENSITIVE_FILE_MODE")
    if env_mode in {"redact", "ask", "deny", "allow"}:
        cfg["sensitiveFileMode"] = env_mode

    return cfg


def redact_text(
    text: str,
    *,
    is_sensitive_file: bool = False,
    is_json_file: bool = False,
    unique: bool = True,
    custom_patterns: list[dict] | None = None,
    disabled_labels: set[str] | None = None,
    vault_updates: dict[str, str] | None = None,
) -> tuple[str, list[str]]:
    """Return (redacted_text, matched_labels)."""
    if not text:
        return text, []

    disabled = {lbl.upper() for lbl in (disabled_labels or set())}
    redacted = text
    matched: list[str] = []
    for label, pattern, repl in SECRET_PATTERNS:
        if label.upper() in disabled:
            continue
        if pattern.search(redacted):
            redacted = pattern.sub(lambda m, r=repl: r(m, unique, vault_updates), redacted)
            matched.append(label)

    for entry in custom_patterns or []:
        if not isinstance(entry, dict):
            continue
        pat_str = entry.get("pattern")
        if not pat_str:
            continue
        label = str(entry.get("label") or "CUSTOM").upper()
        try:
            compiled = re.compile(pat_str)
        except re.error:
            continue
        if compiled.search(redacted):
            redacted = compiled.sub(
                lambda m, lbl=label: make_tag(lbl, m.group(0), unique, vault_updates), redacted
            )
            if label not in matched:
                matched.append(label)

    if is_sensitive_file and SENSITIVE_ENV_ASSIGN_RE.search(redacted):
        redacted = SENSITIVE_ENV_ASSIGN_RE.sub(
            lambda m: f"{m.group(1)}{make_tag('ENV_SECRET', m.group(2), unique, vault_updates)}{m.group(3)}",
            redacted,
        )
        if "ENV_SECRET" not in matched:
            matched.append("ENV_SECRET")

    if is_json_file and JSON_SECRET_VALUE_RE.search(redacted):
        redacted = JSON_SECRET_VALUE_RE.sub(
            lambda m: f"{m.group(1)}{make_tag('JSON_SECRET', m.group(2), unique, vault_updates)}{m.group(3)}",
            redacted,
        )
        if "JSON_SECRET" not in matched:
            matched.append("JSON_SECRET")

    return redacted, matched


def redact_single_value(
    value: str,
    unique: bool,
    vault_updates: dict[str, str] | None = None,
) -> str:
    """Mask a single environment variable value, preserving specific secret label if matched."""
    stripped = value.strip()
    if not stripped or stripped.startswith("[REDACTED:"):
        return value
    unquoted = stripped
    if len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in {"'", '"'}:
        unquoted = unquoted[1:-1]

    redacted, matched = redact_text(unquoted, unique=unique, vault_updates=vault_updates)
    if matched and redacted != unquoted:
        return redacted
    return make_tag("ENV", unquoted, unique, vault_updates)


def redact_stream_line(
    line: str,
    cfg: dict,
    redact_all_lines: bool = False,
    vault_updates: dict[str, str] | None = None,
) -> str:
    """Mask environment variable values in a single stdout line."""
    unique = bool(cfg.get("uniqueRedaction", True))
    mask_all = bool(cfg.get("maskAllEnvValues", True))
    safe_vars = set(cfg.get("safeEnvVars", []))

    newline = "\n" if line.endswith("\n") else ""
    body = line[:-1] if newline else line

    m = GENERAL_ENV_LINE_RE.match(body)
    if m:
        key = m.group("key")
        val = m.group("val")
        if key in safe_vars:
            return line
        if mask_all:
            return f"{m.group('prefix')}{key}={redact_single_value(val, unique, vault_updates)}{newline}"
        redacted_line, _ = redact_text(
            body, is_sensitive_file=True, unique=unique, vault_updates=vault_updates
        )
        return f"{redacted_line}{newline}"

    if redact_all_lines and body.strip():
        return f"{redact_single_value(body, unique, vault_updates)}{newline}"

    redacted_body, _ = redact_text(body, unique=unique, vault_updates=vault_updates)
    return f"{redacted_body}{newline}"


def detect_env_command(cmd: str) -> tuple[bool, bool]:
    """Return (is_env_command, redact_all_lines).

    Detects commands that inspect environment variables:
    - env (dumping env, not `env VAR=val cmd`)
    - printenv [VAR]
    - export / export -p (without `=`)
    - declare -x / typeset -x (without `=`)
    - echo / printf referencing $VAR or ${VAR}
    - inline os.environ / process.env
    """
    if not cmd or "--redact-stream" in cmd:
        return False, False

    stripped = cmd.strip()
    # Split pipeline / chained segments to inspect the leading command
    first_seg = re.split(r"\s*(?:\|\||&&|\||;)\s*", stripped, maxsplit=1)[0].strip()

    # printenv with specific variable name outputs raw value without KEY=
    m_printenv = re.match(r"^printenv\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", first_seg)
    if m_printenv:
        return True, True

    if re.match(r"^(?:printenv|env)\b", first_seg):
        # Exclude `env KEY=VAL command...` unless it's just `env` with flags
        tokens = first_seg.split()[1:]
        has_subcmd = any(not t.startswith("-") and "=" not in t for t in tokens)
        if first_seg.startswith("printenv") or not has_subcmd:
            return True, False

    if re.match(r"^(?:export|declare\s+-x|typeset\s+-x)\b", first_seg) and "=" not in first_seg:
        return True, False

    # echo/printf expanding $VAR (outside single quotes)
    if re.match(r"^(?:echo|printf)\b", first_seg) and re.search(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})", first_seg):
        return True, True

    if re.search(r"\b(?:os\.environ|process\.env)\b", stripped):
        return True, False

    return False, False


def is_sensitive_path(path: str, cfg: dict) -> bool:
    """Return True if path matches configured sensitive file patterns."""
    if not path:
        return False
    basename = os.path.basename(path).lower()
    safe_suffixes = tuple(s.lower() for s in cfg.get("safeEnvSuffixes", []))
    if safe_suffixes and basename.endswith(safe_suffixes):
        return False

    patterns = [p.lower() for p in cfg.get("sensitiveFiles", [])]
    return any(fnmatch.fnmatch(basename, pat) for pat in patterns)


def write_redacted_copy(original_path: str, redacted_content: str) -> str:
    """Write redacted content to a deterministic cache file and return its path."""
    cache_dir = os.path.join(get_data_dir(), "redacted_cache")
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)

    digest = hashlib.sha256(os.path.abspath(original_path).encode("utf-8")).hexdigest()[:16]
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(original_path))
    target_path = os.path.join(cache_dir, f"{digest}_{safe_name}")

    with open(target_path, "w", encoding="utf-8") as f:
        f.write(redacted_content)
    return target_path


def handle_pre_invocation(payload: dict, cfg: dict) -> dict:
    user_input = payload.get("lastUserInput", "")
    unique = bool(cfg.get("uniqueRedaction", True))
    _, matched = redact_text(
        user_input,
        unique=unique,
        custom_patterns=cfg.get("customPatterns"),
        disabled_labels=set(cfg.get("disabledLabels", [])),
    )
    if not matched:
        return {"terminationBehavior": ""}

    labels = ", ".join(matched)
    return {
        "injectSteps": [
            {
                "errorMessage": {
                    "userMessage": (
                        f"安全拦截：检测到输入中包含敏感密钥 ({labels})，"
                        "已终止发送给模型，请打码后重试。"
                    )
                }
            }
        ],
        "terminationBehavior": "terminate",
    }


def handle_sensitive_file_read(path: str, cfg: dict, *, json_scan_only: bool = False) -> dict:
    mode = cfg.get("sensitiveFileMode", "redact")
    unique = bool(cfg.get("uniqueRedaction", True))
    basename = os.path.basename(path)
    is_json = basename.lower().endswith(".json")

    if not json_scan_only:
        if mode == "allow":
            return {"decision": "allow"}
        if mode == "deny":
            return {
                "decision": "deny",
                "reason": f"安全策略禁止读取敏感文件 ({basename})。",
            }
        if mode == "ask":
            return {
                "decision": "ask",
                "reason": f"目标文件 ({basename}) 可能包含明文密钥，读取后内容将进入对话上下文。",
            }

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        if json_scan_only:
            return {"decision": "allow"}
        return {
            "decision": "ask",
            "reason": f"目标文件 ({basename}) 为敏感文件且无法自动脱敏读取，请确认是否继续。",
        }

    vault_updates: dict[str, str] = {}
    redacted_content, matched = redact_text(
        content,
        is_sensitive_file=not json_scan_only,
        is_json_file=is_json,
        unique=unique,
        custom_patterns=cfg.get("customPatterns"),
        disabled_labels=set(cfg.get("disabledLabels", [])),
        vault_updates=vault_updates,
    )
    if not matched:
        return {"decision": "allow"}

    if cfg.get("restorePlaceholders", True) and vault_updates:
        save_vault_entries(vault_updates)

    cache_path = write_redacted_copy(path, redacted_content)
    labels = ", ".join(matched)
    return {
        "decision": "allow",
        "reason": f"已按默认脱敏设置对 {basename} 中的密钥 ({labels}) 自动打码，并重定向至脱敏副本。",
        "overwrite": {"Path": cache_path},
    }


def handle_pre_tool_use(payload: dict, cfg: dict) -> dict:
    tool_call = payload.get("toolCall", {})
    tool_name = tool_call.get("name", "")
    args = tool_call.get("args", {}) or {}
    unique = bool(cfg.get("uniqueRedaction", True))

    if tool_name == "run_command":
        cmd = args.get("CommandLine", "")
        vault_updates: dict[str, str] = {}
        redacted_cmd, matched = redact_text(
            cmd,
            unique=unique,
            custom_patterns=cfg.get("customPatterns"),
            disabled_labels=set(cfg.get("disabledLabels", [])),
            vault_updates=vault_updates,
        )
        reasons: list[str] = []
        changed = False

        if matched:
            if cfg.get("restorePlaceholders", True) and vault_updates:
                save_vault_entries(vault_updates)
            reasons.append(f"已自动打码命令行中的敏感密钥 ({', '.join(matched)})")
            changed = True

        if cfg.get("restorePlaceholders", True) and "[REDACTED:" in redacted_cmd:
            vault = load_vault()
            restored_cmd, restored_count = restore_placeholders(redacted_cmd, vault)
            if restored_count > 0:
                redacted_cmd = restored_cmd
                reasons.append(f"已还原 {restored_count} 处脱敏占位符用于实际执行")
                changed = True

        if cfg.get("maskEnvCommands", True):
            is_env_cmd, redact_all_lines = detect_env_command(redacted_cmd)
            if is_env_cmd:
                flag = "--redact-stream --redact-all-lines" if redact_all_lines else "--redact-stream"
                redacted_cmd = f"({redacted_cmd}) | {shlex.quote(sys.executable)} {shlex.quote(SCRIPT_PATH)} {flag}"
                reasons.append("已开启环境变量输出默认脱敏")
                changed = True

        if changed:
            return {
                "decision": "allow",
                "reason": "；".join(reasons),
                "overwrite": {"CommandLine": redacted_cmd},
            }
        return {"decision": "allow"}

    if tool_name in {"write_file", "edit_file"}:
        if not cfg.get("restorePlaceholders", True):
            return {"decision": "allow"}

        fields = ("Content",) if tool_name == "write_file" else ("Target", "Replacement")
        vault = load_vault()
        overwrite: dict[str, str] = {}
        total_restored = 0
        for field in fields:
            val = args.get(field, "")
            if isinstance(val, str) and "[REDACTED:" in val:
                restored_val, count = restore_placeholders(val, vault)
                if count > 0:
                    overwrite[field] = restored_val
                    total_restored += count

        if overwrite:
            return {
                "decision": "allow",
                "reason": f"已将 {total_restored} 处脱敏占位符还原为真实密文并写入文件。",
                "overwrite": overwrite,
            }
        return {"decision": "allow"}

    if tool_name in {"read_file", "view_file"}:
        path = args.get("Path", "")
        if is_sensitive_path(path, cfg):
            return handle_sensitive_file_read(path, cfg, json_scan_only=False)
        if cfg.get("scanJsonFiles", True) and path.lower().endswith(".json"):
            return handle_sensitive_file_read(path, cfg, json_scan_only=True)
        return {"decision": "allow"}

    return {"decision": "allow"}


def run_stream_mode(redact_all_lines: bool) -> int:
    cfg = load_config()
    store_vault = bool(cfg.get("restorePlaceholders", True))
    vault_updates: dict[str, str] = {}
    for line in sys.stdin:
        sys.stdout.write(
            redact_stream_line(
                line,
                cfg,
                redact_all_lines=redact_all_lines,
                vault_updates=vault_updates if store_vault else None,
            )
        )
    sys.stdout.flush()
    if store_vault and vault_updates:
        save_vault_entries(vault_updates)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--redact-stream", action="store_true")
    parser.add_argument("--redact-all-lines", action="store_true")
    known, _ = parser.parse_known_args()

    if known.redact_stream:
        return run_stream_mode(redact_all_lines=known.redact_all_lines)

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        json.dump({}, sys.stdout)
        return 0

    cfg = load_config()
    event = payload.get("hookEventName", "")
    if event == "PreInvocation":
        result = handle_pre_invocation(payload, cfg)
    elif event == "PreToolUse":
        result = handle_pre_tool_use(payload, cfg)
    else:
        result = {}

    json.dump(result, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
