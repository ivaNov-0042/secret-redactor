import json
import os
import subprocess
import sys
import tempfile
import unittest

PLUGIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(PLUGIN_DIR, "scripts")
sys.path.insert(0, SCRIPTS_DIR)

import redact  # noqa: E402


class SecretRedactorVaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_plugin_data = os.environ.get("PLUGIN_DATA")
        os.environ["PLUGIN_DATA"] = self.tmp.name

    def tearDown(self):
        if self.old_plugin_data is None:
            os.environ.pop("PLUGIN_DATA", None)
        else:
            os.environ["PLUGIN_DATA"] = self.old_plugin_data
        self.tmp.cleanup()

    def test_sensitive_file_read_stores_vault_and_restores_on_write_and_edit(self):
        env_path = os.path.join(self.tmp.name, ".env")
        raw_secret = "sk-proj-1234567890abcdefghijklmnop"
        with open(env_path, "w", encoding="utf-8") as f:
            f.write(f"OPENAI_API_KEY={raw_secret}\n")

        cfg = redact.load_config()
        res = redact.handle_pre_tool_use(
            {
                "hookEventName": "PreToolUse",
                "toolCall": {"name": "read_file", "args": {"Path": env_path}},
            },
            cfg,
        )
        self.assertEqual(res["decision"], "allow")
        cache_path = res["overwrite"]["Path"]
        with open(cache_path, "r", encoding="utf-8") as f:
            redacted_content = f.read()

        self.assertNotIn(raw_secret, redacted_content)
        self.assertIn("[REDACTED:API_KEY#", redacted_content)

        tag = redacted_content.strip().split("=", 1)[1]
        vault_path = redact.get_vault_path()
        self.assertTrue(os.path.isfile(vault_path))
        self.assertEqual(os.stat(vault_path).st_mode & 0o777, 0o600)

        # write_file with placeholder should restore real secret in overwrite.Content
        write_res = redact.handle_pre_tool_use(
            {
                "hookEventName": "PreToolUse",
                "toolCall": {
                    "name": "write_file",
                    "args": {"Path": env_path, "Content": f"OPENAI_API_KEY={tag}\nDEBUG=1\n"},
                },
            },
            cfg,
        )
        self.assertEqual(write_res["decision"], "allow")
        self.assertEqual(
            write_res["overwrite"]["Content"],
            f"OPENAI_API_KEY={raw_secret}\nDEBUG=1\n",
        )

        # edit_file with placeholder in Target and Replacement should restore both
        edit_res = redact.handle_pre_tool_use(
            {
                "hookEventName": "PreToolUse",
                "toolCall": {
                    "name": "edit_file",
                    "args": {
                        "Path": env_path,
                        "Target": f"OPENAI_API_KEY={tag}",
                        "Replacement": f"BACKUP_KEY={tag}",
                    },
                },
            },
            cfg,
        )
        self.assertEqual(edit_res["overwrite"]["Target"], f"OPENAI_API_KEY={raw_secret}")
        self.assertEqual(edit_res["overwrite"]["Replacement"], f"BACKUP_KEY={raw_secret}")

    def test_run_command_restores_placeholder_and_stream_mode_saves_vault(self):
        cfg = redact.load_config()
        updates = {}
        line = redact.redact_stream_line(
            "MY_TOKEN=ghp_1234567890123456789012345678901234\n",
            cfg,
            vault_updates=updates,
        )
        redact.save_vault_entries(updates)
        tag = line.strip().split("=", 1)[1]
        self.assertTrue(tag.startswith("[REDACTED:GITHUB_TOKEN#"))

        cmd_res = redact.handle_pre_tool_use(
            {
                "hookEventName": "PreToolUse",
                "toolCall": {
                    "name": "run_command",
                    "args": {"CommandLine": f"curl -H 'Authorization: Bearer {tag}' https://example.com"},
                },
            },
            cfg,
        )
        self.assertEqual(
            cmd_res["overwrite"]["CommandLine"],
            "curl -H 'Authorization: Bearer ghp_1234567890123456789012345678901234' https://example.com",
        )

    def test_multiline_private_key_restore(self):
        raw_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIBOgIBAAJBALe7testkeyline1\n"
            "MIIBOgIBAAJBALe7testkeyline2\n"
            "-----END RSA PRIVATE KEY-----"
        )
        updates = {}
        redacted, matched = redact.redact_text(raw_key, unique=True, vault_updates=updates)
        self.assertIn("PRIVATE_KEY", matched)
        self.assertIn("\n[REDACTED]\n", redacted)

        restored, count = redact.restore_placeholders(redacted, updates)
        self.assertEqual(count, 1)
        self.assertEqual(restored, raw_key)

    def test_cli_hook_roundtrip(self):
        vault_updates = {}
        raw = "AIzaSyDummyGoogleApiKey1234567890123456"
        redacted, matched = redact.redact_text(raw, unique=True, vault_updates=vault_updates)
        self.assertTrue(matched)
        redact.save_vault_entries(vault_updates)

        payload = {
            "hookEventName": "PreToolUse",
            "toolCall": {
                "name": "write_file",
                "args": {"Path": "/tmp/out.txt", "Content": f"key={redacted}\n"},
            },
        }
        proc = subprocess.run(
            [sys.executable, os.path.join(SCRIPTS_DIR, "redact.py")],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
        )
        out = json.loads(proc.stdout)
        self.assertEqual(out["overwrite"]["Content"], f"key={raw}\n")


if __name__ == "__main__":
    unittest.main()
