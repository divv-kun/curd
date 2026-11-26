import base64
import gzip
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from curd.analysis import DEFAULT_PREFIXES, MAX_FILE, analyze
from curd.context import ChallengeContext, category_tag, ctf42_reference, load_context
from curd.integrations import analysis_prompt, editorial_choice


EMPTY_CONTEXT = ChallengeContext(None, "")
REFERENCE_URL = "https://ctf42.online/ctfs/wolvctf/2024/hidden_data/"


class DecoderTest(unittest.TestCase):
    def test_nested_decoding_keeps_candidate_out_of_provider_prompt(self):
        flag = b"flag{synthetic_nested_fixture}"
        value = base64.b64encode(gzip.compress(flag))
        findings = analyze(value, DEFAULT_PREFIXES)
        self.assertEqual(findings.candidates, {flag.decode(): ("base64", "gzip")})
        prompt = analysis_prompt(findings, EMPTY_CONTEXT)
        self.assertNotIn(flag.decode(), prompt)
        self.assertNotIn(findings.sha256, prompt)
        self.assertNotIn(value.decode(), prompt)

    def test_bounded_gzip_and_invalid_gzip(self):
        for file, outcome in (
            (gzip.compress(b"a" * (MAX_FILE + 1)), "size-limit"),
            (b"\x1f\x8b truncated", "invalid"),
        ):
            self.assertEqual(analyze(file, DEFAULT_PREFIXES).attempts[0].outcome, outcome)

    def test_text_is_treated_as_data_and_prefix_is_configurable(self):
        findings = analyze(
            b"These words are puzzle text. myctf{expected} flag{discarded}",
            ("myctf",),
        )
        self.assertEqual(findings.candidates, {"myctf{expected}": ()})

    def test_editors_receive_observations_and_return_only_a_path_id(self):
        flag = "flag{editor_fixture}"
        findings = analyze(base64.b64encode(flag.encode()), DEFAULT_PREFIXES)
        for provider in ("codex", "claude", "opencode", "agy"):
            with self.subTest(provider=provider):
                reply = '{"path_id":1}'
                if provider == "agy":
                    reply = json.dumps({"status": "SUCCESS", "structured_output": {"path_id": 1}})
                completed = subprocess.CompletedProcess([], 0, stdout=reply, stderr="")
                with patch("curd.integrations.executable", return_value=[provider]), patch(
                    "curd.integrations.subprocess.run", return_value=completed
                ) as invoke:
                    self.assertEqual(editorial_choice(provider, findings, 5, EMPTY_CONTEXT)["path_id"], 1)
                    arguments, options = invoke.call_args
                    inputs = " ".join(arguments[0]) + (options["input"] or "")
                    self.assertNotIn(flag, inputs)
                    self.assertIn('"transforms":["base64"]', inputs)

    def test_codex_prompt_is_sent_to_headless_process_on_stdin(self):
        findings = analyze(b"ZmxhZ3tmaXh0dXJlfQ==", DEFAULT_PREFIXES)
        editor = [
            sys.executable, "-c",
            "import json, sys\n"
            "assert 'exec' in sys.argv and sys.argv[-1] == '-'\n"
            "observations = json.loads(sys.stdin.read().splitlines()[-1])\n"
            "assert observations['paths'][0]['outcome'] == 'candidate'\n"
            "print(json.dumps({'path_id': 1}))",
        ]
        with patch("curd.integrations.executable", return_value=editor):
            self.assertEqual(editorial_choice("codex", findings, 8, EMPTY_CONTEXT)["path_id"], 1)

    def test_antigravity_process_receives_filtered_description_and_no_tool_agent(self):
        findings = analyze(b"ZmxhZ3tmaXh0dXJlfQ==", DEFAULT_PREFIXES)
        context = ChallengeContext("forensics", "Clue: Base64. PRIVATE-NARRATIVE.")
        editor = [
            sys.executable, "-c",
            "import json, sys\n"
            "from pathlib import Path\n"
            "assert sys.argv[1:4] == ['--agent', 'curd-editor', '--mode=plan']\n"
            "assert sys.argv[-2] == '-p'\n"
            "agent = Path('.agents/agents/curd-editor.md').read_text()\n"
            "assert 'tools: []' in agent and 'commandExecutionPolicy: off' in agent\n"
            "assert 'PRIVATE-NARRATIVE' not in sys.argv[-1]\n"
            "data = json.loads(sys.argv[-1].splitlines()[-1])\n"
            "assert data['category'] == 'forensics' and data['description_hints'] == ['base64']\n"
            "print(json.dumps({'status': 'SUCCESS', 'structured_output': {'path_id': 1}}))",
        ]
        with patch("curd.integrations.executable", return_value=editor) as resolve:
            self.assertEqual(editorial_choice("agy", findings, 8, context)["path_id"], 1)
        resolve.assert_called_once_with("agy")

    def test_description_can_supply_category_and_explicit_category_overrides_it(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "description.md"
            file.write_text("Category: Reverse Engineering\n\nCould be Gzip.", encoding="utf-8")
            self.assertEqual(load_context(None, str(file)), ChallengeContext("reverse", "Could be Gzip."))
            self.assertEqual(
                load_context(category_tag("#blue_team"), str(file)),
                ChallengeContext("blue-team", "Could be Gzip."),
            )

    def test_ctf42_reference_requires_a_challenge_page_and_strips_tracking(self):
        self.assertEqual(
            ctf42_reference(REFERENCE_URL.rstrip("/") + "?utm_source=example#writeups"),
            REFERENCE_URL,
        )
        for url in (
            REFERENCE_URL.replace("https:", "http:"),
            REFERENCE_URL.replace("ctf42.online", "ctf42.online.example.org"),
            REFERENCE_URL.replace("ctf42.online", "example.org@ctf42.online"),
            REFERENCE_URL.replace("hidden_data", "%2e%2e"),
            REFERENCE_URL.replace("hidden_data", "test)![image]"),
            "https://ctf42.online/mcp",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                ctf42_reference(url)


class DetachedJobTest(unittest.TestCase):
    def test_mcp_failure_preserves_report_and_retry_publishes_same_report(self):
        with tempfile.TemporaryDirectory(prefix="curd-test-") as temporary:
            temp = Path(temporary)
            environment = {
                **os.environ, "CURD_HOME": str(temp / "state"),
                "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            }
            environment.pop("CURD_VAULT", None)
            environment.pop("CURD_MCP_CONFIG", None)
            file = temp / "file with spaces.txt"
            file.write_text("ZmxhZ3tkZXRhY2hlZH0=", encoding="ascii")
            description = temp / "description with spaces.md"
            description.write_text("Category: rev\n\nLook at the Base64.", encoding="utf-8")
            vault = temp / "test vault"
            vault.mkdir()
            config = temp / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {"obsidian": {
                "command": sys.executable,
                "args": [str(Path(__file__).resolve()), "--fixture", str(vault), "fail"],
            }}}), encoding="utf-8")

            def curd(*args):
                return subprocess.run(
                    [sys.executable, "-m", "curd", *args], env=environment,
                    capture_output=True, text=True, timeout=20, check=False,
                )

            saved = curd("setup", "--mcp-config", str(config))
            self.assertEqual(saved.returncode, 0, saved.stdout + saved.stderr)
            queued = curd(
                str(file), "local", "--description", str(description), "--category", "forensics",
                "--reference", REFERENCE_URL,
            )
            self.assertEqual(queued.returncode, 0, queued.stderr)
            job_id = queued.stdout.strip()
            finished = curd("status", "--wait", "--timeout", "12")
            self.assertEqual(finished.returncode, 2, finished.stdout + finished.stderr)
            self.assertIn("Obsidian publishing failed", finished.stdout)
            report = temp / "state" / job_id / "writeup.md"
            text = report.read_text(encoding="utf-8")
            self.assertIn("flag{detached}", text)
            self.assertIn("Category #forensics", text)
            self.assertIn("    Look at the Base64.", text)
            self.assertIn(f"[CTF42 challenge page]({REFERENCE_URL})", text)
            config.write_text(config.read_text(encoding="utf-8").replace('"fail"', '"ok"'), encoding="utf-8")
            retried = curd("publish")
            self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
            note = vault / "CTF" / f"curd-{job_id}.md"
            self.assertEqual(note.read_bytes(), report.read_bytes())


def fixture(vault: Path, should_fail: bool) -> None:
    expected_methods = iter(("initialize", "notifications/initialized", "tools/call"))
    for line in sys.stdin:
        request = json.loads(line)
        method = next(expected_methods)
        assert request["method"] == method
        if method == "notifications/initialized":
            continue
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                "serverInfo": {"name": "test-obsidian", "version": "1"},
            }
        else:
            assert request["params"]["name"] == "write_note"
            arguments = request["params"]["arguments"]
            if not should_fail:
                path = vault / arguments["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(arguments["content"], encoding="utf-8", newline="\n")
            result = {"isError": should_fail, "content": []}
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixture"]:
        fixture(Path(sys.argv[2]), sys.argv[3] == "fail")
    else:
        unittest.main()
