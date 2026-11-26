import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import __version__
from .analysis import Findings
from .context import ChallengeContext


NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
NPM_PACKAGES = {
    "codex": "@openai/codex",
    "claude": "@anthropic-ai/claude-code",
    "opencode": "@opencode/cli",
    "mcpvault": "@bitbonsai/mcpvault",
}
MAX_RESPONSE = 256 * 1024


def executable(command: str) -> list[str]:
    if os.name != "nt":
        native = shutil.which(command)
        if native:
            return [native]
    else:
        native = shutil.which(command if Path(command).suffix else command + ".exe")
        if native and Path(native).suffix.lower() in (".exe", ".com"):
            return [native]
        if command in NPM_PACKAGES:
            shim = shutil.which(command + ".cmd")
            if shim:
                package = Path(shim).parent / "node_modules" / NPM_PACKAGES[command]
                with (package / "package.json").open(encoding="utf-8") as file:
                    bin_entry = json.load(file)["bin"]
                entry = package / (bin_entry[command] if isinstance(bin_entry, dict) else bin_entry)
                if entry.suffix.lower() == ".exe":
                    return [str(entry)]
                return [*executable("node"), str(entry)]
    raise FileNotFoundError(f"Executable unavailable: {command}")


def analysis_prompt(findings: Findings, context: ChallengeContext) -> str:
    observations = {
        **context.editor_metadata(),
        "initial_format": findings.initial_format,
        "direct_candidate": () in findings.candidates.values(),
        "paths": [
            {"id": index, "transforms": attempt.path, "outcome": attempt.outcome}
            for index, attempt in enumerate(findings.attempts[:20], 1)
        ],
    }
    return (
        "You are an editor for a writeup of an offline data-decoding puzzle. "
        "Based only on the structured observations below, pick the one investigated "
        "path most worth highlighting to a reader. The category is a reporting tag. "
        "Description hints name possible encodings and are only useful when they match "
        "an observed path. Prefer a path that produced a "
        "candidate. A failed or ambiguous path can be useful if no path succeeded. "
        "Return only a JSON object with the integer field path_id, using 0 if the "
        "paths list is empty. This is an editorial choice. Use no tools.\n"
        + json.dumps(observations, separators=(",", ":"))
    )


def provider_arguments(provider: str, folder: Path, prompt: str) -> tuple[list[str], str | None]:
    if provider == "codex":
        return [
            "--ask-for-approval", "never", "exec", "--skip-git-repo-check", "--sandbox", "read-only",
            "--ignore-user-config", "--color", "never",
            "-c", "features.shell_tool=false", "-c", "features.unified_exec=false",
            "-c", 'web_search="disabled"', "-",
        ], prompt
    if provider == "claude":
        mcp = folder / "no-mcp.json"
        mcp.write_text('{"mcpServers":{}}', encoding="utf-8")
        return [
            "-p", "--safe-mode", "--tools", "", "--strict-mcp-config", "--mcp-config", str(mcp),
            "--setting-sources", "", "--output-format", "text",
        ], prompt
    if provider == "opencode":
        config = {
            "update": "disable",
            "policies": [
                {"action": action, "resource": "*", "effect": "deny"}
                for action in ("tool.use", "mcp.use", "skill.use", "plugin.use", "websearch.use")
            ],
        }
        (folder / "opencode.json").write_text(json.dumps(config), encoding="utf-8")
        return ["--standalone", "run", "--format", "default", prompt], None
    if provider != "agy":
        raise ValueError("Unknown editor.")
    agent = folder / ".agents" / "agents" / "curd-editor.md"
    agent.parent.mkdir(parents=True)
    agent.write_text(
        "---\n"
        "name: curd-editor\n"
        "description: Select an already-observed decoding path for a writeup.\n"
        "mainAgent: true\n"
        "subagent: false\n"
        "tools: []\n"
        "commandExecutionPolicy: off\n"
        "mcpServers: []\n"
        "skills: []\n"
        "plugins: []\n"
        "---\n"
        "Review the supplied decoding observations. Return only the requested path ID.\n",
        encoding="utf-8",
    )
    schema = folder / "choice.json"
    schema.write_text(json.dumps({
        "type": "object",
        "properties": {"path_id": {"type": "integer"}},
        "required": ["path_id"],
        "additionalProperties": False,
    }), encoding="utf-8")
    return [
        "--agent", "curd-editor", "--mode=plan", "--disable-slash-commands",
        "--output-format", "json", "--json-schema", str(schema), "-p", prompt,
    ], None


def editorial_choice(provider: str, findings: Findings, timeout: int, context: ChallengeContext) -> dict:
    result = {"provider": provider}
    try:
        command = executable(provider)
        with tempfile.TemporaryDirectory(prefix="curd-editor-") as temp:
            folder = Path(temp)
            args, prompt_input = provider_arguments(provider, folder, analysis_prompt(findings, context))
            completed = subprocess.run(
                [*command, *args],
                cwd=folder,
                input=prompt_input,
                stdin=subprocess.DEVNULL if prompt_input is None else None,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=NO_WINDOW,
                check=False,
            )
        if completed.returncode:
            result["status"] = f"CLI exited with code {completed.returncode}"
            diagnostic = classify_provider_error(completed.stderr + completed.stdout)
            if diagnostic:
                result["status"] += f" ({diagnostic})"
            return result
        output = completed.stdout.strip()
        if provider == "agy":
            envelope = json.loads(output)
            if envelope.get("status") != "SUCCESS":
                raise ValueError("Antigravity did not return a successful response.")
            choice = envelope["structured_output"]["path_id"]
        else:
            if block := re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", output, re.DOTALL):
                output = block.group(1)
            choice = json.loads(output)["path_id"]
        limit = min(20, len(findings.attempts))
        if type(choice) is not int or choice not in (range(1, limit + 1) if limit else range(1)):
            raise ValueError("invalid path selection")
        return {**result, "status": "ok", "path_id": choice}
    except subprocess.TimeoutExpired:
        result["status"] = "timed out"
    except FileNotFoundError:
        result["status"] = "CLI executable unavailable"
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        result["status"] = "CLI failed or returned an invalid selection"
    return result


def classify_provider_error(output: str) -> str:
    for pattern, label in (
        (r"not logged in|login required|please (?:run|log in|sign in)|set an auth method|api[_ ]key|unauthenticated|unauthorized|missing credentials", "check CLI authentication"),
        (r"unknown argument|unknown option|unexpected argument|unrecognized option", "check CLI version"),
        (r"quota|rate.limit|too many requests|usage limit", "check provider limits"),
        (r"network|connection|failed to connect|could not resolve", "check connectivity"),
    ):
        if re.search(pattern, output, re.IGNORECASE):
            return label
    return ""


def mcp_settings(vault: str | None, config: str | None) -> tuple[list[str], dict[str, str]]:
    if vault:
        folder = Path(vault)
        if not folder.is_dir():
            raise ValueError("The Obsidian vault directory does not exist.")
        return [*executable("mcpvault"), str(folder)], {}
    try:
        server = json.loads(Path(config).read_text(encoding="utf-8-sig"))["mcpServers"]["obsidian"]
        command = server["command"]
        args = server.get("args", [])
        env = server.get("env", {})
        if (
            server.get("type", "stdio") != "stdio"
            or not isinstance(command, str)
            or not isinstance(args, list)
            or not all(isinstance(arg, str) for arg in args)
            or not isinstance(env, dict)
            or not all(isinstance(value, str) for value in env.values())
        ):
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ValueError("Expected a stdio server at mcpServers.obsidian in the MCP configuration.") from None
    return [*executable(command), *args], env


class McpSession:
    def __init__(self, process: asyncio.subprocess.Process):
        self.process = process
        self.next_id = 0

    async def send(self, message: dict) -> None:
        data = json.dumps({"jsonrpc": "2.0", **message}, ensure_ascii=True)
        self.process.stdin.write((data + "\n").encode("utf-8"))
        await self.process.stdin.drain()

    async def request(self, method: str, params: dict) -> dict:
        self.next_id += 1
        await self.send({"id": self.next_id, "method": method, "params": params})
        while line := await self.process.stdout.readline():
            message = json.loads(line)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise ValueError("Invalid MCP response.")
            if "method" in message and "id" in message:
                await self.send({
                    "id": message["id"],
                    "error": {"code": -32601, "message": "Method not supported"},
                })
                continue
            if message.get("id") != self.next_id:
                continue
            if "error" in message or not isinstance(message.get("result"), dict):
                raise ValueError(f"MCP server rejected {method}.")
            return message["result"]
        raise ValueError(f"MCP server disconnected during {method}.")

    async def write_note(self, path: str, markdown: str) -> None:
        initialized = await self.request("initialize", {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "curd", "version": __version__},
        })
        if initialized.get("protocolVersion") not in {
            "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25",
        } or "tools" not in initialized.get("capabilities", {}):
            raise ValueError("MCP server must support legacy stdio and tools.")
        await self.send({"method": "notifications/initialized"})
        result = await self.request("tools/call", {
            "name": "write_note",
            "arguments": {"path": path, "content": markdown},
        })
        if result.get("isError"):
            raise ValueError("Obsidian MCP write_note failed.")


async def publish_note(vault: str | None, config: str | None, path: str, markdown: str) -> None:
    command, env = mcp_settings(vault, config)
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        limit=MAX_RESPONSE,
        creationflags=NO_WINDOW,
        env={**os.environ, **env},
    )
    try:
        await asyncio.wait_for(McpSession(process).write_note(path, markdown), timeout=30)
    finally:
        process.stdin.close()
        try:
            await asyncio.wait_for(process.communicate(), timeout=2)
        except asyncio.TimeoutError:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.communicate()
