import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .analysis import DEFAULT_PREFIXES, MAX_FILE, METHODS, Findings, analyze, read_local_file
from .context import ChallengeContext, category_tag, load_context
from .integrations import publish_note, editorial_choice


ALIASES = {
    "co": "codex", "codex": "codex", "cl": "claude", "claude": "claude",
    "oc": "opencode", "opencode": "opencode",
    "agy": "agy", "antigravity": "agy", "ge": "agy", "gemini": "agy",
    "local": "local",
}
TERMINAL_STATES = {"complete", "failed"}
JOB_ID = re.compile(r"[0-9a-f]{32}")
OUTCOMES = {
    "candidate": "I found at least one candidate flag.",
    "text": "I got readable text with no matching flag.",
    "binary": "I got bytes that did not read as UTF-8 text.",
    "invalid": "The decoder rejected the input.",
    "size-limit": "The decoded output exceeded my 1 MiB limit.",
}
INITIAL_FORMATS = {
    "text": "The file read as UTF-8 text, so I looked for a flag as written and for encoding clues.",
    "gzip": "The file started with the Gzip signature, so I tried a bounded decompression.",
    "binary": "The file did not read as UTF-8 text. I checked its starting bytes for a Gzip signature.",
}


def state_root() -> Path:
    if root := os.environ.get("CURD_HOME"):
        return Path(root).expanduser().resolve()
    if os.name == "nt":
        return Path(os.environ["LOCALAPPDATA"]) / "curd"
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "curd"


def atomic_write(path: Path, text: str) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
    ) as file:
        temporary = Path(file.name)
        file.write(text)
    try:
        for attempt in range(5):
            try:
                temporary.replace(path)
                return
            except PermissionError:
                if os.name != "nt" or attempt == 4:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        temporary.unlink(missing_ok=True)


def store(folder: Path, job: dict, **changes) -> None:
    job.update(changes)
    atomic_write(folder / "job.json", json.dumps(job, ensure_ascii=True, indent=2) + "\n")


def load(folder: Path) -> dict:
    return json.loads((folder / "job.json").read_text(encoding="utf-8"))


def path_label(path: tuple[str, ...]) -> str:
    return " → ".join(METHODS[method][0] for method in path) if path else "plain text"


def report(job: dict, findings: Findings, editors: list[dict], context: ChallengeContext) -> str:
    label = re.sub(r"[^A-Za-z0-9 ._()-]", "_", Path(job["file"]).name)[:100]
    lines = [
        f"# CTF writeup for {label}",
        "",
    ]
    if context.category:
        lines.extend([f"Category #{context.category}", ""])
    if context.description:
        lines.extend(["## Challenge description", ""])
        lines.extend(f"    {line}" for line in context.description.splitlines())
        lines.append("")
    lines.extend([
        "## First look",
        "",
        f"I read {findings.size:,} bytes and recorded SHA-256 `{findings.sha256}`.",
        INITIAL_FORMATS[findings.initial_format],
        "",
        "## Paths I tried",
        "",
    ])
    if findings.initial_format == "text":
        direct = "I found a candidate." if () in findings.candidates.values() else "I found no matching flag."
        lines.append(f"- **Plain text.** I checked the original text for a flag. {direct}")
    if not findings.attempts and findings.initial_format != "text":
        lines.append("I found no supported decoding path for these bytes.")
    selected_ids = {editor["path_id"] for editor in editors if editor.get("path_id")}
    attempts = [
        (index, attempt)
        for index, attempt in enumerate(findings.attempts, 1)
        if index <= 10 or index in selected_ids or attempt.outcome == "candidate"
    ]
    for index, attempt in attempts[:25]:
        _, clue = METHODS[attempt.path[-1]]
        lines.append(f"- **Path {index} · {path_label(attempt.path)}.** {clue} {OUTCOMES[attempt.outcome]}")
    if len(findings.attempts) > min(len(attempts), 25):
        lines.append(f"- I ran {len(findings.attempts)} distinct recorded checks in total.")
    if findings.limit_reached:
        lines.extend(["", "I reached the configured search limit on at least one branch."])
    lines.extend(["", "## Result", ""])
    if findings.candidates:
        lines.append("I recovered the following flag candidates under the configured prefixes.")
        for candidate, path in findings.candidates.items():
            lines.append(f"- `{candidate}` via {path_label(path)}")
    else:
        lines.append("I found no flag matching the configured prefixes in the paths I checked.")
    if editors:
        lines.extend(["", "## Editorial review", ""])
        for editor in editors:
            if editor.get("path_id"):
                index = editor["path_id"]
                detail = f"highlighted Path {index} ({path_label(findings.attempts[index - 1].path)})"
            elif editor["status"] == "ok":
                detail = "had no decoder path to highlight"
            else:
                detail = editor["status"]
            name = "Antigravity" if editor["provider"] == "agy" else editor["provider"].capitalize()
            lines.append(f"- {name} {detail}.")
    return "\n".join(lines) + "\n"


def mcp_options(args, parser, defaults: Path | None = None) -> dict:
    vault = args.vault
    config = args.mcp_config
    if defaults is not None and not (vault or config):
        vault = os.environ.get("CURD_VAULT")
        config = os.environ.get("CURD_MCP_CONFIG")
        if not (vault or config):
            try:
                settings = json.loads((defaults / "settings.json").read_text(encoding="utf-8"))
            except FileNotFoundError:
                settings = {}
            vault, config = settings.get("vault"), settings.get("mcp_config")
    if vault and config:
        parser.error("select either a vault or an MCP configuration")
    return {
        "vault": str(Path(vault).expanduser().resolve()) if vault else None,
        "mcp_config": str(Path(config).expanduser().resolve()) if config else None,
    }


def setup(argv: list[str], root: Path) -> int:
    parser = argparse.ArgumentParser(prog="curd setup", description="Save your Obsidian destination.")
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("vault", nargs="?", help="Path to your existing Obsidian vault")
    destination.add_argument("--mcp-config", help="Path to your Obsidian stdio MCP config")
    args = parser.parse_args(argv)
    options = mcp_options(args, parser)
    if options["vault"] and not Path(options["vault"]).is_dir():
        parser.error("the Obsidian vault directory does not exist")
    if options["mcp_config"] and not Path(options["mcp_config"]).is_file():
        parser.error("the MCP configuration file does not exist")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    atomic_write(root / "settings.json", json.dumps(options) + "\n")
    print("Obsidian destination saved.")
    return 0


def publish(folder: Path, job: dict) -> bool:
    note = (folder / "writeup.md").read_text(encoding="utf-8")
    try:
        asyncio.run(publish_note(job["vault"], job["mcp_config"], job["note_path"], note))
    except FileNotFoundError:
        message = "The MCP executable or configuration file was not found."
    except asyncio.TimeoutError:
        message = "The MCP server took longer than 30 seconds to respond."
    except OSError:
        message = "The MCP process could not be started or its connection closed."
    except ValueError as error:
        message = str(error)
    else:
        store(folder, job, publication="published", publication_error=None)
        return True
    store(folder, job, publication="failed", publication_error=message[:500])
    return False


def worker(folder: Path) -> int:
    job = load(folder)
    try:
        store(folder, job, state="analyzing")
        context = load_context(job.get("category"), job.get("description_file"))
        findings = analyze(read_local_file(Path(job["file"]), MAX_FILE), tuple(job["prefixes"]))
        editors = []
        providers = [ALIASES.get(provider, provider) for provider in job["providers"]]
        if providers != ["local"]:
            store(folder, job, state="editing")
            with ThreadPoolExecutor(max_workers=len(providers)) as pool:
                tasks = [
                    pool.submit(editorial_choice, provider, findings, job["provider_timeout"], context)
                    for provider in providers
                ]
                editors = [task.result() for task in tasks]
        atomic_write(folder / "writeup.md", report(job, findings, editors, context))
        store(folder, job, candidate_count=len(findings.candidates), editors=editors, category=context.category)
        if job["vault"] or job["mcp_config"]:
            store(folder, job, state="publishing")
            publish(folder, job)
        store(folder, job, state="complete")
    except Exception as error:
        store(folder, job, state="failed", error=str(error)[:500])
        raise
    return 2 if job["publication"] == "failed" else 0


def check_id(value: str) -> str:
    if not JOB_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("expected a 32-character job ID")
    return value


def latest_job(root: Path) -> str:
    try:
        job_id = (root / "latest-job").read_text(encoding="ascii").strip()
        if JOB_ID.fullmatch(job_id) and (root / job_id / "job.json").is_file():
            return job_id
    except (FileNotFoundError, UnicodeDecodeError):
        pass
    # Jobs submitted before this release only have a job directory.
    try:
        jobs = [
            folder for folder in root.iterdir()
            if JOB_ID.fullmatch(folder.name) and (folder / "job.json").is_file()
        ]
    except FileNotFoundError:
        jobs = []
    if not jobs:
        raise ValueError("No jobs yet. Start one with curd <file>.")
    return max(jobs, key=lambda folder: folder.stat().st_mtime_ns).name


def positive_seconds(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive number of seconds") from None
    if not 1 <= seconds <= 3600:
        raise argparse.ArgumentTypeError("expected 1 to 3600 seconds")
    return seconds


def add_mcp_arguments(parser) -> None:
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--vault", help="Obsidian vault directory for the MCPVault server on PATH")
    options.add_argument("--mcp-config", help="JSON configuration with a stdio server at mcpServers.obsidian")


def status_output(folder: Path, job: dict) -> None:
    print(f"{folder.name}  {job['state']}")
    if (folder / "writeup.md").is_file():
        print(f"Writeup  {folder / 'writeup.md'}")
        print(f"Flag candidates  {job.get('candidate_count', 'counting')}")
    if job["publication"] == "published":
        print(f"Obsidian  {job['note_path']}")
    elif job["publication"] == "failed":
        print(f"Obsidian publishing failed  {job['publication_error']}")
    elif job["state"] == "complete":
        print("Obsidian  not configured")
    for editor in job.get("editors", []):
        print(f"{editor['provider']}  {editor['status']}")
    if job.get("error"):
        print(f"Job failed  {job['error']}")


def start_job(argv: list[str], root: Path) -> int:
    parser = argparse.ArgumentParser(
        prog="curd",
        description="Analyze a local file puzzle in a detached worker and save a writeup.",
        epilog="Commands: curd setup VAULT, curd status [JOB_ID] [--wait], curd publish [JOB_ID].",
    )
    parser.add_argument("file", help="Local challenge file")
    parser.add_argument("provider", nargs="?", default="codex",
                        help="co, cl, oc, agy, local, or a comma-separated list (default: co)")
    parser.add_argument("--description", "--desc", metavar="FILE", help="UTF-8 description file")
    parser.add_argument("--category", "--tag", metavar="TAG", help="Challenge category tag")
    parser.add_argument("--flag-prefix", action="append", help="Replace default flag prefixes. Repeat for more.")
    parser.add_argument("--provider-timeout", type=positive_seconds, default=60,
                        help="Timeout per editor in seconds (default: 60)")
    add_mcp_arguments(parser)
    args = parser.parse_args(argv)
    try:
        providers = list(dict.fromkeys(ALIASES[item.strip().lower()] for item in args.provider.split(",")))
    except KeyError:
        parser.error("provider must be co, cl, oc, agy, local, or a comma-separated list of model providers")
    if "local" in providers and len(providers) > 1:
        parser.error("local must be selected on its own")
    prefixes = args.flag_prefix or DEFAULT_PREFIXES
    if len(prefixes) > 12 or any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,31}", p) for p in prefixes):
        parser.error("use up to 12 flag prefixes of 1 to 32 letters, digits or underscores, starting with a letter")
    source = Path(args.file).expanduser()
    if os.name == "nt" and str(source).startswith(("\\\\", "//")):
        parser.error("use a local file path")
    source = source.absolute()
    description = Path(args.description).expanduser().absolute() if args.description else None
    category = category_tag(args.category) if args.category else None
    options = mcp_options(args, parser, defaults=root)
    job_id = uuid.uuid4().hex
    folder = root / job_id
    folder.mkdir(mode=0o700, parents=True)
    job = {
        "file": str(source), "providers": providers, "prefixes": prefixes,
        "provider_timeout": args.provider_timeout, "note_path": f"CTF/curd-{job_id}.md",
        "category": category, "description_file": str(description) if description else None,
        **options,
    }
    store(folder, job, state="queued", publication="pending" if any(options.values()) else "not configured")
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        with (folder / "worker.log").open("ab") as log:
            subprocess.Popen(
                [sys.executable, "-m", "curd", "_worker", str(folder)],
                cwd=folder,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                creationflags=flags,
                start_new_session=os.name != "nt",
            )
    except OSError as error:
        store(folder, job, state="failed", error=str(error)[:500])
        raise
    atomic_write(root / "latest-job", job_id + "\n")
    print(job_id)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == "_worker":
        return worker(Path(argv[1]))
    root = state_root()
    try:
        if argv and argv[0] == "setup":
            return setup(argv[1:], root)
        if not argv or argv[0] not in ("status", "publish"):
            return start_job(argv, root)
        action, *args = argv
        parser = argparse.ArgumentParser(prog=f"curd {action}")
        parser.add_argument("id", nargs="?", type=check_id, help="Job ID (defaults to the latest job)")
        if action == "status":
            parser.add_argument("--wait", action="store_true", help="Wait for the detached job to finish")
            parser.add_argument("--timeout", type=positive_seconds, default=300)
        else:
            add_mcp_arguments(parser)
        options = parser.parse_args(args)
        folder = root / (options.id or latest_job(root))
        job = load(folder)
        if action == "publish":
            if job["state"] != "complete":
                parser.error("the job must have a completed writeup")
            defaults = None if job["vault"] or job["mcp_config"] else root
            update = mcp_options(options, parser, defaults=defaults)
            if any(update.values()):
                job.update(update)
            if not (job["vault"] or job["mcp_config"]):
                parser.error("configure an Obsidian vault or MCP server")
            publish(folder, job)
        elif options.wait:
            deadline = time.monotonic() + options.timeout
            while job["state"] not in TERMINAL_STATES and time.monotonic() < deadline:
                time.sleep(0.25)
                job = load(folder)
        status_output(folder, job)
        if job["state"] == "failed" or job["publication"] == "failed":
            return 2
        if action == "status" and options.wait and job["state"] not in TERMINAL_STATES:
            return 3
        return 0
    except (OSError, ValueError) as error:
        print(f"curd: {error}", file=sys.stderr)
        return 2
