# curd

`curd` runs an offline file puzzle in a detached worker and returns a job ID immediately. It writes a first-person Markdown account of the initial observations, the decoding paths it tried, and the flag candidates it recovered. With an Obsidian MCP server configured, it publishes the same note under `CTF/`.

## Install

Install the wheel on Windows or Linux with Python 3.10 or newer.

```sh
uv tool install ./curd_puzzle-0.4.0-py3-none-any.whl
```

You can also install the wheel with `pipx install`. To install the source, run `uv tool install .` from the extracted directory.

## Run a challenge

```text
curd "challenge file.txt"
curd "challenge.bin" agy --description "clues.md" --category forensics
curd status
```

The worker automatically sends a built-in prompt to Codex. Add `cl` for Claude Code, `oc` for OpenCode 2.2.6 or newer, `agy` for [Google Antigravity CLI](https://antigravity.google/docs/install?tab=cli), or `local` to skip the agent. The old `ge` and `gemini` selectors also launch `agy`. Use `co,cl,oc,agy` to prompt all four in parallel. Authenticate each CLI before use. The prompt asks each agent to highlight one of the paths the decoder actually tried. The source path, file contents, file hash, and flag values stay with the worker. CLI or authentication failures still leave a local writeup.

`curd status` shows the latest job. Add `--wait` to wait for completion or supply a job ID to check an older job.

## Challenge context

Use `--description clues.md` for a UTF-8 text file up to 8 KiB. Its first line can be `Category: forensics`. An explicit `--category` overrides that line. You can use `--tag` as an alias for `--category`. The writeup includes the full description and an Obsidian tag. Editors receive recognized category tags and supported encoding hints such as Base64 or Gzip as structured metadata.

The [skills and references catalog](references/README.md) covers blue-team work, forensics, static malware triage, cryptography, Web3 development, OT security, and offline CTF puzzles.

The decoder recognizes plaintext flags, hexadecimal, Base64, Base32, percent escapes, ROT13, and Gzip, including combinations up to three transformations deep. It reads regular files up to 1 MiB and treats the file as data. The default flag prefixes are `flag`, `ctf`, `picoCTF`, `HTB`, and `THM`. Repeat `--flag-prefix` to supply multiple custom prefixes. The report records matching strings as candidates so you can verify them with the competition.

## Cite CTF42

Copy a challenge page URL from Brave or another browser and attach it when you start the job. The link appears in the local writeup and the published Obsidian note.

```text
curd "challenge.txt" --reference "https://ctf42.online/ctfs/wolvctf/2024/hidden_data/"
```

`--ctf42` is an alias for `--reference`. CTF42 links are citations. The worker handles them offline and discards URL query parameters and fragments.

## Publish to Obsidian

To enable automatic Obsidian publishing, install [MCPVault](https://github.com/bitbonsai/mcpvault) and save your vault path once. MCPVault requires Node.js 22.12 or newer.

```text
npm install -g @bitbonsai/mcpvault
curd setup "/path/to/vault"
```

In PowerShell, use your Windows vault path, such as `curd setup "C:\Notes\My Vault"`. To reuse an existing MCP configuration, run `curd setup --mcp-config settings.json`. The config must contain a local stdio server called `obsidian` under `mcpServers`. The server must accept `write_note` with `path` and `content` arguments and support the 2025 MCP initialization handshake.

```json
{
  "mcpServers": {
    "obsidian": {
      "type": "stdio",
      "command": "mcpvault",
      "args": ["/path/to/vault"]
    }
  }
}
```

On Windows, use a native executable or an interpreter such as `node` or `python` followed by a script path for a custom stdio server. `curd` also resolves the npm-installed `mcpvault` launcher directly.

If Obsidian publishing fails, the local note stays available. Run `curd publish` to retry the latest job. A retry writes to the same job-specific vault note. Use `--vault` or `--mcp-config` to override the destination for a single job. The worker saves the job status, writeup, and worker log under `%LOCALAPPDATA%\curd` on Windows or `${XDG_STATE_HOME:-$HOME/.local/state}/curd` on Linux. Set `CURD_HOME` to override that location.
