---
name: linux-host
description: Expert Linux and Unix host forensics - auth.log/secure, journald, syslog, wtmp/btmp/lastlog, auditd, shell history, SSH keys and config, cron, systemd units, rc/profile persistence, LD_PRELOAD, kernel modules, web server access/error logs and webshells, Docker/container artefacts, package-manager logs, and UAC collections. Use for any Linux or macOS-style log, home directory, /etc, /var/log or collected Linux triage package, or a question about what happened on a Linux server. Follow forensics:core rules.
---

# Linux host forensics

Apply `forensics:core` throughout. Commands assume evidence is a collected copy (UAC tarball, mounted image, or copied `/var/log`, `/etc`, `/home`, `/root`), not the live host. If the user wants live triage of a host they own, collect with UAC first; never "investigate" by running commands that change the suspect host.

## How an expert approaches a Linux host

1. **Establish the box:** distro and version (`etc/os-release`), hostname, timezone (`etc/timezone`, `etc/localtime` symlink), users (`etc/passwd`, `etc/shadow` change dates, `etc/group` for sudo/wheel/docker), what is exposed (`etc/ssh/sshd_config`, web server configs, listening services in the collection).
2. **Find the entry point:** SSH (auth logs, keys), a web app (access logs, webshells), an exposed service (its own logs), or a supply-chain/container image.
3. **Follow the account:** for every suspicious user or UID, collect logins, sudo use, shell history, files owned and modified in the window.
4. **Sweep persistence** in a fixed order (table below); attackers usually leave more than one.
5. **Watch for tampering:** truncated or zero-size logs, gaps in syslog sequence, `history -c`, `HISTFILE=/dev/null`, `unset HISTFILE`, symlinked `.bash_history -> /dev/null`, `wtmp`/`btmp` edits, timestomped binaries (`touch -r`), unusual immutable flags (`lsattr`).

## Logs and what they answer

| Source | Path | Answers |
|---|---|---|
| Auth | `var/log/auth.log` (Debian/Ubuntu), `var/log/secure` (RHEL) | SSH success/failure (`Accepted password/publickey`, `Failed password`, `Invalid user`), sudo commands (`COMMAND=`), su, useradd/usermod/passwd, PAM |
| journald | `var/log/journal/<machine-id>/*.journal` | everything systemd captured; read with `journalctl -D <dir>` |
| Logins | `var/log/wtmp` (`last -f`), `var/log/btmp` (`lastb -f`, failed), `var/log/lastlog` | session history, source IPs, failed logins |
| auditd | `var/log/audit/audit.log` | execve with args, file watches, user changes; `ausearch -if` / `aureport -if` |
| Syslog | `var/log/syslog`, `var/log/messages`, `var/log/kern.log` | cron runs, service starts, kernel module loads, OOM, segfaults (exploitation) |
| Package logs | `var/log/dpkg.log`, `var/log/apt/history.log`, `var/log/yum.log`, `var/log/dnf.log` | tools the attacker installed (`nmap`, `socat`, `gcc`) |
| Web | `var/log/nginx/`, `var/log/apache2/`, `var/log/httpd/` | exploitation requests, webshell access, scanners |
| Shell | `home/*/.bash_history`, `root/.bash_history`, `.zsh_history`, `.python_history`, `.mysql_history`, `.lesshst`, `.viminfo` | commands typed; no timestamps unless `HISTTIMEFORMAT` was set (zsh extended history has `: <epoch>:0;cmd`) |

## Persistence checklist

| Mechanism | Where |
|---|---|
| SSH keys | `home/*/.ssh/authorized_keys`, `root/.ssh/authorized_keys`, `AuthorizedKeysFile` overrides in `sshd_config`, `command=` options in keys |
| Cron | `etc/crontab`, `etc/cron.d/`, `etc/cron.{hourly,daily,weekly,monthly}/`, `var/spool/cron/crontabs/<user>` (Debian), `var/spool/cron/<user>` (RHEL), `etc/anacrontab` |
| systemd | `etc/systemd/system/`, `usr/lib/systemd/system/`, `lib/systemd/system/`, `home/*/.config/systemd/user/`, `*.timer` units, `ExecStart`/`ExecStartPre` pointing to `/tmp`, `/dev/shm`, `/var/tmp`, hidden dirs |
| Shell init | `etc/profile`, `etc/profile.d/`, `etc/bash.bashrc`, `home/*/.bashrc`, `.bash_profile`, `.profile`, `.zshrc`, `.bash_logout` |
| Preload / loader | `etc/ld.so.preload`, `LD_PRELOAD` in env files, new files in `etc/ld.so.conf.d/` |
| Accounts | UID 0 accounts besides root in `etc/passwd`, new users, users with shells that should not have them, `etc/sudoers` and `etc/sudoers.d/` (`NOPASSWD`) |
| PAM | modified or extra modules in `etc/pam.d/`, unexpected `.so` in `lib/*/security/` |
| Init / rc | `etc/rc.local`, `etc/init.d/`, `etc/update-motd.d/` (runs as root on SSH login) |
| Kernel | `etc/modules`, `etc/modules-load.d/`, unsigned/out-of-tree module loads in kern.log |
| Other | `at` jobs (`var/spool/cron/atjobs`), git hooks, `etc/xdg/autostart/`, web server modules, Docker containers with `--restart always` and host mounts |

## Commands

```bash
# SSH outcomes by source IP and user
grep -h sshd evidence/var/log/auth.log* | \
  sed -nE 's/.*sshd\[[0-9]+\]: (Accepted|Failed|Invalid user)( password| publickey| keyboard-interactive\/pam)?( for)?( invalid user)? ([^ ]+) from ([0-9a-fA-F.:]+).*/\1 \5 \6/p' | \
  sort | uniq -c | sort -rn | head -40          # count outcome user source-ip
zgrep -h 'Accepted' evidence/var/log/auth.log*.gz                    # rotated logs
grep -h 'sudo:' evidence/var/log/auth.log* | grep 'COMMAND='          # sudo commands
last -F -f evidence/var/log/wtmp ; lastb -F -f evidence/var/log/btmp | head
journalctl -D evidence/var/log/journal --utc -o short-iso --since '2026-01-05 13:00' --until '2026-01-05 16:00'
journalctl -D evidence/var/log/journal --utc -u ssh -u sshd -o short-iso
ausearch -if evidence/var/log/audit/audit.log -m EXECVE -i --start 01/05/2026 13:00:00 | head -100
aureport -if evidence/var/log/audit/audit.log --login --summary -i

# Files changed in the incident window (mounted image at evidence/mnt)
find evidence/mnt -xdev -newermt '2026-01-05 13:00' ! -newermt '2026-01-05 16:00' -type f -printf '%TY-%Tm-%TdT%TH:%TM:%TSZ %u %m %p\n' 2>/dev/null | sort
# Executables in writable/hidden places
find evidence/mnt/{tmp,var/tmp,dev/shm} evidence/mnt/home -type f -perm -u+x 2>/dev/null
find evidence/mnt -name '.*' -type d -path '*/tmp/*' 2>/dev/null
# UID 0 and shells
awk -F: '$3==0 || $7 !~ /(nologin|false)$/ {print}' evidence/etc/passwd
# Package installs in window
grep -h ' install ' evidence/var/log/dpkg.log* | sort
```

Web logs (combined format):
```bash
# Top client IPs, then status-code mix per IP
awk '{print $1}' evidence/var/log/nginx/access.log* | sort | uniq -c | sort -rn | head
# Likely exploitation and webshell use
grep -hiE "(\.\./|%2e%2e|union.+select|/etc/passwd|cmd=|exec=|eval\(|base64_decode|wget%20|curl%20|\$\{jndi:|/\.env|\.php\?.*=(id|whoami|uname))" evidence/var/log/nginx/access.log*
# POSTs to rarely-requested PHP/JSP/ASPX files = webshell candidates
awk '$6 ~ /POST/ {print $7}' evidence/var/log/nginx/access.log* | sed 's/?.*//' | sort | uniq -c | sort -n | head -30
```

Webshell candidates on disk: recently modified script files in the web root containing `eval(`, `assert(`, `base64_decode(`, `system(`, `passthru(`, `shell_exec(`, `Runtime.getRuntime().exec`, `ProcessBuilder`. Read them as text; never request them on a live server.

Containers: `var/lib/docker/containers/<id>/config.v2.json` (image, cmd, mounts), `<id>-json.log` (stdout), `var/lib/docker/overlay2/*/diff/` (files a container changed). Privileged containers and host mounts of `/`, `/var/run/docker.sock` or `/etc` are escape paths.

## Common traps

- Syslog timestamps have no year or timezone; anchor them with the file's rotation date and `etc/timezone`.
- `auth.log` rotates weekly by default; pull every `auth.log.*` and `.gz`.
- `lastlog` is sparse and huge; read with `lastlog` against a mounted root (`lastlog -R`), not `cat`.
- Shell history order is not time order when multiple shells were open; history is written at shell exit.
- Inode change time (ctime) cannot be set with `touch`, so a file with an old mtime but recent ctime was likely timestomped.

## Output

Use the core report format. For SSH questions, a short table (time, source IP, user, outcome, method) beats prose. List each persistence mechanism found as its own finding with the exact file path and line.
