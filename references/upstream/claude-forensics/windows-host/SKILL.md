---
name: windows-host
description: Expert Windows host forensics - Security/System/PowerShell/Sysmon event logs (EVTX), logon analysis, registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve), execution artefacts (Prefetch, Amcache, Shimcache, BAM, UserAssist, SRUM), persistence (Run keys, services, scheduled tasks, WMI), lateral movement, LNK and jump lists, and Defender logs. Use for any .evtx, registry hive, .pf, Windows triage collection (KAPE, Velociraptor), or a question about what happened on a Windows machine. Follow forensics:core rules.
---

# Windows host forensics

Apply `forensics:core` (safety, case layout, report format) throughout. Commands for every tool below are in `references/commands.md`; registry paths and artefact locations in `references/artifacts.md`.

## How an expert approaches a Windows host

1. **Scope the clock.** Get the incident window from the user or the first alert. Note the host's timezone from `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`; EVTX timestamps are UTC, several registry and app values are local.
2. **Logs first, then artefacts.** Event logs give who/when; execution and persistence artefacts give what. Parse EVTX to CSV/JSON, then filter. Do not scroll raw XML.
3. **Hunt broad, then pivot.** Run a Sigma-based sweep (Hayabusa or Chainsaw) over all EVTX for a ranked list of detections, then confirm every hit in the raw event. Sigma hits are leads, not findings.
4. **Answer the five questions** for every suspicious account or process: how did it get in (initial access), what ran (execution), how does it stay (persistence), where did it go (lateral movement), what did it take or break (impact).
5. **Check log health.** First and last event time per log, 1102 (Security cleared), 104 (other log cleared), 4719 (audit policy changed), gaps in EventRecordID. Missing data is a finding.

## Logon analysis essentials

- **4624** success, **4625** failure, **4634/4647** logoff, **4648** explicit credentials (runas, lateral movement), **4672** admin privileges assigned at logon, **4768/4769/4771** Kerberos (DC), **4776** NTLM validation (DC or local SAM).
- **Logon types:** 2 interactive (console), 3 network (SMB, net use, PsExec auth, WinRM auth), 4 batch (scheduled task), 5 service, 7 unlock, 8 network cleartext (IIS basic), 9 NewCredentials (`runas /netonly`, some pass-the-hash tooling), 10 RemoteInteractive (RDP), 11 cached interactive.
- **4625 Status/SubStatus:** `0xC0000064` user does not exist (username enumeration/spraying), `0xC000006A` wrong password for a real account (guessing against a known account), `0xC0000234` locked out, `0xC0000072` disabled, `0xC000006F` outside hours, `0xC0000070` workstation restriction, `0xC0000071` password expired, `0xC0000193` account expired, `0xC0000133` clock skew, `0xC000015B` logon type not granted.
- **Patterns:** many 0xC0000064 then 0xC000006A then a 4624 = enumeration, then guessing, then success. Many accounts, one password, low rate = spraying. A type 3 4624 with `LogonProcessName` NtLmSsp, `KeyLength` 0 and an unusual `WorkstationName` from a workstation = suspect pass-the-hash. Type 10 from an internal host that never does RDP = lateral movement.
- **Key 4624 fields:** `TargetUserName`, `TargetDomainName`, `LogonType`, `IpAddress`, `IpPort`, `WorkstationName`, `LogonProcessName`, `AuthenticationPackageName`, `TargetLogonId` (join to 4634/4672/4688 by Logon ID), `ElevatedToken`.

## Execution, persistence and lateral movement - where to look

| Question | Primary artefacts |
|---|---|
| What ran? | 4688 (with command line if enabled), Sysmon 1, Prefetch (`C:\Windows\Prefetch\*.pf`, last 8 run times on Win8+), Amcache.hve (path, SHA1, first-seen), Shimcache/AppCompatCache in SYSTEM (presence, not proof of execution on Win10+), BAM/DAM in SYSTEM (last run per user), UserAssist in NTUSER (GUI launches, ROT13), SRUM (per-app network bytes, 30-60 days), PowerShell 4104 script blocks |
| What persists? | Run/RunOnce (HKLM and HKCU, incl. Wow6432Node), services (7045 System log, 4697 Security; `SYSTEM\CurrentControlSet\Services`), scheduled tasks (4698/4702, Task Scheduler Operational 106/140/200/201, `C:\Windows\System32\Tasks\` XML), WMI subscriptions (Sysmon 19-21, WMI-Activity 5861, `OBJECTS.DATA`), Startup folders, Winlogon `Userinit`/`Shell`, IFEO `Debugger`, AppInit_DLLs, COM hijacks in UsrClass.dat |
| Who moved where? | 4624 type 3/10 on destination, 4648 on source, RDP: TerminalServices-RemoteConnectionManager 1149 + LocalSessionManager 21/22/24/25 + RdpCoreTS 131, PsExec: 7045 `PSEXESVC` + named pipe, WinRM: WinRM Operational 6/91 + 4624 type 3, SMB admin shares: 5140/5145, `NTUSER\...\Terminal Server Client\Servers` (outbound RDP history) |
| What did they touch? | ShellBags (UsrClass.dat), LNK files and jump lists (`Recent\`, `AutomaticDestinations`), RecentDocs, OpenSaveMRU, TypedPaths, `$MFT`/`$UsnJrnl` (see `timeline`), 4663 object access if auditing |
| Defence evasion? | 1102/104 cleared logs, Defender 5001 (real-time off), 5007 (config changed, e.g. exclusions), 1116/1117 detection/action, 4719 audit policy, timestomping (`$SI` vs `$FN` in MFT), deleted shadow copies (`vssadmin delete shadows` in 4688/4104) |

## PowerShell

Event IDs: **4104** script block (Microsoft-Windows-PowerShell/Operational; multi-part blocks share a ScriptBlock ID - reassemble in order), **4103** module/pipeline logging, **400/403/600** legacy Windows PowerShell log (engine start, `HostApplication` shows the full command line even when 4104 is off). Red flags: `-enc`/`-EncodedCommand`, `FromBase64String`, `IEX`/`Invoke-Expression`, `DownloadString`/`DownloadFile`/`Invoke-WebRequest`, `Net.WebClient`, `-w hidden`, `-nop`, `-ep bypass`, `Add-MpPreference -ExclusionPath`, AMSI bypass strings (`amsiInitFailed`, `AmsiUtils`), reflection loading (`[Reflection.Assembly]::Load`). Decode base64 (UTF-16LE for `-enc`) in CyberChef or `base64 -d | iconv -f utf-16le`, never by running it. Also check `ConsoleHost_history.txt` under `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\`.

## Sysmon (if present)

1 process create (with hashes, parent, command line), 3 network connection, 7 image loaded, 8 CreateRemoteThread, 10 process access (LSASS access = credential theft), 11 file create, 12-14 registry, 15 ADS, 17/18 named pipes, 19-21 WMI, 22 DNS query, 23/26 file delete, 25 tampering. Parent/child anomalies to flag: Office apps spawning `cmd`/`powershell`/`wscript`/`mshta`/`rundll32`; `services.exe` spawning shells; `w3wp.exe` spawning anything interactive; `lsass` access with `GrantedAccess` 0x1010/0x1410/0x1FFFFF from non-system tools.

## Common traps

- 4625 with blank `IpAddress` is usually a local logon attempt or a service, not a network attack.
- Shimcache presence on Windows 10+ does not prove execution; Amcache and Prefetch are stronger.
- Prefetch is disabled by default on many servers and on SSD-based systems with some configurations. No prefetch is not proof that nothing ran.
- Timestamps in Timeline Explorer follow the CSV; EvtxECmd writes UTC. Do not double-convert.
- `TargetUserName` ending in `$` is a machine account; usually noise unless it shows up somewhere odd.
- Event IDs collide across providers (4104 is also used elsewhere); always filter on Provider/Channel as well as ID.
- Hives copied from a live system are often dirty. Replay transaction logs (`.LOG1/.LOG2`): RECmd and Registry Explorer do this when the logs sit next to the hive.

## Output

Use the core report format. For logon questions, a compact table of the relevant events (time, EventRecordID, event ID, account, logon type, source IP, status) is signal; anything beyond the events that answer the question is noise.
