# Skills and references

## Downloaded skills

| Area | Start here |
| --- | --- |
| Blue team | Collect, correlate, classify, and escalate a security alert. [Alert triage](upstream/securityskills/alert-triage/SKILL.md) |
| Forensic evidence | Record acquisition, hashes, chain of custody, and reporting gaps. [Forensics core](upstream/claude-forensics/core/SKILL.md) |
| Windows and Linux forensics | Find host artifacts and correlate them with the incident window. [Windows host](upstream/claude-forensics/windows-host/SKILL.md), [Linux host](upstream/claude-forensics/linux-host/SKILL.md) |
| Network forensics | Inspect saved packet captures and correlate them with logs. [Network forensics](upstream/claude-forensics/network/SKILL.md) |
| Timeline analysis | Normalize timestamps and distinguish observations from inference. [Timeline analysis](upstream/claude-forensics/timeline/SKILL.md) |
| Documents and email | Inspect message headers and suspicious attachments as evidence. [Documents and email](upstream/claude-forensics/documents-email/SKILL.md) |
| Malware analysis | Identify suspicious files and inspect their structure without running them. [Static malware triage](upstream/claude-forensics/malware-triage/SKILL.md) |
| Web3 review preparation | Document contract architecture, review scope, and test coverage. [Trail of Bits audit prep](upstream/trailofbits/audit-prep-assistant/SKILL.md) |

The upstream files are reference copies. Some point to companion files in their original repositories.

- UnitOneAI SecuritySkills. [Source](https://github.com/UnitOneAI/SecuritySkills/blob/main/skills/secops/alert-triage/SKILL.md) · [MIT license](upstream/securityskills/LICENSE)
- Atlantium-AI Claude Forensics. [Source](https://github.com/Atlantium-AI/claude-forensics/tree/main/plugins/forensics/skills) · [Apache 2.0 license](upstream/claude-forensics/LICENSE)
- Trail of Bits Skills. [Source](https://github.com/trailofbits/skills/blob/main/plugins/building-secure-contracts/skills/audit-prep-assistant/SKILL.md) · [CC BY-SA 4.0 license](upstream/trailofbits/LICENSE)

## More starting points

| Area | Start here |
| --- | --- |
| Cryptography and encoding | Compare alphabets and padding in encoding puzzles. Use historical cipher demos for Caesar, Vigenère, and transposition exercises. [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html), [CrypTool-Online](https://www.cryptool.org/en/cto/) |
| Web3 contract development | Review access control, upgradeability, and standard library choices. [OpenZeppelin secure contracts skill](https://github.com/OpenZeppelin/openzeppelin-skills/blob/main/skills/develop-secure-contracts/SKILL.md) |
| OT and ICS security | Start with the asset inventory, network zones, access paths, and recovery constraints. [NIST OT security guide](https://csrc.nist.gov/pubs/sp/800/82/r3/final), [CISA OT asset inventory guide](https://www.cisa.gov/sites/default/files/2025-08/joint-guide-foundations-for-OT-cybersecurity-asset-inventory-guidance_508c.pdf) |
| Web application and mobile security | Use requirements for authorization, data protection, storage, and secure communications. [OWASP ASVS](https://asvs.owasp.org/), [OWASP MASVS](https://mas.owasp.org/MASVS/) |
| Static reverse engineering and firmware artifacts | Identify file formats and architectures, then document imports and cross-references. [Static reverse engineering notes](static-reverse-engineering.md) |
| Steganography and challenge artifacts | Inspect embedded metadata and visualize frequencies in provided audio. [ExifTool documentation](https://exiftool.org/exiftool_pod2.html), [Audacity spectrogram guide](https://manual.audacityteam.org/man/spectrogram_view.html) |
| Blue-team detection writing | Specify log sources, conditions, and false positives. [Sigma rule guide](https://sigmahq.io/docs/basics/rules.html) |
| Security exercise planning | Define the scope, objectives, roles, and after-action review for a discussion-based exercise. [CISA exercise planner handbook](https://www.cisa.gov/sites/default/files/publications/2%20-%20CTEP%20Exercise%20Planner%20Handbook%20%282020%29%20FINAL_508.pdf) |

## CTF42 practice references

- EXIF and metadata in a supplied file. [Hidden_Data, WolvCTF 2024](https://ctf42.online/ctfs/wolvctf/2024/hidden_data/)
- Spectrogram and metadata in a supplied audio file. [2_-1_Senses, CSS 2026](https://ctf42.online/ctfs/css/2026/2_-1_senses/)
- PDF metadata and QR codes. [Last_chance, KubSTU 2026](https://ctf42.online/ctfs/kubstu/2026/last_chance/)

Attach a challenge-page URL with `curd FILE --ctf42 URL` to cite it in your writeup. The challenge pages are public. CTF42 may require a member login to view its writeups. [CTF42 archive](https://ctf42.online/)
