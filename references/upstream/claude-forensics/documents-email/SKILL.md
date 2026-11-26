---
name: documents-email
description: Expert analysis of malicious documents and phishing email without opening them - Office files (OLE .doc/.xls/.ppt and OOXML .docm/.xlsm/.docx, VBA macros, XLM/Excel 4.0 macros, remote templates, DDE, embedded OLE objects), RTF exploits, PDFs (JavaScript, OpenAction, launch actions, embedded files), OneNote, HTML smuggling, LNK/ISO/IMG/VHD lures, and email (.eml/.msg) - headers, Received chain, SPF/DKIM/DMARC results, spoofing and lookalike domains, attachments and links. Use for any suspicious attachment, phishing report, or document from an incident. Follow forensics:core rules.
---

# Documents and email

Apply `forensics:core` throughout. Never open the document in Office, Acrobat, a browser or an image viewer. Never enable content. Never click, fetch or resolve a link from the email or document. All analysis is with parsers and text views.

## How an expert approaches a phishing case

1. **The email as evidence:** who really sent it (headers, not the display name), how it travelled, whether authentication passed, what it wants the user to do.
2. **Every payload path:** attachments, links (incl. QR codes in images), HTML smuggling (`<a download>` with a base64 blob, `msSaveOrOpenBlob`), password-protected archives with the password in the body.
3. **Each document:** type, then the active content (macros, scripts, remote templates, embedded objects, actions), then the next stage it fetches (URLs, file names) - extracted as text, never followed.
4. **Impact:** who received it, who clicked or opened (mail logs, proxy logs, host evidence - see `windows-host` for Office `TrustRecords` and child processes of Office).

## Email

Read `.eml` as text. Convert `.msg` first: `extract_msg --out work/msg evidence/m.msg` (or `msgconvert`).

Headers to extract, in this order:
- `From` (display name and address), `Reply-To`, `Return-Path` (envelope sender), `Sender`, `To`, `Subject`, `Date`, `Message-ID` (domain should match the sending system).
- `Received:` chain, read **bottom-up**: the lowest is the origin. The first hop your organisation's MX added is the last trustworthy one; anything below it can be forged. Note the originating IP and HELO name.
- `Authentication-Results` / `ARC-Authentication-Results` from your own gateway: `spf=`, `dkim=` (and `header.d=` - the signing domain), `dmarc=` (and `header.from=`). Pass/fail is only meaningful when it is your gateway that wrote the header.
- `X-Originating-IP`, `X-Mailer`, `User-Agent`, `X-MS-Exchange-*` (tenant info), `List-Unsubscribe`.

Spoofing signals: `From` domain differs from `Return-Path` and DKIM `d=` (and DMARC fails or the domain has no DMARC); display name of an executive with a free-mail address; lookalike domains (`rnicrosoft`, `micros0ft`, extra hyphen, different TLD, IDN homoglyphs - decode `xn--` punycode); `Reply-To` to a different domain; `Message-ID` domain unrelated to the sender.

Headers fold across lines (continuation lines start with whitespace), so unfold before grepping or you will miss `dmarc=` and later `Received` parts:
```bash
sed -n '1,/^\r\?$/p' evidence/m.eml | sed -E ':a;N;$!ba;s/\r?\n[ \t]+/ /g' > work/headers.txt   # header block, unfolded
grep -inE '^(from|reply-to|return-path|sender|to|subject|date|message-id|received|authentication-results|x-originating-ip|x-mailer):' work/headers.txt
grep -ioE '(spf|dkim|dmarc)=[a-z]+[^;]*' work/headers.txt
emldump.py evidence/m.eml                       # MIME tree (Didier Stevens)
emldump.py -s 3 -d evidence/m.eml > work/attachment3.bin   # extract part 3 (as .bin)
grep -oiE 'https?://[^"<> ]+' evidence/m.eml | sort -u        # links - defang, do not visit
```
Body encodings: `Content-Transfer-Encoding: base64` or `quoted-printable`; decode the part to `work/` (CyberChef "From Base64" / "From Quoted Printable", or `emldump.py -d`). HTML bodies: compare link text with `href` - mismatches are a finding. Tracking pixels and remote images are just as off-limits as links.

## Office documents

Order: `oleid` (overview) -> `olevba` (macros, auto-exec, suspicious keywords, IOCs) -> `mraptor` (macro risk verdict) -> `msodde` (DDE) -> `oleobj` (embedded objects, external relationships) -> `oledump.py` (stream-level detail).

```bash
oleid evidence/d.doc
olevba --decode --reveal evidence/d.doc > work/d.olevba.txt          # --deobf for VBA string deobfuscation
mraptor evidence/d.doc
msodde -a evidence/d.docx
oleobj evidence/d.docx                                                  # external template / OLE objects
oledump.py evidence/d.doc                                               # streams; 'M' marks macros
oledump.py -s 8 -v evidence/d.doc                                       # decompress VBA in stream 8
# OOXML is a ZIP: list it and read relationships for remote templates (T1221)
unzip -l evidence/d.docx ; unzip -p evidence/d.docx 'word/_rels/*.rels' | grep -o '<Relationship [^>]*TargetMode="External"[^>]*>'
unzip -p evidence/d.docx '[Content_Types].xml' | grep -io 'vbaProject\|macroEnabled'
# No unzip (stock Ubuntu)? Python's zipfile reads it without extracting:
python3 -I -m zipfile -l evidence/d.docx
# Every external relationship (remote template, OLE link, hyperlink, image) in any .rels part:
python3 -I -c "import zipfile,re,sys; z=zipfile.ZipFile(sys.argv[1]); [print(n, m) for n in z.namelist() if n.endswith('.rels') for m in re.findall(r'<Relationship [^>]*TargetMode=\"External\"[^>]*>', z.read(n).decode('utf-8','replace'))]" evidence/d.docx
exiftool evidence/d.docx | grep -iE 'creator|author|last modified|company|title|create date|modify date|template'
```
**Confirm every olevba keyword in the code.** The Suspicious table is a keyword scan of the whole module, comments and strings included: a macro whose comment says "no Shell, no CreateObject" is flagged for both. Before reporting that a macro calls `Shell`/`CreateObject`/a downloader, quote the line of code that does it. Report what the code actually does, not what the table matched.
Key `olevba` signals: AutoExec (`AutoOpen`, `Document_Open`, `Workbook_Open`, `Auto_Open`), Suspicious (`Shell`, `WScript.Shell`, `CreateObject`, `URLDownloadToFile`, `MSXML2.XMLHTTP`, `ADODB.Stream`, `Environ`, `CallByName`, `Chr(`, `StrReverse`), and the IOC table. XLM macros: `olevba` reports them; also look for very hidden sheets and `Auto_Open` defined names (`oledump.py -p plugin_biff.py --pluginoptions '-x'`). VBA stomping: p-code present but source empty or mismatched - `olevba` flags it (`pcodedmp` for detail).

## RTF

```bash
rtfobj evidence/r.rtf                       # embedded objects, OLE package names, CVE-2017-11882 Equation Editor objects
rtfdump.py -f O evidence/r.rtf              # objects only
```
`objupdate`, `objautlink`, `Equation.3`, huge hex blobs and malformed control words are red flags.

## PDF

```bash
pdfid.py -e evidence/p.pdf                  # counts of /JS, /JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile, /URI, /XFA, /ObjStm
pdf-parser.py -a evidence/p.pdf             # stats
pdf-parser.py -s javascript evidence/p.pdf  # find JS objects
pdf-parser.py -o 12 -f -d work/obj12.bin evidence/p.pdf     # filtered (decompressed) stream of object 12
qpdf --qdf --object-streams=disable evidence/p.pdf work/p.qdf.pdf   # flatten to readable form
```
`/OpenAction` or `/AA` plus `/JS` = code on open. `/Launch` runs commands. `/EmbeddedFile` hides a payload. `/URI` with lure text is the usual credential-phish PDF. `/ObjStm` can hide objects from a naive scan - pdfid counts may be low until expanded. Many phishing PDFs have no code at all: just a big clickable image linking out - report the link (defanged).

## Other lure formats

- **OneNote (`.one`)**: embedded files (`.hta`, `.wsf`, `.bat`, `.lnk`) behind a fake "click to view" image. `onedump.py evidence/n.one` lists and extracts them.
- **LNK**: read with `LECmd.exe -f` or `lnkparse`: target path, arguments (`cmd /c`, `powershell -w hidden`, `mshta`, padding to hide args), icon location, machine ID.
- **ISO/IMG/VHD(X)**: containers that strip Mark-of-the-Web; list with `7z l`, then triage contents.
- **HTML/SVG attachments**: read as text; look for `atob(`, base64 blobs, `<a download`, `window.location` to a login page, form `action=` to an external host. These are often credential phish.
- **Archives**: list first; note encryption, double extensions, and nested containers.

Extracted payloads go to `forensics:malware-triage`.

## Output

Use the core report format. For phishing: sender truth (envelope sender, originating IP, auth results) in one line, the lure in one line, then each payload path as a finding, then the IOC table (sender addresses, domains, URLs, attachment hashes - all defanged). For documents: verdict line, then active content findings with stream/object numbers.
