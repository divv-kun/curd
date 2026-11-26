---
name: network
description: Expert network forensics - PCAP/PCAPNG triage with tshark/Wireshark/capinfos, conversations and protocol hierarchy, DNS (tunnelling, DGA, fast flux), HTTP(S) and TLS (SNI, JA3/JA4, certificates), C2 beaconing detection, SMB/RDP/WinRM lateral movement, credential exposure, file carving from streams, exfiltration, Zeek logs, NetFlow, and firewall/proxy/DNS server logs. Use for any capture file, Zeek/Suricata output, or network log, or a question about what a host talked to. Follow forensics:core rules.
---

# Network forensics

Apply `forensics:core` throughout. Every IP, domain and URL you find is attacker infrastructure until shown otherwise: record it defanged, never contact it, never resolve it.

## How an expert approaches a capture

1. **Shape before content.** Capture span, packet count, hosts, protocol mix, top conversations. Two minutes of statistics decides where the hours go.
2. **Identify roles.** Which internal host is the victim, which are servers, which external endpoints matter. Name them (victim, DC, proxy, C2-candidate) and use the names throughout.
3. **Follow the kill chain on the wire:** delivery (download of the first stage), C2 (periodic connections, unusual DNS), credential access/lateral movement (SMB, RDP, WinRM, Kerberos, NTLM), exfiltration (large outbound, unusual protocols, DNS volume).
4. **Corroborate with host evidence.** A connection is a finding about the network; pair it with the process or logon on the host where possible.

## Triage commands (tshark; Wireshark GUI for drill-down)

```bash
capinfos evidence/c.pcap                                     # span, packets, link type, file hash
tshark -r evidence/c.pcap -qz io,phs                          # protocol hierarchy
tshark -r evidence/c.pcap -qz conv,ip | head -30              # top IP conversations (bytes, duration)
tshark -r evidence/c.pcap -qz conv,tcp | head -30
tshark -r evidence/c.pcap -qz endpoints,ip | head -30
tshark -r evidence/c.pcap -qz expert                          # retransmits, resets, malformed

# DNS: every query and answer
tshark -r evidence/c.pcap -Y 'dns.flags.response==0' -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type | sort -u -k3
tshark -r evidence/c.pcap -Y 'dns.flags.response==1' -T fields -e dns.qry.name -e dns.a -e dns.cname -e dns.resp.ttl
# HTTP requests and responses
tshark -r evidence/c.pcap -Y http.request -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e http.request.method -e http.host -e http.request.uri -e http.user_agent
tshark -r evidence/c.pcap -Y http.response -T fields -e frame.number -e ip.src -e http.response.code -e http.content_type -e http.content_length
# TLS: who the client asked for, and what certificate came back
tshark -r evidence/c.pcap -Y 'tls.handshake.type==1' -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3 -e tls.handshake.ja4
tshark -r evidence/c.pcap -Y 'tls.handshake.type==11' -T fields -e ip.src -e x509sat.uTF8String -e x509sat.printableString -e x509ce.dNSName
# Follow one stream as text (read-only view)
tshark -r evidence/c.pcap -qz follow,tcp,ascii,5
# Export transferred objects to work/ for static analysis (never open them)
tshark -r evidence/c.pcap --export-objects http,work/objects/http
tshark -r evidence/c.pcap --export-objects smb,work/objects/smb
sha256sum work/objects/*/*
```

Times: `frame.time_epoch` is UTC epoch; convert with `date -u -d @<epoch> +%FT%TZ`. Wireshark's GUI shows local time by default (View > Time Display Format > UTC).

Older tshark (<3.x) lacks `ja4` and some fields; check `tshark -v` and drop missing fields rather than failing.

## Detection patterns

- **Beaconing:** many connections from one host to one destination at near-fixed intervals (jitter often 10-30%), small similar-size requests, long overall duration. Compute intervals:
  ```bash
  tshark -r evidence/c.pcap -Y 'ip.dst==<c2> && tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time_epoch | \
    awk 'NR>1{d=$1-p; s+=d; ss+=d*d; n++} {p=$1} END{m=s/n; printf "n=%d mean=%.1fs sd=%.1fs\n", n+1, m, sqrt(ss/n-m*m)}'
  ```
  Low standard deviation relative to mean = beacon. Check HTTP URIs and User-Agents for repetition too.
- **DNS tunnelling / DGA:** long (>40 chars) or high-entropy subdomains, many unique subdomains of one parent, heavy TXT/NULL/CNAME use, NXDOMAIN storms (DGA), very low TTLs and many A records (fast flux).
- **Suspicious HTTP:** raw-IP Host headers, executables or scripts in responses (`MZ` at body start, `application/x-msdownload`, `.hta`, `.ps1`), mismatched Content-Type, User-Agents like `curl`, `python-requests`, `PowerShell`, `WinHTTP`, `Microsoft BITS`, or an outdated browser string, POSTs with base64/high-entropy bodies, `/gate.php`, `/submit.php`.
- **TLS:** SNI absent or a raw IP, self-signed or freshly issued certificates, cert subject not matching SNI, JA3/JA4 hashes matching known tooling, long-lived low-volume sessions.
- **Lateral movement:** SMB to `ADMIN$`/`C$`/`IPC$` with `svcctl` (PsExec), `\PIPE\` names like `PSEXESVC`, `RemCom`, `msagent_*`; DCE/RPC `ITaskSchedulerService` (remote tasks), `IWbemServices` (WMI), WinRM on 5985/5986, RDP 3389 from a workstation, Kerberos TGS-REQ bursts for many SPNs with RC4 (`etype 23`) = Kerberoasting.
- **Credentials in clear:** `tshark -r evidence/c.pcap -Y 'http.authorization || ftp.request.command==PASS || pop.request || imap.request || smtp.auth.username || ntlmssp.auth.username'` (record usernames, never paste passwords into the report; say "cleartext password observed, frame N").
- **Exfiltration:** outbound bytes far exceeding inbound to one destination, uploads to file-sharing/paste/cloud storage, large DNS or ICMP payloads, sustained connections outside business hours.

## Zeek and logs

If Zeek is available, it turns a capture into searchable logs:
```bash
mkdir -p work/zeek && cd work/zeek && zeek -C -r ../../evidence/c.pcap LogAscii::use_json=T
jq -r 'select(.["id.resp_h"]=="<ip>") | [.ts, .["id.orig_h"], .["id.resp_p"], .duration, .orig_bytes, .resp_bytes] | @tsv' conn.log
jq -r '.query' dns.log | sort | uniq -c | sort -rn | head
```
`conn.log` (flows), `dns.log`, `http.log`, `ssl.log` (SNI, JA3), `x509.log`, `files.log` (hashes of transferred files), `smb_files.log`, `dce_rpc.log`, `kerberos.log`, `ntlm.log`, `weird.log`, `notice.log`.

Proxy, firewall and DNS-server logs: normalise to (time UTC, src, dst, port, bytes, action, URL/query), then apply the same beaconing and volume analysis.

## Common traps

- A capture shows only what passed the capture point; absence of traffic is not absence of activity.
- Truncated captures (snaplen) break object export; check `capinfos` "Packet size limit".
- NAT and proxies hide the real client; match on time and port with the proxy logs.
- CDN and cloud IPs host many tenants; the domain (SNI/Host) matters more than the IP.
- Encrypted traffic: report metadata (SNI, JA3/JA4, sizes, timing) and say content was not visible. Never claim knowledge of encrypted content.

## Output

Use the core report format. Cite frame numbers or Zeek `uid`s as the evidence location. Summarise conversations as `victim 10.0.0.5 -> 203.0.113[.]5:443, 214 sessions, 60 s +/- 6 s, 1.2 MB out` rather than packet lists.
