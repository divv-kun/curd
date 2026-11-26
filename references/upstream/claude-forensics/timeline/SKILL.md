---
name: timeline
description: Expert forensic timelining - building one UTC timeline across event logs, registry, filesystem ($MFT, $UsnJrnl, $LogFile), browser history, network and application logs; super-timelines with plaso (log2timeline/psort), targeted timelines with Eric Zimmerman tools and Hayabusa, NTFS timestamps ($STANDARD_INFORMATION vs $FILE_NAME) and timestomping detection, deleted-file recovery with The Sleuth Kit, and disk images (E01, raw, VHD). Use when the question is "what happened in what order", when correlating multiple sources, or when working from a disk image. Follow forensics:core rules.
---

# Timeline analysis

Apply `forensics:core` throughout. A timeline is the backbone of the report: it turns findings from every other skill into one ordered story.

## How an expert builds a timeline

1. **Targeted beats total.** A super-timeline of a whole disk is millions of rows. Start with the sources that matter for the questions (EVTX, Prefetch, Amcache, MFT for the relevant folders, browser history), in a bounded window, then widen if needed.
2. **One clock.** Everything to UTC. Record source timezones and any skew (compare a known event seen by two sources).
3. **Anchor events.** Fix a few certain points (first alert, first malicious logon, first execution of the payload) and work outwards from each.
4. **Every row has a source.** Time, source artefact, record/offset, host, user, description. Without the source column, the timeline cannot be defended.
5. **Gaps are rows.** Insert "log cleared", "no Security events 13:00-14:10", "system powered off" as explicit rows.

## NTFS timestamps

Each file has MACB times in `$STANDARD_INFORMATION` ($SI, easily changed by user-mode tools) and `$FILE_NAME` ($FN, changed only by the kernel on create/rename/move).

- Timestomping signs: $SI created earlier than $FN created; $SI times with zero sub-second precision (`.0000000`) while neighbours have full precision; $SI predating the OS install or the parent folder; USN journal shows the file created recently while $SI says years ago.
- Copy sets created = time of copy and keeps modified - so modified earlier than created is normal for copied files.
- `$UsnJrnl:$J` records create/rename/delete/data-change reasons with timestamps and is the best source for "what happened to files in this folder", including deleted ones.

## Commands

```powershell
MFTECmd.exe -f evidence\$MFT --csv work\mft --csvf mft.csv                     # $SI and $FN times, SI<FN flag
MFTECmd.exe -f evidence\$J -m evidence\$MFT --csv work\mft --csvf usn.csv      # USN with full paths
MFTECmd.exe -f evidence\$LogFile --csv work\mft
# Open in Timeline Explorer; filter by parent path and the incident window.
```
```bash
# plaso: targeted then full (Docker image from log2timeline)
docker run --rm -v "$PWD":/data log2timeline/plaso log2timeline --storage-file /data/work/case.plaso \
  --parsers 'winevtx,prefetch,amcache,lnk,winreg,mft,usnjrnl,chrome_history,firefox_history' /data/evidence/
docker run --rm -v "$PWD":/data log2timeline/plaso psort -o l2tcsv -w /data/work/timeline.csv /data/work/case.plaso \
  "date > '2026-01-05 13:00:00' AND date < '2026-01-05 17:00:00'"
# pinfo shows parser counts and warnings - include failures in Gaps
docker run --rm -v "$PWD":/data log2timeline/plaso pinfo /data/work/case.plaso
```
Docker volume mounts expose `evidence/` read-write to the container by default; add `:ro` to a separate evidence mount: `-v "$PWD/evidence":/data/evidence:ro`.

Sleuth Kit (disk images):
```bash
img_stat evidence/disk.E01 ; mmls evidence/disk.E01                               # partitions (ewf support needed)
fls -r -m C: -o <sector_offset> evidence/disk.E01 > work/bodyfile.txt             # all files incl. deleted (*)
mactime -b work/bodyfile.txt -d -z UTC 2026-01-05..2026-01-06 > work/fs-timeline.csv
icat -o <sector_offset> evidence/disk.E01 <inode> > work/recovered_<inode>.bin    # extract a file (as .bin)
istat -o <sector_offset> evidence/disk.E01 <inode>                                # $SI/$FN detail
```
Mount images read-only only: `ewfmount evidence/disk.E01 /mnt/ewf` then `mount -o ro,loop,noexec,show_sys_files,streams_interface=windows /mnt/ewf/ewf1 /mnt/win` (offset via `mmls`).

Event-log timelines: `hayabusa csv-timeline -d evidence/ -U -o work/hayabusa.csv` gives a Sigma-annotated EVTX timeline that merges well with the MFT and Prefetch CSVs.

Merging: normalise each CSV to `time_utc,source,host,user,event,detail,ref` (a short Python or `csvkit`/`jq` script in `work/`), concatenate, sort by `time_utc`. Keep the script in the case folder so the merge is reproducible.

## Common traps

- plaso's default output timezone is UTC, but the `--timezone` parser option assumes a source timezone for local-time artefacts; set it to the host's zone.
- Prefetch times are the last 8 runs, not all runs. Amcache first-seen is not first execution.
- Browser history uses its own epochs (Chrome: microseconds since 1601; Firefox: microseconds since 1970; Safari: seconds since 2001). Convert explicitly.
- FAT/exFAT store local time; FAT access dates have no time.
- Sorting text timestamps only works with fixed ISO 8601 format and a single timezone.

## Output

The report's Timeline section is a short list of anchor and pivotal events (10-30 rows), each with source reference. The full merged timeline stays in `work/timeline.csv` and is referenced, not pasted.
