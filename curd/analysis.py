import base64
import binascii
import codecs
import gzip
import hashlib
import io
import os
import re
import stat
import zlib
from collections import deque
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from urllib.parse import unquote_to_bytes


MAX_FILE = 1024 * 1024
MAX_DEPTH = 3
MAX_NODES = 80
DEFAULT_PREFIXES = ("flag", "ctf", "picoCTF", "HTB", "THM")
METHODS = {
    "hex": ("Hex", "Even-length hexadecimal digits suggested a byte representation."),
    "base64": ("Base64", "The character set and padding were consistent with Base64."),
    "base32": ("Base32", "The compact text fit the Base32 alphabet."),
    "url": ("Percent decoding", "Percent escapes suggested URL-encoded bytes."),
    "rot13": ("ROT13", "The text contained letters I could test with a fixed Caesar shift."),
    "gzip": ("Gzip", "The first two bytes matched the Gzip signature."),
}


@dataclass
class Attempt:
    path: tuple[str, ...]
    outcome: str


@dataclass
class Findings:
    size: int
    sha256: str
    initial_format: str
    attempts: list[Attempt]
    candidates: dict[str, tuple[str, ...]]
    limit_reached: bool


def read_local_file(path: Path, max_size: int) -> bytes:
    if os.name == "nt" and str(path).startswith(("\\\\", "//")):
        raise ValueError("Use a local file path.")
    path = path.resolve(strict=True)
    if os.name == "nt" and str(path).startswith(("\\\\", "//")):
        raise ValueError("Use a local file path.")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("The input must be a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("The input must be a regular file.")
        if metadata.st_size > max_size:
            raise ValueError(f"The input exceeds the {max_size:,}-byte limit.")
        data = stream.read(max_size + 1)
    if len(data) > max_size:
        raise ValueError(f"The input exceeds the {max_size:,}-byte limit.")
    return data


def text_view(data: bytes) -> str | None:
    try:
        value = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    return value if all(char.isprintable() or char in "\r\n\t" for char in value) else None


def decompress(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
        result = source.read(MAX_FILE + 1)
    if len(result) > MAX_FILE:
        raise OverflowError
    return result


def plausible_transforms(data: bytes, value: str | None):
    if data.startswith(b"\x1f\x8b"):
        yield "gzip", lambda: decompress(data)
    if value is None or not value.isascii():
        return
    compact = "".join(value.split())
    if len(compact) >= 2 and len(compact) % 2 == 0 and re.fullmatch(r"[a-fA-F0-9]+", compact):
        yield "hex", lambda: bytes.fromhex(compact)
    if len(compact) >= 4 and re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", compact):
        if len(compact) % 4 != 1 and ("=" not in compact or len(compact) % 4 == 0):
            padded = compact + "=" * (-len(compact) % 4)
            yield "base64", lambda: base64.b64decode(padded, altchars=b"-_", validate=True)
    up = compact.upper()
    if len(up) >= 4 and re.fullmatch(r"[A-Z2-7]+=*", up):
        if len(up.rstrip("=")) % 8 in (0, 2, 4, 5, 7) and ("=" not in up or len(up) % 8 == 0):
            yield "base32", lambda: base64.b32decode(up + "=" * (-len(up) % 8))
    if re.search(r"%[0-9A-Fa-f]{2}", value):
        yield "url", lambda: unquote_to_bytes(value)
    if re.search(r"[A-Za-z]", value):
        yield "rot13", lambda: codecs.encode(value, "rot_13").encode("ascii")


def analyze(data: bytes, prefixes: tuple[str, ...]) -> Findings:
    prefix_pattern = "|".join(re.escape(prefix) for prefix in prefixes)
    flag_pattern = re.compile(
        r"(?<![A-Za-z0-9_])(?:" + prefix_pattern + r")\{[A-Za-z0-9_.:@!+/=-]{1,128}\}",
        re.IGNORECASE | re.ASCII,
    )
    initial_text = text_view(data)
    initial_format = (
        "gzip" if data.startswith(b"\x1f\x8b") else "text" if initial_text is not None else "binary"
    )
    findings = Findings(len(data), hashlib.sha256(data).hexdigest(), initial_format, [], {}, False)
    if initial_text is not None:
        for match in islice(flag_pattern.finditer(initial_text), 8):
            findings.candidates[match.group()] = ()
    pending = deque([(data, initial_text, ())])
    seen = {findings.sha256}
    while pending:
        current, value, path = pending.popleft()
        if len(path) >= MAX_DEPTH:
            findings.limit_reached = True
            continue
        for method, transform in plausible_transforms(current, value):
            next_path = (*path, method)
            try:
                decoded = transform()
            except OverflowError:
                findings.attempts.append(Attempt(next_path, "size-limit"))
                continue
            except (ValueError, OSError, EOFError, binascii.Error, zlib.error):
                findings.attempts.append(Attempt(next_path, "invalid"))
                continue
            digest = hashlib.sha256(decoded).hexdigest()
            if digest in seen:
                continue
            if len(seen) >= MAX_NODES:
                findings.limit_reached = True
                return findings
            seen.add(digest)
            decoded_text = text_view(decoded)
            outcome = "binary" if decoded_text is None else "text"
            if decoded_text is not None:
                for match in flag_pattern.finditer(decoded_text):
                    outcome = "candidate"
                    if len(findings.candidates) >= 8:
                        break
                    findings.candidates.setdefault(match.group(), next_path)
            findings.attempts.append(Attempt(next_path, outcome))
            if outcome != "candidate":
                pending.append((decoded, decoded_text, next_path))
    return findings
