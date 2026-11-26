import re
from dataclasses import dataclass
from pathlib import Path

from .analysis import read_local_file, text_view


TAG_ALIASES = {
    "binary-exploitation": "pwn", "blueteam": "blue-team", "crypto": "cryptography",
    "dfir": "forensics", "redteam": "red-team", "rev": "reverse",
    "reverse-engineering": "reverse", "steganography": "stego",
}
EDITOR_TAGS = {
    "blue-team", "cryptography", "encoding", "forensics", "misc", "osint",
    "pwn", "red-team", "reverse", "stego", "web",
}
DECODING_HINTS = {
    "hex": r"\bhex(?:adecimal)?\b",
    "base64": r"\bbase[ -]?64\b",
    "base32": r"\bbase[ -]?32\b",
    "url": r"\b(?:percent[ -]encod(?:ing|ed)|url[ -]encod(?:ing|ed))\b",
    "rot13": r"\brot[ -]?13\b",
    "gzip": r"\bgzip\b",
}


def category_tag(value: str) -> str:
    tag = re.sub(r"[ _]+", "-", value.strip().lower().removeprefix("#"))
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", tag):
        raise ValueError("Use a category tag starting with a letter and up to 32 letters, digits, or hyphens.")
    return TAG_ALIASES.get(tag, tag)


@dataclass(frozen=True)
class ChallengeContext:
    category: str | None
    description: str

    def editor_metadata(self) -> dict:
        return {
            "category": self.category if self.category in EDITOR_TAGS else None,
            "description_hints": [
                decoder for decoder, pattern in DECODING_HINTS.items()
                if re.search(pattern, self.description, re.IGNORECASE)
            ],
        }


def load_context(category: str | None, description_file: str | None) -> ChallengeContext:
    if not description_file:
        return ChallengeContext(category, "")
    try:
        description = text_view(read_local_file(Path(description_file), 8192))
    except (OSError, ValueError) as error:
        raise ValueError(f"Could not read the description file. {error}") from error
    if description is None:
        raise ValueError("The description file must contain UTF-8 text.")
    description = description.strip()
    header = re.match(r"category:[ \t]*([^\r\n]+)", description, re.IGNORECASE)
    if header:
        if category is None:
            category = category_tag(header[1])
        description = description[header.end():].lstrip()
    return ChallengeContext(category, description)
