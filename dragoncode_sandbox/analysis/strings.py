from __future__ import annotations

import re
import string
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ExtractedStrings:
    urls: list[str]
    ips: list[str]
    registries: list[str]
    base64: list[str]
    all_strings_count: int


class StringAnalyzer:
    URL_REGEX = re.compile(rb'(?i)\b((?:https?|ftp)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])')
    IP_REGEX = re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    REG_REGEX = re.compile(rb'(?i)(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[a-zA-Z0-9_\-\\]+')
    B64_REGEX = re.compile(rb'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

    @staticmethod
    def _extract_all_strings(data: bytes, min_length: int = 4) -> list[bytes]:
        pattern = rb'[\x20-\x7E]{%d,}' % min_length
        return re.findall(pattern, data)

    @classmethod
    def analyze(cls, path: Path) -> ExtractedStrings:
        if not path.exists():
            return ExtractedStrings([], [], [], [], 0)

        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception:
            return ExtractedStrings([], [], [], [], 0)

        # Apply specific regexes on the binary data directly for speed
        urls = [m.decode('utf-8', 'ignore') for m in cls.URL_REGEX.findall(data)]
        ips = [m.decode('utf-8', 'ignore') for m in cls.IP_REGEX.findall(data)]
        registries = [m.decode('utf-8', 'ignore') for m in cls.REG_REGEX.findall(data)]
        # Add basic filtering for base64 to avoid FPs
        b64 = []
        for x in cls.B64_REGEX.findall(data):
            try:
                dec = x.decode('ascii')
                # Optional: Do actual base64 decoding check here if needed
                b64.append(dec)
            except:
                pass

        all_str = cls._extract_all_strings(data)
        
        return ExtractedStrings(
            urls=list(set(urls)),
            ips=list(set(ips)),
            registries=list(set(registries)),
            base64=list(set(b64)),
            all_strings_count=len(all_str)
        )
