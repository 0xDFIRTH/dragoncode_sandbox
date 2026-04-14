"""
hash_lookup.py
==============
Hash computation + threat-intelligence lookup.

Supported backends (tried in order):
  1. VirusTotal v3 public API  — requires VT_API_KEY env var
  2. MalwareBazaar (abuse.ch)  — free, no key needed
"""
from __future__ import annotations

import hashlib
import os
import urllib.request
import urllib.parse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────────────────

@dataclass
class FileHashes:
    md5:    str
    sha1:   str
    sha256: str


@dataclass
class LookupResult:
    source:        str                   # "VirusTotal" | "MalwareBazaar" | "Not Found" | "Error"
    found:         bool = False
    malicious:     int  = 0              # engines that flagged it (VT)
    total_engines: int  = 0
    threat_name:   str  = ""
    threat_label:  str  = ""             # suggested_threat_label (e.g. trojan.win32/agent)
    category:      str  = ""             # popular_threat_category (e.g. trojan)
    tags:          list[str] = field(default_factory=list)
    sandbox_verdicts: list[dict] = field(default_factory=list)
    permalink:     str  = ""
    raw:           dict = field(default_factory=dict)

    @property
    def detection_ratio(self) -> str:
        if self.total_engines:
            return f"{self.malicious} / {self.total_engines}"
        return "N/A"

    @property
    def verdict_label(self) -> str:
        if not self.found:
            return "NOT FOUND"
        if self.malicious == 0:
            return "CLEAN"
        ratio = self.malicious / max(self.total_engines, 1)
        if ratio >= 0.3:
            return "MALICIOUS"
        return "SUSPICIOUS"
# ... (verdict_color property remains same)

    @property
    def verdict_color(self) -> str:
        v = self.verdict_label
        return {
            "MALICIOUS":  "#f78166",
            "SUSPICIOUS": "#d29922",
            "CLEAN":      "#3fb950",
            "NOT FOUND":  "#58a6ff",
        }.get(v, "#8b949e")


# ─────────────────────────────────────────────────────────
#  Hash computation
# ─────────────────────────────────────────────────────────

def compute_hashes(path: str | Path) -> FileHashes:
    data = Path(path).read_bytes()
    return FileHashes(
        md5    = hashlib.md5(data).hexdigest(),
        sha1   = hashlib.sha1(data).hexdigest(),
        sha256 = hashlib.sha256(data).hexdigest(),
    )


# ─────────────────────────────────────────────────────────
#  VirusTotal v3
# ─────────────────────────────────────────────────────────

_VT_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 12


def _vt_lookup(sha256: str, api_key: str) -> LookupResult:
    url = f"{_VT_BASE}/files/{sha256}"
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return LookupResult(source="VirusTotal", found=False)
        raise

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    mal   = stats.get("malicious", 0)
    sus   = stats.get("suspicious", 0)
    total = sum(stats.values())

    # 1. Classification (Suggested label & Category)
    classification = attrs.get("popular_threat_classification", {})
    threat_label   = classification.get("suggested_threat_label", "")
    category       = ""
    categories     = classification.get("popular_threat_category", [])
    if categories:
        category = categories[0].get("value", "")

    # 2. Extract best threat name from engines
    threat_name = ""
    for engine_data in attrs.get("last_analysis_results", {}).values():
        name = engine_data.get("result") or ""
        if name and len(name) > len(threat_name):
            threat_name = name
    
    # 3. Sandbox Verdicts
    sandbox_verdicts = []
    verdicts_obj = attrs.get("sandbox_verdicts", {})
    for sb_name, sb_data in verdicts_obj.items():
        sandbox_verdicts.append({
            "sandbox": sb_name,
            "verdict": sb_data.get("verdict"),
            "category": sb_data.get("category")
        })

    permalink = f"https://www.virustotal.com/gui/file/{sha256}"
    tags = list(set(attrs.get("tags", []))) # Unique tags

    return LookupResult(
        source        = "VirusTotal",
        found         = True,
        malicious     = mal + sus,
        total_engines = total,
        threat_name   = threat_name,
        threat_label  = threat_label,
        category      = category,
        tags          = tags,
        sandbox_verdicts = sandbox_verdicts,
        permalink     = permalink,
        raw           = data,
    )


# ─────────────────────────────────────────────────────────
#  MalwareBazaar (abuse.ch) — no key needed
# ─────────────────────────────────────────────────────────

_MB_URL = "https://mb-api.abuse.ch/api/v1/"


def _mb_lookup(sha256: str) -> LookupResult:
    body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    req  = urllib.request.Request(
        _MB_URL,
        data    = body,
        headers = {"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        data = json.loads(resp.read())

    if data.get("query_status") != "ok":
        return LookupResult(source="MalwareBazaar", found=False)

    sample = (data.get("data") or [{}])[0]
    tags   = sample.get("tags") or []
    sig    = sample.get("signature") or ""
    link   = f"https://bazaar.abuse.ch/sample/{sha256}/"

    return LookupResult(
        source      = "MalwareBazaar",
        found       = True,
        malicious   = 1,
        threat_name = sig,
        tags        = tags,
        permalink   = link,
        raw         = data,
    )


# ─────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────

def lookup_hash(sha256: str, vt_api_key: str = "") -> LookupResult:
    """
    Try VirusTotal first (if API key available), then MalwareBazaar.
    Never raises — always returns a LookupResult.
    """
    key = vt_api_key.strip() or os.environ.get("VT_API_KEY", "").strip()

    if key:
        try:
            return _vt_lookup(sha256, key)
        except Exception as e:
            # Fall through to MalwareBazaar on VT error
            pass

    try:
        return _mb_lookup(sha256)
    except Exception as e:
        return LookupResult(source="Error", found=False, threat_name=str(e))
