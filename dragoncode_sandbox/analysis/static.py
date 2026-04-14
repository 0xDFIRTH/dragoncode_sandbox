from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .hash_lookup import FileHashes, compute_hashes


@dataclass(slots=True)
class SectionInfo:
    name: str
    entropy: float
    virtual_size: int
    raw_size: int


@dataclass(slots=True)
class StaticAnalysisResult:
    is_packed: bool
    imports: list[str]
    exports: list[str]
    sections: list[SectionInfo]
    threat_score: int
    hashes: Optional[FileHashes] = None


class StaticEngine:
    @staticmethod
    def analyze_file(path: str | Path) -> StaticAnalysisResult:
        p = Path(path)
        buffer = p.read_bytes()

        # Compute hashes up-front (fast, always available)
        hashes = compute_hashes(p)

        score = 0
        imports: list[str] = []
        exports: list[str] = []
        sections: list[SectionInfo] = []
        is_packed = False

        pefile: Any
        try:
            import pefile as _pefile  # type: ignore

            pefile = _pefile
        except Exception:
            pefile = None

        if pefile is not None:
            try:
                pe = pefile.PE(data=buffer)

                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                    for imp in getattr(entry, "imports", []) or []:
                        name = ""
                        if getattr(imp, "name", None):
                            name = bytes(imp.name).decode(errors="ignore")
                        else:
                            name = f"ordinal_{getattr(imp, 'ordinal', 0)}"

                        if StaticEngine._is_suspicious_import(name):
                            score += 15
                        imports.append(name)

                exp_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
                if exp_dir is not None:
                    for sym in getattr(exp_dir, "symbols", []) or []:
                        if getattr(sym, "name", None):
                            exports.append(bytes(sym.name).decode(errors="ignore"))

                for section in getattr(pe, "sections", []) or []:
                    name = bytes(section.Name).rstrip(b"\x00").decode(errors="ignore")
                    data = bytes(section.get_data() or b"")
                    entropy = StaticEngine._calculate_entropy(data)

                    if entropy > 7.0 and name != ".rsrc":
                        score += 20
                        is_packed = True

                    characteristics = int(getattr(section, "Characteristics", 0))
                    if (characteristics & 0x20000000) != 0 and (characteristics & 0x80000000) != 0:
                        score += 30

                    sections.append(
                        SectionInfo(
                            name=name,
                            entropy=entropy,
                            virtual_size=int(getattr(section, "Misc_VirtualSize", 0)),
                            raw_size=int(getattr(section, "SizeOfRawData", 0)),
                        )
                    )

            except Exception:
                score += 5
        else:
            if not buffer.startswith(b"MZ"):
                score += 5
            else:
                entropy = StaticEngine._calculate_entropy(buffer)
                if entropy > 7.0 and len(buffer) > 4096:
                    score += 20
                    is_packed = True

        return StaticAnalysisResult(
            is_packed=is_packed,
            imports=imports,
            exports=exports,
            sections=sections,
            threat_score=min(score, 100),
            hashes=hashes,
        )

    @staticmethod
    def _is_suspicious_import(name: str) -> bool:
        suspicious = [
            "VirtualAlloc",
            "VirtualProtect",
            "CreateRemoteThread",
            "WriteProcessMemory",
            "SetWindowsHookEx",
            "URLDownloadToFile",
            "ShellExecute",
            "RegSetValue",
            "IsDebuggerPresent",
        ]
        return any(s in name for s in suspicious)

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0

        counts = [0] * 256
        for b in data:
            counts[b] += 1

        length = float(len(data))
        entropy = 0.0
        for c in counts:
            if c:
                p = c / length
                entropy -= p * 0.0  # placeholder; overwritten below

        entropy = 0.0
        for c in counts:
            if c:
                p = c / length
                entropy -= p * _log2(p)

        return entropy


def _log2(x: float) -> float:
    import math

    return math.log(x, 2)
