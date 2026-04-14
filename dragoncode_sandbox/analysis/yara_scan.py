from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os

try:
    import yara
except ImportError:
    yara = None

@dataclass(slots=True)
class YaraMatch:
    rule_name: str
    namespace: str
    tags: list[str]
    description: str


class YaraScanner:
    def __init__(self, rules_dir: Path):
        self.rules_dir = Path(rules_dir)
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        if not yara:
            return
            
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            self._create_dummy_rule()

        filepaths = {}
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yar') or file.endswith('.yara'):
                    name = Path(file).stem
                    filepaths[name] = os.path.join(root, file)

        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
            except Exception as e:
                print(f"[YARA] Compile error: {e}")

    def _create_dummy_rule(self):
        dummy_path = self.rules_dir / "basic_malware.yar"
        if not dummy_path.exists():
            dummy_path.write_text("""
rule Suspicious_API_Calls {
    meta:
        description = "Detects common suspicious API combinations"
        author = "DragonCode"
    strings:
        $s1 = "VirtualAlloc" ascii fullword
        $s2 = "CreateRemoteThread" ascii fullword
        $s3 = "WriteProcessMemory" ascii fullword
    condition:
        2 of ($s*)
}

rule Packed_UPX {
    meta:
        description = "Detects UPX packed files"
        author = "DragonCode"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        all of them
}
            """, encoding="utf-8")

    def scan_file(self, target_path: Path) -> list[YaraMatch]:
        if not yara or not self.rules or not target_path.exists():
            return []

        try:
            matches = self.rules.match(str(target_path))
            result = []
            for m in matches:
                desc = "-"
                # Parse meta
                if hasattr(m, 'meta') and isinstance(m.meta, dict):
                    desc = m.meta.get('description', '-')
                
                result.append(YaraMatch(
                    rule_name=m.rule,
                    namespace=m.namespace,
                    tags=list(m.tags),
                    description=desc
                ))
            return result
        except Exception as e:
            print(f"[YARA] Match error: {e}")
            return []
