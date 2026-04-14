from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CampaignMatch:
    name: str
    confidence: float
    matched_iocs: list[str]
    attack_techniques: list[str]


@dataclass(slots=True)
class CampaignTracker:
    known_campaigns: dict[str, dict] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.known_campaigns:
            self._load_defaults()

    def _load_defaults(self) -> None:
        self.known_campaigns["APT28 (Fancy Bear)"] = {
            "iocs": ["zebra.exe", "192.168.1.100", "powershell.exe -enc", "rundll32.exe"],
            "techniques": ["T1059.001 - PowerShell", "T1055 - Process Injection"]
        }
        self.known_campaigns["Emotet (Epoch 5)"] = {
            "iocs": ["payment_doc.js", "certutil.exe -urlcache", "wscript.exe"],
            "techniques": ["T1059.005 - VBScript", "T1105 - Ingress Tool Transfer"]
        }
        self.known_campaigns["Lazarus Group"] = {
            "iocs": ["bitsadmin.exe /transfer", "C:\\Windows\\Temp\\~dat.tmp"],
            "techniques": ["T1197 - BITS Jobs", "T1036 - Masquerading"]
        }
        self.known_campaigns["Ransomware (LockBit)"] = {
            "iocs": ["vssadmin.exe delete shadows", "bcdedit /set {default} recoveryenabled no", ".lockbit"],
            "techniques": ["T1490 - Inhibit System Recovery", "T1486 - Data Encrypted for Impact"]
        }

    def correlate(self, iocs: list[str]) -> CampaignMatch | None:
        best_match = None
        highest_confidence = 0.0
        
        # Unify IOCs to lower string for matching
        normalized_iocs = [str(ioc).lower() for ioc in iocs]

        for campaign, data in self.known_campaigns.items():
            camp_iocs = [str(i).lower() for i in data["iocs"]]
            matched = [ioc for ioc in camp_iocs if any(ioc in n_ioc or n_ioc in ioc for n_ioc in normalized_iocs)]
            
            if matched:
                confidence = len(matched) / max(1, len(camp_iocs))
                if confidence > highest_confidence:
                    highest_confidence = confidence
                    best_match = CampaignMatch(
                        name=campaign,
                        confidence=confidence,
                        matched_iocs=matched,
                        attack_techniques=data["techniques"]
                    )
        
        return best_match
