from __future__ import annotations

import subprocess
from enum import Enum
from pathlib import Path


class TrustVerdict(str, Enum):
    TRUSTED_SIGNED = "TrustedSigned"
    INVALID_SIGNATURE = "InvalidSignature"
    SELF_SIGNED = "SelfSigned"
    UNSIGNED = "Unsigned"
    STOLEN_CERT = "StolenCert"


class TrustAnalyzer:
    @staticmethod
    def verify_signature(path: Path) -> TrustVerdict:
        if not path.exists():
            return TrustVerdict.UNSIGNED
            
        try:
            # Use PowerShell to check Authenticode Signature
            cmd = ['powershell', '-NoProfile', '-Command', f'(Get-AuthenticodeSignature "{path}").Status.ToString()']
            result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
            status = result.stdout.strip()
            
            if status == "Valid":
                return TrustVerdict.TRUSTED_SIGNED
            elif status == "HashMismatch":
                return TrustVerdict.INVALID_SIGNATURE
            elif status == "NotSigned":
                return TrustVerdict.UNSIGNED
            elif status == "UnknownError" or status == "NotTrusted":
                return TrustVerdict.SELF_SIGNED
                
        except Exception:
            pass
            
        # Fallback heuristical check if PS fails
        file_name = path.name.lower()
        if "microsoft" in file_name or "windows" in file_name:
            return TrustVerdict.INVALID_SIGNATURE # Suspicious if PS failed to validate
            
        return TrustVerdict.UNSIGNED

    @staticmethod
    def check_lolbin_abuse(binary_name: str) -> bool:
        # Expanded LOLBins list
        lolbins = [
            "certutil.exe", "bitsadmin.exe", "powershell.exe", "mshta.exe", 
            "rundll32.exe", "regsvr32.exe", "wmic.exe", "cscript.exe", 
            "wscript.exe", "cmstp.exe", "msbuild.exe", "csc.exe",
            "schtasks.exe", "at.exe", "forfiles.exe"
        ]
        return binary_name.lower() in lolbins
