from __future__ import annotations


class ScriptAnalyzer:
    @staticmethod
    def analyze_powershell(script_content: str) -> int:
        score = 0
        suspicious_keywords = [
            "Invoke-Expression",
            "IEX",
            "DownloadString",
            "Net.WebClient",
            "-Enc",
            "FromBase64String",
            "Bypass",
            "Hidden",
        ]

        lower = script_content.lower()
        for keyword in suspicious_keywords:
            if keyword.lower() in lower:
                score += 15

        return min(score, 100)

    @staticmethod
    def analyze_python(script_content: str) -> int:
        score = 0
        if "ctypes.windll" in script_content:
            score += 20
        if "socket.socket" in script_content:
            score += 10
        if "subprocess.Popen" in script_content:
            score += 10
        return min(score, 100)
