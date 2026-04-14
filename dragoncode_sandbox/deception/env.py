from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FakeEnvironment:
    computer_name: str = "DESKTOP-8K32L"
    user_name: str = "JohnDoe"

    def generate_fake_browser_history(self) -> list[str]:
        return [
            "https://www.google.com/search?q=rust+programming",
            "https://stackoverflow.com/questions/12345/how-to-exit-vim",
            "https://news.ycombinator.com/",
            "https://github.com/rust-lang/rust",
            "https://mail.google.com/mail/u/0/#inbox",
        ]

    def generate_fake_documents(self) -> dict[str, str]:
        return {
            r"C:\Users\JohnDoe\Documents\Resume.docx": "[Binary content]",
            r"C:\Users\JohnDoe\Desktop\passwords.txt": "facebook: hunter2",
        }
