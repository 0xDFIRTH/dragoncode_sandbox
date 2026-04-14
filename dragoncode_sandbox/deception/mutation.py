from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class EnvironmentMutator:
    desktop_path: Path

    def randomize(self) -> None:
        rng = random.Random()
        self._create_fake_files(rng)

    def _create_fake_files(self, rng: random.Random) -> None:
        filenames = [
            "Passwords.txt",
            "Resume.docx",
            "Budget_2025.xlsx",
            "Family_Photo.jpg",
            "Keys.txt",
            "bitcoin_wallet.dat",
        ]

        contents = [
            "admin:admin123",
            "TODO: Buy milk",
            "Salary: 50000",
            "CONFIDENTIAL",
            "Mnemonic phrase...",
        ]

        num_files = rng.randint(3, 5)
        self.desktop_path.mkdir(parents=True, exist_ok=True)

        for _ in range(num_files):
            name = rng.choice(filenames)
            content = rng.choice(contents)
            path = self.desktop_path / name
            path.write_text(content, encoding="utf-8", errors="ignore")
