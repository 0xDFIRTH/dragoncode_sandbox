from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class FakeOS:
    version: str
    build_number: int
    product_type: str

    @staticmethod
    def windows_10_enterprise() -> "FakeOS":
        return FakeOS(version="10.0", build_number=19045, product_type="Enterprise")

    @staticmethod
    def windows_7_sp1() -> "FakeOS":
        return FakeOS(version="6.1", build_number=7601, product_type="Professional")

    def populate_environment(self) -> None:
        os.environ["OS"] = "Windows_NT"
