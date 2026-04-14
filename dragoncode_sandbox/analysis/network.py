from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class NetworkMonitor:
    tls_fingerprints: dict[str, int] = field(default_factory=dict)
    dns_queries: dict[str, list[int]] = field(default_factory=dict)

    def analyze_beacon_intervals(self) -> list[str]:
        beacons: list[str] = []
        for domain, timestamps in self.dns_queries.items():
            if len(timestamps) < 3:
                continue

            deltas: list[int] = []
            for i in range(len(timestamps) - 1):
                deltas.append(timestamps[i + 1] - timestamps[i])

            avg = sum(deltas) / float(len(deltas))
            variance = sum((d - avg) ** 2 for d in deltas) / float(len(deltas))

            if variance < 5.0:
                beacons.append(domain)

        return beacons

    def log_ja3(self, _packet_data: bytes) -> None:
        fp = "e7d705a3286e2..."
        self.tls_fingerprints[fp] = self.tls_fingerprints.get(fp, 0) + 1
