from dataclasses import dataclass, field, asdict


@dataclass
class SubdomainEntry:
    name: str
    ips: list[str]
    risky: bool = False


@dataclass
class PortEntry:
    port: int
    service: str
    risky: bool = False
    status: str = "ochiq"


@dataclass
class InfrastructureInfo:
    host: str
    primary_ips: list[str] = field(default_factory=list)
    subdomains: list[SubdomainEntry] = field(default_factory=list)
    ports: list[PortEntry] = field(default_factory=list)
    unique_ips: list[str] = field(default_factory=list)
    dns: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "primary_ips": self.primary_ips,
            "unique_ips": self.unique_ips,
            "subdomains": [asdict(s) for s in self.subdomains],
            "ports": [asdict(p) for p in self.ports],
            "dns": self.dns,
        }

    @staticmethod
    def collect_unique_ips(primary: list[str], subdomains: list[SubdomainEntry]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for ip in primary:
            if ip not in seen:
                seen.add(ip)
                ordered.append(ip)
        for sub in subdomains:
            for ip in sub.ips:
                if ip not in seen:
                    seen.add(ip)
                    ordered.append(ip)
        return ordered
