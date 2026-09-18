from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


RESULTS_BY_QUALIFIER = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}


@dataclass(frozen=True)
class SPFMechanism:
    qualifier: str
    name: str
    value: Optional[str] = None


@dataclass(frozen=True)
class SPFRecord:
    domain: str
    raw: str
    mechanisms: Tuple[SPFMechanism, ...]
    redirect: Optional[str] = None
    explanation: Optional[str] = None


@dataclass(frozen=True)
class SPFCheckResult:
    domain: str
    ip: str
    result: str
    matched_mechanism: Optional[str] = None
    record: Optional[str] = None
    explanation: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "domain": self.domain,
            "ip": self.ip,
            "result": self.result,
            "matched_mechanism": self.matched_mechanism,
            "record": self.record,
            "explanation": self.explanation,
        }


@dataclass
class ResolvedSPF:
    domain: str
    record: Optional[str]
    includes: List["ResolvedSPF"] = field(default_factory=list)
    redirect: Optional["ResolvedSPF"] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "domain": self.domain,
            "record": self.record,
        }
        if self.includes:
            payload["includes"] = [item.to_dict() for item in self.includes]
        if self.redirect is not None:
            payload["redirect"] = self.redirect.to_dict()
        if self.error is not None:
            payload["error"] = self.error
        return payload


class SystemDNSResolver:
    def txt_records(self, domain: str) -> List[str]:
        dig_output = self._run_dns_command(["dig", "+short", "TXT", domain])
        if dig_output is not None:
            records = []
            for line in dig_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                records.append("".join(re.findall(r'"([^"]*)"', line)))
            if records:
                return records

        nslookup_output = self._run_dns_command(["nslookup", "-type=TXT", domain])
        if nslookup_output is not None:
            matches = re.findall(r'"([^"]*)"', nslookup_output)
            if matches:
                return matches

        return []

    def addresses(self, domain: str) -> List[str]:
        addresses = set()
        try:
            for entry in socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP):
                addresses.add(entry[4][0])
        except socket.gaierror:
            return []
        return sorted(addresses)

    def mx_hosts(self, domain: str) -> List[str]:
        dig_output = self._run_dns_command(["dig", "+short", "MX", domain])
        if dig_output is not None:
            hosts = []
            for line in dig_output.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    hosts.append(parts[1].rstrip("."))
            if hosts:
                return hosts

        nslookup_output = self._run_dns_command(["nslookup", "-type=MX", domain])
        if nslookup_output is not None:
            matches = re.findall(r"mail exchanger = ([^\s]+)", nslookup_output)
            if matches:
                return [item.rstrip(".") for item in matches]

        return []

    @staticmethod
    def _run_dns_command(command: Sequence[str]) -> Optional[str]:
        if shutil.which(command[0]) is None:
            return None
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            return None
        return completed.stdout


class SPFResolver:
    def __init__(self, dns_resolver: Optional[SystemDNSResolver] = None, max_depth: int = 10):
        self.dns_resolver = dns_resolver or SystemDNSResolver()
        self.max_depth = max_depth

    def resolve(self, domain: str) -> ResolvedSPF:
        return self._resolve(domain, seen=(), depth=0)

    def _resolve(self, domain: str, seen: Tuple[str, ...], depth: int) -> ResolvedSPF:
        if depth > self.max_depth:
            return ResolvedSPF(domain=domain, record=None, error="SPF resolution exceeded the maximum recursion depth")

        if domain in seen:
            return ResolvedSPF(domain=domain, record=None, error="Cyclic SPF include/redirect detected")

        try:
            record = self.get_spf_record(domain)
        except ValueError as error:
            return ResolvedSPF(domain=domain, record=None, error=str(error))

        if record is None:
            return ResolvedSPF(domain=domain, record=None, error="No SPF record found")

        parsed = self.parse_spf_record(domain, record)
        next_seen = seen + (domain,)
        includes = [
            self._resolve(mechanism.value, next_seen, depth + 1)
            for mechanism in parsed.mechanisms
            if mechanism.name == "include" and mechanism.value
        ]
        redirect = self._resolve(parsed.redirect, next_seen, depth + 1) if parsed.redirect else None
        return ResolvedSPF(domain=domain, record=record, includes=includes, redirect=redirect)

    def get_spf_record(self, domain: str) -> Optional[str]:
        spf_records = [record for record in self.dns_resolver.txt_records(domain) if record.lower().startswith("v=spf1")]
        if not spf_records:
            return None
        if len(spf_records) > 1:
            raise ValueError(f"Multiple SPF records found for {domain}")
        return spf_records[0]

    def parse_spf_record(self, domain: str, record: str) -> SPFRecord:
        parts = record.split()
        if not parts or parts[0].lower() != "v=spf1":
            raise ValueError(f"Invalid SPF record for {domain}")

        mechanisms: List[SPFMechanism] = []
        redirect = None
        explanation = None

        for token in parts[1:]:
            if "=" in token:
                name, value = token.split("=", 1)
                if name == "redirect":
                    redirect = value
                elif name == "exp":
                    explanation = value
                continue

            qualifier = "+"
            if token[0] in RESULTS_BY_QUALIFIER:
                qualifier = token[0]
                token = token[1:]

            if ":" in token:
                name, value = token.split(":", 1)
            elif "/" in token:
                name, value = token.split("/", 1)
                value = f"/{value}"
            else:
                name, value = token, None
            mechanisms.append(SPFMechanism(qualifier=qualifier, name=name, value=value))

        return SPFRecord(
            domain=domain,
            raw=record,
            mechanisms=tuple(mechanisms),
            redirect=redirect,
            explanation=explanation,
        )

    def check_ip(self, domain: str, ip: str) -> SPFCheckResult:
        ip_address = ipaddress.ip_address(ip)
        result, mechanism, record = self._evaluate(domain, ip_address, depth=0, seen=())
        return SPFCheckResult(
            domain=domain,
            ip=ip,
            result=result,
            matched_mechanism=mechanism,
            record=record,
        )

    def _evaluate(
        self,
        domain: str,
        ip_address: ipaddress._BaseAddress,
        depth: int,
        seen: Tuple[str, ...],
    ) -> Tuple[str, Optional[str], Optional[str]]:
        if depth > self.max_depth or domain in seen:
            return "permerror", None, None

        try:
            record = self.get_spf_record(domain)
        except ValueError:
            return "permerror", None, None

        if record is None:
            return "none", None, None

        parsed = self.parse_spf_record(domain, record)
        next_seen = seen + (domain,)

        for mechanism in parsed.mechanisms:
            try:
                matched = self._mechanism_matches(domain, mechanism, ip_address, depth, next_seen)
            except ValueError:
                return "permerror", None, record
            if matched:
                return RESULTS_BY_QUALIFIER[mechanism.qualifier], self._format_mechanism(mechanism), record

        if parsed.redirect:
            redirected, matched, redirected_record = self._evaluate(parsed.redirect, ip_address, depth + 1, next_seen)
            return redirected, matched, redirected_record

        return "neutral", None, record

    def _mechanism_matches(
        self,
        domain: str,
        mechanism: SPFMechanism,
        ip_address: ipaddress._BaseAddress,
        depth: int,
        seen: Tuple[str, ...],
    ) -> bool:
        if mechanism.name == "all":
            return True

        if mechanism.name == "ip4" and ip_address.version == 4 and mechanism.value:
            return self._ip_in_network(ip_address, mechanism.value)

        if mechanism.name == "ip6" and ip_address.version == 6 and mechanism.value:
            return self._ip_in_network(ip_address, mechanism.value)

        if mechanism.name == "include" and mechanism.value:
            result, _, _ = self._evaluate(mechanism.value, ip_address, depth + 1, seen)
            return result == "pass"

        if mechanism.name == "a":
            target_domain, ipv4_length, ipv6_length = self._parse_domain_and_cidr(mechanism.value)
            return self._ip_matches_resolved_addresses(
                target_domain or domain,
                ip_address,
                ipv4_length,
                ipv6_length,
            )

        if mechanism.name == "mx":
            target_domain, ipv4_length, ipv6_length = self._parse_domain_and_cidr(mechanism.value)
            hosts = self.dns_resolver.mx_hosts(target_domain or domain)
            return any(
                self._ip_matches_resolved_addresses(host, ip_address, ipv4_length, ipv6_length)
                for host in hosts
            )

        if mechanism.name == "exists" and mechanism.value:
            if "%" in mechanism.value:
                raise ValueError("SPF macros are not supported")
            return bool(self.dns_resolver.addresses(mechanism.value))

        return False

    @staticmethod
    def _format_mechanism(mechanism: SPFMechanism) -> str:
        prefix = "" if mechanism.qualifier == "+" else mechanism.qualifier
        if mechanism.value is None:
            return f"{prefix}{mechanism.name}"
        if mechanism.value.startswith("/"):
            return f"{prefix}{mechanism.name}{mechanism.value}"
        return f"{prefix}{mechanism.name}:{mechanism.value}"

    @staticmethod
    def _ip_in_network(ip_address: ipaddress._BaseAddress, network: str) -> bool:
        candidate = ipaddress.ip_network(network, strict=False)
        return ip_address in candidate

    @staticmethod
    def _parse_domain_and_cidr(value: Optional[str]) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        if value is None:
            return None, None, None

        parts = value.split("/")
        if len(parts) > 3:
            raise ValueError(f"Invalid SPF mechanism value: {value}")

        domain = parts[0] or None
        ipv4_length = int(parts[1]) if len(parts) >= 2 and parts[1] else None
        ipv6_length = int(parts[2]) if len(parts) == 3 and parts[2] else None
        return domain, ipv4_length, ipv6_length

    def _ip_matches_resolved_addresses(
        self,
        domain: str,
        ip_address: ipaddress._BaseAddress,
        ipv4_length: Optional[int],
        ipv6_length: Optional[int],
    ) -> bool:
        for candidate in self.dns_resolver.addresses(domain):
            try:
                resolved = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if resolved.version != ip_address.version:
                continue
            prefix_length = ipv4_length if resolved.version == 4 else ipv6_length
            network = ipaddress.ip_network(f"{resolved}/{prefix_length or resolved.max_prefixlen}", strict=False)
            if ip_address in network:
                return True
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve SPF records and evaluate sender IP addresses.")
    parser.add_argument("domain", help="Domain to inspect")
    parser.add_argument("--ip", help="Sender IP address to validate against the domain's SPF policy")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    resolver = SPFResolver()

    if args.ip:
        try:
            result = resolver.check_ip(args.domain, args.ip)
        except ValueError:
            print(f"Invalid IP address: {args.ip}", file=sys.stderr)
            return 2
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print(json.dumps(resolver.resolve(args.domain).to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
