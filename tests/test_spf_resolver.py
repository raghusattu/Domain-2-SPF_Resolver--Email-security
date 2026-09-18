import contextlib
import io
import unittest

from spf_resolver import SPFResolver, main


class FakeDNSResolver:
    def __init__(self, txt=None, addresses=None, mx=None):
        self._txt = txt or {}
        self._addresses = addresses or {}
        self._mx = mx or {}

    def txt_records(self, domain):
        return list(self._txt.get(domain, []))

    def addresses(self, domain):
        return list(self._addresses.get(domain, []))

    def mx_hosts(self, domain):
        return list(self._mx.get(domain, []))


class SPFResolverTests(unittest.TestCase):
    def test_returns_single_spf_record(self):
        resolver = SPFResolver(FakeDNSResolver(txt={"example.com": ["google-site-verification=abc", "v=spf1 ip4:203.0.113.0/24 -all"]}))

        record = resolver.get_spf_record("example.com")

        self.assertEqual("v=spf1 ip4:203.0.113.0/24 -all", record)

    def test_include_mechanism_passes_for_authorized_ip(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={
                    "example.com": ["v=spf1 include:_spf.sender.test -all"],
                    "_spf.sender.test": ["v=spf1 ip4:198.51.100.0/24 -all"],
                }
            )
        )

        result = resolver.check_ip("example.com", "198.51.100.12")

        self.assertEqual("pass", result.result)
        self.assertEqual("include:_spf.sender.test", result.matched_mechanism)

    def test_redirect_is_used_when_no_mechanism_matches(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={
                    "example.com": ["v=spf1 redirect=_spf.example.net"],
                    "_spf.example.net": ["v=spf1 ip4:192.0.2.0/24 -all"],
                }
            )
        )

        result = resolver.check_ip("example.com", "192.0.2.40")

        self.assertEqual("pass", result.result)
        self.assertEqual("ip4:192.0.2.0/24", result.matched_mechanism)

    def test_a_and_mx_mechanisms_match_resolved_hosts(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={"example.com": ["v=spf1 a mx -all"]},
                addresses={
                    "example.com": ["203.0.113.7"],
                    "mx1.example.com": ["203.0.113.8"],
                },
                mx={"example.com": ["mx1.example.com"]},
            )
        )

        self.assertEqual("pass", resolver.check_ip("example.com", "203.0.113.7").result)
        self.assertEqual("pass", resolver.check_ip("example.com", "203.0.113.8").result)

    def test_all_qualifier_softfails_unauthorized_ip(self):
        resolver = SPFResolver(FakeDNSResolver(txt={"example.com": ["v=spf1 ip4:203.0.113.0/24 ~all"]}))

        result = resolver.check_ip("example.com", "198.51.100.20")

        self.assertEqual("softfail", result.result)
        self.assertEqual("~all", result.matched_mechanism)

    def test_invalid_ip_mechanism_returns_permerror(self):
        resolver = SPFResolver(FakeDNSResolver(txt={"example.com": ["v=spf1 ip4:not-a-network -all"]}))

        result = resolver.check_ip("example.com", "198.51.100.20")

        self.assertEqual("permerror", result.result)

    def test_exists_matches_when_target_domain_resolves(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={"example.com": ["v=spf1 exists:ipv6-only.example.net -all"]},
                addresses={"ipv6-only.example.net": ["2001:db8::10"]},
            )
        )

        result = resolver.check_ip("example.com", "198.51.100.20")

        self.assertEqual("pass", result.result)
        self.assertEqual("exists:ipv6-only.example.net", result.matched_mechanism)

    def test_dual_cidr_syntax_is_supported_for_a_mechanism(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={"example.com": ["v=spf1 a/24/64 -all"]},
                addresses={"example.com": ["203.0.113.25", "2001:db8::25"]},
            )
        )

        ipv4_result = resolver.check_ip("example.com", "203.0.113.200")
        ipv6_result = resolver.check_ip("example.com", "2001:db8::99")

        self.assertEqual("pass", ipv4_result.result)
        self.assertEqual("a/24/64", ipv4_result.matched_mechanism)
        self.assertEqual("pass", ipv6_result.result)
        self.assertEqual("a/24/64", ipv6_result.matched_mechanism)

    def test_resolve_returns_include_tree(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={
                    "example.com": ["v=spf1 include:_spf.sender.test redirect=_spf.redirect.test"],
                    "_spf.sender.test": ["v=spf1 ip4:198.51.100.0/24 -all"],
                    "_spf.redirect.test": ["v=spf1 ip4:192.0.2.0/24 -all"],
                }
            )
        )

        resolved = resolver.resolve("example.com").to_dict()

        self.assertEqual("example.com", resolved["domain"])
        self.assertEqual("_spf.sender.test", resolved["includes"][0]["domain"])
        self.assertEqual("_spf.redirect.test", resolved["redirect"]["domain"])

    def test_resolve_detects_cycles(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={
                    "example.com": ["v=spf1 include:loop.example.net"],
                    "loop.example.net": ["v=spf1 redirect=example.com"],
                }
            )
        )

        resolved = resolver.resolve("example.com").to_dict()

        self.assertEqual("Cyclic SPF include/redirect detected", resolved["includes"][0]["redirect"]["error"])

    def test_resolve_honors_max_depth(self):
        resolver = SPFResolver(
            FakeDNSResolver(
                txt={
                    "example.com": ["v=spf1 include:level1.example.net"],
                    "level1.example.net": ["v=spf1 include:level2.example.net"],
                    "level2.example.net": ["v=spf1 include:level3.example.net"],
                    "level3.example.net": ["v=spf1 -all"],
                }
            ),
            max_depth=1,
        )

        resolved = resolver.resolve("example.com").to_dict()

        self.assertEqual(
            "SPF resolution exceeded the maximum recursion depth",
            resolved["includes"][0]["includes"][0]["error"],
        )

    def test_main_reports_invalid_ip_address(self):
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            exit_code = main(["example.com", "--ip", "not-an-ip"])

        self.assertEqual(2, exit_code)
        self.assertIn("Invalid IP address: not-an-ip", stderr.getvalue())

    def test_macro_exists_returns_permerror(self):
        resolver = SPFResolver(FakeDNSResolver(txt={"example.com": ["v=spf1 exists:%{i}.spf.example.net -all"]}))

        result = resolver.check_ip("example.com", "198.51.100.20")

        self.assertEqual("permerror", result.result)


if __name__ == "__main__":
    unittest.main()
