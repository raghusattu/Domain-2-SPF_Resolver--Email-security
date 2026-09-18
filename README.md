# Domain-2-SPF_Resolver--Email-security

Small Python SPF resolver for email security use cases.

This is a lightweight resolver for common SPF inspection and IP validation workflows rather than a full RFC 7208 implementation.

## Features

- Resolves a domain's SPF record from DNS TXT records
- Follows `include` and `redirect` relationships
- Evaluates sender IPs against common SPF mechanisms:
  - `ip4`
  - `ip6`
  - `include`
  - `a`
  - `mx`
  - `exists`
  - `all`

## Notes

- `redirect` is supported during policy evaluation and when building the resolved policy tree.
- The resolver is intentionally focused on common SPF cases; advanced macro expansion and other edge-case RFC behaviors are not implemented.
- `exists` uses an A-record-style lookup and rejects macro-based forms as unsupported.

## Usage

Inspect a domain's SPF policy tree:

```bash
python spf_resolver.py example.com
```

Validate a sender IP against a domain's SPF record:

```bash
python spf_resolver.py example.com --ip 203.0.113.10
```

Run tests:

```bash
python -m unittest discover -s tests
```
