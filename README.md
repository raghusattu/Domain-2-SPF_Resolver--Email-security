# Domain-2-SPF_Resolver--Email-security

Small Python SPF resolver for email security use cases.

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
