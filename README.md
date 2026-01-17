# Technitium DNS CLI wrapper + importable python library

Idempotent upsert/delete for A, AAAA, CNAME with optional PTR alignment.
Default behavior: PTR presence aligns with A/AAAA presence.
Override: --no-ptr (do not manage PTRs for that operation)

Config supports defaults:
```json
  {
    "base_url": "https://dns.example.com:5380",
    "api_key": "YOURTOKEN",
    "insecure": true,
    "timeout_seconds": 15,
    "log_level": "INFO",
    "log_format": "json",
    "default_zone": "example.com",
    "default_ptr_zone": "10.in-addr.arpa"
  }
```

CLI precedence:
- For zone / ptr-zone: CLI flag > config default > (error if missing where required)
- For insecure: CLI --insecure (if set) > config insecure > default False

Note: Specified zone will be used to build FQDN if short names are specified.

# Everyday Usage Examples

This document is intentionally **examples-first**.  
You should be able to copy/paste commands and start using the tool immediately without reading the full capability set.

For every CLI example, the **equivalent Python library call** is shown directly underneath.

---

## Python Library Setup (once per python session)

```python
from tdnsctl import TechnitiumClient

c = TechnitiumClient(
    base_url="https://dns.example.com:5380",
    api_key="YOURTOKEN",
    insecure=True,          # False if you have a valid TLS cert
    timeout_seconds=15,
)

# Optional convenience defaults (CLI config equivalent)
DEFAULT_ZONE = "example.com"
DEFAULT_PTR_ZONE = "10.in-addr.arpa"
```

---

## 0) One-time config setup (CLI only)

Write config so you don’t need to pass URL/token/zones every time.

```bash
python3 tdnsctl.py config-write \
  --base-url "https://dns.example.com:5380" \
  --api-key "YOURTOKEN" \
  --insecure \
  --default-zone "example.com" \
  --default-ptr-zone "10.in-addr.arpa" \
  --overwrite
```

Python equivalent:  
The library does **not** manage config files.  
The equivalent is simply constructing `TechnitiumClient` as shown above.

---

## 1) Create or correct an A record (most common)

Idempotent. Safe to run repeatedly.  
Default behavior: PTR is created/kept in sync with the A record.

### CLI
```bash
python3 tdnsctl.py upsert \
  --type A \
  --name host1.example.com \
  --value 10.10.10.25
```

### Python
```python
c.upsert_a(
    "host1.example.com",
    DEFAULT_ZONE,
    "10.10.10.25",
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 2) Create/correct an A record **without touching PTR**

Use when reverse DNS is owned elsewhere.

### CLI
```bash
python3 tdnsctl.py upsert \
  --type A \
  --name host1.example.com \
  --value 10.10.10.25 \
  --no-ptr
```

### Python
```python
c.upsert_a(
    "host1.example.com",
    DEFAULT_ZONE,
    "10.10.10.25",
    no_ptr=True,
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 3) Delete an A record (idempotent)

Default behavior: matching PTR is also deleted.

### CLI
```bash
python3 tdnsctl.py delete \
  --type A \
  --name host1.example.com \
  --value 10.10.10.25
```

### Python
```python
c.delete_a(
    "host1.example.com",
    DEFAULT_ZONE,
    "10.10.10.25",
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 4) Delete an A record but **leave PTR alone**

### CLI
```bash
python3 tdnsctl.py delete \
  --type A \
  --name host1.example.com \
  --value 10.10.10.25 \
  --no-ptr
```

### Python
```python
c.delete_a(
    "host1.example.com",
    DEFAULT_ZONE,
    "10.10.10.25",
    no_ptr=True,
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 5) Create or correct a CNAME

PTR logic does not apply.

### CLI
```bash
python3 tdnsctl.py upsert \
  --type CNAME \
  --name www.example.com \
  --value web-01.example.com
```

### Python
```python
c.upsert_cname(
    "www.example.com",
    DEFAULT_ZONE,
    "web-01.example.com",
)
```

---

## 6) Delete a CNAME

### CLI
```bash
python3 tdnsctl.py delete \
  --type CNAME \
  --name www.example.com \
  --value web-01.example.com
```

### Python
```python
c.delete_cname(
    "www.example.com",
    DEFAULT_ZONE,
    "web-01.example.com",
)
```

---

## 7) IPv6: create or correct an AAAA record

PTR aligned by default.

### CLI
```bash
python3 tdnsctl.py upsert \
  --type AAAA \
  --name host6.example.com \
  --value 2001:db8::25
```

### Python
```python
c.upsert_aaaa(
    "host6.example.com",
    DEFAULT_ZONE,
    "2001:db8::25",
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 8) IPv6: delete an AAAA record

PTR aligned by default.

### CLI
```bash
python3 tdnsctl.py delete \
  --type AAAA \
  --name host6.example.com \
  --value 2001:db8::25
```

### Python
```python
c.delete_aaaa(
    "host6.example.com",
    DEFAULT_ZONE,
    "2001:db8::25",
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 9) Override zones on the fly

Useful when defaults aren’t set or you’re working in another zone.

### Forward zone override

#### CLI
```bash
python3 tdnsctl.py upsert \
  --zone other.example.com \
  --type A \
  --name host1.other.example.com \
  --value 10.20.30.40
```

#### Python
```python
c.upsert_a(
    "host1.other.example.com",
    "other.example.com",
    "10.20.30.40",
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

### PTR zone override (single operation)

#### CLI
```bash
python3 tdnsctl.py upsert \
  --zone example.com \
  --ptr-zone "10.in-addr.arpa" \
  --type A \
  --name host1.example.com \
  --value 10.10.10.25
```

#### Python
```python
c.upsert_a(
    "host1.example.com",
    "example.com",
    "10.10.10.25",
    ptr_zone="10.in-addr.arpa",
)
```

---

## 10) Dry-run (no changes)

Shows exactly what *would* happen.

### CLI
```bash
python3 tdnsctl.py upsert \
  --type A \
  --name host1.example.com \
  --value 10.10.10.25 \
  --dry-run
```

### Python
```python
c_dry = TechnitiumClient(
    base_url="https://dns.example.com:5380",
    api_key="YOURTOKEN",
    insecure=True,
    timeout_seconds=15,
    dry_run=True,
)

c_dry.upsert_a(
    "host1.example.com",
    DEFAULT_ZONE,
    "10.10.10.25",
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 11) Batch changes via CSV

CSV columns:

```
action,type,name,value,zone,ttl,no_ptr,ptr_zone
```

---

## 12) Logging / troubleshooting

CLI:
```bash
python3 tdnsctl.py --log-level DEBUG upsert \
  --type A \
  --name host1.example.com \
  --value 10.10.10.25
```

Python:
```python
import logging
logging.getLogger().setLevel(logging.DEBUG)

c.upsert_a(
    "host1.example.com",
    DEFAULT_ZONE,
    "10.10.10.25",
    ptr_zone=DEFAULT_PTR_ZONE,
)
```

---

## 13) Rewrite config

CLI:
```bash
python3 tdnsctl.py config-write \
  --base-url "https://dns.example.com:5380" \
  --api-key "YOURTOKEN" \
  --default-zone "example.com" \
  --default-ptr-zone "10.in-addr.arpa" \
  --overwrite
```

---

## 14) Dump a forward zone

Example CLI output:
```
{"type":"A","name":"@","value":"10.0.0.10"}
{"type":"CNAME","name":"www","value":"web-01.example.com"}
{"type":"A","name":"*.dev","value":"10.0.0.20"}
```

CLI:
```bash
python3 tdnsctl.py --zone example.com
```

Python:
```python
c.get_records(fqdn=z, zone=z, list_zone=True)
```

