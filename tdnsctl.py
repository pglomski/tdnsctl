#!/usr/bin/env python3
"""
Technitium DNS CLI wrapper + importable library.

Idempotent upsert/delete for A, AAAA, CNAME with optional PTR alignment.
Default behavior: PTR presence aligns with A/AAAA presence.
Override: --no-ptr (do not manage PTRs for that operation)

Config supports defaults:
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

CLI precedence:
- For zone / ptr-zone: CLI flag > config default > (error if missing where required)
- For insecure: CLI --insecure (if set) > config insecure > default False

=====
tdnsctl — quick-start / everyday use (examples-first)
(Each CLI example is immediately followed by the equivalent Python library call.)

Python library setup (do this once in your script/session)
  from tdnsctl import TechnitiumClient
  c = TechnitiumClient(
      base_url="https://dns.example.com:5380",
      api_key="YOURTOKEN",
      insecure=True,          # set False if you have a valid cert
      timeout_seconds=15,
  )
  # If you want “defaults” like the CLI config provides, just define them once:
  DEFAULT_ZONE = "example.com"
  DEFAULT_PTR_ZONE = "10.in-addr.arpa"


0) One-time setup: write config (so you don’t have to pass URL/token every time)
   CLI:
     python3 tdnsctl.py config-write \
       --base-url "https://dns.example.com:5380" \
       --api-key "YOURTOKEN" \
       --insecure \
       --default-zone "example.com" \
       --default-ptr-zone "10.in-addr.arpa" \
       --overwrite
   Python:
     # The library does not write config files; just construct the client (see setup above).
     # Equivalent “setup” is the TechnitiumClient constructor shown at the top.


1) Most common: create or correct an A record (idempotent; safe to run repeatedly)
   - Default behavior: ensure PTR exists (PTR aligned with A)
   CLI:
     python3 tdnsctl.py upsert \
       --type A \
       --name host1.example.com \
       --value 10.10.10.25
   Python:
     c.upsert_a("host1.example.com", DEFAULT_ZONE, "10.10.10.25", ptr_zone=DEFAULT_PTR_ZONE)


2) Most common variant: create/correct A record but DO NOT manage PTRs
   CLI:
     python3 tdnsctl.py upsert \
       --type A \
       --name host1.example.com \
       --value 10.10.10.25 \
       --no-ptr
   Python:
     c.upsert_a("host1.example.com", DEFAULT_ZONE, "10.10.10.25", no_ptr=True, ptr_zone=DEFAULT_PTR_ZONE)


3) Delete an A record (idempotent; safe to run repeatedly)
   - Default behavior: also delete the matching PTR
   CLI:
     python3 tdnsctl.py delete \
       --type A \
       --name host1.example.com \
       --value 10.10.10.25
   Python:
     c.delete_a("host1.example.com", DEFAULT_ZONE, "10.10.10.25", ptr_zone=DEFAULT_PTR_ZONE)


4) Delete an A record but DO NOT touch PTRs
   CLI:
     python3 tdnsctl.py delete \
       --type A \
       --name host1.example.com \
       --value 10.10.10.25 \
       --no-ptr
   Python:
     c.delete_a("host1.example.com", DEFAULT_ZONE, "10.10.10.25", no_ptr=True, ptr_zone=DEFAULT_PTR_ZONE)


5) Create/correct a CNAME (idempotent)
   CLI:
     python3 tdnsctl.py upsert \
       --type CNAME \
       --name www.example.com \
       --value web-01.example.com
   Python:
     c.upsert_cname("www.example.com", DEFAULT_ZONE, "web-01.example.com")


6) Delete a CNAME (idempotent)
   CLI:
     python3 tdnsctl.py delete \
       --type CNAME \
       --name www.example.com \
       --value web-01.example.com
   Python:
     c.delete_cname("www.example.com", DEFAULT_ZONE, "web-01.example.com")


7) IPv6: create/correct an AAAA record (idempotent; PTR aligned by default)
   CLI:
     python3 tdnsctl.py upsert \
       --type AAAA \
       --name host6.example.com \
       --value 2001:db8::25
   Python:
     c.upsert_aaaa("host6.example.com", DEFAULT_ZONE, "2001:db8::25", ptr_zone=DEFAULT_PTR_ZONE)


8) IPv6: delete AAAA record (idempotent; PTR aligned by default)
   CLI:
     python3 tdnsctl.py delete \
       --type AAAA \
       --name host6.example.com \
       --value 2001:db8::25
   Python:
     c.delete_aaaa("host6.example.com", DEFAULT_ZONE, "2001:db8::25", ptr_zone=DEFAULT_PTR_ZONE)


9) Override zones on the fly (when you didn’t set defaults, or you’re working in another zone)
   - Forward zone override
   CLI:
     python3 tdnsctl.py upsert \
       --zone other.example.com \
       --type A \
       --name host1.other.example.com \
       --value 10.20.30.40
   Python:
     c.upsert_a("host1.other.example.com", "other.example.com", "10.20.30.40", ptr_zone=DEFAULT_PTR_ZONE)

   - Reverse zone (PTR zone) override for this one operation
   CLI:
     python3 tdnsctl.py upsert \
       --zone example.com \
       --ptr-zone "10.in-addr.arpa" \
       --type A \
       --name host1.example.com \
       --value 10.10.10.25
   Python:
     c.upsert_a("host1.example.com", "example.com", "10.10.10.25", ptr_zone="10.in-addr.arpa")


10) Dry-run: show what WOULD happen, without changing anything
    - CLI uses --dry-run
    - Python uses a client constructed with dry_run=True
    CLI:
      python3 tdnsctl.py upsert \
        --type A \
        --name host1.example.com \
        --value 10.10.10.25 \
        --dry-run
    Python:
      c_dry = TechnitiumClient(
          base_url="https://dns.example.com:5380",
          api_key="YOURTOKEN",
          insecure=True,
          timeout_seconds=15,
          dry_run=True,
      )
      c_dry.upsert_a("host1.example.com", DEFAULT_ZONE, "10.10.10.25", ptr_zone=DEFAULT_PTR_ZONE)

    CLI:
      python3 tdnsctl.py delete \
        --type CNAME \
        --name www.example.com \
        --value web-01.example.com \
        --dry-run
    Python:
      c_dry.delete_cname("www.example.com", DEFAULT_ZONE, "web-01.example.com")


11) Batch work (CSV): apply many changes quickly (idempotent per row)
    - CSV columns:
      action,type,name,value,zone,ttl,no_ptr,ptr_zone
    Example records.csv:
      action,type,name,value,zone,ttl,no_ptr,ptr_zone
      upsert,A,host1.example.com,10.10.10.25,,3600,,10.in-addr.arpa
      upsert,CNAME,www.example.com,web-01.example.com,,,,
      delete,A,oldhost.example.com,10.10.10.99,example.com,,true,

    Apply (uses config defaults where blank)
    CLI:
      python3 tdnsctl.py csv-apply --csv records.csv
    Python:
      # No built-in “read CSV file” helper is exposed as a public API by name;
      # but the same behavior is simply calling upsert/delete per row:
      import csv
      with open("records.csv", newline="", encoding="utf-8-sig") as f:
          r = csv.DictReader(f)
          for row in r:
              action = row["action"].strip().lower()
              typ = row["type"].strip().upper()
              name = row["name"].strip()
              value = row["value"].strip()
              zone = (row.get("zone") or "").strip() or DEFAULT_ZONE
              ttl = int(row["ttl"]) if (row.get("ttl") or "").strip() else None
              no_ptr = (row.get("no_ptr") or "").strip().lower() in ("1","true","yes","y","on")
              ptr_zone = (row.get("ptr_zone") or "").strip() or DEFAULT_PTR_ZONE

              if action.startswith("upsert"):
                  if typ == "A":
                      c.upsert_a(name, zone, value, ttl=ttl, no_ptr=no_ptr, ptr_zone=ptr_zone)
                  elif typ == "AAAA":
                      c.upsert_aaaa(name, zone, value, ttl=ttl, no_ptr=no_ptr, ptr_zone=ptr_zone)
                  elif typ == "CNAME":
                      c.upsert_cname(name, zone, value, ttl=ttl)
              else:
                  if typ == "A":
                      c.delete_a(name, zone, value, no_ptr=no_ptr, ptr_zone=ptr_zone)
                  elif typ == "AAAA":
                      c.delete_aaaa(name, zone, value, no_ptr=no_ptr, ptr_zone=ptr_zone)
                  elif typ == "CNAME":
                      c.delete_cname(name, zone, value)

    Apply with explicit defaults (override config defaults for this run)
    CLI:
      python3 tdnsctl.py csv-apply --csv records.csv --zone example.com --ptr-zone "10.in-addr.arpa"
    Python:
      # Just override the variables you pass:
      OVERRIDE_ZONE = "example.com"
      OVERRIDE_PTR_ZONE = "10.in-addr.arpa"
      # then use OVERRIDE_ZONE/OVERRIDE_PTR_ZONE in the loop instead of DEFAULT_ZONE/DEFAULT_PTR_ZONE

    Dry-run the batch
    CLI:
      python3 tdnsctl.py csv-apply --csv records.csv --dry-run
    Python:
      # Use c_dry (dry_run=True client) and call the same per-row methods.


12) Logging you’ll actually use when troubleshooting
    - CLI sets log format/level; Python uses standard logging handlers/levels.

    CLI (debug):
      python3 tdnsctl.py --log-level DEBUG upsert \
        --type A \
        --name host1.example.com \
        --value 10.10.10.25
    Python:
      import logging
      logging.getLogger().setLevel(logging.DEBUG)   # or configure handlers/formatters as you like
      c.upsert_a("host1.example.com", DEFAULT_ZONE, "10.10.10.25", ptr_zone=DEFAULT_PTR_ZONE)

    CLI (plain logs):
      python3 tdnsctl.py --log-format plain upsert \
        --type A \
        --name host1.example.com \
        --value 10.10.10.25
    Python:
      import logging
      logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
      c.upsert_a("host1.example.com", DEFAULT_ZONE, "10.10.10.25", ptr_zone=DEFAULT_PTR_ZONE)


13) “Rewrite config” (overwrites the config file)
    CLI:
      python3 tdnsctl.py config-write \
        --base-url "https://dns.example.com:5380" \
        --api-key "YOURTOKEN" \
        --default-zone "example.com" \
        --default-ptr-zone "10.in-addr.arpa" \
        --overwrite
    Python:
      # Same as #0: library doesn’t manage config files. Construct/adjust the client instead:
      c = TechnitiumClient(
          base_url="https://dns.example.com:5380",
          api_key="YOURTOKEN",
          insecure=True,
          timeout_seconds=15,
      )
      DEFAULT_ZONE = "example.com"
      DEFAULT_PTR_ZONE = "10.in-addr.arpa"


"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests


APP_NAME = "tdnsctl"
DEFAULT_TIMEOUT_SECONDS = 15


# ----------------------------
# Config + paths
# ----------------------------

def default_config_path() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / APP_NAME / "config.json"
        return Path.home() / "AppData" / "Roaming" / APP_NAME / "config.json"
    return Path.home() / ".config" / APP_NAME / "config.json"


@dataclass
class Config:
    base_url: str
    api_key: str
    insecure: bool = False
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    log_level: str = "INFO"
    log_format: str = "json"  # "json" or "plain"
    default_zone: Optional[str] = None
    default_ptr_zone: Optional[str] = None

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Config":
        required = ["base_url", "api_key"]
        missing = [k for k in required if not d.get(k)]
        if missing:
            raise ValueError(f"Missing required config keys: {', '.join(missing)}")
        return Config(
            base_url=str(d["base_url"]).rstrip("/"),
            api_key=str(d["api_key"]),
            insecure=bool(d.get("insecure", False)),
            timeout_seconds=int(d.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
            log_level=str(d.get("log_level", "INFO")).upper(),
            log_format=str(d.get("log_format", "json")).lower(),
            default_zone=(str(d["default_zone"]).strip() if d.get("default_zone") else None),
            default_ptr_zone=(str(d["default_ptr_zone"]).strip() if d.get("default_ptr_zone") else None),
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "insecure": self.insecure,
            "timeout_seconds": self.timeout_seconds,
            "log_level": self.log_level,
            "log_format": self.log_format,
        }
        if self.default_zone:
            out["default_zone"] = self.default_zone
        if self.default_ptr_zone:
            out["default_ptr_zone"] = self.default_ptr_zone
        return out


def load_config(path: Path) -> Config:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Config.from_dict(data)


def write_config(path: Path, cfg: Config, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"Config exists: {path} (use --overwrite)")
    path.write_text(json.dumps(cfg.to_dict(), indent=2) + "\n", encoding="utf-8")


# ----------------------------
# Structured logging
# ----------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()
        payload: Dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        extra = getattr(record, "extra", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: str, fmt: str) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    h = logging.StreamHandler(sys.stdout)
    if fmt == "plain":
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    else:
        h.setFormatter(JsonFormatter())
    root.addHandler(h)


def log(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    logger.log(level, msg, extra={"extra": fields} if fields else None)


# ----------------------------
# Technitium client
# ----------------------------

class TechnitiumApiError(RuntimeError):
    pass


class TechnitiumClient:
    """
    Importable client with idempotent operations.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        insecure: bool = False,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        session: Optional[requests.Session] = None,
        dry_run: bool = False,
        logger: Optional[logging.Logger] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_tls = not insecure
        self.timeout = timeout_seconds
        self.s = session or requests.Session()
        self.dry_run = dry_run
        self.logger = logger or logging.getLogger("tdnsctl")

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _request(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        url = self._url(path)
        params2 = dict(params)
        params2["token"] = self.api_key

        if self.dry_run:
            log(self.logger, logging.INFO, "dry_run_request", url=url, params={**params2, "token": "***"})
            return {"status": "ok", "response": {"dry_run": True}}

        r = self.s.post(url, data=params2, timeout=self.timeout, verify=self.verify_tls)
        try:
            data = r.json()
        except Exception as e:
            raise TechnitiumApiError(f"Non-JSON response from {url}: {r.status_code} {r.text[:500]}") from e

        if data.get("status") != "ok":
            raise TechnitiumApiError(f"API error {url}: {data.get('errorMessage') or data}")
        return data

    def get_records(self, fqdn: str, zone: Optional[str] = None, list_zone: bool = False) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"domain": fqdn, "listZone": "true" if list_zone else "false"}
        if zone:
            params["zone"] = zone
        data = self._request("/api/zones/records/get", params)
        return (data.get("response") or {}).get("records") or []

    def add_record(
        self,
        fqdn: str,
        zone: str,
        rtype: str,
        ttl: Optional[int] = None,
        ptr: Optional[bool] = None,
        create_ptr_zone: Optional[bool] = None,
        **rdata_fields: Any,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"domain": fqdn, "zone": zone, "type": rtype}
        if ttl is not None:
            params["ttl"] = str(int(ttl))
        if ptr is not None:
            params["ptr"] = "true" if ptr else "false"
        if create_ptr_zone is not None:
            params["createPtrZone"] = "true" if create_ptr_zone else "false"
        for k, v in rdata_fields.items():
            params[k] = v
        return self._request("/api/zones/records/add", params)

    def delete_record(self, fqdn: str, zone: str, rtype: str, value: str) -> Dict[str, Any]:
        params = {"domain": fqdn, "zone": zone, "type": rtype, "value": value}
        return self._request("/api/zones/records/delete", params)

    @staticmethod
    def _match_value(record: Dict[str, Any], rtype: str) -> Optional[str]:
        rdata = record.get("rData") or {}
        if rtype in ("A", "AAAA"):
            return rdata.get("ipAddress")
        if rtype == "CNAME":
            return rdata.get("cname")
        if rtype == "PTR":
            return rdata.get("ptrName")
        return None

    def record_exists(self, fqdn: str, zone: str, rtype: str, value: str) -> bool:
        records = self.get_records(fqdn, zone=zone, list_zone=False)
        for rr in records:
            if rr.get("type") == rtype and rr.get("name") == fqdn:
                v = self._match_value(rr, rtype)
                if v == value:
                    return True
        return False

    # PTR helpers

    @staticmethod
    def reverse_fqdn_for_ip(ip: str) -> str:
        ip_obj = ipaddress.ip_address(ip)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            octets = str(ip_obj).split(".")
            return ".".join(reversed(octets)) + ".in-addr.arpa"
        hex32 = ip_obj.exploded.replace(":", "")
        return ".".join(reversed(list(hex32))) + ".ip6.arpa"

    def _discover_zone_for_name(self, fqdn: str) -> Optional[str]:
        if self.dry_run:
            return None
        url = self._url("/api/zones/records/get")
        r = self.s.post(
            url,
            data={"token": self.api_key, "domain": fqdn, "listZone": "true"},
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        data = r.json()
        if data.get("status") != "ok":
            return None
        zone = (data.get("response") or {}).get("zone") or {}
        return zone.get("name")

    def ensure_ptr(self, ip: str, target_fqdn: str, ptr_zone: Optional[str] = None) -> Dict[str, Any]:
        rev = self.reverse_fqdn_for_ip(ip)

        # Deterministic path if ptr_zone is provided
        if ptr_zone:
            if self.record_exists(rev, ptr_zone, "PTR", target_fqdn):
                return {"changed": False, "details": {"ptr": "present", "reverse": rev, "zone": ptr_zone}}
            self.add_record(rev, ptr_zone, "PTR", ptrName=target_fqdn)
            return {"changed": True, "details": {"ptr": "created", "reverse": rev, "zone": ptr_zone}}

        # Best-effort path: discover reverse zone
        zone = self._discover_zone_for_name(rev)
        if zone and self.record_exists(rev, zone, "PTR", target_fqdn):
            return {"changed": False, "details": {"ptr": "present", "reverse": rev, "zone": zone}}
        if not zone:
            raise TechnitiumApiError(f"Could not discover reverse zone for {rev}; provide --ptr-zone or config default_ptr_zone.")
        self.add_record(rev, zone, "PTR", ptrName=target_fqdn)
        return {"changed": True, "details": {"ptr": "created", "reverse": rev, "zone": zone}}

    def delete_ptr(self, ip: str, target_fqdn: str, ptr_zone: Optional[str] = None) -> Dict[str, Any]:
        rev = self.reverse_fqdn_for_ip(ip)

        if ptr_zone:
            if self.record_exists(rev, ptr_zone, "PTR", target_fqdn):
                self.delete_record(rev, ptr_zone, "PTR", target_fqdn)
                return {"changed": True, "details": {"ptr": "deleted", "reverse": rev, "zone": ptr_zone}}
            return {"changed": False, "details": {"ptr": "absent", "reverse": rev, "zone": ptr_zone}}

        zone = self._discover_zone_for_name(rev)
        if zone and self.record_exists(rev, zone, "PTR", target_fqdn):
            self.delete_record(rev, zone, "PTR", target_fqdn)
            return {"changed": True, "details": {"ptr": "deleted", "reverse": rev, "zone": zone}}
        return {"changed": False, "details": {"ptr": "absent", "reverse": rev, "zone": zone or "unknown"}}

    # Public idempotent ops

    def upsert_a(self, fqdn: str, zone: str, ip: str, ttl: Optional[int] = None, no_ptr: bool = False, ptr_zone: Optional[str] = None) -> Dict[str, Any]:
        a_changed = False
        if not self.record_exists(fqdn, zone, "A", ip):
            self.add_record(
                fqdn, zone, "A",
                ttl=ttl,
                ipAddress=ip,
                ptr=(False if no_ptr else True),
                create_ptr_zone=(False if no_ptr else True),
            )
            a_changed = True

        ptr_result = {"changed": False, "details": {"ptr": "skipped"}}
        if not no_ptr:
            ptr_result = self.ensure_ptr(ip=ip, target_fqdn=fqdn, ptr_zone=ptr_zone)

        return {"changed": (a_changed or ptr_result["changed"]), "details": {"a": {"changed": a_changed}, "ptr": ptr_result}}

    def upsert_aaaa(self, fqdn: str, zone: str, ip6: str, ttl: Optional[int] = None, no_ptr: bool = False, ptr_zone: Optional[str] = None) -> Dict[str, Any]:
        aaaa_changed = False
        if not self.record_exists(fqdn, zone, "AAAA", ip6):
            self.add_record(
                fqdn, zone, "AAAA",
                ttl=ttl,
                ipAddress=ip6,
                ptr=(False if no_ptr else True),
                create_ptr_zone=(False if no_ptr else True),
            )
            aaaa_changed = True

        ptr_result = {"changed": False, "details": {"ptr": "skipped"}}
        if not no_ptr:
            ptr_result = self.ensure_ptr(ip=ip6, target_fqdn=fqdn, ptr_zone=ptr_zone)

        return {"changed": (aaaa_changed or ptr_result["changed"]), "details": {"aaaa": {"changed": aaaa_changed}, "ptr": ptr_result}}

    def upsert_cname(self, fqdn: str, zone: str, target: str, ttl: Optional[int] = None) -> Dict[str, Any]:
        if self.record_exists(fqdn, zone, "CNAME", target):
            return {"changed": False, "details": {"cname": "present"}}
        self.add_record(fqdn, zone, "CNAME", ttl=ttl, cname=target)
        return {"changed": True, "details": {"cname": "created"}}

    def delete_a(self, fqdn: str, zone: str, ip: str, no_ptr: bool = False, ptr_zone: Optional[str] = None) -> Dict[str, Any]:
        a_deleted = False
        if self.record_exists(fqdn, zone, "A", ip):
            self.delete_record(fqdn, zone, "A", ip)
            a_deleted = True

        ptr_res = {"changed": False, "details": {"ptr": "skipped"}}
        if not no_ptr:
            ptr_res = self.delete_ptr(ip=ip, target_fqdn=fqdn, ptr_zone=ptr_zone)

        return {"changed": (a_deleted or ptr_res["changed"]), "details": {"a_deleted": a_deleted, "ptr": ptr_res}}

    def delete_aaaa(self, fqdn: str, zone: str, ip6: str, no_ptr: bool = False, ptr_zone: Optional[str] = None) -> Dict[str, Any]:
        aaaa_deleted = False
        if self.record_exists(fqdn, zone, "AAAA", ip6):
            self.delete_record(fqdn, zone, "AAAA", ip6)
            aaaa_deleted = True

        ptr_res = {"changed": False, "details": {"ptr": "skipped"}}
        if not no_ptr:
            ptr_res = self.delete_ptr(ip=ip6, target_fqdn=fqdn, ptr_zone=ptr_zone)

        return {"changed": (aaaa_deleted or ptr_res["changed"]), "details": {"aaaa_deleted": aaaa_deleted, "ptr": ptr_res}}

    def delete_cname(self, fqdn: str, zone: str, target: str) -> Dict[str, Any]:
        if not self.record_exists(fqdn, zone, "CNAME", target):
            return {"changed": False, "details": {"cname": "absent"}}
        self.delete_record(fqdn, zone, "CNAME", target)
        return {"changed": True, "details": {"cname": "deleted"}}


# ----------------------------
# CSV import
# ----------------------------

# zone and ptr_zone can be blank (use defaults). ttl/no_ptr optional.
CSV_COLUMNS = ["action", "type", "name", "value", "zone", "ttl", "no_ptr", "ptr_zone"]


def iter_csv_rows(path: Path) -> Iterable[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = [c for c in CSV_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"CSV missing columns: {missing}. Expected: {CSV_COLUMNS}")
        for row in reader:
            yield {k: (row.get(k) or "").strip() for k in CSV_COLUMNS}


def parse_bool(s: str) -> bool:
    return s.lower() in ("1", "true", "yes", "y", "on") if s else False


def apply_csv(
    client: TechnitiumClient,
    csv_path: Path,
    default_zone: Optional[str],
    default_ptr_zone: Optional[str],
) -> Tuple[int, int]:
    changed_count = 0
    total = 0

    for row in iter_csv_rows(csv_path):
        total += 1
        action = row["action"].lower()
        rtype = row["type"].upper()
        name = row["name"]
        value = row["value"]
        zone = row["zone"] or (default_zone or "")
        ptr_zone = row["ptr_zone"] or (default_ptr_zone or "")
        ttl = int(row["ttl"]) if row["ttl"] else None
        no_ptr = parse_bool(row["no_ptr"])

        if not zone:
            raise ValueError(f"Row {total}: zone missing and no default zone available.")

        log(
            client.logger,
            logging.INFO,
            "csv_row",
            row_num=total,
            action=action,
            type=rtype,
            name=name,
            value=value,
            zone=zone,
            ptr_zone=(ptr_zone or None),
            ttl=ttl,
            no_ptr=no_ptr,
        )

        if action in ("upsert", "create", "add", "ensure"):
            if rtype == "A":
                res = client.upsert_a(name, zone, value, ttl=ttl, no_ptr=no_ptr, ptr_zone=(ptr_zone or None))
            elif rtype == "AAAA":
                res = client.upsert_aaaa(name, zone, value, ttl=ttl, no_ptr=no_ptr, ptr_zone=(ptr_zone or None))
            elif rtype == "CNAME":
                res = client.upsert_cname(name, zone, value, ttl=ttl)
            else:
                raise ValueError(f"Row {total}: unsupported type {rtype}")
        elif action in ("delete", "del", "remove", "rm"):
            if rtype == "A":
                res = client.delete_a(name, zone, value, no_ptr=no_ptr, ptr_zone=(ptr_zone or None))
            elif rtype == "AAAA":
                res = client.delete_aaaa(name, zone, value, no_ptr=no_ptr, ptr_zone=(ptr_zone or None))
            elif rtype == "CNAME":
                res = client.delete_cname(name, zone, value)
            else:
                raise ValueError(f"Row {total}: unsupported type {rtype}")
        else:
            raise ValueError(f"Row {total}: unsupported action {action} (use upsert/delete)")

        if res.get("changed"):
            changed_count += 1
        log(client.logger, logging.INFO, "csv_result", row_num=total, changed=bool(res.get("changed")), details=res.get("details"))

    return changed_count, total


# ----------------------------
# CLI helpers
# ----------------------------

def pick_zone(cli_zone: Optional[str], cfg_zone: Optional[str]) -> Optional[str]:
    z = (cli_zone or "").strip() or (cfg_zone or "").strip()
    return z or None


def build_client_from_args(args: argparse.Namespace, logger: logging.Logger, cfg: Optional[Config]) -> TechnitiumClient:
    base_url = (args.base_url or (cfg.base_url if cfg else None))
    api_key = (args.api_key or (cfg.api_key if cfg else None))
    if not base_url:
        raise SystemExit("Missing base URL. Provide --base-url or write config.")
    if not api_key:
        raise SystemExit("Missing API key. Provide --api-key or write config.")

    insecure = bool(args.insecure) if args.insecure is not None else (cfg.insecure if cfg else False)
    timeout = args.timeout_seconds or (cfg.timeout_seconds if cfg else DEFAULT_TIMEOUT_SECONDS)

    return TechnitiumClient(
        base_url=str(base_url).rstrip("/"),
        api_key=str(api_key),
        insecure=insecure,
        timeout_seconds=int(timeout),
        dry_run=bool(getattr(args, "dry_run", False)),
        logger=logger,
    )


# ----------------------------
# CLI
# ----------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="tdnsctl", description="Technitium DNS CLI (idempotent A/AAAA/CNAME + PTR alignment)")
    p.add_argument("--config-path", help=f"Config path (default: {default_config_path()})")
    p.add_argument("--base-url", help="Technitium base URL, e.g. https://dns.example.com:5380")
    p.add_argument("--api-key", help="Technitium API token")
    p.add_argument("--insecure", action="store_true", default=None, help="Disable TLS verification (or set in config)")
    p.add_argument("--timeout-seconds", type=int, help=f"HTTP timeout (default {DEFAULT_TIMEOUT_SECONDS})")
    p.add_argument("--log-level", default=None, help="DEBUG/INFO/WARNING/ERROR (default from config or INFO)")
    p.add_argument("--log-format", default=None, help="json|plain (default from config or json)")

    sub = p.add_subparsers(dest="cmd", required=True)

    # config-write
    pcw = sub.add_parser("config-write", help="Write config file")
    pcw.add_argument("--overwrite", action="store_true", help="Overwrite existing config")
    pcw.add_argument("--base-url", required=True)
    pcw.add_argument("--api-key", required=True)
    pcw.add_argument("--insecure", action="store_true", help="Store insecure=true in config")
    pcw.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    pcw.add_argument("--log-level", default="INFO")
    pcw.add_argument("--log-format", default="json")
    pcw.add_argument("--default-zone", help="Default forward zone (optional)")
    pcw.add_argument("--default-ptr-zone", help="Default reverse zone for PTR operations (optional)")

    # upsert
    pup = sub.add_parser("upsert", help="Idempotent upsert for A/AAAA/CNAME (PTR aligned by default for A/AAAA)")
    pup.add_argument("--zone", help="Forward zone name (optional if default_zone set in config)")
    pup.add_argument("--ptr-zone", help="Reverse zone name for PTR ops (optional if default_ptr_zone set in config)")
    pup.add_argument("--type", required=True, choices=["A", "AAAA", "CNAME"])
    pup.add_argument("--name", required=True, help="FQDN (e.g. host.example.com)")
    pup.add_argument("--value", required=True, help="A/AAAA=IP, CNAME=target FQDN")
    pup.add_argument("--ttl", type=int)
    pup.add_argument("--no-ptr", action="store_true", help="Do NOT align PTR presence with A/AAAA presence")
    pup.add_argument("--dry-run", action="store_true", help="Log actions but do not call API")

    # delete
    pdel = sub.add_parser("delete", help="Idempotent delete for A/AAAA/CNAME (PTR aligned by default for A/AAAA)")
    pdel.add_argument("--zone", help="Forward zone name (optional if default_zone set in config)")
    pdel.add_argument("--ptr-zone", help="Reverse zone name for PTR ops (optional if default_ptr_zone set in config)")
    pdel.add_argument("--type", required=True, choices=["A", "AAAA", "CNAME"])
    pdel.add_argument("--name", required=True, help="FQDN (e.g. host.example.com)")
    pdel.add_argument("--value", required=True, help="A/AAAA=IP, CNAME=target FQDN")
    pdel.add_argument("--no-ptr", action="store_true", help="Do NOT align PTR presence with A/AAAA presence")
    pdel.add_argument("--dry-run", action="store_true", help="Log actions but do not call API")

    # csv-apply
    pcsv = sub.add_parser("csv-apply", help="Apply CSV rows (upsert/delete) with optional dry-run")
    pcsv.add_argument("--csv", required=True, type=Path, help="CSV path")
    pcsv.add_argument("--zone", help="Default forward zone if CSV zone column empty (overrides config default_zone)")
    pcsv.add_argument("--ptr-zone", help="Default PTR zone if CSV ptr_zone column empty (overrides config default_ptr_zone)")
    pcsv.add_argument("--dry-run", action="store_true", help="Log actions but do not call API")

    args = p.parse_args(argv)
    cfg_path = Path(args.config_path or default_config_path())

    # config-write handled first
    if args.cmd == "config-write":
        setup_logging("INFO", "plain")
        cfg = Config(
            base_url=args.base_url.rstrip("/"),
            api_key=args.api_key,
            insecure=bool(args.insecure),
            timeout_seconds=int(args.timeout_seconds),
            log_level=str(args.log_level).upper(),
            log_format=str(args.log_format).lower(),
            default_zone=(args.default_zone.strip() if args.default_zone else None),
            default_ptr_zone=(args.default_ptr_zone.strip() if args.default_ptr_zone else None),
        )
        write_config(cfg_path, cfg, overwrite=bool(args.overwrite))
        print(str(cfg_path))
        return 0

    cfg: Optional[Config] = load_config(cfg_path) if cfg_path.exists() else None
    log_level = (args.log_level or (cfg.log_level if cfg else "INFO")).upper()
    log_format = (args.log_format or (cfg.log_format if cfg else "json")).lower()
    setup_logging(log_level, log_format)

    logger = logging.getLogger("tdnsctl")
    client = build_client_from_args(args, logger, cfg)

    # Defaults for zones
    cfg_default_zone = cfg.default_zone if cfg else None
    cfg_default_ptr_zone = cfg.default_ptr_zone if cfg else None

    try:
        if args.cmd in ("upsert", "delete"):
            zone = pick_zone(getattr(args, "zone", None), cfg_default_zone)
            if not zone:
                raise ValueError("Missing --zone and no default_zone configured.")

            ptr_zone = pick_zone(getattr(args, "ptr_zone", None), cfg_default_ptr_zone)

            rtype = args.type.upper()
            if args.cmd == "upsert":
                if rtype == "A":
                    res = client.upsert_a(args.name, zone, args.value, ttl=args.ttl, no_ptr=bool(args.no_ptr), ptr_zone=ptr_zone)
                elif rtype == "AAAA":
                    res = client.upsert_aaaa(args.name, zone, args.value, ttl=args.ttl, no_ptr=bool(args.no_ptr), ptr_zone=ptr_zone)
                else:
                    res = client.upsert_cname(args.name, zone, args.value, ttl=args.ttl)
            else:
                if rtype == "A":
                    res = client.delete_a(args.name, zone, args.value, no_ptr=bool(args.no_ptr), ptr_zone=ptr_zone)
                elif rtype == "AAAA":
                    res = client.delete_aaaa(args.name, zone, args.value, no_ptr=bool(args.no_ptr), ptr_zone=ptr_zone)
                else:
                    res = client.delete_cname(args.name, zone, args.value)

            log(logger, logging.INFO, "result", changed=bool(res["changed"]), details=res["details"])
            return 0

        if args.cmd == "csv-apply":
            # CLI --zone/--ptr-zone override config defaults for CSV processing
            dz = pick_zone(getattr(args, "zone", None), cfg_default_zone)
            dpz = pick_zone(getattr(args, "ptr_zone", None), cfg_default_ptr_zone)

            changed, total = apply_csv(client, args.csv, default_zone=dz, default_ptr_zone=dpz)
            log(logger, logging.INFO, "csv_summary", total=total, changed_rows=changed, dry_run=bool(args.dry_run))
            return 0

        raise SystemExit(f"Unhandled command: {args.cmd}")

    except (TechnitiumApiError, ValueError, FileExistsError) as e:
        log(logger, logging.ERROR, "error", error=str(e))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

