"""
email_posture_collector.py
==========================
The NETWORK layer for the email-posture module. It fetches the real records and
observations, then hands plain strings to email_posture_analysis (the pure-logic
brain). Keeping fetch and analysis separate is what makes the logic testable
offline and keeps this file small and auditable.

What it touches on the network (all passive / good-faith):
  - DNS TXT/MX lookups for SPF, DMARC, DKIM selectors, MTA-STS  (read-only DNS)
  - one HTTPS GET for the MTA-STS policy file                    (read-only)
  - one SMTP connection to the MX that issues EHLO + STARTTLS capability check,
    then QUITS — it never authenticates, never sends mail, never logs in.

Dependencies: dnspython  (pip install dnspython). Standard library otherwise.

This module is import-safe even if dnspython is missing: it degrades to returning
"could not test" rather than crashing, so the analysis layer can still run on
manually-supplied data.
"""

import smtplib
import socket
import ssl
from typing import Optional

try:
    import dns.resolver
    _HAVE_DNS = True
except Exception:  # noqa: BLE001
    _HAVE_DNS = False

try:
    import urllib.request
    _HAVE_HTTP = True
except Exception:  # noqa: BLE001
    _HAVE_HTTP = False

from email_posture_analysis import EmailPostureInput

# common DKIM selectors used by major providers — probing these is enough to
# detect "DKIM is set up at all" without guessing private selectors.
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "dkim", "s1", "s2", "mandrill", "sendgrid", "zoho", "fm1",
]

# polite timeouts so we never hang on a small/slow NGO host
DNS_TIMEOUT = 5.0
SMTP_TIMEOUT = 8.0


def _txt(name: str) -> Optional[str]:
    if not _HAVE_DNS:
        return None
    try:
        r = dns.resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
        # join the quoted chunks of each TXT record
        for rdata in r:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            return txt
    except Exception:  # noqa: BLE001 (NXDOMAIN, timeout, etc. all mean "absent")
        return None
    return None


def _txt_startswith(name: str, prefix: str) -> Optional[str]:
    """Return the first TXT under `name` whose value starts with `prefix`."""
    if not _HAVE_DNS:
        return None
    try:
        r = dns.resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
        for rdata in r:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.lower().startswith(prefix.lower()):
                return txt
    except Exception:  # noqa: BLE001
        return None
    return None


def _get_mx_hosts(domain: str):
    if not _HAVE_DNS:
        return []
    try:
        r = dns.resolver.resolve(domain, "MX", lifetime=DNS_TIMEOUT)
        return [str(x.exchange).rstrip(".") for x in sorted(r, key=lambda m: m.preference)]
    except Exception:  # noqa: BLE001
        return []


def _dkim_present(domain: str) -> bool:
    for sel in COMMON_DKIM_SELECTORS:
        rec = _txt(f"{sel}._domainkey.{domain}")
        if rec and ("v=dkim1" in rec.lower() or "p=" in rec.lower()):
            return True
    return False


def _fetch_mta_sts(domain: str):
    """Return (dns_record_or_None, policy_body_or_None)."""
    dns_rec = _txt(f"_mta-sts.{domain}")
    body = None
    if dns_rec and _HAVE_HTTP:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(url, timeout=SMTP_TIMEOUT, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = None
    return dns_rec, body


def _check_starttls(mx_host: str) -> Optional[bool]:
    """
    Passive capability probe: connect to the MX on port 25, say EHLO, and look for
    STARTTLS in the advertised features. We do NOT authenticate or send anything.
    Returns True/False, or None if we couldn't connect (so analysis stays silent).
    """
    if not mx_host:
        return None
    try:
        with smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT) as smtp:
            smtp.ehlo()
            supports = smtp.has_extn("starttls")
            try:
                smtp.quit()
            except Exception:  # noqa: BLE001
                pass
            return bool(supports)
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, smtplib.SMTPException, OSError):
        return None


def collect(domain: str, domain_sends_mail: bool = True) -> EmailPostureInput:
    """Gather everything the analyzer needs for one domain."""
    spf = _txt_startswith(domain, "v=spf1")
    dmarc = _txt_startswith(f"_dmarc.{domain}", "v=DMARC1")
    dkim = _dkim_present(domain)
    mta_dns, mta_body = _fetch_mta_sts(domain)

    mx_hosts = _get_mx_hosts(domain)
    mx_host = mx_hosts[0] if mx_hosts else ""
    starttls = _check_starttls(mx_host) if mx_host else None

    # if there's no MX and no SPF, the domain probably doesn't send mail
    inferred_sends = domain_sends_mail and (bool(mx_hosts) or bool(spf))

    return EmailPostureInput(
        domain=domain,
        spf_record=spf,
        dmarc_record=dmarc,
        dkim_found=dkim,
        mta_sts_record=mta_dns,
        mta_sts_policy_body=mta_body,
        supports_starttls=starttls,
        mx_host=mx_host,
        domain_sends_mail=inferred_sends,
    )


if __name__ == "__main__":
    # CLI:
    #   python3 email_posture_collector.py example.org
    #   python3 email_posture_collector.py example.org --json findings.json
    import sys
    import json
    from email_posture_analysis import analyze_all
    if len(sys.argv) < 2:
        print("usage: python3 email_posture_collector.py <domain> [--json OUTFILE]")
        raise SystemExit(1)
    if not _HAVE_DNS:
        print("NOTE: dnspython not installed — install with: pip install dnspython")
    dom = sys.argv[1].strip().lower()
    data = collect(dom)
    findings = analyze_all(data)

    # optional JSON export for the report generator (reports/translate_report.py)
    if "--json" in sys.argv:
        try:
            outpath = sys.argv[sys.argv.index("--json") + 1]
        except IndexError:
            outpath = "findings.json"
        rows = [{
            "name": f.id,
            "target": dom,
            "severity": f.severity,
            "title": f.title,
            "detail": f.evidence or f.plain,
        } for f in findings]
        with open(outpath, "w") as jf:
            json.dump(rows, jf, indent=2)
        print(f"Wrote {outpath}  ({len(rows)} findings) — feed it to reports/translate_report.py")

    print(f"\nEmail-posture findings for {dom}:\n")
    for fnd in findings:
        print(f"[{fnd.severity.upper():6}] {fnd.title}")
        if fnd.severity != "ok":
            print(f"         fix: {fnd.fix}")
