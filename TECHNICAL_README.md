# Diana Email-Posture Scanner — Technical README

A deep email-security scanner for the Diana / LCO project. This document explains
exactly what it does, how it works, what it tests, and how it relates to Artemis —
so any team member (or a judge) can understand and defend it.

---

## 1. What it is, in one paragraph

The email-posture scanner is a small, self-contained Python tool that inspects a
domain's **email-authentication configuration** — the DNS records and mail-server
settings that determine whether someone can send forged email pretending to be
that organisation. It reports, in plain language, which protections are missing,
weak, or misconfigured, and how to fix each one. It is the custom detection
component of the Diana project.

---

## 2. Does it build on Artemis?

**Short answer: no — it is our own standalone code, written to be Artemis-*compatible*.**

This is worth stating precisely, because it's a common question:

- The scanner does **not** import Artemis, call Artemis, or require Artemis to run.
  It is independent Python and runs on its own with a single dependency
  (`dnspython`).
- It **is written in the shape of an Artemis module** — the file
  `email_posture_scanner.py` follows Artemis's documented module pattern (subclass
  `ArtemisBase`, consume a task, emit a result) so it *can* be dropped into an
  Artemis installation and run as a native module alongside the others.
- **Why we built our own instead of using Artemis's `mail_dns_scanner`:** Artemis's
  built-in email check only verifies whether SPF and DMARC records *exist*. Our
  module checks whether they are actually *effective* — catching `p=none` DMARC,
  SPF that exceeds the lookup limit, softfail SPF, missing MTA-STS, and mail
  servers without STARTTLS. Presence is not protection; that gap is what we built.

So in the wider Diana pipeline, **Artemis is the engine for website/CVE/CMS
scanning, and this module is our own contribution for the email layer.** They are
separate tools that produce findings in the same shape, so both flow into the same
Diana report.

---

## 3. What exactly it tests

For a given domain, the scanner checks six things:

| # | Check | What it looks for | Why it matters |
|---|-------|-------------------|----------------|
| 1 | **SPF** | Is there an SPF record? Does it end in `-all` (strict), `~all` (softfail) or `+all` (allow-all)? Does it exceed the 10-DNS-lookup limit? | Says which servers may send mail as the domain. Missing/weak SPF lets spoofed mail through. Over 10 lookups makes SPF silently fail. |
| 2 | **DMARC** | Is there a DMARC record? Is the policy `p=none`, `p=quarantine`, or `p=reject`? Is a reporting address (`rua`) set? | DMARC is what actually blocks forged "From" addresses. `p=none` monitors but blocks nothing — the most common false sense of security. |
| 3 | **DKIM** | Do any of the common DKIM selectors resolve? | DKIM cryptographically signs mail and survives forwarding. (See limitation in §6 — DKIM absence cannot be proven externally.) |
| 4 | **MTA-STS** | Is there an `_mta-sts` DNS record, and does its policy file load and contain a valid `mode:`? | Forces encryption of mail *in transit*. Missing MTA-STS allows downgrade/interception attacks. |
| 5 | **STARTTLS** | Does the domain's mail server (MX) advertise STARTTLS on port 25? | Whether incoming mail is encrypted on the wire. No STARTTLS = mail readable in transit. |
| 6 | **Non-sending domains** | If a domain sends no mail, is it locked down (`v=spf1 -all`)? | Unused-but-legitimate domains are prime spoofing targets. |

Each finding is graded **high / medium / low / ok** and comes with: what it means,
why it matters (framed for NGOs), and the concrete fix — plus a ready-to-send Dutch
email in the Diana layer.

---

## 4. How the scan is performed (the technical flow)

The tool is deliberately split into three layers so the security logic is testable
without any network:

```
 email_posture_scanner.py   ← Artemis-compatible wrapper (optional; for Artemis integration)
 email_posture_collector.py ← NETWORK layer: fetches the real records
 email_posture_analysis.py  ← PURE LOGIC: decides what each record means (no network)
```

**Step by step, for one domain:**

1. **DNS lookups (passive).** Using `dnspython`, the collector queries public DNS for:
   - the domain's `TXT` records → finds the SPF record (`v=spf1 ...`)
   - `_dmarc.<domain>` `TXT` → the DMARC record
   - `<selector>._domainkey.<domain>` `TXT` for a list of common DKIM selectors
   - `_mta-sts.<domain>` `TXT` → the MTA-STS record
   - the domain's `MX` records → the mail server hostname
2. **MTA-STS policy fetch (passive HTTPS GET).** If an MTA-STS DNS record exists, it
   fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` and reads the policy.
3. **STARTTLS probe (light active, read-only).** It opens one SMTP connection to the
   highest-priority MX on port 25, sends `EHLO`, checks whether `STARTTLS` is
   advertised, then `QUIT`s. **It never authenticates, never sends mail, never logs
   in.** This is a single, gentle, read-only capability check.
4. **Analysis (no network).** All fetched strings are passed to
   `email_posture_analysis.py`, which contains the actual rules (e.g. "DMARC policy
   is `none` → high-severity finding") and returns the list of findings.
5. **Output.** Findings print to the terminal, and with `--json` are written to a
   file for the Diana frontend.

**Rate/impact:** the scan is essentially free for the target — a handful of DNS
queries, one HTTPS GET, and one SMTP hello. It places negligible load on anyone's
infrastructure.

---

## 5. Passive vs. active — and consent

This matters for the legal/ethics story:

- **Checks 1, 2, 3, 4, 6 are fully passive.** They read public DNS records and one
  public policy file. You are not touching the organisation's servers — you're
  reading records published to the world. **No consent is required** for these, and
  they can be run at scale.
- **Check 5 (STARTTLS) makes one connection to the organisation's mail server.** It
  is read-only and gentle, but it does touch their infrastructure, so it sits at the
  passive/active boundary. For strictly-passive, consent-free scanning you can rely
  on checks 1–4/6 alone.

This is why Diana's field research (scanning many real NGOs) is legally sound: it
uses the passive layer only.

---

## 6. Honest limitations

State these openly — they make the tool *more* credible, not less:

- **DKIM cannot be disproven externally.** DKIM uses a "selector" in the DNS name
  (`selector._domainkey.domain`). We probe a list of common selectors, but a domain
  can use a private selector we can't guess. So the tool reports **"DKIM not
  confirmed"**, never "DKIM missing" — because absence can't be proven from outside.
  (We caught this when the tool wrongly reported "no DKIM" for google.com, and
  corrected it.)
- **SPF lookup count is a top-level estimate.** A fully accurate count resolves every
  nested `include:` recursively. Our count catches the common "too many includes"
  failure and never over-reports.
- **STARTTLS checks the highest-priority MX only.** Multi-MX setups could differ
  across servers.
- **The severity grades are an NGO-facing summary, not a formal CVSS score.**

---

## 7. How to run it

```bash
# one-time setup
python3 -m venv .venv
source .venv/bin/activate
pip install dnspython

# prove the logic works (no network needed)
python3 test_analysis.py

# scan a real domain (use a BARE domain, not a URL)
python3 email_posture_collector.py example.nl

# scan and save JSON for the Diana frontend
python3 email_posture_collector.py example.nl --json example.json
```

**Verify any DNS finding yourself** (this is how you prove it's real, not invented):

```bash
dig +short TXT _dmarc.example.nl     # see the actual DMARC policy
dig +short TXT example.nl | grep spf # see the actual SPF record
```

---

## 8. Files in this folder

| File | Role |
|------|------|
| `email_posture_analysis.py` | Pure detection logic — the rules, no network. Fully unit-tested. |
| `email_posture_collector.py` | Network layer — DNS/HTTPS/SMTP fetching. Has the `--json` export. |
| `email_posture_scanner.py` | Artemis-compatible module wrapper (for optional integration into Artemis). |
| `test_analysis.py` | Offline test suite — proves the logic across realistic cases. |
| `README.md` | This document. |

---

## 9. Dependencies

- **Python 3.9+**
- **dnspython** (`pip install dnspython`) — the only external dependency, used for
  DNS lookups. Everything else is Python standard library (`smtplib`, `ssl`,
  `urllib`, `json`).
