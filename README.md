# Artemis module — `email_posture_scanner`

A custom Artemis module that catches the email-spoofing exposures Artemis's
built-in checks miss. This is our team's original engineering contribution: a new
module for "something Artemis does not already do."

## The gap it fills (why this is novel)

Artemis's built-in `mail_dns_scanner` checks whether SPF and DMARC records are
**present**. But in 2026, *presence is not protection*. A domain can pass that
check and still be wide open:

| Misconfiguration | Why it's dangerous | Artemis built-in | Our module |
|------------------|--------------------|:----------------:|:----------:|
| DMARC `p=none` | Monitor-only; blocks **zero** spoofed mail | ✅ "has DMARC" | ✅ flags as ineffective |
| SPF > 10 DNS lookups | SPF **silently fails** entirely | ❌ | ✅ |
| SPF ends `~all` / `+all` | Weak/no enforcement (`+all` trusts the whole internet) | ❌ | ✅ |
| No DKIM | Loses anti-tamper + forwarding survival | ❌ | ✅ |
| No / broken MTA-STS | Mail can be downgraded to cleartext in transit | ❌ | ✅ |
| MX without STARTTLS | Incoming mail readable on the wire | ❌ | ✅ (live check) |
| Parked domain left spoofable | Free, trusted-looking phishing source | ❌ | ✅ |

Email spoofing is the **#1 entry point** for NGO ransomware/fraud (≈68% of breaches
start with a human/phishing element), so closing the *quality* gap — not just the
presence gap — is high-impact and squarely on-brief.

## Files

```
email_posture_scanner/
├── email_posture_analysis.py    ← PURE LOGIC: what we detect & why (no network)
├── email_posture_collector.py   ← NETWORK: fetches DNS + live STARTTLS, feeds analysis
├── email_posture_scanner.py     ← ARTEMIS WRAPPER: registers it as an Artemis module
├── test_analysis.py             ← offline proof the logic is correct (run this!)
└── README.md                    ← you are here
```

The security intelligence is isolated in `email_posture_analysis.py` and fully
unit-tested, so the only Artemis-version-specific code is a thin plumbing layer.

## What it does on the network (all passive / good-faith)

- Read-only DNS lookups (TXT/MX) for SPF, DMARC, DKIM selectors, MTA-STS.
- One read-only HTTPS GET for the MTA-STS policy file.
- One SMTP connection to the MX that sends `EHLO` and checks for the `STARTTLS`
  capability, then `QUIT`s. **It never authenticates, never sends mail, never logs
  in.** This is observation, not intrusion — consistent with our capability
  statement and the good-faith rules in `docs/ETHICS.md`.

## Try it without Artemis (works today)

```bash
# 1) prove the detection logic (no network, no dependencies)
python3 test_analysis.py

# 2) run against a real domain (needs dnspython)
pip install dnspython
python3 email_posture_collector.py yourdomain.org
```

`test_analysis.py` should end with “All assertions passed.”

## Integrating into a real Artemis checkout

1. Copy this folder to `artemis/modules/email_posture_scanner/` (or add the three
   `.py` files alongside the other modules — match your repo's layout).
2. Open `email_posture_scanner.py` and reconcile the **three** points marked
   `# >>> ARTEMIS-PLUMBING` against a simple existing module
   (`artemis/modules/mail_dns_scanner.py` is the closest analogue):
   - (a) the `ArtemisBase` import + class signature,
   - (b) the task `filters` / identity that declare it consumes DOMAIN tasks,
   - (c) the exact result-emitting call (`save_task_result` / `TaskStatus`).
3. Add `dnspython` to Artemis's requirements if it isn't already present.
4. Enable `email_posture_scanner` in the module selection when adding targets.

The analysis and collection layers need **no** changes — only that thin wrapper.

## Output → your report

`email_posture_scanner.py` emits results as a dict with a `findings` list, each
carrying `severity`, `title`, `what_it_means`, `why_it_matters`, `what_to_do`,
`evidence`. That maps 1:1 onto the fields the report translator already uses, so
these findings flow straight into the plain-English traffic-light report and the
remediation loop like any other finding.

## Honest limitations

- DKIM detection probes **common selectors** only; a domain using an unusual
  private selector may be reported as "no DKIM found" when DKIM exists. We state
  this in the finding text rather than over-claiming.
- The SPF lookup count is a top-level count; a fully accurate count resolves each
  `include` recursively. The top-level count already catches the common failure
  and never *over*-reports a problem.
- The STARTTLS check tests the highest-priority MX only; multi-MX setups could
  differ across servers.
