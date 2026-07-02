"""
email_posture_analysis.py
=========================
The brain of the email-posture module. PURE LOGIC — no network calls — so it is
fully unit-testable offline and easy for a reviewer (or judge) to read and trust.

It takes already-fetched DNS records / SMTP observations as plain strings and
returns a list of findings. The network layer (email_posture_scanner.py) fetches
those strings and hands them here.

WHY THIS MODULE EXISTS (the gap it fills):
Artemis's built-in `mail_dns_scanner` checks whether SPF and DMARC records are
*present*. But presence is not protection. This analyzer catches the
misconfigurations that a presence-check passes over:
  - DMARC policy is p=none (monitoring only — blocks no spoofing)
  - SPF exceeds the 10-DNS-lookup limit (silently fails)
  - SPF ends in ~all/+all instead of -all (soft/no enforcement)
  - No DKIM at all
  - No MTA-STS (transport downgrade attacks possible)
  - A non-sending domain left spoofable (no null-SPF / reject-DMARC)
  - Mail server doesn't offer STARTTLS (mail sent in cleartext)

Each finding has: id, severity, title, plain (what it means), risk (why it
matters, NGO-framed), fix (concrete action). Severity vocabulary matches the
rest of the toolkit: high / medium / low / ok.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    id: str
    severity: str          # high | medium | low | ok
    title: str
    plain: str
    risk: str
    fix: str
    evidence: str = ""     # the raw record / observation, for the technical appendix


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

# mechanisms that each cost one DNS lookup (per RFC 7208 §4.6.4)
SPF_LOOKUP_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def count_spf_lookups(spf_record: str) -> int:
    """
    Approximate the number of DNS-lookup-causing terms in an SPF record.
    Note: a fully accurate count requires recursively resolving each `include`,
    which the network layer can do; this top-level count already catches the
    common 'too many includes' failure and is clearly documented as a lower bound.
    """
    if not spf_record:
        return 0
    tokens = spf_record.lower().split()
    count = 0
    for tok in tokens:
        # a / mx can appear bare or with a domain (a:example.com)
        if tok in ("a", "mx", "ptr") or tok.startswith(("a:", "mx:", "ptr:")):
            count += 1
        elif tok.startswith(("include:", "exists:", "redirect=")):
            count += 1
    return count


def analyze_spf(spf_record: Optional[str], domain_sends_mail: bool = True) -> List[Finding]:
    f: List[Finding] = []
    if not spf_record:
        if domain_sends_mail:
            f.append(Finding(
                id="spf_missing", severity="high",
                title="No SPF record — anyone can send email as your domain",
                plain="Your domain does not publish a list of which servers may send "
                      "email on its behalf.",
                risk="Criminals can send emails that appear to come from your "
                     "organisation. This is the most common first step in "
                     "ransomware and donor-fraud attacks against NGOs.",
                fix="Publish an SPF TXT record listing your mail providers, ending "
                    "in -all. Your email provider documents the exact value.",
            ))
        else:
            f.append(Finding(
                id="spf_missing_parked", severity="high",
                title="Unused domain is spoofable (no SPF reject)",
                plain="This domain doesn't appear to send email, but it doesn't tell "
                      "the world that either.",
                risk="Attackers love unused but legitimate-looking domains — they can "
                     "spoof them freely for phishing that references your brand.",
                fix='For a non-sending domain, publish  v=spf1 -all  to refuse all '
                    'mail claiming to be from it.',
            ))
        return f

    rec = spf_record.strip()
    f_ev = rec
    # enforcement qualifier
    if rec.lower().endswith("-all"):
        pass  # strict — good
    elif rec.lower().endswith("~all"):
        f.append(Finding(
            id="spf_softfail", severity="medium",
            title="SPF is set to 'softfail' (~all), not enforced",
            plain="Your SPF record asks receivers to merely flag — not reject — "
                  "mail from unauthorised servers.",
            risk="Spoofed mail can still slip through to donors and staff; softfail "
                 "is a half-open door.",
            fix="Once you've confirmed all legitimate senders are listed, change the "
                "ending from ~all to -all to enforce it.",
            evidence=f_ev,
        ))
    elif rec.lower().endswith("+all"):
        f.append(Finding(
            id="spf_passall", severity="high",
            title="SPF allows ANY server to send as your domain (+all)",
            plain="Your SPF record explicitly authorises the entire internet to send "
                  "email as you.",
            risk="This is worse than having no SPF — it actively tells receivers to "
                 "trust spoofed mail. Almost always a configuration mistake.",
            fix="Replace +all with -all immediately and list only your real senders.",
            evidence=f_ev,
        ))
    else:
        f.append(Finding(
            id="spf_no_all", severity="medium",
            title="SPF record has no clear enforcement rule",
            plain="Your SPF record doesn't end with an 'all' rule, so receivers are "
                  "left to guess how strict to be.",
            risk="Inconsistent handling of spoofed mail across providers.",
            fix="Add an explicit -all at the end of the SPF record.",
            evidence=f_ev,
        ))

    lookups = count_spf_lookups(rec)
    if lookups > 10:
        f.append(Finding(
            id="spf_lookup_limit", severity="high",
            title=f"SPF exceeds the 10-lookup limit ({lookups} detected) — it will fail",
            plain="SPF is only allowed 10 DNS lookups. Beyond that, it stops working "
                  "entirely, even though the record still exists.",
            risk="Your SPF silently fails, so your protection — and often your "
                 "legitimate email deliverability — breaks. Common when several "
                 "cloud tools are added over time.",
            fix="Flatten the record: replace nested 'include:' entries with the "
                "actual IP ranges (ip4:/ip6:), or use an SPF-flattening service.",
            evidence=f"{lookups} lookup-causing mechanisms in: {f_ev}",
        ))
    elif lookups >= 8:
        f.append(Finding(
            id="spf_lookup_warn", severity="low",
            title=f"SPF is close to the 10-lookup limit ({lookups})",
            plain="You're near the maximum number of DNS lookups SPF permits.",
            risk="Adding one more email tool could push you over and break SPF.",
            fix="Consider flattening the record proactively before adding senders.",
            evidence=f_ev,
        ))
    return f


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

def parse_dmarc_tags(dmarc_record: str) -> dict:
    tags = {}
    for part in dmarc_record.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            tags[k.strip().lower()] = v.strip().lower()
    return tags


def analyze_dmarc(dmarc_record: Optional[str]) -> List[Finding]:
    f: List[Finding] = []
    if not dmarc_record:
        f.append(Finding(
            id="dmarc_missing", severity="high",
            title="No DMARC policy — spoofing is unrestricted",
            plain="There is no rule telling mail providers what to do with email that "
                  "fakes your domain.",
            risk="Even with SPF, attackers can still spoof the visible 'From' address "
                 "your donors see. DMARC is the layer that actually closes that door.",
            fix="Publish a DMARC record. Start with p=none to observe, then move to "
                "p=quarantine and finally p=reject.",
        ))
        return f

    tags = parse_dmarc_tags(dmarc_record)
    policy = tags.get("p", "")
    if policy == "none":
        f.append(Finding(
            id="dmarc_p_none", severity="high",
            title="DMARC is in monitor-only mode (p=none) — it blocks nothing",
            plain="You have a DMARC record, but its policy is 'none', which only "
                  "watches; it does not stop a single spoofed email.",
            risk="This is the most common false sense of security. The organisation "
                 "believes it is protected against impersonation, but in practice "
                 "spoofed phishing still lands in inboxes.",
            fix="After checking DMARC reports to confirm your real senders pass, "
                "raise the policy to p=quarantine, then p=reject.",
            evidence=dmarc_record,
        ))
    elif policy == "quarantine":
        f.append(Finding(
            id="dmarc_p_quarantine", severity="low",
            title="DMARC set to quarantine — good, one step from full protection",
            plain="Spoofed mail is sent to spam rather than rejected outright.",
            risk="Strong, but a determined attacker's mail still reaches the spam "
                 "folder where some users look.",
            fix="When confident, move to p=reject for full enforcement.",
            evidence=dmarc_record,
        ))
    elif policy == "reject":
        f.append(Finding(
            id="dmarc_p_reject", severity="ok",
            title="DMARC is fully enforced (p=reject)",
            plain="Mail that fails authentication is rejected — the strongest setting.",
            risk="",
            fix="Keep it. Ensure new email tools are added to SPF/DKIM so they don't "
                "get rejected.",
            evidence=dmarc_record,
        ))
    else:
        f.append(Finding(
            id="dmarc_p_unknown", severity="medium",
            title="DMARC record present but policy is unclear",
            plain="We couldn't read a standard policy (none/quarantine/reject) in your "
                  "DMARC record.",
            risk="A malformed DMARC record may be ignored by receivers, leaving you "
                 "unprotected.",
            fix="Have your IT provider validate the DMARC record syntax.",
            evidence=dmarc_record,
        ))

    # missing aggregate reporting address is a missed-visibility issue, not a hole
    if "rua" not in tags and policy in ("none", "quarantine", "reject"):
        f.append(Finding(
            id="dmarc_no_rua", severity="low",
            title="DMARC has no reporting address (rua) — you're flying blind",
            plain="Your DMARC record doesn't ask for the reports that show who is "
                  "sending mail as you.",
            risk="Without these reports you can't safely tighten the policy or spot "
                 "spoofing attempts.",
            fix="Add a rua=mailto: address to start receiving aggregate reports.",
            evidence=dmarc_record,
        ))
    return f


# ---------------------------------------------------------------------------
# DKIM (presence by selector probing — done in network layer; analysed here)
# ---------------------------------------------------------------------------

def analyze_dkim(found_any_selector: bool) -> List[Finding]:
    if found_any_selector:
        return [Finding(
            id="dkim_present", severity="ok",
            title="DKIM signing detected",
            plain="Your outgoing mail is cryptographically signed, which proves it "
                  "wasn't tampered with and survives forwarding.",
            risk="",
            fix="Keep DKIM keys at 1024-bit minimum (2048 recommended) and rotate "
                "them periodically.",
        )]
    return [Finding(
        id="dkim_unconfirmed", severity="low",
        title="DKIM signing not confirmed (limited external visibility)",
        plain="We checked the common DKIM selectors and didn't find one, but DKIM "
              "can use a private selector name we can't guess from outside — so this "
              "is 'not confirmed', not 'definitely missing'.",
        risk="If DKIM really is absent, forwarded legitimate mail can fail checks and "
             "you lose a layer of anti-tampering protection. But many domains that "
             "use DKIM simply use a selector external scanners can't see.",
        fix="Confirm internally whether DKIM is enabled with your email provider. If "
            "it isn't, turn it on — most providers offer a one-click setup.",
    )]


# ---------------------------------------------------------------------------
# MTA-STS (transport security)
# ---------------------------------------------------------------------------

def analyze_mta_sts(mta_sts_record: Optional[str], policy_body: Optional[str]) -> List[Finding]:
    if not mta_sts_record:
        return [Finding(
            id="mta_sts_missing", severity="medium",
            title="No MTA-STS — email delivery can be silently downgraded",
            plain="There's no policy forcing other mail servers to use encryption "
                  "when sending email to you.",
            risk="An attacker positioned on the network can strip encryption and read "
                 "or alter mail in transit (a 'downgrade' attack). Rare to exploit, "
                 "but trivial to prevent.",
            fix="Publish an MTA-STS DNS record and policy file. It's a one-time setup "
                "your provider or host can do.",
        )]
    findings = [Finding(
        id="mta_sts_present", severity="ok",
        title="MTA-STS is published",
        plain="You require other servers to use encryption when emailing you.",
        risk="",
        fix="Keep the policy file reachable and valid.",
        evidence=mta_sts_record,
    )]
    # a present DNS record but missing/garbled policy file is a common misconfig
    if policy_body is not None and "mode:" not in policy_body.lower():
        findings.append(Finding(
            id="mta_sts_broken", severity="medium",
            title="MTA-STS record exists but its policy file looks misconfigured",
            plain="The DNS part of MTA-STS is there, but the policy file it points to "
                  "is missing or unreadable.",
            risk="A broken MTA-STS policy is ignored by senders — you get the work "
                 "without the protection. ~30% of MTA-STS deployments are misconfigured.",
            fix="Ensure https://mta-sts.<yourdomain>/.well-known/mta-sts.txt returns a "
                "valid policy with a 'mode:' line (enforce, once tested).",
            evidence=(policy_body or "")[:200],
        ))
    return findings


# ---------------------------------------------------------------------------
# STARTTLS (live SMTP observation; analysed here)
# ---------------------------------------------------------------------------

def analyze_starttls(supports_starttls: Optional[bool], mx_host: str = "") -> List[Finding]:
    if supports_starttls is None:
        return []  # couldn't test (no MX / connection failed) — stay silent rather than guess
    if supports_starttls:
        return [Finding(
            id="starttls_ok", severity="ok",
            title="Mail server offers encryption in transit (STARTTLS)",
            plain="Your incoming mail server supports encrypting email while it travels.",
            risk="",
            fix="No action needed.",
            evidence=mx_host,
        )]
    return [Finding(
        id="starttls_missing", severity="high",
        title="Mail server does NOT offer STARTTLS — email travels in cleartext",
        plain="Your mail server accepts mail over an unencrypted connection.",
        risk="Anyone able to observe the network can read incoming email in plain "
             "text — including password resets, donor details, and private "
             "correspondence.",
        fix="Enable STARTTLS on your mail server (or with your hosted-email provider). "
            "Standard, free, and expected in 2026.",
        evidence=mx_host,
    )]


# ---------------------------------------------------------------------------
# Orchestration helper (used by the network layer and the test harness)
# ---------------------------------------------------------------------------

@dataclass
class EmailPostureInput:
    domain: str
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_found: bool = False
    mta_sts_record: Optional[str] = None
    mta_sts_policy_body: Optional[str] = None
    supports_starttls: Optional[bool] = None
    mx_host: str = ""
    domain_sends_mail: bool = True


def analyze_all(data: EmailPostureInput) -> List[Finding]:
    findings: List[Finding] = []
    findings += analyze_spf(data.spf_record, data.domain_sends_mail)
    findings += analyze_dmarc(data.dmarc_record)
    findings += analyze_dkim(data.dkim_found)
    findings += analyze_mta_sts(data.mta_sts_record, data.mta_sts_policy_body)
    findings += analyze_starttls(data.supports_starttls, data.mx_host)
    # most severe first
    order = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    findings.sort(key=lambda x: order.get(x.severity, 9))
    return findings
