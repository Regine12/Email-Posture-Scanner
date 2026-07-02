"""
test_analysis.py — proves the analyzer logic without any network.
Run:  python3 test_analysis.py
"""
from email_posture_analysis import (
    analyze_all, EmailPostureInput, count_spf_lookups,
    analyze_spf, analyze_dmarc,
)

def show(title, findings):
    print(f"\n=== {title} ===")
    for x in findings:
        print(f"  [{x.severity.upper():6}] {x.id:22} {x.title}")

# 1) The classic NGO false-sense-of-security: records exist but are decorative
bad = EmailPostureInput(
    domain="example-ngo.org",
    spf_record="v=spf1 include:_spf.google.com include:sendgrid.net include:mailchimp.com "
               "include:_spf.salesforce.com include:servers.mcsv.net include:spf.protection.outlook.com "
               "include:_spf.hubspot.com include:amazonses.com include:zoho.com include:mandrillapp.com "
               "include:mailgun.org ~all",  # 11 includes -> over limit, and ~all
    dmarc_record="v=DMARC1; p=none;",       # monitor-only, no rua
    dkim_found=False,
    mta_sts_record=None,
    supports_starttls=False,                # cleartext mail
    mx_host="mail.example-ngo.org",
)
show("Misconfigured NGO (records present but ineffective)", analyze_all(bad))

# 2) A well-configured domain
good = EmailPostureInput(
    domain="secure-ngo.org",
    spf_record="v=spf1 include:_spf.google.com -all",
    dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@secure-ngo.org;",
    dkim_found=True,
    mta_sts_record="v=STSv1; id=20260101000000Z;",
    mta_sts_policy_body="version: STSv1\nmode: enforce\nmx: *.secure-ngo.org\nmax_age: 604800",
    supports_starttls=True,
    mx_host="aspmx.l.google.com",
)
show("Well-configured NGO", analyze_all(good))

# 3) A parked / non-sending domain left spoofable
parked = EmailPostureInput(
    domain="oldcampaign-ngo.org",
    spf_record=None, dmarc_record=None, dkim_found=False,
    mta_sts_record=None, supports_starttls=None,
    domain_sends_mail=False,
)
show("Parked domain (should be locked down)", analyze_all(parked))

# 4) +all catastrophe
passall = EmailPostureInput(domain="oops.org", spf_record="v=spf1 +all",
                            dmarc_record="v=DMARC1; p=quarantine; rua=mailto:x@oops.org;",
                            dkim_found=True)
show("SPF +all mistake", analyze_all(passall))

# ---- assertions: fail loudly if logic regresses ----
def ids(findings): return {x.id for x in findings}

assert count_spf_lookups(bad.spf_record) > 10, "lookup counter should exceed 10"
assert "spf_lookup_limit" in ids(analyze_all(bad))
assert "dmarc_p_none" in ids(analyze_all(bad))
assert "starttls_missing" in ids(analyze_all(bad))
assert "dkim_unconfirmed" in ids(analyze_all(bad))
assert "mta_sts_missing" in ids(analyze_all(bad))

assert "dmarc_p_reject" in ids(analyze_all(good))
assert "starttls_ok" in ids(analyze_all(good))
g_high = [x for x in analyze_all(good) if x.severity == "high"]
assert not g_high, f"well-configured domain should have no HIGH findings, got {g_high}"

assert "spf_missing_parked" in ids(analyze_all(parked))
assert "spf_passall" in ids(analyze_all(passall))

print("\nAll assertions passed. Analyzer logic is sound.")
