"""
email_posture_scanner.py  —  the Artemis MODULE wrapper
=======================================================
This is the file that makes the email-posture check a first-class Artemis module.
It plugs the pure analyzer (email_posture_analysis) + collector
(email_posture_collector) into Artemis's task/Karton pipeline.

────────────────────────────────────────────────────────────────────────────
⚠️  INTEGRATION NOTE — READ BEFORE RUNNING INSIDE ARTEMIS
This wrapper follows the documented Artemis module pattern (see
https://artemis-scanner.readthedocs.io/en/latest/user-guide/writing-a-module.html).
Artemis modules subclass `ArtemisBase` and are Karton consumers. The exact import
paths, the task `headers`/filters, and the result-emitting helper names can vary
slightly between Artemis releases, so when you drop this into a real checkout:

  1. Open an existing simple module, e.g.  artemis/modules/mail_dns_scanner.py
  2. Match THREE things to that file:
       (a) the base-class import + class signature
       (b) how it declares which tasks it consumes (the `filters` / `identity`)
       (c) how it reports results (e.g. self.db.save_task_result(...) /
           create_analysis_result(...) and the TaskStatus enum)
  3. The analysis + collection logic below does NOT need to change — only the
     three Artemis-plumbing points marked  # >>> ARTEMIS-PLUMBING  below.

Everything that contains the actual security value (what we detect and why) lives
in email_posture_analysis.py and is fully unit-tested in test_analysis.py, so the
risky part is just this thin plumbing layer.
────────────────────────────────────────────────────────────────────────────
"""

from typing import List

# >>> ARTEMIS-PLUMBING (a): base class + task types.
# In a real checkout these come from Artemis. We import defensively so this file
# is still importable (and the logic runnable) outside Artemis.
try:
    from artemis.binds import Service, TaskType        # noqa: F401
    from artemis.module_base import ArtemisBase
    from artemis.task_utils import get_target_host
    from karton.core import Task
    _IN_ARTEMIS = True
except Exception:  # noqa: BLE001
    _IN_ARTEMIS = False

    class ArtemisBase:  # minimal stand-in so the file imports standalone
        identity = "email_posture_scanner"
        filters: list = []

        def __init__(self, *a, **k):
            pass

        def run(self, task):  # overridden below
            raise NotImplementedError

    class Task:  # type: ignore
        pass

from email_posture_collector import collect
from email_posture_analysis import analyze_all, Finding


# map our severity vocabulary to a numeric weight for an overall task status
SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1, "ok": 0}


def _findings_to_dict(findings: List[Finding]) -> dict:
    """Shape results the way the reporting layer / report translator expects."""
    items = [{
        "id": f.id, "severity": f.severity, "title": f.title,
        "what_it_means": f.plain, "why_it_matters": f.risk,
        "what_to_do": f.fix, "evidence": f.evidence,
    } for f in findings]
    worst = max((SEVERITY_WEIGHT.get(f.severity, 0) for f in findings), default=0)
    return {
        "module": "email_posture_scanner",
        "num_findings": sum(1 for f in findings if f.severity != "ok"),
        "max_severity": worst,
        "findings": items,
    }


class EmailPostureScanner(ArtemisBase):
    """
    Artemis module: deep email-authentication posture.

    Goes beyond Artemis's built-in SPF/DMARC *presence* check to catch the
    misconfigurations that leave NGOs spoofable despite 'having' SPF/DMARC:
    DMARC p=none, SPF >10 lookups / ~all / +all, missing DKIM, missing/broken
    MTA-STS, and mail servers that don't offer STARTTLS.
    """

    # >>> ARTEMIS-PLUMBING (b): which tasks this module consumes.
    # A domain-oriented module typically filters for DOMAIN tasks. Confirm the
    # exact constant/shape against mail_dns_scanner.py in your checkout.
    identity = "email_posture_scanner"
    if _IN_ARTEMIS:
        filters = [
            {"type": TaskType.DOMAIN.value},  # type: ignore  # confirm vs example module
        ]

    def run(self, current_task: "Task") -> None:
        # >>> ARTEMIS-PLUMBING (c): get the target + emit the result.
        if _IN_ARTEMIS:
            domain = get_target_host(current_task)
        else:
            domain = getattr(current_task, "domain", None)

        if not domain:
            return

        data = collect(domain)
        findings = analyze_all(data)
        result = _findings_to_dict(findings)

        # Human-readable status line Artemis can show in the dashboard.
        if result["max_severity"] >= 3:
            status_reason = "Critical email-spoofing exposure found"
        elif result["num_findings"] > 0:
            status_reason = "Email-authentication weaknesses found"
        else:
            status_reason = "Email authentication looks healthy"

        if _IN_ARTEMIS:
            # The precise call differs by Artemis version — match your example
            # module. Commonly something like:
            #   from artemis.binds import TaskStatus
            #   status = TaskStatus.INTERESTING if result["num_findings"] else TaskStatus.OK
            #   self.db.save_task_result(task=current_task, status=status,
            #                            status_reason=status_reason, data=result)
            self._emit_artemis_result(current_task, result, status_reason)
        else:
            # standalone debug
            print(status_reason)
            for it in result["findings"]:
                print(f"  [{it['severity'].upper()}] {it['title']}")

    # Isolated so the version-specific call is in ONE place you can adjust.
    def _emit_artemis_result(self, current_task, result, status_reason):  # noqa: ANN001
        from artemis.binds import TaskStatus  # local import: only valid in Artemis
        status = TaskStatus.INTERESTING if result["num_findings"] else TaskStatus.OK  # type: ignore
        self.db.save_task_result(                      # type: ignore[attr-defined]
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=result,
        )


if __name__ == "__main__":
    # Allows:  python3 email_posture_scanner.py example.org   (standalone, no Artemis)
    import sys

    class _Stub:
        def __init__(self, d): self.domain = d

    if len(sys.argv) < 2:
        print("usage: python3 email_posture_scanner.py <domain>")
        raise SystemExit(1)
    EmailPostureScanner().run(_Stub(sys.argv[1].strip().lower()))
