"""Contract-limit regression: verify two negative experiments fail *as intended*.

The counterexample suite is outside default collection. The normal suite counts
its precise failed assertions as a successful limitation check, never as native
qualification or a prohibition on stronger self-contained local designs.
"""

from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from scripts.project_policy import ROOT
from scripts.validation_timeouts import watchdog

CHECK_PURPOSE = {
    "purpose": "public-contract",
    "authority": [
        "AGENTS.md",
        "fishhat/owner-support/src/fishhat_owner/journal.py",
    ],
    "scope": "copyable local journal state cannot alone prove global writer exclusivity or rollback freshness",
    "relationship": "candidate",
    "reason": "Exact intentionally false assertions against the existing owner Journal reject only unsupported copyable-state guarantees; no native or independently protected local authority is tested.",
    "claims": [],
}

CASES = {
    "test_false_claim_disconnected_journal_copies_elect_one_global_writer": (
        "COPYABLE_STATE_CANNOT_ELECT_GLOBAL_WRITER"
    ),
    "test_false_claim_rolled_back_journal_detects_its_missing_tail": (
        "COPYABLE_STATE_CANNOT_ATTEST_ROLLBACK_FRESHNESS"
    ),
}
COUNTEREXAMPLES = (
    "research/copyable_state_counterexamples/test_invalid_copyable_state_guarantees.py"
)


def test_copyable_state_only_guarantees_fail_for_the_intended_assertions(tmp_path: Path) -> None:
    report = tmp_path / "counterexamples.xml"
    environment = os.environ.copy()
    # Inner pytest is *not* a second evidence-producing unit suite. Discard
    # inherited collection override arguments, then inspect raw JUnit failures.
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-o", "addopts=", "-q",
            "--tb=short", f"--junitxml={report}", COUNTEREXAMPLES,
        ],
        cwd=ROOT, env=environment, capture_output=True, text=True,
        timeout=watchdog(60), check=False,
    )
    assert result.returncode == 1, (result.returncode, result.stdout, result.stderr)
    assert report.is_file(), (result.stdout, result.stderr)
    root = ET.parse(report).getroot()
    cases = list(root.iter("testcase"))
    names = [case.get("name") for case in cases]
    assert len(names) == len(CASES) and set(names) == set(CASES), names
    assert len(list(root.iter("failure"))) == len(CASES)
    assert not list(root.iter("error")) and not list(root.iter("skipped"))
    for case in cases:
        failures = case.findall("failure")
        assert len(failures) == 1, (case.get("name"), ET.tostring(case, encoding="unicode"))
        failure = failures[0]
        assert (failure.get("message") or "").split("\n", 1)[0] == (
            "AssertionError: " + CASES[case.get("name") or ""]
        ), (case.get("name"), failure.attrib)
