import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


CHECKER = Path(__file__).resolve().parents[1] / "amule-pr-watch-check.sh"
FIXTURES = Path(__file__).resolve().parent / ".amule-pr-watch-fixtures"


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
log = Path(os.environ["GH_LOG"])
with log.open("a", encoding="utf-8") as output:
    output.write(json.dumps(args) + "\n")
responses = json.loads(Path(os.environ["GH_RESPONSES"]).read_text())
endpoint = next((value for value in args if value.startswith("repos/")), None)
if args[:2] == ["pr", "list"]:
    key = "pr:list:" + args[args.index("--state") + 1]
elif args[:2] == ["search", "issues"]:
    key = "issues:open"
elif args[:2] == ["pr", "view"]:
    key = "pr:view:" + args[2]
elif args[:2] == ["pr", "checks"]:
    key = "pr:checks:" + args[2]
elif endpoint:
    key = "api:" + endpoint.split("?", 1)[0]
else:
    key = "argv:" + " ".join(args)
response = responses.get(key, {"stdout": "", "code": 0})
sys.stdout.write(response.get("stdout", ""))
sys.exit(response.get("code", 0))
'''


class CheckerTests(unittest.TestCase):
    def setUp(self):
        FIXTURES.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=FIXTURES)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake = self.bin / "gh"
        fake.write_text(FAKE_GH)
        fake.chmod(0o755)
        self.responses = self.root / "responses.json"
        self.log = self.root / "gh.log"
        self.base = {
            "pr:list:open": {"stdout": ""},
            "issues:open": {"stdout": ""},
            "pr:list:merged": {"stdout": ""},
            "api:repos/kno/amule/actions/runs": {"stdout": ""},
        }

    def run_checker(self, extra=None):
        responses = dict(self.base)
        responses.update(extra or {})
        self.responses.write_text(json.dumps(responses))
        env = {
            **os.environ,
            "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
            "HOME": str(self.root / "home"),
            "STATE_DIR": str(self.state),
            "GH_RESPONSES": str(self.responses),
            "GH_LOG": str(self.log),
            "ONCE": "1",
        }
        return subprocess.run(
            ["bash", str(CHECKER)], capture_output=True, text=True, env=env, timeout=10
        )

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_fork_failed_push_alert_includes_jobs_and_second_run_dedupes(self):
        rows = (
            "2026-02-25T10:00:00Z\t34190665600\tCI\tnetwork parity\tintegration/network-parity\tpush\thttps://example/run/34190665600\tfailure\n"
            "2026-02-25T09:00:00Z\t34190000000\tCI\tprevious success\tintegration/network-parity\tpush\thttps://example/run/34190000000\tsuccess\n"
        )
        extra = {
            "api:repos/kno/amule/actions/runs": {"stdout": rows},
            "api:repos/kno/amule/actions/runs/34190665600/jobs": {
                "stdout": "linux build\nwindows tests\n"
            },
        }
        first = self.run_checker(extra)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        for text in ("run 34190665600;", "CI", "network parity", "integration/network-parity",
                     "push", "https://example/run/34190665600", "linux build", "windows tests"):
            self.assertIn(text, first.stdout)
        self.assertEqual(
            (self.state / "fork-runs.seen").read_text(),
            "34190000000\n34190665600",
        )

        second = self.run_checker(extra)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout, "")

    def test_successful_fork_run_enters_bounded_snapshot_without_output(self):
        run = "2026-02-25T11:00:00Z\t42\tCI\tgood run\tfeature\tworkflow_dispatch\thttps://example/42\tsuccess\n"
        result = self.run_checker({
            "api:repos/kno/amule/actions/runs": {"stdout": run}
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual((self.state / "fork-runs.seen").read_text(), "42")
        run_call = next(call for call in self.calls() if any("actions/runs?" in arg for arg in call))
        self.assertTrue(any("created=%3E%3D" in arg for arg in run_call), run_call)

    def test_initial_older_failure_with_newer_success_does_not_alert(self):
        rows = (
            "2026-02-25T12:00:00Z\t200\tCI\tgood\tmain\tpush\thttps://example/200\tsuccess\n"
            "2026-02-25T10:00:00Z\t100\tCI\told failure\tmain\tpush\thttps://example/100\tfailure\n"
        )
        result = self.run_checker({
            "api:repos/kno/amule/actions/runs": {"stdout": rows},
            "api:repos/kno/amule/actions/runs/100/jobs": {"stdout": "old job\n"},
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual((self.state / "fork-runs.seen").read_text(), "100\n200")
        self.assertFalse(any("runs/100/jobs" in " ".join(call) for call in self.calls()))

    def test_fork_late_completion_older_than_seen_success_is_non_current(self):
        newer = "2026-02-25T12:00:00Z\t200\tCI\tgood\tmain\tpush\thttps://example/200\tsuccess\n"
        first = self.run_checker({"api:repos/kno/amule/actions/runs": {"stdout": newer}})
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

        older_failure = "2026-02-25T10:00:00Z\t100\tCI\tlate failure\tmain\tpush\thttps://example/100\tfailure\n"
        second = self.run_checker({
            "api:repos/kno/amule/actions/runs": {"stdout": newer + older_failure},
            "api:repos/kno/amule/actions/runs/100/jobs": {"stdout": "late job\n"},
        })
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout, "")
        self.assertEqual((self.state / "fork-runs.seen").read_text(), "100\n200")
        self.assertFalse(any("runs/100/jobs" in " ".join(call) for call in self.calls()))

    def test_fork_latest_failure_in_each_workflow_branch_group_alerts(self):
        rows = (
            "2026-02-25T10:00:00Z\t301\tCI\tfirst\tmain\tpush\thttps://example/301\tfailure\n"
            "2026-02-25T10:00:00Z\t302\tCI\tsecond\tfeature\tpush\thttps://example/302\tfailure\n"
        )
        result = self.run_checker({
            "api:repos/kno/amule/actions/runs": {"stdout": rows},
            "api:repos/kno/amule/actions/runs/301/jobs": {"stdout": "job one\n"},
            "api:repos/kno/amule/actions/runs/302/jobs": {"stdout": "job two\n"},
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("run 301;", result.stdout)
        self.assertIn("run 302;", result.stdout)
        self.assertEqual((self.state / "fork-runs.seen").read_text(), "301\n302")

    def test_old_timestamp_marker_does_not_hide_unseen_run(self):
        (self.state / "fork-runs.at").write_text("2099-01-01T00:00:00Z")
        run = "2026-02-25T10:00:00Z\t88\tCI\tbroken\tmain\tpush\thttps://example/88\tfailure\n"
        result = self.run_checker({
            "api:repos/kno/amule/actions/runs": {"stdout": run},
            "api:repos/kno/amule/actions/runs/88/jobs": {"stdout": "broken job\n"},
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("run 88;", result.stdout)

    def test_fork_api_failure_does_not_advance_snapshot_and_warns_nonzero(self):
        (self.state / "fork-runs.seen").write_text("9")
        result = self.run_checker({
            "api:repos/kno/amule/actions/runs": {"code": 1}
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AVISO", result.stdout)
        self.assertEqual((self.state / "fork-runs.seen").read_text(), "9")

    def test_failed_job_query_makes_round_incomplete_and_keeps_snapshot(self):
        (self.state / "fork-runs.seen").write_text("9")
        run = "2026-02-25T12:00:00Z\t77\tCI\tbroken\tbranch\tpush\thttps://example/77\tfailure\n"
        result = self.run_checker({
            "api:repos/kno/amule/actions/runs": {"stdout": run},
            "api:repos/kno/amule/actions/runs/77/jobs": {"code": 1},
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AVISO", result.stdout)
        self.assertIn("77", result.stdout)
        self.assertEqual((self.state / "fork-runs.seen").read_text(), "9")

    def pr_with_checks(self, checks, code=1):
        return {
            "pr:list:open": {"stdout": "12\n"},
            "api:repos/amule-org/amule/issues/12/comments": {"stdout": ""},
            "api:repos/amule-org/amule/pulls/12/reviews": {"stdout": ""},
            "pr:view:12": {"stdout": "MERGEABLE\n"},
            "pr:checks:12": {"stdout": checks, "code": code},
        }

    def test_upstream_conflict_and_ci_output_is_visible(self):
        extra = self.pr_with_checks(
            "Linux build\t2026-02-25T10:00:00Z\thttps://example/check/1\n"
        )
        extra["pr:view:12"] = {"stdout": "CONFLICTING\n"}
        result = self.run_checker(extra)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("CONFLICTO", result.stdout)
        self.assertIn("CI EN ROJO", result.stdout)
        self.assertIn("1 comprobacion(es)", result.stdout)
        checks_call = next(call for call in self.calls() if call[:2] == ["pr", "checks"])
        self.assertIn("--json", checks_call)
        self.assertIn("name,bucket,completedAt,link", checks_call)

    def test_upstream_same_failure_snapshot_dedupes(self):
        checks = "Linux build\t2026-02-25T10:00:00Z\thttps://example/check/1\n"
        first = self.run_checker(self.pr_with_checks(checks))
        second = self.run_checker(self.pr_with_checks(checks))
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("CI EN ROJO", first.stdout)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertNotIn("CI EN ROJO", second.stdout)

    def test_upstream_same_count_different_failure_identity_alerts(self):
        first = self.run_checker(self.pr_with_checks(
            "Linux build\t2026-02-25T10:00:00Z\thttps://example/check/1\n"
        ))
        second = self.run_checker(self.pr_with_checks(
            "Windows tests\t2026-02-25T10:05:00Z\thttps://example/check/2\n"
        ))
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("CI EN ROJO", second.stdout)
        self.assertIn("1 comprobacion(es)", second.stdout)

    def test_upstream_rerun_same_job_failure_alerts(self):
        first = self.run_checker(self.pr_with_checks(
            "Linux build\t2026-02-25T10:00:00Z\thttps://example/check/1\n"
        ))
        second = self.run_checker(self.pr_with_checks(
            "Linux build\t2026-02-25T11:00:00Z\thttps://example/check/3\n"
        ))
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("CI EN ROJO", second.stdout)

    def test_selected_issue_does_not_invoke_pr_endpoints(self):
        result = self.run_checker({
            "issues:open": {"stdout": "34\n"},
            "api:repos/amule-org/amule/issues/34/comments": {"stdout": ""},
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        rendered = [" ".join(call) for call in calls]
        issue_call = next(call for call in calls if call[:2] == ["search", "issues"])
        self.assertNotIn("--type", issue_call)
        self.assertNotIn("--include-prs", issue_call)
        self.assertFalse(any("pulls/34" in call for call in rendered), rendered)
        self.assertFalse(any(call[:3] in (["pr", "view", "34"], ["pr", "checks", "34"])
                             for call in calls), calls)

    def test_issue_discovery_failure_has_category_warning(self):
        result = self.run_checker({"issues:open": {"code": 1}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AVISO", result.stdout)
        self.assertIn("issues", result.stdout.lower())

    def test_review_api_failure_warns_and_returns_nonzero(self):
        result = self.run_checker({
            "pr:list:open": {"stdout": "12\n"},
            "api:repos/amule-org/amule/issues/12/comments": {"stdout": ""},
            "api:repos/amule-org/amule/pulls/12/reviews": {"code": 1},
            "pr:view:12": {"stdout": "MERGEABLE\n"},
            "pr:checks:12": {"stdout": ""},
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AVISO", result.stdout)


if __name__ == "__main__":
    unittest.main()
